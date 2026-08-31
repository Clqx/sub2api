# Phase 2-H 离线验证与 Reveal 授权记录基础状态

## 1. 阶段结论

Phase 2-H H1 增加了 **公开、无秘密的 Evidence Bundle、纯离线 verifier CLI，以及 Reveal 授权 transcript
基础**。它让审查方在不连接平台、数据库、KMS 或成员设备的环境中，对一份严格 JCS JSON 和单独提供的
信任策略进行确定性校验；migration `010` 与 `EvidenceStore` 为后续受控导出、成员 artifact 回执和 Reveal
授权账本提供持久化边界。

这不是在线恢复或生产 Reveal 能力声明。当前已有将 `PublicEvidenceSnapshot` 映射为严格 JCS Bundle、
固定集合排序并计算 inventory/bundle digest 的纯构建函数，以及一个窄接口的持久导出编排库。该编排库先写
durable intent，再读取公开快照、构建 bundle、对独立 export statement domain 请求外部签名并 fenced commit；
终态重放从持久时间与摘要重建相同 bundle，不依赖旧租约，也不再次调用 signer；提交响应丢失后的重试
使用绑定签名域、integration client 和请求摘要的稳定幂等键，签名前 fence 已失效时不会调用 signer。HTTP server/runtime 已接线
受 recovery key 保护的创建与下载端点；它要求显式 portable profile、独立导出 client 和外部 signer。
当前组合根尚未注入生产 signer，因此开启功能会在监听前失败；Reveal 创建、审批、授权导出或执行端点仍不存在。H1 没有
Share 解密、VSS/Share 重建、Recovery Root 私钥
恢复、DEK unwrap、批次明文解密或明文输出接口。即使授权签名全部通过，离线工具也只能返回
`AUTHORIZED_NOT_EXECUTABLE`，不能执行恢复。

## 2. Evidence Bundle 与信任边界

- Bundle 是一个 `trusted-pool/offline-evidence-bundle/v1` 严格 JCS JSON，不是 ZIP；非规范 JSON、未知字段、
  重复键、非法 UTF-8、超限输入或集合漂移均失败关闭。
- Bundle 只包含 Manifest 规范字节与散列、平台签名、成员审批、Share ACK 和 typed provider proof。
  它不包含 Share ciphertext、Root/Share 私密材料、批次 ciphertext/nonce、wrapped DEK、凭据、API Key、
  claim token 或成员私钥。
- 信任策略是独立输入，不从 Bundle 内嵌 key 自动建立信任。每个 provider Ed25519 key 必须绑定精确的
  `provider_id`、`key_id` 和排序去重的 `allowed_proof_kinds`；ceremony、account、package、Share proof
  不能跨 provider 或跨角色替代。策略同时固定 checkpoint、平台 key 和 Reveal policy state。
- portable verifier 只接受 Manifest 签名域 `trusted-pool/platform-manifest-signature/v2`。历史签名没有可移植的固定 domain，
  或历史记录缺少 typed provider proof 时，只能稳定返回 `INCOMPLETE`，理由分别包括
  `LEGACY_UNSUPPORTED`、`PROVIDER_EVIDENCE_INCOMPLETE`；不得提升为 `VERIFIED`。
- `VERIFIED` 只表示公开 transcript 在给定外部信任策略下通过 JCS、散列链、checkpoint、集合、动态阈值和
  Ed25519 验证，不表示 Share 可解密、Root 可恢复、批次可揭示或 provider 行为在现实世界已完成。

阈值完全来自 Manifest，并要求 `0 < recovery_threshold <= governance_threshold <= 正式成员唯一数`。
[ADR-0002](adr/0002-recovery-threshold.md) 仍为 `Proposed`；H1 不把 `4-of-5` 或任何固定人数写入代码、
数据库规则或运维流程。

## 3. 离线 CLI

CLI 只读取本地普通文件（最多一个输入可使用 stdin），不访问网络、数据库或 KMS。以下命令在
`backend` 目录执行：

```powershell
go run ./cmd/recovery-verifier verify `
  -bundle C:\evidence\bundle.json `
  -policy C:\evidence\trust-policy.json

go run ./cmd/recovery-verifier reveal-authorize `
  -bundle C:\evidence\bundle.json `
  -policy C:\evidence\trust-policy.json `
  -intent C:\evidence\reveal-intent.json `
  -approvals C:\evidence\reveal-approvals.json `
  -at 2026-08-21T00:00:00Z
```

`verify` 输出规范 JSON，verdict 为 `VERIFIED`、`INCOMPLETE` 或 `REJECTED`；退出码依次为 0、2、3，
本地 I/O/用法错误为 1。`reveal-authorize` 只验证已 `VERIFIED` 的 Bundle、intent 绑定、有效期、Manifest
治理阈值和成员 Ed25519 审批。其非拒绝结果只有 `POLICY_UNAPPROVED` 或
`AUTHORIZED_NOT_EXECUTABLE`，退出码仍为 2，明确阻止脚本把授权记录误当成明文恢复成功。
报告会逐字节记录调用方提供的规范 `evaluation_time`。这是离线可重现验证时间，不是可信当前时钟；任何
未来 executor 都必须用自己的可信时钟重新检查有效期，并通过在线 ledger 对 `reveal_id` 与 challenge
执行一次性消费，禁止直接消费一份历史时间生成的离线报告。

## 4. Migration 010 与 Store 基础

Migration `010_phase2h_offline_verification.sql` 增加 portable profile、Manifest 平台签名 domain、typed
provider proof 元数据和更严格的 Root/Share/Manifest/control evidence 不可变约束；同时增加只追加的
member artifact receipt、verification export 元数据、Reveal intent/approval/authorization/executor receipt
及规范事件链。历史行保持 `NULL`/`LEGACY_EXPORT_LIMITED`，不自动伪造 v2 domain 或 provider proof。

### 4.1 Migration 011 恢复协议兼容

Migration `011_phase2h_recovery_protocol_compatibility.sql` 修正 Phase 2-G 三段恢复触发器与当前 Manager typed
snapshot 的协议、字段名和 hash 表示，并只为升级前已有的 009 Seat operation 保留精确七字段兼容读取：
`protocol_version`、`plan_id`、`pool_id`、`seat_id`、`target_member_id`、`from_epoch`、`to_epoch`。兼容要求
完整领域 hash，不接受 mixed shape、大小写别名、未知字段、业务字段或 Pool 内嵌 Seat 漂移，也不改写历史
审计 snapshot。011 后新建 operation 只能使用 typed snapshot，Store 与数据库触发器都会拒绝旧格式新写入。

`EvidenceStore` 只暴露公开 evidence 投影、散列、签名和状态元数据；其类型表面没有 Root/Share/DEK/
credential 明文。Schema、Store、纯 bundle builder、导出编排库和 recovery-key HTTP 发布路由已经建立：
当前没有生产 signer/provider adapter、Reveal 服务或 executor；导出开关开启但 signer 未注入时启动失败。
导出 ledger 使用独立 `trusted-pool/verification-export-signature/v1` statement domain；该签名是导出元数据
attestation，不冒充 Manifest v2 签名，也不改变 portable Bundle 自身的 verifier 语义。`BeginRevealAuthorization`、批准提交、授权导出和
executor receipt 四个 Store 入口统一返回 `ErrRevealExecutionUnavailable`，migration 也拒绝在线批准和
执行状态跃迁。不得通过直接 DML 把 `PENDING` 改成 `AVAILABLE`，也不得用 executor receipt 表的存在
宣称恢复已经执行。

现有 Phase 2-F provider envelope/proof 与 portable detached statement signature 不是同一个密码学对象：
新 ceremony 现在要求每个账号的 detached proof algorithm/signature/protocol 由已验真的全局 provider
attestation 回显，随后进入不可变 plan 快照、Manifest JCS、`provider-attestation-set/v2` hash 与 control evidence；
缺少或发生漂移时不会获得 portable capability。Root 与 Share 的在线 opaque proof 及其自身 SHA-256
绑定也已和 portable algorithm/provider/key/protocol/signature 分列持久化；治理重放会逐字段比较，公共证据
投影只读取新的 detached signature 列，绝不读取旧 opaque proof 列冒充签名。该列模型、Store SQL 与
`001 -> 011` PostgreSQL 解析门禁已经落地，并额外验证 `010 -> 011` 停机迁移账本；这不表示 rolling overlap
或降级已经验收。

生产 provider 仍必须先确定公开 subject digest，再按固定 `ProviderStatement` 域生成 detached Ed25519
签名，并完成 `provider -> Manager -> DB snapshot -> Bundle -> offline VERIFIED` 跨层固定向量；当前仓库没有
此生产 adapter，也没有 portable plan profile writer 或 Manifest v2 HSM signer。旧记录以及缺少任一分离证明、
profile 或 v2 签名的记录只能 `LEGACY_EXPORT_LIMITED`/`INCOMPLETE`，绝不允许通过补 metadata 升级。
数据库只有在 bundle profile=`trusted-pool/offline-evidence-bundle/v1`、provider statement
profile=`trusted-pool/provider-proof-statement/v1`，且平台、成员、ACK、Root、Share、账号证明均为完整
64-byte Ed25519 签名时才允许标记 `REVEAL_CAPABLE`；不支持的算法或半完整证明会被省略并诚实降级，
不会被导出成一条结构无效、看似完整的 proof。

## 5. 生产与发布门禁

- `TRUSTED_POOL_RECOVERY_GOVERNANCE_ENABLED` 仍默认 `false`。当前生产组合根缺少 Root/JCS/HSM/VSS、
  attestation、member signature、governance batch 和 MemberArtifact providers；误开启必须在监听前失败。
- 本地隔离 PostgreSQL 16.15 已实际通过平台空库 `001 -> 011`、带旧 Manifest 的 `009 -> 010`、停机迁移账本
  `010 -> 011`，以及
  Sub2API 受支持基线到 `226`；226 的混合 scope 禁用与新写入约束也已实测。真实执行同时修复了
  migration 005/008 的 PL/pgSQL 解析歧义、migration 009 的同名 trigger 升级冲突，以及 007/008/010
  跨表 deferred trigger 对动态 `NEW` 字段的错误分派；011 进一步修正三段恢复 snapshot 的协议兼容。
- 通用 Operation、Credential Claim、Batch、Recovery plan/finalization 已通过两个独立 PostgreSQL 连接同时
  争抢到期 lease、单赢家、新 fence 和旧 fence CAS 拒绝。旧 plan fence 不能推进计划阶段，旧 finalization
  fence 不能执行结构提交或造成聚合双写。迁移 owner/运行 role 分离也已在真实数据库验证：运行 role 能完成
  Begin/Acquire/Commit，但不能建表或删除账本。
- finalization 七个持久提交/响应丢失边界已通过故障注入，重启不会重复已确认外部副作用或重新披露 claim
  token；`READY_TO_COMMIT` 的持久 activation 恢复路径已修复。这些测试不替代真实进程 kill 后同时联动
  PostgreSQL、Sub2API/provider 的端到端恢复。
- 两 Seat 部分 prepare 响应丢失已验证不同 owner/fence 接管：Pool prepare 可按同一请求精确重放，但已持久
  Seat 不重复 Seal/commit；两 Seat activation 响应丢失也已通过确定性接管门禁。Suspend/Provision、Credential
  Batch retire/finalization 同 Pool 双连接竞争，以及 provider commit durable 写入后的真实子进程退出/精确回放
  已在真实 PostgreSQL 通过；进程门禁使用测试专用 file-backed provider 和 verifier test double，生产签名
  另由独立安全门禁负责。这些门禁同时发现并修复 migration 009 的普通 Seat 更新误判、Bootstrap 源
  Manifest 退休和 Recovery freeze 消费约束问题。
- 公开 Store 入口已验证在 010 下创建的 legacy Seat operation 穿过 011 DDL 后，由当前 typed Manager 换
  owner/fence 接管且不改写旧审计；也验证当前 typed Seat prepare -> Pool prepare -> Seat PREPARED -> Pool
  activation 的真实触发器链路。错误 hash、字段漂移、未知 shape、同长度内嵌 Seat 漂移和 011 后 legacy 新建
  均原子拒绝。
- Sub2API `226` 真实库门禁已覆盖父记录完整性、集合摘要、防跳状态、子记录不能独立激活、父子证据不可删除/
  篡改，以及两个连接竞争同一席位时只有一个提交成功。
- 生产 KMS/HSM、Root/VSS、成员设备、provider attestation 与受控离线介质流程必须分别验收；开发 key、
  mock proof 或仅有表结构不能作为生产证据。
- 在独立密码学审查、真实 provider 演练、授权与执行职责分离、输出 sink 证明和事件链审计通过前，不得
  接线 Share 解密、重建、unwrap 或 plaintext Reveal。
- 多 Seat 部分 activate 的真实 PostgreSQL/provider 进程演练，以及 Batch、plan、finalization 与其他工作流的
  更广跨多副本并发仍未完成生产验收；在其余外部副作用边界的真实进程 kill E2E 和这些并发门禁完成前，
  继续保持单实例并禁止 rolling overlap。

Phase 2-G 的 Pool finalize 语义保持不变；H1 只增加公开证据验证和授权记录基础，不改变 Credential Batch、
Membership Epoch、Owner、claim token 或 Sub2API 三阶段 release 的在线状态转换。
