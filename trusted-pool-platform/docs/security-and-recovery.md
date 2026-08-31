# 密钥批次与恢复协议

## 1. 安全目标

- Sub2API 只获得请求供应商所需的运行凭据。
- 新平台能够按阶段密封登录、MFA、恢复和所有权材料。
- 平台服务失效时，正式成员可用离线工具校验 Manifest 并按治理规则恢复。
- 临时成员和离任成员不能参与新 Epoch 的恢复。
- 平台自身的 Credential Batch、Claim、Share 和 Recovery ledger 不保存凭据明文或未包装 DEK。
  Sub2API migration `226` 曾为精确 `prepare` 重放引入明文 `prepared_credential`；forward migration `227`
  已取代该设计：遇到非空遗留明文时失败关闭，随后删除明文列。当前候选只保存七列独立 envelope，AAD
  绑定完整 rotation/Seat 请求，披露 TTL 只限制精确 `prepare` 重放再次返回 credential；经过认证且绑定
  一致的 `activate` 在 TTL 后仍可使用 envelope 完成 fail-forward，并在同一事务清除全部可解密材料。
  当前只实现独立本地 KEK provider，生产 KMS/HSM adapter、存量扫描和真实数据库清理演练仍是发布门禁。

## 2. 批次划分

| 类型 | 内容示例 | 是否发送 Sub2API |
|---|---|---|
| `OPERATIONAL` | access token、refresh token、运行 cookie | 是，仅发送必要字段 |
| `LOGIN` | 登录名、密码 | 否 |
| `MFA` | TOTP 种子、备用码 | 否 |
| `RECOVERY` | 恢复邮箱和恢复材料 | 否 |
| `OWNERSHIP` | 所有权迁移材料 | 否 |

供应商适配器必须声明字段属于哪个批次，禁止用字符串规则临时拆分 JSON。

## 3. 包络加密

Phase 2-A 的 Provision Claim 已实现在线 KMS 单包装。Phase 2-E 已为 Credential Batch 接入 AES-256-GCM、
规范 AAD、随机 DEK、在线 KMS 与独立 Recovery wrap-only 双包装，以及 PostgreSQL 生命周期。开发模式可
显式使用两把不同的本地 KEK；生产 provider adapter 尚未链接，配置为 production 时会失败关闭。
Phase 2-F 已实现外部 Root/VSS、加密 Share、JCS Manifest、平台/成员签名、Share ACK 和 STAGED batch 的
准备编排与持久边界；Phase 2-H H1 增加只验证公开证据的离线工具，但当前二进制仍未链接生产 providers，
任何 Share 解密、重建、在线 Recovery Unwrap 和批次明文 Reveal 仍未实现。

1. 每个批次版本生成随机 DEK。
2. 使用 AEAD 加密规范化后的批次内容，关联数据包含 Pool、账号引用、批次类型、版本和 Epoch。
3. Provision Claim 的 DEK 由在线 KMS 包装，用于一次性交付。
4. Credential Batch 的同一 DEK 由在线 KMS 与独立 Recovery wrap-only adapter 分别包装；该 Recovery
   包装是后续治理输入，不代表当前已有 Root、Share 或可执行离线恢复。
5. 保存密文、nonce、算法、关联数据散列、包装后 DEK 和内容散列。
6. 清除内存中的明文和原始 DEK；日志只记录批次 ID 和状态。

生产环境必须使用 KMS/HSM。本地 `TRUSTED_POOL_KEK_HEX` 仅供开发测试，不能用于生产数据。

## 4. 治理与密码学阈值分离

以下内容只记录固定五成员场景下的**未采纳方案建议**，不是当前协议默认值：

- 治理授权阈值可保持 5 人一致同意。
- 可考虑让 Recovery Root 使用 `4-of-5` Shamir 阈值以容忍一人不可用。
- Reveal 是否获准由签名策略判定，不以“能否拼出密钥”代替治理授权。

当前实现只接受 Membership Epoch 和 Manifest 中显式记录并通过约束的动态治理/恢复阈值；最终阈值是产品治理决策，不能把 `4-of-5` 或其他组合写死在代码和运营流程里。

## 5. Membership Epoch

新 Epoch 包含正式成员 ID、成员签名公钥、治理阈值、恢复阈值、批次根散列和前一 Manifest 散列。
临时换员不创建新 Epoch。永久换员必须：

1. 暂停并冻结 Pool 的全部 Seat。
2. 轮换供应商真实凭据，而非仅重包旧 DEK。
3. 生成新 Recovery Root 和 Share。
4. 为仍需保留的材料生成新批次版本。
5. 发布并签署新 Manifest。
6. 激活新 Epoch，退休旧批次。

旧 Share 无法被“撤回”，只有换根和换真实凭据才能使其失效。

上述流程是完整永久交接的安全门禁。Phase 2-F 以 `READY` 覆盖第 3 至 5 项的准备与验证；Phase 2-G 接入
Pool 全 Seat credential rotation、最终结构事务和远端 release。生产是否开放仍取决于真实 provider、数据库
并发和崩溃演练，而不是 schema 或状态名称存在。

### 控制凭据轮换证据

`POST /api/v1/control-rotation-evidence` 接收 `pool_id`、`account_ref`、`from_membership_epoch`、
`to_membership_epoch` 和必填的 `provider_attestation_ref`，且两个 Epoch 必须相邻。运营或外部系统必须
先验证该引用所指供应商登录、MFA、恢复和所有权变更证明的真实性，再发起签发请求。Phase 1 只保存
该不透明引用，不获取外部证明，也不做供应商签名或证明的密码学校验；不得宣称平台验证了供应商动作。

平台仅在旧 Epoch 的 `LOGIN`、`MFA`、`RECOVERY`、`OWNERSHIP` 四类批次全部 `RETIRED`，并且新
Epoch 的对应四类批次全部 `ACTIVE` 时签发证据。证据同时绑定 `provider_attestation_ref` 和新旧八个
批次 ID，不包含凭据明文。

永久换员不能只检查引用非空：Coordinator 必须使用
Seat 的 Pool、当前 Membership Epoch 和 `current + 1` 复核证据范围，并重新检查所引用批次仍满足
退休/激活条件。跨 Pool、跨 Epoch 或状态已变化的证据立即失效。永久换员成功后，Manager 把 Pool
最小 Membership Epoch 提升到新 Epoch，后续旧 Epoch 的 Seal 或 Activate 均被拒绝。

Migration 008 已增加逐账号验证证据、精确八批次绑定和准备状态约束；migration 009 增加 Pool finalization、
全 Seat child operation、三阶段证明和 replacement claim。旧 `/control-rotation-evidence` 入口仍失败关闭。
真实 PostgreSQL 恢复演练通过前，不能把 schema 或 `FINALIZED` 测试状态当成生产能力。

### Phase 2-F Root、Share 与成员材料边界

- 每个 Pool/Epoch 使用独立非对称 Recovery keypair；私钥和阈值 Share 仅存在于外部 Root provider/成员侧。
- 成员签名 key 与 Recovery encryption key 必须不同，并分别绑定算法、key ID、fingerprint 和 PoP。
- Manifest 使用外部 RFC 8785/JCS 实现规范化并形成前向散列链，由 HSM 平台签名与治理阈值成员签名共同保护。
- `MemberArtifact` 由外部 gateway 分发；平台响应只公开计划状态和计数，不提供加密 Share 载荷或 Manifest 字节。
- `BOOTSTRAP` 只负责将 legacy active epoch 引入第一条可信链；`ROTATE` 不得从 `LEGACY_UNVERIFIED` 开始。

## 6. Manifest 最低字段

- 协议版本、Pool ID、Epoch、创建时间。
- 正式成员及签名公钥快照。
- 治理阈值和密码学恢复阈值。
- 所有活动批次的 ID、类型、版本、密文散列。
- Recovery Package 根散列。
- 前一 Manifest 散列，形成可审计链。
- 平台签名和成员签名。

任何未来恢复执行器都必须先验证规范化编码、散列链和签名；校验失败时不得尝试解密。Phase 2-H H1
无论 verifier 结果为何都不执行恢复，`VERIFIED` 也不是解密许可。

### Phase 2-H 公开 Evidence Bundle

- Bundle 是单份严格 JCS JSON，只含 Manifest 规范字节/散列、平台签名、成员审批、Share ACK 和 typed
  provider proof；不得包含 Share ciphertext、批次 ciphertext/nonce、wrapped DEK、Root/Share 私密材料、
  credential 或 claim token。
- trust policy 是独立的本地输入，固定 checkpoint 及可信平台/provider Ed25519 key；Bundle 内嵌 key 不能
  自我授权。portable verifier 只接受 `trusted-pool/platform-manifest-signature/v2` 平台签名 domain。
- 历史签名没有固定 v2 domain 或历史 proof 不具备 typed statement 时，结果为 `INCOMPLETE`，不能视为
  `VERIFIED`；证据字段或签名不一致则为 `REJECTED`。
- Manifest 动态阈值必须满足 `0 < recovery <= governance <= unique formal members`。
  [ADR-0002](adr/0002-recovery-threshold.md) 仍为 Proposed，不得写死 `4-of-5`。

离线 Reveal authorization 只验证 intent、时间窗、bundle/policy/manifest 绑定、选定批次和治理成员签名。
policy 未批准时为 `POLICY_UNAPPROVED`；批准且达到阈值时也只能为 `AUTHORIZED_NOT_EXECUTABLE`。H1 没有
解密、VSS/Share 重建、Root/DEK unwrap 或 plaintext sink，调用方不得根据该报告自行推断秘密已恢复。

## 7. 凭据处理禁令

- 不从 Sub2API `accounts.credentials` 反向导出恢复材料。
- 不允许 migration `226` 的 `prepared_credential` 明文列、明文 fallback 或非空遗留值进入当前 schema；
  migration `227` 的七列 envelope、独立密钥、披露 TTL 和 activate 原子清理必须共同通过门禁。
- 不在 API 响应、审计 payload、panic、trace 或指标标签中记录秘密。
- 不把完整批次明文写入临时文件或消息队列。
- 不将 `OPERATIONAL` 之外的批次发送给 Sub2API。
- 不允许已退休批次重新激活。

## 8. 成员领取与 ack

- 每次交付生成独立的 256-bit 密码学随机 claim token，并绑定目标成员 ID、操作 ID 或批次 ID；平台只保存
  SHA-256 摘要和短 TTL，明文仅出现在首次成功响应中。
- token 只随原始受保护命令返回，不出现在状态查询、日志、审计 payload 或指标标签中。
- 成员领取时同时提交自身 ID 和 token；两者与绑定值一致才返回一次性凭据。
- Provision 凭据先以独立 `credential:ack` scope 向 Sub2API 提交稳定 claim operation ID、成员和 credential
  fingerprint；只有明确确认后才交付。结果未知时失败关闭并幂等重放，TTL 到期销毁待交付值。
- 成功领取即完成 ack，必须消费 token 摘要并清除待交付明文；重放和跨成员代领均失败。
- Phase 2-A 已持久化 Provision Seat 访问凭据的 token 哈希、KMS 包络、领取状态和 typed ack 证据。
  Phase 2-G replacement claim 在结构切换时先处于无 token 的 `ISSUANCE_PENDING`，provider release 后才允许
  同步 finalize 原子签发；Credential Batch 不提供明文领取/Open，Share 领取仍未接入持久运行时。

持久化时只保存 claim token 的带密钥摘要或不可逆哈希，不保存原始 token；待交付秘密必须由 KMS
包络加密。上游网络调用不得持有数据库事务：先持久化 ack marker，调用上游，再持久化 typed ack；
解密后以独立 fenced CAS 消费 Claim 并清密，只有 CAS 成功的本次请求可以披露 credential。

## 9. Phase 2-G 三阶段释放与代交付

prepare 和 activate 都不启用新 credential。平台验证 Sub2API Ed25519 证明后，在远端 held 期间完成本地
Epoch/Owner/batch/credential floor 的结构切换；只有 commit 才启用 API Key 和 Subscription。每次网关准入
都把请求 credential SHA-256 与数据库当前 fingerprint 比较，旧的正缓存不能授权；auth-cache outbox 仅用于
收敛，不能替代 fingerprint gate。

replacement claim token 默认 10 分钟、最多 30 分钟，只保存 SHA-256。恢复 worker 不生成 token；首次同步
finalize 提交后才返回 raw token，重放和 GET 不返回。领取接口由 recovery API key 保护，是管理员代交付边界，
不是目标成员的认证协议。平台必须先 fenced CAS 消费并清密，再披露 credential，响应丢失后不二次披露。
