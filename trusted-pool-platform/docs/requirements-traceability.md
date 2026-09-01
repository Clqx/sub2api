# 原方案需求追踪

> 全仓业务能力、跨模块发布门禁和分阶段进度见[项目能力盘点与交付路线图](../../docs/PROJECT_CAPABILITIES_AND_ROADMAP_CN.md)。本文继续作为可信资源池的详细需求证据。

本文把《可信有限成员订阅共享平台可行性方案 V1.0》、后续需求补充与当前实现逐项对应。附件中的描述只作为
研究输入；本项目执行范围以用户明确要求、当前架构决策和阶段验收为准。

| 需求 | 当前责任边界 | 状态 | 证据或下一步 |
|---|---|---|---|
| 额度控制 | Sub2API Group、Subscription、API Key 原生窗口与 RPM | 已接入 | Seat 使用稳定 Principal/Subscription/API Key；冻结快照保留四窗口用量 |
| 分组与账号资源 | Sub2API 独占 Group、Account 调度、Seat Principal | 已接入 | provision 只绑定预建独占 Group；Seat principal 禁止交互登录 |
| 人员动态调整 | 新平台 Seat/Assignment 状态机 | 已接入开发闭环 | 暂停后冻结，支持临时换员与正式成员恢复；结果未知保持禁用 |
| 临时违约先暂停 | 新平台 + Sub2API 双屏障 | 已接入 | SUSPEND_PENDING -> DRAINING -> FROZEN；并发与 pending settlement 必须同时归零 |
| 分阶段密钥批量 | 新平台 Credential Batch/Recovery 治理 | Phase 2-E 已接入批次底座 | Seal/Get/Activate/Retire 持久化；在线 KMS + 独立 Recovery 双包装；不开放在线 Recovery Unwrap |
| 账号控制凭据轮换 | 新平台治理，Sub2API 执行 Pool 全 Seat 访问 Key 三阶段轮换 | Phase 2-G 开发闭环、上线门禁中 | exact four FROM/TO、provider evidence、prepare/activate-held/commit、Ed25519 与 fingerprint gate 已接线；CLI、五套 Compose、签名启动门禁、真实库 CI 定义和 fail-forward 手册已完成，CI 首跑工件、真实进程演练和生产 provider 仍未完成 |
| pending 用量失败处理 | Sub2API 权威账本 + 新平台持久 intent | Phase 2-D 已接入 | 独立 read/resolve 身份、epoch/request 精确绑定、append-only 审计、重启恢复 |
| 设备指纹与并发观察 | Sub2API 网关 + 新平台风险聚合 | 部分实现 | 并发是冻结硬门禁；IP/User-Agent HMAC 组合仅作风险信号，不作认证或自动封禁 |
| Recovery Root/Share/Manifest | 新平台 Trust Plane | Phase 2-H 验证基础、上线门禁中 | Phase 2-F/G 准备与 finalize 代码已完成；H1 增加公开 JCS bundle、离线验证及持久导出 Store/条件路由代码，但当前发布组合根未链接生产 provider/export signer，导出不可激活 |
| 多人恢复与揭示仪式 | 新平台 Trust Plane | Phase 2-H 授权记录基础 | 动态阈值、签名/ACK、Reveal intent/approval transcript 可离线验证；无 Share 解密、重建、unwrap、明文 Reveal 或在线 API |
| 恢复协议跨版本兼容 | 新平台 Store + PostgreSQL migration | Phase 2-H 兼容门禁已接入 | 011 仅接管升级前已有的 009 七字段 Seat snapshot，新 operation 只接受 typed 16-key；migration 005 的历史 checksum 只映射到 PostgreSQL 解析修复，其他漂移失败关闭；旧审计不改写，mixed/alias/hash/字段/内嵌 Seat 漂移失败关闭；仍禁止滚动重叠与降级 |
| 供应商适配与合规矩阵 | 独立 adapter/运营流程 | 接口已定义、实现未链接 | attestation verifier 按账号绑定 provider identity/证明；当前二进制没有生产 adapter，启用即失败启动 |
| 交易、支付、退款、担保 | 商业系统 | 不在当前开发范围 | 不与可信池核心状态机耦合，需单独立项 |

## 当前可行性结论

额度、分组、稳定 Seat 资源和账号调度继续依赖 Sub2API 是合理边界；成员身份、暂停换员、凭据交付、审计与
恢复治理应由独立平台实现。Phase 2-G 在 Phase 2-F 准备闭环上补齐了 Pool 全 Seat 三阶段 rotation、最终
Epoch 切换、provider release 恢复和一次性 claim；Phase 2-H H1 增加公开无秘密证据的离线验证与 Reveal
授权记录基础。真实 PostgreSQL 迁移升级、迁移/运行身份分离、通用 Operation/Credential Claim/Credential
Batch/Recovery plan/finalization 双连接 fence、finalization 响应丢失续跑、两 Seat 部分 prepare 接管、
两 Seat activation 响应丢失单元恢复、Suspend/Provision 与 Credential Batch retire/finalization 同 Pool 竞争、
provider commit 真进程退出精确回放，以及 Sub2API 永久轮换父子证据门禁已验收；进程门禁使用测试专用
file-backed provider，不替代生产 Sub2API/provider 或签名集成验收。由于生产导出 signer/Reveal
未接线；平台 `010 -> 011` 停机迁移账本、升级前 009 七字段 Seat operation 穿过 DDL 后的 typed 接管、
011 后 legacy 新建拒绝和当前 typed Seat -> Pool prepare -> activation 公开链路也已通过真实 PostgreSQL。更广的 Batch/Recovery 跨工作流多副本、
其余外部副作用边界的真实进程退出和生产
providers 尚未验收，不能宣称生产永久换员或恢复 Reveal 可用。

## 后续顺序

1. 继续完成真实 PostgreSQL 16 的更广 Batch/Recovery 跨工作流多副本并发、其余外部副作用边界联动真实
   Sub2API/provider 的进程退出恢复和剩余 direct DML；同 Pool Batch retire/finalization 双向裁决及 provider
   commit durable 写入后的进程退出/精确回放已通过，但这里使用测试专用 provider。平台
   `001 -> 011`、`009 -> 010`、`010 -> 011`、Sub2API 基线到 `226`、通用 Operation/Credential Claim/Credential Batch/
   Recovery plan/finalization 双连接 fencing，以及迁移 owner/最小权限 runtime role 已通过。
2. 链接并验收 Root/VSS/JCS/HSM/attestation/member signature/batch/MemberArtifact 生产 providers。
3. 以真实网关/KMS 验证 Pool prepare/activate-held/commit、credential fingerprint gate 和 at-most-once claim。
4. 独立审查离线 verifier，再接线受控 bundle 导出与 Reveal 授权服务；decrypt/reconstruct/unwrap/plaintext
   executor 必须另立安全阶段和门禁，之后再评估多副本、最终用户会话/RBAC 和更多供应商 adapter。
