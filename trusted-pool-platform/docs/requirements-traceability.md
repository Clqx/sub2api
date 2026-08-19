# 原方案需求追踪

本文把《可信有限成员订阅共享平台可行性方案 V1.0》、后续需求补充与当前实现逐项对应。附件中的描述只作为
研究输入；本项目执行范围以用户明确要求、当前架构决策和阶段验收为准。

| 需求 | 当前责任边界 | 状态 | 证据或下一步 |
|---|---|---|---|
| 额度控制 | Sub2API Group、Subscription、API Key 原生窗口与 RPM | 已接入 | Seat 使用稳定 Principal/Subscription/API Key；冻结快照保留四窗口用量 |
| 分组与账号资源 | Sub2API 独占 Group、Account 调度、Seat Principal | 已接入 | provision 只绑定预建独占 Group；Seat principal 禁止交互登录 |
| 人员动态调整 | 新平台 Seat/Assignment 状态机 | 已接入开发闭环 | 暂停后冻结，支持临时换员与正式成员恢复；结果未知保持禁用 |
| 临时违约先暂停 | 新平台 + Sub2API 双屏障 | 已接入 | SUSPEND_PENDING -> DRAINING -> FROZEN；并发与 pending settlement 必须同时归零 |
| 分阶段密钥批量 | 新平台 Credential Batch/Recovery 治理 | Phase 2-E 已接入批次底座 | Seal/Get/Activate/Retire 持久化；在线 KMS + 独立 Recovery 双包装；不开放在线 Recovery Unwrap |
| 账号控制凭据轮换 | 新平台治理，Sub2API 只轮换访问 Key | 未完成生产门禁 | 永久换员不得把 Sub2API API Key rotate 当作登录/MFA/恢复/所有权轮换证明 |
| pending 用量失败处理 | Sub2API 权威账本 + 新平台持久 intent | Phase 2-D 已接入 | 独立 read/resolve 身份、epoch/request 精确绑定、append-only 审计、重启恢复 |
| 设备指纹与并发观察 | Sub2API 网关 + 新平台风险聚合 | 部分实现 | 并发是冻结硬门禁；IP/User-Agent HMAC 组合仅作风险信号，不作认证或自动封禁 |
| Recovery Root/Share/Manifest | 新平台 Trust Plane | 未实现 | Phase 2-E 只保存独立 Recovery 包装；永久换员保持失败关闭，仍需 Root/Share/Manifest 与离线验证工具 |
| 多人恢复与揭示仪式 | 新平台 Trust Plane | 未实现 | 需阈值 Share、签名 Manifest、Reveal 审计与离线 verifier |
| 供应商适配与合规矩阵 | 独立 adapter/运营流程 | 未实现 | 当前只验证外部证据引用非空，不验证供应商签名真实性 |
| 交易、支付、退款、担保 | 商业系统 | 不在当前开发范围 | 不与可信池核心状态机耦合，需单独立项 |

## 当前可行性结论

额度、分组、稳定 Seat 资源和账号调度继续依赖 Sub2API 是合理边界；成员身份、暂停换员、凭据交付、审计与
恢复治理应由独立平台实现。Phase 2-E 在既有“暂停、双屏障冻结、临时换员/恢复、失败结算受控解除”链路上，
补齐了分阶段凭据批次的双包装持久化底座；但在真实 PostgreSQL 并发/升级、崩溃注入、生产 KMS/HSM 和 Recovery 治理完成前，不能
宣称生产永久换员可用。

## 后续顺序

1. 在 PostgreSQL 16 完成迁移、双连接 fencing、跨工作流并发和崩溃恢复门禁。
2. Phase 2-F 持久化外部控制轮换证据，但永久换员继续受 Recovery 治理门禁。
3. 实现 Recovery Root、阈值 Share、签名 Manifest、离线 verifier 与 Reveal Ceremony，并消费 Phase 2-E 的 Recovery 包装。
4. 在上述门禁完成后再评估多副本、生产 KMS/HSM、最终用户会话/RBAC 和供应商 adapter。
