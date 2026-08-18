# 故障处理与运维手册

## 0. Seat 开通

1. 管理员先在 Sub2API 准备并核对 Pool 对应的独占 Group；运行账号和 Group 不由平台开通接口创建。
2. 调用 `POST /api/v1/seats`，提交稳定 `operation_id`、`existing_group_id`、未来的
   `subscription_expires_at`，以及可选 Principal/API Key 限额。
   平台内部使用独立 `seat:provision` scope 调用 Sub2API
   `POST /api/v1/integrations/trusted-pools/seats/provision`；`seat:write` 密钥不得用于开通。
3. 只有首次响应同时包含 ACTIVE Seat、`PROVISION/SUCCEEDED` Operation 和 claim token，才能进入领取；
   token 只出现一次，后续 provision 重放和操作查询不会返回。
4. owner 在 `credential_claim_expires_at` 前使用 claim token 调用 `credential-ack`。平台先以独立
   `credential:ack` scope 向 Sub2API 提交稳定 claim operation ID、owner 和 credential fingerprint；只有
   上游明确确认后才一次性返回 API Key。
5. ack 超时或响应无法验证时，不得披露 credential；使用同一 token 重放平台领取接口，由平台以同一
   claim operation ID 对账。TTL 到期立即销毁待交付 credential 与 token 摘要，即使迟到 ack 成功也不交付。
   Sub2API ack 明确成功后，平台会持久化 typed snapshot；只要 Claim 尚未消费且 token 未过期，进程重启后
   仍可继续领取。平台一旦把 Claim CAS 为 `CLAIMED` 并清除包络，随后发生进程退出或 HTTP 响应丢失时，
   原 credential 按 at-most-once 规则永久不可恢复，运营人员必须重新开通或轮换。
6. provision 超时、503 或结果未知时，不创建新 operation_id，也不得手工创建本地 ACTIVE Seat；原请求体不变地
   重放创建接口。内容漂移会返回幂等冲突。
7. 分阶段批量开通按 Seat 独立重放；全部 Seat 明确成功前 Pool 保持 `PROVISIONING`。既有 Group 若包含
   普通用户 Subscription/API Key，Sub2API 会拒绝绑定，不得通过直接改库绕过隔离检查。

## 1. 违约暂停与换员

1. 运营人员创建暂停工单，填写原因和证据引用。
2. 平台调用 Seat suspend，业务状态显示 `SUSPEND_PENDING`。
3. 在操作详情确认资源侧已 `BLOCKED`，旧凭据的新请求已被拒绝。
4. 等待资源侧 `DRAINING` 完成；不得手工跳过。
5. 确认连续两次严格并发读数均为 0 且 `pending_settlements=0`。任一 pending 未清除时先完成
   用量对账，不得直接删除数据库记录或强制冻结。
6. 校验 `freeze_snapshot` 中的 Seat、epoch，以及 `usage_snapshot` 的小时、日、周、月用量和窗口起点。
7. 状态达到 `FROZEN` 后，选择临时分配、永久替换或恢复。
8. 新 Assignment 生效后执行最小权限调用测试。
9. 原始换员响应中的 claim token 只交给目标成员；平台仅保存 token 摘要。成员在 TTL 内携带自身 ID 和
   token 调用 `credential-ack`，一次性领取新访问凭据并立即清除摘要与交付值。
10. 记录处理结论和证据，不删除原风险事件。

## 2. 暂停结果未知

当 suspend 超时或连接中断时：

- Seat 保持 `SUSPEND_PENDING`，操作进入 `RECONCILE_REQUIRED`，禁止创建新 Assignment。
- 使用相同 `operation_id` 查询操作状态，不生成新 ID 重试同一意图。
- 同时查询 Seat 实际状态和 Key 版本。
- 无法确认时告警并使用 Sub2API 受控管理入口执行应急禁用。
- 应急操作完成后仍需运行对账，禁止直接手工改数据库状态。

## 3. Sub2API 不可用

- Pool 与成员信息仍可只读展示。
- 暂停、恢复、换员和运行凭据更新均返回暂不可执行。
- 已提交命令保持 `RETRYABLE`，指数退避并设置最大间隔。
- 只有查询确认实际结果后才更新业务状态。
- 开通操作没有本地 Seat 可供查询时，以相同 operation_id 重放 provision，由上游幂等记录恢复结果；
  本地 Seat 仍须等待上游明确成功才创建。

### 3.1 持久结算屏障未清除

可信 Seat 每个已准入请求都有一条 `pending_settlement`。正常同步结算完成后精确删除；计费错误、
panic、超时或删除失败时记录保留，因此 drain/freeze 返回非零 `pending_settlements` 并拒绝冻结。
运营人员使用普通平台密钥调用 `GET /api/v1/seats/{id}/settlements` 和详情接口，按 Seat、Epoch、
`settlement_id`、`request_id`、`billing_id`、错误与尝试次数核验。确认账本已补记或请求确实未消费后，
使用独立 `TRUSTED_POOL_SETTLEMENT_API_KEY` 调用
`POST /api/v1/seats/{id}/settlements/{settlement_id}/resolve`，提交稳定 `operation_id`、理由和证据引用。
平台内部再分别以 Sub2API `seat:read` 和 `settlement:resolve` scope 代理请求；运营人员不得直接持有
Sub2API 集成密钥。Sub2API 在同一事务追加不可变审计并删除精确 pending；相同操作可幂等重放，
内容漂移返回冲突。禁止直接删除数据库记录，也不得把 resolve 当成实际补账动作。

## 4. Outbox 与对账

- 业务状态和 outbox 事件在同一数据库事务提交。
- 投递失败不回滚已完成业务事务，由后台任务重试。
- 定时扫描非终态 `integration_operations`，查询 Sub2API 实际状态。
- 对账差异进入 `RECONCILE_REQUIRED` 并告警，不自动执行可能扩大权限的修复。

## 5. 风险观察处置

设备数突增、并发持续重叠或地理位置异常只产生 `RiskFinding`。运营人员结合流式请求、异步任务、
网络切换等正常场景复核。确认需要止损时，单独创建暂停工单；不得由风险任务直接禁用 Key。

## 6. 密钥轮换

- 集成凭据和 HMAC Key 支持重叠轮换，轮换期同时接受当前和下一版本。
- 指纹 HMAC Key 轮换后保留算法版本；不尝试把不同版本散列强行关联。
- 永久换员先由运营或外部系统核验供应商登录、MFA、恢复和所有权变更证明的真实性，保留不透明的
  `provider_attestation_ref`；Phase 1 平台不校验供应商签名或证明的密码学真实性。
- 完成新旧 Epoch 的四类控制批次切换：旧 `LOGIN`、`MFA`、`RECOVERY`、`OWNERSHIP` 全部退休，
  新相邻 Epoch 对应批次全部激活，再携带 `provider_attestation_ref` 调用
  `POST /api/v1/control-rotation-evidence` 签发证据。
- 将证据 ID 作为 `control_rotation_evidence_ref` 提交；Coordinator 会按 Seat Pool 和相邻 Epoch
  复核证据绑定的供应商证明引用及八个批次状态。Sub2API Seat 访问 Key 轮换不能替代该证据。
- 永久换员成功后确认 Pool 最小 Membership Epoch 已提升到新 Epoch；旧 Epoch 的 Seal/Activate
  请求应稳定失败。
- Phase 1 到此只完成暂停/冻结、Seat 访问 Key 轮换、外部 attestation 引用和控制批次状态机验证，
  不生成或签署 Recovery Root、Recovery Share、Manifest；其成功结果不得作为完整永久交接凭据。
- 生产 permanent replace 必须保持待治理状态，等待 Phase 2 recovery governance 生成新 Recovery Root、
  分发新 Share、发布并签署 Manifest，且门禁全部通过后，才允许确认永久交接完成。
- KMS 轮换优先执行 DEK 重包；怀疑明文泄露时必须同时轮换真实凭据。

## 7. 监控与告警

至少监控：

- 暂停从请求到 `BLOCKED`、`FROZEN` 的延迟。
- 长时间 `SUSPEND_PENDING` 和 `RECONCILE_REQUIRED` 数量。
- 集成接口错误率、超时率和幂等冲突。
- 在途租约超时回收数量。
- 长时间未清除的 `pending_settlements` 数量与最旧年龄。
- 活动 Seat 与活动 Assignment 数量不一致。
- Credential Batch 长时间停留在非终态。
- Outbox 最旧未投递事件年龄。

指标标签不得包含 API Key、原始指纹、用户 JWT 或任何凭据字段。

## 8. Phase 2-A 运行与重启限制

Provision、Operation、Seat/Owner Assignment 和 Provision Claim 已接入 PostgreSQL。重启后可读取已提交
状态，并通过数据库 lease/fencing 接管结果未知的 ack；成功 Operation 不会重放上游或重新签发 token。
Provision 在本地提交前中断时，由原调用方使用相同请求和 operation ID 重放。恢复 worker 会把该状态标记
为 `CALLER_REPLAY_REQUIRED`，但不会自行生成调用方无法取得的新 token。

暂停、换员、settlement 和 credential batch 尚未持久化，在 PostgreSQL Runtime 中失败关闭；不得切回
内存 Coordinator 继续操作。风险窗口仍是可丢失观察信号。

虽然代码已使用持久 CAS/租约，本阶段尚未完成真实 PostgreSQL 双连接和多实例崩溃测试，因此仍禁止
多副本、蓝绿重叠和 rolling update overlap。升级时先停止旧实例，再启动新实例。生产 KMS adapter、
真实数据库恢复演练和多实例竞争测试全部通过后，方可调整该限制。

旧版 initdb 开发卷没有 migration ledger，当前服务会以 `ErrUnmanagedSchema` 拒绝启动。开发卷可以重建；
生产数据库必须备份并走受控 baseline，禁止自动认领或直接删除。
