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
Sub2API 已保存 Seat、Epoch、`settlement_id`、`request_id`、`billing_id`、错误和尝试次数。运营先用独立
只读客户端 list/get，确认补账或上游结果后，再用 `TRUSTED_POOL_SETTLEMENT_API_KEY` 提交 resolve；Header
`Idempotency-Key` 必须等于 body `operation_id`，并携带读到的 expected epoch/request ID。平台先持久化
9 键 intent，再使用只含 `settlement:resolve` scope 的独立 actor 调用 Sub2API。结果未知保持禁用并按原
operation 恢复；未决 intent 禁止换员。resolve 只记录核验结论，不替代实际补账，禁止直接删除数据库记录。

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
- Credential Batch 使用独立 `TRUSTED_POOL_BATCH_API_KEY` 和独立 operation client ID。Seal/Activate/Retire
  的 `Idempotency-Key` 必须与 body `operation_id` 一致；请求重放不得更换 Pool、账号、类型、版本、Epoch 或 payload。
- Seal 只有在线 KMS 与 Recovery wrap-only adapter 都 ready 才开始持久 intent；包装发生在数据库事务外，
  最终提交会重新核对 Pool 当前 ACTIVE Epoch 和 credential floor。PREPARED 表示包装进行中，不能视为可用凭据。
- Recovery wrapper 仅允许 Wrap。当前在线服务没有 Recovery Unwrap、Share 或 Reveal 能力；生产不得配置环境
  Recovery KEK，不得复制在线 wrapped DEK 到 recovery 列。
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

## 8. Phase 2-G 运行与重启限制

Provision、Operation、Seat/Owner Assignment、Provision Claim 和 Suspend/Drain/Freeze 已接入 PostgreSQL。重启后可读取已提交
状态，并通过数据库 lease/fencing 接管结果未知的 ack；成功 Operation 不会重放上游或重新签发 token。
Provision 在本地提交前中断时，由原调用方使用相同请求和 operation ID 重放。恢复 worker 会把该状态标记
为 `CALLER_REPLAY_REQUIRED`，但不会自行生成调用方无法取得的新 token。

暂停与换员恢复线程都从持久 request snapshot 重建命令。暂停结果未知保持 `SUSPEND_PENDING` 或
`DRAINING`；临时换员/恢复结果未知保持 `ASSIGNMENT_PENDING`。无法证明上游未应用的普通 4xx 进入
`OPERATOR_REVIEW_REQUIRED`，不会自动恢复 ACTIVE。结算解除的 timeout/5xx/坏响应进入自动恢复，普通
4xx 进入人工复核；两者都不会声明上游未执行。Credential Batch 已接入独立 Store，不得切回内存 Manager；
旧单 Seat 永久换员和旧 control rotation evidence 继续失败关闭。Pool finalize 已接入持久三阶段恢复；风险窗口
仍是可丢失观察信号。

历史 Seat 若缺少稳定 Principal、Subscription 或 API Key ID，迁移 005 只会从字段完整的成功 Provision
快照回填；无法证明绑定的记录保持可读但拒绝 BeginAssignment。运营必须先完成受控对账或重新开通，
不得手工填充猜测的资源 ID。

通用 Operation、Credential Claim、Credential Batch 与 Recovery plan/finalization 的持久 CAS/租约已通过
真实 PostgreSQL 双连接接管、单赢家与旧 fence 拒绝；finalization 的外部副作用边界和 token 签发边界也已
完成响应丢失续跑测试。两 Seat 部分 prepare 的不同 owner 接管、同 Pool Suspend/Provision 双连接竞争，
Credential Batch retire/finalization 同 Pool 双向裁决，以及 provider commit durable 写入后的真实子进程
退出、不同 owner/fence 精确回放也已通过；这里的 provider 是测试专用 file-backed 幂等实现，不是生产
Sub2API/provider E2E。两 Seat activation 响应丢失由确定性单元门禁覆盖；更广的跨工作流
多副本矩阵和其余外部副作用边界联动真实 provider 的进程退出端到端尚未完成，因此仍禁止多副本、蓝绿重叠和
rolling update overlap。
升级时先停止旧实例，再启动新实例。生产在线 KMS、Recovery
Root/VSS/JCS/HSM/attestation/member/batch/MemberArtifact providers、真实数据库恢复演练和多实例竞争测试
全部通过后，方可调整该限制。

### 8.1 Recovery 治理与最终化面

- 保持 `TRUSTED_POOL_RECOVERY_GOVERNANCE_ENABLED=false`。当前二进制没有生产 Root/JCS/HSM/VSS、
  attestation、member gateway 或 batch provider；误设为 true 应在监听端口前失败，不能绕过。
- 后续链接 provider 时，Recovery API Key 和 client ID 必须与普通、settlement、batch 入口全部分离。
- 运营只能把 plan `READY` 解释为准备材料完整。必须通过 Pool finalize 推进，不得手工启用 API Key、激活
  新 Epoch、退休旧批次或修改 Owner。
- `POST /api/v1/recovery-plans/{id}/finalize` 可返回 202 继续处理中或 200 已 `FINALIZED`；只有第一次完成
  token 签发的 200 响应携带 claims。旧 `/seats/{id}/actions/replace` 固定 503。
- 真实 PostgreSQL 16 空库 `001 -> 011`、`010 -> 011` 停机迁移账本、已有数据 `009 -> 010`，以及通用
  Operation/Credential Claim、
  Credential Batch、Recovery plan/finalization 双连接 lease/fence、Suspend/Provision 同 Pool 竞争和
  Credential Batch retire/finalization 同 Pool 竞争已通过；provider commit 边界也以测试专用 durable provider 验证
  仅执行一次、进程退出后 PostgreSQL 保持 pending、新 owner/fence 精确回放。更广的跨工作流多副本、其余
  外部副作用边界进程退出，以及所有真实 providers 的就绪与故障演练仍是发布门禁。
- Migration 011 只允许升级前已有的 009 Seat snapshot 被当前 typed Manager 以同一领域 hash 和 operation
  接管。旧 shape 必须精确包含 `protocol_version`、`plan_id`、`pool_id`、`seat_id`、`target_member_id`、
  `from_epoch`、`to_epoch`；历史审计快照不改写。011 后新建 operation 只能写 typed snapshot，旧格式新写入会在
  Store 和数据库触发器两层失败。混合字段、别名、未知字段、hash、业务字段或 Pool 内嵌 Seat 漂移均失败关闭。
  当前 typed Seat prepare、Pool prepare 与 Pool activation 已通过公开 Store 入口和真实触发器。

#### Migration 011 停机升级步骤

1. 保持单实例并先停止旧进程，排空正在提交的业务事务；禁止 rolling overlap 或蓝绿双写。
2. 备份数据库，再由独立 migration owner 从 ledger `010` 应用 `011`。迁移失败会事务回滚；新版进程和
   recovery worker 在 ledger 未到 `011_phase2h_recovery_protocol_compatibility.sql` 前不得启动。
3. 核对 ledger 最新文件和 checksum，不得手工修改 operation snapshot、request hash、lease 或 fence。
   011 会在原 operation ledger 内给升级前记录写入不可变兼容标记；新记录默认无兼容资格，伪造创建时间或
   手工修改标记都会被触发器拒绝。该设计不新增 runtime 角色的表权限。
4. 等数据库时钟判定停机遗留 lease 过期后，由新版使用原 operation/hash 和 expected fence 接管；legacy
   snapshot 保持原样。真实 PostgreSQL 测试已在 010 下创建一条在途 009 operation，使其穿过 011 DDL，再由
   新 owner/fence 接管；错误外层 hash、typed 字段漂移和 011 后 legacy 新建都原子拒绝。
5. 新版写入 typed snapshot 后禁止降级到不识别该 shape 的旧二进制。011 没有 down migration；回退只能
   恢复升级前备份或 forward-fix。011 只提供协议兼容，不解除单实例发布门禁。

### 8.2 永久换员卡点处置

详细的状态判定、证据留存、签名键故障和发布前进程退出演练见
[永久凭据轮换 Fail-Forward 故障续跑手册](permanent-rotation-fail-forward-runbook.md)。

- `rotation_prepared`：新 credential 仍在 Sub2API 受限暂存区且所有资源禁用。只以原 operation/hash 重放，
  禁止另建 operation 或直接清理记录。当前暂存是数据库明文且无 TTL/cleanup，只允许受控开发与演练。
- 平台 case `ROTATING`：recovery worker 可接管并精确重放 prepare/activate；子 operation 的
  `RECONCILE_REQUIRED` 表示外部结果未知，需要原请求精确重放，不是新的 case 状态。
- 平台 case `READY_TO_COMMIT`：activation 已持久，worker 只能复核后停止。必须由携带原 finalize 意图的
  同步调用执行平台结构事务，随后 case 才进入 `PROVIDER_COMMIT_PENDING`。
- `rotation_activated_pending_commit` 是 Sub2API held 状态；`PROVIDER_COMMIT_PENDING` 是平台结构事务已提交
  后的 case。只有后者允许 worker 精确重放 Sub2API commit；普通 suspend/freeze 不能穿透 held 状态。
- Sub2API commit 已成功但回执丢失后，即使后续 suspend/freeze 把父记录推进为 `retiring`，原 commit 仍可
  返回历史签名回执且不得重新启用资源。若记录已 `superseded` 或 fingerprint 漂移，则稳定冲突并人工复核。
- `READY_TO_ISSUE`：provider release 已证明，等待原调用方重放 finalize 生成首次 token。worker 和 GET
  不生成 token。
- `FINALIZED` 后响应丢失：token 不可恢复或重发。管理员必须发起新的受控凭据轮换，不得重置 claim 状态。
- replacement claim 领取必须使用 recovery API key、路径 child operation ID 作为 Idempotency-Key，并核对
  Seat 与目标成员。该 key 是管理员代交付服务凭据，不是成员身份。

轮换客户端必须与其他 Sub2API client 分离且只持有 `seat:permanent-rotate`；检查平台配置的 Ed25519 public
key 与 Sub2API private key 的 key ID 配对。签名、fingerprint gate、durable outbox，activation 至少
`2 * Seat 数` 的事件证据，或 commit/release 至少 `Seat 数` 的事件证据任一缺失时不得人工放行。详见
[Phase 2-G Pool 级永久换员最终化状态](phase2g-permanent-finalization-status.md)。

旧版 initdb 开发卷没有 migration ledger，当前服务会以 `ErrUnmanagedSchema` 拒绝启动。开发卷可以重建；
生产数据库必须备份并走受控 baseline，禁止自动认领或直接删除。

生产部署必须分别提供 `TRUSTED_POOL_MIGRATION_DATABASE_URL` 与 `TRUSTED_POOL_DATABASE_URL`。前者是短时
migration owner，只在启动迁移期间连接并在迁移结束后关闭；后者是长期运行身份，只授予业务 schema 的
`USAGE`、表 `SELECT/INSERT/UPDATE`、序列 `USAGE/SELECT` 和所需函数 `EXECUTE`，不得授予建表、改表、删表、
建角色或数据库 owner 权限。生产配置复用同一 DSN 会在监听前失败；开发模式可留空迁移 DSN 并复用本地账号。

### 8.3 Phase 2-H 离线验证操作边界

1. 只从受控介质取得 Evidence Bundle、独立 trust policy、可选 Reveal intent/approvals；分别记录 SHA-256、
   来源、交付人和时间。不得把 Bundle 内 key 当作 trust policy。
2. 在断网或明确无网络依赖的主机运行 `recovery-verifier verify`。输出必须完整保存，`VERIFIED` 才表示公开
   transcript 通过；`INCOMPLETE` 和退出码 2 不得人工改写为成功。
3. 历史签名返回 `LEGACY_UNSUPPORTED`、或缺 typed provider proof 返回
   `PROVIDER_EVIDENCE_INCOMPLETE` 时，保留结果并走公开证据补齐/重新生成流程，禁止数据库回填伪造 domain。
4. `reveal-authorize` 需要显式 UTC `-at` 时间和全部本地输入。`POLICY_UNAPPROVED` 与
   `AUTHORIZED_NOT_EXECUTABLE` 都使用退出码 2；后者只表示签名授权记录成立，不表示可执行恢复。
5. 在线 bundle 导出只允许 recovery key 调用 `/api/v1/recovery-plans/{id}/verification-exports`，且要求
   portable profile、独立 client 和外部 signer；当前组合根缺 signer 时启动失败。仍没有 Reveal API。
   不得直接 DML 创建 `AVAILABLE` export、授权或 executor receipt，也不得手工拼装含秘密的“bundle”。

Migration 010/011 已在真实 PostgreSQL 16 通过空库 `001 -> 011`、历史 `009 -> 010`、停机迁移账本 `010 -> 011`、
Reveal fail-closed DML、公开 legacy/typed recovery snapshot 接管、通用
Operation/Credential Claim 并发 fence 和最小权限运行身份；只追加/延迟聚合的剩余业务写入矩阵、回滚与
完整进程恢复演练仍须完成。生产 Root/JCS/HSM/VSS/attestation/member/batch/
MemberArtifact providers 仍缺失，governance 开关保持关闭。完整边界见
[Phase 2-H 离线验证与 Reveal 授权记录基础状态](phase2h-offline-verification-status.md)。
