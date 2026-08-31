# Phase 2-B 暂停运行时状态

> 历史阶段快照：本文保留 Phase 2-B 当时的范围和证据，不代表当前完整能力。当前状态与发布门禁以 [Phase 2-H 状态](phase2h-offline-verification-status.md) 和[全仓路线图](../../docs/PROJECT_CAPABILITIES_AND_ROADMAP_CN.md)为准。

## 已接线能力

Phase 2-B 在 Phase 2-A 的持久 Provision/Claim 基础上，新增 PostgreSQL Suspend/Drain/Freeze 纵向链路：

1. `POST /api/v1/seats/{id}/actions/suspend` 使用稳定 `Idempotency-Key`。
2. 平台在调用 Sub2API 前，同事务创建或核对 `SUSPEND` Operation、创建 `SuspensionCase`、取得数据库
   lease/fencing token，并把 ACTIVE Seat 置为 `SUSPEND_PENDING`。
3. 上游返回排空中时，平台保存真实 `current_concurrency` 与 `pending_settlements`，Seat 和 case 进入
   `DRAINING`，Operation 保持 `RECONCILE_REQUIRED` 并设置下次扫描时间。
4. 只有两个屏障明确为零，且小时、日、周、月用量与窗口起点、operation、assignment epoch 和采集时间
   全部有效时，Operation、Seat、case 和 freeze snapshot 才在同一事务进入终态。
5. 显式 reconcile 和恢复 worker 都从持久请求快照重建 `operation_id + seat_id + assignment_epoch`，不依赖
   Sub2API 客户端的内存 operation map。
6. Provision 与 Suspend 均先锁各自 Operation，再独立取得公共 Pool 行锁，之后才锁成员和 Seat；同一成员池
   不允许形成 Pool/Seat 反向锁序。

当前暂停入口固定记录 `reason_code=MANUAL_POLICY_BREACH`，`requested_by` 为 NULL，表示由受控服务/运营入口
触发但尚未接入最终用户会话与 RBAC。风险观察不会自动调用该入口。

## 失败关闭

- 上游超时、5xx、坏响应或返回不完整屏障时，Seat 保持 `SUSPEND_PENDING` 或 `DRAINING`，绝不回到 ACTIVE。
- suspend、drain-status 和 freeze 响应必须完整匹配请求的 Pool、Seat 与 assignment epoch；字段缺失或错配
  一律按结果未知处理，不写入其他 Seat 的观察或冻结证据。
- DRAINING 对账失败时保留最后一次真实屏障计数，不用默认零覆盖。
- 明确的上游 4xx/资源冲突记为 `OPERATOR_REVIEW_REQUIRED`，从自动扫描排除；人工仍可使用原 operation
  执行显式 reconcile。
- 通用 `CommitOperation` 不能直接完成 SUSPEND。迁移 004 使用延迟约束，在事务提交时核对 Operation、
  Seat 和 SuspensionCase 的聚合状态。
- 本文记录 Phase 2-B 的阶段边界；后续 Phase 2-C 已在 FROZEN 后开放持久临时分配与正式恢复，永久换员仍返回 503。

## 未开放能力

本节记录 Phase 2-B 当时的边界；pending settlement 代理已由后续 Phase 2-D 接入，当前能力以
[Phase 2-D 结算解除运行时状态](phase2d-settlement-status.md)为准。

Phase 2-B 当时尚未接入独立的出站 `settlement:resolve` 客户端凭据，因此 list/get/resolve 三个代理端点
当时固定返回 503。该限制已由 Phase 2-D 闭合；Pending settlement 的唯一账本和不可变 resolution 审计
仍位于 Sub2API，且不能复用普通 Seat 集成凭据降级开放。

临时换员与恢复已由后续 Phase 2-C 接入，pending settlement 由 Phase 2-D 接入，Credential Batch 由
Phase 2-E 接入；Control Rotation Evidence 和永久换员仍未接入持久运行时。旧内存实现只保留为领域测试
参考，不参与当前组合根。

## 验证与上线门禁

当前已通过 Go 全包测试、Store/Coordinator/Client 契约测试和 `go vet`。上线前仍必须完成：

- 在真实 PostgreSQL 16 上执行空库 `001 -> 002 -> 003 -> 004` 和带历史数据升级。
- 双连接 lease 接管、旧 fence 提交拒绝、不同 operation 并发暂停同一 Seat，以及同 Seat 的 Provision 完成与
  Suspend 交错；要求公共 Pool 锁序无死锁，或数据库异常由可恢复路径接管。
- 在 Begin、Sub2API suspend、drain-status、freeze 和本地提交前后做进程崩溃注入。
- 验证并发与 pending settlement 四种组合，任一非零都不会调用 freeze。
- 生产 KMS/HSM adapter、多实例竞争和完整敏感数据扫描。

上述门禁未通过前继续单副本部署，升级必须先停止旧实例，禁止 rolling overlap。
