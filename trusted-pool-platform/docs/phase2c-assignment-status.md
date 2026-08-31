# Phase 2-C 换员运行时状态

> 历史阶段快照：本文保留 Phase 2-C 当时的范围和证据，不代表当前完整能力。当前状态与发布门禁以 [Phase 2-H 状态](phase2h-offline-verification-status.md) 和[全仓路线图](../../docs/PROJECT_CAPABILITIES_AND_ROADMAP_CN.md)为准。

## 已接线能力

Phase 2-C 在已持久化的 Provision 与 Suspend/Drain/Freeze 之上，开放 `ASSIGN_TEMPORARY` 和 `RESTORE`：

1. 仅允许从 `FROZEN` Seat 发起，且冻结快照必须绑定当前 assignment epoch。
2. `BeginAssignment` 在调用 Sub2API 前锁定 Operation、Pool、当前 Membership Epoch、Seat、当前 Assignment、
   目标成员和冻结工单；创建 PENDING Assignment，将 Seat 置为 `ASSIGNMENT_PENDING`，并取得数据库 lease/fence。
3. 临时分配的目标必须是当前正式成员快照中的非 Owner、非当前成员；恢复目标只能是数据库锁定的 Owner。
4. Sub2API rotate 响应必须匹配 Pool、Seat、operation、源/目标 epoch、稳定 Principal、Subscription、API Key ID，
   并明确确认访问凭据已轮换。平台的 active API Key version 与 assignment epoch 同步递增。
5. 成功时，旧 ACTIVE Assignment 结束、PENDING Assignment 激活、Seat 恢复 ACTIVE、Operation 完成及加密
   READY Claim 创建在同一事务提交。Pool Membership Epoch 和 Owner 不变。
6. 恢复 worker 与显式 reconcile 从持久 request snapshot 和 AssignmentCase 重建命令，不依赖 Sub2API
   客户端内存 map，不生成新的 operation ID。
7. 临时换员/恢复产生的 Claim 不重复调用 Provision credential ack；目标成员通过本地 lease、KMS 解密和
   fenced CAS 一次领取。平台只保存 token SHA-256 和 KMS 包络，领取后清除全部秘密。

## 失败关闭

- 超时、5xx、坏包、资源身份或 epoch 错配都保持 `ASSIGNMENT_PENDING` 并进入 `RECONCILE_REQUIRED`。
- 普通 4xx 不能证明上游完全未应用，统一进入 `OPERATOR_REVIEW_REQUIRED` 并从自动扫描排除；不得自动
  恢复 FROZEN 或以新 operation ID 再次轮换。
- 只有未来获得可验证的“上游明确未应用”证据，才允许聚合事务取消 PENDING Assignment 并回到 FROZEN；
  当前应用流程不使用该分支。
- 成功 Operation 缺少 Seat 或 Claim 视为持久聚合损坏，返回 503，不伪装成 404。
- 历史 Seat 缺 Principal、Subscription 或 API Key 稳定 ID 时仍可查询，但 BeginAssignment 失败关闭。
  迁移 005 只从字段完整且无冲突的成功 Provision 快照回填；其他记录必须受控对账或重新开通。

## 未开放能力

永久换员仍返回 503。它必须等待 Recovery Root、Recovery Share、Manifest、控制凭据轮换证据和生产
KMS/HSM 治理闭合。Pending settlement 代理已由后续 Phase 2-D 接入，Credential Batch 已由 Phase 2-E
接入持久双包装底座；Control Rotation Evidence 继续返回 503，不得复用普通 Sub2API 集成凭据绕过独立 scope。

## 验证与发布门禁

当前已通过 Go 全包测试、Store/Coordinator/Client/HTTP 契约测试和 `go vet`。生产或封闭试点前仍必须：

- 在真实 PostgreSQL 16 执行空库 `001 -> 005` 与带 Phase 2-B 数据的 `004 -> 005` 升级，验证历史 ID 回填与
  无可信证据记录的 fail-close 行为。
- 以双连接交错验证统一 `Operation -> Pool -> Membership -> Seat` 锁序、lease 接管、旧 fence 拒绝、同一
  冻结工单唯一消费和并发 Claim 竞争。
- 对 Begin、Sub2API rotate、KMS Seal/Open、成功聚合提交和 HTTP 响应前后执行崩溃注入。
- 扫描数据库、日志、错误和 trace，确认不存在 credential、claim token、未包装 DEK 或原始设备指纹。
- 接入并演练生产 KMS/HSM adapter；门禁通过前保持单副本，禁止 rolling overlap。
