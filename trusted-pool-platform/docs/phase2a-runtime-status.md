# Phase 2-A 持久运行时状态

> 历史阶段快照：本文保留 Phase 2-A 当时的范围和证据，不代表当前完整能力。当前状态与发布门禁以 [Phase 2-H 状态](phase2h-offline-verification-status.md) 和[全仓路线图](../../docs/PROJECT_CAPABILITIES_AND_ROADMAP_CN.md)为准。

更新时间：2026-08-18

## 阶段结论

本阶段已经把最小可恢复链路接入 PostgreSQL：

1. Provision 请求先持久化规范请求快照，再取得数据库 lease 和 fencing token。
2. Sub2API 明确返回 ACTIVE 后，Pool/Owner 前置条件校验、Seat、活动 Assignment、Operation 成功和加密 Claim 在同一事务提交。
3. claim token 仅保存 SHA-256；credential 使用 AES-256-GCM 数据密钥和 KMS 包络，不进入 Operation 快照、错误或日志。
4. 领取先在数据库写 `ACK_PENDING`，再调用 Sub2API credential ack；只有 typed ack 持久成功后才在事务外解密，并以 fenced CAS 置为 `CLAIMED` 后向本次 HTTP 响应披露。
5. 结果未知写入可恢复状态，明确拒绝与过期 Claim 原子清除 token 摘要和完整包络。
6. 恢复 worker 使用 `SKIP LOCKED` 和数据库时钟发现工作；`CALLER_REPLAY_REQUIRED` 不会被后台反复扫描。

这证明了持久化运行时的代码边界，不等于生产可用。真实 PostgreSQL 和生产 KMS/HSM 验证仍未完成。

## 当前开放能力

本节记录 Phase 2-A 当时的开放边界；后续 Phase 2-B/2-C/2-D 已增量接入暂停/冻结、临时换员/恢复与
pending settlement 查询/解除，当前能力
应以根 README 和对应阶段状态文档为准。

PostgreSQL Runtime 只开放以下持久能力：

- `POST /api/v1/seats`：在可信预建 Pool 和 Owner Member 上开通 Seat。
- `GET /api/v1/seats/{id}`：读取已持久化 Seat 和当前活动 Assignment。
- `GET /api/v1/operations/{id}`：读取持久 Operation，不返回 token 或 credential。
- `POST /api/v1/operations/{id}/credential-ack`：Provision credential 一次性领取。
- `/health` 与 `/ready`：分别表示进程存活和 PostgreSQL/KMS 就绪。

暂停、临时分配、正式成员恢复、永久换员、显式 reconcile、pending settlement 管理、credential batch
和 control rotation evidence 尚未接入 PostgreSQL 工作流，统一返回 503
`PERSISTENT_WORKFLOW_UNSUPPORTED`。风险窗口仍为内存观察数据，重启可丢失，不能用作认证或自动封禁。

## 数据与密钥前置条件

- PostgreSQL 必须是平台独立数据库，禁止复用 Sub2API 数据库。
- Pool、ACTIVE Membership Epoch、`membership_epoch_members` 正式成员快照和 Owner Member 必须由受控
  运营流程预创建。Pool 必须有正的 Membership Epoch，Owner Member 必须 ACTIVE 且属于该当前 Epoch，
  Pool `sub2api_group_id` 必须等于 Provision 请求的 `existing_group_id`。
- 开发模式只有在 `development + local + TRUSTED_POOL_ALLOW_INSECURE_LOCAL_KEK=true` 三项同时满足时
  才允许本地 KEK。该模式不得承载生产数据。
- 生产模式强制 KMS。仓库当前只定义 adapter 边界，未链接具体云 KMS/HSM provider；nil adapter
  会导致启动失败，不存在明文或本地 KEK 回退。

## 迁移策略

启动 runner 使用 checksum ledger 串行执行 `001_init.sql`、`002_phase2a_persistence.sql` 和
`003_phase2a_runtime_invariants.sql`。`003` 阻止同一集成客户端用不同 operation ID 重复开通同一 Seat。

旧 Compose 版本曾由 PostgreSQL `initdb` 直接执行 SQL，没有 ledger。当前 runner 检测到“已有领域表但
无 ledger”时返回 `ErrUnmanagedSchema` 并拒绝自动认领：

- 开发环境：停止服务并重建 `trusted-pool-postgres` 卷，再由 runner 创建结构。
- 生产或保留数据环境：禁止直接删卷；需先备份、核验真实结构和 checksum，再执行专门的受控 baseline
  流程。该 adoption 工具不在本阶段范围内。

## 恢复与交付语义

- 上游成功但本地事务未提交：相同请求和 operation ID 由调用方重放；后台不会生成无法交给调用方的新 token。
- 本地事务已提交但首次 HTTP 响应丢失：Operation 可恢复，但 claim token 不会再次披露。这是安全优先的 at-most-once 可用性损失。
- Sub2API ack 结果未知：保留密文并用同一 claim operation ID 对账；不披露 credential。
- Sub2API ack typed snapshot 已提交但 Claim 尚未消费：原 token 在 TTL 内可继续领取；平台重启不会丢失包络。
- Claim 已 CAS 为 `CLAIMED` 并清密，但最终 HTTP 响应丢失：credential 永久不可二次领取，运营必须重新开通或轮换。
- Claim 已过期：先持久化 `EXPIRED` 并清密，禁止再调用上游 ack 或 KMS 解密。

## 已验证

主工作区已通过：

```text
go test -count=1 ./...
go vet ./...
```

测试覆盖请求漂移、重复 Seat、Group 绑定、epoch 回退、结果快照 secret canary、错误 token 不占 lease、
过期 Claim 不 ack、不解密、typed ack、ambiguous/rejected、终态清密、恢复扫描去抖、HTTP 错误去敏、
KMS AAD、迁移 checksum/unmanaged schema 和 persistent 模式端点 fail-close。

## 上线硬门禁

本机 Docker daemon 未运行且没有本地 PostgreSQL 客户端，本轮未能执行真实 PostgreSQL 测试。上线前必须补齐：

1. PostgreSQL 16 空库 `001 -> 002 -> 003 -> 004 -> 005` 和已有受管数据升级。
2. 双连接 lease 接管、旧 fence 拒绝、同一 Seat/Claim 并发竞争。
3. 迁移并发、checksum 漂移、unmanaged schema 与受控 baseline 演练。
4. 上游、KMS、数据库提交前后崩溃注入及重启恢复。
5. pg_dump、应用日志和错误响应 secret canary 扫描。
6. 生产 KMS/HSM adapter、权限、轮换、停用和灾备演练。
7. 上述门禁通过前保持单副本并禁止 rolling overlap。

后续 Phase 2-B/2-C 已分别接入 Suspend/Drain/Freeze 与临时换员/恢复；永久换员仍必须等待 Recovery
Root、Share、Manifest 和供应商证明治理全部完成。
