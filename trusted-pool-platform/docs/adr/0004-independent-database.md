# ADR-0004：新平台使用独立数据库

- 状态：Accepted
- 日期：2026-08-16

## 背景

直接读写 Sub2API 数据库会绕过其额度、缓存和审计不变量，也会把两个系统的发布周期绑定在一起。

## 决策

Phase 2 新平台使用独立 PostgreSQL，仅保存业务期望状态、Trust Plane 和集成操作。Sub2API 的
Group、Account、Subscription、API Key 与实际用量只通过受限集成 API 操作。

`migrations/001_init.sql` 建立领域基线，`002_phase2a_persistence.sql` 和
`003_phase2a_runtime_invariants.sql` 增加工作流持久化及运行时约束。Phase 2-A Runtime 已强制连接
独立数据库；连接、迁移或 KMS 失败时拒绝启动，不回退进程内存。

Phase 1 已公开的 Member、Pool、Seat 字符串 ID 不改写为 UUID。Phase 2 在三张表分别保存最长 128
字符的唯一 `external_id`，Repository 用它解析内部 UUID；数据库主键与外键继续使用 UUID。迁移和
回滚均以 `external_id` 幂等定位记录，客户端、Manifest 与审计事件无需更换既有公开 ID。
