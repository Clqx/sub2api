# Phase 2-A PostgreSQL 持久化底座状态

更新时间：2026-08-18

## 本阶段目标

Phase 2-A 只建立可信成员池工作流的 PostgreSQL 持久化边界，解决内存实现无法跨重启恢复、无法使用数据库租约协调多 worker、以及一次性凭据领取状态无法持久审计的问题。

本阶段不实现 Recovery Root、恢复 Share、Manifest、阈值签名或完整的生产永久换员治理。永久换员仍不得被描述为已经完成生产级恢复治理。

## 已落地内容

- 增量迁移 `002_phase2a_persistence.sql`，不修改 `001_init.sql` 基线。
- Operation 保存完整请求快照、公开目标 ID、数据库租约、单调 fencing token、重试时间和版本。
- `001` 历史 Operation 统一标记为 `LEGACY_UNRECOVERABLE`。能解析的 Pool/Seat 目标会回填公开 ID，但不会伪造缺失的请求快照，也不会允许恢复 worker 重放。
- Credential Claim 仅持久化 claim token SHA-256、凭据指纹和 KMS 包络；`CLAIMED`、`EXPIRED`、`REJECTED` 终态强制清除所有可交付秘密。
- Claim intent hash 在终态保留，用于清密后的幂等重放和请求漂移判断。
- Claim 必须绑定 Operation 的目标 Seat、当前活动 Assignment 和活动成员；Provision 额外要求领取人为 Seat owner。
- Provision ack 使用两阶段状态：先持久化 `ACK_PENDING` marker，再调用 Sub2API。成功证据必须精确匹配 Seat、Provision operation、claim operation、成员、凭据指纹、`credential_claimed=true` 和有效领取时间。
- ack 超时或结果未知进入 `ACK_RECONCILE_REQUIRED` 并保留包络；明确拒绝进入 `REJECTED` 并立即清密。
- Operation 成功与 Claim 创建通过一个 Store 事务原子提交；普通提交接口禁止将凭据型 Operation 直接置为成功。
- 恢复 worker 可通过 `SKIP LOCKED` 原子发现并抢占到期 Operation 或 Claim；租约判断使用数据库时间，最终提交必须同时匹配 lease owner 和 fencing token。

## 当前接入状态

本文件记录持久化底座本身。后续 Phase 2-A Runtime 已完成 Provision/Claim 纵向接线，当前运行边界、
部署前置条件和剩余门禁以[Phase 2-A Runtime 状态](phase2a-runtime-status.md)为准。

- `cmd/server` 已强制注入 PostgreSQL Store、迁移 runner、KMS 包络 adapter、唯一 worker ID 和恢复循环。
- Provision 的 Pool/Owner Member 必须由可信流程预创建；不得用占位身份绕过约束。
- Suspend、Assign、Restore、Replace、settlement 和 credential batch 尚未接入持久 Coordinator，运行时失败关闭。
- 当前不支持把此底座作为生产永久换员完成条件。

## 已执行验证

在隔离 staging 和主工作区均执行：

```text
go test -count=1 ./...
go vet ./...
gofmt -d <本阶段 Go 文件>
```

覆盖的单元/契约测试包括：请求漂移、JSONB 语义规范化和大整数保持、数据库时钟租约、恢复扫描、旧 fence 拒绝、Operation 与 Claim 原子提交、typed ack、ack 前置 marker、结果未知恢复、明确拒绝清密、终态清密和迁移静态契约。

## 合并与上线门禁

Docker/PostgreSQL 在本次工作环境中不可用，因此以下测试尚未执行，仍是下一阶段强制门禁：

1. PostgreSQL 16 空库执行 `001 -> 002 -> 003`。
2. 带历史数据的 `001 -> 002 -> 003` 升级与 `LEGACY_UNRECOVERABLE` 行为验证。
3. 两个真实数据库连接并发争抢 lease、过期接管和旧 fence 提交拒绝。
4. 真实触发器验证 typed ack、Seat/Assignment/owner 绑定和终态清密。
5. 数据库提交结果未知、KMS 失败、上游 ack 结果未知和进程重启故障注入。
6. 数据库及日志 canary 扫描，确认 raw token、API credential 和解密明文零落盘。
7. 跨重启 Provision/Claim 端到端测试，以及后续 Suspend、Assign、Restore、Replace 的持久化接线测试。

在上述门禁通过前，只能称为“Phase 2-A 已接线开发运行时”，不能称为已具备生产持久恢复能力。
