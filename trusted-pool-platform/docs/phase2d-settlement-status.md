# Phase 2-D 结算解除运行时状态

## 已接线能力

Phase 2-D 在持久暂停和换员工作流之上，接入 Sub2API pending settlement 的查询、受控解除与重启恢复：

1. list/get 使用独立的只读 Sub2API client，读取 Seat、settlement、request ID、assignment epoch、billing ID、
   错误与尝试次数。
2. resolve 只接受独立入站 `TRUSTED_POOL_SETTLEMENT_API_KEY`，且 `Idempotency-Key` 必须等于 body
   `operation_id`。
3. 平台在任何上游 POST 前，同事务持久化 9 键 intent：operation、Seat、settlement、expected request ID、
   expected assignment epoch、expected actor client ID、reason、evidence 和版本。
4. 出站控制、settlement read、settlement resolve 三组 client ID 与 secret 必须互不相同；resolve client 只能
   持有单一 `settlement:resolve` scope，`*` 和混合 scope 均被拒绝。
5. 成功响应必须逐字段匹配持久 intent。Operation、resolution case、typed result 和 trust event 在同一事务
   完成；原始上游响应和内部错误详情不落库。
6. timeout、5xx、坏响应和绑定漂移进入 `RECONCILE_REQUIRED`；普通 4xx 进入
   `OPERATOR_REVIEW_REQUIRED`。两类结果都不声明上游未执行，也不会解除本地禁用状态。
7. 专用恢复扫描器使用原 operation ID 和持久快照重放。完成态重放不依赖当前 Seat epoch 或当前配置的
   actor client ID；未完成 intent 则固定原 actor，允许分阶段轮换 secret，但更换 client ID 前必须清空 intent。

## 跨工作流门禁

- Begin resolve 只允许本地 Seat 为 `DRAINING`，并绑定当前 assignment epoch。
- 恢复提交允许 Seat 已进入 `FROZEN`，但 epoch 不得漂移。
- 存在未决 resolution case 时，Store 和数据库 trigger 都拒绝 Seat 进入 `ASSIGNMENT_PENDING`，防止
  “上游已解除但本地响应丢失”期间换员穿越。
- 通用 operation scanner 不扫描 `RESOLVE_SETTLEMENT`；专用 scanner 独占该类型。通用 Commit 也不能
  直接把 resolve 标记为成功。
- Sub2API 删除 pending 时必须同时匹配 Seat、settlement ID、assignment epoch 和 request ID；审计表
  append-only，相同 operation 精确重放，内容漂移返回冲突。

## 运维流程

1. Seat 保持 `DRAINING`，使用 list/get 取得完整 pending 证据。
2. 在账单、补账记录或供应商结果中完成实际核验，生成不含密钥的 evidence 引用。
3. 使用独立 settlement 入站密钥提交 operation、expected epoch/request ID、reason 和 evidence。
4. 200 表示 Sub2API 已写入不可变审计并删除精确 pending；503/409 不得推断结果，查看 operation 状态并
   让恢复 worker 使用同一 intent 对账。
5. 所有 pending 均清除后，Suspend worker 才能完成双屏障冻结；未决 resolve intent 清理前不得换员。

## 未开放能力

本节记录 Phase 2-D 当时边界；Credential Batch 已由 Phase 2-E 接入持久双包装底座。永久换员、
Control Rotation Evidence、Recovery Root、Recovery Share 和 Manifest 仍失败关闭。
resolve 不是补账引擎，也不验证 evidence 的外部真实性；真实性由受控运营流程负责，平台保证认证、幂等、
字段绑定、不可变审计和失败关闭。

## 发布门禁

开发验证包含 Go 全包测试、vet、Store/Coordinator/Client/HTTP 契约和 OpenAPI 静态校验。生产或封闭试点前
仍必须完成：

- 当前总发布门禁以 Phase 2-E 为准：PostgreSQL 16 空库 `001 -> 007` 与现有 `006 -> 007` 升级；
  本阶段单独仍要求验证 `005 -> 006` 的历史数据、所有 deferred trigger 和 scope 隔离迁移。
- 双连接验证同 operation 重放、hash 漂移、lease 接管、旧 fence 拒绝、同 settlement 不同 operation，
  以及 resolve 与 Suspend/Assignment 交错。
- 在 intent 提交、上游 POST、上游提交、平台 success commit 和 HTTP 响应前后做崩溃注入。
- 验证多个 pending 逐条解除时，剩余计数持续阻止冻结；encoded path、普通 key、`*` scope 和混合 scope
  均不能调用 resolve。
- 使用生产 KMS/HSM、真实 Secret Manager 轮换和日志/数据库敏感数据扫描。

以上门禁未完成前继续单副本部署、停旧再启新，禁止 rolling overlap；当前结果是开发闭环，不是生产数据面。
