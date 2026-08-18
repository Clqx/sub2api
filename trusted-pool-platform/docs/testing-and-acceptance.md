# 测试方案与验收标准

## 1. 测试层级

- 单元测试：状态转换、业务不变量、幂等摘要、批次关联数据、敏感字段脱敏。
- 数据库测试：唯一约束、并发更新、只追加审计触发器、活动 Assignment 部分索引和 Epoch 复合外键。
- 契约测试：平台 OpenAPI 与 Sub2API 受限集成接口的请求和错误码。
- 集成测试：真实 PostgreSQL、伪 Sub2API、超时、重复响应和乱序事件。
- 端到端测试：五成员 Pool 从创建到暂停、临时换员、恢复和永久换员。
- 故障注入：数据库提交后响应丢失、Redis 缓存失效失败、在途请求超时、outbox 重投。

## 2. 必须通过的业务验收

1. 暂停确认后旧 Key 的新请求全部被拒绝。
2. 未达到 `FROZEN` 时临时换员、永久换员和恢复均返回冲突。
3. 换员前后 Seat Principal、订阅、额度用量和窗口起点完全不变。
4. 重复提交相同操作不会生成重复 Group、Seat、订阅、Assignment 或 Key。
5. 相同 `operation_id` 携带不同内容时返回幂等冲突。
6. 旧 `assignment_epoch` 的请求即使命中旧缓存也被拒绝。
7. 正常完成、超时和异常中断的在途请求均不会造成重复计费。
8. 可信 Seat 结算错误、panic、超时或 pending 删除失败时保留持久屏障；即使并发为 0，freeze
   仍返回冲突，人工对账清除前不得换员。
9. 临时成员不能获得 Share、Manifest 投票权或 Reveal 权。
10. Phase 1 验证永久换员后旧运行凭据不能访问新 Epoch；旧 Share 隔离属于 Phase 2 recovery governance 验收。
11. 风险等级变化不会自动暂停 Seat。
12. drain-status 和 freeze 均返回四个额度窗口；未启动窗口保持 null，换员后窗口与已用额度连续。
13. 可信 Seat 提交异步图片、批量图片或视频任务时被网关拒绝，普通同步请求不受影响。
14. `provider_attestation_ref` 缺失、四类旧批次未全部 RETIRED、四类新批次未全部 ACTIVE，或 Epoch
    不相邻时均不能签发控制轮换证据；成功证据绑定该引用和新旧八个批次 ID。
15. 永久换员对跨 Pool、非相邻 Epoch、已失效批次或任意非空外部引用均复核失败；
    `access_credential_rotated=true` 不能替代平台签发证据。Phase 1 测试不得把引用存在误表述为平台
    已验证供应商签名或证明真实性。
16. claim token 只保存 SHA-256 摘要、仅在首次成功响应返回，并只能由绑定目标成员在 TTL 内使用一次；
    状态查询、幂等重放、跨成员领取和重复领取均不泄露凭据。
17. 永久换员成功提交最小 Membership Epoch 后，旧 Epoch 的 Seal 和 Activate 均被稳定拒绝且无副作用。
18. 平台读取 drain-status 时，只要 `current_concurrency` 或 `pending_settlements` 任一非零，就保持
    `DRAINING` 且不调用 freeze；收到仍带 pending 的 FROZEN 响应时失败关闭。
19. 受控 settlement 查询能返回 request/billing ID、状态、错误和尝试次数；平台 resolve 必须使用
    与普通 API Key 不同的 `TRUSTED_POOL_SETTLEMENT_API_KEY`，上游仅接受 `settlement:resolve` scope，
    并覆盖计费成功但屏障删除失败、计费失败、进程中断、同一幂等键重放和内容漂移冲突，完整保留
    操作者、理由、证据和时间。
20. Seat provision 只接受已绑定 Pool 的既有 Group，并在 Sub2API 同一事务创建不可交互 Principal、
    Subscription 与 API Key；响应中 credential 不得越过平台一次性领取边界。
21. Sub2API 未明确成功、超时或返回无法验证的 Seat 时，本地 Seat 不存在且绝不标记 ACTIVE。
22. `RETRYABLE` provision 使用相同请求和 operation_id 重放可恢复；成功后的再次重放不调用上游且不返回
    claim token；任一限额、到期时间、Group、Pool、Seat 或 owner 漂移均冲突。
23. provision claim token 只绑定 owner；平台必须先以独立 `credential:ack` scope、相同 claim operation ID
    和 credential fingerprint 取得 Sub2API 明确确认。ambiguous ack 不披露且可幂等重放；ack 跨越 TTL、
    token 过期、错误 fingerprint 和上游已领取均清除或拒绝 credential，平台重启后不能重新发放。

## 3. Phase 2 数据库契约验收

- 非 UUID 的合法 `operation_id` 可以写入暂停记录和集成操作表，并保持最长 128 字符限制。
- 同一 Seat 不能存在两个活动 Assignment；同一成员也不能在同一 Pool 占用两个活动 Seat。
- Assignment 携带的 `pool_id` 必须与 Seat 所属 Pool 一致。
- Credential Batch 不能引用不存在或属于其他 Pool 的 Membership Epoch。
- Manifest Signature 的成员必须属于该 Manifest 对应的 Membership Epoch。
- Phase 2 增加领取持久化前，必须验证数据库只存 token 哈希和加密待交付值，ack 与消费同事务提交。

## 4. 安全验收

- 数据库、应用日志、错误响应和 trace 中不存在凭据明文、API Key、未包装 DEK、Recovery Share、
  用户 JWT 或原始设备指纹。
- 新平台无法使用集成凭据访问 Sub2API 非 trusted-pools 管理接口。
- URL query 中携带 token 时直接拒绝；fragment 使用后立即清除。
- 审计事件无法 UPDATE 或 DELETE，修正只能追加补偿事件。
- 密文关联数据被修改后解密必须失败。

## 5. 故障恢复验收

- Sub2API 调用提交成功但响应丢失时，相同 `operation_id` 可恢复原结果。
- 平台重启后能读取持久 Provision/Claim，并通过数据库 lease/fencing 接管 ack 对账；后台不得新发 claim token。
- `CALLER_REPLAY_REQUIRED` 不被恢复 worker 反复扫描，原调用方可用同请求和 operation ID 重放。
- 过期 Claim 先持久清密，且不再调用 Sub2API ack 或 KMS 解密。
- 结果未知时 `SUSPEND_PENDING` 不会自动进入 `FROZEN` 或开始换员。
- 对账能发现期望状态与实际状态不一致，并进入人工处理队列。
- 完成一次不依赖在线平台的 Manifest 验证和 Recovery Package 恢复演练。

## 6. 发布门禁

以下任一条件不满足均不得上线封闭试点：

- 单元、数据库和集成测试全部通过。
- 暂停与换员端到端场景通过。
- 敏感数据扫描无高危发现。
- OpenAPI 与实现契约测试通过。
- 数据库迁移在空库和已有测试数据上均验证成功。
- migration ledger、checksum 漂移和 unmanaged 历史卷的受控 baseline 演练通过。
- 生产 KMS/HSM adapter 与双连接 lease/fence、两实例同 Claim 竞争测试通过。
- 运维人员完成暂停结果未知和永久换员演练。

Phase 2-A 当前只通过 Go 单元/契约与静态检查；真实 PostgreSQL、崩溃注入、生产 KMS 和完整换员
端到端尚未通过，因此本节发布门禁仍未满足。
