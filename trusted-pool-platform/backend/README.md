# Trusted Pool Platform Backend MVP

这是可信有限成员订阅共享平台的独立后端核心。当前实现用于验证并固定以下边界：

- Seat 换员必须严格经过 `ACTIVE -> SUSPEND_PENDING -> DRAINING -> FROZEN`。
- 临时分配、恢复和永久替换都不能绕过冻结；所有 Assignment 都要求 Sub2API 明确确认 Seat 访问
  凭据已轮换；永久替换还必须提交本平台在四类旧批次全部退休、相邻新批次全部激活后签发的
  控制凭据轮换证据。证据还绑定运营或外部系统已预先核验的供应商变更证明引用，Coordinator 会按
  Pool 和相邻 Membership Epoch 复核引用及八个批次状态；Phase 1 不校验供应商签名或证明真实性。
- 永久替换成功后提交 Pool 最小 Membership Epoch；旧 Epoch 的批次不能再 Seal 或 Activate。
- Seat 状态变更调用使用稳定 `Idempotency-Key`，结果未知时进入对账而不是直接重试。
- Seat 开通是例外的显式幂等恢复流程：`POST /api/v1/seats` 要求 `operation_id`、既有 Group 和订阅到期时间；
  上游未明确成功时不创建本地 Seat，调用方以相同内容和 operation_id 重放开通请求。
- drain-status/freeze 固化小时、日、周、月四个额度窗口；未启动窗口保留 null。
- 新访问凭据通过绑定目标成员的随机 claim token 单次领取；只保存 token SHA-256 摘要并设置短 TTL。
  Provision credential 必须先由 Sub2API `credential:ack` 明确确认，结果未知时失败关闭且不披露。
- 可信 Seat 禁止提交异步图片、批量图片和视频任务。
- 设备指纹只保留 HMAC 摘要，风险窗口仅观察，不自动暂停成员。
- 凭据批次使用 AES-256-GCM，并将同一随机 DEK 分别交给在线 KMS 与独立 Recovery wrap-only adapter；
  AAD 绑定 operation、batch、Pool、账号、批次版本、成员 epoch 和 HMAC 内容指纹。

## 当前持久边界

组合根强制使用 PostgreSQL `WorkflowStore`。Provision、Owner Assignment、Operation、Provision Claim，
Suspend/Drain/Freeze、临时换员和正式成员恢复已接入数据库 lease 与 fencing；数据库或 KMS 不可用时失败关闭，不回退内存。
暂停命令先持久封锁 Seat，再调用 Sub2API；恢复线程从请求快照重建命令，不依赖进程内 operation map。

临时分配与恢复只允许从 FROZEN 发起，保持 Principal、Subscription、API Key ID 和 Pool Membership Epoch
不变；成功时 Assignment、Seat、Operation 与加密 Claim 原子提交。Pending settlement list/get 使用独立
只读 Sub2API 凭据；resolve 先持久化 intent/lease，再使用另一组 `settlement:resolve` 凭据调用上游，
结果不明时由同一 operation ID 和原始快照恢复。平台只持久化调用审计，Sub2API append-only resolution
是账本真相。Credential Batch 的 Seal/Get/Activate/Retire 已接入 PostgreSQL，旧内存 Manager 不再用于持久模式；
永久替换和 control rotation evidence 仍返回 503。风险窗口仍是可丢失观察面。真实 PostgreSQL 双连接、崩溃注入、生产 KMS 和多实例
竞争测试尚未完成，因此当前版本仍不可作为生产数据平面部署。

## 运行

```text
TRUSTED_POOL_HTTP_ADDR=:8092
TRUSTED_POOL_API_KEY=<至少 32 字符>
TRUSTED_POOL_SETTLEMENT_API_KEY=<独立的至少 32 字符人工对账密钥>
TRUSTED_POOL_BATCH_API_KEY=<独立的至少 32 字符批次管理密钥>
TRUSTED_POOL_FINGERPRINT_HMAC_KEY=<至少 32 字符>
TRUSTED_POOL_CLAIM_TTL=10m
TRUSTED_POOL_KEK_HEX=<64 位十六进制密钥>
TRUSTED_POOL_BATCH_CLIENT_ID=trusted-pool-batch-api
TRUSTED_POOL_BATCH_FINGERPRINT_HMAC_KEY_HEX=<独立 64 位十六进制 HMAC Key>
TRUSTED_POOL_RECOVERY_KEK_HEX=<仅开发模式的独立 64 位十六进制 Recovery KEK>
SUB2API_BASE_URL=https://sub2api.example.com
SUB2API_INTEGRATION_CLIENT_ID=trusted-pool-platform
SUB2API_INTEGRATION_SECRET=<至少 16 字符>
SUB2API_SETTLEMENT_READ_CLIENT_ID=trusted-pool-settlement-read
SUB2API_SETTLEMENT_READ_SECRET=<独立只读密钥>
SUB2API_SETTLEMENT_RESOLVE_CLIENT_ID=trusted-pool-settlement-resolve
SUB2API_SETTLEMENT_RESOLVE_SECRET=<独立 settlement:resolve 密钥>
```

`production` 模式强制 `SUB2API_BASE_URL` 使用 HTTPS。集成客户端不会跟随 HTTP
重定向，避免 Bearer 凭据离开配置的上游端点。本地 HTTP 仅允许用于
`development` 模式。

```bash
go run ./cmd/server
```

健康检查不需要认证：`GET /health`。普通接口使用：

```http
Authorization: Bearer <TRUSTED_POOL_API_KEY>
```

人工解除 pending settlement 的 resolve 路由只接受
`Authorization: Bearer <TRUSTED_POOL_SETTLEMENT_API_KEY>`；两个入站密钥相同时服务拒绝启动。resolve 请求还需
提交最近 list/get 获得的 `expected_assignment_epoch` 与 `expected_request_id`。普通控制、settlement read、
settlement resolve 三组出站 client ID 或 secret 任一复用时服务拒绝启动。未完成 intent 固化 actor client ID，
可轮换对应 secret，但更换 client ID 前必须先清空待恢复操作；历史终态查询不依赖当前 actor 配置。
resolve 还要求 `Idempotency-Key` 与 body `operation_id` 完全一致。

Credential Batch 路由只接受 `TRUSTED_POOL_BATCH_API_KEY`，Seal/Activate/Retire 同样要求 Header
`Idempotency-Key` 与 body `operation_id` 一致。生产模式不读取 Recovery KEK 环境变量，必须由组合根注入
原生 context-aware 在线 KMS 与独立 Recovery wrap-only adapter。

Seat 状态变更接口还必须传入不超过 128 字符的 `Idempotency-Key`。Seat 开通的幂等键位于请求体
`operation_id`；成功响应只返回 `seat + operation`，Sub2API credential 必须由 owner 使用 operation 中的
一次性 claim token 调用 `credential-ack` 领取。token 仅在首次成功响应返回，幂等重放和操作查询不会恢复明文。

## 测试

```bash
go test ./...
go test -race ./...
go vet ./...
```
