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
- 凭据批次使用 AES-256-GCM 信封加密，并将密文绑定到 Pool、账号、批次版本和成员 epoch。

## MVP 边界

当前 repository 是进程内存实现，服务重启后 Seat、操作、风险窗口、凭据批次、claim token 和待领取
访问凭据都会丢失。当前 `Bearer` API Key 也是服务级保护，不是最终的 Sub2API 身份交换和本地 RBAC。

因此当前版本适合接口联调、状态机验证和自动化测试，不可作为生产数据平面部署。现有 Phase 2 SQL
也尚未接入 API，且缺少领取 token 哈希与加密待交付记录。后续必须增加 PostgreSQL repository、
outbox worker、本地会话、细粒度权限和原子领取持久化。

## 运行

```text
TRUSTED_POOL_HTTP_ADDR=:8092
TRUSTED_POOL_API_KEY=<至少 32 字符>
TRUSTED_POOL_SETTLEMENT_API_KEY=<独立的至少 32 字符人工对账密钥>
TRUSTED_POOL_FINGERPRINT_HMAC_KEY=<至少 32 字符>
TRUSTED_POOL_CLAIM_TTL=10m
TRUSTED_POOL_KEK_HEX=<64 位十六进制密钥>
SUB2API_BASE_URL=https://sub2api.example.com
SUB2API_INTEGRATION_CLIENT_ID=trusted-pool-platform
SUB2API_INTEGRATION_SECRET=<至少 16 字符>
```

```bash
go run ./cmd/server
```

健康检查不需要认证：`GET /health`。普通接口使用：

```http
Authorization: Bearer <TRUSTED_POOL_API_KEY>
```

人工解除 pending settlement 的 resolve 接口必须改用
`Authorization: Bearer <TRUSTED_POOL_SETTLEMENT_API_KEY>`；两个密钥相同时服务拒绝启动。

Seat 状态变更接口还必须传入不超过 128 字符的 `Idempotency-Key`。Seat 开通的幂等键位于请求体
`operation_id`；成功响应只返回 `seat + operation`，Sub2API credential 必须由 owner 使用 operation 中的
一次性 claim token 调用 `credential-ack` 领取。token 仅在首次成功响应返回，幂等重放和操作查询不会恢复明文。

## 测试

```bash
go test ./...
go test -race ./...
go vet ./...
```
