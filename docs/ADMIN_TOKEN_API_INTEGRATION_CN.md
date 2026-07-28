# Sub2API 管理员 Token API 与外置兑换平台对接指南

本文档基于当前后端路由和 handler 实现整理，面向需要通过管理员凭证调用
Sub2API 的外部系统，重点覆盖兑换码、余额充值/退款、订阅开通/续期/扣减和
对账。

当前管理端共暴露 397 个 HTTP 路由：

- `backend/internal/server/routes/admin.go`：380 个
- `backend/internal/server/routes/payment.go`：17 个内置支付管理路由

路由数量是能力盘点，不代表外部兑换平台应获得全部权限。生产接入应只代理
本文“最小接口白名单”中的接口。

## 1. 接入结论

外置兑换或支付平台的订单履约，推荐统一调用：

`POST /api/v1/admin/redeem-codes/create-and-redeem`

它适合处理：

- 余额充值：`type=balance`、`value>0`
- 余额退款/扣回：`type=balance`、`value<0`
- 订阅开通或续期：`type=subscription`、`validity_days>0`
- 订阅退款或扣减：`type=subscription`、`validity_days<0`

每个支付、退款或人工补偿动作都使用唯一且稳定的 `code`，并传稳定的
`Idempotency-Key`。同一个动作重试时必须保持请求体完全一致。

不建议把付费订单直接接到以下接口：

- `POST /api/v1/admin/users/:id/balance`：适合后台人工修正，不是首选订单履约入口。
- `POST /api/v1/admin/subscriptions/assign`：活跃订阅不会按订单重复续期，语义不适合付费续费。
- `POST /api/v1/admin/subscriptions/:id/extend`：可用于人工调整，但外部平台还要先可靠定位订阅 ID。

## 2. 认证方式

所有 `/api/v1/admin/**` 接口支持两种认证方式。

### 2.1 Admin API Key

```http
x-api-key: admin-<secret>
```

这是服务间调用的推荐方式。管理员 API Key：

- 是全局单例，不是按调用方分别签发。
- 具有完整管理员权限，没有 scope、接口白名单或独立过期时间。
- 会映射为数据库中的第一个有效管理员，用于审计和权限上下文。
- 重新生成或删除后，旧 key 立即失效。
- 完整 key 只在重新生成时返回一次。

管理接口：

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| `GET` | `/api/v1/admin/settings/admin-api-key` | 查询是否存在及掩码 |
| `POST` | `/api/v1/admin/settings/admin-api-key/regenerate` | 生成或轮换，返回一次完整 key |
| `DELETE` | `/api/v1/admin/settings/admin-api-key` | 删除并停用 |

### 2.2 管理员 JWT

```http
Authorization: Bearer <access_token>
```

登录入口：

`POST /api/v1/auth/login`

```json
{
  "email": "admin@example.com",
  "password": "password",
  "turnstile_token": ""
}
```

成功后的 token 位于 `data.access_token`。启用 TOTP 时，第一次登录响应会返回
`requires_2fa=true` 和 `temp_token`，还要调用：

`POST /api/v1/auth/login/2fa`

JWT 会过期，并可能受 IP/User-Agent 会话绑定影响，因此不适合作为长期机器凭证。

如果请求同时携带 `x-api-key` 和 `Authorization`，后端优先验证 `x-api-key`。
无效的 `x-api-key` 不会回退到 JWT。

### 2.3 统一门控

管理端路由还统一经过：

- 管理员操作审计。
- 管理员合规确认。未确认时通常返回 HTTP `423` 和
  `ADMIN_COMPLIANCE_ACK_REQUIRED`。
- 部分高敏接口的 step-up TOTP。

启用 step-up 后，Admin API Key 不能调用要求真人二次验证的接口，例如账号或
代理凭证导出、S3/备份目标修改、备份创建/下载/恢复等。兑换、余额和订阅接口
当前不要求 step-up。

## 3. 通用协议

### 3.1 请求头

```http
x-api-key: <admin-api-key>
Content-Type: application/json
Idempotency-Key: <stable-business-operation-id>
```

`Idempotency-Key` 规则：

- 去除首尾空白后长度不超过 128。
- 只能包含可见 ASCII 字符。
- 同一 key、同一路由、同一管理员和同一请求体会重放首次成功结果。
- 同一 key 配不同请求体会返回 `409 IDEMPOTENCY_KEY_CONFLICT`。
- 默认记录 TTL 为 24 小时，可由部署配置调整。
- 成功重放时响应头包含 `X-Idempotency-Replayed: true`。
- 处理中或失败退避时可能返回 `409` 和 `Retry-After`。

当前默认配置 `idempotency.observe_only=true`，所以缺少 key 时可能仍会执行。
外部平台仍必须始终发送 key，不能依赖观察模式。

### 3.2 响应格式

普通成功响应：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

分页响应的 `data`：

```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "page_size": 20,
  "pages": 1
}
```

分页参数支持 `page` 和 `page_size`，`page_size` 最大 1000。

普通失败响应：

```json
{
  "code": 409,
  "message": "idempotency key reused with different payload",
  "reason": "IDEMPOTENCY_KEY_CONFLICT",
  "metadata": {}
}
```

调用方应同时判断 HTTP 状态码和响应体。合规门控等少数响应的 `code` 可能是
字符串，反序列化时不要把它固定为整数。

## 4. 外置兑换平台所需接口

### 4.1 用户身份与查询

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/v1/auth/me` | 使用用户 JWT 校验当前登录用户 |
| `GET` | `/api/v1/admin/users?search=<email>` | 按邮箱/用户名查找候选用户 |
| `GET` | `/api/v1/admin/users/:id` | 查询用户、余额和状态 |
| `GET` | `/api/v1/admin/users/:id/subscriptions` | 查询用户全部订阅 |
| `GET` | `/api/v1/admin/users/:id/balance-history` | 查询余额、并发和订阅变更记录 |
| `GET` | `/api/v1/admin/usage?user_id=:id` | 查询真实的明细用量记录 |

从 Sub2API iframe 或自定义菜单进入外部页面时，URL 中的 `user_id` 只能作为提示，
不能作为可信身份。外部平台后端应使用传入的用户 JWT 调用 `/api/v1/auth/me`，
并以返回的 `data.id` 为准。

不要把 Admin API Key 放到浏览器、iframe URL、Local Storage 或前端构建变量中。

### 4.2 商品和订阅分组

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/v1/admin/groups/all` | 拉取全部分组，适合商品映射 |
| `GET` | `/api/v1/admin/groups/:id` | 查询分组详情、类型和配额 |
| `GET` | `/api/v1/admin/groups/:id/subscriptions` | 查询该分组的订阅用户 |
| `GET` | `/api/v1/admin/payment/plans` | 查询内置支付套餐，外置平台可选复用 |

订阅商品只能映射到 `subscription_type=subscription` 的分组。建议外置平台维护
自己的 SKU 快照：

```text
external_sku -> benefit_type + group_id + validity_days/balance_value
```

订单创建后保存快照，不要在支付回调时重新读取可变商品配置来决定权益。

### 4.3 兑换码管理

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/v1/admin/redeem-codes` | 分页查询，支持 `type/status/search/sort_by/sort_order` |
| `GET` | `/api/v1/admin/redeem-codes/:id` | 查询单个兑换码 |
| `POST` | `/api/v1/admin/redeem-codes/generate` | 批量生成 1 至 100 个码 |
| `POST` | `/api/v1/admin/redeem-codes/create-and-redeem` | 固定码创建并立即发放权益 |
| `POST` | `/api/v1/admin/redeem-codes/batch-update` | 批量修改未使用码等记录 |
| `POST` | `/api/v1/admin/redeem-codes/:id/expire` | 手动过期 |
| `POST` | `/api/v1/admin/redeem-codes/batch-delete` | 批量删除 |
| `DELETE` | `/api/v1/admin/redeem-codes/:id` | 删除 |
| `GET` | `/api/v1/admin/redeem-codes/export` | CSV 导出，单次最多取 10000 条 |
| `GET` | `/api/v1/admin/redeem-codes/stats` | 当前是占位实现，不可用于财务统计 |

兑换码类型：

| 类型 | `value` | 其他字段 | 结果 |
| --- | ---: | --- | --- |
| `balance` | 正数或负数 | 无 | 增加余额或原子扣减余额 |
| `concurrency` | 正数或负数 | 无 | 增减用户并发 |
| `subscription` | 非零审计值 | `group_id`、非零 `validity_days` | 开通、续期或扣减订阅 |
| `invitation` | 业务自定 | 无 | 只能在注册流程使用，不能普通兑换 |

`create-and-redeem` 的 `value` 当前带有 `binding:"required"`。订阅发放虽然不使用
它计算天数，也必须传非零值；建议传订单实付金额，退款时传负的退款金额。

### 4.4 订阅管理

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/v1/admin/subscriptions` | 按用户、分组、状态、平台筛选 |
| `GET` | `/api/v1/admin/subscriptions/:id` | 查询订阅 |
| `GET` | `/api/v1/admin/subscriptions/:id/progress` | 查询日/周/月配额进度 |
| `POST` | `/api/v1/admin/subscriptions/assign` | 人工首次分配或幂等返回现有订阅 |
| `POST` | `/api/v1/admin/subscriptions/bulk-assign` | 批量人工分配 |
| `POST` | `/api/v1/admin/subscriptions/:id/extend` | 正数延长、负数缩短，要求幂等 key |
| `POST` | `/api/v1/admin/subscriptions/:id/reset-quota` | 重置日/周/月用量窗口 |
| `POST` | `/api/v1/admin/subscriptions/:id/revoke` | 软撤销 |
| `POST` | `/api/v1/admin/subscriptions/:id/restore` | 恢复已撤销订阅 |
| `DELETE` | `/api/v1/admin/subscriptions/:id` | 兼容旧调用方，语义同 revoke |

`assign` 对已存在且活跃的同分组订阅不会叠加时长。付费续期应使用
`create-and-redeem` 的订阅类型，或先查订阅 ID 后调用 `extend`。

### 4.5 余额人工调整与记录

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `POST` | `/api/v1/admin/users/:id/balance` | `set/add/subtract` 人工修正 |
| `GET` | `/api/v1/admin/users/:id/balance-history` | 对账和审计 |

人工调整请求：

```json
{
  "balance": 10.0,
  "operation": "add",
  "notes": "manual compensation"
}
```

该接口要求 `balance>0`，扣减通过 `operation=subtract` 表达。它本身支持
`Idempotency-Key`，但余额写入和后台调整记录不是一个数据库事务；订单履约仍
优先使用兑换接口。

## 5. 履约请求示例

### 5.1 余额充值

```http
POST /api/v1/admin/redeem-codes/create-and-redeem
x-api-key: <admin-api-key>
Idempotency-Key: ext-capture-order-20260728-10001
Content-Type: application/json
```

```json
{
  "code": "ext-capture-order-20260728-10001",
  "type": "balance",
  "value": 100.0,
  "user_id": 123,
  "notes": "external order 20260728-10001"
}
```

### 5.2 余额退款或扣回

退款必须使用新的 `code`，不能复用原充值码。

```json
{
  "code": "ext-refund-rf-20260728-90001",
  "type": "balance",
  "value": -25.0,
  "user_id": 123,
  "notes": "refund for order 20260728-10001"
}
```

如果扣减会使余额小于零，事务失败，兑换码保持未使用。外部平台应进入人工处理，
不能把 Sub2API 失败误记为退款已履约。

### 5.3 订阅开通或续期

```json
{
  "code": "ext-sub-order-20260728-20001",
  "type": "subscription",
  "value": 29.9,
  "user_id": 123,
  "group_id": 8,
  "validity_days": 30,
  "notes": "30-day subscription renewal"
}
```

同一用户、同一分组已有未过期订阅时，从原 `expires_at` 继续增加天数；已过期时
从当前时间重新起算。

### 5.4 订阅退款或扣减

```json
{
  "code": "ext-sub-refund-rf-20260728-90002",
  "type": "subscription",
  "value": -9.97,
  "user_id": 123,
  "group_id": 8,
  "validity_days": -10,
  "notes": "partial subscription refund"
}
```

负天数会缩短现有订阅；扣减覆盖全部剩余有效期时会取消订阅。退款码必须是新的
业务动作，不能复用原购买码。

## 6. 推荐订单状态机

外部平台至少区分：

```text
created
  -> paid
  -> fulfilling
  -> fulfilled

fulfilling
  -> retryable_failure
  -> manual_review

fulfilled
  -> refund_pending
  -> refunded
```

关键规则：

1. 支付成功和权益发放成功必须分别落库。
2. 支付回调验签后先记录 `paid`，再调用 Sub2API。
3. 每个 capture/refund/补偿动作有独立业务 ID、`code` 和 `Idempotency-Key`。
4. 网络超时或未知结果时，使用相同 key 和完全相同请求体重试。
5. 同一 key 返回 `IDEMPOTENCY_IN_PROGRESS` 时遵守 `Retry-After`。
6. 仍无法确认时，用固定 `code` 搜索兑换记录，校验 `status=used` 和
   `used_by` 是否等于目标用户。
7. 不以客户端跳转成功页作为支付成功或权益发放依据。

兑换时，兑换码标记已用与余额/订阅权益变更在同一数据库事务内完成。固定码的
初次创建发生在该事务之前；如果创建成功但后续发放失败，可能留下未使用码。
使用相同 `code` 重试会继续完成发放。

## 7. 推荐部署边界

```text
浏览器/iframe
  -> 外置平台前端
  -> 外置平台后端
       1. 用用户 JWT 调 Sub2API /auth/me
       2. 校验订单、价格和支付回调
       3. 通过受限 Admin API 代理发放权益
  -> Sub2API
```

安全要求：

- Admin API Key 只保存在外置平台后端的密钥存储中。
- 外置平台数据库保存金额最小单位整数和币种，不直接用浮点数做财务账。
- 调用 Sub2API 时才按约定换算 `value`；Sub2API 兑换码本身没有 `currency` 字段。
- 使用 TLS、固定出口 IP、反向代理 IP allowlist 和请求/响应脱敏日志。
- 不记录用户 JWT、Admin API Key、完整支付凭证。
- 轮换 Admin API Key 时应支持短暂停机切换，因为当前只有一个有效 key。

### 7.1 最小接口白名单

建议在 Sub2API 前增加仅供外置平台访问的反向代理，只放行：

```text
GET  /api/v1/auth/me
GET  /api/v1/admin/users/:id
GET  /api/v1/admin/users/:id/subscriptions
GET  /api/v1/admin/users/:id/balance-history
GET  /api/v1/admin/groups/all
GET  /api/v1/admin/groups/:id
GET  /api/v1/admin/subscriptions/:id
GET  /api/v1/admin/subscriptions/:id/progress
GET  /api/v1/admin/redeem-codes
GET  /api/v1/admin/redeem-codes/:id
POST /api/v1/admin/redeem-codes/create-and-redeem
```

`/auth/me` 使用用户 JWT；其余接口由代理注入 Admin API Key。默认拒绝所有其他
`/api/v1/admin/**` 路径。

## 8. 全部管理员能力盘点

下表覆盖当前 397 个管理端路由。完整方法和路径以两个路由文件为准。

| 能力域 | 数量 | 路径前缀 | 主要功能 |
| --- | ---: | --- | --- |
| 用户 | 17 | `/admin/users` | 用户 CRUD、余额、并发、RPM、平台额度、身份绑定 |
| 分组 | 24 | `/admin/groups` | 分组 CRUD、容量、倍率、RPM、组合路由 |
| API Key 管理 | 1 | `/admin/api-keys` | 绑定分组、重置限速用量 |
| 兑换码 | 10 | `/admin/redeem-codes` | 生成、创建并兑换、查询、导出、批量修改/删除 |
| 订阅 | 12 | `/admin/subscriptions` 等 | 分配、续期、扣减、撤销、恢复、配额进度 |
| 内置支付 | 17 | `/admin/payment` | 支付配置、订单、重试、退款、套餐、支付实例 |
| 用量 | 7 | `/admin/usage` | 明细、统计、搜索、清理任务 |
| 邀请返利 | 9 | `/admin/affiliates` | 邀请、返利、转账、用户返利参数 |
| 注册优惠码 | 6 | `/admin/promo-codes` | CRUD 和使用记录 |
| 上游账号 | 51 | `/admin/accounts` | CRUD、导入导出、刷新、模型、额度、批处理 |
| Claude OAuth | 6 | `/admin/accounts/*auth*` | 授权 URL、code/cookie/setup-token 交换 |
| OpenAI OAuth | 9 | `/admin/openai` 等 | OAuth、PAT、额度、影子账号 |
| Gemini OAuth | 3 | `/admin/gemini` | OAuth 和能力查询 |
| Antigravity OAuth | 3 | `/admin/antigravity` | OAuth 和刷新 |
| Grok OAuth | 10 | `/admin/grok` | OAuth、SSO 导入、对账、额度 |
| 代理 | 14 | `/admin/proxies` | CRUD、导入导出、测试、质量、批量处理 |
| 渠道 | 7 | `/admin/channels` | 渠道 CRUD 和模型定价 |
| 错误透传 | 5 | `/admin/error-passthrough-rules` | 错误透传规则 CRUD |
| TLS 指纹 | 5 | `/admin/tls-fingerprint-profiles` | 指纹模板 CRUD |
| 仪表盘 | 13 | `/admin/dashboard` | 趋势、排行、模型/用户/API Key 聚合 |
| 运维 | 48 | `/admin/ops` | 实时流量、告警、错误、系统日志、运行参数 |
| 内容风控 | 8 | `/admin/risk-control` | 配置、状态、日志、解封、风险哈希 |
| 提示词审计 | 10 | `/admin/prompt-audit` | 配置、探测、运行状态、事件管理 |
| 操作审计 | 3 | `/admin/audit-logs` | 查询、详情、TOTP 清理 |
| 合规确认 | 2 | `/admin/compliance` | 状态和确认 |
| 定时测试 | 5 | `/admin/scheduled-test-plans` | 计划 CRUD、结果、账号关联 |
| 渠道监控 | 15 | `/admin/channel-monitors` 等 | 监控和请求模板 CRUD、运行、历史 |
| 系统设置 | 26 | `/admin/settings` | 全局设置、邮件、Admin Key、运行策略 |
| 公告 | 6 | `/admin/announcements` | CRUD 和已读状态 |
| 用户属性 | 8 | `/admin/user-attributes` 等 | 属性定义、排序、用户值 |
| 数据管理 | 17 | `/admin/data-management` | 数据源、S3 profile、备份任务 |
| 备份 | 14 | `/admin/backups` | S3、对象存储、计划、创建、下载、恢复 |
| 系统 | 6 | `/admin/system` | 版本、升级、回滚、重启 |
| **合计** | **397** |  |  |

## 9. 当前接口缺口和风险

在开发外置平台前，应明确以下现状：

1. Admin API Key 是全权限单密钥。泄露后可访问系统、账号、备份等全部管理能力。
2. 没有面向外部平台的 scope、独立调用方、IP 限制、签名或密钥过期机制。
3. 没有独立的外部订单/退款资源；只能用兑换码 `code` 和 `notes` 关联外部单号。
4. `value` 使用 `float64` 且没有币种字段，不能作为外部平台的财务总账。
5. `GET /api/v1/admin/redeem-codes/stats` 当前固定返回零。
6. `GET /api/v1/admin/users/:id/usage` 当前也是占位统计；对账应使用
   `/api/v1/admin/usage`。
7. `create-and-redeem` 的固定码创建和权益事务不是同一个事务，失败后可能留下未使用码。
8. 直接余额人工调整的历史记录写入是 best-effort，不与余额修改同事务。
9. 默认幂等配置仍处于 observe-only，服务端可能放行缺少 key 的请求。
10. 兑换码 CSV 导出一次最多查询 10000 条，不适合长期全量财务归档。
11. 购买页把用户 token 放在 URL query，可能进入浏览器历史、代理日志和 Referer。

生产级外置平台的下一步后端改造，建议增加专用的 integration credential：

- 每个调用方独立 key。
- 只授予 `users:read`、`groups:read`、`benefits:grant`、`benefits:refund`。
- key 哈希存储、到期时间、轮换重叠窗口和 IP allowlist。
- 使用 `X-Timestamp + X-Nonce + HMAC` 防重放。
- 增加一等公民的外部订单号、退款号、币种、最小货币单位和履约查询接口。

## 10. 代码依据

- 管理路由：`backend/internal/server/routes/admin.go`
- 内置支付管理路由：`backend/internal/server/routes/payment.go`
- 管理员鉴权：`backend/internal/server/middleware/admin_auth.go`
- step-up 门控：`backend/internal/server/middleware/step_up.go`
- 兑换管理 handler：`backend/internal/handler/admin/redeem_handler.go`
- 兑换事务：`backend/internal/service/redeem_service.go`
- 订阅管理 handler：`backend/internal/handler/admin/subscription_handler.go`
- 订阅续期逻辑：`backend/internal/service/subscription_service.go`
- 余额人工调整：`backend/internal/service/admin_user.go`
- 幂等实现：`backend/internal/service/idempotency.go`
- 标准响应：`backend/internal/pkg/response/response.go`
