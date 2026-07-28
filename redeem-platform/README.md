# Sub2API 独立兑换平台

这是一个与 Sub2API 主数据库解耦的单机兑换码服务，支持：

- 余额充值码和订阅续期码
- 从 Sub2API 实时读取已有订阅分组并在管理网页发码
- 用户兑换、个人兑换历史
- 管理员筛选、查看履约明细、手动重试和导出 CSV
- 每日趋势、活动表现、订阅分组等分析数据
- 稳定幂等键、失败自动重试和操作审计

平台使用 Node.js 24 内置的 SQLite，运行时没有 npm 依赖。兑换码数据库只适合单副本部署。

## 安全边界

`SUB2API_ADMIN_API_KEY` 或 `SUB2API_ADMIN_JWT` 只由服务端从环境变量读取，不会进入 HTML、浏览器存储、URL、接口响应或业务日志。建议优先使用 Admin API Key，并在 Sub2API 前的反向代理中实施接口白名单，因为当前 Admin API Key 本身没有 scope：

```text
GET  /api/v1/auth/me
GET  /api/v1/admin/groups/all
POST /api/v1/admin/redeem-codes/create-and-redeem
```

用户从 Sub2API 菜单进入时，平台会用 URL 中的用户 JWT 调用 `/api/v1/auth/me`，再签发 15 分钟的平台会话。URL 中的 `user_id` 仅用于一致性检查，不能直接决定兑换目标。浏览器拿到参数后会立即从地址栏和历史记录中移除 `token`。

兑换码明文只在生成时返回一次，数据库保存 HMAC 哈希和掩码。上游履约始终复用同一个业务码和 `Idempotency-Key`，网络失败可安全重试。

## 直接运行

要求 Node.js 24 或更高版本：

```powershell
Copy-Item .env.example .env
# 编辑 .env 后，将变量导入当前进程或使用容器启动
node src/server.mjs
```

默认地址：

- 用户兑换页：`http://127.0.0.1:8090/`
- 管理运营台：`http://127.0.0.1:8090/admin`
- 健康检查：`http://127.0.0.1:8090/health`

管理运营台使用 `REDEEM_MANAGER_USERNAME` 和 `REDEEM_MANAGER_PASSWORD` 做 HTTP Basic 身份验证。生产环境必须通过 HTTPS 反向代理访问。

## Docker 部署

```powershell
Copy-Item .env.example .env
# 填写所有密钥与真实域名
docker compose up -d --build
```

Compose 只监听宿主机 `127.0.0.1:8090`，应由 Nginx、Caddy 或其他 TLS 反向代理对外发布。SQLite 数据位于命名卷 `redeem-platform-data`。不要将服务横向扩容为多个副本。

生产启动会拒绝以下不安全配置：

- 缺少 Sub2API 管理凭据
- 管理密码短于 12 个字符
- 代码 Pepper 或会话密钥短于 32 个字符
- 启用演示模式或关闭管理认证

## 嵌入 Sub2API 菜单

1. 在 Sub2API 管理设置的“自定义菜单”中新增用户菜单。
2. URL 填写兑换平台公网地址，例如 `https://redeem.example.com/`。
3. 在兑换平台设置：

```dotenv
REDEEM_FRAME_ANCESTORS='self',https://sub2api.example.com
```

4. 重启兑换平台，并确保两个站点都使用 HTTPS。

Sub2API iframe 会自动追加：

```text
user_id, token, theme, lang, ui_mode=embedded, src_host, src_url
```

兑换页识别 `ui_mode=embedded` 后会隐藏重复页头并压缩留白。`REDEEM_FRAME_ANCESTORS` 必须填写 Sub2API 的精确 origin，可以用逗号配置多个来源，不能使用泛域路径。

## 生成已有订阅的兑换码

管理员进入 `/admin`，打开“兑换码”并点击“生成兑换码”：

1. 权益类型选择“订阅续期”。
2. 页面实时调用 Sub2API `/api/v1/admin/groups/all`。
3. 下拉框只展示 `status=active` 且 `subscription_type=subscription` 的已有订阅分组。
4. 选择分组，填写记账金额、有效天数、数量、活动标识和截止时间。
5. 生成后立即复制或下载明文兑换码；关闭窗口后不能再次查看明文。

`value` 是 Sub2API 兑换记录使用的记账金额；`validity_days` 决定订阅延长天数。用户兑换后，平台通过 `create-and-redeem` 将指定分组的订阅权益直接发放给已验证用户。

## 管理与分析

运营台包括：

- 概览：总量、成功率、余额充值额、订阅天数、每日趋势、活动与分组排行
- 兑换记录：按用户、业务码、活动、状态、类型和时间范围筛选
- 兑换详情：上游业务码、幂等键、每次履约状态、耗时和错误信息
- CSV 导出：导出当前筛选范围，单次最多 10000 条
- 兑换码库存：查看掩码、权益、有效期、状态，停用未使用的码
- 审计：所有发码、领用、履约、重试和停用操作保存在 `audit_events`

分析和导出的金额来自平台本地履约记录，用于运营分析；财务对账仍应结合 Sub2API 余额历史和实际收款系统。

## 主要环境变量

| 变量 | 作用 |
| --- | --- |
| `SUB2API_BASE_URL` | Sub2API 服务端地址 |
| `SUB2API_ADMIN_API_KEY` | 首选的管理 API Key |
| `SUB2API_ADMIN_JWT` | 未配置 API Key 时的备选管理员 JWT |
| `REDEEM_CODE_PEPPER` | 兑换码 HMAC Pepper，至少 32 字符 |
| `REDEEM_SESSION_SECRET` | 平台短会话签名密钥，至少 32 字符 |
| `REDEEM_MANAGER_USERNAME` | 运营台用户名 |
| `REDEEM_MANAGER_PASSWORD` | 运营台密码，至少 12 字符 |
| `REDEEM_FRAME_ANCESTORS` | 允许嵌入兑换页的 Sub2API origins |
| `REDEEM_DATABASE_PATH` | SQLite 文件路径 |
| `REDEEM_TRUST_PROXY` | 是否信任反向代理传入的客户端 IP |

完整配置见 [`.env.example`](./.env.example)。

## 本地演示

演示模式只用于本地验证，不连接 Sub2API：

```powershell
$env:REDEEM_DEMO_MODE='true'
$env:REDEEM_MANAGER_AUTH_DISABLED='true'
$env:REDEEM_DATABASE_PATH="$PWD\data\demo.db"
node src/server.mjs
```

用以下地址模拟从 Sub2API 菜单进入：

```text
http://127.0.0.1:8090/?token=demo-user-10001&user_id=10001&ui_mode=embedded
```

生产环境 (`NODE_ENV=production`) 无法启用演示模式或关闭管理认证。
