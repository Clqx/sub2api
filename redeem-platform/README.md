# Sub2API 独立兑换平台

这是一个与 Sub2API 主数据库隔离的兑换码服务，支持余额充值码、订阅续期码、履约重试、操作审计、CSV 导出和运营分析。

平台使用独立 PostgreSQL 数据库，通过 Sub2API 管理接口发放权益。兑换码明文只在生成时返回一次，数据库仅保存 HMAC 哈希和掩码；上游履约始终复用稳定业务码和 `Idempotency-Key`。

## 安全边界

`SUB2API_ADMIN_API_KEY`、`SUB2API_ADMIN_API_KEY_FILE` 或 `SUB2API_ADMIN_JWT` 只由服务端读取，不会进入 HTML、浏览器存储、URL、接口响应或业务日志。建议优先使用 Admin API Key，并在 Sub2API 反向代理中只允许兑换平台访问：

```text
GET  /api/v1/auth/me
GET  /api/v1/admin/groups/all
POST /api/v1/admin/redeem-codes/create-and-redeem
```

用户从 Sub2API 菜单进入时，平台使用 URL 中的用户 JWT 调用 `/api/v1/auth/me`，然后签发 15 分钟的平台会话。浏览器读取参数后会立即从地址栏和历史记录中移除 `token`。

## 统一 Docker Compose

仓库根目录的 `docker-compose.yml` 统一管理：

- 本地源码构建的 `sub2api-loc`
- PostgreSQL 和 Redis
- 兑换平台 PostgreSQL 独立数据库
- Admin API Key 一次性引导容器
- 兑换平台
- PostgreSQL 集成测试 profile

```bash
cd /home/sub2api
cp .env.example .env
# 修改 .env 中的全部 change-me 值
docker compose up -d --build
```

默认地址：

- 本地化 Sub2API：`http://127.0.0.1:18080`
- 用户兑换页：`http://127.0.0.1:8090/`
- 管理运营台：`http://127.0.0.1:8090/admin`
- 健康检查：`http://127.0.0.1:8090/health`

完整 PostgreSQL 集成测试：

```bash
docker compose --profile test run --rm redeem-tests
```

管理运营台使用 `REDEEM_MANAGER_USERNAME` 和 `REDEEM_MANAGER_PASSWORD` 做 HTTP Basic 身份验证。对外提供服务时必须使用 HTTPS 反向代理。

## 直接运行

要求 Node.js 24 或更高版本，并准备可用的 PostgreSQL 数据库：

```bash
cp .env.example .env
npm ci
set -a
. ./.env
set +a
npm start
```

数据库迁移在启动时自动执行，并通过 PostgreSQL advisory lock 和迁移校验和避免并发或篡改。

## 嵌入 Sub2API 菜单

1. 在 Sub2API 管理设置的“自定义菜单”中新增用户菜单。
2. URL 填写兑换平台公网 HTTPS 地址。
3. 将 Sub2API 的精确 origin 写入 `REDEEM_FRAME_ANCESTORS`。
4. 重启兑换平台。

```dotenv
REDEEM_FRAME_ANCESTORS="'self',https://sub2api.example.com"
```

Sub2API iframe 会自动追加：

```text
user_id, token, theme, lang, ui_mode=embedded, src_host, src_url
```

`REDEEM_FRAME_ANCESTORS` 可以用逗号配置多个精确 origin，不能使用路径。

## 生成订阅兑换码

管理员进入 `/admin`，打开“兑换码”并点击“生成兑换码”：

1. 权益类型选择“订阅续期”。
2. 页面实时读取 Sub2API 已启用的订阅分组。
3. 选择分组并填写记账金额、有效天数、数量、活动标识和截止时间。
4. 生成后立即复制或下载明文兑换码，关闭窗口后不能再次查看明文。

用户兑换后，平台通过 `create-and-redeem` 将指定分组的订阅权益直接发放给已验证用户。

## 主要环境变量

| 变量 | 作用 |
| --- | --- |
| `SUB2API_BASE_URL` | Sub2API 服务端地址 |
| `SUB2API_ADMIN_API_KEY` | 管理 API Key |
| `SUB2API_ADMIN_API_KEY_FILE` | 从文件读取管理 API Key，统一 Compose 使用 |
| `SUB2API_ADMIN_JWT` | 未配置 API Key 时的备选管理员 JWT |
| `REDEEM_DATABASE_URL` | PostgreSQL 完整连接 URL，可选 |
| `REDEEM_DATABASE_HOST` | PostgreSQL 主机 |
| `REDEEM_DATABASE_USER` | PostgreSQL 用户 |
| `REDEEM_DATABASE_PASSWORD` | PostgreSQL 密码 |
| `REDEEM_DATABASE_NAME` | PostgreSQL 数据库名 |
| `REDEEM_CODE_PEPPER` | 兑换码 HMAC Pepper，至少 32 字符 |
| `REDEEM_SESSION_SECRET` | 平台短会话签名密钥，至少 32 字符 |
| `REDEEM_MANAGER_USERNAME` | 运营台用户名 |
| `REDEEM_MANAGER_PASSWORD` | 运营台密码，至少 12 字符 |
| `REDEEM_FRAME_ANCESTORS` | 允许嵌入兑换页的 Sub2API origins |
| `REDEEM_TRUST_PROXY` | 是否信任反向代理传入的客户端 IP |

完整配置见 [`.env.example`](./.env.example)。

## 本地演示

演示模式不调用 Sub2API，但仍使用 PostgreSQL：

```bash
export REDEEM_DEMO_MODE=true
export REDEEM_MANAGER_AUTH_DISABLED=true
export REDEEM_DATABASE_URL=postgresql://redeem_platform:password@127.0.0.1:5432/redeem_platform
npm start
```

模拟从 Sub2API 菜单进入：

```text
http://127.0.0.1:8090/?token=demo-user-10001&user_id=10001&ui_mode=embedded
```

生产环境无法启用演示模式或关闭管理认证。
