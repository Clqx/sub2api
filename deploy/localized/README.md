# 本地化统一部署

根目录 `docker-compose.yml` 使用固定的 `sub2api-loc` 项目名、容器名、网络和数据卷，不会操作现有官方实例。

## 启动

```bash
cd /home/sub2api
cp .env.example .env
chmod 600 .env
# 替换全部 change-me 配置
# 将 REDEEM_PUBLIC_URL 和 REDEEM_FRAME_ANCESTORS 设置为浏览器实际访问地址；
# 引导任务会幂等创建用户侧“兑换中心”菜单。
# 阅读 docs/legal/admin-compliance.zh.md，并由管理员本人填写
# ADMIN_COMPLIANCE_ACK_PHRASE 后再启动
docker compose config --quiet
docker compose up -d --build
docker compose ps
```

## 对外访问安全

默认 `BIND_HOST=127.0.0.1`，生产环境应保持该设置，由同机 HTTPS 反向代理转发 Sub2API 和兑换平台。不要直接在公网暴露 PostgreSQL、Redis 或兑换平台的明文 HTTP 端口。

`REDEEM_PUBLIC_URL` 必须填写用户浏览器实际访问的 HTTPS 地址；`REDEEM_FRAME_ANCESTORS` 只填写允许嵌入兑换页的 Sub2API 精确 origin，例如：

```dotenv
REDEEM_PUBLIC_URL=https://redeem.example.com
REDEEM_FRAME_ANCESTORS="'self',https://sub2api.example.com"
```

管理员 Basic Auth、用户 JWT 和兑换会话都必须经 HTTPS 传输。Admin API Key 仅保存在 Docker 私有卷中，由兑换服务以只读方式挂载。

## 测试

```bash
docker compose --profile test run --rm redeem-tests
curl http://127.0.0.1:18080/health
curl http://127.0.0.1:8090/health
```

## 更新

```bash
git pull --ff-only origin feat/redeem-platform
docker compose up -d --build
```

## 停止

```bash
docker compose down
```

不要执行 `docker compose down -v`，除非确定需要删除本地化栈的全部 PostgreSQL、Redis、应用数据和引导密钥。
