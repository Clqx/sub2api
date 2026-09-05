# 成本控制修复：服务端升级说明

适用分支：`codex/monitor-trusted-pool-hardening`。请使用本次提交交付的 SHA 固定版本，不使用会移动的 `latest` 作为验收依据。

## 必须先知道的事项

- 顺序：构建镜像 → 停 Monitor → 备份 → 升级目标 Sub2API → 迁移 Monitor 数据库 → 启动 Monitor → 验收。
- “目标 Sub2API”指 Monitor 中配置的目标地址对应的网关；不是仅升级 Monitor，也不一定是网关账号中配置的远端上游供应商。
- 本次新增专用成本控制接口、用量游标接口。官方 `weishaw/sub2api:latest` 不应被当作已经包含本分支修复；请从交付源码构建目标镜像。
- 保留现有 Compose 项目名、全部 override 文件、端口、网络、卷和 `.env`。不要用示例 `.env` 覆盖现有配置，不要执行 `docker compose down -v`，不在此次升级中更换 PostgreSQL/Redis 主版本。
- 备份两个数据库和现有运行配置，尤其是 `MONITOR_MASTER_KEY`（或对应密钥文件）、数据库连接信息。丢失/更换主密钥会导致原有目标和通知凭据无法解密。
- 已开启 execute 的策略升级后仍开启；新阈值 `maximum_multiplier` 默认 **1**，倍率 **大于等于 1** 的非兜底账号会被抑制。先核对安全兜底和策略配置；如需人工验收后再自动运行，可在停机前将策略切换为推荐模式。
- 需要维护窗口：旧流式响应/长连接应先排空；被抑制的 WebSocket 下一轮会要求客户端重连并重发完整历史，不能把仅有 `previous_response_id` 的上下文无损搬到另一账号。

## 1. 获取代码并构建

下面为 Linux / Bash 示例。源码目录、部署目录和 Compose 参数应替换为服务器实际配置；工作区有修改时先处理冲突，不使用强制覆盖命令。

```bash
cd /path/to/sub2api-source
git status --short
git fetch origin
git switch --detach <本次交付的提交SHA>

export COST_GATE_RELEASE="costgate-$(git rev-parse --short=12 HEAD)"
export MONITOR_IMAGE_TAG="$COST_GATE_RELEASE"

docker build --build-arg COMMIT="$(git rev-parse HEAD)" \
  -t "sub2api-monitor-target:$COST_GATE_RELEASE" .
```

明确两个部署的原始 Compose 命令。下面数组只是示例；如果原来带有 `-p`、`--env-file`、多个 `-f`，这里必须完整保留。执行 `ps` 后确认列出的就是现有容器；不要误创建一套新项目。

```bash
TARGET_DIR=/path/to/existing-sub2api-deployment
MONITOR_DIR=/path/to/sub2api-source/sub2api-monitor

TDC=(docker compose --project-directory "$TARGET_DIR" -f "$TARGET_DIR/docker-compose.yml")
MDC=(docker compose --project-directory "$MONITOR_DIR" -f "$MONITOR_DIR/compose.yaml")
"${TDC[@]}" ps
"${MDC[@]}" ps

# 标准 Monitor Compose 中 migrate/api/worker 共用同一个 backend 镜像。
"${MDC[@]}" build migrate web
```

目标服务名：`deploy/docker-compose.yml` 是 `sub2api`，仓库根目录的本地化 Compose 是 `sub2api-loc`。在现有部署目录新增仅覆盖该服务镜像的 `cost-gate.override.yaml`，例如标准部署：

```yaml
services:
  sub2api:
    image: sub2api-monitor-target:${COST_GATE_RELEASE:?set release tag}
```

将 override 加到命令数组末尾，其他参数不变；本地化部署须将 YAML 服务名和变量一起换成 `sub2api-loc`。

```bash
TDC+=(-f "$TARGET_DIR/cost-gate.override.yaml")
TARGET_SERVICE=sub2api
```

把 `COST_GATE_RELEASE` 和 `MONITOR_IMAGE_TAG` 的确切值记录到对应部署的现有环境配置中，供下一次重启使用；只更新这些镜像标签，不替换整份 `.env`。保留旧镜像及其镜像 ID 以便回滚。

## 2. 停 Monitor 并备份

构建成功后再进入停机窗口。任何命令失败立即停止后续步骤。

```bash
"${MDC[@]}" stop worker api web

umask 077
BACKUP_DIR="$(mktemp -d /var/tmp/sub2api-costgate-backup.XXXXXX)"
# 仅适用于默认内置 monitor-postgres；外部数据库应备份实际连接的库。
"${MDC[@]}" exec -T monitor-postgres pg_dump -U monitor -d monitor -Fc \
  > "$BACKUP_DIR/monitor.dump"
test -s "$BACKUP_DIR/monitor.dump"
```

同时按现有运维流程备份目标 Sub2API 数据库、两端配置和密钥；检查 `pg_dump` 退出码及备份可恢复性。不要把包含密钥的备份提交到 Git。数据库恢复会覆盖备份之后的新数据，应另行评估，不能自动执行。

## 3. 先升级目标 Sub2API

```bash
"${TDC[@]}" up -d --no-deps --no-build --force-recreate --wait "$TARGET_SERVICE"
"${TDC[@]}" logs --tail=100 "$TARGET_SERVICE"
```

确认目标健康、登录和正常请求可用，且镜像确为本次构建版本。若服务端原版本较旧，分支中其他历史数据库迁移也可能随 Sub2API 启动执行；应先在预发布演练，不能把本次补丁当成跨任意旧版本的无风险升级。

使用已有管理员认证只读请求目标的：

```text
GET /api/v1/admin/usage?page=1&page_size=1&sort_by=id&sort_order=asc&after_id=0
```

必须得到 HTTP 200 和响应头 `X-Usage-Cursor-Version: 1`。经过反向代理时也应保留此响应头。专用成本接口为 `PUT /api/v1/admin/accounts/:id/monitor-cost-routing`；不要为了探活对生产账号随意发送写请求。

## 4. 迁移并启动 Monitor

保留原有环境变量、secret 文件挂载、外部网络。本步骤只对 Monitor 数据库执行 Alembic，不能连接目标 Sub2API 数据库。

```bash
# 数据库应保持运行。显式完成迁移后才启动新版应用。
"${MDC[@]}" run --rm --no-deps migrate
"${MDC[@]}" run --rm --no-deps migrate alembic current

# 本次版本应为 ab71c4e20319 (head)。不是该版本或迁移失败时不要继续。
"${MDC[@]}" up -d --no-deps --no-build --force-recreate --wait api worker
"${MDC[@]}" up -d --no-deps --no-build --force-recreate --wait web
"${MDC[@]}" ps
"${MDC[@]}" logs --tail=200 api worker
```

迁移新增 `cost_routing_policies.maximum_multiplier`（既有策略默认 1）及 `routing_usage_cursors`；不删除账号、目标、通知或原策略数据。Compose 原本就提供了 migrate 服务，上面显式执行是为了避免旧应用与新迁移并行运行。

## 5. 升级后验收

1. 页面可以登录，目标连接正常；首次游标观察日志有 `baseline=True`，之后 `routing usage observed` 持续出现，cursor 随新用量递增。
2. 检查阈值、兜底、执行/推荐模式和订阅过滤。ntfy/TG 应启用 `incident.firing` / `incident.escalated` / `incident.resolved`、`routing.account_switched`、`routing.rate_recovered`，并包含 `warning` 严重度。`upstream.rate_multiplier.changed` 是倍率变化的 incident 类型，不是可填写的订阅事件名；过滤掉的事件不会发送。
3. 在隔离测试分组依次测试三账号低倍率 → 部分账号升至阈值以上 → 兜底承接 → 一个账号降价切回。不要在生产账号上未经确认改倍率。
4. 区分日志中的 `desired_suppressed`（计划）与 `applied_suppressed`（已确认写入）。实际切换必须由新用量证明；请求需要稳定会话标识，单纯优先级更新不等于切换。
5. 在通知历史确认发送成功，并在 ntfy/TG 接收端实际看到通知；outbox 已入队不等于远端送达。首次初始化不补发历史切换。
6. 分组计费倍率与账号上游成本分别展示；超过 180 秒的质量聚合显示过期、当前健康未知。模型检测仍暂停，旧绑定不应阻断普通策略保存。

完整场景及本地测试证据见 [COST_GATE_ACCEPTANCE.md](COST_GATE_ACCEPTANCE.md)。

## 回滚边界

- 优先停止 Monitor worker，保留新 Sub2API 网关，再排查或回滚 Monitor 镜像。停策略或停 Worker 不会自动清除已生效的成本抑制，也不会自动恢复手动停用账号。
- 不要直接把仍有成本抑制标记的目标退回旧网关：旧网关可能忽略标记，重新向高倍率账号发送请求。若必须回滚，先在管理后台手动停用需抑制的账号、确认可用兜底并排空请求。
- 不默认执行 `alembic downgrade`：它会删除新增游标及阈值字段；表结构、代码和运行状态要一起评估。优先保留增量表结构，必要恢复前先验证备份并处理新写入数据。
