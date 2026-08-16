# 上游账号倍率适应与 OpenCode 连续会话测试方案

## 1. 目标

验证 Sub2API Monitor 能读取 `https://ai.whiles.cc/` 三个指定账号的
`rate_multiplier`，在倍率逐步上调后正确计算和执行优先级，降低高倍率账号被调度的
机会；同时用 OpenCode 在同一 session 中连续对话，验证账号切换不破坏会话上下文。

主要验收证据是 Monitor Worker 日志、路由决策、审计事件和 Whiles 账号使用统计。
页面排序仅作辅助证据。

## 2. 被测对象与信号规则

| 账号 | ID | 分组 | 原始倍率 | 原始优先级 | 初始状态 |
| --- | ---: | --- | ---: | ---: | --- |
| `GLM` | `12` | `admin专用` | `1.0` | `1` | 正常、调度开启 |
| `GLM (Copy)` | `16` | `admin专用` | `1.0` | `1` | 正常、调度开启 |
| `GLM (Copy) (Copy)` | `17` | `admin专用` | `1.0` | `1` | 正常、调度开启 |

真实联调为每个账号建立了一个专属测试分组和一把独立 Key。Whiles 会通过 Key 对外
声明所属分组的有效倍率，因此测试时必须把测试分组倍率与对应账号倍率同步修改。Monitor
的取值规则为：

1. 探测为 `ok` 且倍率有效时，使用 `upstream_probe`。
2. 探测明确为 `unsupported` 时，使用账号配置倍率 `account_config`。
3. 网络、鉴权、服务端错误或格式错误不回退，账号进入 `unhealthy_priority`。
4. 倍率越高，目标优先级数值越高；Sub2API 优先使用数值更小的账号。

## 3. 拓扑

| 组件 | 地址 | 用途 |
| --- | --- | --- |
| 本地 Sub2API | `http://127.0.0.1:18080` | OpenCode 的本地入口和下游集成环境 |
| Sub2API Monitor | `http://127.0.0.1:8080` | 采集本地 Sub2API、探测 Whiles 有效倍率、计算路由并记录日志/审计 |
| Whiles | `https://ai.whiles.cc/` | 持有账号 `12/16/17` 并执行实际账号调度 |

为避免使用或重置 Whiles 全局管理员 Key，实际采用三路隔离拓扑：

| Whiles 测试分组 | 唯一账号 | 本地账号 |
| --- | --- | --- |
| `monitor-rate-glm-12` | `#12` | `whiles-glm-12` |
| `monitor-rate-glm-16` | `#16` | `whiles-glm-16` |
| `monitor-rate-glm-17` | `#17` | `whiles-glm-17` |

三把 Whiles Key 分别绑定一个测试分组，本地三个账号共同进入
`monitor-rate-test-local`。Monitor 连接本地 Sub2API，成本路由探测通过三把上游 Key
读取 Whiles 对外声明倍率并只更新本地账号优先级。OpenCode 只访问本地
`http://127.0.0.1:18080/v1`。

## 4. 路由策略和阶段矩阵

Monitor 先使用 `recommend` 模式：

- `priority_scale=100`
- `minimum_priority=1`
- `unhealthy_priority=10000`
- 不绑定质量监控，避免把倍率测试与质量故障混在一起

| 阶段 | #12 | #16 | #17 | 期望优先级 | 期望调度顺序 |
| --- | ---: | ---: | ---: | --- | --- |
| B0 基线 | `0.3` | `0.5` | `0.8` | `30 / 50 / 80` | `12 -> 16 -> 17` |
| B1 提高 #12 | `1.2` | `0.5` | `0.8` | `120 / 50 / 80` | `16 -> 17 -> 12` |
| B2 提高 #16 | `1.2` | `1.4` | `0.8` | `120 / 140 / 80` | `17 -> 12 -> 16` |
| B3 提高 #17 | `1.2` | `1.4` | `1.6` | `120 / 140 / 160` | `12 -> 16 -> 17` |
| R 回滚 | `1.0` | `1.0` | `1.0` | 恢复 `1 / 1 / 1` | 恢复原始配置 |

“抑制”在当前实现中指提高数字优先级、降低调度顺位，不是关闭账号。若需要倍率超过
阈值后强制停用，应另立阈值策略测试，不能把优先级降权表述为硬禁用。

## 5. 日志验收

每次路由运行都从 Worker 日志保存一个有时间范围的片段。日志不得包含 API Key、
Cookie 或账号凭据。

每个账号必须出现：

```text
cost routing account evaluated policy_id=... target_id=... account_id=1 multiplier=0.3 cost_source=upstream_probe available=True previous_priority=1 desired_priority=30 reason=...
```

执行模式写入时必须出现：

```text
cost routing priority write ... account_id=1 previous_priority=... desired_priority=... cost_source=upstream_probe status=succeeded error=none
```

每轮末尾必须出现：

```text
cost routing run succeeded ... mode=... account_count=3 change_count=...
```

通过条件：倍率、来源、目标优先级、原因和写入状态与阶段矩阵一致；未变账号不能重复
产生新的建议决策；任何真实探测失败必须记录 `cost_source=none`、
`reason=probe_failed` 和目标优先级 `10000`。

## 6. OpenCode 连续会话用例

使用已安装的 OpenCode `1.18.18`，模型选择三个 GLM 账号共同支持的最小文本模型。
开启 `--format json --print-logs`，保存脱敏输出和 session ID。

1. B0 后发起主 session，记住 `M-A`，并从本地使用日志确认命中 #12。
2. B1-B3 每轮先创建一个独立新 session，确认新请求命中当轮最低优先级账号。
3. OpenAI 调度对主 session 有账号亲和；单纯提高优先级不会抢占现有绑定。因此每轮先
   验证旧 session 仍粘在原账号，再临时把原账号设为不可调度，继续同一个 OpenCode
   session，确认它切到新账号且能返回 `M-A/M-B`，随后立即恢复调度开关。
4. 每轮后读取本地 Sub2API 使用日志中的 `account_id/account_name`，并保存同时间窗口的
   Monitor Worker 日志。

通过条件：连续性主用例始终使用同一 session ID；每次强制迁移后标记完全一致；独立
新 session 命中阶段最低优先级账号。已有粘性 session 继续使用原账号是当前调度器的
设计行为，不应误判为 Monitor 优先级写入失败。

## 7. ntfy 通知验收

使用 `compose.ntfy-local.yaml` 在 Monitor 内部网络启动 ntfy，主机订阅入口为
`http://127.0.0.1:18081/<topic>`。创建绑定 `Local Sub2API` 目标的通知通道，至少订阅
`incident.firing` 与 `routing.account_switched`，严重级别包含 `warning` 和 `critical`。

1. 先调用通道测试接口，并从 ntfy 的 `<topic>/json?poll=1&since=all` 读取同一条消息，
   不以 outbox 的 `sent` 状态代替接收端证据。
2. B0 应收到三条倍率变化和三条优先级变化通知；B1-B3 每轮应分别收到当轮账号的倍率
   与优先级变化通知，消息中的旧值、新值、账号和原因必须与阶段矩阵一致。
3. 首次读取历史使用记录只建立 session 基线，不能通知历史切换。同一 OpenCode session
   强制执行 `#12 -> #16 -> #17 -> #12` 后，每次必须从 Sub2API 使用记录确认实际账号，
   并在 ntfy 收到 `routing.account_switched`，消息包含 session、原账号、新账号和 usage ID。
4. 状态不变时额外运行 Monitor 两次，倍率通知和实际切换通知数量都不得增加。
5. Worker 日志必须同时出现 `usage routes observed ... switch_count=...` 与成功的
   `POST http://ntfy/`；outbox 最终不得存在 `pending`、`retry` 或 `failed` 记录。

## 8. 实施步骤

1. 运行自动化回归，确认倍率来源、失败关闭、日志和多轮策略逻辑通过。
2. 重建 Monitor API/Worker 镜像，确认全部容器健康。
3. 在本地 Sub2API 完成运营者合规确认后，创建本地测试分组、三个隔离上游账号和
   OpenCode 测试 Key。
4. 在 Whiles 创建三个专属测试分组，每组只绑定 #12/#16/#17 中的一个账号，并为每组
   创建独立 Key；Monitor 目标仍为本地 Sub2API。
5. recommend 模式依次运行 B0-B3，每轮核对日志、决策和审计，不做优先级写入。
6. recommend 全部通过后切换 execute，重复 B0-B3；每次只修改一个账号倍率，等待
   Monitor 写入完成再继续。
7. 在 execute 各阶段运行 OpenCode 连续会话用例并核对账号统计，同时按第 7 节核对
   Monitor 日志、outbox 与 ntfy 实际订阅消息。
8. 执行 R 回滚，禁用路由策略，再恢复倍率和优先级，最后复核三账号均为原值。

## 9. 停止条件

出现以下任一情况立即停止后续变更并回滚：

- `admin专用` 存在非测试流量或不属于本次测试的用户；
- 任一写入涉及账号 `12/16/17` 以外的账号；
- Monitor 日志出现密钥、Cookie 或完整凭据；
- 路由决策与矩阵不符，或失败状态仍使用 `account_config`；
- OpenCode 连续会话出现不可恢复的上下文丢失；
- API/Worker/Whiles 任一组件连续两轮健康检查失败。

## 10. 证据与回滚

报告按阶段记录：变更前后倍率/优先级、Monitor 日志、路由决策、审计事件、Whiles
账号统计、OpenCode session ID 和标记校验结果。所有密钥只记录“已配置/未配置”。

回滚顺序固定为：禁用 Monitor 路由策略 -> 恢复本地账号优先级和倍率 `1/1/1` ->
恢复 Whiles 三账号倍率及三个测试分组倍率 `1.0/1.0/1.0` -> 复核账号状态和调度开关。
测试 Key 按运营者要求保留、由运营者稍后删除；删除 Key 后再移除测试分组、账号绑定和
用户专属分组授权。容器保留运行供复查。
