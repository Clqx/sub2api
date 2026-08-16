# 上游账号倍率适应测试报告

## 结论

2026-08-16 端到端测试通过。Monitor 能通过本地 Sub2API 的三个隔离上游账号探测
Whiles 有效倍率，按 `priority = multiplier × 100` 更新优先级，并在倍率逐步升高时让
新会话依次选择 `#12 -> #16 -> #17 -> #12`。Worker 日志中的倍率、来源、原因、目标
优先级和写入状态均与测试矩阵一致，未出现凭据泄漏。

OpenCode 主 session `ses_ff72f607affelaDsGEgEgKDrUZ` 在强制解除旧账号亲和后完成
`#12 -> #16 -> #17 -> #12` 的跨账号迁移，始终正确返回
`M-A=RIVER-314159;M-B=EMBER-271828`，未发生上下文丢失。

## 实际拓扑

| Whiles 测试分组 | Whiles 账号 | 本地账号 | 本地账号 ID |
| --- | --- | --- | ---: |
| `monitor-rate-glm-12` | `GLM #12` | `whiles-glm-12` | `1` |
| `monitor-rate-glm-16` | `GLM (Copy) #16` | `whiles-glm-16` | `2` |
| `monitor-rate-glm-17` | `GLM (Copy) (Copy) #17` | `whiles-glm-17` | `3` |

三个 Whiles 分组均为专属分组且只含一个账号；三把 Key 分别注入一个本地账号。本地
三个账号共同属于 `monitor-rate-test-local`。Monitor 目标为 `Local Sub2API`
（`b6fce0a4-f5fd-4839-bfea-885b45345989`），OpenCode 通过
`http://127.0.0.1:18080/v1` 调用 `glm-4.7`。

Whiles 对外声明的是 API Key 所属分组的有效倍率。为保证探测倍率与账号真实成本配置
一致，每个阶段同时修改对应测试分组倍率和账号倍率；Monitor 决策来源均为
`cost_source=upstream_probe`。

## 阶段结果

| 阶段 | 探测倍率 #12/#16/#17 | 写入优先级 | 新 session 实际账号 | 主 session 强制迁移后账号 | 连续性 |
| --- | --- | --- | --- | --- | --- |
| B0 | `0.3 / 0.5 / 0.8` | `30 / 50 / 80` | #12 | #12 | `M-A` 已保存 |
| B1 | `1.2 / 0.5 / 0.8` | `120 / 50 / 80` | #16 | #16 | `M-A/M-B` 正确 |
| B2 | `1.2 / 1.4 / 0.8` | `120 / 140 / 80` | #17 | #17 | `M-A/M-B` 正确 |
| B3 | `1.2 / 1.4 / 1.6` | `120 / 140 / 160` | #12 | #12 | `M-A/M-B` 正确 |

本地使用日志逐轮确认了 `account_id=1/2/3/1`，不是仅依据页面排序推断。

## 重复稳定性测试

同日完成第二轮重复测试。每个倍率阶段运行 3 个全新 OpenCode session，共 12 个；全部
成功且全部命中该阶段最低优先级账号：

| 阶段 | 3 次新 session 的预期账号 | 实际账号 | 本地使用日志 ID | 结果 |
| --- | --- | --- | --- | --- |
| B0 | `whiles-glm-12` | `1 / 1 / 1` | `10 / 11 / 12` | `3/3` 通过 |
| B1 | `whiles-glm-16` | `2 / 2 / 2` | `16 / 17 / 18` | `3/3` 通过 |
| B2 | `whiles-glm-17` | `3 / 3 / 3` | `21 / 22 / 23` | `3/3` 通过 |
| B3 | `whiles-glm-12` | `1 / 1 / 1` | `26 / 27 / 28` | `3/3` 通过 |

第二轮连续性主 session 为 `ses_ff7139c32ffeilPtz03Ye2sReK`。测试在每阶段先验证原账号
粘性，再短暂关闭当前本地账号调度，强制同一 session 依次迁移
`#12 -> #16 -> #17 -> #12`。对应迁移前/后的使用日志为 `14 -> 15`、`19 -> 20`、
`24 -> 25`。最终导出的会话记录仍准确包含：

`R-A=ORBIT-424242`、`R-B=QUARTZ-161803`、`R-C=NEBULA-577215`、
`R-D=VECTOR-141421`。

Monitor 在每阶段连续手工运行 3 次。B0 的 `change_count` 为 `3/0/0`，B2 和 B3 均为
`1/0/0`。B1 的 30 秒定时任务在手工运行前已完成唯一一次 `30 -> 120` 写入，因此三次
手工运行均为 `0/0/0`；本地优先级和 Worker 写入日志共同确认变更已生效。第二轮日志
窗口内共执行 30 次路由运行、评估 90 个账号，仅发生 6 次必要写入，90 次评估均为
`cost_source=upstream_probe`，路由运行失败数为 0。

## Monitor 日志与决策

- B0：三个账号分别记录 `multiplier=0.3/0.5/0.8`、
  `desired_priority=30/50/80`、`cost_source=upstream_probe`，执行写入均为
  `status=succeeded`。
- B1：#12 记录 `reason=cost_increase`，从 `30` 写到 `120`；其余账号为
  `reason=in_sync`。
- B2：#16 从 `50` 写到 `140`，`change_count=1`；下一轮三个账号全部
  `reason=in_sync`、`change_count=0`。
- B3：#17 从 `80` 写到 `160`，`change_count=1`；下一轮稳定为
  `120/140/160`。
- 连续性强制迁移期间，#12 曾短暂不可调度；Monitor 正确写入
  `unhealthy_priority=10000`，恢复调度后又从 `10000` 修复到 `120`。这验证了故障抑制
  和恢复路径。

## ntfy 端到端通知测试

本地 ntfy `2.27.0` 通过 `compose.ntfy-local.yaml` 启动在
`http://127.0.0.1:18081`，测试主题为 `sub2api-routing-test-20260816`，Monitor 通道 ID 为
`d5f7cf2b-cfe9-430f-a466-eb11ab71ef3a`。通道测试消息先由 outbox 投递，再从 ntfy JSON
订阅接口实际读回，确认不是只依赖发送端状态。

倍率阶段和回滚阶段共收到 9 条 `Upstream rate multiplier changed`：B0 的三账号基线
变化、B1-B3 的三次逐步上调、以及三账号恢复为 `1.0`。消息准确包含
`0.3 -> 1.2`、`0.5 -> 1.4`、`0.8 -> 1.6` 及对应回滚值；相关优先级通知也准确反映
`30 -> 120`、`50 -> 140`、`80 -> 160`。

实际切换使用 OpenCode session `ses_ff6e1d95dffeu1ugH5SVsQrW8u`，Monitor 首次扫描 17 个
已有 session 时只建立基线，`switch_count=0`。之后 ntfy 收到且仅收到以下三条实际切换：

| usage ID | 原账号 | 新账号 | ntfy 结果 |
| ---: | --- | --- | --- |
| `32` | `whiles-glm-12 (1)` | `whiles-glm-16 (2)` | 已接收 |
| `34` | `whiles-glm-16 (2)` | `whiles-glm-17 (3)` | 已接收 |
| `36` | `whiles-glm-17 (3)` | `whiles-glm-12 (1)` | 已接收 |

稳定状态下额外触发两轮 Monitor 后，ntfy 总消息数保持 25、实际切换消息保持 3，证明
重复扫描不会重发。含回滚通知的最终主题缓存共 31 条：测试消息 1、倍率变化 9、实际
切换 3、账号不可用 3、优先级变化 15；Monitor outbox 的 31 条记录全部为 `sent`。

同一 OpenCode session 共 7 个 assistant 回合，最终导出仍完整包含
`NTFY-A=CEDAR-830471`、`NTFY-B=MAPLE-271828`、`NTFY-C=ASH-161803`、
`NTFY-D=BIRCH-141421`，三次实际账号迁移未破坏对话连续性。

## OpenCode 亲和与连续性结论

优先级调整会影响新 session，但不会抢占已有 OpenAI 粘性 session。B1 中主 session 在
#12 已升为 `120` 后仍继续使用 #12，而一个新 session 立即选择优先级 `50` 的 #16。
这是 Sub2API `tryStickySessionHit` 的既有设计，并非 Monitor 写入失败。

为验证真实跨账号连续性，测试对主 session 当前绑定账号做了短暂
`schedulable=false`，请求完成后立即恢复。调度器清除无效亲和并选择新最低优先级账号；
OpenCode 依靠完整会话上下文，在三次迁移后仍准确返回两个标记。因此：

- 新会话的高倍率降权/抑制符合预期；
- 已有粘性会话不会仅因优先级升高而自动迁移；
- 账号真正不可用或亲和被清除时，跨账号对话连续性正常。

## 自动化与环境验证

- `ruff check app tests`：通过。
- Monitor 后端完整测试：`100 passed`。
- 新增路由使用、连接器、成本路由和维护专项：`40 passed`。
- Monitor 前端测试：`16 passed`。
- Local Sub2API、PostgreSQL、Redis、Monitor API/Worker/Web/PostgreSQL 均为 healthy。
- Monitor 手工采集运行 `afca6429-afc6-4aac-99c1-c051d5085b21`：`succeeded`。
- OpenCode：`1.18.18`；临时项目配置只使用环境变量占位符，测试后已删除。

## 回滚与保留项

已完成：

- Monitor 成本路由策略已禁用，`next_run_at=null`。
- Whiles 三个测试分组倍率已恢复 `1.0/1.0/1.0`。
- Whiles 账号 #12/#16/#17 的账号倍率已恢复 `1.0/1.0/1.0`。
- 本地三个账号的优先级和倍率均恢复 `1/1/1`，状态 active、调度开启。
- 本地测试余额从剩余 `$9.9870512` 回滚为 `$0`。
- 第二轮临时测试余额从 `$20` 回滚为 `$0`，临时密钥剪贴板内容已清空。
- 临时 `opencode.json` 已移除。

按运营者要求保留、待其自行删除：

- Whiles Key：`monitor-opencode-rate-20260816`、
  `monitor-rate-glm-12-key-20260816`、`monitor-rate-glm-16-key-20260816`、
  `monitor-rate-glm-17-key-20260816`。
- 本地 Key：`opencode-monitor-rate-20260816`、
  `opencode-monitor-rate-repeat-20260816-125107`、
  `opencode-monitor-ntfy-20260816-134612`。
- 本地 ntfy 服务、`sub2api-routing-test-20260816` 主题及 Monitor 通知通道。
- 三个 Whiles 专属测试分组、对应账号的附加分组绑定、管理员用户的专属分组授权。
- 本地 `monitor-rate-test-local` 分组和三个测试账号。

删除上述 Key 后，可再删除测试分组，并移除 #12/#16/#17 的测试分组绑定和管理员用户
授权；`admin专用` 原有账号绑定不应删除。
