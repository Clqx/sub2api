# 永久凭据轮换 Fail-Forward 故障续跑手册

## 1. 适用范围与决策

本手册覆盖 Pool 级永久换员在 Sub2API prepare、activate、commit 三阶段及平台
finalization 之间发生超时、进程退出、响应丢失或人工接管的处置。

当前版本只允许 fail-forward：使用原始 operation、幂等键、请求散列和 Seat 集合继续推进到终态。
当前协议没有 abort 或 open rotation 自动到期/清理。`prepared_credential_expires_at` 只是精确 `prepare`
重放的再次披露截止时间，不是 rotation expiry，也不阻止经过认证且绑定一致的 `activate` 使用密文 envelope
完成推进并清除材料。不得直接删除 open rotation、回滚 Epoch/Owner、启用 held credential，或重置一次性 claim。

不提供 abort 的原因是：activate 请求结果未知时，新 credential 可能已经安装到稳定 API Key。
仅凭平台超时无法证明远端未执行，回滚或删除记录可能同时破坏新旧凭据的安全边界。

## 2. 续跑前必须保留的证据

每次操作必须把下列非秘密信息写入受控工单或审计系统：

- prepare、activate、commit 的 operation ID、Idempotency-Key、规范请求体散列和阶段状态。
- Pool ID、plan ID、from/to epoch、规范排序的完整 Seat 集合和 child operation ID。
- prepared set hash、每个 Seat 的 credential fingerprint、稳定资源 ID、provider reference。
- 签名 key ID、平台配置的 public-key fingerprint、issuer、协议版本和验证结果。
- 平台 finalization operation/case ID、owner、lease/fence、审计事件 ID 和 outbox 证据。
- 首次异常时间、最后一次确定成功时间、每次重放的时间、操作者和结果。

禁止记录或复制 prepared credential、claim token、API key、私钥、KMS 明文或完整响应体。
credential 只能在首次响应或披露 TTL 内的原 prepare 精确幂等重放中由平台立即包络，不能转存到工单。

## 3. 只读诊断

先按事故工单中的 client 和原 prepare operation 精确查询父记录。这里不能只筛 open 状态，因为 commit
已成功但响应丢失后，后续 suspend 会把记录从 `committed` 推进为 `retiring`：

    SELECT client_id, prepare_operation_id, external_pool_id, plan_id,
           from_epoch, to_epoch, status, seat_count,
           prepared_at, activated_at, committed_at,
           NOW() - prepared_at AS open_age
      FROM trusted_pool_permanent_rotations
     WHERE client_id = $1
       AND prepare_operation_id = $2;

再盘点所有需要推进或核对历史 commit 回执的记录，不读取 child 表中的七列 envelope 材料：

    SELECT client_id, prepare_operation_id, external_pool_id, plan_id,
           from_epoch, to_epoch, status, seat_count,
           prepared_at, activated_at, committed_at
      FROM trusted_pool_permanent_rotations
     WHERE status IN ('prepared', 'activated_pending_commit', 'committed', 'retiring')
     ORDER BY prepared_at;

将查询结果与平台 finalization case、operation ledger、签名证明和 outbox 对齐。不得为了“修复”
而执行 UPDATE、DELETE、TRUNCATE、触发器绕过或临时放权。

## 4. 状态处置矩阵

| 已知状态 | 唯一允许动作 | 完成判据 |
| --- | --- | --- |
| prepare 结果未知 | 以完全相同请求体、operation ID 和幂等键重放 prepare | 签名、request hash、set hash、Seat 集合全部通过 |
| prepared，平台 KMS 包络未确认且披露 TTL 未过期 | 精确重放原 prepare；立即包络并核对 fingerprint，再继续原 activate | 所有 Seat 包络持久且 fingerprint 与签名证明一致 |
| prepared，平台 KMS 包络未确认且披露 TTL 已过期 | 停止自动推进并升级安全事故；不得为了利用 Sub2API 的 activate 能力而跳过平台包络门禁 | 原因和证据完成复核，并按经评审的恢复方案处置；不得直接改库或伪造 claim |
| 平台 case 为 `ROTATING` | recovery worker 可用原 operation/hash/fence 接管，并精确重放未确认的 prepare/activate | activation 证明持久后只推进到 `READY_TO_COMMIT` |
| prepare/activate 子 operation 为 `RECONCILE_REQUIRED` | 保留父 case；只用原子 operation 和原请求重放该外部阶段 | 子 operation 到 `SUCCEEDED`，绑定和签名证明完全一致 |
| 平台 case 为 `READY_TO_COMMIT` | worker 只复核持久 activation 并停止；必须由携带原 finalize 意图的同步调用提交平台结构事务 | Plan、Epoch、Owner、batch、claim barrier 原子提交，case 到 `PROVIDER_COMMIT_PENDING` |
| 平台 case 为 `PROVIDER_COMMIT_PENDING`，或 commit 子 operation 为 `RECONCILE_REQUIRED` | worker 精确重放原 Sub2API commit，不生成 claim token | provider commit 证明持久且 case 到 `READY_TO_ISSUE` |
| Sub2API 父记录为 `committed` 或 `retiring`，平台仍未持久 commit 证明 | 精确重放原 commit；`retiring` 只返回历史回执，不重新启用资源 | 同一 committed 时间、集合和签名回执通过；当前业务暂停状态保持不变 |
| Sub2API 父记录已 `superseded` 或当前 API Key fingerprint 漂移 | 停止自动推进，保留 `RECONCILE_REQUIRED` 并进入人工安全复核 | 查明后续轮换或密钥漂移来源；不得伪造历史证明或重新启用资源 |
| READY_TO_ISSUE | 原调用方以原 finalize 意图同步重放 | 首次成功事务生成 token，operation 到 SUCCEEDED |
| FINALIZED 后 HTTP 响应丢失 | 原 token 永久不可恢复；发起新的受控凭据轮换 | 新轮换完成；旧 claim 不重置、不重发 |

任何重放出现 request hash、Seat set、epoch、资源 ID、签名 key ID、fingerprint 或 fence 不一致，
立即失败关闭并转安全事件，不得“采用最新值”继续。

## 5. 签名键故障

续跑必须恢复与既有证明 key ID 和 public-key fingerprint 精确匹配的同一 Ed25519 私钥。
不得在 open rotation 中途静默换键，也不得关闭签名校验。当前没有双 key overlap 或 KMS 托管换键协议；
若原私钥不可恢复，保持所有资源禁用并升级为安全事故，不能声称 rotation 已完成。

## 6. 失败关闭条件

出现以下任一情况必须停止推进：

- 无法恢复原始规范请求体、operation ID、幂等键或请求散列。
- Pool、Seat 集合、相邻 Epoch、稳定资源 ID 或 child operation 集合发生漂移。
- 签名无效、key ID 不匹配、credential fingerprint 或 prepared set hash 不一致。
- 严格并发或 pending settlement 非零。
- 平台 lease/fence 归属不明，或旧 fence 尝试写入。
- activation/commit 的持久网关 fingerprint gate 或 outbox 证据不足。
- KMS 包络、provider attestation、member/batch proof 或 finalization barrier 不完整。
- prepare 披露 TTL 已过期且平台未能证明 credential 包络已持久化。

失败关闭时保持现有 held/disabled 状态，记录证据并告警。禁止通过普通 suspend/freeze、手工启用、
直接改库或创建新 operation 绕过。

## 7. 发布前演练

使用真实 PostgreSQL、Sub2API 和可持久化 provider，在单实例环境逐项注入进程退出：

1. prepare 请求前、远端提交后响应前、平台 KMS 包络前后，以及披露 TTL 过期前后。
2. activate 请求前、远端安装 credential 后响应前。
3. 平台结构事务提交前后。
4. provider commit 请求前、远端 release 后响应前、证明持久前后。
5. READY_TO_ISSUE 到 token 事务提交前后，以及 HTTP 响应丢失。
6. 错误 signer key、签名损坏、hash/set/fingerprint 漂移、非零 settlement 和旧 fence。

每个场景都必须证明：同一幂等请求允许重复发送，但持久业务效果只发生一次；重启后只从持久状态继续、
worker 不签发 token、
旧 credential 不再通过逐请求 fingerprint gate、失败事务不留下部分 Epoch/Owner/batch/claim 聚合。

在上述真实演练归档前保持单实例，禁止 rolling overlap 或蓝绿双写。对 prepared 和
activated_pending_commit 的数量及最旧年龄告警；告警只触发人工接管，不自动 abort。

## 8. 后续协议演进

若未来确需 abort 或 open rotation 自动 expiry，必须新增显式、签名且幂等的协议，至少绑定 Pool、原 operation、set hash、
from/to epoch 和每个 Seat fingerprint，并能证明 credential 尚未安装或已被安全撤销。该能力需要独立
威胁建模、数据库状态机、审计事件、真实进程故障演练和兼容性迁移，不能由后台定时删除代替。
