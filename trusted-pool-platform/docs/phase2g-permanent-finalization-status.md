# Phase 2-G Pool 级永久换员最终化状态

## 1. 阶段结论

Phase 2-G 在 Phase 2-F 的 `READY` 治理计划上接通了 Pool 级永久换员最终化开发闭环：平台 migration
`009`、Sub2API migrations `226/227`、三阶段 Pool rotation、平台结构切换、provider release、一次性 claim
签发和管理员代交付均已有实现与单元测试。旧单 Seat
`POST /api/v1/seats/{id}/actions/replace` 继续稳定返回 503，永久换员只有 Pool 级 finalize 一条写路径。

这不是生产可用声明。当前组合根仍未链接生产 Root/JCS/HSM/VSS、provider attestation、成员签名、
治理 batch 和 MemberArtifact provider；`TRUSTED_POOL_RECOVERY_GOVERNANCE_ENABLED` 默认 `false`，误开时
必须在监听端口前失败启动。以下真实 PostgreSQL 结果来自前序本地受控会话，不是当前候选 commit 的 CI
发布工件：迁移升级，以及通用 Operation、Credential Claim、Batch、
Recovery plan/finalization 的双连接 lease/fence 门禁均已通过；两 Seat 部分 prepare 的不同 owner 接管、
Suspend/Provision 同 Pool 双连接竞争、Credential Batch retire/finalization 同 Pool 双连接竞争和 finalization
lease 子进程退出也已通过。Migration 011 的升级前 legacy/当前 typed Seat 接管和 typed Seat -> Pool prepare -> activation
公开 Store 链路已在真实 PostgreSQL 验证。逐外部副作用边界的真实进程 kill 联动 Sub2API/provider，以及跨进程多副本演练
仍是发布门禁。

## 2. 三阶段 Sub2API 协议

平台只使用独立的 Sub2API rotation client。该 client 的 scope 必须精确等于单元素集合
`seat:permanent-rotate`；运行时认证、数据库约束和 CLI 拒绝通配符、普通 `seat:*` 或任何混合 scope。
三个请求都要求 `Idempotency-Key == body.operation_id`，并绑定规范排序的 Pool 全 Seat 集合、相邻 Epoch、
稳定资源 ID、子操作 ID 和请求散列。

> 2026-08-31 发布审查：Sub2API provisioning CLI 已包含 `seat:permanent-rotate` 并强制 singleton
> 合同。标准 Compose 的签名键注入及显式启动/readiness 门禁仍按本阶段实现和验证结果判定。

1. `prepare` 为每个 Seat 生成新 API Key credential，但保持 API Key disabled、Subscription suspended、
   Seat 为 `rotation_prepared`。credential 只在首次响应或披露 TTL 内的精确幂等重放中返回给平台，平台
   收到后立即 KMS 包络并清除明文；TTL 过期后精确 `prepare` 重放不再披露 credential。
2. `activate` 把新 credential 安装到原稳定 API Key，并把 Seat 推进到
   `rotation_activated_pending_commit`。此时 API Key 和 Subscription 仍禁用；严格并发和 pending
   settlement 必须为零，普通 suspend/freeze 不能穿透 held 状态。
3. 平台完成本地结构切换后才调用 `commit`。Sub2API 再次核对完整 held 集合、credential fingerprint、
   并发和 settlement 屏障，随后原子启用 API Key/Subscription 并把 Seat 恢复为 `active`。

Sub2API migration `226` 的历史明文暂存已经被 migration `227` 取代。当前 `PREPARED` 行只保存独立
envelope 的 version、key ID、wrap nonce、wrapped DEK、data nonce、ciphertext 和 expires_at；AAD 绑定
client、完整 parent/child set、Pool、协议、计划、Seat、资源、Epoch、fingerprint 和 key ID。披露 TTL
不是 rotation expiry：它过期后 `prepare` 不再返回 credential，但经过认证且绑定一致的 `activate` 仍可
解密并安装 credential，然后原子清除七列材料，避免仅因 TTL 造成永久卡死。平台只有在自己的 credential
包络已经持久确认后才允许进入 activate。

当前协议仍没有 abort 或 open rotation 自动到期/清理；编排永久失联、签名键丢失或人工放弃仍可能使
加密材料和轮换阻断长期保留。上线前必须演练受审计的 fail-forward 人工恢复，或另行设计绑定
Pool/operation/set hash 与签名的 abort/expiry 协议。当前本地独立 KEK 不替代生产 KMS/HSM provider。
当前阶段已选择 fail-forward only，状态处置、证据留存和演练标准见
[永久凭据轮换 Fail-Forward 故障续跑手册](permanent-rotation-fail-forward-runbook.md)；真实环境演练通过前
仍不构成生产门禁完成。

prepare、activate、commit 响应都使用专用 Ed25519 私钥签名。平台只配置对应 public key，并验证 key ID、
issuer、协议版本、request hash、集合 hash 和全部状态字段。activate/commit 的证明还必须表明旧 credential
集合已失效、网关每次准入执行数据库 credential fingerprint gate、持久 auth-cache outbox 已写入且事件数
达到阶段阈值：activation 不少于 `2 * Seat 数`，commit/release 不少于 `Seat 数`。
`authorization_cache_invalidated=false` 本身不构成放行失败；同步缓存失效只是收敛
优化，逐请求 fingerprint gate 才是安全边界。

## 3. 平台最终化状态

```text
Plan: READY -----------------------> FINALIZED（平台结构事务）
Case: READY -> ROTATING -> READY_TO_COMMIT
                         -> PROVIDER_COMMIT_PENDING
                         -> READY_TO_ISSUE -> FINALIZED
```

- Plan `FINALIZED` 与 finalization case `FINALIZED` 含义不同：Plan 在平台结构事务中先置为 `FINALIZED`，
  但 case 和总 operation 仍构成 workflow barrier，不能视为远端 release 或 token 签发完成。
- case `ROTATING` 允许 recovery worker 接管并精确重放 prepare/activate；外部结果未知时，对应子 operation
  进入 `RECONCILE_REQUIRED`，父 case 不因此改名。activation 证明持久后 case 到 `READY_TO_COMMIT`。
- case `READY_TO_COMMIT` 是平台结构提交边界。worker 只复核持久 activation 并停止；只有携带原 finalize
  意图的同步调用才能提交结构事务并进入 `PROVIDER_COMMIT_PENDING`。
- case `PROVIDER_COMMIT_PENDING` 表示 Membership Epoch、Owner Assignment、批次和 credential floor 已在平台
  Serializable 事务中完成结构切换，但 Sub2API 仍处于禁用 held 状态。此时 claim 是
  `ISSUANCE_PENDING`，有 KMS 包络但没有 token hash，不能被领取扫描器取得。
- 恢复 worker 只允许以原 operation/hash/fence 精确重放未完成的 provider commit，并在证明持久后推进到
  `READY_TO_ISSUE`。worker 不生成、记录或返回 raw claim token。
- 只有调用方对同一 finalize 意图的同步请求可在 `READY_TO_ISSUE` 生成 CSPRNG token，并在一个数据库事务
  中把全部 claim 置为 `READY`、保存 token SHA-256/短 TTL、清除 finalization progress 中的包络，并把
  operation 置为 `SUCCEEDED`。Plan 已在前述平台结构事务中置为 `FINALIZED`，此处不再次改变它。
- 仅赢得上述首次成功提交的 HTTP 响应含 `claims[].claim_token`。响应丢失后的重放、计划 GET、operation
  GET 和 worker 都不会重新披露 token，符合 at-most-once 交付。

所有 Seat 都必须参与 rotation，包括 Owner 未变化的 Seat 和 BOOTSTRAP Seat；`replacements` 只声明 Owner
变化，不缩小凭据轮换集合。结构事务按 Pool、Seat、batch 的规范顺序加锁；任何集合漂移、Epoch 漂移、
资源 ID 漂移、非零屏障或证明不匹配都失败关闭。

`BOOTSTRAP` 的源 Epoch 是 `LEGACY_UNVERIFIED`，不存在可退休的 CURRENT 源 Manifest；结构事务只激活目标
Manifest，但仍退休源 Epoch。`ROTATE` 则必须原子退休唯一 ACTIVE/CURRENT 源 Manifest，再激活目标 Manifest；
缺失或多条源 Manifest 都失败关闭。冻结证据只在绑定它的 Recovery plan 已于同一事务进入 `FINALIZED` 后
视为已消费，`READY` 计划不能提前移动 Seat。

## 4. 管理员代交付边界

永久换员 credential 使用：

```text
POST /api/v1/recovery-plans/{plan_id}/credential-claims/{child_operation_id}
```

该路由只接受独立 `TRUSTED_POOL_RECOVERY_API_KEY`，不是成员身份认证。调用者是受审计的恢复管理员或
交付服务，必须在请求体提交 `seat_id`、`target_member_id` 和 `claim_token`；
`Idempotency-Key` 必须等于路径中的 child operation ID。平台核对 plan、Seat、目标成员、token hash、TTL
和 fence，KMS Open 后先以 fenced CAS 消费并清除 claim，只有 CAS 成功的当前请求才返回 credential。
因此 HTTP 响应丢失后不会二次披露；管理员必须通过新的受控轮换恢复，不能直接改库或重置 claim。

`TRUSTED_POOL_RECOVERY_REPLACEMENT_CLAIM_TTL` 默认 10 分钟，最大 30 分钟，与普通 Provision
`TRUSTED_POOL_CLAIM_TTL` 分离。数据库使用自身时间执行 TTL 门禁，避免应用时钟绕过。

## 5. 故障恢复语义

- prepare 前失败：没有远端新凭据，原 finalize 意图可安全重放。
- prepare 后、结构切换前失败：新凭据保持禁用；平台用原 operation/hash 重放 prepare/activate。
- 结构切换后、provider commit 前失败：Pool 保持本地 workflow barrier；worker 精确重放 commit。
- provider commit 后、token 签发前失败：状态停在 `READY_TO_ISSUE`，调用方重放 finalize 完成首次签发。
- Sub2API commit 成功、响应丢失、随后 Seat 被 suspend/freeze：父 rotation 可能已到 `retiring`；原 commit
  的精确重放从持久字段返回同一历史签名回执，不重新启用资源。若记录已 `superseded` 或当前 API Key
  fingerprint 漂移，则返回稳定冲突并保留平台人工复核屏障。
- `FINALIZED` 提交后响应丢失：不重建 raw token，不从 KMS 包络反推 token。
- Sub2API commit 后发生新的 suspend 是后续 fail-closed 业务事件，不回滚已经完成的永久换员。

finalization 已通过七个持久提交/响应丢失边界的故障注入：重启只从已提交状态继续，不重复已确认的 provider
副作用，不由 worker 生成 claim token，也不在终态重放中再次披露 token。`READY_TO_COMMIT` 重启恢复已修复：
恢复路径验证持久 activation 绑定后停在结构提交边界，只有携带原始 finalize 意图的同步流程才可继续结构提交和
后续 token 签发。两 Seat activation 响应丢失和不同 owner 接管已通过确定性单元门禁。provider commit 边界还
通过了真实 PostgreSQL、Manager 子进程和测试专用 file-backed durable provider 门禁：provider 结果落盘后进程退出，第二进程以新
parent/child fence 精确重放，durable 副作用保持一次，数据库证明与回执逐字段一致且 worker 不签发 token。
该场景的 verifier 是 test double，密码学签名由独立 security 单测覆盖；这仍不替代生产 Sub2API/provider
或其余边界的进程 kill 端到端演练。

不得用手工启用 API Key、直接修改 Epoch/Owner、直接更新 claim 状态或跳过 attestation 的方式“修复”中间态。

## 6. 配置和发布门禁

平台新增：

- `SUB2API_RECOVERY_ROTATION_CLIENT_ID`
- `SUB2API_RECOVERY_ROTATION_SECRET`
- `SUB2API_RECOVERY_ROTATION_ATTESTATION_KEY_ID`
- `SUB2API_RECOVERY_ROTATION_ATTESTATION_PUBLIC_KEY_BASE64`
- `TRUSTED_POOL_RECOVERY_REPLACEMENT_CLAIM_TTL`

Sub2API 新增：

- `TRUSTED_POOL_PERMANENT_ROTATION_ENABLED`
- `TRUSTED_POOL_PERMANENT_ROTATION_REQUIRED`
- `TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID`
- `TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64`
- `TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_FILE`
- `TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED`
- `TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_REQUIRED`
- `TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID`
- `TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64`
- `TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_FILE`
- `TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_PREPARED_CREDENTIAL_TTL`

永久轮换默认关闭。启用后所有模式都必须同时启用独立 staging encryption；release 模式还要求 staging
encryption `required=true`。签名私钥和 32-byte staging key 都要求环境变量与只读 base64 文本文件二选一，
两者 key ID 和材料不得复用。五套 Sub2API Compose 已传递上述配置，生产仍需部署系统负责 secret mount，
当前没有生产 KMS/HSM signer 或 staging-encryption adapter。

以下为此前本地会话记录的历史测试证据，不是本次审查复跑或 CI 发布工件：平台 PostgreSQL 16 空库到
`011`、带旧数据 `009 -> 010`、停机迁移账本 `010 -> 011`、Sub2API 受支持基线到 `226` 记录为通过；
当前 migration `227` 仍待本轮 CI 首跑工件。通用
Operation、Credential Claim、Batch、Recovery plan/finalization 也记录为在两个独立真实 PostgreSQL 连接上验证
到期 lease 单赢家、新 fence 和旧 fence CAS 拒绝；旧 fence 不能推进 plan 或提交 finalization 结构聚合。
finalization 七个持久响应丢失边界、`READY_TO_COMMIT` 恢复、两 Seat 部分 prepare 接管和活跃 lease 子进程
退出接管已有故障注入覆盖；同 Pool Suspend/Provision，以及 Credential Batch retire/finalization 双连接竞争
也已通过。后者覆盖两种合法裁决：finalization 先提交时 Batch 失败；Batch 先退休源批次时 finalization
失败关闭。两侧均无死锁/超时，失败事务不留下部分 Epoch、batch、claim 或 fence 聚合。provider commit
durable 写入后的真实进程退出/新 owner 精确回放已通过，使用的是测试专用 file-backed provider；两 Seat
activation 响应丢失接管已通过单元门禁。
011 还验证了升级前已有的 009 七字段 Seat snapshot 穿过 DDL 后，在不改写审计记录的情况下由当前 typed
Manager 接管；011 后 legacy 新建会被 Store 与触发器拒绝。mixed shape、别名、未知字段、hash/业务字段及
Pool 内嵌 Seat 漂移均失败关闭；当前 typed snapshot 已走通公开 Seat、Pool prepare 和 activation 入口。

本轮已完成 provisioning CLI singleton scope、五套 Compose 签名配置传递、显式 enable/required 启动门禁、
三组 DSN 的 CI 强制 job，以及 open rotation 的 fail-forward-only 运维手册。新增 job 会拒绝意外 SKIP，
并逐项要求 migrations 226/227 秘密存储门禁与六个 Phase 2-H 哨兵测试出现顶层 pass 事件，同时归档 PostgreSQL 版本、命令和
JSON 报告；但本机没有运行中的 PostgreSQL，本轮尚未产生远端 CI 首跑工件。
发布前仍必须在受控 commit 上通过该 job，并完成逐外部副作用边界的真实进程 kill + PostgreSQL +
Sub2API/provider 端到端恢复、多 Seat
部分 activate 的真实 PostgreSQL/provider 进程演练、Batch/Recovery 等更广的跨进程多副本并发与死锁演练、
旧新 credential 网关实测、剩余 direct
DML trigger 验证，以及真实
KMS/HSM/VSS/JCS、Ed25519/offline recovery 和全 provider 故障演练。在这些门禁完成前，保持单实例、
禁止 rolling overlap，并保持 governance 默认关闭。

## 7. 明确不在本阶段

最终用户登录与 RBAC、成员自行领取身份协议、公开交易市场、支付分账、自动仲裁、自动风控封禁、
跨地域双活均不在 Phase 2-G。Recovery API key 只能代表管理员服务身份，不能被描述为目标成员身份。
