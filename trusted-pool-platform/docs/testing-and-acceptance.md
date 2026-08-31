# 测试方案与验收标准

## 1. 测试层级

- 单元测试：状态转换、业务不变量、幂等摘要、批次关联数据、敏感字段脱敏。
- 数据库测试：唯一约束、并发更新、只追加审计触发器、活动 Assignment 部分索引和 Epoch 复合外键。
- 契约测试：平台 OpenAPI 与 Sub2API 受限集成接口的请求和错误码。
- 集成测试：真实 PostgreSQL、伪 Sub2API、超时、重复响应和乱序事件。
- 端到端测试：五成员 Pool 从创建到暂停、临时换员、恢复和永久换员。
- 故障注入：数据库提交后响应丢失、Redis 缓存失效失败、在途请求超时、outbox 重投。

## 2. 必须通过的业务验收

1. 暂停确认后旧 Key 的新请求全部被拒绝。
2. 未达到 `FROZEN` 时临时换员、永久换员和恢复均返回冲突。
3. 换员前后 Seat Principal、订阅、额度用量和窗口起点完全不变。
4. 重复提交相同操作不会生成重复 Group、Seat、订阅、Assignment 或 Key。
5. 相同 `operation_id` 携带不同内容时返回幂等冲突。
6. 旧 `assignment_epoch` 的请求即使命中旧缓存也被拒绝。
7. 正常完成、超时和异常中断的在途请求均不会造成重复计费。
8. 可信 Seat 结算错误、panic、超时或 pending 删除失败时保留持久屏障；即使并发为 0，freeze
   仍返回冲突，人工对账清除前不得换员。
9. 临时成员不能获得 Share、Manifest 投票权或 Reveal 权。
10. Phase 1 验证永久换员后旧运行凭据不能访问新 Epoch；旧 Share 隔离属于 Phase 2 recovery governance 验收。
11. 风险等级变化不会自动暂停 Seat。
12. drain-status 和 freeze 均返回四个额度窗口；未启动窗口保持 null，换员后窗口与已用额度连续。
13. 可信 Seat 提交异步图片、批量图片或视频任务时被网关拒绝，普通同步请求不受影响。
14. `provider_attestation_ref` 缺失、四类旧批次未全部 RETIRED、四类新批次未全部 ACTIVE，或 Epoch
    不相邻时均不能签发控制轮换证据；成功证据绑定该引用和新旧八个批次 ID。
15. 永久换员对跨 Pool、非相邻 Epoch、已失效批次或任意非空外部引用均复核失败；
    `access_credential_rotated=true` 不能替代平台签发证据。Phase 1 测试不得把引用存在误表述为平台
    已验证供应商签名或证明真实性。
16. claim token 只保存 SHA-256 摘要、仅在首次成功响应返回，并只能由绑定目标成员在 TTL 内使用一次；
    状态查询、幂等重放、跨成员领取和重复领取均不泄露凭据。
17. 永久换员成功提交最小 Membership Epoch 后，旧 Epoch 的 Seal 和 Activate 均被稳定拒绝且无副作用。
18. 平台读取 drain-status 时，只要 `current_concurrency` 或 `pending_settlements` 任一非零，就保持
    `DRAINING` 且不调用 freeze；收到仍带 pending 的 FROZEN 响应时失败关闭。
19. 受控 settlement 查询能返回 request/billing ID、状态、错误和尝试次数；平台 resolve 必须使用
    与普通 API Key 不同的 `TRUSTED_POOL_SETTLEMENT_API_KEY`，上游仅接受 `settlement:resolve` scope，
    并覆盖计费成功但屏障删除失败、计费失败、进程中断、同一幂等键重放和内容漂移冲突，完整保留
    操作者、理由、证据和时间。
20. Seat provision 只接受已绑定 Pool 的既有 Group，并在 Sub2API 同一事务创建不可交互 Principal、
    Subscription 与 API Key；响应中 credential 不得越过平台一次性领取边界。
21. Sub2API 未明确成功、超时或返回无法验证的 Seat 时，本地 Seat 不存在且绝不标记 ACTIVE。
22. `RETRYABLE` provision 使用相同请求和 operation_id 重放可恢复；成功后的再次重放不调用上游且不返回
    claim token；任一限额、到期时间、Group、Pool、Seat 或 owner 漂移均冲突。
23. provision claim token 只绑定 owner；平台必须先以独立 `credential:ack` scope、相同 claim operation ID
    和 credential fingerprint 取得 Sub2API 明确确认。ambiguous ack 不披露且可幂等重放；ack 跨越 TTL、
    token 过期、错误 fingerprint 和上游已领取均清除或拒绝 credential，平台重启后不能重新发放。
24. 临时换员与恢复只能从完整 FROZEN 证据发起；Begin 本地事务提交前上游调用次数为零，结果未知或
    普通 4xx 均保持 `ASSIGNMENT_PENDING`，只有可验证的成功结果才能激活目标成员。
25. 换员前后 Principal、Subscription、API Key 资源 ID 和 Pool Membership Epoch 保持不变；
    assignment epoch 与本地 active API Key version 同步加一，正式 Owner 不因临时分配改变。
26. 成功换员必须在同一事务结束旧 Assignment、激活目标 Assignment、更新 Seat、完成 Operation 并创建
    加密 READY Claim；成功重放/Operation GET 不返回 claim token，目标成员只能领取一次。
27. ASSIGN_TEMPORARY 的当前 Assignment 必须投影为 TEMPORARY；RESTORE 只能恢复数据库锁定的正式 Owner。
    待激活 Assignment 的 Seat、Pool、类型或稳定资源 ID 任一错配时，数据库延迟聚合约束必须拒绝提交。
28. Credential Batch 任一 wrapper 未就绪或失败时，不得调用 Store Begin 或提交部分 envelope；两侧必须包装
    同一 DEK，但 domain/key/output 独立，相同包装、裸 DEK 或全零包装均拒绝。
29. Batch request snapshot 只含规范元数据和 HMAC 内容指纹；数据库参数、响应、日志与错误不得出现已知
    payload canary、原始 AAD、key ref、密文或 wrapped DEK。
30. Seal 提交重新核对 Pool 当前 ACTIVE Epoch 和 credential floor；并发 Seal/Activate/Retire、旧 fence、
    同 operation 漂移与同范围双 ACTIVE 均由 CAS、唯一索引和延迟聚合约束拒绝。
31. Recovery ceremony 必须覆盖 Pool 全部 Seat 的当前 FROZEN 双屏障，缺 Seat、过期 assignment epoch、
    freeze operation/hash 漂移或未决 settlement 时均不得创建 plan。
32. BOOTSTRAP 只能从 active `LEGACY_UNVERIFIED` Epoch 开始、previous manifest hash 为零且无 Owner replacement；
    ROTATE 只能从 active CURRENT Epoch 和其可信 Root/Manifest/member snapshot 开始。
33. 正式成员 signing key 与 recovery encryption key 必须独立且 PoP 均通过；临时成员、重复 share index、
    key fingerprint 漂移或不属于 to Epoch 的签名/ACK 均被拒绝。
34. Root/VSS/JCS/HSM/attestation/member/batch/MemberArtifact 任一 provider 未就绪时失败关闭；测试 canary 证明
    Root/Share/DEK/credential 明文不进入 Store、响应、日志、错误或 artifact gateway metadata。
35. 每个权威资源账号必须映射至少一个计划 Seat，FROM/TO 各精确四类控制批次；少一类、多一类、跨账号、
    跨 Epoch、非 STAGED TO batch 或 recovery root binding 漂移均不能进入 `READY`。
36. Manifest 绑定前序散列、Pool/Epoch、全员密钥、全 Seat 冻结、Root/VSS、逐成员加密 Share、全部账号和
    batch set；任一字节漂移使平台/成员签名或 Share ACK 验证失败。
37. plan 达到 `READY` 后，只有 Pool finalize 可改变 active Epoch、Owner、credential floor 或批次状态；旧单
    Seat replace 必须稳定返回 503。
38. permanent rotation client scope 必须精确为单元素 `seat:permanent-rotate`；`*`、普通或混合 scope、
    Header/body operation 漂移、跨 Pool、非相邻 Epoch、未排序或缺 Seat 集合均被拒绝。
39. prepare 后 API Key disabled、Subscription suspended、Seat 为 `rotation_prepared`；activate 后安装新
    credential 但仍 disabled/suspended/held，commit 前旧新 credential 均不能通过网关。
40. activate/commit Ed25519 证明必须绑定 request/set hash、每个 Seat、旧 credential 失效、fingerprint gate
    与 durable outbox；activation 事件不少于 `2 * Seat 数`，commit/release 事件不少于 `Seat 数`。任一字段、
    阈值或签名漂移均失败关闭。
41. 平台结构事务在远端 held 时原子切换 Epoch/Owner/batch/floor 并创建无 token 的 `ISSUANCE_PENDING`
    claim；provider commit 失败时保持 `PROVIDER_COMMIT_PENDING`，不能被通用 claim scanner 领取。
42. worker 只能精确重放 provider commit 并推进到 `READY_TO_ISSUE`，不得生成 token；只有首次同步 finalize
    提交返回 raw claim token，幂等重放、GET 和响应丢失恢复不二次披露。
43. replacement claim 只接受 recovery key 管理员代交付、路径 child operation ID 相同的 Idempotency-Key、
    精确 Seat/目标成员/token；CAS 消费并清密后才披露，跨成员、过期和重放均拒绝。
44. Evidence Bundle 必须是单份严格 JCS JSON；未知字段、重复键、非规范编码、超限输入、checkpoint 或
    Manifest 链漂移稳定 `REJECTED`，且验证过程不访问网络、数据库、KMS 或 provider。
45. trust policy 必须独立提供；Bundle 内 key 不得自我授权。历史平台签名缺 v2 domain 时稳定
    `INCOMPLETE/LEGACY_UNSUPPORTED`，缺 typed provider proof 时稳定
    `INCOMPLETE/PROVIDER_EVIDENCE_INCOMPLETE`，两者都不能返回 `VERIFIED`。
46. 阈值从 Manifest 动态读取并满足 `0 < recovery <= governance <= unique formal members`；测试覆盖非五人
    集合，禁止把 Proposed ADR-0002 的 `4-of-5` 建议写死。
47. Bundle、报告、错误和 Store 公共投影均不得含 Share ciphertext、批次 ciphertext/nonce、wrapped DEK、
    Root/Share 私密材料、credential 或 claim token；canary 扫描必须覆盖 CLI stdout/stderr。
48. Reveal intent/approvals 未通过时稳定 `REJECTED`；其余校验通过但 policy 未批准时为
    `POLICY_UNAPPROVED`；policy 批准且达到治理阈值时只为 `AUTHORIZED_NOT_EXECUTABLE`，绝不调用
    decrypt/reconstruct/unwrap/plaintext sink。

## 3. Phase 2 数据库契约验收

- 非 UUID 的合法 `operation_id` 可以写入暂停记录和集成操作表，并保持最长 128 字符限制。
- 同一 Seat 不能存在两个活动 Assignment；同一成员也不能在同一 Pool 占用两个活动 Seat。
- Assignment 携带的 `pool_id` 必须与 Seat 所属 Pool 一致。
- Credential Batch 不能引用不存在或属于其他 Pool 的 Membership Epoch。
- migration 007 的 Legacy Credential Batch 必须标记 `LEGACY_UNRECOVERABLE` 并拒绝 API Get/Activate/Retire；
  不得猜测 wrapper domain/key ref 或把旧行升级为 CURRENT。
- migration 008 必须把历史 governance 标记为 `LEGACY_UNVERIFIED`，不能自动生成 Root、Share、Manifest 或
  签名；只有受控 BOOTSTRAP 可创建第一条 CURRENT 链。
- migration 008 必须在真实 PostgreSQL 16 拒绝不完整账号/Seat 映射、越级 plan 状态、缺失签名/ACK、
  非精确四类批次以及安全 artifact 的更新或删除。
- migration 009 必须拒绝不完整 Pool child set、跨 Pool/Epoch/resource binding、越级 finalization、activation
  低于 `2 * Seat 数` 或 commit/release 低于 `Seat 数` 的 auth-cache proof、`ISSUANCE_PENDING` 提前领取和终态证明修改；锁顺序必须保持
  Pool -> Seat -> batch。
- migration 010 必须保持历史签名 domain/typed proof 为 NULL 或 `LEGACY_EXPORT_LIMITED`，拒绝伪造升级；
  Root/Share/Manifest/control evidence、member artifact receipt、verification export 和 Reveal ledger 的
  不可变/只追加/延迟聚合触发器必须在真实 PostgreSQL 16 生效。
- migration 011 必须在不改写历史审计 snapshot 的前提下，让升级前已有的精确 009 七字段 Seat snapshot 与
  当前 typed Manager intent 按完整领域 hash 兼容接管；七字段为 `protocol_version`、`plan_id`、`pool_id`、
  `seat_id`、`target_member_id`、`from_epoch`、`to_epoch`。011 后新 operation 只能写 typed snapshot；typed
  Seat/Pool prepare/activation 必须绑定精确字段集合和完整内嵌 Seat 数组，混合格式、大小写别名、未知字段、
  hash、业务字段或同长度内嵌 Seat 漂移均必须原子拒绝。
- verification export `REVEAL_CAPABLE` 必须要求已完全 release 的 FINALIZED plan、v2 platform signature、
  typed provider proof 和精确 member artifact receipts；任何缺失只能是带理由的 limited export。
- Sub2API migrations 226/227 必须禁用历史混合 permanent scope client，拒绝非 singleton
  `seat:permanent-rotate`、非法 rotation 状态、非完整 parent/child set 和 held 状态的直接释放；227 必须
  对非空 legacy 明文失败关闭、删除明文列，并把 PREPARED 限定为七列 envelope。
- Manifest Signature 的成员必须属于该 Manifest 对应的 Membership Epoch。
- Phase 2 增加领取持久化前，必须验证数据库只存 token 哈希和加密待交付值，ack 与消费同事务提交。

## 4. 安全验收

- 生产数据库、应用日志、错误响应和 trace 中不存在凭据明文、API Key、未包装 DEK、Recovery Share、
  用户 JWT 或原始设备指纹。Sub2API migration `226` 的历史 `prepared_credential` 已由 migration `227`
  取代；当前候选必须证明遗留非空值升级失败关闭、七列 envelope、披露 TTL、篡改拒绝和 activate 原子清理。
  生产 KMS/HSM、存量扫描和真实故障演练完成前，不得把永久轮换标记为生产可用。
- 新平台无法使用集成凭据访问 Sub2API 非 trusted-pools 管理接口。
- URL query 中携带 token 时直接拒绝；fragment 使用后立即清除。
- 审计事件无法 UPDATE 或 DELETE，修正只能追加补偿事件。
- 密文关联数据被修改后解密必须失败。

## 5. 故障恢复验收

- Sub2API 调用提交成功但响应丢失时，相同 `operation_id` 可恢复原结果。
- Sub2API 永久轮换 `commit` 已提交但响应丢失、随后 Seat 被 suspend/freeze 时，原 commit 的精确重放必须从
  `retiring` 父记录返回同一历史回执，不得要求资源重新变为 active，也不得重复启用资源；请求绑定漂移、
  当前 API Key fingerprint 漂移或记录已 `superseded` 时必须返回稳定冲突并进入人工安全复核。
- 平台重启后能读取持久 Provision/Claim，并通过数据库 lease/fencing 接管 ack 对账；后台不得新发 claim token。
- 平台重启后能从持久 SUSPEND 请求快照重建 Seat、operation 和 assignment epoch，不依赖客户端内存 map。
- 平台重启后能从持久 ASSIGN_TEMPORARY/RESTORE 请求快照和 AssignmentCase 重建目标成员、冻结证据、
  稳定资源 ID 与目标 epoch；不得依赖客户端内存 map，也不得生成新的 operation ID。
- 平台重启后能从 9 键 settlement intent 重建原 actor、Seat、settlement、epoch、request ID、reason 和 evidence；
  通用 worker 不得扫描 resolve operation，专用 worker 不得生成新的 operation ID。
- resolve 的普通 key、`*` scope、混合 scope、encoded-path 绕过、Header/body 幂等键漂移、epoch/request/actor
  响应漂移均被拒绝；结果未知时 Seat 保持禁用，未决 intent 同时阻止 ASSIGNMENT_PENDING 和直接 ACTIVE。
- suspend、drain-status、freeze 返回的 Pool、Seat 或 assignment epoch 任一缺失/错配时必须失败关闭。
- 同一 Seat 的 Provision 完成与 Suspend 使用公共 Pool 行锁串行，真实 PostgreSQL 双连接交错测试不得形成
  Pool/Seat 反向死锁；暂停期间单独修改 Seat assignment epoch 必须被延迟聚合约束拒绝。
- BeginSuspend 本地事务失败时上游调用次数为零；DRAINING 保存真实并发/结算计数，结果未知不回退 ACTIVE。
- Operation、Seat、SuspensionCase 和 freeze snapshot 必须在同一事务进入 FROZEN，旧 fence 提交被拒绝。
- `CALLER_REPLAY_REQUIRED` 不被恢复 worker 反复扫描，原调用方可用同请求和 operation ID 重放。
- 过期 Claim 先持久清密，且不再调用 Sub2API ack 或 KMS 解密。
- 结果未知时 `SUSPEND_PENDING` 不会自动进入 `FROZEN` 或开始换员。
- 对账能发现期望状态与实际状态不一致，并进入人工处理队列。
- 完成一次不依赖在线平台的 Manifest 验证；H1 只验公开 Evidence Bundle，Recovery Package 解密/重建
  演练仍是后续 executor 阶段门禁，不得用 `AUTHORIZED_NOT_EXECUTABLE` 代替。
- prepare、activate-held、平台结构提交、Sub2API commit、release 证明提交和 token 签发各边界的响应丢失
  续跑已通过，活跃 finalization lease 的真实子进程退出接管也已通过。provider commit 边界进一步通过真实
  PostgreSQL + Manager 子进程 + 测试专用 file-backed durable provider 门禁：provider 落盘后进程退出，第二进程以新 owner/fence
  精确回放且 durable 副作用仍为一次，worker 不生成 token。其余边界仍须联动真实 Sub2API/provider 强制退出
  复验，确保重启只推进允许的状态且永不重建 raw token；该进程场景的 verifier 为 test double，密码学签名
  由独立 security 单测覆盖，不能解读为生产签名集成验收。
- 公开 Store 工作流必须从 `READY` 工单开始，先在同一事务进入 `ROTATING` 再创建 Seat progress；真实
  PostgreSQL 必须覆盖在 010 下创建 legacy Seat operation、穿过 011 DDL 后由 typed Manager 换 owner/fence
  接管，以及 typed Seat prepare -> Pool prepare -> Seat PREPARED -> Pool activation。011 后 legacy 新建和
  保持外层 hash/集合 hash 不变的内嵌 Seat 漂移都必须拒绝，且不得改变 operation、attempt、progress 或 case 聚合。
- 使用真实网关验证旧 credential、held 新 credential、commit 后新 credential 和历史正缓存；每次准入必须
  以数据库当前 credential fingerprint 为准。

## 6. 发布门禁

以下任一条件不满足均不得上线封闭试点：

- 单元、数据库和集成测试全部通过。
- 暂停与换员端到端场景通过。
- 敏感数据扫描无高危发现。
- OpenAPI 与实现契约测试通过。
- 数据库迁移在空库和已有测试数据上均验证成功，包括平台 `001 -> 011`、`009 -> 010`、`010 -> 011` 和 Sub2API
  受支持基线到 `226` 的历史审计与混合 scope 处理；`227` 的当前候选结果必须由受控 commit 上的 CI 另行归档。
- migration ledger、checksum 漂移和 unmanaged 历史卷的受控 baseline 演练通过。
- 真实 PostgreSQL 门禁必须显式提供 `PHASE2H_TEST_POSTGRES_DSN`；最小权限门禁另需
  `PHASE2H_TEST_POSTGRES_ADMIN_DSN`，Sub2API 226/227 门禁需在其模块提供 `SUB2API_TEST_POSTGRES_DSN`。
  常规本地 `go test ./...` 会在变量缺失时跳过这些测试；仓库 CI 的 `postgresql-gates` job 已显式提供
  三组 DSN，并把除两个子进程 helper 外的意外 `SKIP` 视为失败，同时归档数据库版本、命令、日期和 JSON
  测试工件。该 job 首次在受控 commit 上成功运行并保存工件后，才能计作本轮发布证据。
- 尚未满足的生产门禁：生产在线 KMS、Recovery Root/VSS/JCS/HSM/attestation/member/batch/MemberArtifact
  providers 接线与故障演练；Batch/Recovery 等跨工作流多副本实测；逐外部副作用边界的真实进程退出端到端。
- 已通过的数据库子门禁：通用 Operation、Credential Claim、Credential Batch、Recovery plan/finalization
  双连接竞争，Suspend/Provision 同 Pool 竞争、Credential Batch retire/finalization 同 Pool 双向裁决，以及
  finalization lease 与 provider commit 子进程退出接管。Batch/finalization 失败侧无部分聚合，且未出现
  `40P01` 或超时；Manager typed Seat prepare snapshot 与 Store 领域绑定已覆盖 semantic drift、旧格式兼容和
  公开 Seat -> Pool preparation -> activation 链路。
  这些结果不能替代上一项生产端到端门禁。
- 运维人员完成暂停结果未知和永久换员演练。

Phase 2-H H1 已形成公开 Evidence Bundle 离线验证、持久导出 Store/条件路由代码与 Reveal 授权记录基础；
当前发布组合根未注入 export signer，导出不可激活。此前本地测试记录的真实
PostgreSQL 16 `001 -> 011`、`009 -> 010`、停机迁移账本 `010 -> 011`，Sub2API 基线到 `226` 的混合 scope 与永久轮换父子证据升级、
迁移/运行最小权限身份，以及通用 Operation/Credential Claim/Credential Batch/Recovery plan/finalization
双连接接管、旧 fence 拒绝、finalization 响应丢失续跑、两 Seat 部分 prepare 接管、Suspend/Provision 同 Pool
竞争、Credential Batch retire/finalization 同 Pool 双连接竞争、provider commit 真进程退出精确回放和两 Seat
activation 响应丢失单元门禁已经通过。生产导出 signer/Reveal、更广的 Batch/Recovery 跨进程多副本、其余
外部副作用边界的真实进程退出、真实 providers 和完整端到端尚未通过，
因此本节发布门禁仍未满足。
