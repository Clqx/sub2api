# Phase 2-F Recovery 治理准备闭环状态（历史边界）

## 1. 阶段结论

本文记录 Phase 2-F 结束时的历史边界。Phase 2-F 建立了 **Recovery 治理准备闭环 foundation**，当时不是
永久换员交付完成。领域编排、生产 provider
接口、HTTP 准备端点和 PostgreSQL migration `008` 已覆盖 Pool 级 ceremony 从计划到 `READY` 的安全边界；
Pool 级 Seat rotation/finalize saga 当时尚未接线。因此：

- `TRUSTED_POOL_RECOVERY_GOVERNANCE_ENABLED` 默认必须为 `false`。
- 当前二进制未链接生产 Root/JCS/HSM/VSS、provider attestation、member signature、治理专用 batch 和
  `MemberArtifact` 分发 provider；设为 `true` 会在监听端口前失败启动。
- 默认关闭时，所有 `/api/v1/recovery-plans` 端点返回 503。
- Phase 2-F 版本的 `POST /api/v1/recovery-plans/{id}/finalize` 固定返回 503；Phase 2-G 已替换该历史行为。
- 旧 `POST /api/v1/seats/{id}/actions/replace` 继续固定返回 503，禁止回退到单 Seat 永久换员。

## 2. 已实现的准备闭环

1. ceremony 以整个 Pool 为聚合；全部 Seat 都必须有当前 `FROZEN` 状态、暂停 operation 和冻结快照散列，
   未更换 Owner 的 Seat 也不能跳过。
2. `BOOTSTRAP` 将迁移后的 `LEGACY_UNVERIFIED` 活跃 Epoch 引入可信链；`ROTATE` 只能从已有 CURRENT
   Root、Manifest 和成员快照的活跃 Epoch 开始。两者都生成相邻新 Epoch。
3. 权威资源账号注册表和账号到 Seat 的显式多对多映射决定完整性，不从已有 credential batch 反推账号集合。
4. 正式成员快照包含独立的签名公钥与 Recovery 加密公钥、算法、key ID、fingerprint 和 PoP；临时成员不入快照。
5. 外部 Root provider 负责非对称 Epoch Recovery key、阈值分片、VSS 证明和逐成员公钥加密。在线平台只接收
   public handle/fingerprint、private-key commitment、证明及加密 Share，接口不接受 Root/Share 明文。
6. 外部 RFC 8785/JCS canonicalizer 生成 Manifest 规范字节，外部 HSM signer 生成并回验平台签名；成员签名
   gateway 回验 Manifest 签名，Share ACK 绑定 Manifest、Root、VSS、接收者 key 和密文散列。
7. 每个权威账号必须精确绑定 `LOGIN`、`MFA`、`RECOVERY`、`OWNERSHIP` 四类 FROM/TO 批次。TO 批次
   由治理专用 provider 以新 Epoch Root 包装并进入 plan-scoped `STAGED`，普通 Phase 2-E Batch API 不能伪造。
8. provider attestation verifier 对每个账号验证控制权轮换证据；证据与 Pool、相邻 Epoch、账号、四类批次和
   provider identity 绑定。只有 Root、Share、Manifest、成员签名、Share ACK、STAGED 批次和账号证据全部完整，
   plan 才能进入 `READY`。
9. `MemberArtifact` 通过外部 gateway 分发；平台 API 的阶段响应只返回计数、状态和 fencing token，不回传
   Manifest 规范字节、Share 密文、签名、DEK、包装值或 key ref。

## 3. 状态和 HTTP 边界

准备状态按单向门禁推进：

`PLANNED -> ROOT_COMMITTED -> SHARES_COMMITTED -> MANIFEST_DRAFT -> MANIFEST_SIGNED -> ACKNOWLEDGED -> BATCHES_STAGED -> READY`

所有写阶段使用独立 Recovery Bearer、`Idempotency-Key == operation_id`、完整不变的 plan intent 和上一步返回的
fencing token。`GET /api/v1/recovery-plans/{id}` 返回去敏状态计数、记录版本，以及在进程崩溃或响应丢失后
继续阶段 CAS 所需的 `fencing_token` 和 `lease_expires_at`；它不返回 Root、Share、Manifest 字节、签名、
DEK、批次密文、key ref 或其他安全 artifact/秘密。计划达到 `READY` 只证明准备材料完整，不会激活新
Epoch、退休旧 Epoch、切换 Owner、创建新 Claim 或解除 Pool 冻结。

## 4. 数据库边界

Migration `008_phase2f_recovery_governance.sql` 增加权威账号/Seat 映射、Epoch plan、全 Seat 冻结快照、成员密钥
快照、Root artifact、加密 Share delivery、Manifest/签名/ACK、账号控制证据、STAGED batch binding、Seat
rotation progress 和永久换员工单。触发器约束完整集合、不可变安全字段、单向状态、相邻 Epoch、精确四类批次、
签名/ACK 阈值及敏感字段清理。

真实 PostgreSQL 发布门禁已继续推进：平台空库 `001 -> 011`、`010 -> 011` 停机迁移账本、历史数据升级、Batch 工作流以及 Recovery
plan/finalization 均已使用两个独立数据库连接验证到期 lease 竞争单赢家、fence 递增和旧 fence CAS 拒绝。
旧 plan fence 不能推进 Root/计划阶段，旧 finalization fence 不能执行结构提交或造成聚合双写；相关事务失败后
状态保持不变。migration `008` 的权威快照、状态跳跃和不可变约束也已随真实升级路径执行。

这些结果证明数据库内并发边界，不等同于生产链路已经发布。两 Seat 仅部分 prepare 后的不同 owner 收敛、
两 Seat activation 响应丢失单元恢复、Suspend/Provision 同 Pool 双连接竞争、Credential Batch
retire/finalization 同 Pool 双连接竞争，以及测试专用 file-backed provider commit durable 写入后的真实子进程退出/精确回放已经
通过。其余外部副作用边界联动 PostgreSQL、Sub2API/provider 的真实进程 kill 端到端恢复，以及
Batch/plan/finalization 与其他工作流跨进程多副本同时运行，仍未完成生产验收。

## 5. 后续发布门禁

数据库内 Batch、Recovery plan/finalization 双连接竞争与旧 fence CAS 已通过。生产发布仍须逐项完成并审查：

1. 链接并验收真实 Root/VSS/JCS/HSM/attestation/member signature/batch/MemberArtifact providers。
2. 在每个外部副作用边界用真实进程 kill 演练 PostgreSQL、Sub2API、provider 调用与恢复 worker 的端到端
   重启和结果未知对账；finalization lease 的进程退出接管子门禁已通过。
3. 继续以真实 PostgreSQL/provider 进程验证多 Seat 仅部分 activate 时整个 Pool 保持禁用；部分 prepare 的
   不同 owner 精确收敛和 activation 响应丢失的确定性单元门禁已通过。
4. 验证 Batch、plan、finalization 与暂停、结算、Claim 等工作流跨多副本并发，不发生重复外部副作用或死锁；
   Suspend/Provision 与 Credential Batch retire/finalization 同 Pool 双连接竞争已通过。
5. 上述门禁全部通过后，才可评审开放 Pool finalize；旧单 Seat replace 不应作为兼容入口重新开放。

在这些门禁完成前继续保持单实例并禁止 rolling overlap。

当前实现边界以 [Phase 2-G Pool 级永久换员最终化状态](phase2g-permanent-finalization-status.md) 为准。
