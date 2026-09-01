# 项目能力盘点与交付路线图

更新时间：2026-09-01

审查基线：分支 `codex/monitor-trusted-pool-hardening` 的受控提交序列。永久轮换核心、Monitor、可信资源池平台、PostgreSQL CI 和首轮文档基线分别固化为 `bf309373e`、`56c792b1c`、`70259d007`、`7a78472eb`、`37202644b`；后续兼容修复与发布证据自动化继续在同一候选分支推进。这些提交是代码封板记录，不是生产发布或远端 CI 成功声明。

本文是当前仓库的跨模块状态入口，用业务语言统一说明“已经能做什么、在什么条件下能用、距离生产交付还差什么”。模块内的架构、协议和历史阶段报告仍负责提供技术细节与当时的验收证据。

## 状态口径

| 状态 | 含义 |
|---|---|
| 可交付 | 主流程已实现并通过自动化验证，可进入正常部署验收；外部支付、上游账号等能力仍取决于实际配置和供应商可用性。 |
| 受控可用 | 开发闭环已经成立，但只能在明确开关、单实例、人工审批或指定基础设施下使用。 |
| 上线门禁中 | 功能主体已完成，仍缺兼容性、性能、灾备、安全或真实外部系统验收。 |
| 规划中 | 已明确业务目标和边界，尚未形成可交付闭环。 |
| 不在范围 | 当前阶段明确不建设，不能从相邻能力推断为已经支持。 |

跨模块阶段名必须带模块前缀：本文的 `Root Release Stage 0` 指永久轮换发布证据基线；Monitor Phase 0
指产品契约与版本样本；可信资源池文档中的 legacy Phase 1 指历史证据阶段。它们不是同一个里程碑。

## 总体结论

仓库已经形成三个可以独立理解、组合交付的产品模块：

1. **Sub2API 核心网关**已经具备账号与 API Key 管理、额度与计费、调度与限流、请求转发、支付和管理后台等基础经营能力。可信资源池所需的受限 Seat 集成和永久轮换数据库约束已进入受控提交，但迁移 226/227 仍需在目标生产基线数据库上完成发布演练。
2. **Sub2API Monitor**已经从基础监控扩展为多实例运维中心，覆盖额度、账号、通道、TTFT、原生运维指标、成本路由、事件通知和受控账号恢复。功能阶段已经闭环，当前处于兼容性与发布加固阶段，尚不能把“功能完成”等同于“生产 V1 已发布”。
3. **可信资源池平台**已经完成 Seat 开通、暂停冻结、换员、结算屏障、凭据批次、Recovery 治理准备、Pool 级永久最终化和公开证据离线验证的开发闭环。由于生产 KMS/HSM、恢复和供应商适配器、Reveal 执行器、最终用户 RBAC 及多副本门禁尚未完成，当前不是生产数据平面。

## 当前业务能力

| 业务域 | 已形成的业务结果 | 当前状态 | 主要边界 |
|---|---|---|---|
| 核心账号与网关 | 管理多种上游账号，向用户分发 API Key，完成鉴权、转发、粘性调度、并发和速率控制 | 可交付 | 具体模型和供应商能力取决于账号类型、上游权限及部署配置 |
| 额度、计费与支付 | Token 级用量和成本核算，用户余额与订阅管理，内置支付接入 | 可交付 | 支付渠道上线前仍需真实商户凭据、回调域名和财务对账验收 |
| 可信 Seat 同步网关集成 | 稳定 Principal、Subscription、API Key 资源，以及同步请求的并发租约、冻结和结算屏障 | 受控可用 | 异步图片、批量图片和视频任务明确拒绝；只覆盖同步网关业务 |
| Pool 级永久轮换 | Prepare、activate-held、commit 协议、迁移 226/227、加密暂存、专用 client、显式启动门禁和 fail-forward 处置已形成开发闭环 | 上线门禁中 | PREPARED 明文存储路径已在代码中消除并形成受控提交；真实库 CI 首跑、真实进程故障演练和生产 signer/KMS/provider 仍未完成 |
| 多实例监控 | 同时接入多个 Sub2API，支持 API-only 和 API + 只读数据库两种模式，区分支持度、运行状态和数据新鲜度 | 上线门禁中 | 仍需至少两个代表版本的脱敏样本和兼容性报告 |
| 额度与账号运营 | 被动额度、显式授权的主动额度刷新、账号可用性、分组、倍率和 7/30/90 天用量分析 | 上线门禁中 | 主动刷新可能触发上游访问，只能双开关启用；未知值不会按 0 处理 |
| 通道与服务质量 | 通道健康、模型覆盖、可用率、延迟和流式首 Token 时间告警 | 上线门禁中 | 必须完成规模基线、故障注入和升级回滚验收 |
| 成本路由 | 按实际倍率调整账号优先级，结合可用性和通道质量失败关闭，识别真实会话切换 | 受控可用 | 执行模式会写账号优先级，必须显式确认；不清理既有粘性会话 |
| 事件与通知 | 统一事件、去重、确认、恢复、持久投递，支持 ntfy、Telegram 和签名 Webhook | 上线门禁中 | 投递为至少一次语义；完整静默、提醒策略和生产通知演练仍需收口 |
| 账号恢复自动化 | 对五类允许动作提供建议、逐次人工审批、幂等执行、冷却、审计和执行后复查 | 受控可用 | 不支持无人值守自动执行；旧版 execute 规则不能重新启用；不开放凭据、路由、系统和备份类破坏性操作 |
| 可信资源池日常运营 | Seat 开通、一次性凭据领取、暂停/排空/冻结、临时换员、正式恢复、pending settlement 处理 | 受控可用 | 固定单实例，禁止滚动重叠；最终用户会话/RBAC 尚未完成 |
| 可信凭据与恢复治理 | 双包装凭据批次、Recovery plan、Pool 全 Seat 最终化、一次性 replacement claim 的代码与测试闭环 | 上线门禁中 | 当前发布组合根没有生产 KMS/HSM/VSS/JCS/attestation/member/batch providers，治理能力不可激活 |
| 公开证据离线验证 | 严格 JCS Evidence Bundle 和独立 offline verifier | 受控可用 | 只验证调用方提供的公开证据与外部信任策略；不连接数据库、KMS 或 provider |
| 持久证据导出与 Reveal | 导出 intent/Store/条件路由和 Reveal 授权 transcript 代码已完成 | 上线门禁中 | 当前发布组合根没有 export signer，导出不可激活；没有解密、重建、unwrap、明文 Reveal 或在线执行 API |
| 资源池交易市场 | 交易、支付分账、退款担保、自动仲裁 | 不在范围 | 需要独立商业系统立项，不与 Trust Plane 状态机混合 |

## 最近验证证据

以下结果是当前工作区最近一次工程验证，不代表持续运行 SLA：

| 模块 | 最近通过的验证 | 尚未覆盖的关键门禁 |
|---|---|---|
| Sub2API 后端 | 单元测试与 `go vet` 通过；在 WSL 隔离 PostgreSQL 16.15 上，迁移 226/227、密文暂存 schema/原始行、回放、篡改拒绝和激活清理完整门禁通过 | live OpenAI 对比不属于本次离线封板；本地 JSON 是修复候选验证，仍需由提交后 CI 工件绑定最终 commit |
| 可信资源池后端 | `go test ./...` 与 `go vet ./...` 通过；隔离 PostgreSQL 16.15 上 persistence 包 113 个测试事件通过，仅两个明确子进程 helper 跳过；`govulncheck` 无发现 | 仍缺最终 commit 对应的远端工件；生产 provider、真实网关/KMS 全链路和更广多副本演练未完成 |
| Monitor 后端 | `pytest -q`：160 个测试通过 | 代表版本兼容性、性能基线、发布镜像安全和灾备演练 |
| Monitor 前端 | 25 个测试通过，生产构建通过 | 完整发布环境浏览器回归和可访问性验收 |
| 独立代码审查 | 本轮确认的 commit/suspend 竞态、PREPARED 明文路径、Compose 覆盖、setup 启动门禁、CI 假绿和文档状态缺口已在受控提交中修复 | 仍需在真实 PostgreSQL 工件、发布候选镜像和真实外部系统上复审 |
| 版本可追溯性 | 核心、Monitor、平台、CI 和文档按依赖边界形成受控提交序列；CI 已定义 Compose 哈希/PASS 工件与带 commit 标签、SPDX SBOM、SLSA provenance 的 OCI 候选包 | 仍需在最终 commit 上实际运行并下载工件，核对 PostgreSQL JSON 与 OCI manifest digest |

## 本轮 P0 收口结果

以下确定性实现缺口已经关闭，但“代码完成”不等于“真实环境发布门禁通过”：

1. **永久轮换客户端入口已关闭阻断。** Provisioning CLI 已允许唯一 scope `seat:permanent-rotate`，并通过 singleton 成功、混合 scope 拒绝的回归测试。
2. **签名与加密暂存配置门禁已关闭阻断。** 永久轮换默认关闭；启用或声明 required 后，key ID 与有效 Ed25519 私钥在监听前成为硬门禁。永久轮换启用时所有模式必须同时启用独立 staging encryption，release 模式还要求 staging `required=true`；32-byte staging key 与签名 key 的 ID 和材料不得复用，环境变量和只读 `_FILE` 二选一。五套 Sub2API Compose 均已传递配置；当前仍没有生产 KMS/HSM signer 或 staging-encryption adapter。
3. **真实 PostgreSQL CI 定义已关闭阻断。** 新 job 使用 PostgreSQL 16 和两个隔离库，实际消费 `SUB2API_TEST_POSTGRES_DSN`、`PHASE2H_TEST_POSTGRES_DSN`、`PHASE2H_TEST_POSTGRES_ADMIN_DSN`；除两个明确子进程 helper 外，任何 SKIP 都会失败，并归档版本、命令和 JSON 结果。
4. **中断恢复决策已关闭设计空白。** 当前采用 fail-forward only，不增加无法安全证明的 abort；状态矩阵、证据留存、签名键故障和真实进程退出演练标准已经进入运维手册。
5. **commit 回执丢失后的 suspend 竞态已关闭。** 服务在检查 Seat 当前 active 状态前先按完整请求绑定查询历史 commit；`committed` 和 `retiring` 可返回原回执且不重新启用资源，`superseded` 或 fingerprint 漂移稳定失败关闭。
6. **启动和 CI 门禁已加固。** manual first-run setup server 在监听前执行永久轮换配置预检；五套 Sub2API Compose 不再用 `false` 覆盖配置文件；PostgreSQL job 除拒绝 skip 外，还归档秘密存储静态结果，并要求十二个真实库哨兵 pass 事件逐项出现。
7. **PREPARED 明文路径已在代码中关闭。** Forward migration 227 对非空 legacy 明文失败关闭并删除旧列；PREPARED 使用独立 envelope、AAD 和 TTL，activate 清除可解密材料。静态与真实 PostgreSQL 子门禁已经接入，是否可发布仍取决于受控 commit 上的 CI 首跑证据。
8. **历史迁移兼容缺口已关闭。** 平台 migration 005 的 PL/pgSQL `CASE` 比较已改为 PostgreSQL 16 可解析的显式表达式；迁移 runner 只为该文件接受已发布旧 checksum，空库记录修复后 checksum，其他版本或任意漂移仍失败关闭。Sub2API migration 226 同步把 Seat 状态列扩至 64 字符，避免激活中间态超过旧 20 字符上限。
9. **发布候选证据已自动化。** 六套 Compose（含 root test profile）进入 CI；全部核心门禁通过后，CI 按正式发布使用的 `Dockerfile.goreleaser` 构建单架构 OCI，生成并验证 SPDX SBOM、SLSA provenance、manifest/config/blob 哈希和 commit revision 标签。该工件不会自动推送或提升为正式 release。
10. **依赖扫描覆盖已扩展。** 安全 workflow 现覆盖核心与可信资源池 Go 模块、Monitor Python 生产依赖、兑换平台 npm 生产依赖和主前端审计；扫描器版本已固定。镜像漏洞与仓库秘密扫描仍是独立未关闭项。

## 仍未关闭的发布门禁

1. **远端 CI 首跑证据尚未产生。** 本机已借助 WSL PostgreSQL 16.15 完成两套真实库候选验证，但 Docker Desktop Linux 引擎仍返回 500；必须在最终受控 commit 上成功运行 CI 并归档数据库版本、命令和 JSON 工件。
2. **加密暂存的发布证据尚未关闭。** migration 227 和 envelope/TTL/activate 清理已在本地真实 PostgreSQL 通过；仍必须由最终 commit 对应的 CI 工件证明 legacy 非空升级失败关闭、七列 schema、PREPARED 原始行无明文、篡改/过期拒绝和 activate 清理全部通过。
3. **真实 fail-forward 演练尚未完成。** 仍需使用真实 PostgreSQL、Sub2API 和可持久 provider，在 prepare、activate、结构事务、commit、token 各边界执行进程退出与响应丢失演练。
4. **可信资源池生产组合根仍关闭。** 生产 KMS adapter、七类 Recovery providers 和 export signer 尚未注入，开启治理或导出会在服务监听前失败；这符合失败关闭设计，但不构成可调用的生产能力。
5. **发布证据基线尚未形成。** PostgreSQL、Compose 与 OCI/SBOM/provenance 门禁已可自动生成证据，但缺少最终 HEAD 对应的远端工件、镜像漏洞/仓库秘密扫描和真实外部系统演练；必须继续执行 [Root Release Stage 0 发布基线清单](STAGE0_RELEASE_BASELINE_CHECKLIST_CN.md)。

## 分阶段交付计划

| 阶段 | 业务目标 | 进度 | 完成标准 |
|---|---|---|---|
| A. 状态与范围收敛 | 建立全仓统一能力口径，消除“开发完成”和“生产可用”的混用 | 已完成 | 根入口、模块状态、需求追踪和路线图互相链接，历史证据保留 |
| B. 兼容性与发布加固 | 把 Monitor 和可信集成从功能闭环推进到可重复发布 | 进行中：本地真实库与发布证据流水线已完成，待远端工件、兼容样本、灾备和真实演练 | 两个代表版本样本、契约冻结、性能基线、故障恢复、备份/恢复/升级/回滚、安全扫描和发布候选报告通过 |
| C. 生产基础设施接线 | 接入真实 KMS/HSM、签名、证明、成员和批次 provider，并完成真实 Sub2API 联调 | 待启动 | 所有生产 provider 就绪，敏感数据扫描通过，逐外部副作用失败和进程退出可恢复 |
| D. 封闭试点 | 在严格边界下验证真实运营、对账和人工处置 | 受 C 阻塞 | 单实例试点、运行手册、告警值班、暂停未知结果和永久换员演练完成 |
| E. 多实例与恢复执行 | 支持滚动发布、多副本接管、最终用户权限和受控 Reveal/恢复执行 | 规划中 | 跨工作流多副本矩阵、RBAC、Recovery Package 演练和独立安全评审通过 |

## 当前优先级

1. **P0：生成最终 commit 的远端发布基线证据。** PREPARED 明文路径与本地 PostgreSQL 门禁已通过；下一步按 [Root Release Stage 0 发布基线清单](STAGE0_RELEASE_BASELINE_CHECKLIST_CN.md)运行完整 CI，归档数据库 JSON、六套 Compose 结果及 OCI/SBOM/provenance 工件。任何哨兵测试缺少 pass、非白名单 SKIP 或 digest/commit 不一致都不能转为“生产可用”。
2. **P0：完成 Monitor 发布证据基线。** 收集两个代表 Sub2API 版本的脱敏 API/Schema 样本，冻结 V1 契约并建立 supported-version matrix。
3. **P1：完成可靠性与灾备。** 建立真实账号规模下的采集并发和延迟基线，覆盖 API 401/429/5xx、数据库中断、通知超时、备份恢复和版本升级。
4. **P2：完成生产安全门禁。** 依赖扫描与候选 OCI SBOM 已接入；继续完成 OCI 镜像漏洞和仓库秘密扫描，接入可信资源池所需的生产 KMS/HSM 与签名/证明 providers。
5. **P3：完成真实联调和封闭试点。** 使用真实网关、KMS 和 provider 验证 prepare、activate-held、commit、claim 及失败恢复，全程保留审计和对账证据。
6. **P4：再评估扩展能力。** 在上述门禁通过后，再启动多副本、滚动发布、最终用户 RBAC、Reveal 执行器和更多供应商适配。

## 模块明细入口

- [Sub2API Monitor 当前状态](../sub2api-monitor/docs/STATUS.md)
- [Sub2API Monitor 交付计划](../sub2api-monitor/docs/DELIVERY_PLAN.md)
- [Sub2API Monitor 需求追踪](../sub2api-monitor/docs/TRACEABILITY.md)
- [Sub2API Monitor 版本证据台账](../sub2api-monitor/docs/SUPPORTED_VERSIONS.md)
- [可信资源池需求追踪](../trusted-pool-platform/docs/requirements-traceability.md)
- [可信资源池测试与验收](../trusted-pool-platform/docs/testing-and-acceptance.md)
- [永久凭据轮换 Fail-Forward 故障续跑](../trusted-pool-platform/docs/permanent-rotation-fail-forward-runbook.md)
- [可信资源池 Phase 2-H 状态](../trusted-pool-platform/docs/phase2h-offline-verification-status.md)
