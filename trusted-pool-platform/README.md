# 可信有限成员订阅共享平台

本目录是独立于 Sub2API 的业务与 Trust Plane。Sub2API 继续负责账号运行、独占分组、
Seat Principal、原生订阅额度、API Key 和网关执行；本平台负责 Pool、Seat、成员关系、
暂停换员、风险观察、分阶段密钥批次、恢复治理及可信审计。

## 架构基线

- 一个 Pool 对应一个 Sub2API 独占 Group。
- 一个 Seat 对应一个稳定的 Sub2API Seat Principal 和 UserSubscription。
- 成员调整只切换 Seat Assignment，不迁移订阅，因此额度用量和窗口保持连续。
- 违约处理必须先暂停并达到 `FROZEN`，之后才允许临时或永久换员。
- 设备指纹与并发仅用于风险观察和人工处置，本轮不做自动封禁。
- 临时成员不进入 Membership Epoch，不获得 Recovery Share 或 Reveal 权限。
- 永久换员必须轮换运行凭据、恢复根、Share 和 Manifest。
- 永久换员必须提交平台签发的控制凭据轮换证据。证据绑定运营或外部系统已预先核验的供应商变更
  证明引用，以及旧 Epoch 已退休、相邻新 Epoch 已激活的 LOGIN、MFA、RECOVERY、OWNERSHIP 八个批次。
  Phase 1 不校验供应商签名或证明的密码学真实性；Sub2API Seat 访问 Key 的轮换结果不能替代该证据。
- 永久换员成功后，Manager 将 Pool 最小 Membership Epoch 提升到新 Epoch；旧 Epoch 不得再 Seal 或 Activate 批次。
- 可信 Seat 禁止提交异步图片、批量图片和视频任务，避免 HTTP 返回后仍产生无法纳入冻结快照的用量。
- Pending settlement 查询和受控解除已接入持久工作流。控制、结算只读、结算解除使用三组独立的
  Sub2API client ID/secret；解除客户端只能持有单一 `settlement:resolve` scope。
- 两个系统使用独立数据库，只通过受限、幂等的集成 API 通信。
- Seat 开通使用独立 `seat:provision` scope；普通 `seat:write` 无权创建 Principal、Subscription 或 API Key。

详细设计：

- [系统架构](docs/architecture.md)
- [领域模型与数据字典](docs/domain-model.md)
- [状态机和业务不变量](docs/state-machines.md)
- [密钥批次与恢复协议](docs/security-and-recovery.md)
- [故障处理与运维手册](docs/operations.md)
- [测试和验收标准](docs/testing-and-acceptance.md)
- [原方案需求追踪](docs/requirements-traceability.md)
- [OpenAPI 契约](api/openapi.yaml)
- [Sub2API 受限集成契约](api/sub2api-integration.openapi.yaml)
- [架构决策记录](docs/adr/README.md)
- [代码审查清单](docs/review-checklist.md)

## 本轮 Phase 2-E 范围

本轮在 Phase 2-D 持久运行时之上，接入分阶段账号凭据批次的 PostgreSQL 生命周期和真实双包装。
Seal 为同一随机 DEK 生成在线 KMS 与独立 Recovery wrapper 两份包装，使用带 operation/batch 身份的规范
AAD，并只在数据库中保存密文、HMAC 内容指纹和包装元数据。Recovery wrapper 只提供 Wrap，不向在线服务
提供 Unwrap；任一包装服务不可用时请求失败关闭且不创建批次 intent。

此前临时换员、正式成员恢复和重启对账边界保持不变。
Assignment 在调用 Sub2API 前进入数据库 `ASSIGNMENT_PENDING`；成功时旧 Assignment 结束、目标 Assignment
激活、Seat 代际与 Key 版本递增、Operation 完成及加密 Claim 创建在同一事务提交。换员保持稳定的
Seat Principal、Subscription 和 API Key 资源 ID，不修改 Pool Membership Epoch 或正式 Owner。

Phase 2-B 的 `BeginSuspend` 仍在任何上游调用前，同事务创建幂等 Operation、暂停工单、数据库 lease/fence，并将 Seat
置为 `SUSPEND_PENDING`。Sub2API 返回排空中时保存真实并发和 pending settlement 计数；只有两者明确
为零且四个额度窗口快照完整时，才能同事务完成 Operation、Seat 和暂停工单的 `FROZEN` 状态。

本轮明确不实现公开交易市场、支付分账、退款担保、自动仲裁、自动风控封禁、硬件证明、
多供应商通用框架和跨地域双活。范围变更必须先更新架构决策和验收标准。

## 当前实现状态

当前 Phase 2-E Runtime 已将 Seat 开通、Operation、正式 Owner Assignment、Provision 凭据领取，
暂停/排空/冻结，以及临时换员/正式恢复接入
独立 PostgreSQL。Operation 使用数据库租约和 fencing token；claim token 只持久化 SHA-256，待交付
访问凭据只保存 KMS 包络。Provision 成功、Seat/Assignment 激活、Operation 完成和 Claim 创建在同一
数据库事务提交；数据库或包络密钥服务不可用时启动或请求失败关闭，不回退内存。

Phase 1 的永久换员只验证暂停/冻结、Seat 访问 Key 轮换、外部 attestation 引用和控制凭据批次状态机；
它不生成或签署 Recovery Root、Recovery Share、Manifest。当前接口返回成功不构成完整永久交接，
生产 permanent replace 必须等待 Phase 2 recovery governance 门禁完成。

本阶段开放持久化的 Provision、Seat/Operation 查询、credential claim、Suspend、临时换员、正式恢复、
pending settlement 查询/解除，以及 Credential Batch 的 Seal/Get/Activate/Retire。永久换员与控制轮换证据仍统一返回
`PERSISTENT_WORKFLOW_UNSUPPORTED`，禁止与旧内存 Manager/Coordinator 形成双真相。设备风险窗口仍是可丢失的
观察信号，不作为认证或自动暂停依据。最终用户会话/RBAC、outbox、完整换员持久化和 Recovery
Root/Share/Manifest 治理仍未完成，因此当前版本不是生产数据平面。

平台已有数据库 CAS/租约边界，但在真实 PostgreSQL 双连接、崩溃注入和多副本测试通过前，部署仍固定
单副本并禁止 rolling overlap。详见[Phase 2-B 暂停运行时状态](docs/phase2b-suspend-status.md)和
[Phase 2-C 换员运行时状态](docs/phase2c-assignment-status.md)和
[Phase 2-D 结算解除运行时状态](docs/phase2d-settlement-status.md)。
[Phase 2-E 凭据批次状态](docs/phase2e-credential-batch-status.md)。

## 本地运行

前置条件：Docker Compose；联调所用 Sub2API mock/服务需实现
[`api/sub2api-integration.openapi.yaml`](api/sub2api-integration.openapi.yaml) 所列路由。

```powershell
Copy-Item .env.example .env
docker compose up --build
```

`.env.example` 提供可启动的开发占位值，仅用于本地联调；部署前必须全部替换为随机密钥。
如需调整宿主机端口，修改 `TRUSTED_POOL_API_PORT`，容器内部固定监听 `8092`。

默认地址：

- API：`http://localhost:8092`
- 存活检查：`http://localhost:8092/health`
- PostgreSQL/KMS 就绪检查：`http://localhost:8092/ready`

API 启动时强制连接独立 PostgreSQL，并按顺序执行 `001` 至 `007`。历史版本由 Compose `initdb`
创建、但没有 `trusted_pool_schema_migrations` ledger 的开发卷会被判定为 unmanaged schema 并拒绝启动；
开发环境须删除并重建该卷。生产数据库不得自动认领，必须先完成受控基线核验和迁移演练。

`.env.example` 显式启用仅限开发的本地 KEK。生产模式强制 `kms`，但仓库当前没有具体云 KMS/HSM provider
adapter；未注入 adapter 时会拒绝启动，不能用本地 KEK 降级替代。首次 Provision 前，可信运营流程必须
预创建 Pool、ACTIVE Membership Epoch、`membership_epoch_members` 正式成员快照和 Owner Member；Pool 的
`sub2api_group_id` 必须与请求 `existing_group_id` 一致。

生产环境不得使用 `.env.example` 中的示例密钥，也不得将 Sub2API Admin API Key 作为集成凭据。
普通、settlement 和 batch 三类入站 API Key 必须两两不同；Batch operation client ID 也必须与控制及
settlement client ID 分离。所有密钥均应由 Secret Manager 注入。

## 目录

```text
trusted-pool-platform/
  backend/       独立 Go API 与业务服务
  api/           OpenAPI 契约
  migrations/    独立 PostgreSQL 迁移
  docs/          中文系统文档与运维说明
  compose.yaml   本地开发部署
```

## 安全约束

- 日志和错误响应不得包含用户 JWT、API Key、凭据明文、DEK、Recovery Share 或原始设备指纹。
- Credential Batch 响应不得包含 payload、content fingerprint、AAD hash、key ref、密文或 wrapped DEK；
  `PREPARED` 只表示双包装进行中，不得展示为已完成保护。
- 生产批次 Seal 必须注入原生支持 encryption context 的在线 KMS adapter 和独立 Recovery wrap-only adapter。
  不得复制同一 wrapped DEK、复用同一 domain/key 或以占位值冒充 Recovery 包装。
- 暂停结果不确定时 Seat 必须保持 `SUSPEND_PENDING`，操作进入 `RECONCILE_REQUIRED`，禁止继续换员。
- 换员结果不确定或上游返回无法证明“未应用”的 4xx 时，Seat 必须保持 `ASSIGNMENT_PENDING`；普通 4xx
  进入 `OPERATOR_REVIEW_REQUIRED`，不得自动恢复旧成员或重复轮换 Key。
- Phase 2-C 要求稳定 Principal、Subscription、API Key 三项资源 ID 完整。历史 Seat 无可信 Provision
  快照可回填时保持可读但禁止换员，必须先受控对账或重新开通。
- Seat 开通超时或结果未知时不得创建本地 Seat；调用方必须以相同请求内容和同一 `operation_id` 重放，
  由 Sub2API 幂等恢复原结果。成功后的平台重放不会再次调用上游，也不会再次返回只在首次响应出现的 claim token。
- Pool 可按 Seat 分阶段开通；每个 Seat 使用独立稳定 operation_id。任一 Seat 失败时 Pool 保持 `PROVISIONING`，
  已成功 Seat 通过原 operation_id 对账，禁止改用新 ID 重建资源。
- 同一个 `operation_id` 携带不同请求内容时必须返回幂等冲突。
- `operation_id` 是最长 128 字符的不透明标识，Phase 2 数据库不强制使用 UUID。
- Trust Plane 只向 Sub2API 发送 `OPERATIONAL` 批次，不从 Sub2API 数据库反向读取凭据。
- claim token 必须绑定目标成员和操作、由 CSPRNG 随机生成且单次使用；平台只保存 SHA-256 摘要并设置短 TTL。
  Provision 领取在披露 credential 前必须以独立 `credential:ack` scope 向 Sub2API 提交 credential fingerprint；
  ack 结果未知时失败关闭并以同一 ack 操作重放，明确成功后清除摘要与访问凭据。
- Credential 采用 at-most-once 交付：Sub2API ack 明确成功后会持久化 typed snapshot，原 token 在 TTL 内可
  继续恢复领取；但平台一旦把 Claim CAS 为 `CLAIMED` 并清密，即使随后 HTTP 响应丢失也不会二次披露，
  管理员必须重新开通或完成凭据轮换。
- 当前发布门禁仍限制单实例，禁止 rolling overlap、多副本和自动故障转移；解除前必须完成真实 PostgreSQL
  双连接、旧 fence、崩溃恢复和两实例同一 Claim 的竞争测试。
