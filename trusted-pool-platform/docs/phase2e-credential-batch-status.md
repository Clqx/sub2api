# Phase 2-E 凭据批次持久化状态

> 本文保留 Phase 2-E 当时边界；当前能力与发布门禁见
> [Phase 2-F Recovery 治理准备闭环状态](phase2f-recovery-governance-status.md)。

## 已接线能力

- `POST /api/v1/credential-batches`：以独立 Batch API Key 和幂等 operation 创建 PREPARED intent，
  在数据库事务外完成 AES-256-GCM 加密与双包装，再以 lease/fencing token 提交 SEALED。
- `GET /api/v1/credential-batches/{id}`：只返回去敏元数据。PREPARED 返回 `202` 和
  `PENDING_DUAL_WRAP`，不宣称包装已经完成。
- `POST .../activate` 与 `POST .../retire`：按数据库记录版本执行不可逆 CAS，并保存转换审计。
- migration 007 将旧批次标记为 `LEGACY_UNRECOVERABLE`。旧行可供数据库运维诊断，但 API 不把它们
  当作可恢复双包装批次返回，也不允许 Activate/Retire。

## 加密边界

Seal 只生成一次随机 32 字节 DEK。Payload 使用 AES-256-GCM 加密，规范 AAD 绑定：

- seal operation ID 与 batch ID；
- Pool、账号引用、批次类型和逻辑版本；
- Membership Epoch；
- 使用独立服务密钥计算的 payload HMAC 指纹。

同一 DEK 分别交给在线 KMS 与独立 Recovery wrap-only adapter。两个 adapter 的 domain、key ref、算法
必须完整配置且安全域不同；包装输出相同、返回裸 DEK、全零结果或任一服务失败都会拒绝提交。Recovery
binding hash 绑定 Recovery domain、算法、key ref、AAD hash 和实际 wrapped DEK。

Payload、DEK、原始 AAD、密文、wrapped DEK、key ref、AAD hash 与内容指纹均不进入公开响应。在线服务
没有 Recovery Unwrap 接口。

## 运维边界

- Phase 2-E 当时要求普通、settlement、batch 三类入站 API Key 两两不同；Phase 2-F 新增的 recovery key
  也必须与三者全部不同。
- Batch operation client ID 必须与控制、settlement read、settlement resolve client ID 不同。
- 开发模式允许两把显式且不同的本地 KEK，仅用于联调。
- 生产模式禁止环境 KEK；必须由组合根注入原生支持 encryption context 的在线 KMS adapter，以及
  独立 Recovery wrap-only adapter。仓库当前未链接具体云 KMS/HSM 或 Recovery provider，因此生产模式
  仍会失败关闭。
- 当前仍固定单副本。总门禁已推进为 PostgreSQL 16 的 001→008/007→008 迁移、双连接 CAS/fence、
  epoch floor 竞态、崩溃注入和敏感 canary 扫描。

## 明确未完成

Phase 2-E 只证明“独立 Recovery 包装已持久化”，不证明成员已经具备恢复能力。以下能力继续返回 503 或
保持未实现：

- control rotation evidence 持久签发；
- Recovery Root 创建与轮换；
- Recovery Share 阈值分发；
- Manifest 签名、离线 verifier 与 Reveal Ceremony；
- 永久换员。

因此不得把 ACTIVE Credential Batch 解释为完整永久交接已经完成。
