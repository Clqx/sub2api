# Trusted-pool integration client provisioning

> **Known release blockers (2026-08-31):**
>
> - Migration `227` removes the PREPARED plaintext column and introduces per-record envelope staging, AAD binding and
>   a bounded redisclosure window. This closes the plaintext code path, but the candidate is not yet a production
>   release: it still requires a controlled commit, the real PostgreSQL CI artifact, a production KMS adapter and a
>   rehearsed provider path. Until those gates pass, the operational decision remains audited fail-forward only; the
>   [recovery runbook](../../../trusted-pool-platform/docs/permanent-rotation-fail-forward-runbook.md)
>   must be rehearsed with the real PostgreSQL/Sub2API/provider path before production use.

Use this command after migration `224` to create the currently supported control and settlement
clients, bind a legacy disabled client, or rotate one in its existing pool. Permanent-rotation
clients additionally require migrations `226` and `227`. The command independently
generates two 256-bit credentials with separate authentication roles:

- `bearer_secret`: returned once; only its SHA-256 verifier is stored in
  `secret_hash`.
- `hmac_secret`: returned once; only its AES-256-GCM ciphertext is stored in
  `hmac_secret_encrypted`.

The Bearer secret is never used as an HMAC key, and the HMAC secret is never
accepted as a Bearer credential. A read-only database leak of `secret_hash`
therefore cannot forge HMAC requests.

The encryption key must be the same fixed `TOTP_ENCRYPTION_KEY` used by the
Sub2API server. The command refuses an absent or malformed key. Database
credentials are accepted through environment variables so they do not appear
in process arguments. For currently supported client types, the CLI accepts only its concrete scopes and
rejects wildcard scope grants so future server features cannot silently expand
an existing client's authority.

```powershell
$env:DATABASE_DSN = 'host=127.0.0.1 port=5432 user=sub2api password=... dbname=sub2api sslmode=disable'
$env:TOTP_ENCRYPTION_KEY = '<the same 64-character hex key used by Sub2API>'
go run ./cmd/trusted-pool-client `
  -client-id platform-pool-a-control `
  -external-pool-id pool-a `
  -scopes seat:write,seat:provision,credential:ack

go run ./cmd/trusted-pool-client `
  -client-id platform-pool-a-settlement-read `
  -external-pool-id pool-a `
  -scopes seat:read

go run ./cmd/trusted-pool-client `
  -client-id platform-pool-a-settlement-resolve `
  -external-pool-id pool-a `
  -scopes settlement:resolve

go run ./cmd/trusted-pool-client `
  -client-id platform-pool-a-permanent-rotation `
  -external-pool-id pool-a `
  -scopes seat:permanent-rotate
```

`settlement:resolve` 必须是该客户端唯一的 scope；CLI、运行时认证和迁移约束都会拒绝将它与
`seat:*` 或其他权限混用。平台的控制、结算只读和结算解除三组 client ID 与 secret 也必须互不相同。
未完成的解除 intent 固化 resolve client ID，因此只能分阶段轮换其 secret；更换 client ID 前必须先清空
待恢复 intent。

`seat:permanent-rotate` 的目标契约要求它是客户端唯一的 scope。它只授权 Pool 全量
`/permanent-rotations/prepare`、`/permanent-rotations/activate` 和
`/permanent-rotations/commit`，不能用于普通 Seat 写入、读取、开通、credential ack 或 settlement resolve。
运行时认证、migration `226` 和 CLI 均拒绝 `*`、混合 scope 以及历史错误授权；migration `227` 负责
删除 PREPARED 明文字段并约束加密暂存。CLI 的回归测试同时
覆盖 singleton 成功和混合 scope 失败。平台必须为每个 Pool 使用与 control/settlement client 不同的
client ID 和 secret。

三个永久轮换端点都要求 `Idempotency-Key` 与 body `operation_id` 完全相同。prepare 生成 credential 但保持
API Key disabled、Subscription suspended；activate 只安装 credential 并保持
`rotation_activated_pending_commit`；commit 才原子启用完整 Pool 集合。不要把 prepare 响应写入日志或 trace，
其中的 credential 是敏感明文。Sub2API 只在 `PREPARED` 数据库行中保存每记录随机 DEK 的 envelope；activate
在同一事务安装 credential 并清除全部可解密暂存材料。redisclosure TTL 过期后 exact prepare replay 不再返回
credential，但已认证的 activate 仍可完成 fail-forward，避免无 abort 协议下永久卡死。

永久轮换端点还要求 Sub2API 进程配置专用 Ed25519 签名密钥：

```powershell
$env:TRUSTED_POOL_PERMANENT_ROTATION_ENABLED = 'true'
$env:TRUSTED_POOL_PERMANENT_ROTATION_REQUIRED = 'true'
$env:TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID = 'production-permanent-rotation-ed25519-v1'
$env:TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64 = '<base64 encoded 64-byte Ed25519 private key>'
$env:TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED = 'true'
$env:TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_REQUIRED = 'true'
$env:TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID = 'permanent-rotation-staging-kek-v1'
$env:TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_FILE = '<read-only file containing base64 encoded 32 random bytes>'
$env:TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_PREPARED_CREDENTIAL_TTL = '15m'
```

`ENABLED=false`（默认）时永久轮换能力明确关闭，普通 trusted-pool 路由不受影响；`REQUIRED=true` 要求
`ENABLED=true`，适合把该能力设为部署硬门禁。永久轮换启用后，staging encryption 在所有模式下都必须启用；
release 模式还要求其 `REQUIRED=true`。签名或 staging key ID 缺失、base64 非法、密钥长度不符、同时配置
inline/file 两个来源，或两个密钥域复用 ID/材料，都会让 Sub2API 在启动期失败，不会等到请求时才 503。

生产优先把仅含 base64 文本的私钥以只读 secret 文件挂载到容器，并改用
`TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_FILE=<容器内路径>`；标准 Compose 会传递该路径，但
主机路径和只读挂载由部署 override 管理。`...PRIVATE_KEY_BASE64` 只用于能安全注入环境变量的 Secret Manager。
平台只配置对应的 key ID 和 32-byte public key，并验证 prepare/activate/commit 的完整 attestation。当前仍
没有 KMS/HSM signer adapter，也没有生产 KMS KEK adapter；当前 staging provider 使用独立的本地 KEK 包装
每记录随机 DEK。存在 PREPARED 行时不得撤销或替换对应 key ID 的 KEK。签名私钥和 staging KEK 均不得写入
项目 `.env`、数据库、镜像或该 CLI 的 stdout。

Redirect stdout directly to the target secret store. The
`bearer_secret` and `hmac_secret` are shown once and cannot be recovered through
the API. Send `bearer_secret` in `Authorization: Bearer ...`; use `hmac_secret`
only as the key for `X-Integration-Signature`. Running the command again with
the same client is rejected by default. To atomically rotate both credentials,
or bind and activate a disabled legacy client, repeat the command with the same
arguments plus `-rotate`. Rotation fails if the client does not exist or is
already bound to a different pool; create a new client ID for that case. The
command never accepts a caller-supplied secret.

Credential rotation preserves the client's current expiry when `-expires-at`
is omitted. Pass a new RFC3339 `-expires-at` value to replace it. Removing an
existing expiry requires the explicit `-clear-expiry` flag together with
`-rotate`; `-clear-expiry` and `-expires-at` are mutually exclusive. For a new
client, omitting `-expires-at` creates a credential without an expiry, and
`-clear-expiry` is rejected because there is no prior value to clear.

Migration `224` does not treat pre-fix activity as proof of pool ownership,
because those writes were created before pool-scoped authorization existed. It
disables every unbound legacy client. Re-enabling one requires this command with
`-rotate`, which explicitly binds the intended pool and replaces the old
credential with the two new secrets above. Legacy HMAC requests remain disabled
until rotation because the previous database verifier cannot be safely
converted back into signing material.
