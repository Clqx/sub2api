# Trusted-pool integration client provisioning

Use this command after migration `224` to create a client, bind a legacy
disabled client, or rotate a client in its existing pool. It independently
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
in process arguments. The CLI accepts only the listed concrete scopes and
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
```

`settlement:resolve` 必须是该客户端唯一的 scope；CLI、运行时认证和迁移约束都会拒绝将它与
`seat:*` 或其他权限混用。平台的控制、结算只读和结算解除三组 client ID 与 secret 也必须互不相同。
未完成的解除 intent 固化 resolve client ID，因此只能分阶段轮换其 secret；更换 client ID 前必须先清空
待恢复 intent。

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
