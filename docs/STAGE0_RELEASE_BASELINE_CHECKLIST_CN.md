# Root Release Stage 0（阶段 0）发布基线清单

更新日期：2026-09-01

本文定义永久轮换候选能力进入发布评审前的最小版本与证据基线。它是门禁清单，
不是生产可用声明，也不授权自动提交、自动发布或启用永久轮换。

## 1. 当前结论

代码候选已经按核心、Monitor、可信资源池平台、CI 和文档边界形成受控提交序列；本清单随最终文档
提交进入同一候选 HEAD。提交后必须再次证明工作树清洁。当前仍没有该 HEAD 对应的远端 PostgreSQL
门禁工件和候选镜像 digest，因此只能称为“代码封板完成、发布证据待生成”，不得标记为生产可用。

## 2. 必须纳入受控版本的文件

下列能力文件及其实际依赖必须由 git ls-files --error-unmatch 验证为已跟踪：

- .github/workflows/backend-ci.yml
- .github/workflows/security-scan.yml
- .goreleaser.yaml
- .goreleaser.simple.yaml
- backend/go.sum
- backend/migrations/226_trusted_pool_permanent_rotation.sql
- backend/migrations/227_trusted_pool_permanent_rotation_encrypted_staging.sql
- backend/migrations/README.md
- backend/internal/repository/trusted_pool_permanent_rotation.go
- backend/internal/repository/trusted_pool_permanent_rotation_envelope.go
- backend/internal/repository/trusted_pool_permanent_rotation_envelope_test.go
- backend/internal/repository/trusted_pool_repo.go
- backend/internal/repository/wire.go
- backend/internal/repository/trusted_pool_permanent_rotation_migration_test.go
- backend/internal/repository/trusted_pool_permanent_rotation_postgres_test.go
- backend/internal/repository/trusted_pool_permanent_rotation_replay_test.go
- backend/internal/repository/trusted_pool_permanent_rotation_secret_storage_test.go
- backend/internal/config/config.go
- backend/internal/config/trusted_pool_permanent_rotation_test.go
- backend/internal/service/trusted_pool_integration.go
- backend/internal/service/trusted_pool_signing_config_test.go
- backend/internal/service/openai_gateway_count_tokens_test.go
- backend/internal/service/wire.go
- backend/cmd/server/main.go
- backend/cmd/server/setup_server_test.go
- backend/cmd/server/wire_gen.go
- backend/cmd/trusted-pool-client/README.md
- backend/cmd/trusted-pool-client/main.go
- backend/cmd/trusted-pool-client/main_test.go
- .env.example
- docker-compose.yml
- deploy/.env.example
- deploy/config.example.yaml
- deploy/docker-compose.yml
- deploy/docker-compose.dev.yml
- deploy/docker-compose.local.yml
- deploy/docker-compose.standalone.yml
- trusted-pool-platform/migrations/005_phase2c_assignment_persistence.sql
- trusted-pool-platform/migrations/008_phase2f_recovery_governance.sql
- trusted-pool-platform/migrations/009_phase2g_permanent_finalization.sql
- trusted-pool-platform/migrations/010_phase2h_offline_verification.sql
- trusted-pool-platform/migrations/011_phase2h_recovery_protocol_compatibility.sql
- trusted-pool-platform/migrations/012_phase2i_assignment_aggregate_repair.sql
- trusted-pool-platform/backend/internal/persistence/postgres/migrator.go
- trusted-pool-platform/backend/internal/persistence/postgres/migrator_test.go
- trusted-pool-platform/backend/internal/persistence/postgres/store_recovery_evidence_test.go
- trusted-pool-platform/backend/internal/integration/sub2api/client.go
- trusted-pool-platform/backend/internal/integration/sub2api/client_test.go
- trusted-pool-platform/backend/internal/persistence/postgres/store_recovery.go
- trusted-pool-platform/backend/internal/persistence/postgres/store_recovery_evidence.go
- trusted-pool-platform/backend/internal/persistence/postgres/store_recovery_legacy_snapshot_postgres_test.go
- trusted-pool-platform/backend/internal/persistence/postgres/store_recovery_postgres_concurrency_test.go
- trusted-pool-platform/backend/internal/persistence/postgres/store_recovery_manager_process_exit_test.go
- trusted-pool-platform/backend/internal/recovery/manager.go
- trusted-pool-platform/backend/internal/recovery/security.go
- trusted-pool-platform/backend/internal/recovery/offline/verify.go
- trusted-pool-platform/backend/cmd/recovery-verifier/main.go
- trusted-pool-platform/backend/internal/runtime/recovery.go
- trusted-pool-platform/docs/permanent-rotation-fail-forward-runbook.md
- trusted-pool-platform/docs/phase2f-recovery-governance-status.md
- trusted-pool-platform/docs/phase2g-permanent-finalization-status.md
- trusted-pool-platform/docs/phase2h-offline-verification-status.md
- docs/PROJECT_CAPABILITIES_AND_ROADMAP_CN.md
- docs/STAGE0_RELEASE_BASELINE_CHECKLIST_CN.md

若加密暂存实现新增 codec、key provider、配置测试或迁移测试，该文件必须追加到本清单，
不能通过未跟踪文件隐式进入候选镜像。

## 3. 版本冻结检查

在候选 commit 上执行并保存输出：

    git rev-parse HEAD
    git status --porcelain=v1 --untracked-files=all
    git ls-files --error-unmatch <本清单中的每个必需文件>
    git show --check --oneline --no-renames HEAD
    git diff --check <候选范围基线>...HEAD

合格条件：

1. commit ID 与 CI 工件、候选镜像标签和评审记录一致。
2. git status 没有任何输出。
3. 必需文件全部被跟踪。
4. 不存在空白错误、临时补丁、测试密钥、数据库转储或本地证据文件。

任何一项不满足都必须停止发布评审，不得由人工备注豁免。

## 4. 永久轮换秘密存储门禁

静态门禁和真实 PostgreSQL 门禁必须同时证明：

1. 最新 schema 在 forward migration 227 后不再存在 migration 226 引入的明文字段；
   227 遇到任何非空 legacy 明文必须失败关闭，禁止在 SQL 中复制或转换该值。
2. repository 不把调用方凭据直接写入 SQL 参数、日志、审计、错误或指标标签。
3. PREPARED 只保存固定七列 envelope：envelope_version、key_id、wrap_nonce、
   wrapped_dek、nonce、ciphertext 和 expires_at。version 必须为 1，两个 nonce
   必须各为 12 bytes，wrapped DEK 必须为 48 bytes，ciphertext 至少为 16 bytes；
   AAD 必须绑定 client、pool、prepare operation、seat、credential fingerprint 和协议版本。
4. 精确 prepare replay 只能在授权路径中解密；认证失败、key ID 不匹配、AAD 漂移
   或材料不完整时失败关闭。
5. activate 在同一受保护事务中消费秘密并清除所有可解密暂存材料；committed、
   retiring 和 superseded 状态不得保留可解密暂存材料。
6. 真实 PostgreSQL 测试必须检查 information_schema、PREPARED 原始行、
   replay、篡改失败和 activate 后清理，并在 go test JSON 中产生独立 pass 事件。

任何 plaintext 列、legacy plaintext fallback 或缺失 pass 事件都必须使 CI 失败。

## 5. 必跑命令

静态和常规测试：

    cd backend
    go test -tags=unit ./internal/repository ./internal/config ./internal/service -count=1
    go test ./cmd/trusted-pool-client -count=1
    go vet ./internal/repository ./internal/config ./internal/service ./cmd/trusted-pool-client

上述命令默认不访问真实 OpenAI；只有显式设置 `SUB2API_LIVE_OPENAI_TEST=1` 且提供
`OPENAI_API_KEY` 时才运行 token 估算对比。该 live 对比不属于阶段 0 离线封板门禁。

真实 PostgreSQL 门禁由 .github/workflows/backend-ci.yml 的 postgresql-gates job 执行。
必须显式提供并实际消费以下三个 DSN：

- SUB2API_TEST_POSTGRES_DSN
- PHASE2H_TEST_POSTGRES_DSN
- PHASE2H_TEST_POSTGRES_ADMIN_DSN

CI 必须保留 skip 拦截，并逐项确认 migration、秘密存储、权限、并发与进程退出
哨兵测试出现顶层 pass。无测试匹配、仅 package pass 或未产生目标 Test pass 均不合格。

部署配置还需逐套解析：

    docker compose --profile test config
    docker compose -f deploy/docker-compose.yml config
    docker compose -f deploy/docker-compose.dev.yml config
    docker compose -f deploy/docker-compose.local.yml config
    docker compose -f deploy/docker-compose.standalone.yml config
    docker compose -f trusted-pool-platform/compose.yaml config

`.github/workflows/backend-ci.yml` 的 `compose-config-gate` 会使用明确的 CI-only 假值执行以上六项，
只归档 Compose 文件哈希和 PASS 结果，不归档展开后可能包含配置值的完整输出。

同一 workflow 的 `candidate-oci-evidence` 只在所有核心测试、真实 PostgreSQL、前端、lint 与
Compose 门禁通过后，按正式发布使用的 `Dockerfile.goreleaser` 构建 `linux/amd64` OCI 候选包。
它不登录或推送镜像仓库，并会生成 SPDX SBOM 与 SLSA provenance，验证 layout index 到根 index 的
descriptor 链，重算 root index、manifest、config、普通镜像层、attestation manifest/config/layer 和
archive SHA-256，验证镜像 revision label 与候选 commit 精确一致，再归档 OCI 和映射文件。
该工件是发布候选证据，不是正式 tag 镜像或生产发布成功声明。

## 6. 必须归档的证据

- commit ID、UTC 时间、Go 版本、PostgreSQL 完整版本。
- 实际执行命令和每个门禁的 go test JSON。
- 必跑哨兵 Test 名称及其 pass 事件检查结果。
- migration ledger、秘密存储 information_schema 投影和清理断言结果。
- 候选镜像不可变 digest，以及与 commit 的映射。
- 配置模式和 key ID；只能记录非秘密标识与指纹。
- 评审结论、未关闭风险、回滚或 fail-forward 演练引用。

禁止归档 DSN 密码、私钥、AES/KMS key、prepared credential、可解密 envelope、
claim token、完整 Authorization header 或数据库明文转储。

## 7. 发布结论规则

只有受控 commit、清洁工作树、全部哨兵 pass、证据工件可下载且候选镜像 digest
一致时，阶段 0 才可标记为“基线已形成”。这仍不等于生产可用；真实 KMS/HSM、
provider、故障注入、备份恢复、安全扫描和封闭试点继续按项目路线图执行。

失败或证据缺失时保持单实例、禁止 rolling overlap，并按 fail-forward 手册处置
已打开的永久轮换，禁止直接修改数据库伪造终态。
