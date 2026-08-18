# 密钥批次与恢复协议

## 1. 安全目标

- Sub2API 只获得请求供应商所需的运行凭据。
- 新平台能够按阶段密封登录、MFA、恢复和所有权材料。
- 平台服务失效时，正式成员可用离线工具校验 Manifest 并按治理规则恢复。
- 临时成员和离任成员不能参与新 Epoch 的恢复。
- 任何持久化位置均不保存凭据明文或未包装 DEK。

## 2. 批次划分

| 类型 | 内容示例 | 是否发送 Sub2API |
|---|---|---|
| `OPERATIONAL` | access token、refresh token、运行 cookie | 是，仅发送必要字段 |
| `LOGIN` | 登录名、密码 | 否 |
| `MFA` | TOTP 种子、备用码 | 否 |
| `RECOVERY` | 恢复邮箱和恢复材料 | 否 |
| `OWNERSHIP` | 所有权迁移材料 | 否 |

供应商适配器必须声明字段属于哪个批次，禁止用字符串规则临时拆分 JSON。

## 3. 包络加密

Phase 2-A 的 Provision Claim 已实现 AES-256-GCM、AAD 绑定、随机 DEK、在线 KMS adapter 边界和
持久 `WrappedDEK`。开发模式可显式使用本地 KEK；生产 provider adapter 尚未链接，配置为 production
时会失败关闭。Recovery Root 双重包装、Share、离线恢复工具，以及 Credential Batch 持久运行时仍未实现。

1. 每个批次版本生成随机 DEK。
2. 使用 AEAD 加密规范化后的批次内容，关联数据包含 Pool、账号引用、批次类型、版本和 Epoch。
3. Phase 2-A：DEK 由在线 KMS KEK 包装，用于平台正常运维。
4. Phase 2-C：DEK 同时由当前 Recovery Root 包装，用于离线恢复。
5. 保存密文、nonce、算法、关联数据散列、包装后 DEK 和内容散列。
6. 清除内存中的明文和原始 DEK；日志只记录批次 ID 和状态。

生产环境必须使用 KMS/HSM。本地 `TRUSTED_POOL_KEK_HEX` 仅供开发测试，不能用于生产数据。

## 4. 治理与密码学阈值分离

固定五成员场景中，`5-of-5` 密钥重建会被一个违约或失联成员永久阻断。因此建议：

- 治理授权阈值可保持 5 人一致同意。
- Recovery Root 使用 `4-of-5` Shamir 阈值以容忍一人不可用。
- Reveal 是否获准由签名策略判定，不以“能否拼出密钥”代替治理授权。

最终阈值是产品治理决策，必须记录在 Membership Epoch 和 Manifest 中，不能写死在代码里。

## 5. Membership Epoch

新 Epoch 包含正式成员 ID、成员签名公钥、治理阈值、恢复阈值、批次根散列和前一 Manifest 散列。
临时换员不创建新 Epoch。永久换员必须：

1. 暂停并冻结相关 Seat。
2. 轮换供应商真实凭据，而非仅重包旧 DEK。
3. 生成新 Recovery Root 和 Share。
4. 为仍需保留的材料生成新批次版本。
5. 发布并签署新 Manifest。
6. 激活新 Epoch，退休旧批次。

旧 Share 无法被“撤回”，只有换根和换真实凭据才能使其失效。

上述流程是完整永久交接的安全门禁。Phase 1 仅验证暂停/冻结、Seat 访问 Key 轮换、外部 attestation
引用和控制凭据批次状态机，不生成或签署 Recovery Root、Recovery Share、Manifest。因此 Phase 1
永久换员操作成功不代表完整永久交接；生产 permanent replace 必须等待 Phase 2 recovery governance
完成第 3、5 项及相关 Share 分发、签名和激活门禁。

### 控制凭据轮换证据

`POST /api/v1/control-rotation-evidence` 接收 `pool_id`、`account_ref`、`from_membership_epoch`、
`to_membership_epoch` 和必填的 `provider_attestation_ref`，且两个 Epoch 必须相邻。运营或外部系统必须
先验证该引用所指供应商登录、MFA、恢复和所有权变更证明的真实性，再发起签发请求。Phase 1 只保存
该不透明引用，不获取外部证明，也不做供应商签名或证明的密码学校验；不得宣称平台验证了供应商动作。

平台仅在旧 Epoch 的 `LOGIN`、`MFA`、`RECOVERY`、`OWNERSHIP` 四类批次全部 `RETIRED`，并且新
Epoch 的对应四类批次全部 `ACTIVE` 时签发证据。证据同时绑定 `provider_attestation_ref` 和新旧八个
批次 ID，不包含凭据明文。

永久换员不能只检查引用非空：Coordinator 必须使用
Seat 的 Pool、当前 Membership Epoch 和 `current + 1` 复核证据范围，并重新检查所引用批次仍满足
退休/激活条件。跨 Pool、跨 Epoch 或状态已变化的证据立即失效。永久换员成功后，Manager 把 Pool
最小 Membership Epoch 提升到新 Epoch，后续旧 Epoch 的 Seal 或 Activate 均被拒绝。

Phase 2-A SQL 已增加证据、供应商证明引用、八批次引用和最小 Epoch 的事务约束；当前
PersistentCoordinator 尚未接入这些表，相关 HTTP 端点统一失败关闭。接线和真实 PostgreSQL 恢复演练
通过前，不能把 schema 存在当成永久换员能力。

## 6. Manifest 最低字段

- 协议版本、Pool ID、Epoch、创建时间。
- 正式成员及签名公钥快照。
- 治理阈值和密码学恢复阈值。
- 所有活动批次的 ID、类型、版本、密文散列。
- Recovery Package 根散列。
- 前一 Manifest 散列，形成可审计链。
- 平台签名和成员签名。

离线验证器必须先验证规范化编码、散列链和签名，再允许恢复。校验失败时不得尝试解密。

## 7. 凭据处理禁令

- 不从 Sub2API `accounts.credentials` 反向导出恢复材料。
- 不在 API 响应、审计 payload、panic、trace 或指标标签中记录秘密。
- 不把完整批次明文写入临时文件或消息队列。
- 不将 `OPERATIONAL` 之外的批次发送给 Sub2API。
- 不允许已退休批次重新激活。

## 8. 成员领取与 ack

- 每次交付生成独立的 256-bit 密码学随机 claim token，并绑定目标成员 ID、操作 ID 或批次 ID；平台只保存
  SHA-256 摘要和短 TTL，明文仅出现在首次成功响应中。
- token 只随原始受保护命令返回，不出现在状态查询、日志、审计 payload 或指标标签中。
- 成员领取时同时提交自身 ID 和 token；两者与绑定值一致才返回一次性凭据。
- Provision 凭据先以独立 `credential:ack` scope 向 Sub2API 提交稳定 claim operation ID、成员和 credential
  fingerprint；只有明确确认后才交付。结果未知时失败关闭并幂等重放，TTL 到期销毁待交付值。
- 成功领取即完成 ack，必须消费 token 摘要并清除待交付明文；重放和跨成员代领均失败。
- Phase 2-A 已持久化 Provision Seat 访问凭据的 token 哈希、KMS 包络、领取状态和 typed ack 证据。
  Credential Batch/Share 领取仍未接入持久运行时，必须复用相同规则后才能开放。

持久化时只保存 claim token 的带密钥摘要或不可逆哈希，不保存原始 token；待交付秘密必须由 KMS
包络加密。上游网络调用不得持有数据库事务：先持久化 ack marker，调用上游，再持久化 typed ack；
解密后以独立 fenced CAS 消费 Claim 并清密，只有 CAS 成功的本次请求可以披露 credential。
