# 状态机与业务不变量

## 1. Pool

```text
DRAFT -> PROVISIONING -> WAITING_MEMBERS -> ACTIVE
                              |              |
                              v              v
                            FAILED         FROZEN -> ACTIVE
                                              |
                                              v
                                           CLOSED
```

只有资源侧独占 Group 和所有 Seat Principal 都成功创建后才能离开 `PROVISIONING`。
当前平台 Seat 开通接口只接受既有 Group，在 Sub2API 同一事务创建不可交互 Principal、Subscription 和
API Key。调用期间不预建本地 ACTIVE Seat；失败或结果未知时 Operation 为 `RETRYABLE`，同一请求重放
恢复，明确成功后才落本地 Seat，并仅在首次成功响应签发 owner 绑定的一次性 claim token。

## 2. Seat 暂停和换员

```text
ACTIVE
  -> SUSPEND_PENDING
  -> DRAINING
  -> FROZEN
       -> ASSIGNMENT_PENDING -> ACTIVE
       -> REPLACEMENT_PENDING -> ACTIVE
```

这是当前 Go 领域内核使用的业务状态。资源侧 `BLOCKED` 和 Key 轮换是 Pending 状态内部的
执行进度，Phase 2 可在操作详情中展示，但不增加可跳转的业务捷径。
结果未知时 Seat 保持 Pending，操作进入 `RECONCILE_REQUIRED`，不能回到 `ACTIVE`。

### 暂停协议

1. 新平台创建 `SuspensionCase`，记录原因、操作者和 `operation_id`。
2. Sub2API 原子禁用旧 Key、将 Seat 标记为阻断；授权 epoch 的最终值由资源执行结果确认。
3. 网关拒绝新请求；`BLOCKED` 是资源侧进度，新平台 Seat 保持 `SUSPEND_PENDING`。
4. Sub2API 等待可续租的在途租约归零，并确认 `pending_settlements=0`；返回排空中时新平台 Seat
   进入 `DRAINING`。结算错误、panic、超时或 pending 删除失败时必须失败关闭并等待人工对账。
5. 连续两个租约心跳周期再次确认并发和 pending 均为 0，再固化小时、日、周、月用量及其窗口
   起点、Key 版本、epoch 和在途处理结果，生成 `freeze_snapshot`；
   原生窗口尚未启动时对应 `window_starts` 为 null。
6. 新平台校验快照后进入 `FROZEN`。

网络超时只意味着结果未知。操作进入 `RECONCILE_REQUIRED`，Seat 保持 `SUSPEND_PENDING` 并查询操作状态，不得恢复为 `ACTIVE`，
更不得直接开始换员。

### 临时换员

- 前置状态必须为 `FROZEN`。
- 创建 `TEMPORARY` Assignment 并轮换 Seat API Key。
- 不修改 Membership Epoch、不发放 Share、不授予 Reveal 权。
- 到期或原成员恢复时再次走暂停、排空、冻结，然后恢复原成员。

### 永久换员

- 前置状态必须为 `FROZEN`，且业务审批已完成。
- 创建 `PERMANENT` Assignment，增加 Membership Epoch。
- 旧 Epoch 的 `LOGIN`、`MFA`、`RECOVERY`、`OWNERSHIP` 四类批次必须全部 `RETIRED`，相邻新
  Epoch 的对应四类批次必须全部 `ACTIVE`，并提交运营或外部系统已预先核验真实性的
  `provider_attestation_ref`，之后由平台签发 `control_rotation_evidence_ref`。
- 平台证据绑定供应商证明引用和新旧八个批次 ID。Coordinator 必须按 Seat Pool、当前 Membership
  Epoch 和相邻新 Epoch 复核该引用及批次当前状态；任意非空外部引用本身不能替代平台证据。
- Phase 1 只保存 `provider_attestation_ref`，不获取外部证明，也不做供应商签名或证明的密码学校验。
- Sub2API 的 `access_credential_rotated` 只证明 Seat 访问 Key 已轮换，不得当作上述控制凭据轮换证据。
- 轮换恢复根、Recovery Share 和 Manifest。
- 永久换员成功后，Manager 将 Pool 最小 Membership Epoch 提升到新 Epoch；旧 Epoch 只保留审计用途，
  不得再 Seal 或 Activate 批次。

## 3. Credential Batch

```text
SEALED -> ACTIVE -> RETIRED
```

- `SEALED`：内容已由批次 DEK 加密，DEK 已由 KMS/恢复根包装。
- `ACTIVE`：满足激活条件，可用于当前 Epoch。
- `RETIRED`：已被新版本替换，不得重新激活。

当前 Go 内核实现以上三个密文生命周期状态。`PREPARED`、Share `DISTRIBUTED` 和失败重试属于
Phase 2 持久化编排状态，不应被描述为当前已经实现。

激活必须使用比较并交换，确保同一 Pool、账号引用、批次类型和 Epoch 只有一个活动版本。

批次或访问凭据交付给成员时使用与“目标成员 + 操作/批次”绑定的密码学随机 claim token。平台只保存
token SHA-256 摘要和短 TTL。Provision 领取状态按
`READY -> ACK_PENDING -> CLAIMED` 推进；结果未知进入 `ACK_RECONCILE_REQUIRED` 并失败关闭，过期进入
`EXPIRED` 且销毁 credential。成功领取消费摘要并清除待交付明文；token 重放、其他成员代领或重复 ack 均失败。
Phase 2-A 已持久化 Provision Seat 访问凭据领取；临时换员、恢复、永久换员和 Credential Batch/Share
领取尚未接入 PersistentCoordinator，相关端点失败关闭。

## 4. 风险等级

```text
NORMAL -> WATCH -> LIMITED -> SUSPEND
```

该状态机只产生观察结果和建议。任何等级变化都不能自动修改 Seat、Assignment 或 API Key 状态。
运营人员确认后另行发起暂停命令，审计中必须区分“风险发现”和“人工处置”。
