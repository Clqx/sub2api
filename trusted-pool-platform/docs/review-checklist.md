# 代码审查清单

审查结论应逐项给出证据；无法验证的项目标记为阻塞，不以“后续补充”代替发布门禁。

## 目标与范围

- [ ] 修改直接服务暂停换员、额度连续、风险观察、凭据批次或必要基础设施。
- [ ] 未引入支付、市场、自动封禁、多供应商框架等范围外能力。
- [ ] README、OpenAPI 和实现没有把 Phase 2 能力写成当前已实现。

## Seat 与一致性

- [ ] 所有换员入口都要求 Seat 为 `FROZEN` 且冻结快照 epoch 匹配。
- [ ] DRAINING 或结果未知不会恢复为 ACTIVE，也不会开始新 Assignment。
- [ ] 相同 Idempotency-Key 只能表示同一 Seat、操作类型和目标成员。
- [ ] 永久换员在凭据轮换未确认时不能成功。
- [ ] 临时换员不增加 Membership Epoch、不修改正式 Owner。

## 风险观察

- [ ] 原始设备指纹不进入聚合结构、日志、指标或持久层。
- [ ] 风险等级变化没有调用暂停、换员或 Key 禁用逻辑。
- [ ] 重复 observation ID 不重复累计请求和并发。

## 凭据与日志

- [ ] payload、API Key、KEK、DEK、Wrapped DEK 和 Share 不出现在日志或错误响应。
- [ ] AEAD AAD 包含 Pool、账号、批次类型、版本和 Membership Epoch。
- [ ] 退休批次不能打开或重新激活。
- [ ] 新增复杂安全逻辑有解释“为什么”的中文注释，没有复述代码的无效注释。

## 接口与测试

- [ ] OpenAPI 路径、字段名、状态枚举、响应包络与实现一致。
- [ ] `go test ./...`、`go test -race ./...` 和 `go vet ./...` 通过。
- [ ] 包含正常、重复、冲突、超时、DRAINING 和对账路径测试。
- [ ] Compose 使用的环境变量、端口和二进制路径与实际代码一致。

## Phase 2 上线门禁

- [ ] PostgreSQL Repository、迁移回滚/升级验证和 outbox 已完成。
- [ ] Sub2API 受限集成路由已实现，未使用通用 Admin API Key 替代。
- [ ] 服务级 Bearer Key 已替换为用户会话与细粒度 RBAC。
- [ ] 本地 KEK 已替换为 KMS/HSM，并完成 Recovery Root 双重包装和恢复演练。
