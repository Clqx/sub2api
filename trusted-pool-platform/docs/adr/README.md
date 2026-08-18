# 架构决策记录

ADR 用于固定会影响跨模块边界、数据一致性或安全模型的决定。状态含 `Accepted`、`Proposed`、
`Superseded`。修改已接受决定时必须新增 ADR，不直接覆盖原结论。

| ADR | 状态 | 决策 |
|---|---|---|
| [0001](0001-seat-principal.md) | Accepted | 额度绑定稳定 Seat Principal |
| [0002](0002-recovery-threshold.md) | Proposed | 治理阈值与恢复阈值分离 |
| [0003](0003-risk-observation-only.md) | Accepted | 风险只观察，不自动暂停 |
| [0004](0004-independent-database.md) | Accepted | 新平台独立数据库，禁止共享写入 |
