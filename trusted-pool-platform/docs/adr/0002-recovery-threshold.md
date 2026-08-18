# ADR-0002：治理阈值与恢复阈值分离

- 状态：Proposed
- 日期：2026-08-16

## 背景

固定五成员使用 `5-of-5` 密钥重建时，任一违约或失联成员都能永久阻断恢复；但降低密码学阈值
不应自动降低 Reveal 的治理授权要求。

## 建议

- Manifest 分别记录 `governance_threshold` 和 `recovery_threshold`。
- 治理可保持五人一致同意，恢复根建议使用 `4-of-5` 容忍一人不可用。
- 临时成员不进入 Membership Epoch，也不获得 Share。

## 未决事项

业务和法律治理尚需最终确认恢复阈值。本 ADR 未被接受前，代码不得把 `4` 或 `5` 写死；当前
Phase 1 也尚未实现 Shamir Share 和 Reveal。
