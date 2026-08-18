# ADR-0001：额度绑定稳定 Seat Principal

- 状态：Accepted
- 日期：2026-08-16

## 背景

Sub2API 原生额度窗口和用量绑定 UserSubscription。若订阅跟随成员迁移，在途请求和延迟结算可能
落入旧成员记录，导致重复或遗漏计费。

## 决策

平台通过 Sub2API 受限 provision API 为每个 Seat 创建不可交互登录的稳定 Principal。UserSubscription 始终绑定
该 Principal；换员只轮换 Assignment 和 API Key，不迁移订阅。

## 影响

- 额度和窗口天然连续，继续使用 Sub2API 原生计量。
- Sub2API 已提供受限的登记、暂停、排空、冻结、轮换与风险查询接口。
- 当前开通接口要求管理员提供既有 Group，在同一事务创建 Seat Principal、Subscription 和 API Key；
  Group 与运行账号的创建仍在管理员控制面完成。
