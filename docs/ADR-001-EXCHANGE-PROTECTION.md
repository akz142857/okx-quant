# ADR-001：使用独立 OCO/conditional 作为主保护

状态：Accepted（2026-07-27；官方契约复核：2026-07-27）

## 决策

生产路径采用“普通订单累计成交投影 + 独立 OKX OCO/conditional 保护单”。每次新增
成交按实际净持仓创建或 amend 保护数量；移动止损只允许收紧。任何创建/amend/cancel
响应丢失都先按 `algoClOrdId`/`algoId` 查询，不盲目重复。

## 原因

attached TP/SL 简化首次提交，但普通订单部分成交、保护数量变化、主动退出竞争、移动
止损和 ACK 丢失都仍需要独立状态机。独立保护路线能让保护单拥有永久本地 ID、乐观
版本、明确状态和完整审计链，也能在恢复时与 pending algo orders 联合对账。

## 后果

普通订单成交到 ACTIVE 保护之间存在短暂窗口，因此设置 10 秒 SLO，失败立即进入
`EMERGENCY_EXIT`。主动 SELL 必须先取得 exit lease 并取消/确认保护事实，保护触发优先。
`scripts/demo_contract.py` 先以真实成交净数量验证生产采用的独立 OCO 路线，再用
`tgtCcy=quote_ccy` 探测 attached 路线。独立 OCO 未 ACTIVE、attached 探测结果不明确、
或清理 SELL 未确认成交都会使契约失败；即使 attached 被证实支持，也不自动切换生产
架构。

2026-07-27 重新核对 [OKX API Guide](https://www.okx.com/docs-v5/en/) 后确认：

- `clOrdId` 只在当前 pending 订单中强制唯一，历史查询可能只返回最新匹配；
- `accFillSz` 是累计成交量，`fillSz` 是最近一笔成交量；
- `orders-algo` 首次订阅不推送初始快照，仍须 REST baseline；
- algo 查询、pending/history、cancel 和 amend 是独立接口；
- 保护数量和修改数量受 `lotSz` 约束，触发价格受 `tickSz` 约束；生产与 demo 路径
  均在发送前按相同规则量化；
- 通用参数错误 `51000` 不能证明 attached 能力不受支持，必须保持 probe
  `inconclusive`，不能把参数精度问题误写成能力结论。

attached 激活、现货余额冻结和 demo 环境具体拒绝码仍以生成的脱敏 contract evidence
为准，不能由官方字段说明代替真实演练。
