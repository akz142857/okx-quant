# 非实盘验证指南

本项目不要求直接用真实资金发现工程缺陷。推荐按以下顺序提升证据强度：

```text
离线确定性验证
    → 历史数据回测与压力测试
    → OKX Demo 只读诊断
    → OKX Demo 真实 API 契约测试
    → Demo Shadow/连续运行
    → 隔离预生产主机演练
    → 极小资金 Canary（最终仍不可由仿真替代）
```

前六层均不需要投入真实资金。它们可以验证绝大多数代码、恢复、风控、发布和运维
问题，但不能证明真实流动性、未来收益或生产人员是否会正确响应。

## 1. 一键离线验收

开发工作树可以运行：

```bash
uv sync --locked --dev
uv run python scripts/non_live_validation.py \
  --allow-dirty \
  --output non-live-validation.json
```

干净发布提交运行时不要使用 `--allow-dirty`：

```bash
uv run python scripts/non_live_validation.py \
  --output non-live-validation.json
```

脚本会把全部测试文件分成六个可审计 suite，覆盖：

- 订单状态机、响应丢失、幂等成交和并发资金预留；
- OKX adapter 与 demo 契约离线模型；
- SQLite、投影重建、WS replay、启动恢复和联合对账；
- 保护单、紧急退出、kill switch、备份恢复和 SLO；
- 回测、策略循环、研究溯源和准入抗伪造；
- 配置、脱敏、超时和证据工具自身。

报告绑定提交、Git tree、完整源码/测试 manifest、测试清单、Python 和操作系统。
CI 只接受干净提交生成的报告，部署 preflight 会再次验证。报告始终包含：

```json
{
  "assurance_scope": "offline_deterministic_only",
  "production_admissible": false
}
```

因此它不能被复制进生产准入 evidence 冒充真实 Demo 或人工审批。

如果文件已经存在，脚本拒绝覆盖；请保留旧报告或显式移动后重新执行。

## 2. 历史行情与压力验证

先做单策略回测：

```bash
uv run python main.py \
  --config config.yaml \
  backtest \
  --inst BTC-USDT \
  --strategy ma_cross \
  --bar 1H \
  --days 365
```

再执行网格和参数稳定性分析：

```bash
uv run python scripts/backtest_grid.py
uv run python scripts/backtest_analyze_alpha.py \
  --results backtest_results/results.csv \
  --candles backtest_results/candles
uv run python scripts/param_sweep.py \
  --from-grid \
  --top 5 \
  --min-sharpe 0.3
```

判断重点不是单次最高收益，而是：

- next-bar 成交、手续费和动态滑点后仍为正；
- walk-forward 的连续样本外窗口稳定；
- 参数附近形成连通稳定区域，而不是单点尖峰；
- 多策略共享现金后不产生隐式杠杆；
- gap、成交量下降和波动率放大场景未突破风险预算。

历史回测仍无法模拟真实订单簿排队和未来市场制度变化。

## 3. OKX Demo：无真实资金的交易所验证

OKX Demo 使用交易所真实 REST/WS 协议和模拟资金，是验证 adapter、字段、订单状态与
保护单行为的关键环境。必须使用单独申请的 Demo API Key，并确保配置同时满足：

```yaml
okx:
  simulated: true

production:
  environment: demo
  journal_path: state/demo/trading.db
  lock_path: state/demo/trading.lock
  backup_dir: backups/demo
  heartbeat_path: state/demo/heartbeat
```

先只读验证网络、时钟、行情和鉴权，不提交订单：

```bash
uv run python scripts/test_api.py \
  --config config.demo.yaml \
  --inst BTC-USDT
```

然后显式运行 Demo 契约。该步骤会使用模拟资金产生并清理订单：

```bash
uv run python scripts/demo_contract.py \
  --config config.demo.yaml \
  --confirm I_UNDERSTAND_DEMO_TRADES \
  --output evidence/demo-contract.json \
  --fixture-output evidence/okx-demo-contract-fixture.v1.json
```

只有真实 Demo 运行成功，才能确认当前 OKX 版本下的：

- 市价成交和累计成交字段；
- `clOrdId`/`ordId` 查询关系；
- lot/tick 精度；
- 独立 OCO/conditional 的 ACTIVE、amend、cancel 和清理行为；
- attached TP/SL 是否被明确支持或明确拒绝。

## 4. Demo Shadow 与连续观察

设置：

```yaml
production:
  environment: demo
  shadow_mode: true
```

再使用 Demo Key 启动 `live`。Shadow 会持久化策略决策和订单意图，但
`ExecutionCoordinator` 在交易所写调用之前将意图标记为
`SHADOW_NOT_SUBMITTED`。建议使用零持仓的专用 Demo 子账户，避免已有 Demo 仓位触发
无保护告警。

Shadow 适合比较：

- 信号频率和方向；
- 数据新鲜度、K 线去重及策略超时；
- 风控拒绝原因；
- 假设成交价格与后续真实行情；
- LLM 策略相对确定性策略的 A/B 增量。

Shadow 不产生真实成交，因此不能验证成交概率、真实手续费、滑点或保护激活延迟。
这些必须由 Demo 非 Shadow 运行补齐。

## 5. 隔离预生产主机

即使没有实盘资金，也应在与生产相同的 Linux/systemd 布局中验证：

- `okxquant-trader`、watchdog、backup 的权限隔离；
- SIGKILL、网络黑洞、只读数据库和 `SQLITE_FULL`；
- 外部 Page 接收与升级；
- S3 versioned 加密归档；
- 空主机恢复及 RTO；
- release SHA、非实盘 evidence 和 fault evidence 的部署前复核。

CI 生成的 `non-live-validation.json` 与 `fault-injection.json` 都会封入不可变发布包，
`scripts/verify_deploy.sh preflight` 会重新验证它们。

## 6. 非实盘验证不能替代什么

以下项目无论增加多少 FakeExchange 测试都不能诚实地标记为完成：

1. 真实盘口深度、市场冲击和极端行情成交质量；
2. 生产 API 权限、出口 IP 白名单和外部基础设施状态；
3. 连续 30 个自然日的稳定运行；
4. 操作人员对真实 Page、恢复和回滚流程的响应；
5. 独立风险审批和资金责任；
6. 极小资金 Canary 下的端到端生产事实。

所以非实盘阶段的目标是把技术未知量压缩到“交易所、时间、基础设施和人”四类，而
不是把仿真报告改名为生产准入。
