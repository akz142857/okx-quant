# OKX 量化交易系统

## 快速开始

```bash
# 交互模式（无参数启动向导）
uv run python main.py
```

## 命令行用法

```bash
# 查看行情
uv run python main.py ticker --inst BTC-USDT

# 策略回测
uv run python main.py backtest --inst DOGE-USDT --strategy bollinger --bar 4H --days 30

# 实盘交易 — 单币种
uv run python main.py live --inst DOGE-USDT --strategy bollinger --bar 4H --interval 10

# 实盘交易 — 多币种（逗号分隔）
uv run python main.py live --inst DOGE-USDT,PUMP-USDT --strategy ma_cross --bar 15m --interval 10

# 实盘交易 — 日志模式（不渲染仪表盘）
uv run python main.py live --inst DOGE-USDT,PUMP-USDT --strategy ma_cross --bar 15m --no-dashboard

# 查看可用交易对
uv run python main.py list-pairs

# 查看可用策略
uv run python main.py list-strategies
```

### 实盘参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--inst` | 交易对，多个用逗号分隔 | 必填 |
| `--strategy` | 策略名称 | `ma_cross` |
| `--bar` | K 线周期 | `1H` |
| `--interval` | 轮询间隔（秒） | `60` |
| `--no-dashboard` | 禁用面板，使用日志输出 | 关 |

### 多币种架构

单币种走 `LiveTrader`，多币种自动切换为 `Supervisor + Worker` 架构：

- 每个交易对一个 Worker 线程，独立运行策略和下单
- 共享同一个 `RiskManager`（线程安全），统一监控账户回撤
- `max_position_pct` 自动均分（如配置 0.95，2 个币种时每个 0.475）
- `max_open_positions` 自动设为币种数
- 主线程渲染多币种仪表盘，每秒刷新

### 策略说明

Bollinger — 有明确买入价位：下轨就是买入触发价。价格跌到下轨 + RSI<40 就买。

MA Cross — 没有固定买入价位。它看的是两条均线的相对位置，不是价格到某个点就买。买入触发条件是 EMA快线从下方穿越慢线（金叉），这取决于价格走势的动量，没法提前算出一个具体价格。

Dashboard 上看 差值 就行：
- 差值为负（快线 < 慢线）→ 等待金叉买入
- 差值由负转正 → 触发 BUY
- 差值为正（快线 > 慢线）→ 持仓中，等死叉卖出

简单说：差值越接近 0 且在收窄，离买入信号就越近。