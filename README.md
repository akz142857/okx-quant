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

## 配置说明

复制 `config.yaml.example` 为 `config.yaml` 并填写：

```bash
cp config.yaml.example config.yaml
```

> **`config.yaml` 包含 API Key 等敏感信息，已在 `.gitignore` 中排除，请勿提交。**

### OKX API (`okx`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `api_key` | OKX API Key | 必填 |
| `secret_key` | OKX Secret Key | 必填 |
| `passphrase` | OKX Passphrase | 必填 |
| `simulated` | `true` 模拟盘 / `false` 实盘 | `true` |
| `base_url` | API 地址 | `https://www.okx.com` |
| `proxy` | HTTP 代理（可选，留空直连） | 空 |

### 风控 (`risk`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `max_position_pct` | 单笔最大仓位占总资产比例 | `0.5` (50%) |
| `max_drawdown_pct` | 最大回撤触发停止 | `0.15` (15%) |
| `stop_loss_pct` | 默认止损比例 | `0.02` (2%) |
| `take_profit_pct` | 默认止盈比例 | `0.04` (4%) |
| `max_open_positions` | 最大同时持仓数 | `1` |
| `min_order_usdt` | 最小下单金额 (USDT) | `1.0` |

### 日志 (`logging`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `level` | 日志级别 (`DEBUG` / `INFO` / `WARNING` / `ERROR`) | `INFO` |
| `file` | 日志文件路径 | `logs/quant.log` |

### 回测 (`backtest`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `initial_capital` | 初始资金 (USDT) | `10000.0` |
| `fee_rate` | 手续费率 | `0.001` (0.1%) |
| `slippage` | 滑点 | `0.0005` (0.05%) |

### LLM 配置 (`llm` / `llm_deep`)

`llm` 用于 AI 策略的分析模型（轻量），`llm_deep` 用于多 Agent 辩论+决策（强力模型）。

| 参数 | 说明 | 默认值 |
|---|---|---|
| `provider` | 模型提供商 (`openai` / `claude` / `deepseek`) | `openai` |
| `api_key` | API Key | 必填 |
| `model` | 模型名称，留空用提供商默认 | — |
| `base_url` | API 地址，留空用提供商默认 | — |
| `temperature` | 生成温度 | `0.3` |
| `max_tokens` | 最大 token 数 | `1024` / `2048` |
| `timeout` | 请求超时（秒） | `30` / `60` |

### 多 Agent (`multi_agent`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `debate_rounds` | 多空辩论轮数 | `2` |
| `confidence_threshold` | 低于此置信度 → HOLD | `0.6` |

### 因子选币器 (`screener`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `min_vol_24h_usdt` | 最小 24H 成交额 (USDT) | `500000` |
| `min_listing_days` | 最少上线天数 | `90` |
| `pre_filter_top_n` | 硬过滤后保留 top N | `30` |
| `bar` | K 线周期 | `4H` |
| `lookback` | 回看 K 线根数 | `100` |
| `corr_threshold` | 相关性去重阈值 | `0.85` |

权重参数（总和建议为 1.0）：`weight_adx` (0.30)、`weight_atr_pct` (0.20)、`weight_vol_ratio` (0.15)、`weight_roc` (0.15)、`weight_bandwidth_pctile` (0.20)。

### 新闻 (`news`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `auth_token` | CryptoPanic API token（可选，不填也能用） | 空 |