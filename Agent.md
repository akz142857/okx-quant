# 多 Agent LLM 量化交易策略

灵感来自 TradingAgents 论文（Columbia University），通过多个专业化 AI Agent 协作辩论来产生更高质量的交易信号。

## 核心思想

传统 LLM 策略是"一个大脑做决策"，容易产生偏见。多 Agent 策略模拟的是**一个专业投资团队的工作流程**：

```
分析师各自调研 → 多空双方辩论 → 交易员拍板 → 风控审核
```

## 完整流程（每根 K 线触发一次）

### 第一步：4 个分析师并行分析（便宜模型，省钱）

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  技术分析师   │  │  情绪分析师   │  │  新闻分析师   │  │  基本面分析师  │
│             │  │             │  │             │  │             │
│ EMA/MACD/RSI│  │ 量价关系     │  │ 新闻标题     │  │ 成交量/流动性  │
│ 布林带/ATR   │  │ K线形态      │  │ 情绪倾向     │  │ 波动率环境    │
│ 趋势/动量    │  │ 买卖压力     │  │ 事件催化剂   │  │ 市场健康度    │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │                │
       └────────────────┴────────────────┴────────────────┘
                               │
                          4 份分析报告
```

- 并行执行（`ThreadPoolExecutor`），不互相等待
- 用 DeepSeek 等便宜模型，4 次调用成本约 ¥0.01
- 每个分析师只关注自己的专业领域，分析更深入

### 第二步：多空辩论（强模型，需要推理能力）

```
            Round 1                    Round 2
    ┌──────────────────┐       ┌──────────────────┐
    │  Bull: 基于4份报告  │       │  Bull: 反驳Bear    │
    │  构建看涨论点      │       │  补充新论据        │
    │                  │       │                  │
    │  Bear: 基于4份报告  │       │  Bear: 反驳Bull    │
    │  构建看跌/谨慎论点  │       │  强化风险警告       │
    └──────────────────┘       └──────────────────┘
```

- 2 轮辩论（可配置 `debate_rounds`），每轮 Bull 和 Bear 各发言一次
- Bear 能看到 Bull 的论点并针对性反驳，反之亦然
- **关键价值**：强制系统考虑正反两面，避免单一偏见

### 第三步：交易员综合决策（强模型）

```
输入：4份分析报告 + 完整辩论记录
                │
                ▼
    ┌──────────────────┐
    │     交易员 Agent   │
    │                  │
    │  权衡多空双方论点   │
    │  做出最终判断      │
    │                  │
    │  输出 JSON：       │
    │  {               │
    │    signal: BUY   │
    │    confidence: 0.8│
    │    size_pct: 0.5 │
    │    stop_loss: 3% │
    │    take_profit: 6%│
    │    reason: "..."  │
    │  }               │
    └──────┬───────────┘
           │
```

- 看到所有信息后做判断，不是简单投票
- 保守原则：证据不充分时倾向 HOLD

### 第四步：风控经理审核（安全门）

```
    ┌──────────────────┐
    │   风控经理 Agent   │
    │                  │
    │  检查：           │
    │  - 当前回撤水平    │
    │  - 仓位暴露       │
    │  - 置信度是否够高   │
    │  - 止损是否合理    │
    │                  │
    │  可以：           │
    │  ✓ 通过（保持信号） │
    │  ✓ 缩减仓位       │
    │  ✓ 收紧止损       │
    │  ✗ 否决 → HOLD   │
    └──────────────────┘
```

- 最后一道防线，只能收紧不能放松
- 风控 Agent 失败时系统自动降级为 HOLD

## 与单 LLM 策略对比

| | 单 LLM (`--strategy llm`) | 多 Agent (`--strategy multi_agent`) |
|---|---|---|
| 分析维度 | 一个 prompt 塞所有信息 | 4 个专家各聚焦一个维度 |
| 偏见控制 | 无 | 强制多空辩论，正反论证 |
| 决策质量 | LLM 一次性输出 | 分析→辩论→综合→审核，层层过滤 |
| 安全机制 | 置信度阈值 | 置信度 + 风控 Agent 双重把关 |
| 成本 | 1 次 LLM 调用/K线 | ~10 次调用/K线 |
| 适合周期 | 15m+ | 1H+（调用多，短周期太贵） |

## 成本控制设计

- 分析师用**便宜模型**（DeepSeek ¥0.001/千token），辩论+决策用**强模型**
- `max_total_tokens: 50000` 安全上限，超出自动中止返回 HOLD
- `confidence_threshold: 0.6` 低置信度不交易，减少无效操作
- 回测前显示费用预估，按双模型分别计算

## 使用方法

### 配置 `config.yaml`

```yaml
# 廉价模型 — 4个分析师并行调用，token 消耗大但单价低
llm:
  provider: "deepseek"
  api_key: "sk-your-deepseek-key"
  model: "deepseek-chat"
  temperature: 0.3
  max_tokens: 1024
  timeout: 60

# 强力模型 — 辩论 + 交易员 + 风控，需要强推理能力
llm_deep:
  provider: "claude"              # 或 openai
  api_key: "sk-ant-api03-..."     # 需要 API Key，不支持 OAuth 令牌
  model: "claude-sonnet-4-6"
  max_tokens: 2048
  timeout: 60

# 策略参数
multi_agent:
  debate_rounds: 2               # 辩论轮数，越多越贵但越充分
  confidence_threshold: 0.6      # 低于此置信度不交易
  analyst_timeout: 120           # 分析师超时（秒），需 >= llm.timeout
```

> 如果不配置 `llm_deep`，系统会用 `llm` 同一个模型跑所有 Agent。

### 回测

```bash
uv run python main.py backtest --inst DOGE-USDT --strategy multi_agent --bar 4H --days 7
```

### 实盘（终端仪表盘）

```bash
uv run python main.py live --inst DOGE-USDT --strategy multi_agent --bar 4H --interval 60
```

### 实盘（日志模式）

```bash
uv run python main.py live --inst DOGE-USDT --strategy multi_agent --bar 4H --no-dashboard
```

## 文件结构

```
okx_quant/agentic/
├── __init__.py          # 公共 API：AgenticPipeline, AgenticConfig
├── config.py            # AgenticConfig 配置数据类
├── agents.py            # 8 个 Agent 类（共享 BaseAgent 基类）
├── prompts.py           # 所有 system/user prompt 模板
├── pipeline.py          # AgenticPipeline：编排完整流程
└── token_tracker.py     # Token 用量跟踪（线程安全）

okx_quant/strategy/
└── multi_agent_strategy.py  # 薄封装：BaseStrategy → 调用 agentic pipeline
```

## 8 个 Agent 说明

| Agent | 模型 | 职责 |
|-------|------|------|
| TechnicalAnalyst | 便宜 | 分析 EMA、MACD、RSI、布林带、ATR 等技术指标 |
| SentimentAnalyst | 便宜 | 从量价关系、K线形态推断市场情绪 |
| NewsAnalyst | 便宜 | 评估新闻标题和情绪对市场的潜在影响 |
| FundamentalsAnalyst | 便宜 | 评估成交量、流动性、波动率等市场条件 |
| BullResearcher | 强力 | 构建最强看涨论点，反驳空头 |
| BearResearcher | 强力 | 构建最强看跌/谨慎论点，反驳多头 |
| TraderAgent | 强力 | 综合所有分析和辩论，输出交易决策 JSON |
| RiskManagerAgent | 强力 | 审核交易信号，可否决或缩减仓位 |

## 安全机制

1. **置信度阈值** — confidence < 0.6 → 自动 HOLD
2. **风控 Agent 否决** — 风险过高时降级为 HOLD
3. **风控失败兜底** — 风控 Agent 调用失败时保守返回 HOLD（不跳过风控）
4. **Token 预算上限** — 超过 `max_total_tokens` 自动中止 pipeline
5. **分析师超时保护** — 超时的分析师不阻塞其他已完成的分析师
6. **LLM 调用失败降级** — 任何 Agent 调用失败返回空结果，不会抛异常
