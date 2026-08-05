# 最小证伪实验：LLM 决策深度到底值不值钱

> 状态：**协议已冻结，待执行**
> 日期：2026-08-05
> 来源：[`docs/agentic-brain-roadmap-review.md`](agentic-brain-roadmap-review.md) §5.1
> 目的：在投入 `agentic-brain-roadmap.md` 的四步（合计约 20–35 人日）之前，用 3 天
> 回答一个前置问题——**现有 multi_agent 相对传统策略到底有没有增量价值。**

**这份文档的判定标准必须在跑实验之前冻结。** 跑完之后再调阈值、再换指标、再补
样本，等于把证伪实验变成确认偏误的仪式。改动本文任何"判定"小节，都要在
git 历史里留下改动理由和时间戳。

---

## 0. 为什么是这个实验，而不是 roadmap 的阶段 0

roadmap 阶段 0 要新建一个评估台（M 工作量）+ 人工挑选的场景集。但：

- `scripts/backtest_grid.py:92` 已有 `LLM_STRATEGIES = {"llm","ensemble","multi_agent"}`，
  `build_strategy()` 已会为 multi_agent 注入 `StrategyContext(llm_client, deep_llm_client)`
  ——**回放骨架已经存在**，缺的只是 LLM 缓存和几个决策级指标。
- 人工挑选的"趋势启动 / 顶部背离 / 震荡 / 黑天鹅急跌"场景集，标签**只有事后才能打**，
  挑段动作本身就注入未来信息，且人会不自觉地挑"结论清晰"的段落。5 币 × 365 天的
  **连续**样本天然覆盖这四种 regime，且没有挑拣自由度。

所以：**先用手边已经上膛的枪开一发，而不是先花 M 造一把能开枪的枪。**

---

## 1. 前置（已完成）

- ✅ `okx_quant/llm/cache.py` —— record/replay 缓存，key 含 provider/model/base_url/
  **temperature**/**max_tokens**/system/user；失败响应不落盘；原子写。
- ✅ `scripts/backtest_grid.py --llm-cache DIR` 接入。
- ⬜ `config.yaml` 需填入可用的 `llm.api_key`（本机当前为 0 字节）。

---

## 2. 执行

```bash
# 主轮：1D，5 个大/中市值币，1 年
uv run python scripts/backtest_grid.py \
  --strategies multi_agent,ensemble,adaptive,bollinger,ma_cross,trend_momentum \
  --instruments BTC-USDT,ETH-USDT,SOL-USDT,DOGE-USDT,LINK-USDT \
  --bars 1D --days 365 \
  --llm-cache state/llm_cache \
  --outdir backtest_results/min_experiment

# 高频段抽样：4H，2 个币，90 天
uv run python scripts/backtest_grid.py \
  --strategies multi_agent,ensemble,adaptive,bollinger,ma_cross,trend_momentum \
  --instruments BTC-USDT,ETH-USDT \
  --bars 4H --days 90 \
  --llm-cache state/llm_cache \
  --outdir backtest_results/min_experiment --resume

# 出 alpha
uv run python scripts/backtest_analyze_alpha.py   # 指向上面的 outdir
```

**成本控制**（这决定了实验是否真的"几天内可做"）：`MultiAgentStrategy.generate_signal`
**每根 bar 都会跑完整 8 agent 管线**，没有前置门控——这正是 grid 的
`DEFAULT_STRATEGIES` 把它排除在外的原因。所以必须锁在低频：

| 轮次 | 组合 | 决策数 | LLM 调用数 |
|---|---|---|---|
| 主轮 | 1D × 5 币 × 365 根 | 1,825 | ~14,600 |
| 抽样 | 4H × 2 币 × 90 天 | 1,080 | ~8,640 |
| 合计 | | 2,905 | **~23,000** |

全部走 cheap model（配置 `llm`，**不要**配 `llm_deep`，让 pipeline 用 quick 兜底），
量级在几十美元、一次性。加上缓存，重复跑免费。

---

## 3. 判定标准（**事前冻结，不许事后调**）

主指标：**`alpha_sharpe` = strategy_sharpe − hodl_sharpe**（`backtest_analyze_alpha.py` 已实现）。
用 HODL 调整后的口径，而不是原始 Sharpe——long-only 现货的原始 Sharpe 主要是 beta。

副指标（否决项）：`n_trades`、HOLD 占比、`llm_calls` / token 成本。

| 结论 | 条件 | 后续动作 |
|---|---|---|
| **PASS** | `multi_agent` 的 `alpha_sharpe` 在 **≥60% 的 (币, bar) 单元**上不低于**该单元最好的传统策略**，**且**扣除 token 成本后每决策期望收益 > 0 | 放行方案，但**仅**解锁「步骤 3 纯 prompt 改造」与「衍生品分析师」两项；其余仍等业绩 |
| **FAIL** | `alpha_sharpe` 中位数 ≤ 最好的传统策略，**或** HOLD 占比 > 85%（等于不决策）**或** < 20%（等于乱交易） | **整份 roadmap 归档**。`agentic/` 保持现状作为可选策略，全部资源转 Gate A + 传统策略研究 |
| **不确定** | 介于两者之间 | 只允许做步骤 3 的纯 prompt 改动，重测一次；仍不确定则归档 |

裁决人：仓库所有者。裁决时点：两轮 grid 跑完、`backtest_analyze_alpha.py` 出表当天。

---

## 4. 必须承认的局限（不能藏）

1. **回测拿不到历史新闻。** `scripts/backtest_grid.py:165` 明写"回测不接入新闻（历史
   新闻 API 无法获取）"，`data/news.py` 也只有"最新新闻"端点。所以这是对 LLM 决策
   价值的**下界测试**——它能干净地**证伪**"LLM 有 alpha"，不能完全证实。
2. **LLM 训练数据记忆泄漏未消除。** 模型语料包含这段历史。这个偏差的方向是**让
   multi_agent 显得更好**，因此：FAIL 的结论是稳健的（连作弊都赢不了），PASS 的结论
   必须打折。若结果是 PASS，下一步应做"真名 vs 匿名（价格归一化 + 剥离标的名与绝对
   时间轴）"的差分，量化泄漏幅度。
3. **非确定性未消除。** `temperature=0.3`，缓存冻结的是一次采样。本实验测的是单次
   采样表现；若结论落在临界区，需要同一输入跑 N 次报告分布（成本 ×N）。
4. **样本量。** 2,905 次决策听起来不少，但进入统计的是**交易数**不是决策数。出表时
   必须同时报告 `n_trades`；若某单元交易数 < 30，该单元的胜率/盈亏比不得用于判定。

---

## 5. 与 Gate A 的关系

本实验**纯离线、纯本地**，不碰 `okx_quant/agentic/` 的源码、不碰交易所写入路径，
因此**不改变发布身份、不重置 Gate A 的连续观察时钟**。它可以与 Gate A 的
Shadow 72h / Active 7d 完全并行。

反过来，roadmap 的四步**每一步都会修改 `agentic/`**，属于换冻结候选，会触发
provenance 重算、Linux CI 重跑、Demo contract v2 重采。这是"先做实验、后动代码"的
根本原因。
