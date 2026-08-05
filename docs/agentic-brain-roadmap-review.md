# Agentic 大脑升级方案 — 多 Agent 评审报告

> 评审对象：[`docs/agentic-brain-roadmap.md`](agentic-brain-roadmap.md)（提案日期 2026-08-04）
> 评审日期：2026-08-05
> 方式：5 个独立评审 Agent 并行，视角互不重叠
> **总结论：推迟（Defer）。四步整体不执行，只保留其中两小块。**

评审视角：

| # | 评审官 | 职责 |
|---|---|---|
| 1 | 代码现状核对 | 方案对自身代码的断言是否属实、集成点能否落地、引用物是否存在 |
| 2 | 量化交易有效性 | 有没有 alpha、信号价值排序、评估方法论 |
| 3 | 成本/复杂度/安全 | token 与美元账、延迟、外部故障点、注入面 |
| 4 | 方案质量/可执行性 | 内部一致性、验收可判定性、对标恰当性、缺失章节 |
| 5 | **该不该执行（Go/No-Go）** | 本次新增的一条：只回答方案是否应当被执行 |

---

## 一、结论：该不该执行

**推迟。** 理由不是方案质量差——它的依赖图清晰、自带自我证伪红线、明确拒绝了"加 Agent 凑深度"和"抄 DCF"这两个显而易见的坑。问题是**时机**。

### 1.1 项目真实阶段（证据）

| 事实 | 证据 |
|---|---|
| 系统从未产生过一笔决策 | `state/demo/trading.db`：`decisions` / `order_intents` / `order_events` / `fills` / `positions` / `realized_pnl_events` / `account_snapshots` / `probe_runs` **全部 0 行**；`system_state.mode = halted`，`mode_reason = journal_initialized_halted` |
| 从未成功跑过一次循环 | `logs/quant.log` **0 字节**；本机 `config.yaml` **0 字节** |
| 上线验证未点火 | `docs/GATE_A_EXECUTION_CHECKLIST.md`：Shadow **0/72h**、Active **0/7d**、核心 Chaos **0/6**、Linux 实机 preflight PENDING、Demo contract v2 RE-RUN REQUIRED |
| 官方准入结论 | `docs/DEMO_SHADOW_REMAINING_TASKS.md`：**NOT_ADMITTED / EXTERNAL OPEN**，12 项剩余任务，P0-03 仍为 PARTIAL |
| 连传统策略都没有业绩 | `docs/PRODUCTION_COMPLETION_AUDIT.md` §16："尚无获批策略的正 OOS、完整周期、平台区、滑点和压力损失证据"；全盘无 `*.parquet`、无 `backtest_results/` → **网格回测从未跑过** |
| 项目自己已点名正确的前置动作 | `docs/PROJECT_EVALUATION.md`：LLM 策略可信度 **5.5/10（全表最低）**，注明"必须独立 shadow A/B 证明增量价值" |
| git 重心是最后一刻转向 | 最近 15 个 commit 集中在上线验证，`5aef4c7 fix: close interrupted validation gaps` 后停滞 4 天，随后单个 commit 一次性塞入 `ai-berkshire.md` + `agentic-brain-roadmap.md` 并改动 `agentic/pipeline.py` |

方案 §0 的"核心判断"（输入太薄 / prompt 太泛 / 决策冷启动）**没有任何运行数据支撑**，是纯代码阅读推断。在 `decisions` 表为 0 行的系统上论证"决策深度不够"，是在没有地基的地方加楼。

> 边界说明：`logs/` `state/` `evidence/` 均在 `.gitignore` 内，以上只反映本机（开发机）。但文档层面的权威声明（NOT_ADMITTED、Gate A 全 PENDING、§16 量化准入 OPEN）与本机现象互相印证。

### 1.2 隐含前提核对

| 方案的隐含前提 | 是否满足 |
|---|---|
| 执行系统已稳 | ❌ Gate A 全项 PENDING，`mode=halted` |
| 现有大脑跑过真实环境、能观察到"深度不够" | ❌ `decisions` 表 0 行 |
| 传统策略基线已站住、LLM 是增量 | ❌ §16 量化准入 OPEN，grid 从未产出结果 |
| multi_agent 已被证明优于传统策略 | ❌ 且从未测过（`backtest_grid.py:69` 注释主动排除） |
| 步骤 4 有"历史可学" | ❌ **硬性不成立**：`fills`=0、`realized_pnl_events`=0 → `memory.recall` 永远返回空集 |
| 改 `agentic/` 不影响发布流程 | ❌ 改动 = 换冻结候选 → 重算 provenance、重跑 Linux CI、contract v2 重采 |
| 阶段 0 需要从零建（M 工作量） | ⚠️ 部分为伪，见 §2.1 |
| AI Berkshire 是合适的北极星 | ❌ 见 §3.3 |

**8 条前提，7 条不成立。**

### 1.3 两条硬阻塞

**步骤 4 物理上不可能。** 记忆闭环要求"平仓时给 thesis 打盈亏结果"，而 `fills` = 0。即使 Gate A 的 Active 7d 跑完，也只有 7 个 5–10 USDT 探针样本。按"同标的 × 同 regime"分格检索（约 3 regime × 3 标的 = 9 格，每格需 ~30 样本）需 **9–12 个月**；而币圈一轮完整周期是 12–18 个月——当记忆终于有统计意义时，它描述的已是一个不再存在的市场。

**动 `agentic/` 会重置 Gate A 的日历时钟。** `DEMO_SHADOW_VALIDATION_PLAN.md` 写明"任何发布身份变化或硬门槛失败都会延长"；`IMPLEMENTATION_STATUS.md` 要求发布身份绑定"实际导入源码"。Gate A 需 8–10 周日历时间，四步 = 至少四次清零。

### 1.4 反方最强论证与回应

| 反方 | 回应 |
|---|---|
| **Gate A 瓶颈是日历时间不是人力，等待窗内并行做大脑升级不冲突** | 在本项目的证据规则下不成立：改 `agentic/` = 换冻结候选 = 往一个用日历计时的进程里持续注入重置。且"人力闲着"是伪命题——Gate A 还有 15–25 人日工程补齐，以及一整套从未运行过的量化研究工具 |
| **方案自带 kill switch（阶段 0 不可跳过 + "Δ 不正向就砍"）** | 这是方案最值得尊敬的地方，也是保留 `llm/cache.py` 的原因。但 kill switch 要在 M 工作量之后才拿到手，而同样 80% 的证伪结论用**现成的** `backtest_grid.py` 3 天就能拿到。是**定价错了**，不是方向错了 |
| **先升级再点火，Gate A 才不用重跑** | 倒因为果：Shadow 72h **本来就不产生交易**（只读、零交易所写入），Active 7d 只是每天一个 5–10 USDT 探针。**Gate A 验证的是执行系统，不是大脑**——升不升级大脑对它的证据价值毫无影响，反过来却会重置它的计时 |

---

## 二、方案自身的硬伤

### 2.1 对自身代码的描述不可信（可信度：中偏低）

| 断言 | 判定 | 证据 |
|---|---|---|
| §1「`backtest/`、`backtest_grid.py` 未覆盖 LLM 策略」 | **不实** | `scripts/backtest_grid.py:92` `LLM_STRATEGIES = {"llm","ensemble","multi_agent"}`；`build_strategy()` 注入 `StrategyContext(llm_client, deep_llm_client)`；`main.py:266` 有 `_confirm_llm_backtest` 费用预估、`main.py:282` 有 `_print_llm_usage`。真实情况只是 `DEFAULT_STRATEGIES`（`:69`）默认不含它们 |
| §1「`data/market.py` REST→DataFrame」 | 不完整 | `market.py:181/199` **已有** `get_orderbook()` / `get_spread()`——步骤 1「微观结构分析师 🟡」的数据层已落地大半 |
| 步骤 2「复用 `financial_rigor.benford`」 | **不成立** | 该文件只在 `project_examples/ai-berkshire/tools/financial_rigor.py`，而 `git status` 显示 **`?? project_examples/`（未纳入版本控制）**；真名是 `benford_check`（`:227`），是 argparse 子命令、结果 print 到 stdout，**不可 import**。import 它还会破坏 `docs/SECURITY.md` 要求的"身份含实际导入源码摘要" |
| 交付路径 `tools/market_rigor.py` | **不存在** | 本仓库无 `tools/` 目录；惯例是 `scripts/`（70+ 文件），`pyproject.toml:31` 只打包 `okx_quant*` |
| 阶段 0 对标 `report_audit.py` | **不存在** | 同样只在 `project_examples/` |
| `tests/test_financial_rigor.py`（风格对标） | **不存在** | 同上 |
| L117「对标 AI Berkshire 决策终章'赔率思维收尾'」 | **查无此文** | `docs/ai-berkshire.md` 全文无"赔率""决策终章" |
| L113「段永平必问生意变好变差」 | **查无出处** | 被引文档只提到 `dyp-ask` 与 business-analyst 角色（"芒格必做逆向"有出处，`ai-berkshire.md:145`） |
| 步骤 1「衍生品 🟢 OKX 原生、好接」 | 部分不实 | funding/OI 是**永续合约**数据（`-SWAP`），全链路是现货；`client/rest.py` 全文仅 `public/time`、`public/instruments`，**无任何 funding/OI 封装**；`exchange/base.py` Protocol 也无。且大量中小市值现货无对应永续，方案未给缺失路径 |

✅ 确实存在且可复用的：`_wrap_untrusted`（`strategy/llm_strategy.py:52`）、`tests/test_agentic_hardening.py`、`strategy/adaptive.py:72` `_detect_regime`、`data_quality` ceiling 机制、`docs/ai-berkshire.md` §11–§11.5。

### 2.2 集成点落不了地

方案给的"骨架不动，只在并行组加 task"片段无法直接使用：

- `deriv_metrics` 不在 `_run_analysts(self, indicators, recent_candles, inst_id, news_text)`（`pipeline.py:215`）作用域内 → 需穿透 4 层签名（`run()` `pipeline.py:74` → `_run_analysts` → wrapper `multi_agent_strategy.py:174`）。
- **`_DISPLAY_NAMES` 按 `fn.__name__` 硬编码**（`pipeline.py:223`）：只加 task 不更新此 dict，超时/异常路径的 key 会退化成 `_derivatives`，与成功路径的 `"Derivatives Analysis"` 不一致 → `analyst_reports` 出现两套 key，污染 `build_debate_prompt`/`build_trader_prompt` 的小节标题与 thesis evidence 键。
- **`max_workers=4` 写死**（`pipeline.py:244`）：8 个分析师仍只有 4 并发。
- **`as_completed(futures, timeout=timeout+5)` 是所有 future 的共享墙钟**（`pipeline.py:247`），而 `future.result(timeout=timeout)` 才是单个的。任务数 > `max_workers` 时排队时间计入共享预算：8 分析师 / 4 worker 最坏需 2×timeout，共享预算却只有 timeout+5 → **后半批必然被判「分析师超时」，即使每个 LLM 调用本身都没超时**。

### 2.3 阶段 0 这个地基不成立

**致命级：**

1. **LLM 训练数据记忆泄漏（方案完全没提）** — 模型训练语料包含这段历史本身及其事后复盘。fixtures 又专挑"黑天鹅急跌"这类高辨识度片段 → 模型可能在**回忆**而非推理。污染程度随标的知名度非均匀（BTC/ETH 严重、小市值轻微），因此连"同一集内相对 Δ 比较"都不成立。**`docs/Research LLM quantitative trading.md` 第 5 条已自行点名前视偏差**，方案没有回应自己收集的文献。
   缓解方向：评估窗口取模型 cutoff 之后；价格归一化到相对刻度、剥离标的名与绝对时间轴；用合成路径作对照组；对同批片段做"真名 vs 匿名"差分来量化泄漏幅度。

2. **新闻/外部源缺失 point-in-time 快照** — `data/news.py` 只有 `get_news(coin, limit)` 打最新端点、5 分钟内存缓存，**无任何按历史时间点查询能力**。回放 2024-03 时 NewsAnalyst 拿到的是**今天的新闻** → 这不是偏差，是直接的未来信息注入，且 NewsAnalyst 是现有 4 分析师之一，**baseline 本身就被污染**。`llm/cache.py` 只缓存 LLM 响应，不解决输入侧时点一致性。
   `scripts/backtest_grid.py:165` 早已记录同一个坑："回测不接入新闻（历史新闻 API 无法获取）"，方案未引用。

3. **样本量低于统计功效一个数量级** — 乐观按 2000 bar 决策、现有 60%+ HOLD 率 → 实际约 50–150 笔完整交易。要在 α=0.05 / power=0.8 下检出胜率 45%→50% 需**每组约 1500 笔**；100 笔时胜率 95% 噪声区间约 **±10pp**。方案计划做 ≥8 次 Δ 检验（4 分析师 + 3 项框架化 + 逆向 Agent + 记忆），零假设下出现至少一个"显著改善"的概率 ≈ **34%**，而**无任何多重比较修正**——`docs/PROJECT_EVALUATION.md` §四.2 已明确要求"多重比较修正或 Deflated Sharpe Ratio"。

4. **数据源与"历史回放"物理不兼容** — 订单簿深度（`/api/v5/market/books`，`client/rest.py:531` 即快照调用）**根本没有历史快照**；funding/OI 是当前值接口；链上历史需付费 provider。→ 4 个新分析师至少 3 个**在物理上无法通过方案自己写的验收门**，而红线又不许不过门就合入 → **自锁**。

**严重级：**

5. **评估集过拟合，record/replay 是它的加速器** — "同一评估集零成本重复跑"正是研究者过拟合的最优基础设施；prompt 自由度极高，本质是在百笔样本上做无限次搜索。且场景标签（趋势启动/顶部背离/震荡/黑天鹅）**只有事后才能打**，挑段动作本身注入未来信息。方案无 dev/holdout 划分。
6. **LLM 非确定性未处理** — `temperature=0.3`（`llm/client.py:28`），缓存把它冻结成**一次采样**；测的是"某次采样的表现"而非期望。`PROJECT_EVALUATION.md` §四.4 要求的"多次重复运行后的决策一致性"与缓存的省钱目的直接冲突，方案未面对。
7. **指标全是决策级、无组合级、无基准** — 无净值/Sharpe/最大回撤/换手率；无 vs HODL、vs 传统策略、vs 永远 HOLD 三条基准。而 `scripts/backtest_analyze_alpha.py` 的整个存在意义就是做 alpha_sharpe = strategy_sharpe − hodl_sharpe，阶段 0 却退回到更原始的水平。
8. **执行假设可能与 `BacktestEngine` 不一致** — 引擎约定严谨（第 i 根收盘生成信号、第 i+1 根开盘成交、滑点作用于开盘价、同 K 线内 SL/TP 双命中保守假设先止损）。若 `agentic_eval.py` 另起炉灶算"每决策期望收益"，几乎必然系统性乐观。

### 2.4 内部矛盾

| # | 矛盾 | 行号 |
|---|---|---|
| M1 | **排期表成环**：序 4「步骤1 其余分析师」前置=步骤2，序 5「步骤2」前置=步骤1，且与依赖图 `步骤1 → 步骤2` 矛盾 → 拓扑不可排。根因是 L107「要有多源输入才谈得上交叉」过强——`cross-exchange` / `volume-anomaly` 只需现有 K 线 + 外部所 ticker，与步骤 1 无关 | L144-147 vs L149-156 |
| M2 | **步骤 3 标题与内容自相矛盾**：标题"只改 `prompts.py`，不加 token 成本 / S"，正文却"**新增**逆向 Agent…放在辩论层（**strong model**）"。而辩论层全走 `deep_llm`（`pipeline.py:69-72`）。同时违反 §0 自立的"❌ 不加 Agent 数量凑深度"，也与 L162"每加一个分析师都增 token"互斥 | L111/L113 vs L116 |
| M3 | **多处退回"靠 prompt 自觉"，违反 L20 自立的"用代码钉死"**：① L115 让 LLM 在 prompt 里判 regime，而 `adaptive.py:72` `_detect_regime` 已是确定性实现；② L117 让 LLM 在 `reason` 里"给出赔率判断"，而 R:R 是算术且 SL/TP 由 `RiskManager` 已算出——直接撞上 `ai-berkshire.md:206`"永远不让 LLM 输出参与到最终下单量的算术里"；③ L164 用"标注历史不代表未来"防过拟合 | L20 vs L115/L117/L164 |
| M4 | **`memory.recall(inst_id, regime, k)` 无 `as_of` 时间围栏**，而结果标签由未来平仓写入 → 回放中必然把未来盈亏泄漏进过去决策，"带记忆更准"100% 是伪的 | L130 vs L135 |
| M5 | **步骤 4 依赖对象点错**：写"依赖步骤1（regime 标签）"，但 regime 标签是**步骤 3**的交付物 | L137 vs L115 |
| M6 | **门禁两套口径**：L49/L162"Δ 不正向就砍"（要求 Δ>0）vs L87"正向**或至少不劣化**"（允许 Δ≥0，在噪声指标上等价于永远能过） | L49/L87/L162 |
| M7 | **LLM 缓存 key 不含 temperature/max_tokens**，且步骤 1/2/3/4 每一步都改 prompt，一改就整体击穿缓存——"零成本重复跑"只在同一 prompt 版本内成立，而跨版本恰恰是唯一有意义的对比场景 | L44 |
| M8 | **步骤 4 缺"对应"的钩子**：`ThesisStore.save()` 返回的 path 被 wrapper 丢弃（`multi_agent_strategy.py:254`），持仓与 thesis **无任何 ID 关联**；落点选的 `position_monitor.py` 只持有 `_sell_fn(reason)`，**不知道 PnL**（实际在 `executor.py:252`）；`regime` 字段不在 `THESIS_SCHEMA` v1 内 | L129-130 |

### 2.5 验收标准可判定性

10 条验收里 **只有 2 条完全可判定，5 条完全不可判定**。共同缺陷：没有阈值、没有样本量、没有显著性定义、没有裁决人与裁决时点。典型：

- 「不改善就砍」— 无阈值、无样本量、无显著性、无裁决人、无时限。
- 「胜率/盈亏比需正向**或至少不劣化**」— "不劣化"无容差，等价于永远能过；且与 L162 冲突；两个指标一升一降时未定义仲裁。
- 「逆向 Agent **应提升**"顶部/急跌段"的 HOLD 命中，**降低接盘**」— "顶部/急跌段""HOLD 命中""接盘"全部未定义，无幅度，无副作用约束（靠"全 HOLD"即可刷分）。
- 「验证"带记忆 vs 冷启动"的**决策一致性**」— 一致性高说明记忆没起作用、低说明改变了决策，两者都无法判定好坏。
- 「在评估台用**样本外数据**验证」— 样本外集合从未在交付物中定义，且方案要求所有步骤都在"同一集"上比 Δ。

---

## 三、量化有效性

### 3.1 前提链的四个断点

1. **long-only 现货结构性截断收益** — 决策空间只有 {持币, 部分仓位, 空仓}；下跌行情最优解是空仓，而**空仓收益上限是 0**。所以"深度"的真实回报函数是"把最大回撤从 -60% 压到 -30%"，不是"收益翻倍"。方案给的四个分析师里有三个（挤仓、流动性、链上流出）本质是**风险规避型**信号——它实际在做防守型 alpha，却用"深度→收益"的叙事包装，导致优先级与验收标准都对不上目标。
2. **15m–4H 尺度信噪比硬限** — 该尺度价格变异主体来自流动性冲击与订单流，LLM 的核心优势（跨源综合、叙事理解）**没有承载物**。方案移植了框架，没有移植时间尺度。
3. **成本端未进 ROI 计算** — 阶段 0 指标里 `token/决策` 是孤立数字，没有和收益放在同一分母上。真正的门槛应是 **LLM 成本 / 策略毛利**。
4. **管线已高度保守，加深度最可能的结果是 HOLD 率单调上升** — `pipeline.py` 的机制全部单向收紧（数据质量天花板、BUY 置信度门、`min(交易员,风控)`、token 超限 abort、分析师超时填"调用失败"）。再加 4 个可能说"数据不足"的分析师 + 一个专职找茬的 pre-mortem + 一个只会回忆亏损的记忆模块 → HOLD 率上升 → 交易数下降 → 样本更少 → 更难验证 → 记忆积累更慢，自我强化的死循环。

**链条成立的条件**：目标改为明确的"降低回撤/规避崩盘"并以 alpha_sharpe/最大回撤验收；时间尺度上移到 4H–1D；决策改为事件驱动而非每 bar；先证明非 LLM 部分有样本外 alpha。

### 3.2 四类分析师价值排序

| 分析师 | 信号领先性 | 与现有指标冗余 | 时间尺度匹配 | 结论 |
|---|---|---|---|---|
| **催化剂日历** | **强**（唯一结构性领先：解锁日期提前数月公布、上币公告有时间戳、升级绑定区块高度） | **零冗余** | 好但形态特殊：是"距下次事件 T-N"的日历状态，可低频拉取 + 长缓存，token 成本近乎为零 | **alpha 密度最高**，方案排第 4 是排序错误。正确形态是**代码硬规则**（大额解锁前 48h 禁开新仓），不是 LLM 分析师——这样可直接用 `BacktestEngine` 验证 |
| **衍生品** | 中，且 funding 是**拥挤度不是方向**（极端正 funding = 多头拥挤 = 回调风险，反向信号）；预测力集中在极值区间 | **低**（四者最低，杠杆结构是 K 线看不见的独立维度） | 中等偏弱：OI 5m 粒度尚可，funding 8h 结算——15m bar 上 96 次决策中 funding 只提供约 3 bit 新信息 | **值得做，但只在 1H/4H 上**，且做成百分位/状态标签而非原始数字 |
| **微观结构** | 秒–分钟级强，其他尺度为零（订单簿不平衡半衰期通常 < 1 分钟） | **高**：其用途"流动性真伪/能否进出"与 `screener` 的成交量硬过滤、production 层 `max_spread_ratio`/`max_slippage_ratio` 功能重叠 | 严重不匹配 | **不值得做成分析师**。"价差+深度"作为**执行前置检查**有价值，且 production 层已有雏形——把确定性的执行成本约束错放到 LLM 推理层是层次错配 |
| **链上** | 弱且不稳定（交易所净流入学术结论摇摆，大额转账常是内部再平衡；稳定币供应是月级，活跃地址周–月级） | 高共线（数据可得时价格通常已反应完） | 灾难性不匹配：区块确认 + provider 索引 + 聚合窗口 = 10 分钟到数小时延迟，免费源多为小时/日级；**且是唯一存在"历史重述"风险的源**（provider 事后修正 → 隐性 look-ahead） | **不值得做**。"先做接口后接源"尤其危险：会诱导后续为填满接口而接入低质源 |

**排序：催化剂 ≳ 衍生品 ≫（执行层价差/深度检查）> 微观结构分析师 > 链上。**

关于"先做衍生品"：**方向可接受，但理由错、形态错。** 方案给的依据是"数据 OKX 原生、好接"——这是工程可行性理由不是 alpha 理由，而同一依据会继续把同样"好接"的微观结构排到前面。形态上，funding/OI 是纯数值、有明确阈值、可直接回测的信号，是四者中**最应该硬化**的一个，方案却做成了最软的形态。正确顺序：先做确定性过滤器（`funding_percentile > 95 → 禁止 BUY`），用 `backtest_grid.py` 验证是否提升 alpha_sharpe，通过后再考虑喂给 LLM——这条路径不烧一分钱 token 就能得到统计上可信的答案。

### 3.3 对标失效点

1. **循环论证** — `ai-berkshire.md:173` 白纸黑字："单账户、无第三方审计、样本仅两年、框架成型时间与业绩期高度重叠……**作为方法论有效性证据不充分**"。而本方案 L11 开篇即以"AI Berkshire 之所以强"为不证自明的前提。同一作者在两份文档里对同一对象给出互斥的证据评级。
2. **时间尺度失效** — 价值投资的产出是报告/论点，对错 5–10 年才见分晓，所以 AI Berkshire 的质量主张自始至终是**过程性的**（结构一致、强制结论、内置反偏见、可复盘），它从不声称"能提高胜率"。本方案却把过程性方法论绑死在**结果性门禁**（胜率/盈亏比 Δ）上。
3. **逐条判定方案自认可移植的三样东西**：
   - **四大师硬框架** — 大部分不可移植。它的"硬"来自判据内容跨周期成立；币圈短周期无等价稳定判据，落地后只剩"多写几段 prompt"，正好生产 `ai-berkshire.md:146` 警告的"与市场一致的正确的废话"。**可移植的是形式**（强制结论、固定输出结构、快速否决清单），**不可移植的是判据本身**。
   - **事前尸检** — 方法可移植，但成本与必要性都没算清。价值投资一年几十次决策，本仓库每 bar × 每标的都跑，是**乘以决策频次的常驻成本**。且 pipeline 已有 Bear 分析师 + 多空辩论，方案断言"补上辩论没覆盖的事前尸检"却未做论证——更便宜的等价方案是**改写 Bear 的 system prompt**（这才是真正的"只改 prompts.py"）。
   - **赔率思维** — 最不可移植，且方向搞反。本仓库的赔率是**可精确计算的量**，让 LLM 在 `reason` 里"给出赔率判断"正是明令禁止的"让 LLM 做算术"。正确形态：代码算 R:R、代码卡门槛（如 R:R < 1.5 直接拒绝），LLM 只提供概率的定性输入。
4. **选错移植优先级** — `ai-berkshire.md:139-151` 的八条反偏见清单才是真正可转移的资产，其中三条 §11.5 已实施；**最便宜且直接抓幻觉的一条——"指标复算抽检"（`ai-berkshire.md:208`：对 LLM 引用的技术指标值随机抽取、用 `indicators/cache.py` 复算比对，不一致则否决该信号）被完全漏掉**；方案反而把 80% 权重压在最贵、最依赖外部源、历史数据最不可得的"输入多源化"上（L57 自称"拿到 ~80% 的深度提升"，无任何依据）。

### 3.4 步骤 4 记忆闭环（单独结论：当前形态弊大于利）

- **样本量算术**：4H bar、1–3 币 → 每天 6–18 次决策；置信度门 + 数据质量天花板下 BUY 率乐观 5–15%；且必须平仓才有标签 → 乐观每天 1–2 个"决策+结果"对，实际可能每周几笔。9 格 × 30 样本 = 9–12 个月。
- **近因偏差的机械放大**：k=3–5 时回喂的是极少数样本的具体叙事。给 LLM 看"你上次在类似情形买它，-8% 止损"，它几乎必然降低这次置信度——不管这次是否真的不同。
- **幸存者偏差（方案完全没意识到）**：只有**开过仓**的决策才有结果标签，所有被拦为 HOLD 的决策没有反事实结果 → 记忆库是"只包含买了之后发生什么"的有偏样本，用它调整"要不要买"是系统性错误。修正在技术上是免费的（回看后续 K 线即可算"假设当时买了会怎样"），方案没提。
- **路径依赖**：记忆影响决策 → 决策产生新记忆 → 自我强化，无 exploration、无记忆衰减、无对照组。
- 若一定要做，唯一低风险的版本：喂**聚合统计**（"你在震荡 regime 的 BUY 历史胜率 38%，n=27"）而非具体案例——聚合统计不触发叙事性近因偏差，且能诚实携带样本量；并同时记录 HOLD 的反事实收益。
- 方案把这一步标为"差异化，能反超 AI Berkshire"——这是**用差异化叙事驱动技术决策**而非 ROI。它在依赖链最末端、样本量要求最高、失效模式最隐蔽，理应优先级**最低**。

### 3.5 被忽略的更高 ROI 方向

共同优势：可用现有 `BacktestEngine` + `backtest_grid.py` 直接验证，不需要 LLM 调用、不需要新数据源、不受记忆泄漏污染——**结论可信**。

| 方向 | 说明 |
|---|---|
| **A. 市场状态过滤（熊市停手）** | long-only 最大杀伤源是趋势性下跌。BTC 主导趋势开关（BTC < 200D SMA → 只允许 SELL）是几十行代码、可完整回测，历史上对 long-only 组合的 Sharpe/最大回撤改善通常**大于任何入场信号的改进**。现状缺口明确：`RiskManager` 只有**事后**的 `max_drawdown_pct: 0.15` 停盘，没有**事前**的 regime 开关。这恰好能实现步骤 3 想要的效果，完全不用 LLM，且可被统计证明 |
| **B. 组合级回测 + 放开多品种** | `PROJECT_EVALUATION.md` §四.1 已指出"单资产结果不能证明组合实盘有效"并给出方案。而 `max_open_positions: 1` 意味着系统**主动放弃了分散化**——对一个已有 `Screener`（含 corr 去重）和 `Supervisor`（多 worker 共享 RiskManager）的系统，这是把已建好的基础设施闲置。分散化是金融里少数几个免费午餐 |
| **C. 仓位管理 / 分数凯利** | `RiskManager.calc_position_size` 现在是 `available_usdt × min(size_pct, 0.5)`，而 `size_pct` **来自 LLM**——已经违背 `ai-berkshire.md:206`。改进方向是纯确定性代码：基于回测胜率/盈亏比做 1/4 Kelly + 波动率倒数缩放。对 long-only，**仓位规则对最终几何收益率的影响通常大于入场信号质量** |
| **D. 执行成本优化** | 一次往返 0.3%。可做且确定性：市价单→限价挂单；**bar 边界对齐**（`PROJECT_EVALUATION.md` §五已指出 `interval_seconds` 与 bar 边界未对齐，同一根已完成 K 线被重复计算，"策略内部状态和 **LLM 成本**仍可能重复发生"——这是**正在发生的 token 浪费**）；最小持仓时间约束 |
| **E. 参数稳健性 / walk-forward** | `scripts/param_sweep.py` **无任何 train/valid 划分**，`backtest_grid.py` 也是全样本跑。`PROJECT_EVALUATION.md` §四.2 已写好完整 walk-forward 方案（训练 12 月 → 验证 3 月 → 前滚）与 Deflated Sharpe 要求，尚未实施。**在还没证明传统策略有样本外 alpha 之前投入 LLM 深度是本末倒置**——若底层 alpha 本身是过拟合假象，届时你无法区分"LLM 深度没用"和"底层就没 alpha" |
| **F. Shadow mode A/B** | `PROJECT_EVALUATION.md` §四.4 已建议"传统策略真实执行，LLM 只记录建议"。此法在方法论上**严格优于**历史回放：无记忆泄漏（决策发生在 cutoff 之后）、天然 point-in-time、真实执行成本、真实非确定性。唯一代价是慢。`config.yaml.example` 里已有 `shadow_mode` 开关。方案选了快但结论不可信的路径，放弃了慢但结论可信的路径，且**未说明为什么** |

---

## 四、成本、延迟、故障点与安全

### 4.1 成本账

用真实 prompt 构建函数实测（DOGE-USDT + 20 根 K 线 + 5 条新闻，~4 字符/token）：现状 **10 次调用**（4 cheap + 6 strong）/ ~20.5k token / **$0.089 每决策**；四步完成后 **15 次** / ~41.8k / **$0.153**（1.7×）。

成本结构的关键是**辩论层的平方级重发**：分析师报告（~1,650 tok）被 Bull/Bear 各重发 2 轮 = 4 次、再被交易员重发 1 次，共 5 次；辩论记录（~2,800 tok）再被交易员重发一次。token 不随 Agent 数线性增长，而是随"分析师报告体积 × 下游 strong 调用数"增长。strong 模型占 token 83%、**占钱 98%**。

按 `--screen 5`、`production.enabled: true`（每根收盘 K 线一次决策）：

| bar | 决策/天 | 现状/月 | 完成后/月 |
|---|---|---|---|
| 4H | 30 | $81 | $138 |
| 1H | 120 | $324 | $551 |
| 15m | 480 | $1,296 | $2,204 |

**若 `production.enabled: false`**（K 线去重消失，按 `--interval` 每 60s 跑一次）：7,200 决策/天 → 现状 **$19.4k/月**，完成后 **$33k/月**。唯一挡住这个的是生产内核开关，不是策略层。

对照 `config.demo.yaml`：`max_position_notional_usdt: 2000`、`max_total_exposure_usdt: 5000`、`max_daily_loss_usdt: 250`、`max_open_positions: 1`（账户 $2k–5k，同时最多 1 个仓位）：

- 1H/5pair/完成后：$551/月 ÷ $5,000 = **11%/月 ≈ 132%/年的 AUM**；4H 档 33%/年；**即使现状 4H 也是 19%/年**（顶级对冲基金管理费 2%/年）。
- 单笔满仓止盈 $2,000 × 4% = $80 毛、扣费约 $74 净。1H 档一天推理费 $18.4 = **一笔满仓盈利单净利的 25%**；15m 档 $73/天 ≈ **每天必须打满一笔盈利单才够付模型钱**，且是 `max_daily_loss_usdt: 250` 的 **29%**——但它不进任何风控账。
- `max_open_positions: 1` 意味着 5 个 pair 的分析最多兑现 1 个仓位：**5 倍分析成本换 1 倍执行容量**。

### 4.2 延迟

| 阶段 | 典型 | 硬上限 |
|---|---|---|
| 4 分析师（并行 4） | 5–12s | 30s（`llm.timeout`） |
| 辩论 2 轮（轮内并行 2、轮间串行） | 20–40s | 120s |
| 交易员 | 5–10s | 60s |
| 风控 | 3–6s | 60s |
| **合计** | **35–70s** | **~270s** |

`analyst_timeout=120` / `debate_timeout=120` 比 HTTP 层的 30s/60s 松，真正生效的是 `llm.timeout` / `llm_deep.timeout`。

方案完成后 **55–110s 典型 / ~330s 上限**（分析师阶段因 `max_workers=4` 分两波跑而翻倍；pre-mortem 在辩论层无法与交易员并行，净加一次 strong 串行调用）。

**卡住的不是 bar 周期（15m = 900s ≫ 110s），而是三个更小的数**：`executor.signal_timeout_s` 默认 **20s**、`--interval` 默认 **60s**、`utils/timeout.py:27` 的 `_MAX_IN_FLIGHT`（1–2 vCPU droplet 上 = **8**）。

### 4.3 新增故障点

外部依赖 4 个 → 8–9 个。

| 依赖 | 付费 | 挂掉/被墙的后果 | 方案是否给了降级设计 |
|---|---|---|---|
| OKX funding-rate / open-interest | 否 | 与行情共命运，不是独立故障点 | ❌ |
| OKX `/market/books` | 否 | 调用频次更高、payload 更大，有挤占行情配额风险 | ❌ |
| **币安 public ticker** | 否 | **DigitalOcean 常见美区 IP 会被 `api.binance.com` 以 HTTP 451 拒绝**——大概率而非小概率事件。跨所校验退化为单源 | ❌ 完全未提地域封锁；`okx.proxy` 只对 OKX 生效，无 per-source 代理 |
| **Coinbase public ticker** | 否 | 同上（非美区受限） | ❌ |
| **链上 provider** | **是**（交易所净流入/稳定币供应通常在高价档） | 方案自标 🔴"先做接口后接源" → 分析师会在**没有数据源**的状态下上线，每次决策烧一次调用只为输出 N/A，按 1H/5pair 约 **$8–15/月纯浪费** | ❌ |
| **催化剂日历** | 部分免费档有硬配额，解锁表多为付费/爬取 | 分析师空转；**同时是第二个不可信文本源** | ❌ |
| `project_examples/.../financial_rigor.py` | — | **untracked 目录**，import 会破坏 CI、deploy 与发布身份 | ❌ "复用"不成立，必须 vendor 并补测试 |

**降级路径的 5 个缺口**：① 没有"源死了 → 压低置信度天花板"的通路（`assess_data_sufficiency` 只看 K 线，链上源全挂 grade 依旧是 A、ceiling 依旧 1.0 → **用更差的输入宣称同样的信心**，正是它声称要防的"伪装"，只不过从代码侧发生）；② 没有 fetcher 失败语义规范（照抄 `news.py` 的"永不抛异常返回空列表"会让宕机静默变成一堆 N/A）；③ 没有"源死了就跳过该分析师"的规则；④ 没有 staleness 上限（生产内核对 K 线有 `max_market_data_age_s: 5`，对链上/日历这类低频源无对应物）；⑤ 没有 per-source 超时/重试/熔断预算与 per-source 代理。

### 4.4 安全缺口

**S1（高）— 分析师报告在下游 prompt 里失去哨兵。** `_wrap_untrusted` 强度不错（NFKC 归一化、零宽/方向控制字符剥离、伪哨兵正则中和、4,096 字符硬截断，4 个专项单测），但**只用在 `prompts.py:226` 一处**。`build_debate_prompt`（`:248`）与 `build_trader_prompt`（`:265`）把分析师输出**原样拼接**，且 `BULL_/BEAR_RESEARCHER_SYSTEM`、`TRADER_AGENT_SYSTEM`、`RISK_MANAGER_SYSTEM`（`:119-178`）**一条 SECURITY 条款都没有**。

完整洗白路径：不可信新闻 → 新闻分析师（有防护）→ 报告文本（**防护消失**）→ Bull/Bear（无告警）→ **交易员（无告警，且正是输出 `signal`/`size_pct`/`stop_loss_pct` JSON 的那个 agent）** → 风控（无告警）。

方案让这个面**扩大三倍**：催化剂分析师是第二个不可信文本源；**步骤 4 的记忆回喂是第三条、也是最危险的一条**——它把"曾经读过不可信文本的 LLM 写出来的文本"从 `logs/thesis/` 读回来喂给交易员，是一条**注入持久化通道**：一次投毒可经论点快照在该标的的每一次后续决策里复现。

**S2（高 / 生产路径中）— `stop_loss_pct` 无代码级夹取。** `size_pct` 处理是对的（`_clamp01` + `min(proposed, reviewed)`），但 `stop_loss_pct` **只有 `min()` 没有 clamp**（`pipeline.py:190-192`），`risk/manager.py:235` 也只判 `> 0`。`sl_pct=0.5` → 止损挂在入场价 50% 之下（在 `max_daily_loss` 之内等于没有止损）；`sl_pct=0.0005` → 进场即被扫。

生产内核确实兜住了钱（`risk_service.py:510-518` 强制 `0 < stop < price` 且 `expected_loss > max_order_loss_usdt($100)` → 拒单），但两点保留：(a) 它是**拒绝**而非**夹取**，被注入的荒谬止损会变成"所有 BUY 全被拒"的静默交易拒绝服务；(b) **`production.enabled: false` 的单 trader 路径完全没有这个下界**。

**S3（中）— 每个新 provider 密钥都会绕过两条脱敏路径。** ① 日志脱敏是硬编码 5 项清单（`main.py:1700-1706`）：OKX 三件套 + `llm.api_key` + `llm_deep.api_key`——**`news.auth_token` 今天就不在里面**。② 证据/身份脱敏是"规范化后精确匹配"（`evidence.py:22-33`）：`_normalized_key("auth_token") = "authtoken"` 而集合里是 `"token"`，**不相等 → 不脱敏**；同理 `glassnode_api_key` → `"glassnodeapikey"` ≠ `"apikey"`。任何带前缀的密钥字段都会以明文进入 `redacted_config_hash`。

**S4（中）— 数值源可信度只有 prompt 级约束。** L103 的"（**可选**）压低置信度天花板"直接违反 L20 自立的"用代码钉死"。跨所价格与链上流量都是攻击者/宕机可影响的数值；若污染或缺失只体现在 prompt 措辞上，模型完全可以忽略它。正确做法：`ceiling` 变成 `f(K线质量, 源健康度)` 的确定性函数，**强制**而非可选。

**S5（低/中）— 不可信文本额度随源数线性放大。** `_UNTRUSTED_MAX_LEN = 4096` 是**每块**上限，新闻 + 催化剂各占一块 → 攻击者可控文本预算翻倍，且这些内容经摘要后在下游被重发 5–6 次（**注入文本本身也要按 token 付钱**）。缺"每次决策不可信文本总预算"。

**S6（低）— 层次倒置。** `agentic/prompts.py:226` 从 `okx_quant.strategy.llm_strategy` 反向 import `_wrap_untrusted`（函数内 import 绕开循环依赖），应下沉到共享模块。

### 4.5 复杂度债

`okx_quant/agentic/` 当前 **1,154 行**。四步后 agentic/ 约 **2,050 行（1.8×）**，但**项目层面新增约 4,000 行**（数据层 ~700、工具层 ~500、脚本层 ~550、测试 ~1,230），其中一半以上落在 agentic/ 之外——这部分方案的 S/M/L 估算没有覆盖。

- 外部 HTTP 客户端 4 → 8–9 个，其中 4 个是第三方源；按 `news.py` 现有范式，schema 漂移会**静默**退化成 N/A，无告警。单人维护下这是 4 个新的无声 on-call 面。
- 新增长期磁盘状态 3 处（LLM 缓存、`logs/thesis_outcomes/`、评估台 fixtures），生产内核的 `backup_dir`/`backup_retention_days` 目前不覆盖。
- `prompts.py` 299 → ~600 行，且步骤 3 把 regime 判定/赔率/pre-mortem 全部固化进 prompt——这部分**天然不可单测**，只能靠阶段 0 端到端 Δ 对比。**这意味着阶段 0 不是"先做的一步"，而是步骤 3 唯一的质量保证机制。**
- 新增约 **+30 个配置键**（LLM 相关配置面翻三倍）。每个新键还要同步进 `config.yaml.example`、`config.demo.yaml`、发布身份的脱敏配置哈希、`research/canary.py` 的字段白名单；而 `AgenticConfig.from_dict` / `LLMConfig.from_dict` 对未知键是**静默丢弃**，拼错一个键不报错、只安静失效。
- `agentic/` 是 56,717 行包里的 1,154 行（**2%**），而真正保护资金的部分是它的十几倍体量。方案会让这 2% 吃掉未来大部分增量工作量与全部新增外部依赖。

### 4.6 缺失章节（P0，缺了就不能开工）

1. **与 `PRODUCTION_PLAN.md` 的关系 / 资源与时钟冲突** —— 最严重的缺失，见 §1.3。
2. **失败退出条件 / 整体止损** —— 现在只有单步"砍"，没有全局 kill 条件：前置否决（阶段 0 baseline 若显示 multi_agent 相对传统策略无 alpha，整个 roadmap 不启动）、过程否决（连续 2 步 Δ 不显著 → 停止）、**不可分辨预案**（Δ 长期落在统计不可分辨区间——这在短周期上是大概率结果——如何决策）、累计成本上限。
3. **回滚方案与开关设计** —— `PRODUCTION_PLAN` §14.3 有分层回滚基线，本方案完全没有：每个新输入一个默认关闭的 feature flag、单源失败的降级语义**写死在代码里**、prompt 版本号进决策日志、记忆库污染时的清理重建流程。
4. **影子/灰度验证与上实盘门槛** —— 仓库已有 shadow mode / demo 连续运行 / canary 小资金三级设施，方案一处都没接。从"离线 Δ 为正"到"真金白银下单"之间整段是空的。**且对无历史数据的 3 个分析师，影子模式是唯一可行的验证路径**（这也顺带解开 §2.3-4 的死锁）。
5. **金钱成本预算** —— "不改善就砍"这道门本身要花钱；付不起的门禁等于没有门禁。

P1：时间预算与责任人（全文只有 S/M/L，无人天无日历，低于 `PRODUCTION_PLAN` §15 的写法基线）；统计方法学章节；数据源契约与降级矩阵；攻击面扩大与顺序倒置（步骤 2 的校验必须前移到步骤 1 之前或同批）；测试注册进 `scripts/non_live_validation.py`（方案 5 处验收写"配单测"、无一处提注册）；可观测性。

### 4.7 风险章节漏掉的两条

现有 5 条（成本失控、数据源造假、过拟合、约束刚性、spot-only 一致性）本身没问题，但漏掉的两条比写出来的 5 条都大：

- **风险 A：整个方案的收益是一个不可证的假设。** "输入更丰富 → 决策更好"在短周期加密现货上没有先验证据，而唯一对标物的有效性证据被本仓库自己判定为"不充分"。更麻烦的是自指问题：**度量工具（评估台）与被度量对象（LLM 决策）共享同一噪声源**，Δ 极可能永远落在统计不可分辨区间——届时"不改善就砍"将把所有步骤依次砍掉，方案完成后等于原地踏步但已烧掉全部预算。
- **风险 B：LLM 回测的记忆泄漏（双重）。** 训练数据泄漏 + `recall()` 无时间围栏的结果泄漏，见 §2.3-1 与 §2.4-M4。这会击穿阶段 0 这个全方案地基。

---

## 五、处置决定

### 5.1 立即做（已在本次评审后执行，见 §5.4）

| 项 | 说明 |
|---|---|
| `okx_quant/llm/cache.py` record/replay | 方案阶段 0 里唯一真正值钱且不可替代的交付物。key 必须含 `temperature`/`max_tokens`/`provider`（原方案 key 只有 `system+user+model`） |
| 最小证伪实验（协议 + 运行器） | 见 [`docs/agentic-min-experiment.md`](agentic-min-experiment.md)，判定标准事前写死 |
| 三组存量 bug 修复 | 见 §5.4；它们独立于本方案，但会被方案显著放大 |
| 重启 Gate A（A1 账户 / A2 Linux preflight / A3 contract v2 重采） | **必须在动 `agentic/` 之前冻结候选**。属外部/运维动作，不在本次代码改动范围 |

### 5.2 缩到最小版做（且必须在最小实验 PASS 之后）

| 项 | 缩成什么 |
|---|---|
| 阶段 0 评估台 | **砍掉 `tests/fixtures/agentic_eval/` 人工场景集**（挑段本身是选择偏差的温床，而 5 币 × 365 天连续样本天然覆盖四种 regime 且无挑拣自由度）；只给 grid 加 3 个决策级指标（HOLD 占比、每决策期望收益、token/决策）。M → S |
| 步骤 3 框架化 | 只做纯 prompt 三条，**不新增独立 Agent**——把 pre-mortem 折进现有 bear agent 的 system prompt，零新增 strong 调用。且 regime 判定与赔率计算**下沉到代码**，不交给 prompt 自觉 |

### 5.3 推迟 / 砍掉

**推迟到有业绩之后**：步骤 1 衍生品分析师（解冻条件：最小实验 PASS + Shadow 72h 完成）；步骤 2 `market_rigor.py`；**步骤 4 记忆闭环**（硬阻塞：`fills`=0，现实解冻时间是数月后）；步骤 1 催化剂分析师（需外部日历源）。

**直接砍掉**：
- **步骤 1 链上分析师** —— 无源还要"先做接口"= 每次决策烧一次调用只为输出 N/A；且信噪比全表最差。
- **步骤 2 cross-exchange 跨所校验** —— 引入币安/Coinbase 两个外部依赖（且 DigitalOcean 美区 IP 会被 HTTP 451 拒绝），而系统连一次 REST 5xx Chaos 演练都没做过（Gate A 0/6）；OKX 主流 USDT 现货的跨所偏差本身极小。
- **微观结构分析师中的"跨所价差"** —— 同上。
- **"深度追上/反超 AI Berkshire"这个目标本身** —— 拿一个不承担 P&L 的投研报告生成器当北极星。北极星应该是 `alpha_sharpe` 与 Gate A/C。
- **方案末段的定位段落** —— "既能深度研究、又能安全自主执行"中的"安全自主执行"是**尚未取得的准入结论**（NOT_ADMITTED），不能作为方案的既有前提写在结论里。

**形态改造（不砍但换做法）**：衍生品与催化剂解冻后应做成**代码硬规则**（`funding_percentile > 95 → 禁止 BUY`、大额解锁前 48h 禁开新仓），可直接用 `BacktestEngine` 回测验证、零 token——这才符合方案自己引用的"用代码钉死"。

### 5.4 本次评审后实际执行的代码改动

均为**独立于本方案**的存量问题，但会被方案显著放大，故先行修复：

1. **`okx_quant/llm/cache.py`（新增）** —— record/replay 缓存，key 含 provider/model/base_url/temperature/max_tokens/system/user；错误响应不落盘；原子写；`scripts/backtest_grid.py --llm-cache DIR` 接入。
2. **LLM 策略的信号超时** —— `signal_timeout_s` 默认 20s 与 multi_agent 实测 35–70s 相差一个数量级，且 `utils/timeout.py` 的守护线程**不会被杀**（后台继续跑完全部调用并计费）。现改为：LLM 类策略在未显式配置时使用与 LLM 超时相匹配的默认值，并在启动时打印。
3. **Token 预算** —— 新增**每决策**预算（代码内默认值，不依赖 yaml 是否配置）；`max_total_tokens` 明确为会话级并在 pipeline 内也做前置检查；`TokenTracker` 增加 run-scoped 计数与 quick/deep 分层（使成本可见），`summary()` 的 lifetime 语义保持不变以兼容 `get_usage_summary()` 与 grid 报表。
4. **安全** —— `_wrap_untrusted` 下沉到 `okx_quant/utils/untrusted.py`（原位置保留别名）；辩论/交易员 prompt 对分析师报告重新包裹哨兵；Bull/Bear/Trader/Risk 四个 system prompt 补 SECURITY 条款；`stop_loss_pct` / `take_profit_pct` 增加代码级夹取（上下界为 `AgenticConfig` 字段）。
5. **`_run_analysts` 的三处硬编码**（见 §2.2）—— 任务表改为 `_build_analyst_tasks()` 返回的 `(display_name, callable)` 列表，新增分析师只改这一处：
   - **`_DISPLAY_NAMES`** 删除。`display_name` 成为唯一 key 来源，成功/异常/超时三条路径共用，不会再出现两套 key。
   - **`max_workers=4`** → 默认等于任务数（新增 `AgenticConfig.analyst_max_workers`，0 = 全部并行，可显式钉住）。
   - **共享墙钟预算** → 按实际波次放大为 `timeout × ceil(n/max_workers) + 5`。注意 `ThreadPoolExecutor` 退出时 `shutdown(wait=True)` 本来就要等在跑的任务收尾（真正的时间上界是 `llm.timeout`），所以预算配小了**并不能提前返回**，只会把已经付过钱、也确实拿到了的响应标成"超时"丢掉——这才是这处硬编码的实际损失。超时分支同时对尚未开跑的 future 调 `cancel()`，不再白花 token。
