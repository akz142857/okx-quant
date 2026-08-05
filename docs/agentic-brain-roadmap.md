# Agentic 大脑升级方案 — 让多 Agent 决策深度追上 AI Berkshire

> 状态：**已评审 / 暂缓执行（2026-08-05）**
> 日期：2026-08-04
> 背景：见 [`docs/ai-berkshire.md`](ai-berkshire.md) 十一 / 十一·五。本方案是"如何让 `okx_quant/agentic/` 的分析深度追上 AI Berkshire"的落地设计。

---

## ⚠️ 评审结论（2026-08-05）

多 Agent 评审报告见 [`docs/agentic-brain-roadmap-review.md`](agentic-brain-roadmap-review.md)。**结论：推迟，本方案四步整体不执行。**

核心原因（证据见评审报告 §1）：本系统**从未产生过一笔决策**——`state/demo/trading.db` 的 `decisions` / `fills` / `positions` / `realized_pnl_events` 全部 0 行，`mode=halted`；Gate A 的 Shadow 0/72h、Active 0/7d、Chaos 0/6 全部未开始，准入结论 NOT_ADMITTED。在这样的系统上论证"决策深度不够"，缺少任何运行数据支撑。另有两条硬阻塞：**步骤 4 物理上不可能**（记忆闭环要平仓结果打标签，而 `fills`=0）；**改 `agentic/` 会重置 Gate A 的日历时钟**（换冻结候选 → provenance 重算、Linux CI 重跑、contract v2 重采）。

下一步不是本方案，而是 [`docs/agentic-min-experiment.md`](agentic-min-experiment.md) 的 **3 天最小证伪实验**：用**现成的** `scripts/backtest_grid.py`（`LLM_STRATEGIES` 已含 `multi_agent`）跑 multi_agent vs 传统策略的 `alpha_sharpe` 对照，判定标准事前冻结。

本文以下内容保持原样存档。阅读时请注意评审查出的事实性错误：

- §1 表格「`backtest/` 未覆盖 LLM 策略」**不实**——`scripts/backtest_grid.py:92` 早有 `LLM_STRATEGIES`。
- 步骤 2 的 `financial_rigor.benford` / `report_audit.py` / `tests/test_financial_rigor.py` / `tools/` 目录**本仓库均不存在**，只在**未纳入版本控制**的 `project_examples/` 里；且真名是 `benford_check`，是 argparse 子命令、不可 import。
- 步骤 1「衍生品 🟢 好接」不成立——funding/OI 是 `-SWAP` 数据而全链路是现货，`client/rest.py` 无任何封装。
- L117「对标 AI Berkshire 决策终章'赔率思维收尾'」在被引文档中**查无此文**。
- 排期表与依赖图**成环**（序 4 前置=步骤2，序 5「步骤2」前置=步骤1）。
- 步骤 3「只改 `prompts.py`、不加 token 成本」与其正文「新增逆向 Agent、放在辩论层（strong model）」**自相矛盾**。

---

## 0. 目标与非目标

**核心判断**：agentic 的深度天花板不来自 Agent 数量，而来自——(a) 输入太薄（只吃计算出的指标 + 单一新闻源），(b) 每个 Agent 是泛泛的"你是分析师"而非硬框架，(c) 决策每次冷启动、不从历史学习。AI Berkshire 之所以强，正是在这三点上做到了极致（联网多源 + 交叉验证 + 四大师硬框架 + 反偏见）。

**要做的**：把 AI Berkshire 的"输入丰富 + 严谨性校验 + 框架化推理 + 可复盘"移植过来，**适配到币圈短周期现货**。

**明确不做的**：
- ❌ 不加 Agent 数量凑深度（"确定性来自输入质量，不来自 Agent 数量"）。
- ❌ 不抄 DCF / 护城河 / 估值那套——短周期现货用不上。
- ❌ 不在没有评估台的情况下盲目加输入（每加一样都在烧 token，必须先能量化"是否真的改善决策"）。

**约束**：本仓库 spot-only / long-only / USDT。衍生品数据（资金费率/OI）是**信号输入**而非交易标的；决策仍只产出 BUY/SELL/HOLD。所有新约束沿用 §11.5 原则——**用代码钉死，不靠 prompt 自觉**。

---

## 1. 现状锚点（改动都落在这些文件）

| 层 | 文件 | 现状 |
|---|---|---|
| 编排 | `agentic/pipeline.py` | `_run_analysts` 用 `ThreadPoolExecutor` 并行 4 分析师；已加数据质量天花板 / 置信度门 / 风控硬约束 |
| Agent | `agentic/agents.py` | `BaseAgent(name, llm, tracker)`；分析师 = `analyze()` → `self.run(SYSTEM, user_prompt)` |
| 提示词 | `agentic/prompts.py` | 泛化 system prompt + `build_*_prompt`；已有 `_fmt`/N/A |
| 输入构建 | `strategy/multi_agent_strategy.py` `_build_indicators` | 只从 K 线算指标 |
| 数据 | `data/market.py`、`data/news.py` | REST→DataFrame；新闻 5 分钟缓存 |
| 记忆 | `agentic/thesis.py`（新）、`trading/decision_log.py` | 建仓论点已落盘，但**无结果标签、无检索回喂** |
| 评估 | `backtest/`、`scripts/backtest_grid.py` | 有回测底子，但未覆盖 LLM 策略 |

---

## 阶段 0（前提，必须先做）：离线决策评估台

> **没有这个，后面三步全是信仰充值。** 对标 AI Berkshire 的 `report_audit.py`（准出抽检）——它的对应物是"量化每个新输入是否真的改善决策"。

**交付物**
- `scripts/agentic_eval.py` — 在历史 K 线上回放 `MultiAgentStrategy`，输出决策质量指标。
- `okx_quant/llm/cache.py` — LLM 请求 **record/replay 缓存**（按 `hash(system+user+model)` 存 `LLMResponse`），让同一评估集可零成本重复跑、可离线复现。
- `tests/fixtures/agentic_eval/` — 一个小而有代表性的场景集（趋势启动 / 顶部背离 / 震荡 / 黑天鹅急跌各若干段真实 K 线）。

**指标**：决策胜率、盈亏比、每决策期望收益、HOLD 占比（过度保守检测）、token/决策。

**验收**：能跑出 baseline 数值；此后每引入一个新输入/框架，跑同一集对比 Δ，**不改善就砍**。

**工作量**：M。**依赖**：无（最先做）。

---

## 步骤 1（最高 ROI）：输入丰富化 — 新增币圈原生分析师

> 对标 AI Berkshire 的"联网 + 多源"。这一步拿到 ~80% 的深度提升，因为大脑第一次能看到"价格之外的世界"。

新增 4 类分析师，每个 = `data/` 一个 fetcher + `agents.py` 一个 `BaseAgent` 子类 + `prompts.py` 一个 system+builder，并入 `pipeline._run_analysts`。

| 分析师 | 数据源 | 判断 | 对标 | 源可得性 |
|---|---|---|---|---|
| **衍生品分析师** | 资金费率、未平仓量(OI) | 杠杆结构 / 挤仓与踩踏风险 | 风险信号猎手 | 🟢 OKX 原生：`/api/v5/public/funding-rate`、`/api/v5/public/open-interest` |
| **微观结构分析师** | 订单簿深度、买卖价差、跨所价差 | 流动性真伪 / 能否进出 | 基本面(流动性) | 🟡 OKX 原生 `/api/v5/market/books` + 外部所公开 ticker |
| **链上分析师** | 交易所净流入流出、稳定币供应、活跃地址 | 真实资金进出 | 财务质量(真钱假钱) | 🔴 需外部 provider（分级付费/免费源），先做接口后接源 |
| **催化剂分析师** | 代币解锁表、上/下币、升级/分叉、监管 | 已知的未来事件 | 新闻+事件，但结构化 | 🟡 部分需外部日历源 |

**先做**：🟢 衍生品分析师（数据 OKX 原生、公开、好接，验证整条路径最快）。

**集成点**（骨架不动，只在并行组加 task）：
```python
# pipeline._run_analysts 内新增
def _derivatives():
    return "Derivatives Analysis", self.derivatives.analyze(deriv_metrics)
tasks = [_technical, _sentiment, _news, _fundamentals, _derivatives, ...]
```
```python
# agents.py
class DerivativesAnalyst(BaseAgent):
    def analyze(self, deriv: dict) -> str:
        return self.run(DERIVATIVES_ANALYST_SYSTEM, build_derivatives_prompt(deriv))
```
数据在 `_build_indicators` 旁并行获取（`data/derivatives.py` 新 fetcher），随 `indicators` 一起传入 `run()`。

**反注入**：所有外部文本源（新闻/催化剂）复用 `_wrap_untrusted` 哨兵；数值源过阶段 2 的严谨性校验后才进 prompt。

**验收**：每个分析师配 fake 数据单测（模式同 `test_agentic_hardening.py`）；在阶段 0 评估台上跑 Δ，胜率/盈亏比需正向或至少不劣化。

**工作量**：每个 S–M；衍生品先行 S。**依赖**：阶段 0。

---

## 步骤 2：行情严谨性工具 — 输入可信度校验

> 对标 `financial_rigor.py`（`Decimal` 精确 + 多源交叉 + Benford）。币圈版是**喂进 Agent 前先校验输入本身可信**，每个数字带"可信度标签"，而不是照单全收。

**交付物**：`tools/market_rigor.py`（零依赖，风格同 `financial_rigor.py`）
- `cross-exchange` — 跨所价格一致性（OKX/币安/Coinbase 偏差 >X% → 标记，防薄盘/操纵）
- `funding-consistency` — 资金费率 vs 现货溢价内部一致性
- `volume-anomaly` — 成交量 Benford / 异常检测（复用 `financial_rigor.benford`，识别冷门币刷量）
- `source-credibility` — 新闻源 A/B/C 可信度分级（对标信息丰富度评级 + "联网失败不伪装"）

**集成**：校验结果作为 `data_quality` 的兄弟字段传入 `pipeline.run`，低可信度输入**在 prompt 里显式降权**并（可选）压低置信度天花板——延续阶段已有的 ceiling 机制。

**验收**：工具单测（放 `tests/`，风格同 `test_financial_rigor.py`）；构造跨所背离/刷量样本验证告警命中。

**工作量**：M。**依赖**：步骤 1（要有多源输入才谈得上交叉）。

---

## 步骤 3（近零成本，高 ROI）：Agent 框架化 — 硬推理路径

> 对标四大师"框架强制特定推理"（段永平必问生意变好变差、芒格必做逆向）。只改 `prompts.py`，不加 token 成本。

1. **技术分析师先判 regime**：趋势/震荡/无序，不同状态切换信号权重（把 `strategy/adaptive.py` 已有的 regime 逻辑固化进 system prompt）。
2. **新增逆向/证伪 Agent（pre-mortem，对标芒格"反过来想"）**：强制回答"这笔 BUY 最可能怎么亏钱？什么情况下我在接盘？"——补上现有多空辩论没覆盖的**事前尸检**。放在辩论层（strong model），产物进交易员上下文。
3. **交易员走赔率思维**：不是"看涨即买"，而是"上行空间/下行风险 × 概率"，强制在 JSON `reason` 里给出赔率判断（对标 AI Berkshire 决策终章"赔率思维收尾"）。

**验收**：prompt 变更后在阶段 0 评估台跑 Δ；逆向 Agent 应提升"顶部/急跌段"的 HOLD 命中，降低接盘。

**工作量**：S。**依赖**：阶段 0（否则无法判断框架是否真有用）。

---

## 步骤 4（差异化，能反超 AI Berkshire）：记忆闭环 — 让大脑从历史学习

> AI Berkshire 的 `thesis-tracker`/`thesis-drift` 只让**人**复盘，不回喂模型。你刚加的 `agentic/thesis.py` 可以更进一步，做成**结果反馈闭环**——这是 AI Berkshire 没有的。

1. **结果标签**：平仓时给对应 thesis 打盈亏结果。落点 `trading/position_monitor.py` / 平仓路径 → 回写 `logs/thesis/` 或新增 `logs/thesis_outcomes/`。
2. **检索回喂**：决策时检索**同标的 + 同 regime** 的历史 thesis + 结果，作为上下文喂给交易员：「你上次在类似情形买它，-8% 止损，当时理由是 X」。新增 `agentic/memory.py`：`recall(inst_id, regime, k) -> list[past_decision_with_outcome]`。
3. **漂移检测**：对比本次论点与上次（对标 `thesis-drift`），区分"事实变化 vs 措辞变化"。

**隐私/体积**：只检索结构化摘要（信号/regime/置信度/结果），不把整段 transcript 塞回 prompt（token 与噪声）。

**验收**：`memory.recall` 单测（构造历史 thesis 目录，验证按标的+regime 命中且按时间倒序）；评估台上验证"带记忆 vs 冷启动"的决策一致性/胜率。

**工作量**：M–L。**依赖**：步骤 1（regime 标签）、`thesis.py`（已完成）。

---

## 排期与依赖

```
阶段0 评估台 ──┬─→ 步骤1 输入丰富(先做衍生品) ──┬─→ 步骤2 严谨性校验
              │                                └─→ 步骤4 记忆闭环
              └─→ 步骤3 框架化(可与步骤1并行)
```

| 顺序 | 工作项 | 工作量 | 前置 | 一句话价值 | **评审处置（2026-08-05）** |
|---|---|---|---|---|---|
| 1 | 阶段0 评估台 + LLM 缓存 | M | — | 让后续每一步可度量、防自我欺骗 | **拆开**：`llm/cache.py` 已实现；评估台缩到"给 grid 加 3 个决策级指标"，人工场景集**砍掉**（挑段本身是选择偏差） |
| 2 | 步骤1 衍生品分析师（端到端一刀） | S | 阶段0 | 验证"加输入"整条路径最快 | **推迟**（解冻：最小实验 PASS + Shadow 72h）。且工作量实为 M；形态应改为**代码硬规则**而非 LLM 分析师 |
| 3 | 步骤3 框架化 + 逆向 Agent | S | 阶段0 | 近零成本提升决策纪律 | **缩到最小**：只做纯 prompt，**不新增独立 Agent**（折进现有 bear prompt）；regime 与赔率**下沉到代码** |
| 4 | 步骤1 其余分析师（微观/链上/催化剂） | M×3 | 步骤2 | 深度主体 | 链上**砍掉**；微观结构分析师**砍掉**（其价值应落在执行前置检查，且 `market.py:181/199` 已有 orderbook/spread）；催化剂**推迟** |
| 5 | 步骤2 `market_rigor.py` | M | 步骤1 | 输入可信度标签 | **推迟**；`cross-exchange` **砍掉**（DigitalOcean 美区 IP 会被币安 HTTP 451 拒绝）；`benford` 无法"复用"须重写 |
| 6 | 步骤4 记忆闭环 | M–L | 步骤1 | 差异化，反超点 | **硬阻塞推迟**：`fills`=0 → 无 outcome 标签；且 `recall()` 缺 `as_of` 会造成前视泄漏，thesis 与持仓无 ID 关联 |

---

## 风险与红线

- **成本失控**：每加一个分析师都增 token。红线——**必须先过评估台，Δ 不正向就砍**。
- **数据源脆弱/造假**：外部源（链上/跨所）可能不可靠。所有外部输入必须过步骤 2 的可信度校验，且**联网失败禁止伪装**（沿用 §11.5，降级标注而非用训练知识冒充）。
- **过拟合历史**：步骤 4 的记忆回喂可能让大脑"刻舟求剑"。只喂结构化摘要 + 明确标注"历史不代表未来"，并在评估台用样本外数据验证。
- **约束刚性不退化**：所有新增数值输出（若有）继续用代码钉死边界，不回退到"只写在 prompt 里"。
- **spot-only 一致性**：衍生品信号只作输入，绝不衍生出做空/合约下单路径。

---

## 与 AI Berkshire 的最终定位

做完这四步，agentic 的**大脑深度**（输入丰富 + 框架化 + 校验）会逼近 AI Berkshire 在其领域的水准，而 okx-quant 本就更强的**工程硬度、自主执行、约束刚性、记忆闭环**保持不变——两者从"研究框架 vs 执行系统"的错位，收敛为"**一个既能深度研究、又能安全自主执行、还能从历史学习的交易大脑**"。
