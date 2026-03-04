# LLM 量化交易：最新论文与项目汇总

> 收集时间：2026-03，覆盖 2024-2026 年发表的论文和活跃开源项目。

---

## 一、多 Agent 交易系统

### 1. TradingAgents — 多 Agent 金融交易框架
- **机构：** Columbia University / Tauric Research (2024.12)
- **核心思路：** 模拟真实交易公司，部署 7 个专业 LLM Agent（基本面分析师、情绪分析师、新闻分析师、技术分析师、多空研究员、交易员、风控经理）。多空研究员通过结构化辩论对抗偏见，交易员综合辩论记录和历史数据做最终决策。在累计收益、Sharpe 比率和最大回撤方面显著优于基线策略。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2412.20138) | [GitHub](https://github.com/TauricResearch/TradingAgents) | [项目主页](https://tradingagents-ai.github.io/)

### 2. AlphaAgents — 基于 LLM 多 Agent 的股票组合构建
- **机构：** BlackRock Research (2025.8)
- **核心思路：** 模块化角色分工的多 Agent 框架，整合基本面分析（10-K/10-Q 财报）、情绪分析和估值分析，用于系统化股票组合构建。结构化辩论协议有效减少 LLM 幻觉，多 Agent 协作优于单 Agent 方案和市场基准，且回撤更低。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2508.11152)

### 3. MarketSenseAI 2.0 — 基于 LLM Agent 的股票分析增强
- **机构：** EU FAME 项目 (2025)
- **核心思路：** 在原始 GPT-4 选股框架基础上引入 RAG 和 LLM Agent 处理 SEC 文件和财报电话会议。S&P 100 上 2023-2024 年实现 125.9% 累计收益（指数 73.5%），S&P 500 上 2024 年选股组合收益 25.8%（等权基准 12.8%，相对超额 102%）。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2502.00415) | [原始论文 (2024)](https://link.springer.com/article/10.1007/s00521-024-10613-4)

---

## 二、LLM 金融分析与预测

### 4. CryptoTrade — 反思式 LLM 零样本加密货币交易
- **机构：** EMNLP 2024
- **核心思路：** 结合链上数据（透明、不可篡改）和链下信号（新闻、社交媒体），通过反思机制分析历史交易结果来修正后续决策。零样本无需微调，在 BTC、ETH、SOL 的牛熊行情中均有测试。
- **链接：** [论文 (ACL Anthology)](https://aclanthology.org/2024.emnlp-main.63/) | [GitHub](https://github.com/Xtra-Computing/CryptoTrade)

### 5. The New Quant — LLM 金融预测与交易综述
- **时间：** 2025.10
- **核心思路：** 全面综述 LLM 在金融预测中的应用——从情绪提取、股票收益预测到全自主交易 Agent。重点识别了两大偏见：前视偏差（模型无意中利用了未来收益信息）和干扰效应（无关信息扭曲情绪判断）。
- **链接：** [论文 (arXiv)](https://arxiv.org/html/2510.05533v1)

### 6. LLM Agent 金融交易综述
- **时间：** 2024
- **核心思路：** 将 LLM 交易 Agent 架构分为两类："LLM as Trader"（直接生成交易决策）和 "LLM as Alpha Miner"（发掘 Alpha 信号供下游系统使用）。总结常见架构、数据输入、回测表现和开放挑战（包括规划可靠性和工具误用）。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2408.06361)

### 7. LLaMA 驱动的股票预测
- **时间：** 2025
- **核心思路：** 利用 LLaMA 系列模型结合历史价格数据和新闻进行股票预测。LLaMA 3.3 在建模复杂金融关系方面优于 LLaMA 3.1 和传统 ARIMA 模型。
- **链接：** [论文 (Sciendo)](https://sciendo.com/pdf/10.2478/picbe-2025-0043)

### 8. LLM 投资管理 Agent 综述
- **机构：** ACM ICAIF 2025
- **核心思路：** 按用途分类（组合优化、风险管理、信息检索、自动化策略生成）和架构创新（多 Agent 协作、反思机制、工具增强管线）系统梳理 LLM 投资 Agent 文献。
- **链接：** [论文 (ACM)](https://dl.acm.org/doi/10.1145/3768292.3770387)

---

## 三、金融专用 LLM

### 9. FinGPT — 开源金融大模型
- **机构：** AI4Finance Foundation
- **核心思路：** BloombergGPT 的开源替代方案。通过 LoRA 微调 LLaMA2-7B/13B 和 ChatGLM2-6B，微调成本仅约 $300（BloombergGPT 训练成本 $3M）。金融情绪分析 F1=87.62%，接近 GPT-4 水平。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2306.06031) | [GitHub](https://github.com/AI4Finance-Foundation/FinGPT)

### 10. LLM Open Finance — 金融领域开源模型
- **机构：** DragonLLM / AGEFI（法国 France 2030 计划）
- **核心思路：** 基于 LLaMA 3.1 和 Qwen 3 微调的 8B 金融专用模型（英法双语），面向财报分析、风险评估、合规检查和情绪分析。商用 Pro 版本提供 12B/32B/70B 规模。
- **链接：** [博客 (HuggingFace)](https://huggingface.co/blog/DragonLLM/llm-open-finance-models) | [模型集合](https://huggingface.co/collections/DragonLLM/llm-open-finance)

### 11. Open FinLLM Leaderboard — 金融 LLM 评测排行榜
- **机构：** FINOS Foundation (HuggingFace)
- **核心思路：** 标准化公开排行榜，对金融 LLM 在核心金融 NLP 任务上的表现进行评估和比较。
- **链接：** [排行榜](https://huggingface.co/spaces/finosfoundation/Open-Financial-LLM-Leaderboard)

---

## 四、强化学习 + LLM

### 12. FLAG-TRADER — LLM + 梯度强化学习融合交易
- **机构：** Harvard / Columbia / NVIDIA 等 (ACL 2025 Findings)
- **核心思路：** 将部分微调的 LLM 作为 RL 策略网络——冻结底层保留预训练知识，可训练的顶层通过 PPO 策略梯度优化适应金融决策。同时提升了交易表现和下游金融 NLP 任务。
- **链接：** [论文 (ACL)](https://aclanthology.org/2025.findings-acl.716/) | [arXiv](https://arxiv.org/abs/2502.11433)

### 13. 语言模型引导的强化学习量化交易
- **时间：** 2025
- **核心思路：** LLM 从财经新闻和分析师报告中生成高层交易策略和上下文指导，用于引导 RL Agent。实证结果表明 LLM 指导能改善收益和风险指标，将关注点从原始 Alpha 转向风险调整指标（Sharpe、CVaR、回撤韧性）。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2508.02366)

### 14. FinMem — 分层记忆 LLM 交易 Agent
- **机构：** ICLR Workshop / IJCAI 2024 FinLLM Challenge
- **核心思路：** 受认知架构启发，包含三个模块：画像（可定制交易者性格）、记忆（分层消息处理——工作记忆、情景记忆、语义记忆）和决策。可调认知跨度突破人类感知极限，通过经验自主进化专业知识。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2311.13743) | [GitHub](https://github.com/pipiku915/FinMem-LLM-StockTrading)

---

## 五、开源框架与工具

### 15. FinRobot — 开源金融 AI Agent 平台
- **机构：** AI4Finance Foundation (2024)
- **核心思路：** 四层 AI Agent 平台：金融 AI Agent 层 -> 金融 LLM 算法层 -> LLMOps/DataOps 层 -> 多源 LLM 基础模型层。统一 LLM、强化学习和量化分析，支持投研自动化、算法交易和风险评估。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2405.14767) | [GitHub](https://github.com/AI4Finance-Foundation/FinRobot)

### 16. FinRL — 金融强化学习框架
- **机构：** AI4Finance Foundation（月活 20 万+）
- **核心思路：** 首个金融 RL 开源框架，支持构建、训练和回测交易 Agent。2025 竞赛包含 FinRL-DeepSeek（LLM+RL 股票交易）和 FinRL-AlphaSeek（加密货币交易）。
- **链接：** [GitHub](https://github.com/AI4Finance-Foundation/FinRL) | [2025 竞赛](https://open-finance-lab.github.io/FinRL_Contest_2025/)

### 17. LLM_trader — LLM + Vision AI 加密货币交易
- **作者：** qrak (GitHub)
- **核心思路：** 结合 LLM 推理和 Vision AI 图表分析——生成带指标的技术图表发送给视觉模型做图形确认。包含记忆增强推理、实时神经引擎和实时监控面板。
- **链接：** [GitHub](https://github.com/qrak/LLM_trader)

---

## 六、评测基准

### 18. StockBench — LLM Agent 真实市场交易评测
- **时间：** 2025.10
- **核心思路：** 无污染基准，评测 LLM Agent 在 82 个交易日（2025.3-6）内的表现。测试 20 只 DJIA 股票，$100K 起始资金。核心发现：大部分 LLM Agent 在熊市跑不赢 buy-and-hold，但在上涨行情中多数能超越基线。擅长静态金融知识不等于能成功交易。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2510.02209) | [项目主页](https://stockbench.github.io/)

### 19. Market-Bench — LLM 量化交易入门评测
- **时间：** 2024.12
- **核心思路：** 评测 LLM 从自然语言策略描述生成可执行回测代码的能力。测试三种经典策略（定期交易、配对交易、Delta 对冲）。核心发现：当前 LLM 能搭建基本交易基础设施，但在价格、仓位和风险推理上仍有困难。
- **链接：** [论文 (arXiv)](https://arxiv.org/abs/2512.12264)

### 20. LLM + RL 情绪驱动量化交易
- **时间：** 2025.10
- **核心思路：** 两阶段框架：LLM 基于历史数据和新闻情绪提供初始预测，PPO 根据金融风险指标进一步优化。结合 LLM 的语义理解能力和 RL 的自适应决策能力。
- **链接：** [论文 (arXiv)](https://arxiv.org/html/2510.10526v1)

---

## 总览表

| # | 名称 | 类型 | 年份 | 方向 |
|---|------|------|------|------|
| 1 | TradingAgents | 框架+论文 | 2024 | 多 Agent 交易公司模拟 |
| 2 | AlphaAgents | 论文 | 2025 | 多 Agent 组合构建（BlackRock） |
| 3 | MarketSenseAI 2.0 | 论文 | 2025 | RAG + LLM Agent 选股 |
| 4 | CryptoTrade | 论文+代码 | 2024 | 反思式 LLM 加密货币交易 |
| 5 | The New Quant | 综述 | 2025 | LLM 金融预测偏见分析 |
| 6 | LLM Agent Trading | 综述 | 2024 | LLM 交易 Agent 架构分类 |
| 7 | LLaMA 股票预测 | 论文 | 2025 | LLaMA 系列股票预测 |
| 8 | LLM 投资管理综述 | 综述 | 2025 | 组合/风险管理 Agent（ACM） |
| 9 | FinGPT | 框架+模型 | 2023-25 | 开源金融 LLM（LoRA 微调） |
| 10 | LLM Open Finance | 模型 | 2025 | 双语金融 LLM（8B） |
| 11 | Open FinLLM 排行榜 | 基准 | 2025 | 金融 LLM 评测 |
| 12 | FLAG-TRADER | 论文 | 2025 | LLM + RL 融合交易（ACL） |
| 13 | LM-Guided RL | 论文 | 2025 | LLM 引导 RL 交易 |
| 14 | FinMem | 论文+代码 | 2024 | 分层记忆 LLM 交易 |
| 15 | FinRobot | 平台+代码 | 2024 | 金融 AI Agent 平台 |
| 16 | FinRL | 框架 | 2024-25 | 金融 RL + LLM 信号 |
| 17 | LLM_trader | 代码 | 2025 | Vision AI 加密货币交易 |
| 18 | StockBench | 基准 | 2025 | 多月 LLM 交易评测 |
| 19 | Market-Bench | 基准 | 2024 | LLM 回测代码生成评测 |
| 20 | LLM+RL 情绪交易 | 论文 | 2025 | PPO 优化 LLM 预测 |

---

## 关键结论

1. **多 Agent 辩论是当前最有效的架构** — TradingAgents、AlphaAgents 都证明了多角色辩论比单 LLM 更稳健
2. **LLM 做 Alpha 信号挖掘比直接交易更靠谱** — LLM 擅长理解新闻/情绪，但对价格推理仍较弱
3. **LLM + RL 是前沿方向** — LLM 提供语义理解，RL 负责序贯决策优化
4. **便宜模型 + 微调可替代昂贵闭源模型** — FinGPT 用 $300 微调接近 GPT-4 的金融情绪分析能力
5. **评测显示 LLM Agent 在熊市表现不佳** — StockBench 发现大部分 LLM Agent 在下跌行情中跑不赢 buy-and-hold，说明风控和仓位管理仍是核心挑战
