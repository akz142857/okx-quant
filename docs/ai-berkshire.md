# AI Berkshire 深度分析报告

> 分析对象：`project_examples/ai-berkshire`（GitHub: `xbtlin/ai-berkshire`，约 14.9k star）
> 分析日期：2026-08-04
> 分析视角：一个多 Agent LLM 系统的架构 / 工程 / 方法论拆解，并结合本仓库（okx-quant）的 `agentic/` 多 Agent 交易管线给出可迁移的启示。

---

## 一、一句话定性

AI Berkshire **不是一个软件系统，而是一套"提示词工程 + 轻量 Python 校验工具 + 多 Agent 编排约定"的方法论包**。它把巴菲特、芒格、段永平、李录四位价值投资大师的方法论拆成 20 个可复用的 Claude Code / Codex Skill（本质是结构化 Markdown 提示词），配上 3 个用于"防 LLM 心算错误"的零依赖 Python 工具，让"一个人 + Claude Code = 一个投研团队"。

它的真正价值主张不在"能不能分析"，而在**分析质量与决策纪律的可复现性**——把一次性、随机、两面讨好的 AI 问答，变成结构一致、强制给结论、内置反偏见机制、数据可审计的投研流水线。

核心工程含量集中在三处：**多 Agent 并行编排的约定**、**LLM 幻觉与偏见的对抗机制**、**Claude Code / Codex 双客户端的 canonical-source 同步工程**。绝大部分"逻辑"以自然语言写在 Skill 里，而非代码——这既是它的轻量优势，也是它的根本局限。

---

## 二、设计动机：为什么"不能直接问 AI"

README 用一整节回答了产品的存在理由，这也是理解整个项目的钥匙。它识别出直接问 LLM 做投研的六个失效模式，并针对每个给出机制化对策：

| 失效模式 | AI Berkshire 的对策 | 机制落点 |
|---|---|---|
| 两面讨好、不给结论 | 强制输出「通过/不通过/灰色地带」+ 具体价格区间 + 分层建议（激进/稳健/保守） | Skill 输出模板 |
| 单一视角有盲点 | 四大师视角**对抗**（段说好生意，芒格问"怎么会死"；巴菲特说便宜，李录问"10年后还在吗"） | 多 Agent 角色分工 |
| 答案"看起来对但经不起推敲" | 信息丰富度 A/B/C 评级、芒格式逆向、快速否决清单、反共识检查、留白原则 | 提示词内置检查清单 |
| LLM 心算不可靠（PE 算错、币种混淆） | 所有关键计算走 `financial_rigor.py`，用 `decimal.Decimal` 精确十进制，关键数据 ≥2 源交叉验证 | Python 工具 |
| 每次输出格式/深度不一致 | 固定 Skill 模板 → 同输入同结构输出，支持横向对比与半年后复盘 | Skill 标准化 |
| 单上下文窗口信息量有限 | `/investment-team` 起 4 个独立 Agent 并行，各自联网搜索 = 4 倍信息源 + 4 个独立视角 | 后台 Agent 并行 |

**关键洞察**：这套东西本质是在对抗 LLM 的三个先天缺陷——**趋同（输出=市场共识，无 alpha）、幻觉（用"合理推测"填补空白伪装确定性）、算术不可靠**。项目的所有机制几乎都能归到这三条对抗上。这一点对任何 LLM 应用（包括量化交易的 AI 策略）都是通用的。

---

## 三、整体架构：三层设计

```
┌─────────────────────────────────────────────────────┐
│  Skill 层（20 个 .md）                                │
│  "你要做什么"的入口：深度研究/财报/行业筛选/持仓/思维工具  │
├─────────────────────────────────────────────────────┤
│  Agent 层（团队型 Skill）                             │
│  Team Lead 并行调度 4 个大师 Agent → 独立搜索/判断/挑战 │
│  → 综合研判（轻量 Skill 跳过此层，直连工具快进快出）      │
├─────────────────────────────────────────────────────┤
│  工具层（tools/*.py）                                │
│  精确计算 financial_rigor · 报告抽检 report_audit ·   │
│  数据取数 twstock/ashare/xueqiu · 回测 momentum        │
└─────────────────────────────────────────────────────┘
```

分层的巧妙之处：**不是所有任务都走重流程**。`/quality-screen`（去劣初筛）、`/news-pulse`（10 分钟异动归因）这类轻量 Skill 直连工具、不起团队；只有 `/investment-team`、`/earnings-team` 才启动 4-Agent 并行。这是明确的**成本/深度分级**——README 里专门提示"想控制成本时优先调 workflow，而不是指望完整深度研究变便宜"。

---

## 四、Skill 层：20 个入口的产品化拆解

Skill 是 `skills/*.md`，纯 Markdown 提示词，通过 `scripts/install-claude-commands.sh` 复制到 `~/.claude/commands/` 即成为斜杠命令。按场景分五类：

| 类别 | Skill | 定位 |
|---|---|---|
| 🔬 深度研究 | `investment-research` | 单公司七模块顺序执行（数据→生意→护城河→逆向→管理层→文明趋势→估值） |
| | `investment-team` | 4 Agent 并行版，最全面 |
| | `management-deep-dive` | "买股票就是买人"，管理层纵深 |
| | `private-company-research` | 未上市公司"侦探式"研究（45KB，最大的一个）|
| | `deep-company-series` | 3-8 篇长文系列（腾讯篇 ~12 万字），公众号级 |
| 📊 财报 | `earnings-review` / `earnings-team` | 只读一手财报；team 版含编辑+读者评审→可发布文章 |
| 🏭 行业筛选 | `industry-research` | 产业链全景（按环节切片）|
| | `industry-funnel` | 漏斗：全市场→≤10 家→3 家 |
| | `quality-screen` | 7 条硬指标去劣，支持个股/行业/指数/主题批量 |
| | `bottleneck-hunter` | 供应链瓶颈猎手 |
| | `investment-checklist` | 巴菲特买入前六关，10 分钟决策 |
| 📈 持仓管理 | `income-investment` / `portfolio-review` / `thesis-tracker` / `thesis-drift` / `news-pulse` | 收益股/组合/论文追踪/论文漂移/异动归因 |
| 🧠 思维工具 | `dyp-ask` / `financial-data` / `wechat-article` | 段永平问答/数据规范/公众号三 Agent 协作 |

几个体现设计成熟度的细节：

- **`investment-checklist` 的"镜子测试"**：要求用 5 句话说清买入理由，"5 句话说不完整 = 不买，没有例外"。这是把决策纪律做成硬约束，而不是软建议。
- **`industry-funnel` 的反 AI 偏好设计**：显式对抗"龙头偏好/英文偏好/故事偏好/上市偏好"，并强制列"未来 IPO 候选"以免漏掉一级市场核心玩家；终选 3 家按"组合互补性"（高确定性+中弹性+高弹性）而非打分前 3。
- **`quality-screen` 的豁免规则**：7 条硬指标 + 3 条豁免（战略投入期/主动低利润率/高周转薄利），分别对应美团、亚马逊、Costco 这类"指标难看但一流"的真实反例——说明作者是拿真实案例反复打磨过阈值的，不是拍脑袋定标准。
- **`quality-screen` / `investment-research` 都带"局限性声明"**：明确"通过筛选 ≠ 确定好，去劣是第一步不是最后一步"。

`financial-data.md` 更像一份**数据工程 SOP** 而非 Skill：按市场（美股/港股/A 股/台股）规定主/副数据源、误差分档处理（≤1% 取用、1-5% 标记差异、>5% 查原始财报）、前复权/后复权/不复权的口径纪律。这是整个体系"可信"的地基。

---

## 五、Agent 层：多 Agent 并行编排的实际机制

以旗舰 `investment-team.md` 为样本，编排流程是（关键点带我的评注）：

1. **展示团队框架 → 确认** — 4 个角色：business-analyst（段永平/商业模式）、financial-analyst（巴菲特/财务）、industry-researcher（芒格/行业）、risk-assessor（李录/风险管理层）+ team-lead（自己）。
2. **AI 可研究性评级（A/B/C）** — 决定研究策略：A 级信息充裕 → 重点做反面检验避免"正确的废话"；C 级信息稀缺 → 转"第一性原理模式"，不追求报告完整性。评级会下发给每个 Agent 影响其研究方式。
3. **⭐ WebSearch 权限预检（第一步¾）** — 这是**最见工程功力的一处**。因为团队用 `run_in_background: true` 起后台 Agent，而**后台 Agent 无法弹出交互式权限确认**；若 `WebSearch` 不在 `.claude/settings.local.json` 白名单，子 Agent 联网会被**静默拦截**，退化成仅凭训练知识作答，却仍输出一份"看起来完整、实则没联网"的伪研究（README 明确点名这是 issue #58 的最危险失败模式）。Skill 强制在起 Agent 前用 `grep` 检查白名单，未命中就停下提示用户。
4. **TeamCreate / TaskCreate ×4 / Task ×4 并行启动** — 强调"必须在同一条消息中并行调用 4 次 Task"。
5. **Agent 通过 SendMessage 向 team-lead 汇报**（消息通信，非文件协作），team-lead 实时向用户更新进度表。
6. **shutdown_request 关闭成员 → team-lead 综合最终报告 → TeamDelete 清理**。

每个 Agent 的 prompt 模板里有两条硬约束尤其值得注意：
- **两源交叉验证下沉到 Agent 级**：每个子 Agent 都被要求按 `financial-data.md` 用两个独立源取财务数据，>1% 标记。
- **"联网失败禁止伪装"**：若 WebSearch 被拦截，禁止用训练知识冒充，必须在报告顶部醒目标注"未联网、置信度降级"并告知 team-lead。

这套约定的本质：**它不是一个 Agent 框架，而是一份用自然语言写死的编排 runbook**，依赖 Claude Code 内建的 Team/Task/SendMessage 原语执行。没有代码保证时序或消息可靠性——可靠性来自提示词的严格程度 + 底层 Claude Code 运行时。

---

## 六、工具层：把"严谨性"做成可执行代码

这是整个项目**唯一真正意义上的"软件"部分**，也是它区别于"一堆提示词"的关键。

### `tools/financial_rigor.py`（~460 行，零依赖）

设计原则一句话：**所有计算用 `decimal.Decimal` 精确十进制，绝不用 `float`**（`0.1+0.2=0.3` 在金融场景不允许失败）。6 个子命令：

| 命令 | 作用 | 防的是什么 |
|---|---|---|
| `verify-market-cap` | 股价×总股本 vs 报告市值，>5% 报错、1-5% 警告 | 币种混淆（港币亿/人民币亿）、股本过期 |
| `verify-valuation` | PE/PB/ROE/FCF Yield/股息率精确算 | LLM 心算 PE 小数点错位 |
| `cross-validate` | N 源同一字段比中位数，超容差告警 | 单源数据错误 |
| `three-scenario` | 乐观/中性/悲观目标价，`(1+g)^years × PE` | 估值拍脑袋 |
| `benford` | 首位数字分布 vs Benford 定律（MAD/卡方） | 财务造假信号 |
| `calc` | 任意算术表达式精确求值 | 通用防心算 |

工程细节里能看出踩过坑：`_force_utf8_stdio()` 专门处理 Windows GBK 控制台下 `❌/⚠️/✅` 触发 `UnicodeEncodeError` 导致"最该看到的告警路径反而崩溃退出"；`calc` 用 `allowed` 字符白名单 + `eval(expr, {"__builtins__": {}}, {})` 做了基础沙箱（虽然 `eval` 仍不理想，但对纯算术表达式够用）。

### `tools/report_audit.py`（~600 行）

**准出流程**：报告写完后不直接发布，而是三步抽检——`extract` 用正则从 Markdown 抽取财务数字并随机抽样 15% → Claude 逐项从可靠源重新取数填 `fetched_value` → `verdict` 判决，任一点偏差 >1% 则【打回】修正后重审。

正则设计同样带血泪：注释明确说明所有数字捕获组必须带符号位 `_SIGN`（涵盖 ASCII 负号、Unicode 减号 U+2212、en-dash、全角±），否则 `-1.72%` 会被抓成 `1.72`，核验时符号相反产生 200% 偏差的假打回（这正是 commit `f45bb8c` 修的 bug）。

### 其余工具

`twstock_data.py`（台股 FinMind，自带市值验算）、`ashare_data.py`、`xueqiu_scraper.py`、`morningstar_fair_value.py` 取数；`momentum_backtest.py/_v2` 动量回测；`star_history_chart.py` 生成 star 曲线。`tests/` 下有 `test_financial_rigor.py` 和 `test_report_audit.py` 两个单测——**只覆盖工具，不覆盖 Skill**（Skill 是提示词，无法单测，这正是这类项目的测试盲区，ROADMAP P2 也承认了这点）。

---

## 七、反偏见 / 防幻觉机制（项目精髓）

把散落各处的机制归拢，这是最值得任何 LLM 应用借鉴的一层：

1. **信息丰富度 A/B/C 评级** — 从源头切断"资料多 = 确定性高"的幻觉。反复强调"AI 能输出的置信度 ≠ 投资真实确定性；确定性来自商业模式本身，不来自资料数量"。
2. **AI 分析置信度 vs 投资确定性分离** — 报告结尾必须区分二者：前者取决于资料量，后者取决于生意本质。
3. **多视角对抗而非分工** — 四大师被设计成互相挑战，产出"四种思维方式的碰撞"而非"四份报告拼接"。
4. **芒格式逆向 + 快速否决清单** — 强制思考"什么情况下这公司会死"；8 条红线一票否决（管理层诚信污点 → 直接否决，不管多便宜）。
5. **反共识检查** — "聪明人为什么在做空？"避免输出与市场一致的"正确的废话"。
6. **留白原则** — 数据不足时标注"灰色地带"，宁可说"不知道"，不用推测伪装确定性；C 级公司报告末尾要列"需一手验证的问题清单"。
7. **联网失败不伪装** — 前述 WebSearch 预检 + 降级标注。
8. **程序化数据校验** — 计算下沉到工具、数据两源交叉、报告 15% 抽检准出。

**这八条几乎构成了一份"如何让 LLM 少骗你"的通用清单。** 它对"生成看起来很对但没法用的答案"这一 LLM 头号风险的系统性防御，是整个项目最有转移价值的资产。

---

## 八、双客户端兼容：一处被低估的工程

项目同时服务 Claude Code 和 Codex（OpenAI）用户，采用 **canonical source + 代码生成** 的策略（`AGENTS.md` 规定）：

- `skills/*.md` 是**唯一权威源**（canonical workflow）。
- `codex-skills/*/SKILL.md` 由 `scripts/sync-codex-skills.py` 从 `skills/*.md` **自动生成**——生成器会补 YAML frontmatter（name/description）、注入一段"Codex adapter note"把 Claude 专属原语（Task/Agent/WebSearch/Bash）翻译成 Codex 对应能力（subagents/web search/shell）。
- `codex-prompts/*.md` 是可选的 Codex 斜杠命令兼容层，由 `sync-codex-prompts.py` 生成。
- CI 侧用 `--check` 模式（`sync-codex-skills.py --check`）验证生成物是否 stale，防止手改生成文件导致漂移。

**这是把"提示词"当"代码"来做版本一致性管理**——单一事实源、生成而非手维护、CI 校验漂移。对任何需要跨多个 LLM 客户端/模型分发同一套提示词的团队，这个模式直接可抄。

---

## 九、输出产物与实盘闭环

- `reports/`（37MB，200+ 目录）是主产出，按公司名建文件夹，命名有严格规范（见 `CLAUDE.md`）。覆盖腾讯、拼多多、美团、阿里、快手、MiniMax、AI 全产业链、存储行业等大量真实报告。
- `筛选公司/` 是 `quality-screen` 的批量产出（A 股召回池分 10 个行业、科创板 100 去劣）。
- `实盘记录/` 含"镜子测试"买入论文、卖出条件、实盘操作记录——**把 Skill 输出接回真实交易决策**，形成"研究→论文→纪律→复盘"闭环。
- README 高调展示实盘业绩：2024 +69.29% / 2025 +66.38%，两年累计跑赢主要指数 40+ 个百分点。**需批判看待**：这是单账户、无第三方审计、样本仅两年、且框架成型时间与业绩期高度重叠，无法归因业绩多大程度来自框架 vs 牛市 beta vs 作者个人判断（README 自己也说"精选 + 我的判断"在公众号）。作为营销叙事有效，作为方法论有效性证据不充分。

`git log` 显示项目**活跃且认真**：commit message 全中文、描述具体（"修复 report_audit 数字提取丢负号与 Windows GBK 崩溃 #84"），报告持续增补，工具持续修 bug。这不是一个 demo 仓库，是有人天天在用的活项目。

---

## 十、工程质量评估

### 优点

- **方法论密度极高**：四大师框架的拆解、豁免规则、反偏见清单，明显是长期实战打磨的产物，不是拼凑。
- **对 LLM 缺陷的系统性防御**：幻觉/趋同/算术三条对抗做到了机制化。
- **成本/深度分级清晰**：轻量 Skill 直连工具，重流程才起团队。
- **双客户端同步工程成熟**：canonical source + 生成 + CI check。
- **真实闭环**：研究→实盘→复盘，不是纸上谈兵。
- **零依赖工具**：`financial_rigor` / `report_audit` 只用 stdlib，可移植性极好。

### 局限与风险

- **核心逻辑是自然语言，不可测、不可保证**：Skill 的"必须两源验证""联网失败不伪装"全靠 LLM 自觉遵守。没有运行时强制。一旦模型不听话或提示词被截断，防御失效且难以察觉。测试只覆盖 3 个工具，覆盖不了 90% 的价值所在。
- **依赖底层运行时的隐性契约**：WebSearch 静默拦截那一类问题说明——整个体系的可靠性系于 Claude Code / Codex 的行为细节，客户端一升级就可能悄悄改变行为。
- **业绩证据不足以支撑"框架有效"**：见上节。
- **可扩展性受提示词长度限制**：`private-company-research.md` 已 45KB，`deep-company-series` 单次 12 万字，逼近上下文与注意力的实际边界。
- **数据源脆弱**：依赖 macrotrends/aastocks/东方财富等网页可访问性，无正式 API 契约（ROADMAP 也把"基于 MCP 的实时数据接入"列为未来方向）。

---

## 十一、对 okx-quant 的启示（重点）

本仓库的 `agentic/` 已经是一个多 Agent LLM 交易管线（4 分析师并行 → 多空辩论 → 交易员 → 风控否决），与 AI Berkshire 的 `investment-team` 高度同构。可直接借鉴的点：

1. **把"防幻觉八条"移植进交易 Agent**。当前 `agentic/` 有 token 预算 → abort to HOLD，但缺少 AI Berkshire 那套**信息丰富度评级 + 联网失败不伪装 + 分析置信度 vs 真实确定性分离**。对山寨币这类"信息稀缺标的"尤其关键——LLM 极易用推测填补空白给出伪装确定的 BUY 信号。可在 `agentic/prompts.py` 里加"资料充分度评级"和"数据不足时强制降级到 HOLD"。

2. **数值计算下沉到确定性工具，学 `financial_rigor.py` 的 `Decimal` 纪律**。凡是让 LLM 算仓位、盈亏比、SL/TP 距离、预期收益的地方,都应像 AI Berkshire 一样交给 Python 精确计算，只让 LLM 做判断不做算术。本仓库 `risk/`、`indicators/` 已是 pandas 计算，方向一致——要守住的边界是**永远不让 LLM 输出参与到最终下单量的算术里**。

3. **"准出抽检"思路 → 决策抽检**。`report_audit.py` 的"随机抽 15% 重新核验、偏差 >1% 打回"可类比为：对 LLM 生成的交易理由，随机抽取其引用的技术指标值，用 `indicators/cache.py` 复算比对，不一致则否决该信号。这能抓住"LLM 编造指标数值支撑结论"的幻觉。

4. **成本/深度分级**。AI Berkshire 用轻量 Skill 初筛、重团队深研。本仓库的 `ensemble` 策略已经是"传统策略先投票、只在共识时才调 LLM"——同一思路。可进一步：只对 `screener` 选出的高分标的启用 `multi_agent`，低分标的用便宜的 `llm` 单模型，与 `llm`/`llm_deep` 的 cheap/strong 分层呼应。

5. **canonical source + 生成的提示词管理**。若未来 okx-quant 的 AI 策略要同时支持多个 LLM provider（`llm/` 已支持 OpenAI/DeepSeek/Claude），可借鉴 `sync-codex-skills.py` 的模式：把提示词写成单一权威源，为各 provider 生成适配版本，CI 用 `--check` 防漂移。

6. **警惕同一个坑：自然语言约束不可靠**。AI Berkshire 的教训是——写在提示词里的"必须验证"不等于"一定验证"。交易系统比投研报告后果严重得多，凡是"必须"的约束（如 spot-only、long-only、最大仓位、真实交易需 `I UNDERSTAND`）都应像本仓库现在这样**用代码强制**（`risk/RiskManager`、`state.py` 的白名单校验），而不是靠 Prompt 自觉。这一点本仓库做得比 AI Berkshire 更稳健，应继续保持。

---

## 十一·五、落地：agentic/ 管线加固（已实施）

第十一节的建议不是纸上谈兵——其中可直接落地的部分已在本仓库的 `okx_quant/agentic/` 实施。核心思路贯穿始终：**把 AI Berkshire 的反偏见方法论学过来，但每一条"必须"的约束用代码钉死，而不是写在 Prompt 里祈祷模型遵守。**

### 改动一览

| # | 借鉴的 AI Berkshire 机制 | 落点 | 性质 |
|---|---|---|---|
| 1 | 置信度门（决策纪律硬约束） | `pipeline.py` `run()` | 防御纵深 |
| 2 | 风控只减不增（留白/保守原则） | `pipeline.py` `run()` | **修真漏洞** |
| 3 | 信息丰富度 A/B/C 评级 | 新增 `data_quality.py` | 新能力 |
| 4 | 留白原则（数据不足不伪装） | `prompts.py` | 防幻觉 |
| 5 | thesis-tracker（论点可复盘） | 新增 `thesis.py` + wrapper | 新能力 |

### 逐条说明

**1. 置信度阈值下沉进 pipeline（防御纵深）。** 原先 `confidence_threshold` 只在策略 wrapper（`multi_agent_strategy.py`）里生效，`AgenticConfig.confidence_threshold` 则是无人读取的死配置。现在 `pipeline.run()` 自身也强制：BUY 置信度低于阈值 → 直接降级 HOLD。直连 pipeline 的调用方（绕过 wrapper）也受保护，死配置被激活。

**2. 风控"只能收紧、不能放大"从 Prompt 提升为代码（真漏洞修复）。** `RISK_MANAGER_SYSTEM` 一直写着"may reduce size_pct but never increase / tighten stop_loss never loosen",但 `RiskManagerAgent.review` 只是原样返回 LLM 的 JSON——一个抽风的风控模型可以把仓位从 0.3 改成 0.9。现在 pipeline 用代码钉死：`size_pct = min(交易员, 风控)`、`stop_loss_pct = min(...)`（不得放宽）。这正是 AI Berkshire 那条教训在交易系统上的兑现——风控是最后一道保命闸，它的边界必须由代码而非它自己的自觉来保证。

**3. 数据充分度评级 + 置信度天花板（对标 A/B/C）。** 新增 `assess_data_sufficiency(df)`：用**确定性代码**（bar 数、零成交量占比、无振幅占比、价格停滞占比）给标的定级 A/B/C，越差 `confidence_ceiling` 越低。pipeline 用它压制置信度——薄数据（山寨币最常见）不允许高信心，C 级天花板 0.4 低于默认阈值 0.6 时会直接 HOLD。这切断了"数据稀薄 → LLM 用推测填空 → 输出伪装确定的 BUY"这条最危险的路径，对应 AI Berkshire"确定性来自生意本质、不来自资料数量"的核心洞察。

**4. 缺失指标渲染为 `N/A` 而非伪装的 `0`（留白原则）。** 原先 `indicators.get('rsi', 0)` 会把缺失/NaN 的指标显示成 `0`，被模型误读为"极度超卖"等真实信号。现在 `_fmt()` 统一渲染缺失值为 `N/A`，并在三个分析师 system prompt 里明确指示"N/A 表示数据缺失，不得当 0、不得据此推断信号，应据此降低置信度"。

**5. 建仓论点快照（thesis-tracker 思路）。** pipeline 现在把完整决策证据（4 位分析师报告 + 多空辩论全文 + 交易员/风控理由 + 数据质量评级）汇入返回结果的 `evidence` 字段；wrapper 在 BUY 时落盘为 `logs/thesis/thesis_{inst}_{ts}.json`（含路径穿越防护、落盘失败不影响交易）。这把黑箱 LLM 决策变成可回放的序列——平仓复盘时能直接对照"当初买它的理由现在还成立吗",也是回答"业绩多少来自 alpha、多少来自 beta"的前提。为避免灌爆决策日志 CSV，体积较大的 `evidence` 在入库前被剥离。

### 测试

新增 `tests/test_agentic_hardening.py`（14 项，`unit` marker），用一个按 system prompt 路由的 `FakeLLM` 覆盖：低置信度 BUY 被 pipeline 拦为 HOLD、风控无法放大仓位/放宽止损、数据质量天花板压制置信度、A/B/C 评级（含空 DataFrame）、缺失指标渲染为 N/A、论点快照落盘与路径穿越防护。新测试文件已在 `scripts/non_live_validation.py` 的非实盘清单注册。

### 边界（诚实说明）

这些改动强化的是**多 Agent 管线内部**的决策质量与约束刚性；真正把最终下单量、SL/TP 钉死的仍是 `risk/RiskManager` 与执行层——这层本来就比 AI Berkshire 稳健，未动。AI Berkshire 其余机制（联网失败降级、多源交叉验证、报告抽检准出）对应到交易场景需要外部行情/新闻源的可信度校验，属于后续可做的方向，尚未实施。

---

## 十二、总结

AI Berkshire 是"**用提示词工程 + 极简校验工具，把一位资深价值投资者的思维流程复制成可复现流水线**"的优秀范本。它的技术含量不在算法，而在：(a) 对 LLM 幻觉/趋同/算术三大缺陷的系统性机制化对抗，(b) 多 Agent 并行的自然语言 runbook 编排，(c) canonical-source 的双客户端同步工程。

它最大的软肋——核心逻辑是不可测的自然语言，可靠性系于模型自觉与底层运行时——恰恰是所有"重提示词、轻代码"的 LLM 应用的共同宿命。对 okx-quant 这类**后果严重**的系统，正确的取舍是：**把 AI Berkshire 的反偏见方法论学过来，但把每一条"必须"的约束用代码钉死，而不是写在 Prompt 里祈祷模型遵守。**
