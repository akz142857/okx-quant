# LLM 策略的成本、超时与安全控制

> 适用策略：`llm` / `ensemble` / `multi_agent`
> 相关代码：`okx_quant/llm/cache.py`、`okx_quant/agentic/`、`okx_quant/utils/untrusted.py`
> 背景：[`docs/agentic-brain-roadmap-review.md`](agentic-brain-roadmap-review.md) §5.4

传统策略是纯 pandas 计算，跑一次几毫秒、零边际成本。LLM 策略不是——一次
`multi_agent` 决策要串起 4 个分析师 + N 轮辩论 + 交易员 + 风控共 10 次 LLM 调用，
典型 35–70 秒、约 $0.09。**它的三个失效模式（钱、时间、注入）都不会自己暴露：
超时不会报错只会静默 HOLD，预算耗尽不会报错只会静默 HOLD，注入成功了看起来就
是一个普通的 BUY。** 这份文档说明系统里为此设的几道闸怎么用。

---

## 1. 速查表

| 配置项 | 位置 | 默认 | 作用 |
|---|---|---|---|
| `executor.signal_timeout_s` | `config.yaml` | **留空 = 自动推导** | 单次 `generate_signal` 的硬超时 |
| `multi_agent.max_decision_tokens` | `config.yaml` | 120000（代码内） | **单次决策**的 token 上限 |
| `multi_agent.max_total_tokens` | `config.yaml` | 0（不限） | **会话级**（进程累计）token 上限 |
| `multi_agent.analyst_max_workers` | `config.yaml` | 0 = 全部并行 | 分析师并发度 |
| `multi_agent.min/max_stop_loss_pct` | `config.yaml` | 0.005 / 0.10 | LLM 输出止损距离的**硬边界** |
| `multi_agent.min/max_take_profit_pct` | `config.yaml` | 0.005 / 0.50 | LLM 输出止盈距离的**硬边界** |
| `--llm-cache DIR` | `scripts/backtest_grid.py` | 关闭 | LLM record/replay 缓存 |

---

## 2. 信号超时（`executor.signal_timeout_s`）

### 为什么不能沿用默认的 20 秒

`utils/timeout.py` 的 `run_with_timeout` **无法杀死被包裹的线程**（Python 的限制，
该文件开头就写明了）。超时只是让主循环先返回 HOLD，**后台线程仍会把全部 10 次
LLM 调用跑完并计费**。

所以对 `multi_agent`（典型 35–70s）配 20s 的效果是：每一次决策都付全款、拿 HOLD，
而且日志里看不出异常——只有一行"策略调用超时"。

### 现在的行为

```yaml
executor:
  # signal_timeout_s: 20    # 留空/注释掉 = 自动推导
  state_dir: "state"
```

- **显式配置** → 一律尊重你的值，不做任何调整。
- **未配置 + 传统策略** → 20s（原默认，对纯计算策略是合适的保护）。
- **未配置 + LLM 类策略** → 按各阶段超时上限推导：

  ```
  llm.timeout + (multi_agent.debate_rounds + 2) × llm_deep.timeout
  ```

  默认参数下 = `30 + (2+2) × 60` = **270s**，启动时会打印一行说明。

推导用的是**上限**而非典型值，因为超时的作用是"防挂死"，不是"卡性能"。

### 与 `--interval` 的关系

`--interval` 默认 60s，而一次 multi_agent 决策典型 35–70s。两者接近意味着上一
tick 的后台线程可能与下一 tick 重叠。跑 LLM 策略时建议把 `--interval` 提到与 bar
周期同量级（4H bar 用 `--interval 300` 之类），或启用 `production.enabled`
（按收盘 K 线去重，不会同一根重复决策）。

另外注意 `utils/timeout.py` 的在飞槽位 `_MAX_IN_FLIGHT = max(8, min(32, cpu×2))`：
1–2 vCPU 的小机器上就是 8。5 个 pair × 每次决策 10+ 个在飞调用会耗尽槽位，抛
`超时调用槽已耗尽，拒绝排队`，同样降级为 HOLD。**多 pair + LLM 策略请用 ≥4 核。**

---

## 3. Token 预算（两道闸）

```yaml
multi_agent:
  max_total_tokens: 0            # 会话级（进程累计），0 = 不限
  # max_decision_tokens: 120000  # 单次决策，不配则用代码内默认值
```

两者**语义不同，不要混用**：

| | `max_total_tokens` | `max_decision_tokens` |
|---|---|---|
| 计数范围 | 进程生命周期累计 | 每次决策重新计数 |
| 触发后 | 该进程后续**永久** HOLD | 只影响当次决策 |
| 检查时机 | 每次决策**发起任何调用之前** | 每个阶段之后 |
| 默认 | 0（不限） | 120000 |
| 用途 | 给一次运行封顶总开销 | 防单次决策失控 |

设计要点：

- 会话级上限在**发起调用之前**检查，超限后不会再产生任何费用。
- 单次上限用 run-scoped 计数，所以不会出现"跑几次之后永久触发、此后每个 tick
  都直接 HOLD"——那正是把 lifetime 计数当"单次上限"用的老毛病。
- 单次上限的默认值写在 `AgenticConfig` 里，**不依赖 yaml 是否配置**。`config.yaml`
  里 `max_total_tokens: 0` 意味着开箱即用没有会话级上限，单次上限是唯一兜底。

### 看清钱花在哪

`TokenTracker` 按 quick / deep 分层统计。deep（辩论 + 交易员 + 风控）大约占
token 的 83%、但占**费用的 98%**——只看总 token 数看不见这个价差。

```python
summary = strategy.get_usage_summary()          # 总量（回测报表也用它）
per_tier = pipeline.tracker.summary()["per_tier_tokens"]
# {"quick": 3400, "deep": 17100}
```

成本主要由**辩论层的重发**驱动，不是分析师数量：分析师报告会被 Bull/Bear 各重发
`debate_rounds` 轮、再被交易员重发一次。降成本最有效的两个旋钮是
`debate_rounds`（2 → 1 直接砍掉一半 deep 调用）和分析师报告的长度。

---

## 4. 止损/止盈的硬边界

```yaml
multi_agent:
  # min_stop_loss_pct: 0.005
  # max_stop_loss_pct: 0.10
  # min_take_profit_pct: 0.005
  # max_take_profit_pct: 0.50
```

管线原先只对 `stop_loss_pct` 做 `min(交易员, 风控)`——那保证的是"风控不得放宽"，
**不是边界**。LLM 给出 `0.5` 等于把止损挂在入场价 50% 之下（在日亏上限之内形同
没有止损），给出 `0.0005` 则进场即被扫。而这两个数都可能被上游不可信文本影响。

现在越界会被夹取并打 WARNING：

```
[Pipeline] stop_loss_pct 0.5000 越界，夹取到 0.1000（允许区间 0.0050–0.1000）
```

调这两个边界时记住它们是**硬约束不是建议值**：放宽 `max_stop_loss_pct` 等于放大
单笔最大亏损。`size_pct` 一直有 `[0,1]` clamp，这次是把同等待遇补给 SL/TP。

> `production.enabled: true` 时生产内核还有一层（`risk_service` 强制
> `0 < stop < price` 且 `expected_loss > max_order_loss_usdt` 就拒单）。但它是
> **拒绝**而非夹取，且 `production.enabled: false` 的单 trader 路径没有这层。

---

## 5. 分析师并发度

```yaml
multi_agent:
  # analyst_max_workers: 0    # 0 = 全部并行（默认）
```

默认等于分析师数量，即全部并行。钉成小于分析师数的值会让它们分多波跑：墙钟时间
成倍增加，并挤占 `as_completed` 的共享超时预算——**已经付过钱、也确实拿到了的
响应会被标成"超时"丢掉**。除非你在限制并发连接数，否则保持 0。

新增分析师只需改 `AgenticPipeline._build_analyst_tasks()` 返回的任务表：

```python
def _build_analyst_tasks(self, indicators, recent_candles, inst_id, news_text):
    return [
        ("Technical Analysis", lambda: self.technical.analyze(indicators, recent_candles)),
        ...
        ("Derivatives Analysis", lambda: self.derivatives.analyze(deriv)),   # 新增
    ]
```

`display_name` 是唯一 key 来源，成功 / 异常 / 超时三条路径共用，不需要再同步任何
映射表；并发度与超时预算会自动跟随任务数。

---

## 6. LLM record/replay 缓存

### 用途

让同一份评估集**零成本重复跑**、可离线复现。第一次真实调用并落盘，之后同样的
请求直接命中。

### 在回测网格里用

```bash
uv run python scripts/backtest_grid.py \
  --strategies multi_agent,ensemble,adaptive,bollinger,ma_cross \
  --instruments BTC-USDT,ETH-USDT,SOL-USDT \
  --bars 1D --days 365 \
  --llm-cache state/llm_cache
```

首轮真实付费，之后重跑同一组合免费。

### 在代码里用

```python
from okx_quant.llm import LLMCache, LLMClient, LLMConfig

cache = LLMCache("state/llm_cache")            # mode="rw"（默认）
client = LLMCache.wrap(LLMClient(cfg), cache)
client.chat(system, user)
cache.log_stats()      # 命中 12 / 未命中 3（命中率 80.0%），写入 3，跳过失败响应 0
```

三种模式：

| mode | 行为 |
|---|---|
| `rw`（默认） | 命中即用；未命中真实调用并落盘 |
| `replay` | 只读。**未命中直接返回错误响应，绝不发网络请求**——用于保证"离线复现"不会悄悄变成付费重跑 |
| `off` | 完全旁路，`wrap()` 原样返回客户端 |

### 三条必须知道的边界

1. **缓存只降本，不消除非确定性。** `temperature` 默认 0.3（非 0），缓存冻结的是
   **某一次采样**，不是期望表现。要测期望必须同一输入跑 N 次报告分布——那与缓存
   的省钱目的直接冲突，需要显式取舍。
2. **prompt 一改就全 miss。** 任何 prompt / 框架改动都会击穿缓存，而"改动前 vs
   改动后"恰恰是唯一有意义的对比场景。缓存能覆盖 baseline 侧与回归重跑，**变更侧
   必须真实付费**——做预算时不能把这笔钱算掉。
3. **key 覆盖所有影响输出的入参**：provider / model / base_url / temperature /
   max_tokens / system / user。**不含 `api_key`**（同一份缓存可跨密钥复用，且密钥
   绝不进磁盘）。失败响应不落盘，避免把一次网络抖动永久固化成"这个输入就是失败的"。

缓存目录结构（两级分片）：`state/llm_cache/ab/ab3f....json`。可以直接删目录重来。

---

## 7. 提示注入防线

外部文本（新闻）与由它派生的文本（Agent 报告）在**每一跳**都要重新包裹哨兵。
`okx_quant/utils/untrusted.py` 提供两个包装器：

| 函数 | 哨兵 | 用于 |
|---|---|---|
| `wrap_untrusted()` | `[UNTRUSTED_CONTENT]` | 第一方之外的原始文本（新闻标题） |
| `wrap_derived()` | `[AGENT_REPORT]` | 读过不可信文本的 Agent 写出来的文本 |

两者都做：NFKC 归一化（全宽括号等同处理）→ 剥离零宽/方向控制字符 → 正则中和伪
哨兵 → 长度硬截断（4096 / 8192 字符）。

**为什么派生内容也要包**：新闻分析师的**输入**有哨兵保护，但它的**输出**会被拼进
辩论者和交易员的 prompt。若不重新包裹，任何在摘要里存活下来的指令都会以"可信
内容"的身份出现在真正产出 `signal` / `size_pct` / `stop_loss_pct` 的那个 Agent
面前。Bull / Bear / Trader / Risk 四个 system prompt 现在都带 SECURITY 条款。

> 输入端加固只是第一层。LLM 没有硬边界，真正兜底的是 output 端：置信度门槛 +
> `size_pct` / `stop_loss_pct` 的代码级 clamp + 风控校验 + 生产内核拒单。

写新的 fetcher 时：**任何非第一方文本进 prompt 前必须过 `wrap_untrusted()`**，
任何 Agent 输出再次进 prompt 前必须过 `wrap_derived()`。

---

## 8. 排查：为什么 `multi_agent` 总是 HOLD

按出现频率排序，看 `reason` 字段就能定位：

| `reason` | 原因 | 处理 |
|---|---|---|
| `策略调用超时 (>20s)` | `signal_timeout_s` 配得太小 | 注释掉让它自动推导，或显式配 ≥180 |
| `LLM token 预算已达上限` | wrapper 层的会话预算耗尽（`multi_agent.max_total_tokens`） | 重启进程或调大/设 0。这一层在**任何调用之前**短路，不会继续花钱 |
| `会话 Token 预算超限，未发起调用` | 同上，pipeline 层的同一道闸（直接使用 `AgenticPipeline` 时触发） | 同上 |
| `Token 预算超限，提前终止` | 单次决策超过 `max_decision_tokens` | 调大，或降 `debate_rounds`。注意这次决策**已经付了部分费用** |
| `置信度 0.XX < 阈值 0.6` | 正常的保守行为 | 想更激进就降 `confidence_threshold`，但这是最后一道信心闸 |
| `所有分析师调用失败` | LLM key / 网络 / 限流 | 看日志里 `[technical] LLM 调用失败: ...` |
| `交易员决策解析失败` / `风控审核失败，保守降级` | 模型没返回合法 JSON | 多为模型能力或 `max_tokens` 截断所致；调大 `llm_deep.max_tokens` |
| `数据不足` | K 线 < 30 根 | 实盘固定取 100 根，出现此情况说明该交易对历史太短或周期过大——换 `--bar` 或换交易对；回测则加大 `--days` |
| 置信度被压到阈值以下 | 数据质量评级 B/C 压了天花板 | 看 `data_quality.grade`，薄数据本来就该低信心 |

另外查这两个：

```bash
grep "分析师超时\|越界，夹取到\|Token 用量" logs/quant.log
```

---

## 9. 相关文档

- [多 Agent 方案评审报告](agentic-brain-roadmap-review.md) —— 这些控制项的来龙去脉
- [最小证伪实验协议](agentic-min-experiment.md) —— 用缓存跑 LLM vs 传统策略对照
- [多 Agent 设计文档](../Agent.md)
- [系统使用手册](SYSTEM_USAGE_GUIDE.md)
