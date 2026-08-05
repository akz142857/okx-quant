"""多 Agent 策略 — 编排管线

AgenticPipeline 协调 8 个 Agent 的完整流程：
    分析师并行 → 多空辩论 → 交易员决策 → 风控审核
"""

import logging
import math
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from okx_quant.llm.client import LLMClient

from .agents import (
    BearResearcher,
    BullResearcher,
    FundamentalsAnalyst,
    NewsAnalyst,
    RiskManagerAgent,
    SentimentAnalyst,
    TechnicalAnalyst,
    TraderAgent,
)
from .config import AgenticConfig
from .token_tracker import TokenTracker

logger = logging.getLogger(__name__)


def _as_float(value, default: float = 0.0) -> float:
    """把 LLM 返回的数值字段稳健地转成 float，无法解析时用 default。"""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    if f != f:  # NaN
        return default
    return f


def _clamp01(value: float) -> float:
    """约束到 [0, 1]。"""
    return max(0.0, min(1.0, value))


def _clamp(value: float, lo: float, hi: float) -> float:
    """约束到 [lo, hi]。"""
    return max(lo, min(hi, value))


class AgenticPipeline:
    """多 Agent 交易管线

    Args:
        quick_llm: 廉价模型客户端（用于 4 个分析师）
        deep_llm:  强力模型客户端（用于辩论 + 决策）
        config:    管线配置
    """

    def __init__(
        self,
        quick_llm: LLMClient,
        deep_llm: LLMClient,
        config: AgenticConfig | None = None,
    ):
        self.config = config or AgenticConfig()
        self.tracker = TokenTracker()

        # 分析师 — 使用 cheap model
        self.technical = TechnicalAnalyst("technical", quick_llm, self.tracker)
        self.sentiment = SentimentAnalyst("sentiment", quick_llm, self.tracker)
        self.news_analyst = NewsAnalyst("news", quick_llm, self.tracker)
        self.fundamentals = FundamentalsAnalyst("fundamentals", quick_llm, self.tracker)

        # 辩论 + 决策 — 使用 strong model
        self.bull = BullResearcher("bull", deep_llm, self.tracker)
        self.bear = BearResearcher("bear", deep_llm, self.tracker)
        self.trader = TraderAgent("trader", deep_llm, self.tracker)
        self.risk_mgr = RiskManagerAgent("risk_mgr", deep_llm, self.tracker)

    def run(
        self,
        indicators: dict,
        recent_candles: str,
        inst_id: str,
        news_text: str = "",
        portfolio_state: dict | None = None,
        data_quality: dict | None = None,
    ) -> dict:
        """执行完整 pipeline

        Args:
            indicators: 技术指标字典（由 strategy wrapper 构建）
            recent_candles: 格式化后的近期 K 线文本
            inst_id: 交易对 ID
            news_text: 格式化后的新闻文本
            portfolio_state: 当前组合状态（equity, drawdown_pct 等）
            data_quality: 数据充分度评级（含 confidence_ceiling），薄数据会压低
                置信度天花板，见 data_quality.assess_data_sufficiency

        Returns:
            决策字典: {signal, confidence, size_pct, stop_loss_pct, take_profit_pct,
            reason, data_quality, evidence}。失败时返回 HOLD 决策。
        """
        portfolio_state = portfolio_state or {
            "equity": 10000, "drawdown_pct": 0, "open_positions": 0,
            "max_drawdown_pct": 15,
        }

        # 会话级上限在**发起任何调用之前**检查，避免"已经超预算了还照跑一遍分析师
        # 再返回 HOLD"。per-decision 上限则从这里重新计数。
        if self._over_session_budget():
            return self._hold("会话 Token 预算超限，未发起调用")
        self.tracker.begin_run()

        # ------------------------------------------------------------------
        # Step 1: 并行运行 4 个分析师
        # ------------------------------------------------------------------
        logger.info("[Pipeline] Step 1/4: 运行分析师...")
        analyst_reports = self._run_analysts(indicators, recent_candles, inst_id, news_text)

        if not any(analyst_reports.values()):
            logger.warning("[Pipeline] 所有分析师返回空结果")
            return self._hold("所有分析师调用失败")

        if self._over_budget("分析师阶段"):
            return self._hold("Token 预算超限，提前终止")

        # ------------------------------------------------------------------
        # Step 2: 多空辩论（N 轮）
        # ------------------------------------------------------------------
        logger.info("[Pipeline] Step 2/4: 多空辩论 (%d 轮)...", self.config.debate_rounds)
        debate_transcript = self._run_debate(analyst_reports)

        if self._over_budget("辩论阶段"):
            return self._hold("Token 预算超限，提前终止")

        # ------------------------------------------------------------------
        # Step 3: 交易员决策
        # ------------------------------------------------------------------
        logger.info("[Pipeline] Step 3/4: 交易员决策...")
        decision = self.trader.decide(analyst_reports, debate_transcript, inst_id)

        if decision is None:
            logger.warning("[Pipeline] 交易员返回空决策")
            return self._hold("交易员决策解析失败")

        if self._over_budget("交易员阶段"):
            return self._hold("Token 预算超限，提前终止")

        # ------------------------------------------------------------------
        # Step 4: 风控审核
        # ------------------------------------------------------------------
        logger.info("[Pipeline] Step 4/4: 风控审核...")
        final = self.risk_mgr.review(decision, portfolio_state)

        if final is None:
            logger.warning("[Pipeline] 风控审核返回空结果，保守降级为 HOLD")
            return self._hold("风控审核失败，保守降级")

        evidence = {
            "analyst_reports": analyst_reports,
            "debate": debate_transcript,
            "trader": decision,
            "risk": final,
            "data_quality": data_quality,
        }

        sig = str(final.get("signal", "HOLD")).upper()
        if sig not in ("BUY", "SELL", "HOLD"):
            sig = "HOLD"
        confidence = _as_float(final.get("confidence"), 0.0)

        # ------------------------------------------------------------------
        # 硬约束（代码强制，不依赖 prompt 自觉）
        # ------------------------------------------------------------------
        # (1) 数据质量置信度天花板：薄数据不允许高信心
        if data_quality:
            ceiling = _as_float(data_quality.get("confidence_ceiling"), 1.0)
            if confidence > ceiling:
                logger.info(
                    "[Pipeline] 置信度 %.2f 被数据质量(%s级)限制到 %.2f",
                    confidence, data_quality.get("grade", "?"), ceiling,
                )
                confidence = ceiling

        # (2) 置信度阈值：BUY 必须过线，否则降级 HOLD（pipeline 自包含，不只靠 wrapper）
        #     SELL 是离场，出于保命偏向不因低置信度被拦。
        if sig == "BUY" and confidence < self.config.confidence_threshold:
            hold = self._hold(
                f"置信度 {confidence:.2f} < 阈值 {self.config.confidence_threshold}"
            )
            hold["confidence"] = confidence
            hold["data_quality"] = data_quality
            hold["evidence"] = evidence
            return hold

        # (3) 风控只能收紧、不能放大：仓位取更小、止损取更紧（更小的 pct = 更近的止损）
        proposed_size = _clamp01(_as_float(decision.get("size_pct"), 0.0))
        reviewed_size = _clamp01(_as_float(final.get("size_pct"), proposed_size))
        final_size = min(proposed_size, reviewed_size) if sig == "BUY" else 0.0

        # (4) 止损/止盈距离的代码级夹取：min() 只保证"风控不得放宽"，不构成边界。
        #     LLM 给出 0.5 等于把止损挂在入场价 50% 之下（形同没有止损），给出
        #     0.0005 则进场即被扫——两者都能被上游不可信文本影响。size_pct 早有
        #     clamp，这里把同样的待遇补给 SL/TP。
        proposed_sl = _as_float(decision.get("stop_loss_pct"), 0.02)
        reviewed_sl = _as_float(final.get("stop_loss_pct"), proposed_sl)
        final_sl = min(proposed_sl, reviewed_sl)  # 风控不得把止损放宽
        clamped_sl = _clamp(
            final_sl, self.config.min_stop_loss_pct, self.config.max_stop_loss_pct
        )
        if clamped_sl != final_sl:
            logger.warning(
                "[Pipeline] stop_loss_pct %.4f 越界，夹取到 %.4f（允许区间 %.4f–%.4f）",
                final_sl, clamped_sl,
                self.config.min_stop_loss_pct, self.config.max_stop_loss_pct,
            )
        final_sl = clamped_sl

        final_tp = _as_float(final.get("take_profit_pct"), 0.04)
        clamped_tp = _clamp(
            final_tp, self.config.min_take_profit_pct, self.config.max_take_profit_pct
        )
        if clamped_tp != final_tp:
            logger.warning(
                "[Pipeline] take_profit_pct %.4f 越界，夹取到 %.4f（允许区间 %.4f–%.4f）",
                final_tp, clamped_tp,
                self.config.min_take_profit_pct, self.config.max_take_profit_pct,
            )
        final_tp = clamped_tp

        result = {
            "signal": sig,
            "confidence": confidence,
            "size_pct": final_size,
            "stop_loss_pct": final_sl,
            "take_profit_pct": final_tp,
            "reason": final.get("reason", "多Agent决策"),
            "data_quality": data_quality,
            "evidence": evidence,
        }

        logger.info(
            "[Pipeline] 最终决策: %s (置信度=%.2f, 仓位=%.2f)",
            result["signal"], result["confidence"], result["size_pct"],
        )
        return result

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _build_analyst_tasks(
        self, indicators: dict, recent_candles: str, inst_id: str, news_text: str,
    ) -> list[tuple[str, Callable[[], str]]]:
        """构建 (display_name, callable) 任务表 —— 新增分析师只改这里

        display_name 是**唯一**的 key 来源：成功、异常、超时三条路径都用它。
        旧实现用 ``fn.__name__`` 反查一张手写的映射表，只加 task 不更新映射，
        失败路径就会退化成 ``_derivatives`` 这类内部函数名，与成功路径返回的
        ``"Derivatives Analysis"`` 形成两套 key，污染下游 prompt 的小节标题
        和 thesis evidence 的键。
        """
        return [
            ("Technical Analysis",
             lambda: self.technical.analyze(indicators, recent_candles)),
            ("Sentiment Analysis",
             lambda: self.sentiment.analyze(indicators, recent_candles)),
            ("News Analysis",
             lambda: self.news_analyst.analyze(news_text, inst_id)),
            ("Fundamentals Analysis",
             lambda: self.fundamentals.analyze(indicators)),
        ]

    def _run_analysts(
        self, indicators: dict, recent_candles: str, inst_id: str, news_text: str,
    ) -> dict[str, str]:
        """并行运行全部分析师，返回 {display_name: report}"""
        reports: dict[str, str] = {}
        timeout = self.config.analyst_timeout
        tasks = self._build_analyst_tasks(indicators, recent_candles, inst_id, news_text)
        if not tasks:
            return reports

        # 并发度默认等于任务数（全部并行）。写死 4 的话，分析师加到 8 个就会分两
        # 波跑，墙钟时间翻倍。
        configured = self.config.analyst_max_workers
        max_workers = len(tasks) if configured <= 0 else min(configured, len(tasks))

        # as_completed 的 timeout 是**所有** future 共享的墙钟预算，而
        # future.result(timeout) 才是单个的。任务数 > max_workers 时排队时间会
        # 计入这个共享预算：8 个任务 / 4 worker 最坏要 2×timeout，若只给
        # timeout+5，后半批必然被判"超时"——哪怕每个 LLM 调用本身都没超时。
        # 因此按实际波次数放大预算。注意 ThreadPoolExecutor 退出时 shutdown(wait=True)
        # 本来就要等在跑的任务收尾（真正的时间上界是 llm.timeout），所以预算配小了
        # 并不能提前返回，只会把**已经付过钱、也确实拿到了**的响应标成"超时"丢掉。
        waves = math.ceil(len(tasks) / max_workers)
        wall_clock_budget = timeout * waves + 5

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fn): display for display, fn in tasks}
            try:
                # as_completed 只产出已完成的 future，result() 不会再阻塞
                for future in as_completed(futures, timeout=wall_clock_budget):
                    display = futures[future]
                    try:
                        report = future.result()
                        reports[display] = report if report else "(分析师未返回结果)"
                    except Exception as e:  # noqa: BLE001
                        logger.warning("[Pipeline] 分析师 %s 异常: %s", display, e)
                        reports[display] = "(分析师调用失败)"
            except TimeoutError:
                # 部分分析师超时，保留已完成的结果
                for future, display in futures.items():
                    if display in reports:
                        continue
                    future.cancel()  # 尚未开跑的任务直接取消，不再白花 token
                    logger.warning("[Pipeline] 分析师 %s 超时", display)
                    reports[display] = "(分析师超时)"

        return reports

    def _run_debate(self, analyst_reports: dict[str, str]) -> str:
        """运行多轮多空辩论，返回辩论记录

        并行化：每一轮内 Bull/Bear 都只读对手"上一轮"的论点，因此可并行
        发起。相比原先 Bear 等待 Bull 当轮结果的串行实现，辩论阶段墙钟
        时间减半（每轮 ~50%）。语义略微改变：原先 Bear 反驳 Bull 当轮
        最新论点，现在反驳上一轮论点——这在多轮辩论中仍然合理。
        """
        transcript_parts: list[str] = []
        bull_prev = ""
        bear_prev = ""

        for round_num in range(1, self.config.debate_rounds + 1):
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix="debate") as ex:
                bull_future = ex.submit(
                    self.bull.argue, analyst_reports, bear_prev, round_num,
                )
                bear_future = ex.submit(
                    self.bear.argue, analyst_reports, bull_prev, round_num,
                )
                try:
                    bull_arg = bull_future.result(timeout=self.config.debate_timeout)
                except Exception as e:  # noqa: BLE001
                    logger.warning("[Pipeline] Bull round %d 异常: %s", round_num, e)
                    bull_arg = "(Bull 研究员调用失败)"
                try:
                    bear_arg = bear_future.result(timeout=self.config.debate_timeout)
                except Exception as e:  # noqa: BLE001
                    logger.warning("[Pipeline] Bear round %d 异常: %s", round_num, e)
                    bear_arg = "(Bear 研究员调用失败)"

            transcript_parts.append(f"=== Round {round_num} — Bull ===\n{bull_arg}")
            transcript_parts.append(f"=== Round {round_num} — Bear ===\n{bear_arg}")
            bull_prev, bear_prev = bull_arg, bear_arg

        return "\n\n".join(transcript_parts)

    def _over_session_budget(self) -> bool:
        """会话级（进程生命周期累计）预算是否已耗尽"""
        cap = self.config.max_total_tokens
        if cap <= 0:
            return False
        used = self.tracker.lifetime_tokens
        if used >= cap:
            logger.warning("[Pipeline] 会话 Token 用量 %d 已达上限 %d", used, cap)
            return True
        return False

    def _over_budget(self, stage: str) -> bool:
        """检查本次决策的 token 用量是否超过预算上限

        两道闸：per-decision（每次决策重新计数，防单次失控）与会话级
        （进程累计，防长期烧钱）。前者用 run-scoped 计数，因此不会出现
        "跑几次之后永久触发、此后每个 tick 都直接 HOLD"。
        """
        decision_cap = self.config.max_decision_tokens
        if decision_cap > 0:
            used = self.tracker.run_tokens
            if used > decision_cap:
                logger.warning(
                    "[Pipeline] 本次决策 Token 用量 %d 超过单次上限 %d（%s后）",
                    used, decision_cap, stage,
                )
                return True
        if self._over_session_budget():
            logger.warning("[Pipeline] 会话 Token 预算在%s后耗尽", stage)
            return True
        return False

    @staticmethod
    def _hold(reason: str) -> dict:
        """构建 HOLD 默认返回"""
        return {
            "signal": "HOLD",
            "confidence": 0.0,
            "size_pct": 0.0,
            "stop_loss_pct": 0.0,
            "take_profit_pct": 0.0,
            "reason": reason,
            "data_quality": None,
            "evidence": None,
        }
