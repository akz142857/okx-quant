"""多 Agent 策略 — 编排管线

AgenticPipeline 协调 8 个 Agent 的完整流程：
    分析师并行 → 多空辩论 → 交易员决策 → 风控审核
"""

import logging
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

        proposed_sl = _as_float(decision.get("stop_loss_pct"), 0.02)
        reviewed_sl = _as_float(final.get("stop_loss_pct"), proposed_sl)
        final_sl = min(proposed_sl, reviewed_sl)  # 风控不得把止损放宽

        result = {
            "signal": sig,
            "confidence": confidence,
            "size_pct": final_size,
            "stop_loss_pct": final_sl,
            "take_profit_pct": _as_float(final.get("take_profit_pct"), 0.04),
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

    def _run_analysts(
        self, indicators: dict, recent_candles: str, inst_id: str, news_text: str,
    ) -> dict[str, str]:
        """并行运行 4 个分析师，返回 {name: report}"""
        reports: dict[str, str] = {}
        timeout = self.config.analyst_timeout

        # 每个 task 返回 (display_name, report)，display_name 用作 dict key
        _DISPLAY_NAMES = {
            "_technical": "Technical Analysis",
            "_sentiment": "Sentiment Analysis",
            "_news": "News Analysis",
            "_fundamentals": "Fundamentals Analysis",
        }

        def _technical():
            return "Technical Analysis", self.technical.analyze(indicators, recent_candles)

        def _sentiment():
            return "Sentiment Analysis", self.sentiment.analyze(indicators, recent_candles)

        def _news():
            return "News Analysis", self.news_analyst.analyze(news_text, inst_id)

        def _fundamentals():
            return "Fundamentals Analysis", self.fundamentals.analyze(indicators)

        tasks = [_technical, _sentiment, _news, _fundamentals]

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(fn): fn.__name__ for fn in tasks}
            try:
                for future in as_completed(futures, timeout=timeout + 5):
                    fn_name = futures[future]
                    display = _DISPLAY_NAMES.get(fn_name, fn_name)
                    try:
                        name, report = future.result(timeout=timeout)
                        reports[name] = report if report else "(分析师未返回结果)"
                    except Exception as e:
                        logger.warning("[Pipeline] 分析师 %s 异常: %s", display, e)
                        reports[display] = "(分析师调用失败)"
            except TimeoutError:
                # 部分分析师超时，保留已完成的结果
                for _future, fn_name in futures.items():
                    display = _DISPLAY_NAMES.get(fn_name, fn_name)
                    if display not in reports:
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

    def _over_budget(self, stage: str) -> bool:
        """检查当前 token 用量是否超过预算上限"""
        cap = self.config.max_total_tokens
        if cap <= 0:
            return False
        used = self.tracker.summary()["total_tokens"]
        if used > cap:
            logger.warning(
                "[Pipeline] Token 用量 %d 超过上限 %d（%s后）",
                used, cap, stage,
            )
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
