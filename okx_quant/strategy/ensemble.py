"""集成策略 — 传统策略共识投票 + LLM 确认"""

from collections import Counter

import pandas as pd

from okx_quant.data.news import CryptoNewsFetcher
from okx_quant.llm.client import LLMClient
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType, StrategyContext
from okx_quant.strategy.bollinger import BollingerBandStrategy
from okx_quant.strategy.llm_strategy import LLMStrategy
from okx_quant.strategy.ma_cross import MACrossStrategy
from okx_quant.strategy.rsi_mean import RSIMeanReversionStrategy


class EnsembleStrategy(BaseStrategy):
    """集成策略：传统策略共识 + LLM 确认

    工作流:
    1. 运行 3 个传统策略（MA Cross / RSI Mean / Bollinger），统计 BUY/SELL/HOLD 票数
    2. 票数 >= consensus_threshold → 有共识，调用 LLM 确认
    3. LLM 同意 → 使用 LLM 的 size_pct / stop_loss / take_profit
    4. LLM 否决 → HOLD
    5. 无共识 → HOLD（不调用 LLM，节省 API 费用）

    依赖注入（代理到内部 LLMStrategy）：
        set_llm_client(client)    — 必须在使用前注入
        set_news_fetcher(fetcher) — 可选
    """

    name = "Ensemble"

    def __init__(
        self,
        params: dict | None = None,
        context: "StrategyContext | None" = None,
    ):
        defaults = {"consensus_threshold": 2}
        merged = {**defaults, **(params or {})}

        # 内部 LLMStrategy 需在 super().__init__（触发 _apply_context）前初始化
        self._traditional: list[BaseStrategy] = [
            MACrossStrategy(),
            RSIMeanReversionStrategy(),
            BollingerBandStrategy(),
        ]
        # 子 LLMStrategy 也接收同一个 context，自动拿到 llm_client / news_fetcher
        self._llm = LLMStrategy(context=context)

        super().__init__(merged, context)

    def _apply_context(self) -> None:
        # context 已经传给内部 _llm 构造器，这里是 super().__init__ 触发的 hook
        # 预留钩子，目前无额外动作
        pass

    # ------------------------------------------------------------------
    # 代理方法 — 兼容旧的 setter API（已 DEPRECATED）
    # ------------------------------------------------------------------

    def set_llm_client(self, client: LLMClient) -> None:
        """DEPRECATED: 构造时通过 StrategyContext(llm_client=...) 注入"""
        self._llm.set_llm_client(client)

    def set_news_fetcher(self, fetcher: CryptoNewsFetcher) -> None:
        """DEPRECATED: 构造时通过 StrategyContext(news_fetcher=...) 注入"""
        self._llm.set_news_fetcher(fetcher)

    @property
    def llm_model(self) -> str:
        return self._llm.llm_model

    def get_usage_summary(self) -> dict:
        return self._llm.get_usage_summary()

    # ------------------------------------------------------------------
    # 核心逻辑
    # ------------------------------------------------------------------

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        threshold = self.get_param("consensus_threshold")
        curr_price = df["close"].iloc[-1] if len(df) > 0 else 0

        # 1. 收集传统策略投票
        votes: list[SignalType] = []
        details: list[dict] = []
        for strat in self._traditional:
            sig = strat.generate_signal(df, inst_id)
            votes.append(sig.signal)
            details.append({"strategy": strat.name, "signal": sig.signal.value, "reason": sig.reason})

        counter = Counter(votes)
        vote_summary = {t: counter.get(t, 0) for t in SignalType}

        # 2. 判断是否有共识（BUY 或 SELL 达到阈值，且无冲突）
        consensus_type: SignalType | None = None
        buy_consensus = counter[SignalType.BUY] >= threshold
        sell_consensus = counter[SignalType.SELL] >= threshold
        if buy_consensus and not sell_consensus:
            consensus_type = SignalType.BUY
        elif sell_consensus and not buy_consensus:
            consensus_type = SignalType.SELL

        base_extra = {"votes": {t.value: n for t, n in vote_summary.items()}, "details": details}

        if consensus_type is None:
            return Signal(
                signal=SignalType.HOLD,
                inst_id=inst_id,
                price=curr_price,
                reason=f"传统策略无共识 (BUY={vote_summary[SignalType.BUY]}, SELL={vote_summary[SignalType.SELL]}, HOLD={vote_summary[SignalType.HOLD]})",
                extra={**base_extra, "llm_called": False},
            )

        # 3. 有共识 → 调用 LLM 确认
        llm_signal = self._llm.generate_signal(df, inst_id)
        llm_extra = {
            **base_extra,
            "llm_called": True,
            "llm_signal": llm_signal.signal.value,
            "llm_reason": llm_signal.reason,
        }

        # 4. LLM 同意共识方向 → 使用 LLM 的参数
        if llm_signal.signal == consensus_type:
            return Signal(
                signal=consensus_type,
                inst_id=inst_id,
                price=llm_signal.price,
                size_pct=llm_signal.size_pct,
                stop_loss=llm_signal.stop_loss,
                take_profit=llm_signal.take_profit,
                reason=f"共识{consensus_type.value.upper()}({vote_summary[consensus_type]}/{len(self._traditional)}) + LLM确认",
                extra={**llm_extra, **llm_signal.extra},
            )

        # 5. LLM 否决 → HOLD
        return Signal(
            signal=SignalType.HOLD,
            inst_id=inst_id,
            price=curr_price,
            reason=f"共识{consensus_type.value.upper()}({vote_summary[consensus_type]}/{len(self._traditional)}) 被LLM否决 ({llm_signal.reason})",
            extra=llm_extra,
        )
