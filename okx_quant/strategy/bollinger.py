"""布林带均值回归策略"""

import pandas as pd
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from okx_quant.indicators import bollinger_bands, rsi


class BollingerBandStrategy(BaseStrategy):
    """布林带策略（结合 RSI 过滤）

    - 收盘价触碰下轨且 RSI < 40：买入信号
    - 收盘价触碰上轨且 RSI > 60：卖出信号
    - 中轨作为止盈目标

    默认参数:
        bb_period: 20
        bb_std: 2.0
        rsi_period: 14
        rsi_filter_low: 40   （买入时 RSI 须低于此值）
        rsi_filter_high: 60  （卖出时 RSI 须高于此值）
    """

    name = "BollingerBand"

    def __init__(self, params: dict | None = None):
        defaults = {
            "bb_period": 20,
            "bb_std": 2.0,
            "rsi_period": 14,
            "rsi_filter_low": 40,
            "rsi_filter_high": 60,
        }
        merged = {**defaults, **(params or {})}
        super().__init__(merged)

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        bb_period = self.get_param("bb_period")
        bb_std = self.get_param("bb_std")
        rsi_period = self.get_param("rsi_period")
        rsi_low = self.get_param("rsi_filter_low")
        rsi_high = self.get_param("rsi_filter_high")

        min_len = max(bb_period, rsi_period) + 1
        if len(df) < min_len:
            return Signal(SignalType.HOLD, inst_id, price=0, reason="数据不足")

        bb = bollinger_bands(df["close"], bb_period, bb_std)
        rsi_series = rsi(df["close"], rsi_period)

        curr_close = df["close"].iloc[-1]
        curr_rsi = rsi_series.iloc[-1]
        upper = bb["upper"].iloc[-1]
        lower = bb["lower"].iloc[-1]
        middle = bb["middle"].iloc[-1]
        pct_b = bb["percent_b"].iloc[-1]

        # 触碰下轨 + RSI 未超卖极值：买入
        if curr_close <= lower and curr_rsi < rsi_low:
            return Signal(
                signal=SignalType.BUY,
                inst_id=inst_id,
                price=curr_close,
                stop_loss=round(lower * 0.95, 8),
                take_profit=round(middle + (upper - middle) * 0.5, 8),
                reason=f"价格触碰布林下轨({lower:.4f})，RSI={curr_rsi:.1f}",
                extra={"upper": upper, "middle": middle, "lower": lower, "pct_b": pct_b, "rsi": curr_rsi},
            )

        # 触碰上轨 + RSI 偏高：卖出
        if curr_close >= upper and curr_rsi > rsi_high:
            return Signal(
                signal=SignalType.SELL,
                inst_id=inst_id,
                price=curr_close,
                take_profit=round(middle, 8),
                reason=f"价格触碰布林上轨({upper:.4f})，RSI={curr_rsi:.1f}",
                extra={"upper": upper, "middle": middle, "lower": lower, "pct_b": pct_b, "rsi": curr_rsi},
            )

        return Signal(
            SignalType.HOLD,
            inst_id,
            price=curr_close,
            reason=f"布林%B={pct_b:.1f}，RSI={curr_rsi:.1f}",
            extra={"upper": upper, "middle": middle, "lower": lower, "pct_b": pct_b, "rsi": curr_rsi},
        )
