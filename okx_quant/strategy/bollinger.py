"""布林带均值回归策略"""

import pandas as pd
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from okx_quant.indicators import bollinger_bands, rsi


class BollingerBandStrategy(BaseStrategy):
    """布林带策略（结合 RSI 过滤）

    - %B 低于 pct_b_buy 且 RSI < rsi_filter_low：买入信号
    - %B 高于 pct_b_sell 且 RSI > rsi_filter_high：卖出信号
    - 中轨作为止盈目标（均值回归）

    默认参数:
        bb_period: 20
        bb_std: 2.0
        rsi_period: 14
        rsi_filter_low: 40   （买入时 RSI 须低于此值）
        rsi_filter_high: 60  （卖出时 RSI 须高于此值）
        pct_b_buy: 20        （买入时 %B 须低于此值）
        pct_b_sell: 80       （卖出时 %B 须高于此值）
    """

    name = "BollingerBand"

    def __init__(self, params: dict | None = None):
        defaults = {
            "bb_period": 20,
            "bb_std": 2.0,
            "rsi_period": 14,
            "rsi_filter_low": 45,
            "rsi_filter_high": 55,
            "pct_b_buy": 30,
            "pct_b_sell": 70,
        }
        merged = {**defaults, **(params or {})}
        super().__init__(merged)

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        bb_period = self.get_param("bb_period")
        bb_std = self.get_param("bb_std")
        rsi_period = self.get_param("rsi_period")
        rsi_low = self.get_param("rsi_filter_low")
        rsi_high = self.get_param("rsi_filter_high")
        pct_b_buy = self.get_param("pct_b_buy")
        pct_b_sell = self.get_param("pct_b_sell")

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

        # %B 进入下轨区域 + RSI 偏低：买入
        if pct_b <= pct_b_buy and curr_rsi < rsi_low:
            return Signal(
                signal=SignalType.BUY,
                inst_id=inst_id,
                price=curr_close,
                stop_loss=round(lower * 0.95, 8),
                take_profit=round(middle, 8),
                reason=f"布林%B={pct_b:.1f} ≤ {pct_b_buy}，RSI={curr_rsi:.1f}",
                extra={"upper": upper, "middle": middle, "lower": lower, "pct_b": pct_b, "rsi": curr_rsi},
            )

        # %B 进入上轨区域 + RSI 偏高：卖出
        if pct_b >= pct_b_sell and curr_rsi > rsi_high:
            return Signal(
                signal=SignalType.SELL,
                inst_id=inst_id,
                price=curr_close,
                take_profit=round(middle, 8),
                reason=f"布林%B={pct_b:.1f} ≥ {pct_b_sell}，RSI={curr_rsi:.1f}",
                extra={"upper": upper, "middle": middle, "lower": lower, "pct_b": pct_b, "rsi": curr_rsi},
            )

        return Signal(
            SignalType.HOLD,
            inst_id,
            price=curr_close,
            reason=f"布林%B={pct_b:.1f}，RSI={curr_rsi:.1f}",
            extra={"upper": upper, "middle": middle, "lower": lower, "pct_b": pct_b, "rsi": curr_rsi},
        )
