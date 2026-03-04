"""RSI 均值回归策略"""

import pandas as pd
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from okx_quant.indicators import rsi, atr


class RSIMeanReversionStrategy(BaseStrategy):
    """RSI 超买超卖均值回归策略

    - RSI 从超卖区（<oversold）反弹（RSI 由低变高）：买入
    - RSI 从超买区（>overbought）回落（RSI 由高变低）：卖出

    默认参数:
        rsi_period: 14
        oversold: 30
        overbought: 70
        atr_period: 14
        atr_sl_mult: 1.5
        atr_tp_mult: 2.5
    """

    name = "RSIMeanReversion"

    def __init__(self, params: dict | None = None):
        defaults = {
            "rsi_period": 14,
            "oversold": 30,
            "overbought": 70,
            "atr_period": 14,
            "atr_sl_mult": 1.5,
            "atr_tp_mult": 2.5,
        }
        merged = {**defaults, **(params or {})}
        super().__init__(merged)

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        rsi_period = self.get_param("rsi_period")
        oversold = self.get_param("oversold")
        overbought = self.get_param("overbought")
        atr_period = self.get_param("atr_period")
        sl_mult = self.get_param("atr_sl_mult")
        tp_mult = self.get_param("atr_tp_mult")

        if len(df) < rsi_period + 2:
            return Signal(SignalType.HOLD, inst_id, price=0, reason="数据不足")

        rsi_series = rsi(df["close"], rsi_period)
        atr_val = atr(df, atr_period)

        prev_rsi = rsi_series.iloc[-2]
        curr_rsi = rsi_series.iloc[-1]
        curr_price = df["close"].iloc[-1]
        curr_atr = atr_val.iloc[-1]

        # 超卖反弹买入
        if prev_rsi < oversold and curr_rsi >= oversold:
            sl = curr_price - curr_atr * sl_mult
            tp = curr_price + curr_atr * tp_mult
            return Signal(
                signal=SignalType.BUY,
                inst_id=inst_id,
                price=curr_price,
                stop_loss=round(sl, 8),
                take_profit=round(tp, 8),
                reason=f"RSI 从超卖区({prev_rsi:.1f})回升至({curr_rsi:.1f})",
                extra={"rsi": curr_rsi, "atr": curr_atr},
            )

        # 超买回落卖出
        if prev_rsi > overbought and curr_rsi <= overbought:
            return Signal(
                signal=SignalType.SELL,
                inst_id=inst_id,
                price=curr_price,
                reason=f"RSI 从超买区({prev_rsi:.1f})回落至({curr_rsi:.1f})",
                extra={"rsi": curr_rsi},
            )

        return Signal(SignalType.HOLD, inst_id, price=curr_price, reason=f"RSI={curr_rsi:.1f}")
