"""双均线金叉/死叉策略"""

import pandas as pd
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from okx_quant.indicators import cached_atr, cached_ema


class MACrossStrategy(BaseStrategy):
    """双 EMA 金叉/死叉策略

    - 金叉（快线上穿慢线）：买入
    - 死叉（快线下穿慢线）：卖出
    - 止损基于 ATR 倍数

    默认参数:
        fast_period: 9（快线）
        slow_period: 21（慢线）
        atr_period: 14
        atr_sl_mult: 2.0（止损 = 入场价 - ATR * mult）
        atr_tp_mult: 3.0（止盈 = 入场价 + ATR * mult）
    """

    name = "MACross"

    def __init__(self, params: dict | None = None):
        defaults = {
            "fast_period": 7,
            "slow_period": 15,
            "atr_period": 14,
            "atr_sl_mult": 2.0,
            "atr_tp_mult": 3.0,
        }
        merged = {**defaults, **(params or {})}
        super().__init__(merged)

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        fast = self.get_param("fast_period")
        slow = self.get_param("slow_period")
        atr_period = self.get_param("atr_period")
        sl_mult = self.get_param("atr_sl_mult")
        tp_mult = self.get_param("atr_tp_mult")

        if len(df) < slow + 1:
            return Signal(SignalType.HOLD, inst_id, price=0, reason="数据不足")

        close = df["close"]
        fast_ma = cached_ema(df, fast)
        slow_ma = cached_ema(df, slow)
        atr_val = cached_atr(df, atr_period)

        prev_fast, curr_fast = fast_ma.iloc[-2], fast_ma.iloc[-1]
        prev_slow, curr_slow = slow_ma.iloc[-2], slow_ma.iloc[-1]
        curr_price = close.iloc[-1]
        curr_atr = atr_val.iloc[-1]

        # 金叉
        if prev_fast <= prev_slow and curr_fast > curr_slow:
            sl = curr_price - curr_atr * sl_mult
            tp = curr_price + curr_atr * tp_mult
            return Signal(
                signal=SignalType.BUY,
                inst_id=inst_id,
                price=curr_price,
                stop_loss=round(sl, 8),
                take_profit=round(tp, 8),
                reason=f"EMA{fast} 上穿 EMA{slow}（金叉）",
                extra={"fast_ma": curr_fast, "slow_ma": curr_slow, "atr": curr_atr},
            )

        # 死叉
        if prev_fast >= prev_slow and curr_fast < curr_slow:
            return Signal(
                signal=SignalType.SELL,
                inst_id=inst_id,
                price=curr_price,
                reason=f"EMA{fast} 下穿 EMA{slow}（死叉）",
                extra={"fast_ma": curr_fast, "slow_ma": curr_slow},
            )

        gap_pct = (curr_fast / curr_slow - 1) * 100 if curr_slow else 0
        return Signal(
            SignalType.HOLD, inst_id, price=curr_price,
            reason=f"EMA{fast}={curr_fast:.6f}, EMA{slow}={curr_slow:.6f}, 差={gap_pct:+.2f}%",
            extra={"fast_ma": curr_fast, "slow_ma": curr_slow, "atr": curr_atr, "gap_pct": gap_pct},
        )
