"""趋势动量策略：多指标趋势确认 + 移动止盈"""

import pandas as pd
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from okx_quant.indicators import ema, macd, adx, rsi, atr


class TrendMomentumStrategy(BaseStrategy):
    """趋势动量策略

    买入条件（全部满足）：
    - EMA20 > EMA50（中期上升趋势）
    - ADX > 20（趋势存在）
    - MACD 柱 > 0 且递增（动量加速）
    - RSI 在 40~70（有动量但不过热）
    - 价格在 EMA20 之上（站稳支撑）

    两种入场模式：
    - 突破入场：MACD 柱从负转正 + 上述条件
    - 回踩入场：价格回踩 EMA20 附近后反弹 + RSI 40~55 + MACD 柱 > 0

    卖出条件（任一触发）：
    - MACD 柱转负 + RSI < 45（动量消失）
    - 价格跌破 EMA50（趋势结构破坏）

    止损：入场价 - 2.5 × ATR
    止盈：不设固定止盈（take_profit=0），配合 executor 的 trailing stop
    """

    name = "TrendMomentum"

    def __init__(self, params: dict | None = None):
        defaults = {
            "ema_fast": 20,
            "ema_slow": 50,
            "adx_period": 14,
            "adx_thresh": 15,
            "macd_fast": 12,
            "macd_slow": 26,
            "macd_signal": 9,
            "rsi_period": 14,
            "rsi_buy_low": 35,
            "rsi_buy_high": 75,
            "rsi_sell": 45,
            "pullback_pct": 2.5,
            "atr_period": 14,
            "atr_sl_mult": 2.5,
        }
        merged = {**defaults, **(params or {})}
        super().__init__(merged)

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        p = self.params
        min_bars = max(p["ema_slow"], p["macd_slow"] + p["macd_signal"]) + 2
        if len(df) < min_bars:
            return Signal(SignalType.HOLD, inst_id, price=0, reason="数据不足")

        close = df["close"]
        curr_price = close.iloc[-1]

        # 计算指标
        ema_fast = ema(close, p["ema_fast"])
        ema_slow = ema(close, p["ema_slow"])
        macd_df = macd(close, p["macd_fast"], p["macd_slow"], p["macd_signal"])
        adx_df = adx(df, p["adx_period"])
        rsi_val = rsi(close, p["rsi_period"])
        atr_val = atr(df, p["atr_period"])

        curr_ema_fast = ema_fast.iloc[-1]
        curr_ema_slow = ema_slow.iloc[-1]
        curr_hist = macd_df["histogram"].iloc[-1]
        prev_hist = macd_df["histogram"].iloc[-2]
        curr_adx = adx_df["adx"].iloc[-1]
        curr_rsi = rsi_val.iloc[-1]
        curr_atr = atr_val.iloc[-1]

        extra = {
            "ema_fast": round(curr_ema_fast, 6),
            "ema_slow": round(curr_ema_slow, 6),
            "adx": round(curr_adx, 2),
            "macd_hist": round(curr_hist, 6),
            "rsi": round(curr_rsi, 2),
            "atr": round(curr_atr, 6),
        }

        # --- 买入基础条件 ---
        trend_up = curr_ema_fast > curr_ema_slow
        adx_ok = curr_adx > p["adx_thresh"]
        hist_positive = curr_hist > 0
        hist_increasing = curr_hist > prev_hist
        rsi_ok = p["rsi_buy_low"] <= curr_rsi <= p["rsi_buy_high"]
        price_above_ema = curr_price > curr_ema_fast

        # 突破入场：MACD 柱从负转正 + 基础条件
        macd_cross_up = prev_hist <= 0 and curr_hist > 0
        if (macd_cross_up and trend_up and adx_ok and rsi_ok and price_above_ema
                and hist_increasing):
            sl = round(curr_price - curr_atr * p["atr_sl_mult"], 8)
            return Signal(
                signal=SignalType.BUY,
                inst_id=inst_id,
                price=curr_price,
                stop_loss=sl,
                take_profit=0,
                reason=f"突破入场: MACD柱转正, ADX={curr_adx:.1f}, RSI={curr_rsi:.1f}",
                extra=extra,
            )

        # 回踩入场：价格回踩 EMA20 附近（±pullback_pct%）后反弹
        # 允许价格略低于 EMA20，捕捉经典回踩场景
        dist_pct = (curr_price / curr_ema_fast - 1) * 100 if curr_ema_fast else 0
        pullback = abs(dist_pct) <= p["pullback_pct"]
        rsi_pullback = p["rsi_buy_low"] <= curr_rsi <= 60
        if (pullback and trend_up and adx_ok and hist_positive and rsi_pullback):
            sl = round(curr_price - curr_atr * p["atr_sl_mult"], 8)
            return Signal(
                signal=SignalType.BUY,
                inst_id=inst_id,
                price=curr_price,
                stop_loss=sl,
                take_profit=0,
                reason=f"回踩入场: 距EMA{p['ema_fast']}={dist_pct:+.2f}%, RSI={curr_rsi:.1f}",
                extra=extra,
            )

        # --- 卖出条件（买入条件不满足时才评估，避免阻断买入信号） ---
        # 1. 价格跌破 EMA50（趋势结构破坏）
        if curr_price < curr_ema_slow:
            return Signal(
                signal=SignalType.SELL,
                inst_id=inst_id,
                price=curr_price,
                reason=f"价格跌破EMA{p['ema_slow']}，趋势破坏",
                extra=extra,
            )

        # 2. MACD 柱转负 + RSI < 45（动量消失）
        if curr_hist < 0 and curr_rsi < p["rsi_sell"]:
            return Signal(
                signal=SignalType.SELL,
                inst_id=inst_id,
                price=curr_price,
                reason=f"MACD柱转负+RSI={curr_rsi:.1f}<{p['rsi_sell']}，动量消失",
                extra=extra,
            )

        # --- HOLD ---
        trend_str = "↑" if trend_up else "↓"
        return Signal(
            SignalType.HOLD, inst_id, price=curr_price,
            reason=f"趋势{trend_str} ADX={curr_adx:.1f} MACD柱={curr_hist:.4f} RSI={curr_rsi:.1f}",
            extra=extra,
        )
