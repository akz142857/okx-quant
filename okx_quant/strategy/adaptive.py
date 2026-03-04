"""自适应策略：根据市场状态自动切换子策略"""

from enum import Enum
from typing import Optional

import pandas as pd

from okx_quant.indicators import adx, bollinger_bands
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from okx_quant.strategy.ma_cross import MACrossStrategy
from okx_quant.strategy.bollinger import BollingerBandStrategy
from okx_quant.strategy.rsi_mean import RSIMeanReversionStrategy


class MarketRegime(Enum):
    TRENDING = "趋势"
    RANGING_HIGH_VOL = "震荡高波"
    RANGING_LOW_VOL = "震荡低波"


_REGIME_LABELS = {
    MarketRegime.TRENDING: "趋势",
    MarketRegime.RANGING_HIGH_VOL: "震荡高波",
    MarketRegime.RANGING_LOW_VOL: "震荡低波",
}


class AdaptiveStrategy(BaseStrategy):
    """自适应策略

    通过 ADX + 布林带宽度检测市场状态，自动选择最合适的子策略：
    - 趋势市场 (ADX ≥ 25) → 双均线策略 (MACross)
    - 震荡 + 高波动 → 布林带策略
    - 震荡 + 低波动 → RSI 均值回归策略

    带冷却机制防止频繁切换。
    """

    name = "Adaptive"

    def __init__(self, params: Optional[dict] = None):
        defaults = {
            "adx_period": 14,
            "adx_trend_thresh": 25,
            "adx_range_thresh": 20,
            "bb_period": 20,
            "bb_std": 2.0,
            "bw_lookback": 50,
            "cooldown_bars": 4,
        }
        merged = {**defaults, **(params or {})}
        super().__init__(merged)

        # 子策略实例
        self._strategies = {
            MarketRegime.TRENDING: MACrossStrategy(),
            MarketRegime.RANGING_HIGH_VOL: BollingerBandStrategy(),
            MarketRegime.RANGING_LOW_VOL: RSIMeanReversionStrategy(),
        }

        # 状态追踪
        self._current_regime: MarketRegime = MarketRegime.TRENDING
        self._pending_regime: Optional[MarketRegime] = None
        self._pending_count: int = 0

    def _compute_indicators(self, df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
        """一次性计算 ADX 和布林带指标，避免重复计算"""
        adx_df = adx(df, self.get_param("adx_period"))
        bb_df = bollinger_bands(df["close"], self.get_param("bb_period"), self.get_param("bb_std"))
        return adx_df, bb_df

    def _detect_regime(
        self, adx_df: pd.DataFrame, bb_df: pd.DataFrame,
    ) -> Optional[MarketRegime]:
        """检测当前市场状态

        Args:
            adx_df: 预计算的 ADX DataFrame
            bb_df: 预计算的布林带 DataFrame

        Returns:
            MarketRegime 或 None（过渡区，保持不变）
        """
        trend_thresh = self.get_param("adx_trend_thresh")
        range_thresh = self.get_param("adx_range_thresh")
        bw_lookback = self.get_param("bw_lookback")

        curr_adx = adx_df["adx"].iloc[-1]

        if curr_adx >= trend_thresh:
            return MarketRegime.TRENDING

        if curr_adx < range_thresh:
            bw = bb_df["bandwidth"]
            curr_bw = bw.iloc[-1]
            median_bw = bw.iloc[-bw_lookback:].median()

            if curr_bw > median_bw:
                return MarketRegime.RANGING_HIGH_VOL
            else:
                return MarketRegime.RANGING_LOW_VOL

        # ADX 在 range_thresh ~ trend_thresh 之间（过渡区），不切换
        return None

    def _apply_cooldown(self, detected: Optional[MarketRegime]) -> MarketRegime:
        """冷却过滤：连续 cooldown_bars 根确认才切换"""
        cooldown = self.get_param("cooldown_bars")

        # 过渡区：保持当前状态，不重置等待计数
        if detected is None:
            return self._current_regime

        # 检测结果与当前状态一致：重置等待
        if detected == self._current_regime:
            self._pending_regime = None
            self._pending_count = 0
            return self._current_regime

        # 检测到新状态
        if detected == self._pending_regime:
            self._pending_count += 1
        else:
            self._pending_regime = detected
            self._pending_count = 1

        if self._pending_count >= cooldown:
            self._current_regime = detected
            self._pending_regime = None
            self._pending_count = 0

        return self._current_regime

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        adx_period = self.get_param("adx_period")
        bb_period = self.get_param("bb_period")
        bw_lookback = self.get_param("bw_lookback")
        min_bars = max(adx_period * 3, bb_period + 1, bw_lookback)

        if len(df) < min_bars:
            return Signal(
                SignalType.HOLD, inst_id, price=0,
                reason=f"数据不足（需 {min_bars} 根，当前 {len(df)} 根）",
            )

        # 一次性计算指标
        adx_df, bb_df = self._compute_indicators(df)

        # 检测状态 → 冷却过滤
        detected = self._detect_regime(adx_df, bb_df)
        regime = self._apply_cooldown(detected)

        curr_adx = adx_df["adx"].iloc[-1]
        curr_bw = bb_df["bandwidth"].iloc[-1]

        # 调用子策略
        strategy = self._strategies[regime]
        signal = strategy.generate_signal(df, inst_id)

        # 组装状态标签
        label = _REGIME_LABELS[regime]
        prefix = f"[{label}|ADX={curr_adx:.1f}|BW={curr_bw:.1f}]"
        signal.reason = f"{prefix} {strategy.name}: {signal.reason}"

        # 合并 extra
        signal.extra = {
            **signal.extra,
            "regime": regime.value,
            "adx": round(curr_adx, 2),
            "bandwidth": round(curr_bw, 2),
            "plus_di": round(adx_df["plus_di"].iloc[-1], 2),
            "minus_di": round(adx_df["minus_di"].iloc[-1], 2),
            "sub_strategy": strategy.name,
        }

        return signal
