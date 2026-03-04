"""趋势类技术指标：MA、EMA、MACD、布林带、ATR"""

import pandas as pd
import numpy as np


def sma(series: pd.Series, period: int) -> pd.Series:
    """简单移动平均"""
    return series.rolling(window=period).mean()


def ema(series: pd.Series, period: int) -> pd.Series:
    """指数移动平均（adjust=False 与 TradingView 一致）"""
    return series.ewm(span=period, adjust=False).mean()


def macd(
    series: pd.Series,
    fast: int = 12,
    slow: int = 26,
    signal: int = 9,
) -> pd.DataFrame:
    """MACD 指标

    Returns:
        DataFrame 含列:
          - macd: 快线 (DIF)
          - signal: 信号线 (DEA)
          - histogram: 柱状图 (MACD Bar = 2 * (DIF - DEA))
    """
    ema_fast = ema(series, fast)
    ema_slow = ema(series, slow)
    dif = ema_fast - ema_slow
    dea = ema(dif, signal)
    hist = (dif - dea) * 2  # 国内习惯乘以 2
    return pd.DataFrame({"macd": dif, "signal": dea, "histogram": hist})


def bollinger_bands(
    series: pd.Series,
    period: int = 20,
    std_dev: float = 2.0,
) -> pd.DataFrame:
    """布林带

    Returns:
        DataFrame 含列: upper, middle, lower, bandwidth, percent_b
    """
    middle = sma(series, period)
    std = series.rolling(window=period).std()
    upper = middle + std_dev * std
    lower = middle - std_dev * std
    bandwidth = (upper - lower) / middle * 100
    percent_b = (series - lower) / (upper - lower) * 100
    return pd.DataFrame(
        {
            "upper": upper,
            "middle": middle,
            "lower": lower,
            "bandwidth": bandwidth,
            "percent_b": percent_b,
        }
    )


def atr(df: pd.DataFrame, period: int = 14) -> pd.Series:
    """平均真实波幅 (ATR)

    Args:
        df: 需含 high, low, close 列
    """
    high = df["high"]
    low = df["low"]
    close = df["close"]
    prev_close = close.shift(1)
    tr = pd.concat(
        [
            (high - low),
            (high - prev_close).abs(),
            (low - prev_close).abs(),
        ],
        axis=1,
    ).max(axis=1)
    return tr.ewm(span=period, adjust=False).mean()


def adx(df: pd.DataFrame, period: int = 14) -> pd.DataFrame:
    """平均趋向指数 (ADX)

    使用 Wilder 平滑法计算 +DI、-DI 和 ADX。

    Args:
        df: 需含 high, low, close 列
        period: 平滑周期，默认 14

    Returns:
        DataFrame 含列: plus_di, minus_di, adx
    """
    high = df["high"]
    low = df["low"]
    close = df["close"]
    prev_high = high.shift(1)
    prev_low = low.shift(1)
    prev_close = close.shift(1)

    # True Range
    tr = pd.concat(
        [
            (high - low),
            (high - prev_close).abs(),
            (low - prev_close).abs(),
        ],
        axis=1,
    ).max(axis=1)

    # Directional Movement
    up_move = high - prev_high
    down_move = prev_low - low
    plus_dm = np.where((up_move > down_move) & (up_move > 0), up_move, 0.0)
    minus_dm = np.where((down_move > up_move) & (down_move > 0), down_move, 0.0)

    plus_dm = pd.Series(plus_dm, index=df.index)
    minus_dm = pd.Series(minus_dm, index=df.index)

    # Wilder 平滑
    alpha = 1 / period
    atr_smooth = tr.ewm(alpha=alpha, adjust=False).mean()
    plus_dm_smooth = plus_dm.ewm(alpha=alpha, adjust=False).mean()
    minus_dm_smooth = minus_dm.ewm(alpha=alpha, adjust=False).mean()

    # +DI / -DI
    plus_di = (plus_dm_smooth / atr_smooth) * 100
    minus_di = (minus_dm_smooth / atr_smooth) * 100

    # DX → ADX
    di_sum = plus_di + minus_di
    di_sum = di_sum.replace(0, np.nan)
    dx = ((plus_di - minus_di).abs() / di_sum) * 100
    adx_val = dx.ewm(alpha=alpha, adjust=False).mean()

    return pd.DataFrame(
        {"plus_di": plus_di, "minus_di": minus_di, "adx": adx_val}
    )
