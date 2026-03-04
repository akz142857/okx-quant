"""动量类技术指标：RSI、Stochastic、CCI"""

import pandas as pd
import numpy as np


def rsi(series: pd.Series, period: int = 14) -> pd.Series:
    """相对强弱指数 (RSI)

    值域 0-100；>70 超买，<30 超卖。
    使用 Wilder 平滑法（与 TradingView 一致）。
    """
    delta = series.diff()
    gain = delta.clip(lower=0)
    loss = (-delta).clip(lower=0)

    avg_gain = gain.ewm(alpha=1 / period, adjust=False).mean()
    avg_loss = loss.ewm(alpha=1 / period, adjust=False).mean()

    rs = avg_gain / avg_loss.replace(0, np.nan)
    return 100 - (100 / (1 + rs))


def stochastic(
    df: pd.DataFrame,
    k_period: int = 14,
    d_period: int = 3,
    smooth_k: int = 3,
) -> pd.DataFrame:
    """随机指标 KDJ (Stochastic Oscillator)

    Args:
        df: 含 high, low, close 列
        k_period: %K 周期
        d_period: %D 平滑周期
        smooth_k: %K 平滑（slow stochastic）

    Returns:
        DataFrame 含列: k, d, j
    """
    low_min = df["low"].rolling(window=k_period).min()
    high_max = df["high"].rolling(window=k_period).max()
    raw_k = (df["close"] - low_min) / (high_max - low_min).replace(0, np.nan) * 100

    k = raw_k.rolling(window=smooth_k).mean()
    d = k.rolling(window=d_period).mean()
    j = 3 * k - 2 * d
    return pd.DataFrame({"k": k, "d": d, "j": j})


def cci(df: pd.DataFrame, period: int = 20) -> pd.Series:
    """商品通道指数 (CCI)

    Args:
        df: 含 high, low, close 列

    Returns:
        Series；>100 超买，<-100 超卖。
    """
    typical = (df["high"] + df["low"] + df["close"]) / 3
    ma = typical.rolling(window=period).mean()
    mean_dev = typical.rolling(window=period).apply(lambda x: abs(x - x.mean()).mean())
    return (typical - ma) / (0.015 * mean_dev)
