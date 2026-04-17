"""测试公共 fixtures"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest


@pytest.fixture
def synthetic_ohlcv() -> pd.DataFrame:
    """生成 200 根合成 OHLCV，价格呈缓涨 + 随机扰动"""
    rng = np.random.default_rng(42)
    n = 200
    ts = pd.date_range("2026-01-01", periods=n, freq="1h", tz="UTC")
    drift = np.linspace(100.0, 130.0, n)
    noise = rng.normal(0, 1.0, n).cumsum() * 0.3
    close = drift + noise
    open_ = np.concatenate([[close[0]], close[:-1]])
    spread = rng.uniform(0.2, 0.8, n)
    high = np.maximum(open_, close) + spread
    low = np.minimum(open_, close) - spread
    vol = rng.uniform(100, 500, n)
    return pd.DataFrame({
        "ts": ts,
        "open": open_,
        "high": high,
        "low": low,
        "close": close,
        "vol": vol,
        "vol_ccy": vol * close,
    })
