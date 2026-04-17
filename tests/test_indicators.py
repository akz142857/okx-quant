"""指标函数单元测试"""

import numpy as np
import pandas as pd
import pytest

from okx_quant.indicators import atr, bollinger_bands, ema, macd, rsi, sma


@pytest.mark.unit
def test_sma_matches_rolling_mean():
    s = pd.Series([1.0, 2.0, 3.0, 4.0, 5.0])
    got = sma(s, 3).dropna().tolist()
    assert got == pytest.approx([2.0, 3.0, 4.0])


@pytest.mark.unit
def test_ema_last_value_in_range():
    s = pd.Series(np.linspace(1, 100, 100))
    # EMA 应介于最早值与最新值之间
    assert 50 < ema(s, 10).iloc[-1] < 100


@pytest.mark.unit
def test_rsi_bounds(synthetic_ohlcv):
    r = rsi(synthetic_ohlcv["close"], 14).dropna()
    assert ((r >= 0) & (r <= 100)).all()


@pytest.mark.unit
def test_macd_columns(synthetic_ohlcv):
    m = macd(synthetic_ohlcv["close"])
    assert set(m.columns) == {"macd", "signal", "histogram"}
    assert len(m) == len(synthetic_ohlcv)


@pytest.mark.unit
def test_bollinger_order(synthetic_ohlcv):
    bb = bollinger_bands(synthetic_ohlcv["close"]).dropna()
    assert (bb["lower"] <= bb["middle"]).all()
    assert (bb["middle"] <= bb["upper"]).all()


@pytest.mark.unit
def test_atr_non_negative(synthetic_ohlcv):
    a = atr(synthetic_ohlcv).dropna()
    assert (a >= 0).all()
