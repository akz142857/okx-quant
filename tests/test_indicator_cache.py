"""指标缓存正确性测试 — 确保 cached_* 与原始函数数值一致"""

import numpy as np
import pytest

from okx_quant.indicators import (
    adx as raw_adx,
    atr as raw_atr,
    bollinger_bands as raw_bb,
    cached_adx,
    cached_atr,
    cached_bollinger,
    cached_ema,
    cached_macd,
    cached_rsi,
    ema as raw_ema,
    macd as raw_macd,
    populate_cache,
    rsi as raw_rsi,
    slice_cache,
)


@pytest.mark.unit
def test_cached_matches_raw_when_cache_empty(synthetic_ohlcv):
    """缓存未命中时，cached_* 应回退到直接计算，结果一致"""
    assert np.allclose(
        cached_ema(synthetic_ohlcv, 14).to_numpy(),
        raw_ema(synthetic_ohlcv["close"], 14).to_numpy(),
        equal_nan=True,
    )
    assert np.allclose(
        cached_rsi(synthetic_ohlcv, 14).dropna().to_numpy(),
        raw_rsi(synthetic_ohlcv["close"], 14).dropna().to_numpy(),
    )
    assert np.allclose(
        cached_atr(synthetic_ohlcv, 14).to_numpy(),
        raw_atr(synthetic_ohlcv, 14).to_numpy(),
        equal_nan=True,
    )


@pytest.mark.unit
def test_cached_matches_raw_when_cache_populated(synthetic_ohlcv):
    """缓存命中时应返回与直接计算相同的序列"""
    populate_cache(
        synthetic_ohlcv,
        ema_periods=(14,),
        rsi_periods=(14,),
        macd_specs=((12, 26, 9),),
        bbands_specs=((20, 2.0),),
        atr_periods=(14,),
        adx_periods=(14,),
    )
    assert np.allclose(
        cached_ema(synthetic_ohlcv, 14).to_numpy(),
        raw_ema(synthetic_ohlcv["close"], 14).to_numpy(),
        equal_nan=True,
    )
    assert np.allclose(
        cached_macd(synthetic_ohlcv)["histogram"].dropna().to_numpy(),
        raw_macd(synthetic_ohlcv["close"])["histogram"].dropna().to_numpy(),
    )
    assert np.allclose(
        cached_bollinger(synthetic_ohlcv)["percent_b"].dropna().to_numpy(),
        raw_bb(synthetic_ohlcv["close"])["percent_b"].dropna().to_numpy(),
    )
    assert np.allclose(
        cached_adx(synthetic_ohlcv)["adx"].dropna().to_numpy(),
        raw_adx(synthetic_ohlcv)["adx"].dropna().to_numpy(),
    )


@pytest.mark.unit
def test_slice_cache_equals_subset_compute(synthetic_ohlcv):
    """引擎 slice 后的缓存值必须与直接在子区间上计算结果一致（无 lookahead）"""
    populate_cache(synthetic_ohlcv, ema_periods=(14,), atr_periods=(14,))
    upto = 100
    sub = synthetic_ohlcv.iloc[:upto].copy()  # 必须 copy，否则共享 attrs
    slice_cache(synthetic_ohlcv, sub, upto)

    # 通过 cache 得到
    ema_cached = cached_ema(sub, 14)
    # 直接在子区间单独计算（不走 cache；走 cached_* 走的是 attrs，所以先清空）
    sub.attrs.clear()
    ema_fresh = cached_ema(sub, 14)
    assert np.allclose(ema_cached.to_numpy(), ema_fresh.to_numpy(), equal_nan=True)


@pytest.mark.unit
def test_cache_does_not_break_pandas_concat(synthetic_ohlcv):
    """回归：df.attrs 内不能放会被逐元素比较的 Series，否则 pd.concat 会抛"""
    import pandas as pd

    populate_cache(synthetic_ohlcv, ema_periods=(14,))
    # concat 触发 __finalize__，内部会比较 attrs。不应抛 ValueError
    concatted = pd.concat([synthetic_ohlcv.head(10), synthetic_ohlcv.tail(10)])
    assert len(concatted) == 20
