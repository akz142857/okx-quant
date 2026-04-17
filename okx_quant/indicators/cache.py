"""指标缓存助手

在回测场景下，引擎会一次性对完整 df 预计算所有指标，并把结果缓存到
``df.attrs["_cached_indicators"]``。策略通过此处的 ``cached_*`` 函数
读取：命中缓存直接返回，未命中则按原逻辑重新计算。

生产实盘模式下 df 每轮都是新对象，缓存必然未命中，行为等价于直接调用
``indicators.trend``/``indicators.momentum`` 的纯函数版本 —— 不产生
额外开销，但在回测中把 O(n²) 降到 O(n)。
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from okx_quant.indicators import momentum as _momentum
from okx_quant.indicators import trend as _trend

_CACHE_ATTR = "_cached_indicators"


class _Cache:
    """按身份比较的缓存容器

    pandas 在 concat / __finalize__ 时会比较 df.attrs 字典相等性；若直接
    把 ``dict`` 存进 attrs 且其中放了 pandas Series，``dict.__eq__`` 会
    对 Series 做逐元素比较并抛 ``ValueError: truth value ambiguous``。
    改用自定义类并以身份比较（两个 _Cache 实例相等当且仅当同一对象），
    即可绕过 pandas 的内部比较开销并完全避免 Series 相等性问题。
    """

    __slots__ = ("data",)

    def __init__(self) -> None:
        self.data: dict[tuple, Any] = {}

    def __eq__(self, other: object) -> bool:  # identity
        return self is other

    def __ne__(self, other: object) -> bool:
        return self is not other

    def __hash__(self) -> int:
        return id(self)


def _get_cache(df: pd.DataFrame) -> _Cache:
    cache = df.attrs.get(_CACHE_ATTR)
    if not isinstance(cache, _Cache):
        cache = _Cache()
        df.attrs[_CACHE_ATTR] = cache
    return cache


def _lookup(df: pd.DataFrame, key: tuple) -> Any:
    cache = df.attrs.get(_CACHE_ATTR)
    if not isinstance(cache, _Cache):
        return None
    return cache.data.get(key)


def cached_ema(df: pd.DataFrame, period: int) -> pd.Series:
    key = ("ema", period)
    hit = _lookup(df, key)
    if hit is not None:
        return hit
    return _trend.ema(df["close"], period)


def cached_sma(df: pd.DataFrame, period: int) -> pd.Series:
    key = ("sma", period)
    hit = _lookup(df, key)
    if hit is not None:
        return hit
    return _trend.sma(df["close"], period)


def cached_rsi(df: pd.DataFrame, period: int = 14) -> pd.Series:
    key = ("rsi", period)
    hit = _lookup(df, key)
    if hit is not None:
        return hit
    return _momentum.rsi(df["close"], period)


def cached_macd(
    df: pd.DataFrame,
    fast: int = 12,
    slow: int = 26,
    signal: int = 9,
) -> pd.DataFrame:
    key = ("macd", fast, slow, signal)
    hit = _lookup(df, key)
    if hit is not None:
        return hit
    return _trend.macd(df["close"], fast, slow, signal)


def cached_bollinger(
    df: pd.DataFrame,
    period: int = 20,
    std_dev: float = 2.0,
) -> pd.DataFrame:
    key = ("bbands", period, std_dev)
    hit = _lookup(df, key)
    if hit is not None:
        return hit
    return _trend.bollinger_bands(df["close"], period, std_dev)


def cached_atr(df: pd.DataFrame, period: int = 14) -> pd.Series:
    key = ("atr", period)
    hit = _lookup(df, key)
    if hit is not None:
        return hit
    return _trend.atr(df, period)


def cached_adx(df: pd.DataFrame, period: int = 14) -> pd.DataFrame:
    key = ("adx", period)
    hit = _lookup(df, key)
    if hit is not None:
        return hit
    return _trend.adx(df, period)


def populate_cache(
    df: pd.DataFrame,
    *,
    ema_periods: tuple[int, ...] = (),
    sma_periods: tuple[int, ...] = (),
    rsi_periods: tuple[int, ...] = (),
    macd_specs: tuple[tuple[int, int, int], ...] = (),
    bbands_specs: tuple[tuple[int, float], ...] = (),
    atr_periods: tuple[int, ...] = (),
    adx_periods: tuple[int, ...] = (),
) -> None:
    """在完整 df 上预计算一次指定指标并缓存到 df.attrs。

    所有这些指标是因果的（第 i 行仅依赖 <=i 的输入），因此在完整 df 上
    预计算后，任意后续 ``series.iloc[: i+1]`` 等价于在 df.iloc[: i+1] 上
    单独计算——不产生 lookahead。
    """
    cache = _get_cache(df).data
    close = df["close"]
    for p in ema_periods:
        cache[("ema", p)] = _trend.ema(close, p)
    for p in sma_periods:
        cache[("sma", p)] = _trend.sma(close, p)
    for p in rsi_periods:
        cache[("rsi", p)] = _momentum.rsi(close, p)
    for fast, slow, signal in macd_specs:
        cache[("macd", fast, slow, signal)] = _trend.macd(close, fast, slow, signal)
    for period, std in bbands_specs:
        cache[("bbands", period, std)] = _trend.bollinger_bands(close, period, std)
    for p in atr_periods:
        cache[("atr", p)] = _trend.atr(df, p)
    for p in adx_periods:
        cache[("adx", p)] = _trend.adx(df, p)


def slice_cache(src: pd.DataFrame, dst: pd.DataFrame, upto: int) -> None:
    """把 src 上已缓存的整条序列按位置 [:upto] 切片赋给 dst 的缓存。

    回测引擎在每根 K 线的 history 片段上调用此函数，避免策略在子片段上
    再次触发缓存未命中并重新计算。
    """
    src_cache = src.attrs.get(_CACHE_ATTR)
    if not isinstance(src_cache, _Cache):
        return
    dst_cache = _get_cache(dst).data
    for k, v in src_cache.data.items():
        if isinstance(v, (pd.Series, pd.DataFrame)):
            dst_cache[k] = v.iloc[:upto]
