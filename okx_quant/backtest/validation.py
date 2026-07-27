"""研究与回测共用的 fail-closed OHLCV 数据契约。"""

from __future__ import annotations

import math

import numpy as np
import pandas as pd


def validate_ohlcv(
    data: pd.DataFrame,
    *,
    context: str = "K 线",
    require_ts: bool = True,
) -> None:
    if not isinstance(data, pd.DataFrame) or data.empty:
        raise ValueError(f"{context}数据必须是非空 DataFrame")
    required = {"open", "high", "low", "close"}
    if require_ts:
        required.add("ts")
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"{context}数据缺少列: {sorted(missing)}")
    if require_ts:
        timestamps = pd.to_datetime(data["ts"], utc=True, errors="coerce")
        if timestamps.isna().any():
            raise ValueError(f"{context}时间戳必须有效")
    numeric_names = [
        name
        for name in ("open", "high", "low", "close", "vol", "vol_ccy")
        if name in data.columns
    ]
    boolean_names = [
        name
        for name in numeric_names
        if data[name].map(
            lambda value: isinstance(value, (bool, np.bool_))
        ).any()
    ]
    if boolean_names:
        raise ValueError(
            f"{context}OHLCV 禁止布尔值: {sorted(boolean_names)}"
        )
    numeric = data[numeric_names].apply(pd.to_numeric, errors="coerce")
    if not np.isfinite(numeric.to_numpy(dtype=float)).all():
        raise ValueError(f"{context}OHLCV 必须全部是有限数")
    ohlc = numeric[["open", "high", "low", "close"]]
    if (
        (ohlc <= 0).any().any()
        or (ohlc["high"] < ohlc[["open", "close", "low"]].max(axis=1)).any()
        or (ohlc["low"] > ohlc[["open", "close", "high"]].min(axis=1)).any()
    ):
        raise ValueError(
            f"{context}OHLC 必须为正且满足 low <= open/close <= high"
        )
    for name in ("vol", "vol_ccy"):
        if name in numeric and (numeric[name] < 0).any():
            raise ValueError(f"{context}{name} 必须是非负有限数")

    # 防止 object/Decimal 转换过程中产生 Python 层的非有限特殊值。
    for name in numeric_names:
        if not all(math.isfinite(float(value)) for value in numeric[name]):
            raise ValueError(f"{context}{name} 必须是有限数")
