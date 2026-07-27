"""随波动率和成交量变化的保守交易成本模型。"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass

import pandas as pd


def canonical_manifest_hash(value) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def dataframe_manifest(data: pd.DataFrame) -> dict:
    """Return the exact canonical payload used to identify research data."""
    return {
        "columns": [str(column) for column in data.columns],
        "dtypes": [str(dtype) for dtype in data.dtypes],
        "data": data.to_json(
            orient="split",
            date_format="iso",
            date_unit="ns",
            double_precision=15,
        ),
    }


def dataframe_manifest_hash(data: pd.DataFrame) -> str:
    return canonical_manifest_hash(dataframe_manifest(data))


def cost_model_manifest_hash(
    cost_model,
    *,
    fee_rate: float,
    slippage: float,
) -> str:
    for name, value in {
        "fee_rate": fee_rate,
        "slippage": slippage,
    }.items():
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not 0 <= float(value) < 1
        ):
            raise ValueError(f"{name} 必须是 [0, 1) 内有限数")
    if cost_model is None:
        manifest = {
            "model": "static_fee_and_slippage",
            "fee_rate": float(fee_rate),
            "slippage": float(slippage),
        }
        return canonical_manifest_hash(manifest)
    hasher = getattr(cost_model, "manifest_hash", None)
    if not callable(hasher):
        raise ValueError(
            "自定义 cost_model 必须提供稳定的 manifest_hash()"
        )
    rendered = str(hasher())
    if len(rendered) != 64:
        raise ValueError("cost_model.manifest_hash() 必须返回 SHA-256")
    return rendered


@dataclass(frozen=True)
class DynamicCostModel:
    fee_rate: float = 0.001
    minimum_slippage: float = 0.0005
    range_fraction: float = 0.05
    impact_coefficient: float = 0.10
    maximum_slippage: float = 0.05
    stress_multiplier: float = 1.0

    def __post_init__(self) -> None:
        values = asdict(self)
        for name, value in values.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                raise ValueError(f"{name} 必须是有限数")
        for name in {
            "fee_rate",
            "minimum_slippage",
            "range_fraction",
            "impact_coefficient",
            "maximum_slippage",
        }:
            if values[name] < 0:
                raise ValueError(f"{name} 不能为负")
        if not (
            self.minimum_slippage
            <= self.maximum_slippage
            < 1
        ):
            raise ValueError(
                "滑点必须满足 0 <= minimum_slippage "
                "<= maximum_slippage < 1"
            )
        if self.fee_rate >= 1 or self.fee_rate * self.stress_multiplier >= 1:
            raise ValueError("压力后的 fee_rate 必须小于 1")
        if self.stress_multiplier <= 0:
            raise ValueError("stress_multiplier 必须大于 0")

    def manifest(self) -> dict[str, float | str]:
        return {
            "model": f"{type(self).__module__}.{type(self).__qualname__}",
            **asdict(self),
        }

    def manifest_hash(self) -> str:
        return canonical_manifest_hash(self.manifest())

    def __call__(
        self, side: str, bar: pd.Series, notional: float
    ) -> tuple[float, float]:
        if side not in {"buy", "sell"}:
            raise ValueError("side 必须是 buy 或 sell")
        if (
            isinstance(notional, bool)
            or not isinstance(notional, (int, float))
            or not math.isfinite(float(notional))
            or float(notional) < 0
        ):
            raise ValueError("notional 必须是非负有限数")
        missing = {"close", "high", "low"} - set(bar.index)
        if missing:
            raise ValueError(f"成本模型缺少 K 线字段: {sorted(missing)}")
        close = float(bar["close"])
        high = float(bar["high"])
        low = float(bar["low"])
        if (
            not all(math.isfinite(value) for value in (close, high, low))
            or close <= 0
            or low <= 0
            or high < low
            or not low <= close <= high
        ):
            raise ValueError("成本模型要求有限且结构合法的正数 OHLC")
        range_component = max(high - low, 0) / close * self.range_fraction
        quote_volume = self._optional_nonnegative(bar, "vol_ccy")
        if quote_volume <= 0:
            quote_volume = self._optional_nonnegative(bar, "vol") * close
        participation = (
            float(notional) / quote_volume if quote_volume > 0 else 1
        )
        impact = self.impact_coefficient * math.sqrt(max(participation, 0))
        slippage = max(self.minimum_slippage, range_component + impact)
        slippage = min(
            slippage * self.stress_multiplier, self.maximum_slippage
        )
        return self.fee_rate * self.stress_multiplier, slippage

    @staticmethod
    def _optional_nonnegative(bar: pd.Series, name: str) -> float:
        if name not in bar.index:
            return 0
        value = float(bar[name])
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{name} 必须是非负有限数")
        return value
