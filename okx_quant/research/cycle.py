"""共享的日历窗口市场周期统计。"""

from __future__ import annotations

import math
from bisect import bisect_right
from collections.abc import Sequence
from datetime import date, timedelta


def compute_calendar_cycle_metrics(
    points: Sequence[tuple[date, float]],
    *,
    window_days: int = 90,
    minimum_cycle_days: int = 365,
    minimum_cycle_coverage: float = 0.90,
    maximum_cycle_gap_days: int = 7,
    regime_threshold: float = 0.20,
) -> dict[str, float | int | bool]:
    """从严格递增的日基准值计算可重放的日历窗口周期指标。"""
    if not points:
        raise ValueError("cycle points 不能为空")
    if type(window_days) is not int or window_days < 1:
        raise ValueError("window_days 必须是正整数")
    if type(minimum_cycle_days) is not int or minimum_cycle_days < 1:
        raise ValueError("minimum_cycle_days 必须是正整数")
    if (
        isinstance(minimum_cycle_coverage, bool)
        or not isinstance(minimum_cycle_coverage, (int, float))
        or not math.isfinite(float(minimum_cycle_coverage))
        or not 0 < float(minimum_cycle_coverage) <= 1
    ):
        raise ValueError("minimum_cycle_coverage 必须位于 (0, 1]")
    if (
        type(maximum_cycle_gap_days) is not int
        or maximum_cycle_gap_days < 1
    ):
        raise ValueError("maximum_cycle_gap_days 必须是正整数")
    if (
        isinstance(regime_threshold, bool)
        or not isinstance(regime_threshold, (int, float))
        or not math.isfinite(float(regime_threshold))
        or not 0 < float(regime_threshold) < 1
    ):
        raise ValueError("regime_threshold 必须位于 (0, 1)")

    normalized: list[tuple[date, float]] = []
    for index, (day, raw_value) in enumerate(points):
        if type(day) is not date:
            raise ValueError(f"cycle points[{index}].day 必须是 date")
        if (
            isinstance(raw_value, bool)
            or not isinstance(raw_value, (int, float))
            or not math.isfinite(float(raw_value))
            or float(raw_value) <= 0
        ):
            raise ValueError(
                f"cycle points[{index}].value 必须是正有限数"
            )
        normalized.append((day, float(raw_value)))
    if any(
        right[0] <= left[0]
        for left, right in zip(normalized, normalized[1:], strict=False)
    ):
        raise ValueError("cycle points 日期必须严格递增")

    duration = (normalized[-1][0] - normalized[0][0]).days + 1
    observations = len(normalized)
    coverage = observations / duration
    maximum_gap = max(
        (
            (right[0] - left[0]).days
            for left, right in zip(
                normalized,
                normalized[1:],
                strict=False,
            )
        ),
        default=0,
    )
    days = [point[0] for point in normalized]
    returns: list[float] = []
    for end_day, end_value in normalized:
        target = end_day - timedelta(days=window_days)
        start_index = bisect_right(days, target) - 1
        if start_index < 0:
            continue
        start_day, start_value = normalized[start_index]
        if (target - start_day).days > maximum_cycle_gap_days:
            continue
        returns.append(end_value / start_value - 1)
    maximum_return = max(returns, default=0.0)
    minimum_return = min(returns, default=0.0)
    covers = (
        duration >= minimum_cycle_days
        and observations >= minimum_cycle_days
        and coverage >= float(minimum_cycle_coverage)
        and maximum_gap <= maximum_cycle_gap_days
        and maximum_return >= float(regime_threshold)
        and minimum_return <= -float(regime_threshold)
    )
    return {
        "cycle_duration_days": duration,
        "cycle_observations": observations,
        "cycle_coverage": coverage,
        "cycle_max_gap_days": maximum_gap,
        "cycle_window_days": window_days,
        "cycle_max_return": maximum_return,
        "cycle_min_return": minimum_return,
        "cycle_regime_threshold": float(regime_threshold),
        "covers_full_cycle": covers,
    }
