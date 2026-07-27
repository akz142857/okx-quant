"""市场压力场景与参数平台稳健性评估。"""

from __future__ import annotations

import math
from collections.abc import Callable
from itertools import product

import numpy as np
import pandas as pd

from okx_quant.backtest import BacktestEngine
from okx_quant.research.costs import (
    canonical_manifest_hash,
    cost_model_manifest_hash,
    dataframe_manifest_hash,
)
from okx_quant.research.identity import (
    build_strategy_family_manifest,
    strategy_family_hash,
    strategy_type_name,
)
from okx_quant.research.portfolio import PortfolioBacktester
from okx_quant.strategy.base import BaseStrategy


def apply_market_stress(
    data: pd.DataFrame,
    *,
    gap_ratio: float = 0,
    volume_multiplier: float = 1,
    volatility_multiplier: float = 1,
) -> pd.DataFrame:
    for name, value in {
        "gap_ratio": gap_ratio,
        "volume_multiplier": volume_multiplier,
        "volatility_multiplier": volatility_multiplier,
    }.items():
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError(f"{name} 必须是有限数")
    if volume_multiplier <= 0 or volatility_multiplier <= 0:
        raise ValueError("压力倍数必须是大于 0 的有限数")
    if not 0 <= gap_ratio < 1:
        raise ValueError("gap_ratio 必须在 [0, 1) 区间")
    required = {"open", "high", "low", "close"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"压力数据缺少列: {sorted(missing)}")
    if data.empty:
        raise ValueError("压力数据不能为空")
    numeric_columns = list(required) + [
        name for name in ("vol", "vol_ccy") if name in data.columns
    ]
    numeric = data[numeric_columns].apply(pd.to_numeric, errors="coerce")
    if not np.isfinite(numeric.to_numpy(dtype=float)).all():
        raise ValueError("压力数据必须是有限数")
    ohlc = numeric[list(required)]
    if (
        (ohlc <= 0).any().any()
        or (ohlc["high"] < ohlc[["open", "close", "low"]].max(axis=1)).any()
        or (ohlc["low"] > ohlc[["open", "close", "high"]].min(axis=1)).any()
    ):
        raise ValueError("压力数据 OHLC 必须为正数且 high/low 结构合法")
    for name in ("vol", "vol_ccy"):
        if name in numeric and (numeric[name] < 0).any():
            raise ValueError(f"{name} 必须是非负有限数")
    stressed = data.copy()
    midpoint = stressed["close"]
    half_range = (stressed["high"] - stressed["low"]) / 2
    stressed["high"] = midpoint + half_range * volatility_multiplier
    stressed["low"] = (
        midpoint - half_range * volatility_multiplier
    ).clip(lower=0)
    if "vol" in stressed:
        stressed["vol"] *= volume_multiplier
    if "vol_ccy" in stressed:
        stressed["vol_ccy"] *= volume_multiplier
    if gap_ratio:
        # 交替向下/向上跳空，避免只挑有利方向。
        directions = pd.Series(
            [(-1 if i % 2 == 0 else 1) for i in range(len(stressed))],
            index=stressed.index,
        )
        stressed["open"] *= 1 + directions * gap_ratio
    stressed["high"] = stressed[
        ["open", "high", "close"]
    ].max(axis=1)
    stressed["low"] = stressed[
        ["open", "low", "close"]
    ].min(axis=1)
    generated = stressed[["open", "high", "low", "close"]].apply(
        pd.to_numeric, errors="coerce"
    )
    if (
        not np.isfinite(generated.to_numpy(dtype=float)).all()
        or (generated <= 0).any().any()
    ):
        raise ValueError("压力场景生成了非正或非有限 OHLC")
    stressed.attrs["source_dataset_hash"] = dataframe_manifest_hash(data)
    stressed.attrs["stress_scenario_hash"] = canonical_manifest_hash({
        "gap_ratio": float(gap_ratio),
        "volume_multiplier": float(volume_multiplier),
        "volatility_multiplier": float(volatility_multiplier),
    })
    return stressed


def evaluate_portfolio_stress_scenarios(
    datasets: dict[str, pd.DataFrame],
    strategy_factory: Callable[[str], BaseStrategy],
    scenarios: list[dict],
    *,
    backtester_factory: Callable[[], PortfolioBacktester],
    weights: dict[str, float] | None = None,
) -> dict:
    """Produce reproducible stress evidence from the same portfolio contract."""
    if not datasets:
        raise ValueError("压力评估至少需要一个数据集")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("压力评估至少需要一个场景")
    required = {
        "name",
        "gap_ratio",
        "volume_multiplier",
        "volatility_multiplier",
    }
    normalized: list[dict] = []
    names: set[str] = set()
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict) or set(scenario) != required:
            raise ValueError(f"stress scenario[{index}] 结构非法")
        name = scenario["name"]
        if not isinstance(name, str) or not name.strip():
            raise ValueError("stress scenario name 必须非空且唯一")
        normalized_name = name.strip()
        if normalized_name in names:
            raise ValueError("stress scenario name 必须非空且唯一")
        names.add(normalized_name)
        values: dict[str, float] = {}
        for key in (
            "gap_ratio",
            "volume_multiplier",
            "volatility_multiplier",
        ):
            raw_value = scenario[key]
            if (
                isinstance(raw_value, bool)
                or not isinstance(raw_value, (int, float))
                or not math.isfinite(float(raw_value))
            ):
                raise ValueError(f"stress scenario[{index}].{key} 必须是有限数")
            values[key] = float(raw_value)
        if not 0 <= values["gap_ratio"] < 1:
            raise ValueError("stress scenario gap_ratio 必须位于 [0, 1)")
        if (
            values["volume_multiplier"] <= 0
            or values["volatility_multiplier"] <= 0
        ):
            raise ValueError("stress scenario 压力倍数必须大于 0")
        normalized.append({
            "name": normalized_name,
            **values,
        })
    scenario_manifest = [dict(scenario) for scenario in normalized]
    scenario_manifest_hash = canonical_manifest_hash(scenario_manifest)
    base = backtester_factory().run(
        datasets,
        strategy_factory,
        weights=weights,
    )
    initial = float(base.metrics["initial_capital"])
    if not math.isfinite(initial) or initial <= 0:
        raise ValueError("组合初始资本必须是正有限数")
    rows: list[dict] = []
    for scenario in normalized:
        stressed = {
            inst_id: apply_market_stress(
                data,
                gap_ratio=scenario["gap_ratio"],
                volume_multiplier=scenario["volume_multiplier"],
                volatility_multiplier=scenario["volatility_multiplier"],
            )
            for inst_id, data in datasets.items()
        }
        result = backtester_factory().run(
            stressed,
            strategy_factory,
            weights=weights,
        )
        if result.metrics["cost_model_hash"] != base.metrics["cost_model_hash"]:
            raise ValueError("压力运行改变了 cost model manifest")
        if result.metrics["strategy_hash"] != base.metrics["strategy_hash"]:
            raise ValueError("压力运行改变了 portfolio strategy manifest")
        final = float(result.metrics["final_capital"])
        if not math.isfinite(final) or final < 0:
            raise ValueError("压力运行 final_capital 必须是非负有限数")
        scenario_definition = dict(scenario)
        rows.append({
            "name": scenario["name"],
            "scenario": scenario_definition,
            "scenario_hash": canonical_manifest_hash(
                scenario_definition
            ),
            "final_capital": final,
            "loss_usdt": max(initial - final, 0),
            "stressed_dataset_hash": result.metrics["dataset_hash"],
        })
    return {
        "loss_usdt": max(row["loss_usdt"] for row in rows),
        "cost_model_hash": base.metrics["cost_model_hash"],
        "dataset_hash": base.metrics["dataset_hash"],
        "strategy_hash": base.metrics["strategy_hash"],
        "scenario_manifest": scenario_manifest,
        "scenario_manifest_hash": scenario_manifest_hash,
        "initial_capital": initial,
        "scenarios": rows,
    }


def evaluate_parameter_surface(
    data: pd.DataFrame,
    inst_id: str,
    strategy_factory: Callable[[dict], BaseStrategy],
    grid: dict[str, list],
    *,
    engine_factory: Callable[[], BacktestEngine] = BacktestEngine,
) -> dict:
    if not isinstance(grid, dict) or not grid:
        raise ValueError("参数网格不能为空")
    names = sorted(grid)
    if any(not isinstance(name, str) or not name for name in names):
        raise ValueError("参数网格名称必须是非空字符串")
    normalized_grid: dict[str, list] = {}
    for name in names:
        values = grid[name]
        if not isinstance(values, list) or not values:
            raise ValueError("参数网格每个维度必须是非空数组")
        identities = [
            canonical_manifest_hash({"value": value}) for value in values
        ]
        if len(set(identities)) != len(identities):
            raise ValueError(f"参数网格维度 {name} 包含重复值")
        normalized_grid[name] = list(values)
    point_count = math.prod(
        len(normalized_grid[name]) for name in names
    )
    parameter_grid_manifest = {
        "version": 1,
        "parameters": normalized_grid,
        "point_count": point_count,
    }
    parameter_grid_hash = canonical_manifest_hash(
        parameter_grid_manifest
    )
    rows: list[dict] = []
    cost_hashes: set[str] = set()
    strategy_manifest: list[dict] = []
    strategies: list[BaseStrategy] = []
    for values in product(*(normalized_grid[name] for name in names)):
        params = dict(zip(names, values, strict=True))
        engine = engine_factory()
        strategy = strategy_factory(params)
        strategies.append(strategy)
        cost_hashes.add(cost_model_manifest_hash(
            getattr(engine, "cost_model", None),
            fee_rate=getattr(engine, "fee_rate", 0.001),
            slippage=getattr(engine, "slippage", 0.0005),
        ))
        strategy_manifest.append({
            "params": params,
            "strategy": strategy_type_name(strategy),
        })
        result = engine.run(data, strategy, inst_id)
        sharpe = float(result.metrics.get("sharpe_ratio", 0))
        return_pct = float(result.metrics.get("total_return_pct", 0))
        if not math.isfinite(sharpe) or not math.isfinite(return_pct):
            raise ValueError("参数面结果必须是有限数")
        rows.append({
            "params": params,
            "sharpe": sharpe,
            "return_pct": return_pct,
        })
    if len(cost_hashes) != 1:
        raise ValueError("参数面所有运行必须使用同一 cost model manifest")
    positive = [row for row in rows if row["sharpe"] > 0]
    sharpes = pd.Series([row["sharpe"] for row in rows], dtype=float)
    positive_indexes = {
        index
        for index, row in enumerate(rows)
        if row["sharpe"] > 0
    }
    dimensions = [len(normalized_grid[name]) for name in names]

    def coordinates(flat_index: int) -> tuple[int, ...]:
        result: list[int] = []
        for size in reversed(dimensions):
            result.append(flat_index % size)
            flat_index //= size
        return tuple(reversed(result))

    coords = {index: coordinates(index) for index in positive_indexes}
    largest_component = 0
    unseen = set(positive_indexes)
    while unseen:
        stack = [unseen.pop()]
        component = 0
        while stack:
            current = stack.pop()
            component += 1
            current_coord = coords[current]
            neighbors = {
                candidate
                for candidate in unseen
                if sum(
                    abs(left - right)
                    for left, right in zip(
                        current_coord, coords[candidate], strict=True
                    )
                ) == 1
            }
            unseen -= neighbors
            stack.extend(neighbors)
        largest_component = max(largest_component, component)
    connected_positive_ratio = (
        largest_component / len(rows) if rows else 0
    )
    plateau = (
        len(rows) >= 3
        and len(positive) / len(rows) >= 0.6
        and connected_positive_ratio >= 0.6
        and float(sharpes.std(ddof=0)) <= max(abs(float(sharpes.mean())), 0.5)
    )
    family_manifest = build_strategy_family_manifest(strategies)
    family_hash = strategy_family_hash(family_manifest)
    return {
        "plateau": plateau,
        "positive_ratio": len(positive) / len(rows) if rows else 0,
        "connected_positive_ratio": connected_positive_ratio,
        "mean_sharpe": float(sharpes.mean()) if rows else 0,
        "sharpe_std": float(sharpes.std(ddof=0)) if rows else 0,
        "cost_model_hash": next(iter(cost_hashes)),
        "dataset_hash": dataframe_manifest_hash(data),
        "strategy_hash": family_hash,
        "strategy_family_manifest": family_manifest,
        "strategy_family_hash": family_hash,
        "evaluation_manifest_hash": canonical_manifest_hash(
            strategy_manifest
        ),
        "parameter_grid_manifest": parameter_grid_manifest,
        "parameter_grid_hash": parameter_grid_hash,
        "rows": rows,
    }
