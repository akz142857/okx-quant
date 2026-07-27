"""研究证据生产者之间的可重放契约。"""

from datetime import date

import numpy as np
import pandas as pd
import pytest

from okx_quant.backtest import BacktestEngine
from okx_quant.research.costs import (
    DynamicCostModel,
    canonical_manifest_hash,
)
from okx_quant.research.cycle import compute_calendar_cycle_metrics
from okx_quant.research.portfolio import PortfolioBacktester
from okx_quant.research.stress import (
    evaluate_parameter_surface,
    evaluate_portfolio_stress_scenarios,
)
from okx_quant.research.walk_forward import WalkForwardRunner
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType


class BuyHold(BaseStrategy):
    name = "producer_buy_hold"

    def generate_signal(self, df, inst_id):
        close = float(df["close"].iloc[-1])
        return Signal(
            SignalType.BUY,
            inst_id,
            close,
            size_pct=1,
            stop_loss=close * 0.5,
            reason="buy",
        )


def _candles(
    n: int = 40,
    *,
    dates: pd.DatetimeIndex | None = None,
    close: pd.Series | None = None,
) -> pd.DataFrame:
    dates = dates if dates is not None else pd.date_range(
        "2024-01-01",
        periods=n,
        freq="D",
        tz="UTC",
    )
    close = close if close is not None else pd.Series(
        [100 + index for index in range(len(dates))],
        dtype=float,
    )
    return pd.DataFrame({
        "ts": dates,
        "open": close,
        "high": close * 1.01,
        "low": close * 0.99,
        "close": close,
        "vol": 1_000,
        "vol_ccy": 100_000,
    })


@pytest.mark.unit
def test_portfolio_uses_shared_calendar_window_cycle_metrics():
    all_dates = pd.date_range(
        "2023-01-01",
        periods=410,
        freq="D",
        tz="UTC",
    )
    dates = all_dates[
        np.array([index % 10 != 5 for index in range(len(all_dates))])
    ]
    midpoint = len(dates) // 2
    close = pd.Series(np.concatenate([
        np.linspace(100, 170, midpoint),
        np.linspace(170, 75, len(dates) - midpoint),
    ]))
    result = PortfolioBacktester().run(
        {"BTC-USDT": _candles(dates=dates, close=close)},
        lambda _inst: BuyHold(),
    )
    points = [
        (date.fromisoformat(item["day"]), float(item["value"]))
        for item in result.metrics["cycle_daily_benchmark"]
    ]
    recomputed = compute_calendar_cycle_metrics(points)
    for key, value in recomputed.items():
        assert result.metrics[key] == pytest.approx(value)

    benchmark = pd.Series(
        [value for _, value in points],
        index=pd.DatetimeIndex([day for day, _ in points]),
    )
    old_observation_window = benchmark.pct_change(
        periods=90,
        fill_method=None,
    ).max()
    assert result.metrics["cycle_max_return"] != pytest.approx(
        old_observation_window
    )
    assert result.metrics["cycle_benchmark_weights"] == {
        "BTC-USDT": 1.0,
    }
    assert (
        result.metrics["strategy_hash"]
        == result.metrics["evaluation_manifest_hash"]
    )


@pytest.mark.unit
def test_walk_forward_and_parameter_surface_share_strategy_family():
    data = _candles(24)
    model = DynamicCostModel(maximum_slippage=0.01)

    def strategy_factory(params):
        return BuyHold(params)

    walk_forward = WalkForwardRunner(
        train_bars=6,
        test_bars=6,
        cost_model=model,
    ).run(
        data,
        "BTC-USDT",
        optimize=lambda _train: {"period": 10},
        strategy_factory=strategy_factory,
    )
    surface = evaluate_parameter_surface(
        data,
        "BTC-USDT",
        strategy_factory,
        {"period": [5, 10, 15]},
        engine_factory=lambda: BacktestEngine(cost_model=model),
    )

    assert (
        walk_forward.metrics["strategy_family_manifest"]
        == surface["strategy_family_manifest"]
    )
    assert (
        walk_forward.metrics["strategy_family_hash"]
        == surface["strategy_family_hash"]
    )
    assert (
        walk_forward.metrics["evaluation_manifest_hash"]
        != surface["evaluation_manifest_hash"]
    )
    assert (
        walk_forward.metrics["strategy_hash"]
        == walk_forward.metrics["strategy_family_hash"]
    )
    assert surface["strategy_hash"] == surface["strategy_family_hash"]


@pytest.mark.unit
def test_parameter_surface_binds_complete_ordered_grid_manifest():
    grid = {
        "threshold": [0.2, 0.1],
        "period": [5, 10],
    }
    result = evaluate_parameter_surface(
        _candles(8),
        "BTC-USDT",
        lambda params: BuyHold(params),
        grid,
    )

    manifest = result["parameter_grid_manifest"]
    assert manifest == {
        "version": 1,
        "parameters": {
            "period": [5, 10],
            "threshold": [0.2, 0.1],
        },
        "point_count": 4,
    }
    assert result["parameter_grid_hash"] == canonical_manifest_hash(manifest)
    assert [row["params"] for row in result["rows"]] == [
        {"period": 5, "threshold": 0.2},
        {"period": 5, "threshold": 0.1},
        {"period": 10, "threshold": 0.2},
        {"period": 10, "threshold": 0.1},
    ]


@pytest.mark.unit
def test_parameter_surface_rejects_duplicate_grid_values():
    with pytest.raises(ValueError, match="重复值"):
        evaluate_parameter_surface(
            _candles(8),
            "BTC-USDT",
            lambda params: BuyHold(params),
            {"period": [5, 5, 10]},
        )


@pytest.mark.unit
def test_stress_evidence_contains_recomputable_scenario_contract():
    result = evaluate_portfolio_stress_scenarios(
        {"BTC-USDT": _candles()},
        lambda _inst: BuyHold(),
        [
            {
                "name": " liquidity-gap ",
                "gap_ratio": 0.05,
                "volume_multiplier": 0.1,
                "volatility_multiplier": 2,
            },
            {
                "name": "wide-range",
                "gap_ratio": 0,
                "volume_multiplier": 0.5,
                "volatility_multiplier": 3,
            },
        ],
        backtester_factory=lambda: PortfolioBacktester(
            cost_model=DynamicCostModel(maximum_slippage=0.01),
        ),
    )

    assert result["scenario_manifest_hash"] == canonical_manifest_hash(
        result["scenario_manifest"]
    )
    assert [item["name"] for item in result["scenario_manifest"]] == [
        "liquidity-gap",
        "wide-range",
    ]
    for row, definition in zip(
        result["scenarios"],
        result["scenario_manifest"],
        strict=True,
    ):
        assert row["scenario"] == definition
        assert row["scenario_hash"] == canonical_manifest_hash(definition)
        assert row["loss_usdt"] == max(
            result["initial_capital"] - row["final_capital"],
            0,
        )
    assert result["loss_usdt"] == max(
        row["loss_usdt"] for row in result["scenarios"]
    )


@pytest.mark.unit
def test_stress_evidence_rejects_boolean_scenario_values():
    with pytest.raises(ValueError, match="必须是有限数"):
        evaluate_portfolio_stress_scenarios(
            {"BTC-USDT": _candles()},
            lambda _inst: BuyHold(),
            [{
                "name": "bad",
                "gap_ratio": True,
                "volume_multiplier": 1,
                "volatility_multiplier": 1,
            }],
            backtester_factory=PortfolioBacktester,
        )
