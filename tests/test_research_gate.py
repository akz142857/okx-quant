"""组合、动态成本、walk-forward 与 30 天准入门禁。"""

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest
import yaml

from okx_quant.application.approval import canonical_bytes
from okx_quant.backtest import BacktestEngine
from okx_quant.config import ProductionSettings
from okx_quant.ops.demo_chaos_evidence import DRILL_SCENARIOS
from okx_quant.research.admission import (
    AdmissionApprovalVerifier,
    AdmissionGate,
    DemoObservationLedger,
    build_admission_request,
)
from okx_quant.research.costs import DynamicCostModel, canonical_manifest_hash
from okx_quant.research.portfolio import PortfolioBacktester
from okx_quant.research.provenance import build_dataset_provenance
from okx_quant.research.stress import (
    apply_market_stress,
    evaluate_parameter_surface,
    evaluate_portfolio_stress_scenarios,
)
from okx_quant.research.walk_forward import WalkForwardRunner
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from scripts import production_gate as gate_module
from scripts import production_launch as launch_module
from scripts.deployment_receipt import (
    build_deployment_receipt,
    validate_deployment_receipt,
)
from scripts.production_gate import (
    _evaluate,
    _runtime_config_hash,
    _validate_clean_streak_aggregate,
)
from scripts.production_launch import _live_argv, _load_launch_manifest
from scripts.sign_research_artifact import _validate as validate_research_request


def _stage_c_coverage() -> dict:
    return {
        "version": 1,
        "action": "verify-stage-c-wp4-wp5-coverage",
        "scenario_count": len(DRILL_SCENARIOS),
    }


def _stage_c_coverage_sha256() -> str:
    return hashlib.sha256(canonical_bytes(_stage_c_coverage())).hexdigest()


class BuyHold(BaseStrategy):
    name = "buy_hold"

    def generate_signal(self, df, inst_id):
        return Signal(
            SignalType.BUY,
            inst_id,
            float(df["close"].iloc[-1]),
            size_pct=1,
            stop_loss=float(df["close"].iloc[-1]) * 0.5,
            reason="buy",
        )


class ScriptedStrategy(BaseStrategy):
    name = "scripted"

    def __init__(self, script):
        super().__init__()
        self.script = script

    def generate_signal(self, df, inst_id):
        signal = self.script.get(len(df), SignalType.HOLD)
        close = float(df["close"].iloc[-1])
        return Signal(
            signal,
            inst_id,
            close,
            size_pct=1,
            stop_loss=close * 0.9,
            reason=signal.value,
        )


class BuyWithoutStop(BaseStrategy):
    name = "buy_without_stop"

    def generate_signal(self, df, inst_id):
        return Signal(
            SignalType.BUY,
            inst_id,
            float(df["close"].iloc[-1]),
            size_pct=1,
            take_profit=1_000_000,
            reason="buy",
        )


def _candles(n=40, offset=0):
    ts = pd.date_range("2024-01-01", periods=n, freq="D")
    close = pd.Series([100 + offset + i for i in range(n)])
    return pd.DataFrame({
        "ts": ts,
        "open": close,
        "high": close * 1.01,
        "low": close * 0.99,
        "close": close,
        "vol": 1000,
        "vol_ccy": 100_000,
    })


_COST_MANIFEST = {
    "model": "okx_quant.research.costs.DynamicCostModel",
    "fee_rate": 0.001,
    "minimum_slippage": 0.0005,
    "range_fraction": 0.05,
    "impact_coefficient": 0.10,
    "maximum_slippage": 0.01,
    "stress_multiplier": 1.0,
}
_COST_HASH = canonical_manifest_hash(_COST_MANIFEST)

_FAMILY_MANIFEST = {
    "version": 1,
    "strategy_types": [f"{BuyHold.__module__}.{BuyHold.__qualname__}"],
}
_FAMILY_HASH = canonical_manifest_hash(_FAMILY_MANIFEST)
_WF_EVALUATION_HASH = "6" * 64
_PORTFOLIO_EVALUATION_HASH = "1" * 64
_ROBUSTNESS_EVALUATION_HASH = "7" * 64
_GRID_MANIFEST = {
    "version": 1,
    "parameters": {"period": [5, 10, 15, 20, 25]},
    "point_count": 5,
}
_GRID_HASH = canonical_manifest_hash(_GRID_MANIFEST)
_SCENARIO_MANIFEST = [{
    "name": "liquidity-gap",
    "gap_ratio": 0.10,
    "volume_multiplier": 0.1,
    "volatility_multiplier": 3.0,
}]
_SCENARIO_HASH = canonical_manifest_hash(_SCENARIO_MANIFEST)


def _cycle_points():
    first = date(2024, 1, 1)
    points = []
    for offset in range(400):
        if offset <= 120:
            value = 100 * (1.6 ** (offset / 120))
        elif offset <= 240:
            value = 160 * (0.5 ** ((offset - 120) / 120))
        else:
            value = 80 * (1.625 ** ((offset - 240) / 159))
        points.append({
            "day": (first + timedelta(days=offset)).isoformat(),
            "value": value / 100,
        })
    return points


def _portfolio_source_frame():
    points = _cycle_points()
    close = pd.Series([point["value"] for point in points], dtype=float)
    return pd.DataFrame({
        "ts": pd.to_datetime([point["day"] for point in points], utc=True),
        "open": close,
        "high": close * 1.01,
        "low": close * 0.99,
        "close": close,
        "vol": 1000,
        "vol_ccy": 100_000,
    })


_PROVENANCE_NOW = datetime.now(UTC) - timedelta(hours=1)
_WF_PROVENANCE = build_dataset_provenance(
    {"BTC-USDT": _candles(397)},
    kind="walk_forward",
    provider="OKX",
    bar="1D",
    source_uri="s3://fixture/walk-forward.json",
    source_version_id="wf-version-1",
    retrieved_at=_PROVENANCE_NOW,
)
_PORTFOLIO_PROVENANCE = build_dataset_provenance(
    {"BTC-USDT": _portfolio_source_frame()},
    kind="portfolio",
    provider="OKX",
    bar="1D",
    source_uri="s3://fixture/portfolio.json",
    source_version_id="portfolio-version-1",
    retrieved_at=_PROVENANCE_NOW,
)

_RESEARCH_IDENTITY = {
    "walk_forward": {
        "cost_model_hash": _COST_HASH,
        "dataset_hash": _WF_PROVENANCE["dataset_hash"],
        "strategy_hash": _FAMILY_HASH,
        "evaluation_manifest_hash": _WF_EVALUATION_HASH,
    },
    "portfolio": {
        "cost_model_hash": _COST_HASH,
        "dataset_hash": _PORTFOLIO_PROVENANCE["dataset_hash"],
        "strategy_hash": _PORTFOLIO_EVALUATION_HASH,
        "evaluation_manifest_hash": _PORTFOLIO_EVALUATION_HASH,
    },
    "robustness": {
        "cost_model_hash": _COST_HASH,
        "dataset_hash": _WF_PROVENANCE["dataset_hash"],
        "strategy_hash": _FAMILY_HASH,
        "evaluation_manifest_hash": _ROBUSTNESS_EVALUATION_HASH,
        "parameter_grid_hash": _GRID_HASH,
    },
    "stress": {
        "cost_model_hash": _COST_HASH,
        "dataset_hash": _PORTFOLIO_PROVENANCE["dataset_hash"],
        "strategy_hash": _PORTFOLIO_EVALUATION_HASH,
        "scenario_manifest_hash": _SCENARIO_HASH,
    },
}


def _metadata():
    now = datetime.now(UTC)
    return {
        "commit_sha": "a" * 40,
        "config_hash": "b" * 64,
        "cost_model_hash": _COST_HASH,
        "cost_model_manifest": _COST_MANIFEST,
        "dataset_provenance": {
            "walk_forward": json.loads(json.dumps(_WF_PROVENANCE)),
            "portfolio": json.loads(json.dumps(_PORTFOLIO_PROVENANCE)),
        },
        "research_manifest_hash": canonical_manifest_hash(
            _RESEARCH_IDENTITY
        ),
        "approved_max_slippage_ratio": 0.01,
        "monitor_key_fingerprint": "3" * 64,
        "research_policy_key_fingerprint": "4" * 64,
        "account_id": "demo-fixture",
        "environment": "canary",
        "evidence_uri": "s3://fixture/evidence.json",
        "generated_at": now.isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "operator": "fixture-operator",
        "risk_approver": "fixture-approver",
    }


def _portfolio_admission_metrics(**overrides):
    points = _cycle_points()
    metrics = {
        "total_return_pct": 10,
        "covers_full_cycle": True,
        "shared_cash": True,
        "cost_model_hash": _COST_HASH,
        "dataset_hash": _PORTFOLIO_PROVENANCE["dataset_hash"],
        "strategy_hash": _PORTFOLIO_EVALUATION_HASH,
        "evaluation_manifest_hash": _PORTFOLIO_EVALUATION_HASH,
        "cycle_benchmark_weights": {"BTC-USDT": 1.0},
        "cycle_regime_threshold": 0.20,
        "cycle_daily_benchmark": points,
    }
    computed = AdmissionGate._recompute_cycle(metrics)
    metrics.update({
        key: value
        for key, value in computed.items()
        if key != "covers_full_cycle"
    })
    metrics.update(overrides)
    return metrics


def _robustness_admission_metrics(**overrides):
    rows = [
        {
            "params": {"period": period},
            "sharpe": sharpe,
            "return_pct": 5,
        }
        for period, sharpe in zip(
            [5, 10, 15, 20, 25],
            [0.9, 1.0, 1.1, 1.0, 0.9],
            strict=True,
        )
    ]
    metrics = {
        "plateau": True,
        "cost_model_hash": _COST_HASH,
        "dataset_hash": _WF_PROVENANCE["dataset_hash"],
        "strategy_hash": _FAMILY_HASH,
        "strategy_family_manifest": _FAMILY_MANIFEST,
        "strategy_family_hash": _FAMILY_HASH,
        "evaluation_manifest_hash": _ROBUSTNESS_EVALUATION_HASH,
        "parameter_grid_manifest": _GRID_MANIFEST,
        "parameter_grid_hash": _GRID_HASH,
        "rows": rows,
    }
    computed = AdmissionGate._recompute_robustness(metrics)
    metrics.update({
        key: value for key, value in computed.items() if key != "plateau"
    })
    metrics.update(overrides)
    return metrics


def _stress_admission_evidence(**overrides):
    scenario = _SCENARIO_MANIFEST[0]
    evidence = {
        "loss_usdt": 100.0,
        **_RESEARCH_IDENTITY["stress"],
        "scenario_manifest": _SCENARIO_MANIFEST,
        "initial_capital": 10_000.0,
        "scenarios": [{
            "name": scenario["name"],
            "scenario": scenario,
            "scenario_hash": canonical_manifest_hash(scenario),
            "final_capital": 9_900.0,
            "loss_usdt": 100.0,
            "stressed_dataset_hash": "8" * 64,
        }],
    }
    evidence.update(overrides)
    return evidence


def _research_policy_claims():
    return {
        "version": 1,
        "action": "pre-register-research-policy",
        "policy_id": "fixture-policy-v1",
        "commit_sha": "a" * 40,
        "strategy_family_hash": _FAMILY_HASH,
        "parameter_grid_hash": _GRID_HASH,
        "stress_scenario_manifest_hash": _SCENARIO_HASH,
        "dataset_sources": {
            name: {
                key: manifest[key]
                for key in (
                    "source_uri",
                    "source_version_id",
                    "source_sha256",
                )
            }
            for name, manifest in {
                "walk_forward": _WF_PROVENANCE,
                "portfolio": _PORTFOLIO_PROVENANCE,
            }.items()
        },
        "evaluation_started_at": "2026-07-27T00:00:00+00:00",
        "issued_at": int(
            datetime(2026, 7, 26, 23, tzinfo=UTC).timestamp()
        ),
    }


def _stress_runner_claims(stress_evidence):
    return {
        "version": 1,
        "action": "attest-stress-run",
        "policy_id": "fixture-policy-v1",
        "commit_sha": "a" * 40,
        "dataset_hash": stress_evidence["dataset_hash"],
        "cost_model_hash": stress_evidence["cost_model_hash"],
        "portfolio_evaluation_manifest_hash": (
            _PORTFOLIO_EVALUATION_HASH
        ),
        "scenario_manifest_hash": stress_evidence[
            "scenario_manifest_hash"
        ],
        "stress_evidence_sha256": hashlib.sha256(
            json.dumps(
                stress_evidence,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "runner": "independent-research-runner",
        "issued_at": int(
            datetime(2026, 7, 27, 1, tzinfo=UTC).timestamp()
        ),
    }


def _admission_inputs(**overrides):
    stress_evidence = _stress_admission_evidence()
    values = {
        "walk_forward_metrics": {
            "folds": 4,
            "positive_folds": 3,
            "oos_sharpe_ratio": 1,
            "oos_return_pct": 10,
            "oos_observations": 100,
            "oos_duration_days": 99,
            "oos_total_trades": 4,
            "oos_max_drawdown_pct": -5,
            "strategy_family_manifest": _FAMILY_MANIFEST,
            "strategy_family_hash": _FAMILY_HASH,
            **_RESEARCH_IDENTITY["walk_forward"],
        },
        "portfolio_metrics": _portfolio_admission_metrics(),
        "robustness": _robustness_admission_metrics(),
        "stress_evidence": stress_evidence,
        "clean_demo_days": 30,
        "demo_slippage_observations": [0.001] * 30,
        "engineering_checks": {
            name: True
            for name in AdmissionGate().required_engineering_checks
        },
        "operational_checks": {
            name: True
            for name in AdmissionGate().required_operational_checks
        },
        "evidence_metadata": _metadata(),
        "research_policy_claims": _research_policy_claims(),
        "stress_runner_claims": _stress_runner_claims(
            stress_evidence
        ),
    }
    values.update(overrides)
    if "stress_evidence" in overrides and (
        "stress_runner_claims" not in overrides
    ):
        values["stress_runner_claims"] = _stress_runner_claims(
            values["stress_evidence"]
        )
    return values


def _sign_payload(tmp_path, claims):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    if not private_key.exists():
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
        )
    with tempfile.NamedTemporaryFile() as message:
        message.write(canonical_bytes(claims))
        message.flush()
        signature = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                message.name,
            ],
            check=True,
            capture_output=True,
        ).stdout
    return public_key, {
        "payload": claims,
        "signature": base64.b64encode(signature).decode(),
    }


@pytest.mark.unit
def test_dynamic_cost_increases_when_liquidity_falls():
    model = DynamicCostModel()
    liquid = _candles(1).iloc[0]
    illiquid = liquid.copy()
    illiquid["vol_ccy"] = 100
    assert model("buy", illiquid, 1000)[1] > model("buy", liquid, 1000)[1]
    assert len(model.manifest_hash()) == 64


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("close", float("nan")),
        ("high", float("inf")),
        ("low", -1),
        ("vol_ccy", float("nan")),
    ],
)
def test_dynamic_cost_rejects_invalid_market_inputs(field, value):
    bar = _candles(1).iloc[0].copy()
    bar[field] = value
    with pytest.raises(ValueError, match="有限|OHLC"):
        DynamicCostModel()("buy", bar, 1000)


@pytest.mark.unit
@pytest.mark.parametrize("notional", [float("nan"), float("inf"), -1])
def test_dynamic_cost_rejects_invalid_notional(notional):
    with pytest.raises(ValueError, match="notional"):
        DynamicCostModel()("buy", _candles(1).iloc[0], notional)


@pytest.mark.unit
def test_market_stress_rejects_nan_source_data():
    data = _candles(3)
    data.loc[1, "close"] = np.nan
    with pytest.raises(ValueError, match="有限"):
        apply_market_stress(data)


@pytest.mark.unit
@pytest.mark.parametrize(
    "kwargs",
    [
        {"stress_multiplier": -1},
        {"fee_rate": float("nan")},
        {"minimum_slippage": 0.2, "maximum_slippage": 0.1},
        {"maximum_slippage": 1},
    ],
)
def test_dynamic_cost_rejects_nonfinite_or_unsafe_parameters(kwargs):
    with pytest.raises(ValueError):
        DynamicCostModel(**kwargs)


@pytest.mark.unit
def test_portfolio_backtest_combines_capital_without_leverage():
    result = PortfolioBacktester(initial_capital=10_000).run(
        {"BTC-USDT": _candles(), "ETH-USDT": _candles(offset=20)},
        lambda _inst: BuyHold(),
    )
    assert result.metrics["initial_capital"] == 10_000
    assert result.metrics["final_capital"] > 10_000
    assert set(result.component_results) == {"BTC-USDT", "ETH-USDT"}


@pytest.mark.unit
def test_short_portfolio_sample_cannot_claim_full_market_cycle():
    result = PortfolioBacktester().run(
        {"BTC-USDT": _candles(2)},
        lambda _inst: BuyHold(),
    )
    assert result.metrics["cycle_duration_days"] == 2
    assert not result.metrics["covers_full_cycle"]


@pytest.mark.unit
def test_full_cycle_requires_observed_bull_and_bear_regimes():
    close = pd.Series(np.concatenate([
        np.linspace(100, 160, 180),
        np.linspace(160, 90, 180),
        np.linspace(90, 120, 41),
    ]))
    data = pd.DataFrame({
        "ts": pd.date_range("2023-01-01", periods=len(close), freq="D"),
        "open": close,
        "high": close * 1.01,
        "low": close * 0.99,
        "close": close,
        "vol": 1000,
        "vol_ccy": 100_000,
    })
    result = PortfolioBacktester().run(
        {"BTC-USDT": data},
        lambda _inst: BuyHold(),
    )
    assert result.metrics["cycle_duration_days"] >= 365
    assert result.metrics["cycle_max_return"] >= 0.20
    assert result.metrics["cycle_min_return"] <= -0.20
    assert result.metrics["covers_full_cycle"]


@pytest.mark.unit
def test_sparse_bars_cannot_fabricate_full_cycle():
    close = pd.Series([100, 140, 80, 120], dtype=float)
    data = pd.DataFrame({
        "ts": pd.to_datetime([
            "2023-01-01",
            "2023-05-01",
            "2023-09-01",
            "2024-01-02",
        ]),
        "open": close,
        "high": close * 1.01,
        "low": close * 0.99,
        "close": close,
        "vol": 1000,
        "vol_ccy": 100_000,
    })
    result = PortfolioBacktester().run(
        {"BTC-USDT": data},
        lambda _inst: BuyHold(),
    )
    assert result.metrics["cycle_observations"] == 4
    assert result.metrics["cycle_coverage"] < 0.02
    assert not result.metrics["covers_full_cycle"]


@pytest.mark.unit
def test_portfolio_weights_and_limits_are_bound_to_strategy_identity():
    datasets = {
        "UP-USDT": _candles(),
        "DOWN-USDT": _candles().assign(
            open=lambda frame: 200 - frame.index,
            high=lambda frame: (200 - frame.index) * 1.01,
            low=lambda frame: (200 - frame.index) * 0.99,
            close=lambda frame: 200 - frame.index,
        ),
    }
    up = PortfolioBacktester().run(
        datasets,
        lambda _inst: BuyHold(),
        weights={"UP-USDT": 1, "DOWN-USDT": 0},
    )
    down = PortfolioBacktester().run(
        datasets,
        lambda _inst: BuyHold(),
        weights={"UP-USDT": 0, "DOWN-USDT": 1},
    )
    assert up.metrics["strategy_hash"] != down.metrics["strategy_hash"]


@pytest.mark.unit
def test_full_cycle_definition_is_bound_to_portfolio_identity():
    data = _candles(400)
    permissive = PortfolioBacktester(
        cycle_regime_threshold=0.20,
    ).run({"BTC-USDT": data}, lambda _inst: BuyHold())
    strict = PortfolioBacktester(
        cycle_regime_threshold=0.40,
    ).run({"BTC-USDT": data}, lambda _inst: BuyHold())
    assert (
        permissive.metrics["strategy_hash"]
        != strict.metrics["strategy_hash"]
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "weights",
    [
        {"BTC-USDT": -1},
        {"BTC-USDT": float("nan")},
        {"BTC-USDT": True},
    ],
)
def test_portfolio_rejects_invalid_weights(weights):
    with pytest.raises(ValueError, match="权重"):
        PortfolioBacktester().run(
            {"BTC-USDT": _candles()},
            lambda _inst: BuyHold(),
            weights=weights,
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    "max_positions",
    [float("nan"), 1.5, True, 0],
)
def test_portfolio_rejects_invalid_position_limit(max_positions):
    with pytest.raises(ValueError, match="max_open_positions"):
        PortfolioBacktester(max_open_positions=max_positions)


@pytest.mark.unit
@pytest.mark.parametrize(
    "costs",
    [
        (-0.2, -0.3),
        (float("nan"), 0),
        (0, float("inf")),
        (1, 0),
    ],
)
def test_backtest_engine_rejects_invalid_custom_cost_output(costs):
    engine = BacktestEngine(cost_model=lambda *_args: costs)
    with pytest.raises(ValueError, match="cost_model"):
        engine.run(_candles(3), BuyHold(), "BTC-USDT")


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("close", 0),
        ("open", float("nan")),
        ("high", float("inf")),
        ("low", 1_000),
        ("vol", -1),
        ("vol", True),
    ],
)
def test_research_entrypoints_fail_closed_on_invalid_ohlcv(field, value):
    data = _candles(8)
    if isinstance(value, bool):
        data[field] = data[field].astype(object)
    data.loc[3, field] = value

    with pytest.raises(ValueError, match="OHLC|vol"):
        BacktestEngine().run(data, BuyHold(), "BTC-USDT")
    with pytest.raises(ValueError, match="OHLC|vol"):
        PortfolioBacktester().run(
            {"BTC-USDT": data},
            lambda _inst: BuyHold(),
        )
    with pytest.raises(ValueError, match="OHLC|vol"):
        WalkForwardRunner(train_bars=2, test_bars=2).run(
            data,
            "BTC-USDT",
            lambda _train: {},
            lambda _params: BuyHold(),
        )


@pytest.mark.unit
def test_research_entrypoints_reject_boolean_price_cycle_forgery():
    data = _candles(400)
    data[["open", "high", "low", "close"]] = data[
        ["open", "high", "low", "close"]
    ].astype(object)
    data.loc[200, ["open", "high", "low", "close"]] = True

    with pytest.raises(ValueError, match="禁止布尔值"):
        BacktestEngine().run(data, BuyHold(), "BTC-USDT")
    with pytest.raises(ValueError, match="禁止布尔值"):
        PortfolioBacktester().run(
            {"BTC-USDT": data},
            lambda _inst: BuyHold(),
        )
    with pytest.raises(ValueError, match="禁止布尔值"):
        WalkForwardRunner(train_bars=100, test_bars=100).run(
            data,
            "BTC-USDT",
            lambda _train: {},
            lambda _params: BuyHold(),
        )


@pytest.mark.unit
def test_portfolio_shared_cash_enforces_cross_asset_position_limit():
    result = PortfolioBacktester(
        initial_capital=10_000,
        max_open_positions=1,
    ).run(
        {"BTC-USDT": _candles(), "ETH-USDT": _candles(offset=20)},
        lambda _inst: BuyHold(),
    )
    assert result.metrics["total_trades"] == 1
    assert sum(
        component.metrics["total_trades"]
        for component in result.component_results.values()
    ) == 1


@pytest.mark.unit
def test_portfolio_processes_all_exits_before_competing_entries():
    data = _candles(4)
    scripts = {
        "A-USDT": {2: SignalType.BUY},
        "B-USDT": {1: SignalType.BUY, 2: SignalType.SELL},
    }
    result = PortfolioBacktester(
        initial_capital=10_000,
        fee_rate=0,
        slippage=0,
        max_open_positions=1,
    ).run(
        {"A-USDT": data, "B-USDT": data},
        lambda inst: ScriptedStrategy(scripts[inst]),
    )
    assert result.metrics["total_trades"] == 2


@pytest.mark.unit
def test_portfolio_does_not_use_future_intrabar_stop_to_admit_open_entry():
    data = _candles(4)
    data.loc[2, "low"] = 80
    scripts = {
        "A-USDT": {2: SignalType.BUY},
        "B-USDT": {1: SignalType.BUY},
    }
    result = PortfolioBacktester(
        initial_capital=10_000,
        fee_rate=0,
        slippage=0,
        max_open_positions=1,
    ).run(
        {"A-USDT": data, "B-USDT": data},
        lambda inst: ScriptedStrategy(scripts[inst]),
    )
    assert result.metrics["total_trades"] == 1


@pytest.mark.unit
def test_portfolio_gap_stop_releases_slot_before_open_entry():
    data = _candles(4)
    data.loc[2, "open"] = 80
    data.loc[2, "low"] = 79
    scripts = {
        "A-USDT": {2: SignalType.BUY},
        "B-USDT": {1: SignalType.BUY},
    }
    result = PortfolioBacktester(
        initial_capital=10_000,
        fee_rate=0,
        slippage=0,
        max_open_positions=1,
    ).run(
        {"A-USDT": data, "B-USDT": data},
        lambda inst: ScriptedStrategy(scripts[inst]),
    )
    assert result.metrics["total_trades"] == 2


@pytest.mark.unit
def test_portfolio_gap_through_stop_uses_worse_open_price():
    data = pd.DataFrame({
        "ts": pd.date_range("2024-01-01", periods=3, freq="D"),
        "open": [100, 100, 50],
        "high": [101, 101, 55],
        "low": [99, 95, 45],
        "close": [100, 100, 50],
        "vol": [1000, 1000, 1000],
        "vol_ccy": [100_000, 100_000, 100_000],
    })
    result = PortfolioBacktester(
        initial_capital=10_000,
        fee_rate=0,
        slippage=0,
    ).run(
        {"BTC-USDT": data},
        lambda _inst: ScriptedStrategy({1: SignalType.BUY}),
    )
    trade = result.component_results["BTC-USDT"].trades[0]
    assert trade.reason_close == "stop_loss"
    assert trade.exit_price == 50


@pytest.mark.unit
def test_walk_forward_only_reports_out_of_sample_folds():
    result = WalkForwardRunner(
        train_bars=15, test_bars=10, step_bars=10
    ).run(
        _candles(40),
        "BTC-USDT",
        optimize=lambda _train: {},
        strategy_factory=lambda _params: BuyHold(),
    )
    assert result.metrics["folds"] == 2
    assert result.metrics["positive_folds"] == 2
    assert result.metrics["oos_return_pct"] > 0
    # 现金与持仓贯穿 fold，只在整个连续 OOS 末尾强平一次。
    assert sum(
        fold.result.metrics["total_trades"] for fold in result.folds
    ) == 1


@pytest.mark.unit
def test_walk_forward_split_definition_is_bound_to_evaluation_identity():
    data = _candles(40)
    first = WalkForwardRunner(train_bars=10, test_bars=10).run(
        data,
        "BTC-USDT",
        optimize=lambda _train: {},
        strategy_factory=lambda _params: BuyHold(),
    )
    second = WalkForwardRunner(train_bars=25, test_bars=5).run(
        data,
        "BTC-USDT",
        optimize=lambda _train: {},
        strategy_factory=lambda _params: BuyHold(),
    )
    assert (
        first.metrics["evaluation_manifest_hash"]
        != second.metrics["evaluation_manifest_hash"]
    )
    assert (
        first.metrics["strategy_family_hash"]
        == second.metrics["strategy_family_hash"]
    )


@pytest.mark.unit
def test_walk_forward_normalizes_descending_time_without_future_leak():
    result = WalkForwardRunner(
        train_bars=15,
        test_bars=10,
    ).run(
        _candles(40).iloc[::-1],
        "BTC-USDT",
        optimize=lambda _train: {},
        strategy_factory=lambda _params: BuyHold(),
    )
    assert all(
        fold.train_end < fold.test_start
        for fold in result.folds
    )


@pytest.mark.unit
def test_walk_forward_rejects_gapped_oos_schedule():
    with pytest.raises(ValueError, match="step_bars == test_bars"):
        WalkForwardRunner(train_bars=15, test_bars=10, step_bars=11)


@pytest.mark.unit
def test_walk_forward_drawdown_includes_first_oos_bar():
    data = _candles(9)
    data[["open", "high", "low", "close"]] = [
        [100, 101, 99, 100],
        [100, 101, 99, 100],
        [100, 101, 99, 100],
        [100, 101, 99, 100],
        [100, 101, 99, 100],
        [100, 101, 49, 50],
        [50, 61, 49, 60],
        [60, 81, 59, 80],
        [80, 111, 79, 110],
    ]
    result = WalkForwardRunner(
        train_bars=5,
        test_bars=4,
        fee_rate=0,
        slippage=0,
    ).run(
        data,
        "BTC-USDT",
        optimize=lambda _train: {},
        strategy_factory=lambda _params: BuyWithoutStop(),
    )
    assert result.metrics["oos_return_pct"] == pytest.approx(10)
    assert result.metrics["oos_max_drawdown_pct"] == pytest.approx(-50)


@pytest.mark.unit
def test_stress_expands_range_and_reduces_volume():
    original = _candles(3)
    stressed = apply_market_stress(
        original,
        gap_ratio=0.05,
        volume_multiplier=0.1,
        volatility_multiplier=2,
    )
    assert stressed["vol"].iloc[0] == 100
    assert (
        stressed["high"].iloc[0] - stressed["low"].iloc[0]
        > original["high"].iloc[0] - original["low"].iloc[0]
    )
    assert (stressed["high"] >= stressed[["open", "close"]].max(axis=1)).all()
    assert (stressed["low"] <= stressed[["open", "close"]].min(axis=1)).all()


@pytest.mark.unit
def test_stress_evidence_is_produced_from_portfolio_contract():
    model = DynamicCostModel(maximum_slippage=0.01)
    result = evaluate_portfolio_stress_scenarios(
        {"BTC-USDT": _candles(40)},
        lambda _inst: BuyHold(),
        [{
            "name": "liquidity-gap",
            "gap_ratio": 0.05,
            "volume_multiplier": 0.1,
            "volatility_multiplier": 2,
        }],
        backtester_factory=lambda: PortfolioBacktester(
            cost_model=model,
        ),
    )
    assert result["cost_model_hash"] == model.manifest_hash()
    assert result["loss_usdt"] >= 0
    assert len(result["scenario_manifest_hash"]) == 64
    assert result["scenarios"][0]["name"] == "liquidity-gap"


@pytest.mark.unit
@pytest.mark.parametrize(
    "kwargs",
    [
        {"volume_multiplier": float("nan")},
        {"volatility_multiplier": float("inf")},
        {"gap_ratio": float("nan")},
    ],
)
def test_stress_rejects_nonfinite_parameters(kwargs):
    with pytest.raises(ValueError):
        apply_market_stress(_candles(3), **kwargs)


@pytest.mark.unit
def test_parameter_plateau_requires_connected_positive_region():
    scores = iter([1.0, -1.0, 1.0])

    class FixedEngine:
        def __init__(self):
            self.score = next(scores)

        def run(self, *_args):
            return SimpleNamespace(metrics={
                "sharpe_ratio": self.score,
                "total_return_pct": self.score,
            })

    result = evaluate_parameter_surface(
        _candles(3),
        "BTC-USDT",
        lambda _params: BuyHold(),
        {"period": [1, 2, 3]},
        engine_factory=FixedEngine,
    )
    assert result["positive_ratio"] == pytest.approx(2 / 3)
    assert result["connected_positive_ratio"] == pytest.approx(1 / 3)
    assert result["plateau"] is False


@pytest.mark.unit
def test_admission_gate_remains_closed_until_30_clean_days(tmp_path):
    first = date(2026, 1, 1)
    clock = [datetime(2026, 1, 1, 23, tzinfo=UTC)]
    ledger = DemoObservationLedger(
        tmp_path / "demo.json",
        clock=lambda: clock[0],
    )
    for offset in range(29):
        observed_day = first + timedelta(days=offset)
        clock[0] = datetime.combine(
            observed_day,
            datetime.min.time(),
            tzinfo=UTC,
        ) + timedelta(hours=23)
        ledger.append(
            day=observed_day,
            unexplained_mismatches=0,
            protection_p99_seconds=2,
            observed_slippage_ratio=0.001,
            git_commit="a" * 40,
            config_hash="b" * 64,
            account_id="demo-fixture",
            source_uri=f"s3://fixture/{observed_day}.json",
            observation_started_at=clock[0] - timedelta(hours=22),
            observation_ended_at=clock[0],
        )
    clean = ledger.consecutive_clean_days(
        max_slippage_ratio=0.01,
        expected_git_commit="a" * 40,
        expected_config_hash="b" * 64,
        expected_account_id="demo-fixture",
        as_of=first + timedelta(days=28),
    )
    stress_evidence = _stress_admission_evidence()
    inputs = dict(
        walk_forward_metrics={
            "folds": 4,
            "positive_folds": 3,
            "oos_sharpe_ratio": 1,
            "oos_return_pct": 10,
            "oos_observations": 100,
            "oos_duration_days": 99,
            "oos_total_trades": 4,
            "oos_max_drawdown_pct": -5,
            "strategy_family_manifest": _FAMILY_MANIFEST,
            "strategy_family_hash": _FAMILY_HASH,
            **_RESEARCH_IDENTITY["walk_forward"],
        },
        portfolio_metrics=_portfolio_admission_metrics(),
        robustness=_robustness_admission_metrics(),
        stress_evidence=stress_evidence,
        engineering_checks={
            name: True
            for name in AdmissionGate().required_engineering_checks
        },
        operational_checks={
            name: True
            for name in AdmissionGate().required_operational_checks
        },
        evidence_metadata=_metadata(),
        research_policy_claims=_research_policy_claims(),
        stress_runner_claims=_stress_runner_claims(stress_evidence),
    )
    assert not AdmissionGate().evaluate(
        clean_demo_days=clean,
        demo_slippage_observations=[0.001] * clean,
        **inputs,
    )["admitted"]
    observed_day = first + timedelta(days=29)
    clock[0] = datetime.combine(
        observed_day,
        datetime.min.time(),
        tzinfo=UTC,
    ) + timedelta(hours=23)
    ledger.append(
        day=observed_day,
        unexplained_mismatches=0,
        protection_p99_seconds=2,
        observed_slippage_ratio=0.001,
        git_commit="a" * 40,
        config_hash="b" * 64,
        account_id="demo-fixture",
        source_uri=f"s3://fixture/{observed_day}.json",
        observation_started_at=clock[0] - timedelta(hours=22),
        observation_ended_at=clock[0],
    )
    clean = ledger.consecutive_clean_days(
        max_slippage_ratio=0.01,
        expected_git_commit="a" * 40,
        expected_config_hash="b" * 64,
        expected_account_id="demo-fixture",
        as_of=first + timedelta(days=29),
    )
    assert AdmissionGate().evaluate(
        clean_demo_days=clean,
        demo_slippage_observations=[0.001] * clean,
        **inputs,
    )["admitted"]


@pytest.mark.unit
def test_admission_recomputes_cycle_instead_of_trusting_boolean():
    portfolio = _portfolio_admission_metrics()
    for index, point in enumerate(portfolio["cycle_daily_benchmark"]):
        point["value"] = 100 + index / 100
    computed = AdmissionGate._recompute_cycle(portfolio)
    portfolio.update({
        key: value
        for key, value in computed.items()
        if key != "covers_full_cycle"
    })
    portfolio["covers_full_cycle"] = True
    with pytest.raises(ValueError, match="benchmark 未绑定 source"):
        AdmissionGate().evaluate(
            **_admission_inputs(portfolio_metrics=portfolio)
        )


@pytest.mark.unit
def test_admission_recomputes_parameter_plateau_from_rows():
    robustness = _robustness_admission_metrics()
    for index, row in enumerate(robustness["rows"]):
        row["sharpe"] = 1 if index in {0, 4} else -1
    recomputed = AdmissionGate._recompute_robustness(robustness)
    robustness.update({
        key: value
        for key, value in recomputed.items()
        if key != "plateau"
    })
    robustness["plateau"] = True
    result = AdmissionGate().evaluate(
        **_admission_inputs(robustness=robustness)
    )
    assert not result["admitted"]
    assert not result["checks"]["parameter_plateau"]


@pytest.mark.unit
def test_admission_rejects_selected_subset_of_approved_parameter_grid():
    robustness = _robustness_admission_metrics()
    robustness["rows"] = robustness["rows"][1:4]
    with pytest.raises(ValueError, match="批准参数网格|至少需要"):
        AdmissionGate().evaluate(
            **_admission_inputs(robustness=robustness)
        )


@pytest.mark.unit
def test_external_research_policy_prevents_post_result_grid_shrink():
    robustness = _robustness_admission_metrics()
    robustness["rows"] = robustness["rows"][1:4]
    grid = {
        "version": 1,
        "parameters": {"period": [10, 15, 20]},
        "point_count": 3,
    }
    robustness["parameter_grid_manifest"] = grid
    robustness["parameter_grid_hash"] = canonical_manifest_hash(grid)
    computed = AdmissionGate._recompute_robustness(robustness)
    robustness.update({
        key: value
        for key, value in computed.items()
        if key != "plateau"
    })
    with pytest.raises(ValueError, match="policy 未绑定"):
        AdmissionGate().evaluate(
            **_admission_inputs(robustness=robustness)
        )


@pytest.mark.unit
def test_research_signer_requires_policy_before_evaluation():
    claims = _research_policy_claims()
    now = datetime.now(UTC)
    claims["issued_at"] = int(now.timestamp())
    claims["evaluation_started_at"] = (
        now + timedelta(hours=1)
    ).isoformat()
    assert validate_research_request(claims) == claims
    claims["evaluation_started_at"] = (
        now - timedelta(hours=1)
    ).isoformat()
    with pytest.raises(ValueError, match="预注册"):
        validate_research_request(claims)


@pytest.mark.unit
def test_admission_binds_dynamic_cost_and_demo_slippage():
    result = AdmissionGate().evaluate(
        **_admission_inputs(
            demo_slippage_observations=[0.011] * 30,
        )
    )
    assert not result["checks"]["demo_slippage_bound_to_cost_model"]

    metadata = _metadata()
    metadata["cost_model_manifest"] = {
        "model": "static_fee_and_slippage",
        "fee_rate": 0.001,
        "minimum_slippage": 0.001,
        "range_fraction": 0,
        "impact_coefficient": 0,
        "maximum_slippage": 0.01,
        "stress_multiplier": 1,
    }
    metadata["cost_model_hash"] = canonical_manifest_hash(
        metadata["cost_model_manifest"]
    )
    with pytest.raises(ValueError, match="DynamicCostModel"):
        AdmissionGate._validate_metadata(metadata)


@pytest.mark.unit
def test_admission_reuses_dynamic_cost_model_constructor_constraints():
    metadata = _metadata()
    manifest = dict(metadata["cost_model_manifest"])
    manifest["fee_rate"] = 0.75
    manifest["stress_multiplier"] = 2.0
    metadata["cost_model_manifest"] = manifest
    metadata["cost_model_hash"] = canonical_manifest_hash(manifest)
    with pytest.raises(ValueError, match="压力后的 fee_rate"):
        AdmissionGate().evaluate(
            **_admission_inputs(evidence_metadata=metadata)
        )


@pytest.mark.unit
def test_admission_rejects_dataset_provenance_identity_mismatch():
    metadata = _metadata()
    metadata["dataset_provenance"]["portfolio"]["dataset_hash"] = "9" * 64
    with pytest.raises(ValueError, match="source/research dataset_hash"):
        AdmissionGate().evaluate(
            **_admission_inputs(evidence_metadata=metadata)
        )


@pytest.mark.unit
def test_admission_verifies_embedded_dataset_source_bytes_and_shape():
    metadata = _metadata()
    portfolio = metadata["dataset_provenance"]["portfolio"]
    portfolio["rows"] = 1
    portfolio["bar"] = "1m"
    portfolio["instruments"] = ["NOT-IN-EVIDENCE"]
    with pytest.raises(ValueError, match="artifact identity|rows/time/instruments"):
        AdmissionGate().evaluate(
            **_admission_inputs(evidence_metadata=metadata)
        )

    metadata = _metadata()
    metadata["dataset_provenance"]["portfolio"][
        "source_uri"
    ] = "s3://fabricated-bucket/plausible.json"
    metadata["dataset_provenance"]["portfolio"][
        "source_version_id"
    ] = "fabricated-version"
    with pytest.raises(ValueError, match="exact dataset locator"):
        AdmissionGate().evaluate(
            **_admission_inputs(evidence_metadata=metadata)
        )

    metadata = _metadata()
    metadata["dataset_provenance"]["walk_forward"][
        "source_uri"
    ] = "https://example.invalid/mutable.csv"
    with pytest.raises(ValueError, match="版本化 S3"):
        AdmissionGate().evaluate(
            **_admission_inputs(evidence_metadata=metadata)
        )


@pytest.mark.unit
def test_admission_requires_recomputable_stress_schema():
    minimal = {
        "loss_usdt": 1,
        **_RESEARCH_IDENTITY["stress"],
    }
    with pytest.raises(ValueError, match="stress_evidence 字段"):
        AdmissionGate().evaluate(
            **_admission_inputs(stress_evidence=minimal)
        )


@pytest.mark.unit
def test_admission_rejects_noop_only_stress_policy():
    noop = {
        "name": "noop",
        "gap_ratio": 0.0,
        "volume_multiplier": 1.0,
        "volatility_multiplier": 1.0,
    }
    evidence = _stress_admission_evidence()
    evidence["scenario_manifest"] = [noop]
    evidence["scenario_manifest_hash"] = canonical_manifest_hash([noop])
    evidence["scenarios"][0].update({
        "name": "noop",
        "scenario": noop,
        "scenario_hash": canonical_manifest_hash(noop),
    })
    with pytest.raises(ValueError, match="生产硬下限场景"):
        AdmissionGate().evaluate(
            **_admission_inputs(stress_evidence=evidence)
        )


@pytest.mark.unit
def test_independent_runner_attestation_prevents_forged_stress_loss():
    forged = _stress_admission_evidence()
    forged["scenarios"][0]["final_capital"] = 10_000.0
    forged["scenarios"][0]["loss_usdt"] = 0.0
    forged["loss_usdt"] = 0.0
    original_attestation = _stress_runner_claims(
        _stress_admission_evidence()
    )
    with pytest.raises(ValueError, match="stress_evidence_sha256"):
        AdmissionGate().evaluate(
            **_admission_inputs(
                stress_evidence=forged,
                stress_runner_claims=original_attestation,
            )
        )


@pytest.mark.unit
def test_demo_slippage_requires_samples_and_uses_maximum():
    no_samples = AdmissionGate().evaluate(
        **_admission_inputs(
            demo_slippage_observations=[],
            demo_slippage_sample_count=0,
        )
    )
    assert not no_samples["checks"]["demo_slippage_bound_to_cost_model"]

    outlier = AdmissionGate().evaluate(
        **_admission_inputs(
            demo_slippage_observations=[0.05],
            demo_slippage_sample_count=100,
        )
    )
    assert not outlier["checks"]["demo_slippage_bound_to_cost_model"]


@pytest.mark.unit
def test_demo_clean_streak_is_bound_to_release_identity(tmp_path):
    now = datetime(2026, 1, 1, 23, tzinfo=UTC)
    ledger = DemoObservationLedger(
        tmp_path / "demo.json",
        clock=lambda: now,
    )
    ledger.append(
        day=now.date(),
        unexplained_mismatches=0,
        protection_p99_seconds=2,
        observed_slippage_ratio=0.001,
        git_commit="a" * 40,
        config_hash="b" * 64,
        account_id="demo-fixture",
        source_uri="s3://fixture/day.json",
        observation_started_at=now - timedelta(hours=22),
        observation_ended_at=now,
    )
    assert ledger.consecutive_clean_days(
        max_slippage_ratio=0.01,
        expected_git_commit="d" * 40,
        expected_config_hash="b" * 64,
        expected_account_id="demo-fixture",
        as_of=now.date(),
    ) == 0


@pytest.mark.unit
@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"required_demo_days": 0}, "正整数"),
        ({"maximum_stress_loss_usdt": float("inf")}, "有限数"),
        ({"minimum_oos_sharpe": -1}, "不能为负"),
        ({"minimum_positive_fold_ratio": 1.1}, "\\[0, 1\\]"),
    ],
)
def test_admission_gate_rejects_unsafe_thresholds(kwargs, message):
    with pytest.raises(ValueError, match=message):
        AdmissionGate(**kwargs)


@pytest.mark.unit
def test_admission_gate_fails_closed_when_evidence_keys_are_omitted():
    with pytest.raises(ValueError, match="证据键不完整"):
        AdmissionGate().evaluate(
            walk_forward_metrics={
                "folds": 4,
                "positive_folds": 4,
                "oos_sharpe_ratio": 1,
            },
            portfolio_metrics={
                "total_return_pct": 10,
                "covers_full_cycle": True,
                "shared_cash": True,
            },
            robustness={"plateau": True},
            stress_evidence={},
            clean_demo_days=30,
            demo_slippage_observations=[],
            engineering_checks={},
            operational_checks={},
            evidence_metadata=_metadata(),
            research_policy_claims={},
            stress_runner_claims={},
        )


@pytest.mark.unit
def test_admission_gate_rejects_string_booleans():
    gate = AdmissionGate()
    inputs = _admission_inputs()
    portfolio = _portfolio_admission_metrics(covers_full_cycle="false")
    with pytest.raises(ValueError, match="JSON 原生布尔值"):
        gate.evaluate(
            **{
                **inputs,
                "portfolio_metrics": portfolio,
            },
        )


@pytest.mark.unit
def test_admission_rejects_stress_identity_mismatched_from_portfolio():
    gate = AdmissionGate()
    identity = {
        name: dict(values)
        for name, values in _RESEARCH_IDENTITY.items()
    }
    identity["stress"]["dataset_hash"] = "9" * 64
    identity["stress"]["strategy_hash"] = "8" * 64
    metadata = _metadata()
    metadata["research_manifest_hash"] = canonical_manifest_hash(identity)
    stress_evidence = _stress_admission_evidence(
        **identity["stress"],
    )
    result = gate.evaluate(
        walk_forward_metrics={
            "folds": 4,
            "positive_folds": 4,
            "oos_sharpe_ratio": 1,
            "oos_return_pct": 10,
            "oos_observations": 100,
            "oos_duration_days": 99,
            "oos_total_trades": 4,
            "oos_max_drawdown_pct": -5,
            "strategy_family_manifest": _FAMILY_MANIFEST,
            "strategy_family_hash": _FAMILY_HASH,
            **identity["walk_forward"],
        },
        portfolio_metrics=_portfolio_admission_metrics(
            **identity["portfolio"],
        ),
        robustness=_robustness_admission_metrics(
            **identity["robustness"],
        ),
        stress_evidence=stress_evidence,
        clean_demo_days=30,
        demo_slippage_observations=[0.001] * 30,
        engineering_checks={
            name: True for name in gate.required_engineering_checks
        },
        operational_checks={
            name: True for name in gate.required_operational_checks
        },
        evidence_metadata=metadata,
        research_policy_claims=_research_policy_claims(),
        stress_runner_claims=_stress_runner_claims(stress_evidence),
    )
    assert not result["admitted"]
    assert not result["checks"]["stress_matches_portfolio"]


@pytest.mark.unit
def test_demo_ledger_rejects_historical_backfill(tmp_path):
    ledger = DemoObservationLedger(tmp_path / "demo.json")
    with pytest.raises(ValueError, match="禁止历史回填"):
        ledger.append(
            day=date(2020, 1, 1),
            unexplained_mismatches=0,
            protection_p99_seconds=1,
            observed_slippage_ratio=0.001,
            git_commit="a" * 40,
            config_hash="b" * 64,
            account_id="demo",
            source_uri="s3://fixture/day.json",
            observation_started_at=datetime(2020, 1, 1, tzinfo=UTC),
            observation_ended_at=datetime(2020, 1, 1, 23, tzinfo=UTC),
        )


@pytest.mark.unit
def test_demo_ledger_requires_immutable_s3_source(tmp_path):
    now = datetime.now(UTC)
    ledger = DemoObservationLedger(tmp_path / "demo.json", clock=lambda: now)
    with pytest.raises(ValueError, match="S3"):
        ledger.append(
            day=now.date(),
            unexplained_mismatches=0,
            protection_p99_seconds=1,
            observed_slippage_ratio=0.001,
            git_commit="a" * 40,
            config_hash="b" * 64,
            account_id="demo",
            source_uri="file:///tmp/evidence.json",
            observation_started_at=now - timedelta(hours=21),
            observation_ended_at=now,
        )


@pytest.mark.unit
def test_demo_ledger_rejects_fractional_mismatch_count(tmp_path):
    now = datetime.now(UTC)
    ledger = DemoObservationLedger(
        tmp_path / "demo.json",
        clock=lambda: now,
    )
    with pytest.raises(ValueError, match="非负整数"):
        ledger.append(
            day=now.date(),
            unexplained_mismatches=0.9,
            protection_p99_seconds=1,
            observed_slippage_ratio=0.001,
            git_commit="a" * 40,
            config_hash="b" * 64,
            account_id="demo",
            source_uri="s3://fixture/day.json",
            observation_started_at=now - timedelta(hours=21),
            observation_ended_at=now,
        )


@pytest.mark.unit
def test_demo_clean_day_requires_external_signed_source_anchor(tmp_path):
    now = datetime.now(UTC)
    day = now.date()
    started = now - timedelta(hours=21)
    anchor_claims = {
        "version": 1,
        "action": "anchor-demo-day",
        "day": day.isoformat(),
        "unexplained_mismatches": 0,
        "protection_sample_count": 1,
        "protection_p99_seconds": 1,
        "slippage_sample_count": 1,
        "observed_slippage_ratio": 0.001,
        "slippage_max_ratio": 0.001,
        "git_commit": "a" * 40,
        "config_hash": "b" * 64,
        "account_id": "demo",
        "source_uri": "s3://fixture/day.json",
        "source_sha256": "c" * 64,
        "source_version_id": "s3-version-1",
        "slo_report_sha256": "6" * 64,
        "observation_started_at": started.isoformat(),
        "observation_ended_at": now.isoformat(),
        "monitor": "independent-monitor",
        "issued_at": int(now.timestamp()),
    }
    public_key, anchor = _sign_payload(tmp_path, anchor_claims)
    ledger = DemoObservationLedger(
        tmp_path / "demo.json",
        clock=lambda: now,
        anchor_public_key=public_key,
    )
    ledger.append(
        day=day,
        unexplained_mismatches=0,
        protection_p99_seconds=1,
        observed_slippage_ratio=0.001,
        git_commit="a" * 40,
        config_hash="b" * 64,
        account_id="demo",
        source_uri="s3://fixture/day.json",
        source_sha256="c" * 64,
        source_version_id="s3-version-1",
        slo_report_sha256="6" * 64,
        anchor=anchor,
        observation_started_at=started,
        observation_ended_at=now,
    )
    assert ledger.consecutive_clean_days(
        max_slippage_ratio=0.01,
        expected_git_commit="a" * 40,
        expected_config_hash="b" * 64,
        expected_account_id="demo",
        as_of=day,
        require_trusted_anchor=True,
    ) == 1

    rows = json.loads(ledger.path.read_text())
    rows[0]["source_version_id"] = "attacker-version"
    rows[0]["entry_hash"] = DemoObservationLedger._entry_hash(rows[0])
    ledger.path.write_text(json.dumps(rows))
    assert ledger.consecutive_clean_days(
        max_slippage_ratio=0.01,
        expected_git_commit="a" * 40,
        expected_config_hash="b" * 64,
        expected_account_id="demo",
        as_of=day,
        require_trusted_anchor=True,
    ) == 0


@pytest.mark.unit
def test_admission_root_signature_binds_evidence_ledger_and_budget(tmp_path):
    evidence = {"evidence_metadata": _metadata()}
    evidence_hash = hashlib.sha256(
        json.dumps(evidence, sort_keys=True).encode()
    ).hexdigest()
    request = build_admission_request(
        evidence,
        evidence_sha256=evidence_hash,
        ledger_head_hash="d" * 64,
        empty_host_restore_sha256="f" * 64,
        stage_c_coverage_sha256=_stage_c_coverage_sha256(),
        canary_readiness_sha256="c" * 64,
        approved_max_stress_loss_usdt=100,
        now=int(time.time()),
    )
    request["risk_approver"] = evidence["evidence_metadata"][
        "risk_approver"
    ]
    public_key, artifact = _sign_payload(tmp_path, request)
    verifier = AdmissionApprovalVerifier(public_key)
    verifier.verify(
        artifact,
        evidence=evidence,
        evidence_sha256=evidence_hash,
        ledger_head_hash="d" * 64,
        empty_host_restore_sha256="f" * 64,
        stage_c_coverage_sha256=_stage_c_coverage_sha256(),
        canary_readiness_sha256="c" * 64,
        approved_max_stress_loss_usdt=100,
    )
    with pytest.raises(ValueError, match="evidence_sha256"):
        verifier.verify(
            artifact,
            evidence=evidence,
            evidence_sha256="e" * 64,
            ledger_head_hash="d" * 64,
            empty_host_restore_sha256="f" * 64,
            stage_c_coverage_sha256=_stage_c_coverage_sha256(),
            canary_readiness_sha256="c" * 64,
            approved_max_stress_loss_usdt=100,
        )
    with pytest.raises(ValueError, match="empty_host_restore_sha256"):
        verifier.verify(
            artifact,
            evidence=evidence,
            evidence_sha256=evidence_hash,
            ledger_head_hash="d" * 64,
            empty_host_restore_sha256="e" * 64,
            stage_c_coverage_sha256=_stage_c_coverage_sha256(),
            canary_readiness_sha256="c" * 64,
            approved_max_stress_loss_usdt=100,
        )
    with pytest.raises(ValueError, match="stage_c_coverage_sha256"):
        verifier.verify(
            artifact,
            evidence=evidence,
            evidence_sha256=evidence_hash,
            ledger_head_hash="d" * 64,
            empty_host_restore_sha256="f" * 64,
            stage_c_coverage_sha256="e" * 64,
            canary_readiness_sha256="c" * 64,
            approved_max_stress_loss_usdt=100,
        )
    with pytest.raises(ValueError, match="canary_readiness_sha256"):
        verifier.verify(
            artifact,
            evidence=evidence,
            evidence_sha256=evidence_hash,
            ledger_head_hash="d" * 64,
            empty_host_restore_sha256="f" * 64,
            stage_c_coverage_sha256=_stage_c_coverage_sha256(),
            canary_readiness_sha256="e" * 64,
            approved_max_stress_loss_usdt=100,
        )
    public_key.chmod(0o666)
    with pytest.raises(ValueError, match="group/other"):
        verifier.verify(
            artifact,
            evidence=evidence,
            evidence_sha256=evidence_hash,
            ledger_head_hash="d" * 64,
            empty_host_restore_sha256="f" * 64,
            stage_c_coverage_sha256=_stage_c_coverage_sha256(),
            canary_readiness_sha256="c" * 64,
            approved_max_stress_loss_usdt=100,
        )


@pytest.mark.unit
def test_production_gate_rejects_release_commit_not_used_by_runtime(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "okx": {
                "simulated": True,
                "base_url": "https://www.okx.com",
            },
            "production": {
                "environment": "demo",
                "account_id": "demo-account",
            },
        }),
        encoding="utf-8",
    )
    revision = tmp_path / "REVISION"
    revision.write_text("a" * 40 + "\n", encoding="ascii")
    evidence = tmp_path / "evidence.json"
    evidence.write_text(
        json.dumps({
            "evidence_metadata": {
                "commit_sha": "b" * 40,
            },
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="实际启动"):
        _evaluate(
            ledger=DemoObservationLedger(tmp_path / "ledger.json"),
            evidence_path=evidence,
            max_slippage=0.01,
            approved_max_stress_loss=100,
            config_path=config_path,
            release_commit_file=revision,
            strategy="ma_cross",
            bar="1H",
            instruments=["BTC-USDT"],
            interval=60,
            research_public_key=tmp_path / "unused-research.pem",
        )


@pytest.mark.unit
def test_runtime_identity_binds_full_config_and_exact_live_launch(tmp_path):
    cfg = {
        "okx": {
            "simulated": True,
            "base_url": "https://www.okx.com",
        },
        "production": {
            "environment": "demo",
            "allowed_instruments": ["BTC-USDT"],
        },
        "risk": {"stop_loss_pct": 0.02},
        "strategies": {"ma_cross": {"fast_period": 5}},
        "llm": {"api_key": "secret", "max_total_tokens": 1000},
    }
    settings = ProductionSettings.from_config(
        cfg,
        require_credentials=False,
        require_external_controls=False,
    )
    baseline = _runtime_config_hash(
        settings,
        cfg,
        strategy="ma_cross",
        bar="1H",
        instruments=["BTC-USDT"],
        interval=60,
        deployed_source_sha256="a" * 64,
    )
    changed = json.loads(json.dumps(cfg))
    changed["risk"]["stop_loss_pct"] = 0.5
    assert baseline != _runtime_config_hash(
        settings,
        changed,
        strategy="ma_cross",
        bar="1H",
        instruments=["BTC-USDT"],
        interval=60,
        deployed_source_sha256="a" * 64,
    )
    token_budget_changed = json.loads(json.dumps(cfg))
    token_budget_changed["llm"]["max_total_tokens"] = 0
    assert baseline != _runtime_config_hash(
        settings,
        token_budget_changed,
        strategy="ma_cross",
        bar="1H",
        instruments=["BTC-USDT"],
        interval=60,
        deployed_source_sha256="a" * 64,
    )
    multi_settings = ProductionSettings.from_config(
        {
            **cfg,
            "production": {
                **cfg["production"],
                "allowed_instruments": ["BTC-USDT", "ETH-USDT"],
            },
        },
        require_credentials=False,
        require_external_controls=False,
    )
    first_order = _runtime_config_hash(
        multi_settings,
        cfg,
        strategy="ma_cross",
        bar="1H",
        instruments=["BTC-USDT", "ETH-USDT"],
        interval=60,
        deployed_source_sha256="a" * 64,
    )
    assert first_order != _runtime_config_hash(
        multi_settings,
        cfg,
        strategy="ma_cross",
        bar="1H",
        instruments=["ETH-USDT", "BTC-USDT"],
        interval=60,
        deployed_source_sha256="a" * 64,
    )
    manifest_path = tmp_path / "launch.json"
    manifest_path.write_text(json.dumps({
        "version": 1,
        "strategy": "ma_cross",
        "bar": "1H",
        "instruments": ["BTC-USDT"],
        "interval_seconds": 60,
    }), encoding="utf-8")
    manifest_path.chmod(0o600)
    launch = _load_launch_manifest(manifest_path)
    argv = _live_argv(Path("/venv/bin/okx-quant"), tmp_path / "cfg.yaml", launch)
    assert argv[argv.index("--strategy") + 1] == launch["strategy"]
    assert argv[argv.index("--bar") + 1] == launch["bar"]
    assert argv[argv.index("--inst") + 1] == ",".join(launch["instruments"])
    assert argv[argv.index("--interval") + 1] == "60"
    manifest_path.chmod(0o666)
    with pytest.raises(ValueError, match="group/other"):
        _load_launch_manifest(manifest_path)


@pytest.mark.unit
def test_production_launch_execs_only_the_manifest_values(
    tmp_path, monkeypatch
):
    manifest = tmp_path / "launch.json"
    manifest.write_text(json.dumps({
        "version": 1,
        "strategy": "ma_cross",
        "bar": "4H",
        "instruments": ["BTC-USDT", "ETH-USDT"],
        "interval_seconds": 90,
    }), encoding="utf-8")
    manifest.chmod(0o600)
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text("{}", encoding="utf-8")
    observed = {}

    monkeypatch.setattr(
        launch_module,
        "_actual_runtime_identity",
        lambda **_kwargs: {"config_hash": "a" * 64},
    )

    monkeypatch.setattr(
        launch_module,
        "validate_deployment_receipt",
        lambda *_args, **kwargs: observed.update({
            "receipt_identity": kwargs["identity"],
        }),
    )
    monkeypatch.setattr(
        launch_module.os,
        "execv",
        lambda executable, argv: observed.update({
            "executable": executable,
            "argv": argv,
        }),
    )
    monkeypatch.setattr(sys, "argv", [
        "production_launch.py",
        "--config", str(tmp_path / "config.yaml"),
        "--release-commit-file", str(tmp_path / "REVISION"),
        "--launch-manifest", str(manifest),
        "--receipt", str(tmp_path / "receipt.json"),
        "--evidence", str(evidence),
        "--approval", str(approval),
        "--approval-public-key", str(tmp_path / "approval.pem"),
    ])
    assert launch_module.main() == 127
    argv = observed["argv"]
    assert argv[argv.index("--strategy") + 1] == "ma_cross"
    assert argv[argv.index("--bar") + 1] == "4H"
    assert argv[argv.index("--inst") + 1] == "BTC-USDT,ETH-USDT"
    assert argv[argv.index("--interval") + 1] == "90"
    assert observed["receipt_identity"] == {"config_hash": "a" * 64}


@pytest.mark.unit
def test_production_launch_falls_back_to_safety_only_on_bad_receipt(
    tmp_path, monkeypatch
):
    manifest = tmp_path / "launch.json"
    manifest.write_text(json.dumps({
        "version": 1,
        "strategy": "ma_cross",
        "bar": "1H",
        "instruments": ["BTC-USDT"],
        "interval_seconds": 60,
    }), encoding="utf-8")
    manifest.chmod(0o600)
    observed = {}
    monkeypatch.setattr(
        launch_module,
        "_actual_runtime_identity",
        lambda **_kwargs: {"config_hash": "a" * 64},
    )

    def reject_receipt(*_args, **_kwargs):
        raise ValueError("expired material missing")

    monkeypatch.setattr(
        launch_module,
        "validate_deployment_receipt",
        reject_receipt,
    )
    monkeypatch.setattr(
        launch_module.os,
        "execv",
        lambda _executable, argv: observed.update({"argv": argv}),
    )
    monkeypatch.setattr(sys, "argv", [
        "production_launch.py",
        "--config", str(tmp_path / "config.yaml"),
        "--release-commit-file", str(tmp_path / "REVISION"),
        "--launch-manifest", str(manifest),
        "--receipt", str(tmp_path / "receipt.json"),
        "--evidence", str(tmp_path / "evidence.json"),
        "--approval", str(tmp_path / "approval.json"),
        "--approval-public-key", str(tmp_path / "approval.pem"),
    ])
    assert launch_module.main() == 127
    assert "--safety-only" in observed["argv"]
    assert observed["argv"][0] == sys.executable
    assert observed["argv"][1] == str(
        Path(launch_module.__file__).resolve().parents[1] / "main.py"
    )
    assert Path(observed["argv"][0]).name != "okx-quant"


@pytest.mark.unit
def test_deployed_hash_binds_exact_python_interpreter_bytes(tmp_path, monkeypatch):
    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o755)
    monkeypatch.setattr(
        gate_module,
        "_runtime_python_executable",
        lambda: (interpreter, interpreter, b"<regular-file>"),
    )
    first = gate_module._deployed_source_hash()
    interpreter.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    second = gate_module._deployed_source_hash()
    assert first != second


@pytest.mark.unit
def test_deployed_hash_rejects_group_writable_python(tmp_path, monkeypatch):
    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o775)
    monkeypatch.setattr(gate_module.sys, "executable", str(interpreter))
    with pytest.raises(ValueError, match="executable/target"):
        gate_module._deployed_source_hash()


@pytest.mark.unit
def test_runtime_python_rejects_world_writable_directory_chain(
    tmp_path, monkeypatch
):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o777)
    interpreter = unsafe / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o755)
    monkeypatch.setattr(gate_module.sys, "executable", str(interpreter))
    with pytest.raises(ValueError, match="目录链不安全"):
        gate_module._runtime_python_executable()


@pytest.mark.unit
def test_deployment_receipt_allows_same_identity_restart_after_window(
    tmp_path,
):
    evidence = {"evidence_metadata": _metadata()}
    evidence_bytes = json.dumps(evidence, sort_keys=True).encode()
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_bytes(evidence_bytes)
    evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
    request = build_admission_request(
        evidence,
        evidence_sha256=evidence_sha256,
        ledger_head_hash="d" * 64,
        empty_host_restore_sha256="f" * 64,
        stage_c_coverage_sha256=_stage_c_coverage_sha256(),
        canary_readiness_sha256="c" * 64,
        approved_max_stress_loss_usdt=100,
        lifetime_s=600,
        now=1000,
    )
    request["risk_approver"] = evidence["evidence_metadata"][
        "risk_approver"
    ]
    public_key, artifact = _sign_payload(tmp_path, request)
    approval_bytes = json.dumps(artifact, sort_keys=True).encode()
    approval_path = tmp_path / "approval.json"
    approval_path.write_bytes(approval_bytes)
    identity = {
        "commit_sha": request["commit_sha"],
        "config_hash": request["config_hash"],
        "account_id": request["account_id"],
        "environment": request["environment"],
        "deployed_source_sha256": "f" * 64,
    }
    receipt = build_deployment_receipt(
        identity=identity,
        approval_claims=request,
        approval_bytes=approval_bytes,
        evidence_sha256=evidence_sha256,
        ledger_head_hash="d" * 64,
        empty_host_restore_sha256="f" * 64,
        stage_c_coverage=_stage_c_coverage(),
        canary_readiness_sha256="c" * 64,
        activated_at=1200,
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    receipt_path.chmod(0o600)
    # No wall-clock check occurs here: the signed in-window activation is
    # durable, but every immutable identity and artifact hash is rechecked.
    assert validate_deployment_receipt(
        receipt_path,
        identity=identity,
        approval_path=approval_path,
        approval_public_key=public_key,
        evidence_path=evidence_path,
    )["activated_at"] == 1200
    changed = dict(identity, deployed_source_sha256="0" * 64)
    with pytest.raises(ValueError, match="deployed_source_sha256"):
        validate_deployment_receipt(
            receipt_path,
            identity=changed,
            approval_path=approval_path,
            approval_public_key=public_key,
            evidence_path=evidence_path,
        )


@pytest.mark.unit
def test_formal_gate_validates_latest_exact_30_days_after_longer_streak(
    monkeypatch,
):
    observed = []
    ledger = object()
    monkeypatch.setattr(
        gate_module,
        "validate_30_day_aggregate",
        lambda actual, *, clean_days: observed.append(
            (actual, clean_days)
        ),
    )
    _validate_clean_streak_aggregate(ledger, 29)
    assert observed == []
    _validate_clean_streak_aggregate(ledger, 30)
    _validate_clean_streak_aggregate(ledger, 31)
    assert observed == [(ledger, 30), (ledger, 30)]


@pytest.mark.unit
def test_deployment_receipt_rejects_legacy_unbound_ledger_policy(tmp_path):
    evidence = {"evidence_metadata": _metadata()}
    evidence_bytes = json.dumps(evidence, sort_keys=True).encode()
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_bytes(evidence_bytes)
    evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
    request = build_admission_request(
        evidence,
        evidence_sha256=evidence_sha256,
        ledger_head_hash="d" * 64,
        empty_host_restore_sha256="f" * 64,
        stage_c_coverage_sha256=_stage_c_coverage_sha256(),
        canary_readiness_sha256="c" * 64,
        approved_max_stress_loss_usdt=100,
        lifetime_s=600,
        now=1000,
    )
    request["risk_approver"] = evidence["evidence_metadata"][
        "risk_approver"
    ]
    public_key, artifact = _sign_payload(tmp_path, request)
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps(artifact), encoding="utf-8")
    identity = {
        "commit_sha": request["commit_sha"],
        "config_hash": request["config_hash"],
        "account_id": request["account_id"],
        "environment": request["environment"],
        "deployed_source_sha256": "f" * 64,
    }
    receipt = build_deployment_receipt(
        identity=identity,
        approval_claims=request,
        approval_bytes=approval_path.read_bytes(),
        evidence_sha256=evidence_sha256,
        ledger_head_hash="d" * 64,
        empty_host_restore_sha256="f" * 64,
        stage_c_coverage=_stage_c_coverage(),
        canary_readiness_sha256="c" * 64,
        activated_at=1200,
    )
    for version in (1, 2):
        legacy_version = dict(receipt, version=version)
        legacy_version_path = tmp_path / f"legacy-version-{version}.json"
        legacy_version_path.write_text(
            json.dumps(legacy_version),
            encoding="utf-8",
        )
        legacy_version_path.chmod(0o600)
        with pytest.raises(ValueError, match="版本、ledger"):
            validate_deployment_receipt(
                legacy_version_path,
                identity=identity,
                approval_path=approval_path,
                approval_public_key=public_key,
                evidence_path=evidence_path,
            )
    for field in (
        "demo_ledger_version",
        "slo_schema",
        "slo_policy_hash",
    ):
        legacy = dict(receipt)
        legacy.pop(field)
        path = tmp_path / f"legacy-{field}.json"
        path.write_text(json.dumps(legacy), encoding="utf-8")
        path.chmod(0o600)
        with pytest.raises(ValueError, match="字段不完整"):
            validate_deployment_receipt(
                path,
                identity=identity,
                approval_path=approval_path,
                approval_public_key=public_key,
                evidence_path=evidence_path,
            )


@pytest.mark.unit
def test_admission_rejects_unsafe_budget_or_self_approval():
    with pytest.raises(ValueError, match="硬上限"):
        AdmissionGate(maximum_stress_loss_usdt=501)

    metadata = _metadata()
    metadata["risk_approver"] = metadata["operator"]
    with pytest.raises(ValueError, match="不同"):
        AdmissionGate._validate_metadata(metadata)

    metadata = _metadata()
    metadata["approved_max_slippage_ratio"] = 0.051
    with pytest.raises(ValueError, match="0.05"):
        AdmissionGate._validate_metadata(metadata)

    metadata = _metadata()
    metadata["commit_sha"] = "0" * 40
    with pytest.raises(ValueError, match="全零"):
        AdmissionGate._validate_metadata(metadata)
