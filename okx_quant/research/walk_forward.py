"""滚动样本外 walk-forward 评估。"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

import pandas as pd

from okx_quant.backtest.engine import BacktestEngine, BacktestResult
from okx_quant.backtest.validation import validate_ohlcv
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
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType


@dataclass(frozen=True)
class WalkForwardFold:
    train_start: object
    train_end: object
    test_start: object
    test_end: object
    params: dict
    result: BacktestResult


@dataclass(frozen=True)
class WalkForwardResult:
    folds: list[WalkForwardFold]
    oos_equity_curve: pd.Series
    metrics: dict


class _ScheduledStrategy(BaseStrategy):
    """按 OOS fold 切换参数，但让引擎现金/持仓跨边界连续。"""

    name = "walk_forward_schedule"

    def __init__(self, schedule: list[dict]):
        super().__init__()
        self.schedule = schedule

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        now = pd.Timestamp(df["ts"].iloc[-1])
        # 边界时使用刚完成训练的新 fold；倒序保证相同边界的新参数优先。
        for item in reversed(self.schedule):
            if item["active_from"] <= now < item["active_until"]:
                history = df[df["ts"] >= item["train_start"]].copy()
                return item["strategy"].generate_signal(history, inst_id)
        return Signal(SignalType.HOLD, inst_id, float(df["close"].iloc[-1]))


class WalkForwardRunner:
    def __init__(
        self,
        *,
        train_bars: int,
        test_bars: int,
        step_bars: int | None = None,
        initial_capital: float = 10_000,
        fee_rate: float = 0.001,
        slippage: float = 0.0005,
        cost_model=None,
    ):
        if (
            type(train_bars) is not int
            or type(test_bars) is not int
            or train_bars < 2
            or test_bars < 2
        ):
            raise ValueError("train_bars/test_bars 至少为 2")
        if step_bars is not None and type(step_bars) is not int:
            raise ValueError("step_bars 必须是整数或 None")
        if step_bars is not None and step_bars != test_bars:
            raise ValueError(
                "生产 walk-forward 要求 step_bars == test_bars，"
                "确保样本外区间连续且不重叠"
            )
        if (
            isinstance(initial_capital, bool)
            or not isinstance(initial_capital, (int, float))
            or not math.isfinite(float(initial_capital))
            or float(initial_capital) <= 0
        ):
            raise ValueError("initial_capital 必须是正有限数")
        self.train_bars = train_bars
        self.test_bars = test_bars
        self.step_bars = step_bars or test_bars
        self.initial_capital = initial_capital
        self.fee_rate = fee_rate
        self.slippage = slippage
        self.cost_model = cost_model
        self.cost_model_hash = cost_model_manifest_hash(
            cost_model,
            fee_rate=fee_rate,
            slippage=slippage,
        )

    def run(
        self,
        data: pd.DataFrame,
        inst_id: str,
        optimize: Callable[[pd.DataFrame], dict],
        strategy_factory: Callable[[dict], BaseStrategy],
    ) -> WalkForwardResult:
        if "ts" not in data.columns:
            raise ValueError("walk-forward 数据缺少 ts")
        data = data.copy()
        data["ts"] = pd.to_datetime(data["ts"], utc=True, errors="raise")
        data = (
            data.sort_values("ts")
            .drop_duplicates("ts", keep="last")
            .reset_index(drop=True)
        )
        validate_ohlcv(data, context="walk-forward")
        dataset_hash = dataframe_manifest_hash(data)
        if not data["ts"].is_monotonic_increasing:
            raise ValueError("walk-forward 时间轴必须严格升序")
        fold_specs: list[dict] = []
        start = 0
        while start + self.train_bars + self.test_bars <= len(data):
            train = data.iloc[start : start + self.train_bars].copy()
            test_start = start + self.train_bars
            test = data.iloc[test_start : test_start + self.test_bars].copy()
            if train["ts"].iloc[-1] >= test["ts"].iloc[0]:
                raise ValueError("walk-forward 训练区间必须严格早于样本外区间")
            fold_specs.append({
                "train_start_index": start,
                "train_start": train["ts"].iloc[0],
                "train_end": train["ts"].iloc[-1],
                "test_start_index": test_start,
                "test_start": test["ts"].iloc[0],
                "test_end_index": test_start + self.test_bars - 1,
                "test_end": test["ts"].iloc[-1],
                "params": dict(optimize(train)),
            })
            start += self.step_bars
        if not fold_specs:
            raise ValueError("数据不足以形成一个 walk-forward fold")

        schedule = [
            {
                "train_start": spec["train_start"],
                # 在 test 第一根开盘成交，信号必须由 train 最后一根收盘产生。
                "active_from": spec["train_end"],
                "active_until": spec["test_end"],
                "strategy": strategy_factory(spec["params"]),
            }
            for spec in fold_specs
        ]
        evaluation_manifest = {
            "fold_strategies": [
                {
                    "params": spec["params"],
                    "strategy": strategy_type_name(item["strategy"]),
                }
                for spec, item in zip(fold_specs, schedule, strict=True)
            ],
            "walk_forward": {
                "train_bars": self.train_bars,
                "test_bars": self.test_bars,
                "step_bars": self.step_bars,
                "initial_capital": self.initial_capital,
                "continuous_oos": True,
            },
        }
        evaluation_manifest_hash = canonical_manifest_hash(
            evaluation_manifest
        )
        strategy_family_manifest = build_strategy_family_manifest(
            item["strategy"] for item in schedule
        )
        family_hash = strategy_family_hash(strategy_family_manifest)
        final_index = int(fold_specs[-1]["test_end_index"])
        continuous_data = data.iloc[: final_index + 1].copy()
        engine = BacktestEngine(
            initial_capital=self.initial_capital,
            fee_rate=self.fee_rate,
            slippage=self.slippage,
            cost_model=self.cost_model,
        )
        continuous = engine.run(
            continuous_data,
            _ScheduledStrategy(schedule),
            inst_id,
            warmup=self.train_bars - 1,
        )
        first_oos = fold_specs[0]["test_start"]
        last_oos = fold_specs[-1]["test_end"]
        equity = continuous.equity_curve.loc[first_oos:last_oos].copy()
        first_oos_index = int(fold_specs[0]["test_start_index"])
        analysis_equity = continuous.equity_curve.iloc[
            first_oos_index - 1:final_index + 1
        ].copy()

        folds: list[WalkForwardFold] = []
        for spec in fold_specs:
            fold_curve = continuous.equity_curve.loc[
                spec["test_start"]:spec["test_end"]
            ].copy()
            starting_equity = float(
                continuous.equity_curve.iloc[
                    int(spec["test_start_index"]) - 1
                ]
            )
            ending_equity = float(fold_curve.iloc[-1])
            closed_trades = [
                trade
                for trade in continuous.trades
                if (
                    trade.close_ts is not None
                    and spec["test_start"]
                    <= pd.Timestamp(trade.close_ts)
                    <= spec["test_end"]
                )
            ]
            fold_result = BacktestResult(
                trades=closed_trades,
                equity_curve=fold_curve,
                metrics={
                    "total_trades": len(closed_trades),
                    "initial_capital": starting_equity,
                    "final_capital": ending_equity,
                    "total_return_pct": (
                        (ending_equity / starting_equity - 1) * 100
                        if starting_equity > 0
                        else 0
                    ),
                },
            )
            folds.append(WalkForwardFold(
                train_start=spec["train_start"],
                train_end=spec["train_end"],
                test_start=spec["test_start"],
                test_end=spec["test_end"],
                params=spec["params"],
                result=fold_result,
            ))

        # 风险统计包含 OOS 开始前一刻的资金锚点；否则首根 OOS 的亏损
        # 会从 pct_change/cummax 中消失，系统性虚高 Sharpe、压低回撤。
        daily = analysis_equity.resample("1D").last().pct_change().dropna()
        peak = analysis_equity.cummax()
        drawdown = (analysis_equity - peak) / peak
        downside = daily[daily < 0]
        duration_days = max(
            (analysis_equity.index[-1] - analysis_equity.index[0]).days,
            1,
        )
        starting_equity = float(analysis_equity.iloc[0])
        total_return = equity.iloc[-1] / starting_equity - 1
        annual_return = (1 + total_return) ** (365 / duration_days) - 1
        max_drawdown = abs(float(drawdown.min()))
        longest_drawdown = 0
        current_drawdown = 0
        for underwater in drawdown < 0:
            current_drawdown = current_drawdown + 1 if underwater else 0
            longest_drawdown = max(longest_drawdown, current_drawdown)
        metrics = {
            "folds": len(folds),
            "positive_folds": sum(
                fold.result.metrics.get("total_return_pct", 0) > 0
                for fold in folds
            ),
            "oos_return_pct": float(
                total_return * 100
            ),
            "oos_observations": len(equity),
            "oos_duration_days": duration_days,
            "oos_total_trades": len(continuous.trades),
            "oos_sharpe_ratio": float(
                daily.mean() / daily.std() * (365 ** 0.5)
                if daily.std() > 0
                else 0
            ),
            "oos_max_drawdown_pct": float(
                drawdown.min() * 100
            ),
            "oos_sortino_ratio": float(
                daily.mean() / downside.std() * (365 ** 0.5)
                if downside.std() > 0
                else 0
            ),
            "oos_calmar_ratio": float(
                annual_return / max_drawdown if max_drawdown > 0 else 0
            ),
            "oos_max_drawdown_observations": longest_drawdown,
            "cash_benchmark_return_pct": 0.0,
            "cost_model_hash": self.cost_model_hash,
            "dataset_hash": dataset_hash,
            "strategy_hash": family_hash,
            "strategy_family_manifest": strategy_family_manifest,
            "strategy_family_hash": family_hash,
            "evaluation_manifest_hash": evaluation_manifest_hash,
        }
        return WalkForwardResult(folds, equity, metrics)
