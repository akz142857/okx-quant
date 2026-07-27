"""多交易对资本分配组合回测。"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

import pandas as pd

from okx_quant.backtest.engine import BacktestResult, Trade
from okx_quant.backtest.validation import validate_ohlcv
from okx_quant.research.costs import (
    canonical_manifest_hash,
    cost_model_manifest_hash,
    dataframe_manifest_hash,
)
from okx_quant.research.cycle import compute_calendar_cycle_metrics
from okx_quant.strategy.base import BaseStrategy


@dataclass(frozen=True)
class PortfolioResult:
    component_results: dict[str, BacktestResult]
    equity_curve: pd.Series
    metrics: dict


class PortfolioBacktester:
    """统一时间轴、共享现金与组合仓位上限的现货事件回测。"""

    def __init__(
        self,
        initial_capital: float = 10_000,
        fee_rate: float = 0.001,
        slippage: float = 0.0005,
        cost_model=None,
        max_open_positions: int | None = None,
        minimum_cycle_days: int = 365,
        cycle_regime_threshold: float = 0.20,
        minimum_cycle_coverage: float = 0.90,
        maximum_cycle_gap_days: int = 7,
    ):
        if (
            isinstance(initial_capital, bool)
            or not isinstance(initial_capital, (int, float))
            or not math.isfinite(float(initial_capital))
            or float(initial_capital) <= 0
        ):
            raise ValueError("initial_capital 必须是正有限数")
        if (
            max_open_positions is not None
            and (
                type(max_open_positions) is not int
                or max_open_positions < 1
            )
        ):
            raise ValueError("max_open_positions 必须是正整数或 None")
        self.initial_capital = initial_capital
        self.fee_rate = fee_rate
        self.slippage = slippage
        self.cost_model = cost_model
        self.max_open_positions = max_open_positions
        if type(minimum_cycle_days) is not int or minimum_cycle_days < 365:
            raise ValueError("minimum_cycle_days 必须是至少 365 的整数")
        if (
            isinstance(cycle_regime_threshold, bool)
            or not isinstance(cycle_regime_threshold, (int, float))
            or not math.isfinite(float(cycle_regime_threshold))
            or not 0 < cycle_regime_threshold < 1
        ):
            raise ValueError("cycle_regime_threshold 必须在 (0, 1) 区间")
        if (
            isinstance(minimum_cycle_coverage, bool)
            or not isinstance(minimum_cycle_coverage, (int, float))
            or not math.isfinite(float(minimum_cycle_coverage))
            or not 0.8 <= minimum_cycle_coverage <= 1
        ):
            raise ValueError("minimum_cycle_coverage 必须在 [0.8, 1] 区间")
        if (
            type(maximum_cycle_gap_days) is not int
            or not 1 <= maximum_cycle_gap_days <= 7
        ):
            raise ValueError("maximum_cycle_gap_days 必须是 1..7 的整数")
        self.minimum_cycle_days = minimum_cycle_days
        self.cycle_regime_threshold = cycle_regime_threshold
        self.minimum_cycle_coverage = minimum_cycle_coverage
        self.maximum_cycle_gap_days = maximum_cycle_gap_days
        self.cost_model_hash = cost_model_manifest_hash(
            cost_model,
            fee_rate=fee_rate,
            slippage=slippage,
        )

    def run(
        self,
        datasets: dict[str, pd.DataFrame],
        strategy_factory: Callable[[str], BaseStrategy],
        weights: dict[str, float] | None = None,
    ) -> PortfolioResult:
        if not datasets:
            raise ValueError("组合回测至少需要一个交易对")
        weights = weights or {
            inst_id: 1 / len(datasets) for inst_id in datasets
        }
        unknown = set(weights) - set(datasets)
        if unknown:
            raise ValueError(f"权重包含未知交易对: {sorted(unknown)}")
        for inst_id in datasets:
            weight = weights.get(inst_id, 0)
            if (
                isinstance(weight, bool)
                or not isinstance(weight, (int, float))
                or not math.isfinite(float(weight))
                or float(weight) < 0
            ):
                raise ValueError(
                    f"{inst_id} 权重必须是非负有限数"
                )
        total_weight = sum(weights.get(inst_id, 0) for inst_id in datasets)
        if not math.isfinite(float(total_weight)) or total_weight <= 0:
            raise ValueError("组合权重之和必须大于 0")
        normalized_weights = {
            inst_id: float(weights.get(inst_id, 0) / total_weight)
            for inst_id in sorted(datasets)
        }
        normalized: dict[str, pd.DataFrame] = {}
        positions: dict[str, Trade] = {}
        pending: dict[str, object] = {}
        strategies: dict[str, BaseStrategy] = {}
        trades: dict[str, list[Trade]] = {}
        last_close: dict[str, float] = {}
        component_records: dict[str, list[tuple[pd.Timestamp, float]]] = {}
        timeline: set[pd.Timestamp] = set()
        for inst_id, source in datasets.items():
            required = {"ts", "open", "high", "low", "close"}
            if not required.issubset(source.columns):
                raise ValueError(f"{inst_id} K 线缺少列: {sorted(required - set(source.columns))}")
            if source.empty:
                raise ValueError(f"{inst_id} K 线不能为空")
            data = source.copy()
            data["ts"] = pd.to_datetime(data["ts"], utc=True)
            data = data.sort_values("ts").drop_duplicates("ts", keep="last")
            validate_ohlcv(data, context=f"{inst_id} 组合回测")
            data.index = data["ts"]
            normalized[inst_id] = data
            strategies[inst_id] = strategy_factory(inst_id)
            trades[inst_id] = []
            component_records[inst_id] = []
            timeline.update(data.index)
        max_positions = self.max_open_positions or len(normalized)
        if max_positions < 1:
            raise ValueError("max_open_positions 必须至少为 1")
        dataset_hash = canonical_manifest_hash({
            inst_id: dataframe_manifest_hash(data.reset_index(drop=True))
            for inst_id, data in sorted(normalized.items())
        })
        evaluation_manifest = {
            "strategies": {
                inst_id: {
                    "strategy": (
                        f"{type(strategy).__module__}."
                        f"{type(strategy).__qualname__}"
                    ),
                    "params": strategy.params,
                }
                for inst_id, strategy in sorted(strategies.items())
            },
            "portfolio": {
                "weights": normalized_weights,
                "max_open_positions": max_positions,
                "initial_capital": self.initial_capital,
                "full_cycle_definition": {
                    "minimum_cycle_days": self.minimum_cycle_days,
                    "cycle_regime_threshold": self.cycle_regime_threshold,
                    "minimum_cycle_coverage": self.minimum_cycle_coverage,
                    "maximum_cycle_gap_days": self.maximum_cycle_gap_days,
                    "regime_window_days": 90,
                },
            },
        }
        evaluation_manifest_hash = canonical_manifest_hash(
            evaluation_manifest
        )

        cash = self.initial_capital
        equity_records: list[tuple[pd.Timestamp, float]] = []
        turnover = 0.0
        total_fees = 0.0

        def apply_intrabar_protection(
            candidates: set[str],
            rows: dict[str, pd.Series],
            timestamp: pd.Timestamp,
            *,
            open_only: bool = False,
        ) -> None:
            nonlocal cash, turnover, total_fees
            for inst_id in sorted(candidates & set(rows)):
                position = positions.get(inst_id)
                if position is None:
                    continue
                row = rows[inst_id]
                reason = ""
                trigger = 0.0
                open_px = float(row["open"])
                if (
                    position.stop_loss > 0
                    and (
                        open_px <= position.stop_loss
                        if open_only
                        else float(row["low"]) <= position.stop_loss
                    )
                ):
                    reason = "stop_loss"
                    trigger = min(position.stop_loss, open_px)
                elif (
                    position.take_profit > 0
                    and (
                        open_px >= position.take_profit
                        if open_only
                        else float(row["high"]) >= position.take_profit
                    )
                ):
                    reason = "take_profit"
                    trigger = (
                        open_px if open_only else position.take_profit
                    )
                if not reason:
                    continue
                fee_rate, slip = self._costs(
                    "sell", row, position.size * trigger
                )
                exit_price = trigger * (1 - slip)
                proceeds = position.size * exit_price
                exit_fee = proceeds * fee_rate
                cash += proceeds - exit_fee
                turnover += proceeds
                total_fees += exit_fee
                self._close_trade(
                    position, timestamp, exit_price, exit_fee, reason
                )
                trades[inst_id].append(position)
                positions.pop(inst_id)

        for timestamp in sorted(timeline):
            rows = {
                inst_id: data.loc[timestamp]
                for inst_id, data in normalized.items()
                if timestamp in data.index
            }
            for inst_id, row in rows.items():
                last_close[inst_id] = float(row["close"])

            # 同一时间戳分阶段执行：先统一释放退出，再竞争入场，避免
            # symbol 字典序决定“先买失败还是先卖释放仓位”。
            actions = {
                inst_id: pending.pop(inst_id)
                for inst_id in sorted(rows)
                if inst_id in pending
            }
            for inst_id in sorted(actions):
                action = actions[inst_id]
                position = positions.get(inst_id)
                if action and action["side"] == "sell" and position is not None:
                    row = rows[inst_id]
                    fee_rate, slip = self._costs("sell", row, position.size * float(row["open"]))
                    exit_price = float(row["open"]) * (1 - slip)
                    proceeds = position.size * exit_price
                    exit_fee = proceeds * fee_rate
                    cash += proceeds - exit_fee
                    turnover += proceeds
                    total_fees += exit_fee
                    self._close_trade(
                        position, timestamp, exit_price, exit_fee, action["reason"]
                    )
                    trades[inst_id].append(position)
                    positions.pop(inst_id)

            # BUY 在开盘成交前，只能知道开盘已经穿越保护价的 gap；不能
            # 偷看当根稍后才发生的 high/low 来提前释放仓位槽。
            positions_at_open = set(positions)
            apply_intrabar_protection(
                positions_at_open,
                rows,
                timestamp,
                open_only=True,
            )

            buy_candidates = [
                (inst_id, action)
                for inst_id, action in actions.items()
                if action["side"] == "buy"
            ]
            # priority 由信号 extra 显式给出；相同 priority 才以 inst_id
            # 作为可审计、确定性的 tie-breaker。
            buy_candidates.sort(
                key=lambda item: (-float(item[1]["priority"]), item[0])
            )
            for inst_id, action in buy_candidates:
                position = positions.get(inst_id)
                if (
                    position is None
                    and len(positions) < max_positions
                ):
                    row = rows[inst_id]
                    current_equity = cash + sum(
                        item.size * last_close.get(symbol, item.entry_price)
                        for symbol, item in positions.items()
                    )
                    weight = weights.get(inst_id, 0) / total_weight
                    budget = min(
                        cash,
                        cash * action["size_pct"],
                        current_equity * weight,
                    )
                    fee_rate, slip = self._costs("buy", row, budget)
                    entry_price = float(row["open"]) * (1 + slip)
                    if budget > 0 and entry_price > 0:
                        quantity = budget / (entry_price * (1 + fee_rate))
                        entry_notional = quantity * entry_price
                        entry_fee = entry_notional * fee_rate
                        cash -= entry_notional + entry_fee
                        turnover += entry_notional
                        total_fees += entry_fee
                        anchor = action["signal_price"] or float(row["open"])
                        ratio = entry_price / anchor if anchor > 0 else 1
                        position = Trade(
                            open_ts=timestamp,
                            close_ts=None,
                            inst_id=inst_id,
                            direction="long",
                            entry_price=entry_price,
                            size=quantity,
                            fee=entry_fee,
                            reason_open=action["reason"],
                            stop_loss=action["stop_loss"] * ratio,
                            take_profit=action["take_profit"] * ratio,
                        )
                        positions[inst_id] = position

            # 开盘成交竞争结束后，旧仓和新仓一起接受本根盘中保护；
            # SL/TP 同时命中取保守的 SL。
            apply_intrabar_protection(set(positions), rows, timestamp)

            portfolio_equity = cash + sum(
                position.size * last_close.get(inst_id, position.entry_price)
                for inst_id, position in positions.items()
            )
            equity_records.append((timestamp, portfolio_equity))
            for inst_id in normalized:
                allocation = (
                    self.initial_capital
                    * weights.get(inst_id, 0)
                    / total_weight
                )
                closed_pnl = sum(trade.pnl for trade in trades[inst_id])
                position = positions.get(inst_id)
                unrealized = (
                    position.size
                    * (last_close.get(inst_id, position.entry_price) - position.entry_price)
                    - position.fee
                    if position
                    else 0
                )
                component_records[inst_id].append(
                    (timestamp, allocation + closed_pnl + unrealized)
                )

            # 信号只看到当前收盘及之前数据，并在下一根该品种 K 线开盘执行。
            for inst_id in sorted(normalized):
                data = normalized[inst_id]
                if timestamp not in data.index:
                    continue
                history = data.loc[:timestamp].reset_index(drop=True)
                signal = strategies[inst_id].generate_signal(history, inst_id)
                if signal.is_buy and inst_id not in positions:
                    pending[inst_id] = {
                        "side": "buy",
                        "size_pct": min(max(float(signal.size_pct), 0), 1),
                        "signal_price": float(signal.price),
                        "stop_loss": float(signal.stop_loss),
                        "take_profit": float(signal.take_profit),
                        "reason": signal.reason,
                        "priority": float(signal.extra.get("priority", 0)),
                    }
                elif signal.is_sell and inst_id in positions:
                    pending[inst_id] = {
                        "side": "sell",
                        "reason": signal.reason,
                    }

        # 研究报告必须闭合所有未实现盈亏，最后一根收盘保守计卖出成本。
        if equity_records:
            final_ts = equity_records[-1][0]
            for inst_id, position in list(positions.items()):
                row = normalized[inst_id].iloc[-1]
                fee_rate, slip = self._costs(
                    "sell", row, position.size * float(row["close"])
                )
                exit_price = float(row["close"]) * (1 - slip)
                proceeds = position.size * exit_price
                exit_fee = proceeds * fee_rate
                cash += proceeds - exit_fee
                turnover += proceeds
                total_fees += exit_fee
                self._close_trade(
                    position, final_ts, exit_price, exit_fee, "end_of_backtest"
                )
                trades[inst_id].append(position)
            equity_records[-1] = (final_ts, cash)
            for inst_id in normalized:
                allocation = (
                    self.initial_capital
                    * weights.get(inst_id, 0)
                    / total_weight
                )
                component_records[inst_id][-1] = (
                    final_ts,
                    allocation + sum(trade.pnl for trade in trades[inst_id]),
                )

        equity = pd.Series(
            [value for _, value in equity_records],
            index=pd.DatetimeIndex([ts for ts, _ in equity_records]),
            name="portfolio_equity",
            dtype=float,
        )
        returns = equity.resample("1D").last().pct_change().dropna()
        rolling_peak = equity.cummax()
        drawdown = (equity - rolling_peak) / rolling_peak
        duration_days = max((equity.index[-1] - equity.index[0]).days, 1)
        total_return = equity.iloc[-1] / self.initial_capital - 1
        annual_return = (1 + total_return) ** (365 / duration_days) - 1
        max_drawdown = abs(float(drawdown.min()))
        downside = returns[returns < 0]
        gross_profit = sum(
            max(trade.pnl + trade.fee, 0)
            for rows in trades.values()
            for trade in rows
        )
        hodl_final = 0.0
        benchmark_components: list[pd.Series] = []
        for inst_id, data in normalized.items():
            weight = normalized_weights[inst_id]
            hodl_final += (
                self.initial_capital
                * weight
                * float(data["close"].iloc[-1])
                / float(data["open"].iloc[0])
            )
            daily_close = data["close"].astype(float).resample("1D").last()
            benchmark_components.append(
                daily_close / daily_close.iloc[0] * weight
            )
        benchmark_frame = pd.concat(
            benchmark_components, axis=1, join="inner"
        )
        benchmark = benchmark_frame.sum(
            axis=1,
            min_count=len(benchmark_components),
        ).dropna()
        cycle_metrics = compute_calendar_cycle_metrics(
            [
                (timestamp.date(), float(value))
                for timestamp, value in benchmark.items()
            ],
            window_days=90,
            minimum_cycle_days=self.minimum_cycle_days,
            minimum_cycle_coverage=self.minimum_cycle_coverage,
            maximum_cycle_gap_days=self.maximum_cycle_gap_days,
            regime_threshold=self.cycle_regime_threshold,
        )
        metrics = {
            "initial_capital": self.initial_capital,
            "final_capital": float(equity.iloc[-1]),
            "total_return_pct": float(total_return * 100),
            "annual_return_pct": float(
                annual_return * 100
            ),
            "max_drawdown_pct": float(drawdown.min() * 100),
            "sharpe_ratio": float(
                returns.mean() / returns.std() * (365 ** 0.5)
                if returns.std() > 0
                else 0
            ),
            "sortino_ratio": float(
                returns.mean() / downside.std() * (365 ** 0.5)
                if downside.std() > 0
                else 0
            ),
            "calmar_ratio": float(
                (annual_return / max_drawdown) if max_drawdown > 0 else 0
            ),
            "total_trades": sum(len(rows) for rows in trades.values()),
            "total_fees": total_fees,
            "turnover": turnover,
            "fee_to_gross_profit_ratio": (
                total_fees / gross_profit if gross_profit > 0 else None
            ),
            "hodl_return_pct": (hodl_final / self.initial_capital - 1) * 100,
            "alpha_vs_hodl_pct": (
                (equity.iloc[-1] - hodl_final) / self.initial_capital * 100
            ),
            "cost_model_hash": self.cost_model_hash,
            "dataset_hash": dataset_hash,
            "strategy_hash": evaluation_manifest_hash,
            "evaluation_manifest_hash": evaluation_manifest_hash,
            **cycle_metrics,
            "cycle_benchmark_weights": normalized_weights,
            "cycle_daily_benchmark": [
                {
                    "day": timestamp.date().isoformat(),
                    "value": float(value),
                }
                for timestamp, value in benchmark.items()
            ],
            "shared_cash": True,
        }
        results = {}
        for inst_id, rows in trades.items():
            component_equity = pd.Series(
                [value for _, value in component_records[inst_id]],
                index=pd.DatetimeIndex(
                    [ts for ts, _ in component_records[inst_id]]
                ),
                name=inst_id,
                dtype=float,
            )
            results[inst_id] = BacktestResult(
                trades=rows,
                equity_curve=component_equity,
                metrics={"total_trades": len(rows)},
            )
        return PortfolioResult(results, equity, metrics)

    def _costs(
        self, side: str, bar: pd.Series, notional: float
    ) -> tuple[float, float]:
        if self.cost_model is None:
            return self.fee_rate, self.slippage
        fee, slippage = self.cost_model(side, bar, notional)
        fee = float(fee)
        slippage = float(slippage)
        if (
            not math.isfinite(fee)
            or not math.isfinite(slippage)
            or not 0 <= fee < 1
            or not 0 <= slippage < 1
        ):
            raise ValueError("cost_model 必须返回 [0, 1) 内有限费率/滑点")
        return fee, slippage

    @staticmethod
    def _close_trade(
        trade: Trade,
        timestamp: pd.Timestamp,
        exit_price: float,
        exit_fee: float,
        reason: str,
    ) -> None:
        trade.close_ts = timestamp
        trade.exit_price = exit_price
        trade.fee += exit_fee
        trade.pnl = (
            trade.size * (exit_price - trade.entry_price) - trade.fee
        )
        entry_notional = trade.size * trade.entry_price
        trade.pnl_pct = (
            trade.pnl / entry_notional * 100 if entry_notional > 0 else 0
        )
        trade.reason_close = reason
        trade.is_open = False
