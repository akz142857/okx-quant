"""事件驱动回测引擎"""

import logging
from dataclasses import dataclass, field
from typing import Optional
import pandas as pd

from okx_quant.indicators import atr as calc_atr
from okx_quant.strategy.base import BaseStrategy, SignalType

logger = logging.getLogger(__name__)


@dataclass
class Trade:
    """单笔交易记录"""

    open_ts: pd.Timestamp
    close_ts: Optional[pd.Timestamp]
    inst_id: str
    direction: str           # "long" | "short"
    entry_price: float
    exit_price: float = 0.0
    size: float = 0.0        # 以币种为单位
    pnl: float = 0.0         # 已实现盈亏（USDT）
    pnl_pct: float = 0.0
    fee: float = 0.0
    reason_open: str = ""
    reason_close: str = ""
    stop_loss: float = 0.0
    take_profit: float = 0.0
    is_open: bool = True


@dataclass
class BacktestResult:
    trades: list[Trade]
    equity_curve: pd.Series      # 以 K 线时间戳为索引的净值曲线
    metrics: dict


class BacktestEngine:
    """简单现货回测引擎

    特性:
    - 每次只持有一个方向的仓位（无做空）
    - 支持止损/止盈自动出场
    - 计算手续费和滑点
    - 输出权益曲线和绩效指标

    用法::

        engine = BacktestEngine(initial_capital=10000, fee_rate=0.001, slippage=0.0005)
        result = engine.run(df, strategy, inst_id="BTC-USDT")
        report = BacktestReport(result)
        report.print_summary()
    """

    def __init__(
        self,
        initial_capital: float = 10000.0,
        fee_rate: float = 0.001,
        slippage: float = 0.0005,
        trailing_atr_mult: float = 2.0,
    ):
        self.initial_capital = initial_capital
        self.fee_rate = fee_rate
        self.slippage = slippage
        self.trailing_atr_mult = trailing_atr_mult

    def run(
        self,
        df: pd.DataFrame,
        strategy: BaseStrategy,
        inst_id: str,
        warmup: int = 0,
    ) -> BacktestResult:
        """执行回测

        Args:
            df: K 线 DataFrame，含 ts/open/high/low/close/vol
            strategy: 策略实例
            inst_id: 交易对
            warmup: 预热 K 线数（不参与交易的最初 N 根）

        Returns:
            BacktestResult
        """
        capital = self.initial_capital
        position: Optional[Trade] = None
        trades: list[Trade] = []
        equity_records: list[tuple] = []
        highest_since_entry: float = 0.0

        # 预计算 ATR 序列，供 trailing stop 使用
        atr_series = calc_atr(df)

        for i in range(1, len(df)):
            bar = df.iloc[i]
            history = df.iloc[: i + 1]
            ts = bar["ts"]
            close = bar["close"]
            high = bar["high"]
            low = bar["low"]

            # 移动止盈：更新最高价并上移止损
            if position and position.is_open:
                if high > highest_since_entry:
                    highest_since_entry = high
                # take_profit == 0 表示使用 trailing stop 代替固定止盈
                if position.take_profit == 0:
                    curr_atr = atr_series.iloc[i]
                    if curr_atr > 0:
                        trailing_stop = highest_since_entry - self.trailing_atr_mult * curr_atr
                        if trailing_stop > position.stop_loss:
                            position.stop_loss = trailing_stop

            # 检查止损/止盈（在生成信号前执行，模拟 K 线内触发）
            if position and position.is_open:
                exit_price, exit_reason = self._check_sl_tp(position, high, low)
                if exit_price:
                    capital = self._close_position(position, exit_price, ts, exit_reason, capital)
                    trades.append(position)
                    position = None
                    highest_since_entry = 0.0

            # 跳过预热期
            if i < warmup:
                equity_records.append((ts, capital))
                continue

            # 生成信号
            signal = strategy.generate_signal(history, inst_id)

            # 执行交易逻辑
            if position is None:
                if signal.is_buy:
                    # 开仓，下一根 K 线开盘价成交（这里用当前收盘价近似）
                    entry = close * (1 + self.slippage)
                    cost = capital * signal.size_pct
                    size = cost / entry
                    fee = cost * self.fee_rate
                    capital -= cost + fee

                    position = Trade(
                        open_ts=ts,
                        close_ts=None,
                        inst_id=inst_id,
                        direction="long",
                        entry_price=entry,
                        size=size,
                        fee=fee,
                        reason_open=signal.reason,
                        stop_loss=signal.stop_loss,
                        take_profit=signal.take_profit,
                    )
                    highest_since_entry = entry
                    logger.debug("[%s] 开仓 %.4f @ %.4f  SL=%.4f", ts, size, entry, signal.stop_loss)

            else:
                if signal.is_sell:
                    exit_price = close * (1 - self.slippage)
                    capital = self._close_position(position, exit_price, ts, signal.reason, capital)
                    trades.append(position)
                    position = None
                    highest_since_entry = 0.0

            # 记录当前权益（持仓市值 + 现金）
            portfolio_value = capital + (position.size * close if position else 0)
            equity_records.append((ts, portfolio_value))

        # 回测结束，强制平仓
        if position and position.is_open:
            final_close = df["close"].iloc[-1]
            capital = self._close_position(
                position, final_close, df["ts"].iloc[-1], "回测结束强制平仓", capital
            )
            trades.append(position)

        equity_series = pd.Series(
            [v for _, v in equity_records],
            index=pd.DatetimeIndex([t for t, _ in equity_records]),
            name="equity",
        )

        metrics = self._calc_metrics(trades, equity_series)
        return BacktestResult(trades=trades, equity_curve=equity_series, metrics=metrics)

    def _check_sl_tp(
        self, pos: Trade, high: float, low: float
    ) -> tuple[float, str]:
        """判断 K 线内是否触发止损/止盈"""
        if pos.stop_loss > 0 and low <= pos.stop_loss:
            # take_profit == 0 时止损由 trailing stop 动态上移
            reason = "止损触发（移动止盈）" if pos.take_profit == 0 else "止损触发"
            return pos.stop_loss, reason
        if pos.take_profit > 0 and high >= pos.take_profit:
            return pos.take_profit, "止盈触发"
        return 0.0, ""

    def _close_position(
        self, pos: Trade, exit_price: float, ts, reason: str, capital: float
    ) -> float:
        fee = pos.size * exit_price * self.fee_rate
        pnl = pos.size * (exit_price - pos.entry_price) - pos.fee - fee
        pos.exit_price = exit_price
        pos.close_ts = ts
        pos.pnl = round(pnl, 6)
        pos.pnl_pct = round(pnl / (pos.entry_price * pos.size) * 100, 4)
        pos.fee += fee
        pos.reason_close = reason
        pos.is_open = False
        logger.debug(
            "[%s] 平仓 %.4f @ %.4f  PnL=%.2f USDT (%.2f%%)",
            ts, pos.size, exit_price, pnl, pos.pnl_pct,
        )
        return capital + pos.size * exit_price - fee

    def _calc_metrics(self, trades: list[Trade], equity: pd.Series) -> dict:
        closed = [t for t in trades if not t.is_open]
        if not closed:
            return {"total_trades": 0}

        wins = [t for t in closed if t.pnl > 0]
        losses = [t for t in closed if t.pnl <= 0]
        total_pnl = sum(t.pnl for t in closed)
        total_fee = sum(t.fee for t in closed)

        # 最大回撤
        roll_max = equity.cummax()
        drawdown = (equity - roll_max) / roll_max * 100
        max_dd = drawdown.min()

        # 年化收益
        duration_days = (equity.index[-1] - equity.index[0]).days or 1
        final_val = equity.iloc[-1]
        init_val = equity.iloc[0]
        total_return_pct = (final_val - init_val) / init_val * 100
        annual_return_pct = (1 + total_return_pct / 100) ** (365 / duration_days) - 1

        # Sharpe（简化版，用每日收益率）
        daily_returns = equity.resample("1D").last().pct_change().dropna()
        sharpe = (
            daily_returns.mean() / daily_returns.std() * (252 ** 0.5)
            if daily_returns.std() > 0
            else 0
        )

        avg_win = sum(t.pnl for t in wins) / len(wins) if wins else 0
        avg_loss = abs(sum(t.pnl for t in losses) / len(losses)) if losses else 0
        profit_factor = (
            sum(t.pnl for t in wins) / abs(sum(t.pnl for t in losses))
            if losses and sum(t.pnl for t in losses) != 0
            else float("inf")
        )

        return {
            "total_trades": len(closed),
            "win_trades": len(wins),
            "loss_trades": len(losses),
            "win_rate_pct": round(len(wins) / len(closed) * 100, 2),
            "total_pnl": round(total_pnl, 4),
            "total_fee": round(total_fee, 4),
            "avg_win": round(avg_win, 4),
            "avg_loss": round(avg_loss, 4),
            "profit_factor": round(profit_factor, 4),
            "total_return_pct": round(total_return_pct, 4),
            "annual_return_pct": round(annual_return_pct * 100, 4),
            "max_drawdown_pct": round(max_dd, 4),
            "sharpe_ratio": round(sharpe, 4),
            "final_capital": round(final_val, 4),
            "initial_capital": self.initial_capital,
        }
