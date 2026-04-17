"""事件驱动回测引擎

执行约定：
  - 信号由第 i 根 K 线收盘后生成，基于 history[: i+1] 的数据。
  - 订单在第 i+1 根 K 线的开盘价成交，滑点作用于开盘价。
  - 止损/止盈在第 i+1 根 K 线内依 high/low 检查：
      · 同一根 K 线内若 low <= SL 且 high >= TP，保守假设先触发止损
        （open→low→high→close 路径，最坏情形）。
      · 仅触发其一则按命中价平仓。
"""

import logging
from dataclasses import dataclass
from typing import Optional

import pandas as pd

from okx_quant.indicators import atr as calc_atr
from okx_quant.indicators import populate_cache, slice_cache
from okx_quant.strategy.base import BaseStrategy

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
    """现货多头回测引擎

    特性:
    - 单向持仓（无做空），最多一笔
    - 信号 → 下一根 K 线开盘价成交
    - SL/TP 在 K 线内用 high/low 路径判断（保守偏向止损）
    - 支持移动止盈（take_profit == 0 时启用 trailing ATR stop）
    - 手续费+滑点建模，计算权益曲线与常规指标
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
            df: K 线 DataFrame，含 ts/open/high/low/close/vol，按时间升序
            strategy: 策略实例
            inst_id: 交易对
            warmup: 预热 K 线数（不参与交易的最初 N 根）

        Returns:
            BacktestResult
        """
        if "open" not in df.columns:
            raise ValueError("K 线 DataFrame 必须包含 open 列以支持下根 K 线开盘成交")

        capital = self.initial_capital
        position: Optional[Trade] = None
        trades: list[Trade] = []
        equity_records: list[tuple] = []
        highest_since_entry: float = 0.0

        # 预计算 ATR 序列，供 trailing stop 使用
        atr_series = calc_atr(df)

        # 预计算一组常用指标到 df.attrs，策略通过 cached_* 读取，O(n²) → O(n)
        # 指标都是因果的（第 i 行仅依赖 <=i 输入），slice 后等价于子区间内单独计算
        populate_cache(
            df,
            ema_periods=(7, 9, 12, 14, 15, 20, 21, 26, 50),
            rsi_periods=(14,),
            macd_specs=((12, 26, 9),),
            bbands_specs=((20, 2.0),),
            atr_periods=(14,),
            adx_periods=(14,),
        )

        # 待执行订单：由前一根 K 线收盘生成，于当前 K 线开盘成交
        pending_entry: Optional[dict] = None  # {size_pct, sl, tp, reason}
        pending_exit: bool = False
        pending_exit_reason: str = ""

        n = len(df)
        for i in range(n):
            bar = df.iloc[i]
            ts = bar["ts"]
            open_px = float(bar["open"])
            high = float(bar["high"])
            low = float(bar["low"])
            close = float(bar["close"])

            # ---------- 1. 执行上一根 K 线生成的挂单 ----------
            if pending_exit and position and position.is_open:
                exit_price = open_px * (1 - self.slippage)
                capital = self._close_position(position, exit_price, ts, pending_exit_reason, capital)
                trades.append(position)
                position = None
                highest_since_entry = 0.0
            pending_exit = False
            pending_exit_reason = ""

            if pending_entry and position is None:
                entry_price = open_px * (1 + self.slippage)
                cost = capital * pending_entry["size_pct"]
                if cost > 0 and entry_price > 0:
                    size = cost / entry_price
                    fee = cost * self.fee_rate
                    capital -= cost + fee

                    sl = pending_entry["sl"]
                    tp = pending_entry["tp"]
                    position = Trade(
                        open_ts=ts,
                        close_ts=None,
                        inst_id=inst_id,
                        direction="long",
                        entry_price=entry_price,
                        size=size,
                        fee=fee,
                        reason_open=pending_entry["reason"],
                        stop_loss=sl,
                        take_profit=tp,
                    )
                    highest_since_entry = entry_price
                    logger.debug("[%s] 开仓 %.6f @ %.4f  SL=%.4f TP=%.4f", ts, size, entry_price, sl, tp)
            pending_entry = None

            # ---------- 2. 持仓期间 trailing stop 调整 ----------
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

            # ---------- 3. 当根 K 线内检查 SL/TP 触发 ----------
            if position and position.is_open:
                exit_price, exit_reason = self._check_sl_tp(position, open_px, high, low)
                if exit_price:
                    capital = self._close_position(position, exit_price, ts, exit_reason, capital)
                    trades.append(position)
                    position = None
                    highest_since_entry = 0.0

            # ---------- 4. 基于当根 K 线收盘生成下一根 K 线的挂单 ----------
            if i < warmup:
                equity_records.append((ts, capital))
                continue

            # 回测最后一根不再挂单（无下一根可执行）
            if i < n - 1:
                history = df.iloc[: i + 1]
                # 把预计算结果切片传给策略，避免其在子区间上重算指标
                slice_cache(df, history, i + 1)
                signal = strategy.generate_signal(history, inst_id)

                if position is None and signal.is_buy and signal.size_pct > 0:
                    pending_entry = {
                        "size_pct": min(max(signal.size_pct, 0.0), 1.0),
                        "sl": signal.stop_loss,
                        "tp": signal.take_profit,
                        "reason": signal.reason,
                    }
                elif position is not None and signal.is_sell:
                    pending_exit = True
                    pending_exit_reason = signal.reason or "策略卖出"

            # 记录当前权益（持仓市值按收盘价 + 现金）
            portfolio_value = capital + (position.size * close if position else 0)
            equity_records.append((ts, portfolio_value))

        # 回测结束，强制平仓
        if position and position.is_open:
            final_close = float(df["close"].iloc[-1])
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
        self, pos: Trade, open_px: float, high: float, low: float
    ) -> tuple[float, str]:
        """判断 K 线内是否触发止损/止盈（路径不可知情形下保守取最差）

        规则：
          - 若开盘价已穿越 SL/TP，按开盘价立即触发。
          - 若同根 K 线 high/low 同时触及两者，假设先到 SL（最坏情形）。
          - 仅触及其一则按触及价触发。
        """
        sl = pos.stop_loss
        tp = pos.take_profit

        # 开盘跳空场景
        if sl > 0 and open_px <= sl:
            reason = "止损触发（跳空）"
            return open_px, reason
        if tp > 0 and open_px >= tp:
            reason = "止盈触发（跳空）"
            return open_px, reason

        hit_sl = sl > 0 and low <= sl
        hit_tp = tp > 0 and high >= tp

        if hit_sl and hit_tp:
            # 路径未知 → 保守按止损成交
            reason = "止损触发（同K线双命中，保守假设）"
            return sl, reason
        if hit_sl:
            reason = "止损触发（移动止盈）" if tp == 0 else "止损触发"
            return sl, reason
        if hit_tp:
            return tp, "止盈触发"
        return 0.0, ""

    def _close_position(
        self, pos: Trade, exit_price: float, ts, reason: str, capital: float
    ) -> float:
        fee = pos.size * exit_price * self.fee_rate
        pnl = pos.size * (exit_price - pos.entry_price) - pos.fee - fee
        pos.exit_price = exit_price
        pos.close_ts = ts
        pos.pnl = round(pnl, 6)
        denom = pos.entry_price * pos.size
        pos.pnl_pct = round(pnl / denom * 100, 4) if denom > 0 else 0.0
        pos.fee += fee
        pos.reason_close = reason
        pos.is_open = False
        logger.debug(
            "[%s] 平仓 %.6f @ %.4f  PnL=%.2f USDT (%.2f%%)",
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
