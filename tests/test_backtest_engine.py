"""回测引擎单元测试"""

import numpy as np
import pandas as pd
import pytest

from okx_quant.backtest import BacktestEngine
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType


class BuyHoldStrategy(BaseStrategy):
    """第一根 K 线买入，最后一根卖出"""

    name = "BuyHoldTest"

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        price = float(df["close"].iloc[-1])
        if len(df) == 1:
            return Signal(SignalType.BUY, inst_id, price=price, size_pct=1.0)
        # 最后一根 K 线由引擎自动强平，不需要显式 SELL
        return Signal(SignalType.HOLD, inst_id, price=price)


class AlwaysHoldStrategy(BaseStrategy):
    name = "AlwaysHold"

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        return Signal(SignalType.HOLD, inst_id, price=float(df["close"].iloc[-1]))


class PeekFuturesStrategy(BaseStrategy):
    """故意尝试 "偷看" 下一根 K 线 — 用于验证引擎不泄露未来数据

    如果引擎把完整 df 喂给策略，那么 df 最后一行就是 "当前" 根；
    若引擎错误地把未来一根也喂进来，len(df) 会超出预期。
    """

    name = "PeekFutures"

    def __init__(self, total_bars: int):
        super().__init__()
        self.total_bars = total_bars
        self.max_history_len = 0

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        self.max_history_len = max(self.max_history_len, len(df))
        return Signal(SignalType.HOLD, inst_id, price=float(df["close"].iloc[-1]))


@pytest.mark.unit
def test_engine_runs_without_error(synthetic_ohlcv):
    engine = BacktestEngine(initial_capital=10000, fee_rate=0.001, slippage=0.0005)
    result = engine.run(synthetic_ohlcv, AlwaysHoldStrategy(), "BTC-USDT")
    assert result.metrics["total_trades"] == 0
    assert len(result.equity_curve) == len(synthetic_ohlcv)
    # 没交易 → 权益保持初始资金
    assert result.equity_curve.iloc[-1] == pytest.approx(10000.0)


@pytest.mark.unit
def test_buy_hold_executes_on_next_bar_open(synthetic_ohlcv):
    engine = BacktestEngine(initial_capital=10000, fee_rate=0.0, slippage=0.0)
    result = engine.run(synthetic_ohlcv, BuyHoldStrategy(), "BTC-USDT")
    assert result.metrics["total_trades"] == 1
    trade = result.trades[0]
    # 信号在第 0 根 K 线结束产生 → 在第 1 根 K 线 open 成交
    expected_entry = synthetic_ohlcv["open"].iloc[1]
    assert trade.entry_price == pytest.approx(expected_entry, rel=1e-6)


@pytest.mark.unit
def test_no_lookahead_in_history_passed_to_strategy(synthetic_ohlcv):
    strat = PeekFuturesStrategy(total_bars=len(synthetic_ohlcv))
    engine = BacktestEngine()
    engine.run(synthetic_ohlcv, strat, "BTC-USDT")
    # 策略只能看到当前 bar 及之前的数据：最长等于总数 - 1
    # （最后一根 K 线不再产生新信号）
    assert strat.max_history_len <= len(synthetic_ohlcv) - 1


@pytest.mark.unit
def test_stop_loss_hit_conservative_path():
    """同根 K 线内 SL/TP 双命中时应保守按止损成交"""
    engine = BacktestEngine(initial_capital=10000, fee_rate=0.0, slippage=0.0)

    # 构造 3 根 K 线：
    # bar0 close=100 → 策略发出 BUY，目标在 bar1 open=100 成交
    # bar1 high=110 / low=95 → 同根内既穿越 SL=98 又穿越 TP=105
    # 引擎应判定：止损先触发（保守）
    df = pd.DataFrame({
        "ts": pd.date_range("2026-01-01", periods=3, freq="1h", tz="UTC"),
        "open":  [100.0, 100.0, 105.0],
        "high":  [101.0, 110.0, 110.0],
        "low":   [99.0,   95.0, 104.0],
        "close": [100.0, 105.0, 108.0],
        "vol":   [100, 100, 100],
    })

    class FixedSLTP(BaseStrategy):
        name = "FixedSLTP"

        def generate_signal(self, hist, inst_id):
            if len(hist) == 1:
                return Signal(
                    SignalType.BUY, inst_id, price=100.0, size_pct=1.0,
                    stop_loss=98.0, take_profit=105.0,
                )
            return Signal(SignalType.HOLD, inst_id, price=float(hist["close"].iloc[-1]))

    result = engine.run(df, FixedSLTP(), "BTC-USDT")
    assert result.metrics["total_trades"] == 1
    trade = result.trades[0]
    assert trade.exit_price == pytest.approx(98.0)
    assert "止损" in trade.reason_close


@pytest.mark.unit
def test_engine_requires_open_column():
    df = pd.DataFrame({
        "ts": pd.date_range("2026-01-01", periods=5, freq="1h", tz="UTC"),
        "high": [1, 2, 3, 4, 5],
        "low":  [1, 1, 2, 3, 4],
        "close": [1, 2, 3, 4, 5],
        "vol": [1, 1, 1, 1, 1],
    })
    with pytest.raises(ValueError):
        BacktestEngine().run(df, AlwaysHoldStrategy(), "BTC-USDT")
