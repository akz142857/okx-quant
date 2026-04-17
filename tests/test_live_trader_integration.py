"""LiveTrader end-to-end tick 集成测试

使用 FakeExchange + 可编程策略，完整驱动 _tick 一次 BUY + 一次 SELL，
覆盖：
  - exchange.get_candles → 策略信号 → 风控 → OrderExecutor.buy 链路
  - _on_buy_success 回调 → 写入 _trade_log + 重置 _monitor._highest
  - SL/TP 触发 → PositionMonitor.check → _sell_for_monitor → OrderExecutor.sell
  - 状态持久化写 StateStore
"""

from __future__ import annotations

import pandas as pd
import pytest

from okx_quant.exchange import InstrumentInfo
from okx_quant.exchange.fake import FakeExchange
from okx_quant.risk.manager import RiskConfig, RiskManager
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from okx_quant.trading.executor import LiveTrader
from okx_quant.trading.state import StateStore


class ScriptedStrategy(BaseStrategy):
    """按预置剧本返回信号的策略 —— 用于确定性驱动 _tick"""

    name = "Scripted"

    def __init__(self, scripted_signals: list[SignalType]):
        super().__init__({})
        self._scripted = list(scripted_signals)

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        price = float(df["close"].iloc[-1])
        if not self._scripted:
            return Signal(SignalType.HOLD, inst_id, price=price)
        sig_type = self._scripted.pop(0)
        if sig_type == SignalType.BUY:
            return Signal(
                signal=SignalType.BUY,
                inst_id=inst_id,
                price=price,
                size_pct=0.1,
                stop_loss=round(price * 0.95, 8),
                take_profit=round(price * 1.10, 8),
                reason="scripted buy",
            )
        if sig_type == SignalType.SELL:
            return Signal(SignalType.SELL, inst_id, price=price, reason="scripted sell")
        return Signal(SignalType.HOLD, inst_id, price=price, reason="scripted hold")


def _build_candles(prices: list[float]) -> pd.DataFrame:
    n = len(prices)
    ts = pd.date_range("2026-01-01", periods=n, freq="1h", tz="UTC")
    return pd.DataFrame({
        "ts": ts,
        "open": prices,
        "high": [p * 1.005 for p in prices],
        "low": [p * 0.995 for p in prices],
        "close": prices,
        "vol": [100] * n,
        "vol_ccy": [p * 100 for p in prices],
    })


def _build_trader(tmp_path, scripted: list[SignalType]) -> tuple[LiveTrader, FakeExchange, RiskManager]:
    ex = FakeExchange(quote_ccy="USDT")
    ex.set_balance(total=10_000, quote_avail=10_000)
    ex.set_instrument(InstrumentInfo("BTC-USDT", "BTC", "USDT", lot_size=0.0001, min_size=0.0001))
    ex.set_candles("BTC-USDT", "1H", _build_candles([50000.0] * 50))

    risk = RiskManager(RiskConfig(
        max_position_pct=1.0, stop_loss_pct=0.02, take_profit_pct=0.04,
        max_open_positions=1, min_order_usdt=1.0,
    ))
    risk.initialize(10_000)
    store = StateStore(state_dir=str(tmp_path / "state"))

    trader = LiveTrader(
        exchange=ex,
        strategy=ScriptedStrategy(scripted),
        inst_id="BTC-USDT",
        risk_manager=risk,
        state_store=store,
        signal_timeout_s=0,  # 同步调用，简化测试
        dashboard=False,
    )
    return trader, ex, risk


@pytest.mark.unit
def test_tick_buy_signal_opens_position(tmp_path):
    trader, ex, risk = _build_trader(tmp_path, [SignalType.BUY])
    trader._tick("1H", lookback=50)

    # 交易所收到一笔 buy
    assert len(ex.orders) == 1
    assert ex.orders[0].side == "buy"
    # 风控登记了仓位
    assert risk.has_position("BTC-USDT")
    # trade_log 写入 BUY 记录
    assert len(trader._trade_log) == 1
    assert trader._trade_log[0]["side"] == "BUY"
    # trailing stop 基准被 PositionMonitor 重置为入场价
    assert trader._monitor.highest_since_entry == pytest.approx(50000.0)


@pytest.mark.unit
def test_tick_sell_signal_closes_position(tmp_path):
    trader, ex, risk = _build_trader(tmp_path, [SignalType.BUY, SignalType.SELL])
    # run() 负责递增 _tick_count；直接调 _tick 需手动递增
    trader._tick_count += 1
    trader._tick("1H", lookback=50)
    assert risk.has_position("BTC-USDT")

    # 让 FakeExchange 在卖出前模拟持仓到账
    ex.set_holding("BTC", balance=0.01, available=0.01)
    trader._tick_count += 1
    trader._tick("1H", lookback=50)

    assert len(ex.orders) == 2
    assert ex.orders[1].side == "sell"
    assert not risk.has_position("BTC-USDT")
    # _monitor 已重置
    assert trader._monitor.highest_since_entry == 0.0
    # 状态已落盘
    reloaded = trader._state_store.load("BTC-USDT")
    assert reloaded is not None
    assert reloaded.tick_count == 2


@pytest.mark.unit
def test_tick_sl_triggers_sell_without_strategy_signal(tmp_path):
    trader, ex, risk = _build_trader(tmp_path, [SignalType.BUY])
    trader._tick("1H", lookback=50)
    assert risk.has_position("BTC-USDT")
    ex.set_holding("BTC", balance=0.01, available=0.01)

    # 把 K 线价格拉到止损之下（SL = 50000*0.95 = 47500）
    crash = _build_candles([50000.0] * 49 + [46000.0])
    ex.set_candles("BTC-USDT", "1H", crash)

    # 策略队列为空 → 后续 HOLD；SL 应在 PositionMonitor 触发
    trader._tick("1H", lookback=50)

    assert not risk.has_position("BTC-USDT")
    assert ex.orders[-1].side == "sell"


@pytest.mark.unit
def test_tick_buy_fail_enters_cooldown(tmp_path):
    class FailingExchange(FakeExchange):
        def place_market_order(self, *a, **kw):  # type: ignore[override]
            raise RuntimeError("insufficient funds")

    ex = FailingExchange(quote_ccy="USDT")
    ex.set_balance(total=10_000, quote_avail=10_000)
    ex.set_instrument(InstrumentInfo("BTC-USDT", "BTC", "USDT", 0.0001, 0.0001))
    ex.set_candles("BTC-USDT", "1H", _build_candles([50000.0] * 50))

    risk = RiskManager(RiskConfig(max_position_pct=1.0))
    risk.initialize(10_000)
    store = StateStore(state_dir=str(tmp_path / "state"))

    trader = LiveTrader(
        exchange=ex, strategy=ScriptedStrategy([SignalType.BUY]),
        inst_id="BTC-USDT", risk_manager=risk, state_store=store,
        signal_timeout_s=0, dashboard=False,
    )
    trader._tick("1H", lookback=50)

    assert not risk.has_position("BTC-USDT")
    # 买入失败后进入冷却
    assert trader._orders.in_buy_cooldown()


@pytest.mark.unit
def test_tick_persists_state_each_iteration(tmp_path):
    trader, _, _ = _build_trader(tmp_path, [SignalType.BUY])
    trader._tick_count += 1
    trader._tick("1H", lookback=50)
    state = trader._state_store.load("BTC-USDT")
    assert state is not None
    assert state.tick_count == 1
    assert state.highest_since_entry > 0