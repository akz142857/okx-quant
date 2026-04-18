"""OrderExecutor 单元测试 —— 使用 FakeExchange 完全本地化"""

import pytest

from okx_quant.exchange import InstrumentInfo
from okx_quant.exchange.fake import FakeExchange
from okx_quant.risk.manager import RiskConfig, RiskManager
from okx_quant.trading.orders import OrderExecutor


def _build_order_executor(*, min_sz: float = 0.0, lot_sz: float = 0.0) -> tuple[OrderExecutor, FakeExchange, RiskManager]:
    ex = FakeExchange()
    ex.set_instrument(InstrumentInfo(
        inst_id="BTC-USDT",
        base_ccy="BTC",
        quote_ccy="USDT",
        lot_size=lot_sz,
        min_size=min_sz,
    ))
    risk = RiskManager(RiskConfig(max_position_pct=1.0))
    risk.initialize(10000.0)
    oe = OrderExecutor(exchange=ex, inst_id="BTC-USDT", risk=risk)
    return oe, ex, risk


@pytest.mark.unit
def test_buy_registers_position_and_returns_true():
    oe, ex, risk = _build_order_executor(min_sz=0.0001)
    ok = oe.buy(price=50000, size_coin=0.01, sl=49000, tp=52000, reason="test")
    assert ok is True
    assert risk.has_position("BTC-USDT")
    pos = risk.get_position("BTC-USDT")
    assert pos.size == pytest.approx(0.01)
    assert len(ex.orders) == 1
    assert ex.orders[0].side == "buy"


@pytest.mark.unit
def test_buy_skips_when_below_min_size():
    oe, ex, risk = _build_order_executor(min_sz=0.01)
    ok = oe.buy(price=50000, size_coin=0.001, sl=0, tp=0, reason="small")
    assert ok is False
    assert not risk.has_position("BTC-USDT")
    assert len(ex.orders) == 0


@pytest.mark.unit
def test_buy_failure_triggers_cooldown():
    class RaisingExchange(FakeExchange):
        def place_market_order(self, *a, **kw):  # type: ignore[override]
            raise RuntimeError("API down")

    ex = RaisingExchange()
    ex.set_instrument(InstrumentInfo("BTC-USDT", "BTC", "USDT", 0, 0))
    risk = RiskManager(RiskConfig())
    risk.initialize(10000)
    oe = OrderExecutor(exchange=ex, inst_id="BTC-USDT", risk=risk)

    ok = oe.buy(price=50000, size_coin=0.01, sl=0, tp=0, reason="x")
    assert ok is False
    assert oe.in_buy_cooldown()


@pytest.mark.unit
def test_sell_removes_position_and_orders():
    oe, ex, risk = _build_order_executor(min_sz=0.0001)
    # 先买入
    oe.buy(price=50000, size_coin=0.01, sl=0, tp=0, reason="entry")
    assert risk.has_position("BTC-USDT")
    # 模拟 OKX 扣手续费后实际到账
    ex.set_holding("BTC", balance=0.00999, available=0.00999)
    # 卖出 —— 新逻辑会查 exchange.available 并取 min(pos.size, 0.00999)
    ok = oe.sell(last_price=51000, reason="tp")
    assert ok is True
    assert not risk.has_position("BTC-USDT")
    assert ex.orders[-1].side == "sell"
    # 实际卖单量应为 exchange 可用，而非 pos.size
    assert ex.orders[-1].size == pytest.approx(0.00999)


@pytest.mark.unit
def test_sell_uses_exchange_available_not_pos_size():
    """回归测试：买入 0.01 BTC，手续费后实际到账 0.00999；
    sell 应当用 0.00999 而不是 0.01 下单，避免 OKX 51008。"""
    oe, ex, risk = _build_order_executor(min_sz=0.0001)
    from okx_quant.risk.manager import PositionInfo
    risk.add_position(PositionInfo("BTC-USDT", size=0.01, entry_price=50000))
    ex.set_holding("BTC", balance=0.00999, available=0.00999)

    ok = oe.sell(last_price=50100, reason="死叉")
    assert ok is True
    placed = ex.orders[-1]
    # 关键断言：下单量 ≤ 交易所实际可用
    assert placed.size <= 0.00999 + 1e-9
    assert placed.size < 0.01


@pytest.mark.unit
def test_sell_cleans_phantom_when_exchange_balance_dust():
    """实际余额低于 minSz → 自动清除幻影仓位，不发订单"""
    oe, ex, risk = _build_order_executor(min_sz=0.01)
    from okx_quant.risk.manager import PositionInfo
    risk.add_position(PositionInfo("BTC-USDT", size=0.01, entry_price=50000))
    # 交易所只有粉尘余额（< minSz 0.01）
    ex.set_holding("BTC", balance=0.005, available=0.005)

    ok = oe.sell(last_price=50000, reason="死叉")
    assert ok is False
    assert not risk.has_position("BTC-USDT")
    # 不应该向交易所发单
    assert len(ex.orders) == 0


@pytest.mark.unit
def test_lot_size_rounds_down():
    oe, _, _ = _build_order_executor(min_sz=0.0, lot_sz=0.01)
    assert oe.round_lot_size(0.0123) == pytest.approx(0.01)
    assert oe.round_lot_size(0.999) == pytest.approx(0.99)


@pytest.mark.unit
def test_phantom_position_cleanup_on_insufficient_balance():
    class PhantomExchange(FakeExchange):
        def place_market_order(self, *a, **kw):  # type: ignore[override]
            raise RuntimeError("OKX API Error [51008]: insufficient balance")

    ex = PhantomExchange()
    ex.set_instrument(InstrumentInfo("BTC-USDT", "BTC", "USDT", 0, 0.01))
    # 账户没 BTC 持仓 → _cleanup_phantom_position 应清除 risk 中的幻影仓
    risk = RiskManager(RiskConfig())
    risk.initialize(10000)
    # 模拟：风控里有仓位但交易所没 BTC
    from okx_quant.risk.manager import PositionInfo
    risk.add_position(PositionInfo("BTC-USDT", size=0.01, entry_price=50000))

    oe = OrderExecutor(exchange=ex, inst_id="BTC-USDT", risk=risk)
    oe.sell(last_price=50000, reason="exit")
    assert not risk.has_position("BTC-USDT")
