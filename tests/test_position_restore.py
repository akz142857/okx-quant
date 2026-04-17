"""position_restore 模块测试 — 用 FakeExchange 验证不触网"""

import pytest

from okx_quant.exchange.fake import FakeExchange
from okx_quant.risk.manager import RiskConfig, RiskManager
from okx_quant.trading.position_restore import discover_positions, restore_to_risk


def _build_fake(total: float = 10000.0) -> FakeExchange:
    ex = FakeExchange(quote_ccy="USDT")
    ex.set_balance(total=total, quote_avail=total / 2)
    return ex


@pytest.mark.unit
def test_discover_positions_ignores_quote_ccy():
    ex = _build_fake()
    ex.set_holding("BTC", balance=0.1, available=0.1)
    ex.set_holding("ETH", balance=0.5, available=0.5)
    items = discover_positions(ex, "USDT")
    pairs = {inst_id for inst_id, _ in items}
    assert pairs == {"BTC-USDT", "ETH-USDT"}


@pytest.mark.unit
def test_restore_to_risk_scopes_to_given_inst_ids():
    ex = _build_fake()
    ex.set_holding("BTC", balance=0.1, available=0.1)
    ex.set_holding("ETH", balance=0.5, available=0.5)
    ex.set_ticker("BTC-USDT", last=50000.0)
    # ETH 不在 scope 里，即使有持仓也不应登记

    risk = RiskManager(RiskConfig(stop_loss_pct=0.02, take_profit_pct=0.04))
    n = restore_to_risk(ex, risk, ["BTC-USDT"], quote_ccy="USDT")
    assert n == 1
    assert risk.has_position("BTC-USDT")
    assert not risk.has_position("ETH-USDT")

    pos = risk.get_position("BTC-USDT")
    assert pos.size == pytest.approx(0.1)
    assert pos.entry_price == pytest.approx(50000.0)
    assert pos.stop_loss == pytest.approx(50000.0 * 0.98, rel=1e-6)
    assert pos.take_profit == pytest.approx(50000.0 * 1.04, rel=1e-6)


@pytest.mark.unit
def test_restore_to_risk_skips_already_registered():
    ex = _build_fake()
    ex.set_holding("BTC", balance=0.1, available=0.1)
    ex.set_ticker("BTC-USDT", last=50000.0)

    risk = RiskManager(RiskConfig())
    # 先登记一次
    restore_to_risk(ex, risk, ["BTC-USDT"])
    first_entry_price = risk.get_position("BTC-USDT").entry_price
    # 价格改变后再调用——不应覆盖已登记的
    ex.set_ticker("BTC-USDT", last=99999.0)
    restore_to_risk(ex, risk, ["BTC-USDT"])
    assert risk.get_position("BTC-USDT").entry_price == first_entry_price


@pytest.mark.unit
def test_restore_skips_when_ticker_price_zero():
    ex = _build_fake()
    ex.set_holding("BTC", balance=0.1, available=0.1)
    # 故意不设 ticker → price=0
    risk = RiskManager(RiskConfig())
    n = restore_to_risk(ex, risk, ["BTC-USDT"])
    assert n == 0
    assert not risk.has_position("BTC-USDT")


@pytest.mark.unit
def test_discover_positions_returns_empty_on_exchange_error():
    class BrokenExchange(FakeExchange):
        def get_balance(self):  # type: ignore[override]
            raise RuntimeError("network down")

    ex = BrokenExchange()
    assert discover_positions(ex, "USDT") == []
