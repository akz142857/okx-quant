"""风控管理器单元测试"""

import pytest

from okx_quant.risk.manager import PositionInfo, RiskConfig, RiskManager


@pytest.mark.unit
def test_check_order_rejects_when_halted():
    rm = RiskManager(RiskConfig(max_drawdown_pct=0.1), initial_equity=10000)
    rm.update_equity(9000)  # 10% drawdown → halt
    assert rm.is_halted
    ok, reason = rm.check_order("BTC-USDT", "buy", 100, 50000, 9000)
    assert not ok
    assert "暂停" in reason


@pytest.mark.unit
def test_drawdown_auto_recovery():
    rm = RiskManager(
        RiskConfig(max_drawdown_pct=0.2, drawdown_recover_ratio=0.5),
        initial_equity=10000,
    )
    rm.update_equity(7999)  # 20%+ drawdown → halted
    assert rm.is_halted
    # 回升到峰值的 95%（drawdown 5% <= 10%）→ 应自动解除
    rm.update_equity(9500)
    assert not rm.is_halted


@pytest.mark.unit
def test_drawdown_recovery_disabled_by_zero_ratio():
    rm = RiskManager(
        RiskConfig(max_drawdown_pct=0.1, drawdown_recover_ratio=0.0),
        initial_equity=10000,
    )
    rm.update_equity(8999)
    assert rm.is_halted
    rm.update_equity(9800)
    assert rm.is_halted  # ratio=0 → 不自动恢复


@pytest.mark.unit
def test_max_position_pct_guard():
    rm = RiskManager(RiskConfig(max_position_pct=0.1), initial_equity=10000)
    ok, reason = rm.check_order("BTC-USDT", "buy", 2000, 50000, 10000)
    assert not ok
    assert "最大仓位" in reason


@pytest.mark.unit
def test_sell_requires_position():
    rm = RiskManager(RiskConfig(), initial_equity=10000)
    ok, reason = rm.check_order("BTC-USDT", "sell", 0, 50000, 10000)
    assert not ok
    assert "无持仓" in reason


@pytest.mark.unit
def test_add_and_remove_position():
    rm = RiskManager(RiskConfig(), initial_equity=10000)
    rm.add_position(PositionInfo("ETH-USDT", size=0.5, entry_price=3000))
    assert rm.has_position("ETH-USDT")
    rm.remove_position("ETH-USDT")
    assert not rm.has_position("ETH-USDT")


@pytest.mark.unit
def test_min_order_usdt_enforced():
    rm = RiskManager(RiskConfig(min_order_usdt=5.0), initial_equity=10000)
    ok, _ = rm.check_order("BTC-USDT", "buy", 1.0, 50000, 10000)
    assert not ok


@pytest.mark.unit
def test_halt_reason_property():
    rm = RiskManager(RiskConfig(max_drawdown_pct=0.1), initial_equity=10000)
    rm.update_equity(8000)
    assert rm.is_halted
    assert "最大回撤" in rm.halt_reason
