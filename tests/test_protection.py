"""交易所保护单和主动退出竞争的故障测试。"""

import threading
import time
from decimal import Decimal

import pytest
import requests

from okx_quant.application.execution import ExecutionCoordinator, ExecutionRequest
from okx_quant.application.protection import ExitCoordinator, ProtectionManager
from okx_quant.domain.orders import (
    ExchangeOrder,
    OrderState,
    ProtectionOrder,
    ProtectionState,
    SystemMode,
)
from okx_quant.exchange import InstrumentInfo
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal


def _stack(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=50_000)
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    execution = ExecutionCoordinator(exchange, journal)
    protection = ProtectionManager(exchange, journal)
    protection.attach_to(execution)
    return exchange, journal, execution, protection


@pytest.mark.unit
def test_fill_creates_exchange_oco_using_actual_quantity(tmp_path):
    exchange, journal, execution, _ = _stack(tmp_path)
    exchange.queue_order_outcome(
        state="partially_filled", fill_size=Decimal("0.04"), fill_price=50_000
    )
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
        stop_loss=Decimal("49000"),
        take_profit=Decimal("52000"),
    ))
    protection = journal.list_protections("BTC-USDT")[0]
    assert protection.state is ProtectionState.ACTIVE
    assert protection.protected_qty == Decimal("0.04")
    assert protection.trigger_px == Decimal("49000")


@pytest.mark.unit
def test_later_partial_fill_amends_quantity_and_only_tightens_stop(tmp_path):
    exchange, journal, execution, manager = _stack(tmp_path)
    exchange.queue_order_outcome(
        state="partially_filled", fill_size=0.04, fill_price=50_000
    )
    intent = execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
        stop_loss=Decimal("49000"),
        take_profit=Decimal("52000"),
    ))
    execution.process_exchange_update(ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.FILLED,
        ord_id=intent.exchange_ord_id,
        cl_ord_id=intent.cl_ord_id,
        requested_qty=Decimal("0.1"),
        acc_fill_qty=Decimal("0.1"),
        avg_fill_px=Decimal("50000"),
        trade_id="trade-second",
    ))
    amended = journal.list_protections("BTC-USDT", active_only=True)[0]
    assert amended.protected_qty == Decimal("0.1")
    assert amended.trigger_px == Decimal("49000")

    # 新计算值更低时不能放松已有止损。
    same = manager.ensure_for_position(
        "BTC-USDT",
        Decimal("0.1"),
        reference_price=Decimal("50000"),
        stop_loss=Decimal("48000"),
        take_profit=Decimal("52000"),
    )
    assert same.trigger_px == Decimal("49000")


@pytest.mark.unit
def test_lost_algo_response_resolves_by_client_id_without_emergency(tmp_path):
    exchange, journal, execution, _ = _stack(tmp_path)
    exchange.queue_algo_outcome(lose_response=True)
    intent = execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    assert intent.state is OrderState.FILLED
    assert journal.has_active_protection("BTC-USDT", Decimal("0.1"))
    assert journal.get_mode() is SystemMode.READY
    assert len(exchange.get_pending_algo_orders()) == 1


@pytest.mark.unit
@pytest.mark.parametrize("status_code", [408, 502])
def test_algo_http_5xx_after_acceptance_resolves_without_duplicate_sell(
    tmp_path,
    monkeypatch,
    status_code,
):
    exchange, journal, execution, _ = _stack(tmp_path)
    original = exchange.place_protection_order
    response = requests.Response()
    response.status_code = status_code

    def accepted_then_502(*args, **kwargs):
        original(*args, **kwargs)
        raise requests.HTTPError("bad gateway", response=response)

    monkeypatch.setattr(exchange, "place_protection_order", accepted_then_502)
    intent = execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    assert intent.state is OrderState.FILLED
    assert journal.has_active_protection("BTC-USDT", Decimal("0.1"))
    assert [order.side for order in exchange.orders] == ["buy"]


@pytest.mark.unit
def test_lost_algo_response_waits_for_eventual_query_visibility(tmp_path):
    exchange, journal, execution, _ = _stack(tmp_path)
    exchange.queue_algo_outcome(lose_response=True)
    original = exchange.get_algo_order
    attempts = 0

    def eventually_visible(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise KeyError("not visible yet")
        return original(*args, **kwargs)

    exchange.get_algo_order = eventually_visible
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    assert attempts == 3
    assert journal.has_active_protection("BTC-USDT", Decimal("0.1"))
    assert [order.side for order in exchange.orders] == ["buy"]


@pytest.mark.unit
def test_definitive_algo_rejection_enters_emergency_and_pages(tmp_path):
    exchange, journal, execution, _ = _stack(tmp_path)
    exchange.queue_algo_outcome(reject=True)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    protection = journal.list_protections("BTC-USDT")[0]
    assert protection.state is ProtectionState.EMERGENCY_EXIT
    assert journal.get_unpublished_outbox()[0]["event_name"] == (
        "page.position_unprotected"
    )
    assert [order.side for order in exchange.orders] == ["buy", "sell"]
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == 0


@pytest.mark.unit
def test_invalid_protection_prices_trigger_immediate_emergency_exit(tmp_path):
    exchange, journal, execution, _ = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
        stop_loss=Decimal("51000"),
    ))
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert [order.side for order in exchange.orders] == ["buy", "sell"]
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == 0


@pytest.mark.unit
def test_triggered_protection_wins_against_local_exit(tmp_path):
    exchange, journal, execution, protection = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    local = journal.list_protections("BTC-USDT", active_only=True)[0]
    exchange.trigger_algo_order(local.exchange_algo_id, actual_order_id="protect-sell")
    exchange.set_holding("BTC", balance=0.1, available=0)

    exit_coordinator = ExitCoordinator(exchange, journal, execution, protection)
    assert exit_coordinator.exit_position("BTC-USDT", "strategy") is None
    assert len(exchange.orders) == 1  # 仅有原始 BUY，没有重复 SELL
    assert journal.find_protection(
        protection_id=local.protection_id
    ).state is ProtectionState.TRIGGERED
    # exit lease 过期或再次点击也不能绕过历史 TRIGGERED 事实。
    journal._conn.execute(
        "UPDATE exit_leases SET expires_at=0 WHERE inst_id='BTC-USDT'"
    )
    assert exit_coordinator.exit_position("BTC-USDT", "retry") is None
    assert len(exchange.orders) == 1


@pytest.mark.unit
def test_amend_rejection_cancels_old_algo_and_exits_full_durable_qty(tmp_path):
    exchange, journal, execution, manager = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.04"),
    ))
    original = journal.list_protections("BTC-USDT", active_only=True)[0]
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.1"),
        available_qty=Decimal("0.1"),
        reference_price=Decimal("50000"),
        reason="later_partial_fill_fixture",
    )
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    exchange.queue_algo_amend_outcome(reject=True)

    manager.ensure_for_position(
        "BTC-USDT",
        Decimal("0.1"),
        reference_price=Decimal("50000"),
        stop_loss=Decimal("49500"),
    )

    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == 0
    assert [order.side for order in exchange.orders] == ["buy", "sell"]
    assert exchange.get_algo_order(
        algo_id=original.exchange_algo_id
    ).state is ProtectionState.CANCELED


@pytest.mark.unit
def test_active_protection_is_canceled_before_single_market_exit(tmp_path):
    exchange, journal, execution, protection = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    exit_coordinator = ExitCoordinator(exchange, journal, execution, protection)
    sold = exit_coordinator.exit_position("BTC-USDT", "strategy")
    assert sold is not None and sold.state is OrderState.FILLED
    assert [order.side for order in exchange.orders] == ["buy", "sell"]
    assert exit_coordinator.exit_position("BTC-USDT", "duplicate") is None
    assert [order.side for order in exchange.orders] == ["buy", "sell"]


@pytest.mark.unit
@pytest.mark.parametrize("exit_state", ["rejected", "canceled", "live"])
def test_exit_nonfilled_latches_emergency_before_return(
    tmp_path,
    exit_state,
):
    exchange, journal, execution, protection = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    exchange.queue_order_outcome(state=exit_state)
    coordinator = ExitCoordinator(
        exchange,
        journal,
        execution,
        protection,
    )
    intent = coordinator.exit_position("BTC-USDT", "fixture")
    assert intent is not None
    assert intent.state is not OrderState.FILLED
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert any(
        row["event_name"] == "page.exit_not_filled"
        for row in journal.get_unpublished_outbox()
    )
    assert not journal.has_active_protection(
        "BTC-USDT",
        Decimal("0.1"),
    )


@pytest.mark.unit
def test_protection_and_exit_use_instrument_tick_and_lot_grid(tmp_path):
    exchange, journal, execution, protection = _stack(tmp_path)
    exchange.set_instrument(InstrumentInfo(
        inst_id="BTC-USDT",
        base_ccy="BTC",
        quote_ccy="USDT",
        lot_size=0.001,
        min_size=0.001,
        tick_size=0.1,
    ))
    exchange.set_ticker(
        "BTC-USDT",
        last=50_123.4,
        bid=50_123.3,
        ask=50_123.5,
    )
    original_protection = exchange.place_protection_order

    def strict_protection(inst_id, *, size, stop_loss, take_profit, **kwargs):
        assert Decimal(str(size)) % Decimal("0.001") == 0
        assert Decimal(str(stop_loss)) % Decimal("0.1") == 0
        assert Decimal(str(take_profit)) % Decimal("0.1") == 0
        return original_protection(
            inst_id,
            size=size,
            stop_loss=stop_loss,
            take_profit=take_profit,
            **kwargs,
        )

    exchange.place_protection_order = strict_protection
    exchange.queue_order_outcome(
        state="filled",
        fill_size=0.1,
        fill_price=50_123.4,
    )
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    active = journal.list_protections("BTC-USDT", active_only=True)[0]
    assert active.protected_qty == Decimal("0.1")
    assert active.trigger_px == Decimal("49120.9")
    assert active.take_profit_px == Decimal("52128.4")

    exchange.set_holding("BTC", balance=0.1, available=0.1)
    original_order = exchange.place_market_order

    def strict_sell(inst_id, side, size, **kwargs):
        if side == "sell":
            assert Decimal(str(size)) % Decimal("0.001") == 0
        return original_order(inst_id, side, size, **kwargs)

    exchange.place_market_order = strict_sell
    sold = ExitCoordinator(
        exchange,
        journal,
        execution,
        protection,
    ).exit_position("BTC-USDT", "fixture")
    assert sold is not None and sold.state is OrderState.FILLED


@pytest.mark.unit
def test_material_base_fee_remainder_fails_closed_and_exits_tradable_qty(
    tmp_path,
):
    exchange, journal, execution, _ = _stack(tmp_path)
    exchange.set_instrument(InstrumentInfo(
        inst_id="BTC-USDT",
        base_ccy="BTC",
        quote_ccy="USDT",
        lot_size=0.001,
        min_size=0.001,
        tick_size=0.1,
    ))
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
    )
    exchange.queue_order_outcome(
        state="filled",
        fill_size=0.1,
        fill_price=50_000,
        fee=-0.0001,
        fee_ccy="BTC",
    )
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert [order.side for order in exchange.orders] == ["buy", "sell"]
    assert Decimal(str(exchange.orders[-1].size)) == Decimal("0.099")
    assert Decimal(
        journal.get_position("BTC-USDT")["base_qty"]
    ) == Decimal("0.0009")


@pytest.mark.unit
def test_exit_latches_emergency_when_price_makes_remainder_material(
    tmp_path,
):
    exchange, journal, execution, protection = _stack(tmp_path)
    exchange.set_instrument(InstrumentInfo(
        inst_id="ABC-USDT",
        base_ccy="ABC",
        quote_ccy="USDT",
        lot_size=0.001,
        min_size=0.001,
        tick_size=0.1,
    ))
    exchange.set_ticker(
        "ABC-USDT",
        last=100,
        bid=99.9,
        ask=100.1,
    )
    exchange.queue_order_outcome(
        state="filled",
        fill_size=0.1,
        fill_price=100,
        fee=-0.0001,
        fee_ccy="ABC",
    )
    execution.submit(ExecutionRequest(
        inst_id="ABC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    assert journal.get_mode() is SystemMode.READY
    assert journal.list_protections("ABC-USDT", active_only=True)[
        0
    ].protected_qty == Decimal("0.099")

    exchange.set_ticker(
        "ABC-USDT",
        last=2000,
        bid=1999,
        ask=2001,
    )
    exchange.set_holding(
        "ABC",
        balance=0.0999,
        available=0.0999,
    )
    sold = ExitCoordinator(
        exchange,
        journal,
        execution,
        protection,
    ).exit_position("ABC-USDT", "fixture")
    assert sold is not None and sold.state is OrderState.FILLED
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert Decimal(
        journal.get_position("ABC-USDT")["base_qty"]
    ) == Decimal("0.0009")
    assert any(
        row["event_name"]
        == "page.exit_material_nontradable_remainder"
        for row in journal.get_unpublished_outbox()
    )


@pytest.mark.unit
def test_filled_label_with_short_fill_fails_exit_postcondition(tmp_path):
    exchange, journal, execution, protection = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    exchange.queue_order_outcome(
        state="filled",
        fill_size=0.05,
        fill_price=50_000,
    )
    intent = ExitCoordinator(
        exchange,
        journal,
        execution,
        protection,
    ).exit_position("BTC-USDT", "fixture")
    assert intent is not None and intent.state is OrderState.FILLED
    assert intent.acc_fill_qty == Decimal("0.05")
    assert Decimal(
        journal.get_position("BTC-USDT")["base_qty"]
    ) == Decimal("0.05")
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert any(
        row["event_name"] == "page.exit_postcondition_failed"
        for row in journal.get_unpublished_outbox()
    )


@pytest.mark.unit
def test_algo_trigger_during_cancel_blocks_duplicate_market_sell(
    tmp_path,
    monkeypatch,
):
    exchange, journal, execution, protection = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    local = journal.list_protections("BTC-USDT", active_only=True)[0]
    exchange.set_holding("BTC", balance=0.1, available=0.1)

    def trigger_instead_of_cancel(inst_id, algo_id):
        exchange.queue_order_outcome(state="live")
        actual = exchange.place_market_order(
            inst_id,
            "sell",
            0.1,
            cl_ord_id="QPROTECTIONTRIGGER01",
        )
        exchange.trigger_algo_order(algo_id, actual_order_id=actual.ord_id)
        return exchange.get_algo_order(algo_id=algo_id)

    monkeypatch.setattr(exchange, "cancel_algo_order", trigger_instead_of_cancel)
    exit_coordinator = ExitCoordinator(
        exchange, journal, execution, protection
    )
    linked = exit_coordinator.exit_position("BTC-USDT", "fixture")
    assert linked is not None and linked.state is OrderState.LIVE
    assert [order.side for order in exchange.orders] == ["buy", "sell"]
    assert (
        exchange.get_algo_order(algo_id=local.exchange_algo_id).state
        is ProtectionState.TRIGGERED
    )


@pytest.mark.unit
def test_partial_sell_shrinks_protection_to_exact_durable_position(tmp_path):
    exchange, journal, execution, _ = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="sell", base_qty=Decimal("0.04")
    ))
    active = journal.list_protections("BTC-USDT", active_only=True)[0]
    assert active.protected_qty == Decimal("0.06")
    assert journal.has_active_protection("BTC-USDT", Decimal("0.06"))
    assert not journal.has_active_protection("BTC-USDT", Decimal("0.05"))


@pytest.mark.unit
def test_late_base_fee_correction_resizes_active_protection(tmp_path):
    exchange, journal, execution, _ = _stack(tmp_path)
    intent = execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    execution.process_exchange_update(ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.FILLED,
        ord_id=intent.exchange_ord_id,
        cl_ord_id=intent.cl_ord_id,
        requested_qty=Decimal("0.1"),
        acc_fill_qty=Decimal("0.1"),
        avg_fill_px=Decimal("50000"),
        fee=Decimal("-0.0001"),
        fee_ccy="BTC",
        trade_id="late-fee",
    ))
    assert Decimal(
        journal.get_position("BTC-USDT")["base_qty"]
    ) == Decimal("0.0999")
    assert journal.has_active_protection(
        "BTC-USDT", Decimal("0.0999")
    )


@pytest.mark.unit
def test_reconcile_cancels_orphan_exchange_protection(tmp_path):
    exchange, journal, _, manager = _stack(tmp_path)
    remote = exchange.place_protection_order(
        "BTC-USDT",
        size=0.1,
        stop_loss=49_000,
        take_profit=52_000,
        algo_cl_ord_id="QORPHANPROTECTIONS01",
    )
    assert manager.reconcile() == []
    assert exchange.get_algo_order(
        algo_id=remote.algo_id
    ).state is ProtectionState.CANCELED
    assert journal.list_protections() == []


@pytest.mark.unit
def test_reconcile_recovers_algo_ack_before_local_db_update(tmp_path):
    exchange, journal, _, manager = _stack(tmp_path)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.1"),
        reference_price=Decimal("50000"),
        reason="fixture",
    )
    local = ProtectionOrder(
        protection_id="p-crash",
        inst_id="BTC-USDT",
        kind="oco",
        protected_qty=Decimal("0.1"),
        trigger_px=Decimal("49000"),
        take_profit_px=Decimal("52000"),
        algo_cl_ord_id="QRECOVERALGOACK01",
    )
    local = journal.create_protection(local)
    local = journal.update_protection(
        local, state=ProtectionState.SUBMITTING
    )
    remote = exchange.place_protection_order(
        "BTC-USDT",
        size=0.1,
        stop_loss=49_000,
        take_profit=52_000,
        algo_cl_ord_id=local.algo_cl_ord_id,
    )
    assert manager.reconcile() == []
    recovered = journal.find_protection(protection_id=local.protection_id)
    assert recovered.state is ProtectionState.ACTIVE
    assert recovered.exchange_algo_id == remote.algo_id
    assert len(exchange.get_pending_algo_orders()) == 1


@pytest.mark.unit
def test_duplicate_active_protection_remains_unresolved_across_reconciles(
    tmp_path,
):
    exchange, journal, execution, manager = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    exchange.place_protection_order(
        "BTC-USDT",
        size=0.1,
        stop_loss=49_000,
        take_profit=52_000,
        algo_cl_ord_id="QDUPLICATEPROTECT01",
    )
    first = manager.reconcile()
    second = manager.reconcile()
    assert any("multiple_remote_protections" in item for item in first)
    assert any("multiple_remote_protections" in item for item in second)
    assert not journal.has_active_protection(
        "BTC-USDT", Decimal("0.1")
    )


@pytest.mark.unit
def test_amend_response_loss_resolves_without_duplicate_protection(tmp_path):
    exchange, journal, execution, manager = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    original = journal.list_protections("BTC-USDT", active_only=True)[0]
    exchange.queue_algo_amend_outcome(lose_response=True)
    amended = manager.ensure_for_position(
        "BTC-USDT",
        Decimal("0.2"),
        reference_price=Decimal("50000"),
        stop_loss=Decimal("49500"),
        take_profit=Decimal("52000"),
    )
    assert amended.state is ProtectionState.ACTIVE
    assert amended.protected_qty == Decimal("0.2")
    assert amended.trigger_px == Decimal("49500")
    assert amended.exchange_algo_id == original.exchange_algo_id
    assert len(exchange.get_pending_algo_orders()) == 1


@pytest.mark.unit
def test_cancel_response_loss_is_resolved_before_exit(tmp_path):
    exchange, journal, execution, manager = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    exchange.queue_algo_cancel_outcome(lose_response=True)
    assert manager.cancel_all("BTC-USDT")
    assert journal.list_protections("BTC-USDT", active_only=True) == []


@pytest.mark.unit
def test_exit_does_not_sell_when_balance_remains_frozen(tmp_path):
    exchange, journal, execution, manager = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    exchange.set_holding("BTC", balance=0.1, available=0)
    exit_coordinator = ExitCoordinator(
        exchange,
        journal,
        execution,
        manager,
        balance_release_timeout_s=0.01,
    )
    with pytest.raises(RuntimeError, match="余额仍未释放"):
        exit_coordinator.exit_position("BTC-USDT", "fixture")
    assert [order.side for order in exchange.orders] == ["buy"]
    assert journal.get_mode() is SystemMode.DEGRADED


@pytest.mark.unit
def test_exit_deadline_pages_while_cancel_call_is_blocked(tmp_path, monkeypatch):
    exchange, journal, execution, manager = _stack(tmp_path)
    execution.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
    ))
    cancel_entered = threading.Event()
    cancel_release = threading.Event()
    original_cancel_all = manager.cancel_all

    def blocked_cancel_all(inst_id):
        cancel_entered.set()
        cancel_release.wait(timeout=1)
        return original_cancel_all(inst_id)

    monkeypatch.setattr(manager, "cancel_all", blocked_cancel_all)
    exit_coordinator = ExitCoordinator(
        exchange,
        journal,
        execution,
        manager,
        balance_release_timeout_s=0.02,
    )
    outcome = []

    def run_exit():
        try:
            outcome.append(
                exit_coordinator.exit_position("BTC-USDT", "deadline fixture")
            )
        except Exception as exc:  # noqa: BLE001
            outcome.append(exc)

    worker = threading.Thread(target=run_exit)
    worker.start()
    assert cancel_entered.wait(timeout=1)
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if any(
            row["event_name"] == "page.exit_workflow_deadline"
            for row in journal.get_unpublished_outbox()
        ):
            break
        time.sleep(0.01)
    assert any(
        row["event_name"] == "page.exit_workflow_deadline"
        for row in journal.get_unpublished_outbox()
    )
    assert worker.is_alive()
    cancel_release.set()
    worker.join(timeout=1)
    assert not worker.is_alive()
