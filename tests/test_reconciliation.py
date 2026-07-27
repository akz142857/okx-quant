"""启动恢复和周期性对账测试。"""

import time
from decimal import Decimal

import pytest

from okx_quant.application.execution import ExecutionCoordinator, ExecutionRequest
from okx_quant.application.protection import ProtectionManager
from okx_quant.application.reconciliation import Reconciler, RecoveryGate
from okx_quant.domain.orders import OrderIntent, OrderState, SystemMode
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal


def _setup(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    journal = SQLiteJournal(tmp_path / "journal.db")
    return exchange, journal


@pytest.mark.unit
def test_recovery_resolves_lost_response_without_duplicate_order(tmp_path):
    exchange, journal = _setup(tmp_path)
    journal.set_mode(SystemMode.READY)
    exchange.queue_order_outcome(
        state="filled",
        fill_size=0.1,
        fill_price=50_000,
        lose_response=True,
    )
    coordinator = ExecutionCoordinator(exchange, journal)
    unknown = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    assert unknown.state is OrderState.UNKNOWN
    assert len(exchange.orders) == 1

    # 模拟交易所成交后余额已反映。
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
    )
    protection = ProtectionManager(exchange, journal)
    result = Reconciler(
        exchange, journal, protection_manager=protection
    ).run()
    assert result.safe
    resolved = journal.get_intent(unknown.intent_id)
    assert resolved.state is OrderState.FILLED
    assert journal.has_active_protection("BTC-USDT", Decimal("0.1"))
    assert len(exchange.orders) == 1


@pytest.mark.unit
def test_persisted_but_never_submitted_intent_is_safely_rejected(tmp_path):
    exchange, journal = _setup(tmp_path)
    intent = journal.create_order_intent(OrderIntent(
        intent_id="i1",
        cl_ord_id="QRECOVERYB01",
        inst_id="BTC-USDT",
        side="buy",
        requested_base_qty=Decimal("0.1"),
    ))
    assert intent.state is OrderState.PERSISTED

    result = Reconciler(exchange, journal).run()
    assert result.safe
    assert journal.get_intent("i1").state is OrderState.REJECTED
    assert not exchange.orders


@pytest.mark.unit
def test_external_pending_order_is_imported_and_degrades_system(tmp_path):
    exchange, journal = _setup(tmp_path)
    exchange.set_ticker("BTC-USDT", last=50_000, ask=50_010)
    exchange.queue_order_outcome(state="live")
    exchange.place_market_order(
        "BTC-USDT", "buy", 0.1, cl_ord_id="EXTERNALORDER01"
    )
    result = Reconciler(exchange, journal).run()
    assert not result.safe
    assert any("external_pending_order" in x for x in result.unresolved)
    assert journal.get_mode() is SystemMode.DEGRADED
    imported = journal.find_intent(cl_ord_id="EXTERNALORDER01")
    assert imported is not None
    assert imported.reserved_quote > 0

    second = Reconciler(exchange, journal).run()
    assert not second.safe
    assert any("external_pending_order" in x for x in second.unresolved)
    assert journal.get_mode() is SystemMode.DEGRADED


@pytest.mark.unit
def test_exchange_balance_repairs_local_projection_but_requires_protection(tmp_path):
    exchange, journal = _setup(tmp_path)
    exchange.set_holding("ETH", balance=2, available=1.5)
    exchange.set_ticker("ETH-USDT", last=3000)
    result = Reconciler(exchange, journal).run()
    assert not result.safe
    position = journal.get_position("ETH-USDT")
    assert Decimal(position["base_qty"]) == Decimal("2")
    assert Decimal(position["available_qty"]) == Decimal("1.5")
    assert "position_requires_protection:ETH-USDT" in result.unresolved


@pytest.mark.unit
def test_matching_position_without_protection_still_degrades(tmp_path):
    exchange, journal = _setup(tmp_path)
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    exchange.set_ticker("BTC-USDT", last=50_000)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.1"),
        available_qty=Decimal("0.1"),
        reference_price=Decimal("50000"),
        reason="fixture",
    )
    result = Reconciler(exchange, journal).run()
    assert not result.safe
    assert result.unresolved == ["position_requires_protection:BTC-USDT"]


@pytest.mark.unit
def test_startup_detects_corrupted_accounting_projection(tmp_path):
    exchange, journal = _setup(tmp_path)
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.1"),
        available_qty=Decimal("0.1"),
        reference_price=Decimal("50000"),
        reason="trusted checkpoint",
    )
    journal._conn.execute(
        """
        UPDATE positions
        SET avg_entry_px='1', realized_pnl='123'
        WHERE inst_id='BTC-USDT'
        """
    )

    result = Reconciler(exchange, journal).run(
        startup=True,
        reconcile_protections=False,
    )

    assert not result.safe
    assert result.unresolved == ["position_projection_drift:BTC-USDT"]
    assert journal.get_mode() is SystemMode.DEGRADED
    detail = next(
        item
        for item in result.details
        if item["type"] == "position_projection_verification"
    )
    assert detail["current"]["avg_entry_px"] == "1"
    assert detail["projected"]["avg_entry_px"] == "50000"


@pytest.mark.unit
def test_startup_cannot_launder_corruption_through_balance_checkpoint(
    tmp_path,
):
    exchange, journal = _setup(tmp_path)
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.1"),
        available_qty=Decimal("0.1"),
        reference_price=Decimal("50000"),
        reason="trusted checkpoint",
    )
    adjustment_count = journal._conn.execute(
        "SELECT COUNT(*) FROM reconciliation_adjustments"
    ).fetchone()[0]
    journal._conn.execute(
        """
        UPDATE positions
        SET base_qty='0.2', available_qty='0.2',
            avg_entry_px='1', realized_pnl='123'
        WHERE inst_id='BTC-USDT'
        """
    )

    result = Reconciler(exchange, journal).run(startup=True)

    assert not result.safe
    assert result.unresolved == ["position_projection_drift:BTC-USDT"]
    assert journal.get_mode() is SystemMode.DEGRADED
    assert journal._conn.execute(
        "SELECT COUNT(*) FROM reconciliation_adjustments"
    ).fetchone()[0] == adjustment_count
    position = journal.get_position("BTC-USDT")
    assert Decimal(position["base_qty"]) == Decimal("0.2")
    assert Decimal(position["avg_entry_px"]) == Decimal("1")
    assert Decimal(position["realized_pnl"]) == Decimal("123")


@pytest.mark.unit
def test_dust_balance_is_repaired_without_blocking_ready(tmp_path):
    exchange, journal = _setup(tmp_path)
    exchange.set_holding("DUST", balance=0.001, available=0.001)
    exchange.set_ticker(
        "DUST-USDT",
        last=0.1,
        bid=0.09,
        ask=0.11,
    )
    result = Reconciler(exchange, journal).run()
    assert result.safe
    assert journal.get_mode() is SystemMode.READY


@pytest.mark.unit
def test_stale_low_mark_cannot_hide_material_position_as_dust(tmp_path):
    exchange, journal = _setup(tmp_path)
    exchange.set_holding("BTC", balance=0.001, available=0.001)
    exchange.set_ticker(
        "BTC-USDT",
        last=100,
        bid=99,
        ask=101,
        timestamp=1,
    )
    result = Reconciler(exchange, journal).run(startup=True)
    assert not result.safe
    assert "position_requires_protection:BTC-USDT" in result.unresolved
    position = journal.get_position("BTC-USDT")
    assert position is not None
    mismatch = next(
        detail
        for detail in result.details
        if detail["type"] == "balance_mismatch"
    )
    assert mismatch["dust"] is False


@pytest.mark.unit
def test_startup_fails_closed_when_balance_unavailable(tmp_path):
    class BrokenExchange(FakeExchange):
        def get_balance(self):  # type: ignore[override]
            raise RuntimeError("network down")

    journal = SQLiteJournal(tmp_path / "journal.db")
    with pytest.raises(RuntimeError, match="network down"):
        RecoveryGate(Reconciler(BrokenExchange(), journal)).recover()
    assert journal.get_mode() is SystemMode.HALTED


@pytest.mark.unit
def test_old_unresolvable_unknown_moves_to_manual_review(tmp_path):
    exchange, journal = _setup(tmp_path)
    intent = journal.create_order_intent(OrderIntent(
        intent_id="i-old",
        cl_ord_id="QUNKNOWNB01",
        inst_id="BTC-USDT",
        side="buy",
        requested_base_qty=Decimal("0.1"),
    ))
    intent = journal.update_intent(intent, OrderState.SUBMITTING)
    intent = journal.update_intent(intent, OrderState.UNKNOWN)
    # 直接把更新时间改旧以构造超时恢复。
    journal._conn.execute(
        "UPDATE order_intents SET updated_at=? WHERE intent_id=?",
        (time.time() - 1000, intent.intent_id),
    )
    result = Reconciler(
        exchange, journal, unknown_manual_after_s=10
    ).run()
    assert not result.safe
    assert journal.get_intent(intent.intent_id).state is OrderState.MANUAL_REVIEW
    assert journal.active_reserved_instruments() == {"BTC-USDT"}
    pages = [
        row
        for row in journal.get_unpublished_outbox()
        if row["event_name"] == "page.order_unknown_deadline"
    ]
    assert len(pages) == 1

    second = Reconciler(
        exchange, journal, unknown_manual_after_s=10
    ).run()
    assert not second.safe
    assert f"manual_review:{intent.intent_id}" in second.unresolved
    assert journal.get_mode() is SystemMode.DEGRADED
    assert journal.active_reserved_instruments() == {"BTC-USDT"}
    assert len([
        row
        for row in journal.get_unpublished_outbox()
        if row["event_name"] == "page.order_unknown_deadline"
    ]) == 1


@pytest.mark.unit
def test_external_terminal_fill_is_imported_and_flagged(tmp_path):
    exchange, journal = _setup(tmp_path)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
    )
    exchange.set_holding("BTC", balance=0.01, available=0.01)
    exchange.place_market_order(
        "BTC-USDT",
        "buy",
        0.01,
        cl_ord_id="QEXTERNALFILLB01",
    )
    protection = ProtectionManager(exchange, journal)
    result = Reconciler(
        exchange, journal, protection_manager=protection
    ).run()
    assert not result.safe
    assert any(item.startswith("external_fill:") for item in result.unresolved)
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("0.01")
    assert journal.has_active_protection("BTC-USDT", Decimal("0.01"))
