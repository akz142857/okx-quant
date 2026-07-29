"""SQLite WAL 生产订单日志测试。"""

import sqlite3
import time
from decimal import Decimal

import pytest

from okx_quant.domain.orders import (
    ExchangeOrder,
    IntentRiskGuard,
    OrderIntent,
    OrderState,
    SystemMode,
)
from okx_quant.infrastructure.db import JournalRepository, SQLiteJournal


def _journal(tmp_path) -> SQLiteJournal:
    return SQLiteJournal(tmp_path / "journal.db")


def _intent() -> OrderIntent:
    return OrderIntent(
        intent_id="intent-1",
        cl_ord_id="QTESTB01",
        inst_id="BTC-USDT",
        side="buy",
        requested_base_qty=Decimal("0.1"),
        reserved_quote=Decimal("5000"),
    )


@pytest.mark.unit
def test_buy_guard_rechecks_snapshot_inside_intent_transaction(tmp_path):
    journal = _journal(tmp_path)
    journal.set_mode(SystemMode.READY)
    first_id = journal.record_account_snapshot(
        total_equity_quote=Decimal("1000"),
        available_quote=Decimal("1000"),
        holdings=[],
        source="fixture",
    )
    _, epoch = journal.get_mode_state()
    guard = IntentRiskGuard(
        mode_epoch=epoch,
        snapshot_id=first_id,
        max_snapshot_age_s=90,
        max_open_positions=3,
        max_order_intents_per_hour=20,
    )
    journal.record_account_snapshot(
        total_equity_quote=Decimal("1000"),
        available_quote=Decimal("0"),
        holdings=[],
        source="newer-fixture",
    )
    with pytest.raises(RuntimeError, match="快照版本已变化"):
        journal.create_order_intent(_intent(), risk_guard=guard)
    assert journal.get_intent("intent-1") is None
    assert journal.active_reserved_quote() == 0


@pytest.mark.unit
def test_journal_uses_wal_full_sync_and_integrity(tmp_path):
    journal = _journal(tmp_path)
    assert isinstance(journal, JournalRepository)
    assert journal.integrity_check()
    assert journal._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert journal._conn.execute("PRAGMA synchronous").fetchone()[0] == 2


@pytest.mark.unit
def test_intent_is_persisted_before_submission(tmp_path):
    journal = _journal(tmp_path)
    persisted = journal.create_order_intent(_intent())
    assert persisted.state is OrderState.PERSISTED
    assert journal.get_intent("intent-1") == persisted


@pytest.mark.unit
def test_cl_ord_id_is_permanently_unique(tmp_path):
    journal = _journal(tmp_path)
    journal.create_order_intent(_intent())
    duplicate = OrderIntent(
        intent_id="intent-2",
        cl_ord_id="QTESTB01",
        inst_id="ETH-USDT",
        side="buy",
        requested_base_qty=Decimal("1"),
    )
    with pytest.raises(sqlite3.IntegrityError):
        journal.create_order_intent(duplicate)


@pytest.mark.unit
def test_cumulative_fills_project_position_once(tmp_path):
    journal = _journal(tmp_path)
    intent = journal.create_order_intent(_intent())
    intent = journal.update_intent(intent, OrderState.SUBMITTING)

    first = ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.PARTIALLY_FILLED,
        ord_id="o1",
        cl_ord_id=intent.cl_ord_id,
        acc_fill_qty=Decimal("0.04"),
        avg_fill_px=Decimal("50000"),
        trade_id="t1",
    )
    updated, delta = journal.apply_exchange_order(first)
    assert delta == Decimal("0.04")
    assert updated.state is OrderState.PARTIALLY_FILLED

    final = ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.FILLED,
        ord_id="o1",
        cl_ord_id=intent.cl_ord_id,
        acc_fill_qty=Decimal("0.1"),
        avg_fill_px=Decimal("50100"),
        trade_id="t2",
    )
    updated, delta = journal.apply_exchange_order(final)
    assert delta == Decimal("0.06")
    assert updated.state is OrderState.FILLED
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("0.1")
    assert Decimal(journal.get_position("BTC-USDT")["avg_entry_px"]) == Decimal("50100")

    # 重复终态消息不会重复记仓。
    _, delta = journal.apply_exchange_order(final)
    assert delta == 0
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("0.1")


@pytest.mark.unit
def test_position_projection_rebuild_uses_complete_event_ledger(tmp_path):
    journal = _journal(tmp_path)
    intent = journal.create_order_intent(_intent())
    intent = journal.update_intent(intent, OrderState.SUBMITTING)
    journal.apply_exchange_order(
        ExchangeOrder(
            inst_id="BTC-USDT",
            side="buy",
            state=OrderState.FILLED,
            ord_id="o-rebuild",
            cl_ord_id=intent.cl_ord_id,
            acc_fill_qty=Decimal("0.1"),
            avg_fill_px=Decimal("50100"),
            trade_id="t-rebuild",
        )
    )
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.09"),
        available_qty=Decimal("0.08"),
        reference_price=Decimal("50000"),
        reason="exchange checkpoint",
    )
    healthy = journal.rebuild_position_projection("BTC-USDT")
    assert healthy["complete"]
    assert healthy["positions"][0]["matches"]

    journal._conn.execute(
        """
        UPDATE positions
        SET base_qty='999', available_qty='999',
            avg_entry_px='1', realized_pnl='123'
        WHERE inst_id='BTC-USDT'
        """
    )
    drift = journal.rebuild_position_projection("BTC-USDT")
    assert not drift["positions"][0]["matches"]
    with pytest.raises(RuntimeError, match="MAINTENANCE/HALTED"):
        journal.rebuild_position_projection("BTC-USDT", apply=True)

    journal.set_mode(SystemMode.MAINTENANCE)
    repaired = journal.rebuild_position_projection("BTC-USDT", apply=True)
    assert repaired["applied"]
    position = journal.get_position("BTC-USDT")
    assert Decimal(position["base_qty"]) == Decimal("0.09")
    assert Decimal(position["available_qty"]) == Decimal("0.08")
    assert Decimal(position["avg_entry_px"]) == Decimal("50100")
    assert Decimal(position["realized_pnl"]) == 0


@pytest.mark.unit
def test_projection_rebuild_refuses_incomplete_legacy_adjustment(tmp_path):
    journal = _journal(tmp_path)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.1"),
        reference_price=Decimal("50000"),
        reason="legacy fixture",
    )
    journal._conn.execute(
        "UPDATE reconciliation_adjustments SET snapshot_complete=0"
    )
    report = journal.rebuild_position_projection("BTC-USDT")
    assert not report["complete"]
    journal.set_mode(SystemMode.MAINTENANCE)
    with pytest.raises(RuntimeError, match="历史事件不足"):
        journal.rebuild_position_projection("BTC-USDT", apply=True)


@pytest.mark.unit
def test_order_fill_and_position_projection_roll_back_atomically(tmp_path, monkeypatch):
    journal = _journal(tmp_path)
    intent = journal.create_order_intent(_intent())
    intent = journal.update_intent(intent, OrderState.SUBMITTING)
    order = ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.FILLED,
        ord_id="o-atomic",
        cl_ord_id=intent.cl_ord_id,
        acc_fill_qty=Decimal("0.1"),
        avg_fill_px=Decimal("50000"),
    )

    def crash_before_projection(_conn, _fill):
        raise RuntimeError("simulated process boundary")

    monkeypatch.setattr(
        journal, "_insert_fill_and_project_conn", crash_before_projection
    )
    with pytest.raises(RuntimeError, match="process boundary"):
        journal.apply_exchange_order(order)
    persisted = journal.get_intent(intent.intent_id)
    assert persisted.state is OrderState.SUBMITTING
    assert persisted.acc_fill_qty == 0
    assert journal.get_position("BTC-USDT") is None


@pytest.mark.unit
def test_out_of_order_fill_cannot_reduce_accumulated_size(tmp_path):
    journal = _journal(tmp_path)
    intent = journal.create_order_intent(_intent())
    intent = journal.update_intent(intent, OrderState.SUBMITTING)
    newest = ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.PARTIALLY_FILLED,
        ord_id="o1",
        cl_ord_id=intent.cl_ord_id,
        acc_fill_qty=Decimal("0.08"),
        avg_fill_px=Decimal("50000"),
        trade_id="t-new",
    )
    journal.apply_exchange_order(newest)
    stale = ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.PARTIALLY_FILLED,
        ord_id="o1",
        cl_ord_id=intent.cl_ord_id,
        acc_fill_qty=Decimal("0.02"),
        avg_fill_px=Decimal("49000"),
        trade_id="t-old",
    )
    current, delta = journal.apply_exchange_order(stale)
    assert delta == 0
    assert current.acc_fill_qty == Decimal("0.08")


@pytest.mark.unit
def test_exit_lease_is_exclusive_and_explicitly_released(tmp_path):
    journal = _journal(tmp_path)
    assert journal.acquire_exit_lease("BTC-USDT", "owner-1")
    assert not journal.acquire_exit_lease("BTC-USDT", "owner-2")
    journal.release_exit_lease("BTC-USDT", "owner-1")
    assert journal.acquire_exit_lease("BTC-USDT", "owner-2")


@pytest.mark.unit
def test_outbox_deduplication_key_is_durable(tmp_path):
    journal = _journal(tmp_path)
    first = journal.enqueue_outbox_once(
        "unknown:intent-1",
        "page.order_unknown",
        {"attempt": 1},
    )
    second = journal.enqueue_outbox_once(
        "unknown:intent-1",
        "page.order_unknown",
        {"attempt": 2},
    )
    assert first == second
    rows = journal.get_unpublished_outbox()
    assert len(rows) == 1
    assert rows[0]["event_name"] == "page.order_unknown"
    journal.close()


@pytest.mark.unit
def test_alert_delivery_tracks_attempt_provider_ack_and_escalation(tmp_path):
    journal = _journal(tmp_path)
    event_id = journal.enqueue_outbox(
        "page.unprotected_position",
        {"inst_id": "BTC-USDT"},
    )
    event = journal.get_due_alerts()[0]
    assert event["event_id"] == event_id
    assert event["priority"] == "P0"
    created = float(event["created_at"])
    retried = journal.record_alert_attempt(
        event_id,
        started_at=created,
        completed_at=created + 1,
        http_status=503,
        ingestion_accepted=False,
        error="provider unavailable",
    )
    assert retried["state"] == "retry"
    assert retried["attempt_count"] == 1
    ingested = journal.record_alert_attempt(
        event_id,
        started_at=retried["next_attempt_at"],
        completed_at=retried["next_attempt_at"] + 1,
        http_status=202,
        ingestion_accepted=True,
    )
    assert ingested["state"] == "ingested"
    assert journal.get_unpublished_outbox() == []
    provider_at = max(
        float(ingested["created_at"]) + 2,
        time.time() - 1,
    )
    provider = journal.record_alert_provider_received(
        event_id,
        provider_received_at=provider_at,
        provider_event_id="provider-1",
        artifact_sha256="a" * 64,
    )
    assert provider["state"] == "provider_received"
    acknowledged = journal.record_alert_human_ack(
        event_id,
        human_ack_at=provider_at + 0.1,
        actor="on-call",
        artifact_sha256="b" * 64,
    )
    assert acknowledged["state"] == "acknowledged"
    with pytest.raises(RuntimeError, match="不得标记"):
        journal.record_alert_escalation(event_id)
    journal.close()


@pytest.mark.unit
def test_alert_delivery_moves_to_dlq_after_bounded_attempts(tmp_path):
    journal = _journal(tmp_path)
    event_id = journal.enqueue_outbox("warning.ws_disconnect", {})
    created = journal.get_due_alerts()[0]["created_at"]
    first = journal.record_alert_attempt(
        event_id,
        started_at=created,
        completed_at=created + 1,
        http_status=None,
        ingestion_accepted=False,
        error="timeout",
        max_attempts=2,
    )
    second = journal.record_alert_attempt(
        event_id,
        started_at=first["next_attempt_at"],
        completed_at=first["next_attempt_at"] + 1,
        http_status=None,
        ingestion_accepted=False,
        error="timeout",
        max_attempts=2,
    )
    assert second["state"] == "dlq"
    assert second["dlq_at"] is not None
    assert journal.get_due_alerts(now=second["updated_at"] + 1000) == []
    journal.close()


@pytest.mark.unit
def test_online_backup_is_consistent(tmp_path):
    journal = _journal(tmp_path)
    journal.create_order_intent(_intent())
    backup_path = tmp_path / "backup.db"
    journal.backup(backup_path)
    backup = SQLiteJournal(backup_path)
    assert backup.integrity_check()
    assert backup.get_intent("intent-1") is not None


@pytest.mark.unit
def test_forward_migration_creates_pre_migration_online_backup(tmp_path):
    path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(path)
    legacy.executescript(
        """
        CREATE TABLE schema_migrations(
            version INTEGER PRIMARY KEY,
            applied_at REAL NOT NULL
        );
        INSERT INTO schema_migrations(version, applied_at) VALUES(1, 1);
        CREATE TABLE legacy_marker(value TEXT);
        INSERT INTO legacy_marker(value) VALUES('preserved');
        """
    )
    legacy.close()
    journal = SQLiteJournal(path)
    backups = list(tmp_path.glob("legacy.db.pre-migration-v1-*.db"))
    assert len(backups) == 1
    assert journal.get_mode() is SystemMode.MAINTENANCE
    probe = sqlite3.connect(f"file:{backups[0]}?mode=ro", uri=True)
    try:
        assert probe.execute(
            "SELECT value FROM legacy_marker"
        ).fetchone()[0] == "preserved"
    finally:
        probe.close()
        journal.close()


@pytest.mark.unit
def test_schema_migrations_are_contiguous_and_failure_is_reentrant(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "migration-reentry.db"
    journal = SQLiteJournal(path)
    journal.close()
    raw = sqlite3.connect(path)
    raw.execute("DELETE FROM schema_migrations WHERE version=11")
    raw.commit()
    raw.close()

    original = SQLiteJournal.__dict__[
        "_migration_011_durable_alert_delivery"
    ]

    def fail_migration(_cls, _conn):
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(
        SQLiteJournal,
        "_migration_011_durable_alert_delivery",
        classmethod(fail_migration),
    )
    with pytest.raises(RuntimeError, match="injected migration failure"):
        SQLiteJournal(path)
    raw = sqlite3.connect(path)
    try:
        assert raw.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0] == 10
    finally:
        raw.close()

    monkeypatch.setattr(
        SQLiteJournal,
        "_migration_011_durable_alert_delivery",
        original,
    )
    reopened = SQLiteJournal(path)
    try:
        versions = [
            row[0]
            for row in reopened._conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert versions == list(range(1, 12))
        assert reopened.get_mode() is SystemMode.MAINTENANCE
    finally:
        reopened.close()


@pytest.mark.unit
def test_current_schema_does_not_reenter_maintenance(tmp_path):
    path = tmp_path / "current.db"
    journal = SQLiteJournal(path)
    journal.set_mode(SystemMode.READY)
    journal.close()

    reopened = SQLiteJournal(path)
    try:
        assert reopened.get_mode() is SystemMode.READY
    finally:
        reopened.close()


@pytest.mark.unit
def test_newer_schema_refuses_old_binary(tmp_path):
    path = tmp_path / "future.db"
    future = sqlite3.connect(path)
    future.executescript(
        """
        CREATE TABLE schema_migrations(
            version INTEGER PRIMARY KEY,
            applied_at REAL NOT NULL
        );
        INSERT INTO schema_migrations(version, applied_at) VALUES(999, 1);
        """
    )
    future.close()
    with pytest.raises(RuntimeError, match="高于当前程序"):
        SQLiteJournal(path)


@pytest.mark.unit
def test_system_mode_persists(tmp_path):
    path = tmp_path / "journal.db"
    journal = SQLiteJournal(path)
    journal.set_mode(SystemMode.HALTED)
    journal.close()
    reopened = SQLiteJournal(path)
    assert reopened.get_mode() is SystemMode.HALTED


@pytest.mark.unit
def test_halted_cannot_downgrade_stronger_hard_modes(tmp_path):
    journal = SQLiteJournal(tmp_path / "hard-modes.db")
    journal.set_mode(SystemMode.EMERGENCY_EXIT)
    assert not journal.set_mode(SystemMode.HALTED)
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    journal.set_mode(SystemMode.MAINTENANCE)
    assert not journal.set_mode(SystemMode.HALTED)
    assert journal.get_mode() is SystemMode.MAINTENANCE
    journal.close()


@pytest.mark.unit
def test_must_exist_never_creates_blank_production_database(tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError):
        SQLiteJournal(missing, must_exist=True)
    assert not missing.exists()


@pytest.mark.unit
def test_read_only_journal_cannot_mutate_production_state(tmp_path):
    path = tmp_path / "journal.db"
    writable = SQLiteJournal(path)
    writable.set_mode(SystemMode.HALTED)
    writable.close()
    readonly = SQLiteJournal(path, must_exist=True, read_only=True)
    try:
        assert readonly.get_mode() is SystemMode.HALTED
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            readonly.set_mode(SystemMode.EMERGENCY_EXIT)
    finally:
        readonly.close()


@pytest.mark.unit
def test_base_fee_and_realized_pnl_are_accounting_facts(tmp_path):
    journal = _journal(tmp_path)
    buy = journal.create_order_intent(_intent())
    buy = journal.update_intent(buy, OrderState.SUBMITTING)
    journal.apply_exchange_order(ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.FILLED,
        ord_id="buy-fee",
        cl_ord_id=buy.cl_ord_id,
        acc_fill_qty=Decimal("0.1"),
        avg_fill_px=Decimal("50000"),
        fee=Decimal("-0.0001"),
        fee_ccy="BTC",
        trade_id="buy-fee-trade",
    ))
    position = journal.get_position("BTC-USDT")
    assert Decimal(position["base_qty"]) == Decimal("0.0999")
    assert Decimal(position["avg_entry_px"]) == (
        Decimal("5000") / Decimal("0.0999")
    )

    sell = journal.create_order_intent(OrderIntent(
        intent_id="sell-intent",
        cl_ord_id="QTESTS01",
        inst_id="BTC-USDT",
        side="sell",
        requested_base_qty=Decimal("0.05"),
    ))
    sell = journal.update_intent(sell, OrderState.SUBMITTING)
    journal.apply_exchange_order(ExchangeOrder(
        inst_id="BTC-USDT",
        side="sell",
        state=OrderState.FILLED,
        ord_id="sell-fee",
        cl_ord_id=sell.cl_ord_id,
        acc_fill_qty=Decimal("0.05"),
        avg_fill_px=Decimal("51000"),
        fee=Decimal("-2"),
        fee_ccy="USDT",
        trade_id="sell-fee-trade",
    ))
    position = journal.get_position("BTC-USDT")
    expected = (
        Decimal("0.05")
        * (Decimal("51000") - Decimal("5000") / Decimal("0.0999"))
        - Decimal("2")
    )
    assert Decimal(position["realized_pnl"]) == expected
    assert journal.realized_pnl_since(0) == expected


@pytest.mark.unit
def test_terminal_order_accepts_late_fill_and_fee_corrections(tmp_path):
    journal = _journal(tmp_path)
    intent = journal.create_order_intent(_intent())
    intent = journal.update_intent(intent, OrderState.SUBMITTING)
    journal.apply_exchange_order(ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.CANCELED,
        ord_id="late-fill",
        cl_ord_id=intent.cl_ord_id,
        acc_fill_qty=Decimal("0.04"),
        avg_fill_px=Decimal("50000"),
        fee=Decimal("0"),
        fee_ccy="BTC",
    ))
    updated, delta = journal.apply_exchange_order(ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.CANCELED,
        ord_id="late-fill",
        cl_ord_id=intent.cl_ord_id,
        acc_fill_qty=Decimal("0.1"),
        avg_fill_px=Decimal("50000"),
        fee=Decimal("-0.001"),
        fee_ccy="BTC",
    ))
    assert delta == Decimal("0.06")
    assert updated.state is OrderState.CANCELED
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("0.099")

    journal.apply_exchange_order(ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.CANCELED,
        ord_id="late-fill",
        cl_ord_id=intent.cl_ord_id,
        acc_fill_qty=Decimal("0.1"),
        avg_fill_px=Decimal("50000"),
        fee=Decimal("-0.002"),
        fee_ccy="BTC",
    ))
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("0.098")


@pytest.mark.unit
def test_must_exist_rejects_missing_and_zero_length_journal(tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError, match="不存在、为空"):
        SQLiteJournal(missing, must_exist=True)
    assert not missing.exists()

    empty = tmp_path / "empty.db"
    empty.touch()
    with pytest.raises(FileNotFoundError, match="不存在、为空"):
        SQLiteJournal(empty, must_exist=True)
    assert empty.stat().st_size == 0


@pytest.mark.unit
def test_journal_identity_is_atomic_immutable_and_account_bound(tmp_path):
    journal = _journal(tmp_path)
    assert journal.get_identity() is None
    with pytest.raises(RuntimeError, match="初始化 marker"):
        journal.assert_identity("account-a")

    journal.initialize_identity(
        account_id="account-a",
        initial_config_hash="a" * 64,
        actor="bootstrap",
    )
    assert journal.assert_identity("account-a")["initialized_by"] == "bootstrap"
    assert journal.get_mode() is SystemMode.HALTED
    with pytest.raises(RuntimeError, match="不匹配"):
        journal.assert_identity("account-b")
    with pytest.raises(RuntimeError, match="禁止覆盖"):
        journal.initialize_identity(
            account_id="account-b",
            initial_config_hash="b" * 64,
            actor="attacker",
        )


@pytest.mark.unit
def test_health_and_writes_fail_if_open_database_path_is_unlinked(tmp_path):
    path = tmp_path / "journal.db"
    journal = SQLiteJournal(path)
    path.unlink()
    assert not journal.health_check()
    with pytest.raises(sqlite3.OperationalError, match="inode"):
        journal.set_mode(SystemMode.HALTED)
    journal.close()
