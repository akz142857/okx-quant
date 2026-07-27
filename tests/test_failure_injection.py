"""生产方案列出的关键故障注入与持续不变量。"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from decimal import Decimal

import pytest

from okx_quant.application.execution import ExecutionCoordinator, ExecutionRequest
from okx_quant.application.runtime import ProductionRuntime
from okx_quant.domain.orders import ExchangeOrder, OrderState, SystemMode
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal
from scripts import fault_injection
from scripts.fault_injection import (
    CASES,
    _source_manifest_hash,
    run_system_faults,
    verify_evidence_artifact,
)


def ready_exchange() -> FakeExchange:
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=50_000, bid=49_990, ask=50_010)
    return exchange


@pytest.mark.unit
def test_os_level_fault_harness_preserves_invariants():
    results = run_system_faults()
    assert {item["level"] for item in results} == {
        "os_process",
        "os_filesystem",
        "storage_engine",
        "os_network",
    }
    assert all(item["passed"] for item in results)


@pytest.mark.unit
def test_ci_fault_evidence_verifies_without_git_metadata(tmp_path, monkeypatch):
    revision = "a" * 40
    revision_file = tmp_path / "REVISION"
    revision_file.write_text(revision + "\n", encoding="ascii")
    evidence_path = tmp_path / "fault-injection.json"
    evidence = {
        "started_at": 100.0,
        "completed_at": 110.0,
        "git_commit": revision,
        "git_tree_hash": "b" * 40,
        "workspace_clean": True,
        "source_manifest_sha256": _source_manifest_hash(),
        "system_fault_cases": [
            {"level": level, "passed": True}
            for level in (
                "os_process",
                "os_filesystem",
                "storage_engine",
                "os_network",
            )
        ],
        "semantic_fault_cases": CASES,
        "exit_code": 0,
    }
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    monkeypatch.setattr(
        fault_injection.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail(
            "evidence verification must not invoke git or subprocesses"
        ),
    )

    verified = verify_evidence_artifact(evidence_path, revision_file)
    assert verified["git_commit"] == revision

    evidence["source_manifest_sha256"] = "0" * 64
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(RuntimeError, match="源码/测试 manifest"):
        verify_evidence_artifact(evidence_path, revision_file)


@pytest.mark.unit
def test_disk_full_before_persist_never_reaches_exchange(tmp_path, monkeypatch):
    exchange = ready_exchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal)

    def disk_full(_intent, **_kwargs):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(journal, "create_order_intent", disk_full)
    with pytest.raises(sqlite3.OperationalError, match="disk is full"):
        coordinator.submit(ExecutionRequest(
            inst_id="BTC-USDT",
            side="sell",
            base_qty=Decimal("0.01"),
        ))
    assert exchange.orders == []
    journal.close()


@pytest.mark.unit
def test_clock_skew_blocks_runtime_before_ready(tmp_path):
    exchange = ready_exchange()
    exchange.get_server_time = lambda: time.time() - 5
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        lock_path=tmp_path / "trading.lock",
        max_clock_skew_s=1,
    )
    with pytest.raises(RuntimeError, match="时间偏差"):
        runtime.start()
    assert journal.get_mode() is SystemMode.HALTED
    assert exchange.orders == []
    journal.close()


@pytest.mark.unit
def test_account_api_failure_is_fail_closed_before_intent(tmp_path):
    exchange = ready_exchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        lock_path=tmp_path / "trading.lock",
    )
    runtime.start()
    try:
        exchange.get_balance = lambda: (_ for _ in ()).throw(
            RuntimeError("temporary account outage")
        )
        with pytest.raises(RuntimeError, match="无法刷新账户快照"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                reserved_quote=Decimal("500"),
                stop_loss=Decimal("49000"),
            ))
        assert exchange.orders == []
        assert journal.recent_intent_count(0) == 0
    finally:
        runtime.stop()


@pytest.mark.unit
def test_ten_duplicate_updates_project_only_one_fill(tmp_path):
    exchange = ready_exchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal)
    intent = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.01"),
    ))
    update = exchange.get_order_status(
        "BTC-USDT", cl_ord_id=intent.cl_ord_id
    )
    for _ in range(10):
        _, delta = coordinator.process_exchange_update(update)
        assert delta == 0
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("0.01")
    journal.close()


@pytest.mark.unit
def test_filled_update_without_trade_id_is_idempotent(tmp_path):
    exchange = ready_exchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal)
    intent = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.01"),
    ))
    update = ExchangeOrder(
        inst_id="BTC-USDT",
        side="buy",
        state=OrderState.FILLED,
        ord_id=intent.exchange_ord_id,
        cl_ord_id=intent.cl_ord_id,
        requested_qty=Decimal("0.01"),
        acc_fill_qty=Decimal("0.01"),
        avg_fill_px=Decimal("50000"),
        trade_id="",
        update_ts=time.time(),
    )
    for _ in range(2):
        _, delta = coordinator.process_exchange_update(update)
        assert delta == 0
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("0.01")
    journal.close()


@pytest.mark.unit
def test_simultaneous_workers_cannot_spend_same_cash(tmp_path):
    exchange = ready_exchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        lock_path=tmp_path / "trading.lock",
    )

    def debit_after_first(order):
        if order.side == "buy":
            exchange.set_balance(total=500, quote_avail=0)

    exchange.on_order(debit_after_first)
    runtime.start()
    outcomes: list[str] = []

    def submit(inst_id: str):
        try:
            runtime.execution.submit(ExecutionRequest(
                inst_id=inst_id,
                side="buy",
                base_qty=Decimal("0.01"),
                reserved_quote=Decimal("500"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            ))
            outcomes.append("filled")
        except RuntimeError:
            outcomes.append("rejected")

    exchange.set_ticker("ETH-USDT", last=50_000, bid=49_990, ask=50_010)
    workers = [
        threading.Thread(target=submit, args=("BTC-USDT",)),
        threading.Thread(target=submit, args=("ETH-USDT",)),
    ]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=2)
        assert sorted(outcomes) == ["filled", "rejected"]
        assert len(exchange.orders) == 1
    finally:
        runtime.stop()


@pytest.mark.unit
def test_shadow_mode_persists_intent_without_exchange_order(tmp_path):
    exchange = ready_exchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal, shadow_mode=True)
    intent = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.01"),
    ))
    assert intent.state is OrderState.REJECTED
    assert intent.last_error_code == "SHADOW_NOT_SUBMITTED"
    assert exchange.orders == []
    journal.close()
