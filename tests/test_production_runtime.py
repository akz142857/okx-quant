"""生产运行时、组合风控和控制命令集成测试。"""

import json
import threading
import time
from decimal import Decimal
from types import SimpleNamespace

import pandas as pd
import pytest

from okx_quant.application.execution import ExecutionRequest
from okx_quant.application.reconciliation import ReconciliationResult
from okx_quant.application.risk_service import (
    ProductionRiskLimits,
    ProductionRiskService,
)
from okx_quant.application.runtime import ProductionRuntime, SingleInstanceLock
from okx_quant.cli.operations import enqueue_and_wait
from okx_quant.client.websocket import ConnectionState, OKXWebSocketClient
from okx_quant.domain.orders import OrderState, SystemMode
from okx_quant.exchange import InstrumentInfo
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.risk.manager import PositionInfo, RiskManager
from okx_quant.trading.orders import OrderExecutor


def _runtime(tmp_path, *, limits=None):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=50_000, bid=49_990, ask=50_010)
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        risk_limits=limits,
        lock_path=tmp_path / "trading.lock",
        reconciliation_interval_s=0.05,
    )
    return exchange, journal, runtime


@pytest.mark.unit
def test_ws_disconnect_during_recovery_cannot_restore_ready(tmp_path, monkeypatch):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=50_000, bid=49_990, ask=50_010)
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.READY)

    def disconnect_during_reconcile(**_kwargs):
        ws._set_state("private", ConnectionState.BACKOFF)
        return ReconciliationResult(run_id="fixture")

    monkeypatch.setattr(runtime.reconciler, "run", disconnect_during_reconcile)
    runtime._restore_after_reconnect()

    assert journal.get_mode() is SystemMode.DEGRADED
    assert not runtime.streams.ready
    allowed, reason = runtime.risk_service.check(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.01"),
        reserved_quote=Decimal("500"),
        stop_loss=Decimal("49000"),
    ))
    assert not allowed
    assert "READY" in reason
    journal.close()


@pytest.mark.unit
def test_reconnect_repeats_baseline_when_ws_generation_changes(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
        ws_ready_timeout_s=1,
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    calls = 0

    def generation_changes_once(**_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            runtime._ws_generation += 2
        return ReconciliationResult(run_id=f"fixture-{calls}")

    monkeypatch.setattr(runtime.reconciler, "run", generation_changes_once)
    runtime._restore_after_reconnect()
    assert calls == 2
    assert runtime.streams.ready
    journal.close()


@pytest.mark.unit
def test_reconnect_repeats_baseline_when_private_event_arrives(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
        ws_ready_timeout_s=1,
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    calls = 0

    def event_arrives_once(**_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            runtime.streams._on_balance([{"ccy": "BTC"}])
        return ReconciliationResult(run_id=f"event-{calls}")

    monkeypatch.setattr(runtime.reconciler, "run", event_arrives_once)
    runtime._restore_after_reconnect()
    assert calls == 2
    assert runtime.streams.ready
    journal.close()


@pytest.mark.unit
def test_periodic_reconcile_repeats_if_balance_event_changes_snapshot(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=100, bid=99, ask=101)
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.READY)
    original_pending = exchange.get_pending_orders
    triggered = False

    def balance_changes_after_old_snapshot():
        nonlocal triggered
        if not triggered:
            triggered = True
            exchange.set_holding("BTC", balance=1, available=1)
            runtime.streams._on_balance([{"ccy": "BTC"}])
        return original_pending()

    monkeypatch.setattr(
        exchange, "get_pending_orders", balance_changes_after_old_snapshot
    )
    runtime._periodic_reconcile_once()
    assert Decimal(
        journal.get_position("BTC-USDT")["base_qty"]
    ) == Decimal("1")
    assert runtime.streams.ready
    assert journal.get_mode() is SystemMode.READY
    healthy, _ = runtime._health()
    assert healthy
    journal.close()


@pytest.mark.unit
def test_reconcile_now_uses_same_event_sequence_fence(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=100, bid=99, ask=101)
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.READY)
    original_pending = exchange.get_pending_orders
    triggered = False

    def balance_changes_after_old_snapshot():
        nonlocal triggered
        if not triggered:
            triggered = True
            exchange.set_holding("BTC", balance=1, available=1)
            runtime.streams._on_balance([{"ccy": "BTC"}])
        return original_pending()

    monkeypatch.setattr(
        exchange, "get_pending_orders", balance_changes_after_old_snapshot
    )
    runtime._stop_event.clear()
    control = threading.Thread(target=runtime._control_loop)
    control.start()
    try:
        command = enqueue_and_wait(
            journal,
            "reconcile-now",
            {},
            timeout_s=2,
        )
        assert command["status"] == "completed"
        assert command["result"]["safe"]
        assert Decimal(
            journal.get_position("BTC-USDT")["base_qty"]
        ) == Decimal("1")
        assert journal.get_mode() is SystemMode.READY
    finally:
        runtime._stop_event.set()
        control.join(timeout=2)
        journal.close()


@pytest.mark.unit
def test_resume_event_at_hard_release_cannot_leave_ready(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.HALTED)
    original_set_mode = journal.set_mode
    original_health = runtime._health
    event_started = threading.Event()
    event_thread = None

    def emit_balance():
        event_started.set()
        runtime.streams._on_balance([{"ccy": "BTC"}])

    def set_mode_with_event(
        mode,
        *,
        allow_hard_release=False,
        expected_hard_epoch=None,
    ):
        nonlocal event_thread
        if allow_hard_release:
            event_thread = threading.Thread(target=emit_balance)
            event_thread.start()
            assert event_started.wait(1)
        return original_set_mode(
            mode,
            allow_hard_release=allow_hard_release,
            expected_hard_epoch=expected_hard_epoch,
        )

    def health_after_event():
        if event_thread is not None:
            event_thread.join(timeout=1)
        return original_health()

    monkeypatch.setattr(journal, "set_mode", set_mode_with_event)
    monkeypatch.setattr(runtime, "_health", health_after_event)
    with pytest.raises(RuntimeError, match="readiness"):
        runtime._resume_entries(
            "a" * 32,
            {"actor": "operator", "risk_approver": "risk"},
        )
    assert journal.get_mode() is SystemMode.HALTED
    assert event_thread is not None and not event_thread.is_alive()
    journal.close()


@pytest.mark.unit
def test_concurrent_halt_epoch_prevents_stale_resume_release(
    tmp_path,
    monkeypatch,
):
    exchange, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.HALTED)

    def halt_during_reconcile(**_kwargs):
        # 重复 HALTED 也推进 epoch，代表一个比当前 resume 更新的人工意图。
        journal.set_mode(SystemMode.HALTED)
        return ReconciliationResult(run_id="halt-race")

    monkeypatch.setattr(runtime.reconciler, "run", halt_during_reconcile)
    with pytest.raises(RuntimeError, match="readiness"):
        runtime._resume_entries(
            "b" * 32,
            {"actor": "operator", "risk_approver": "risk"},
        )
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_startup_subscribes_then_builds_second_rest_baseline(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
        ws_ready_timeout_s=1,
    )
    calls = 0
    original_run = runtime.reconciler.run

    def count_reconcile(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_run(*args, **kwargs)

    def mark_transport_ready():
        ws._states["private"] = ConnectionState.READY
        ws._states["business"] = ConnectionState.READY

    monkeypatch.setattr(runtime.reconciler, "run", count_reconcile)
    monkeypatch.setattr(runtime.streams, "start", mark_transport_ready)
    runtime.start()
    try:
        assert calls >= 2
        assert runtime.streams.ready
        assert runtime.ready
    finally:
        runtime.stop()


@pytest.mark.unit
def test_alert_delivery_failure_makes_runtime_unhealthy(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    runtime.alerts.webhook_url = "https://alerts.example"
    runtime.alerts.consecutive_failures = 3
    healthy, detail = runtime._health()
    assert not healthy
    assert detail["alert_delivery_healthy"] is False
    journal.close()


@pytest.mark.unit
def test_alert_delivery_failure_rejects_new_buy(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        runtime.alerts.webhook_url = "https://alerts.example"
        runtime.alerts.consecutive_failures = 3
        with pytest.raises(RuntimeError, match="门禁未 READY"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                stop_loss=Decimal("49000"),
            ))
    finally:
        runtime.stop()


@pytest.mark.unit
def test_halted_mode_survives_runtime_restart_and_remains_live(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.HALTED)
    runtime.start()
    try:
        assert journal.get_mode() is SystemMode.HALTED
        live, detail = runtime._liveness()
        assert live
        assert detail["reconciliation_fresh"]
        ready, _ = runtime._health()
        assert not ready
    finally:
        runtime.stop()


@pytest.mark.unit
def test_hard_mode_cannot_be_relaxed_by_ws_or_safe_reconcile(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.HALTED)
    runtime._on_ws_state("private", ConnectionState.BACKOFF)
    runtime._promote_ready_if_safe(True)
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_public_market_disconnect_closes_readiness_and_degrades(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    runtime.register_public_market_data(["BTC-USDT"], "1H")
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    ws._states["public"] = ConnectionState.READY
    ws._last_message_at["public"] = time.time()
    runtime._on_public_market_event("ticker", "BTC-USDT", [{"last": "1"}])
    runtime._on_public_market_event("candle", "BTC-USDT", [["1"]])
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.READY)
    assert runtime.ready

    runtime._on_ws_state("public", ConnectionState.BACKOFF)
    assert journal.get_mode() is SystemMode.DEGRADED
    assert not runtime.ready
    journal.close()


@pytest.mark.unit
def test_public_market_readiness_requires_every_registered_channel(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    runtime.register_public_market_data(["BTC-USDT", "ETH-USDT"], "1H")
    ws._states["public"] = ConnectionState.READY
    for inst_id in ("BTC-USDT", "ETH-USDT"):
        runtime._on_public_market_event("ticker", inst_id, [{"last": "1"}])
    runtime._on_public_market_event("candle", "BTC-USDT", [["1"]])
    assert not runtime._public_market_ready()
    runtime._on_public_market_event("candle", "ETH-USDT", [["1"]])
    assert runtime._public_market_ready()
    journal.close()


@pytest.mark.unit
def test_runtime_refuses_mismatched_exchange_account(tmp_path):
    exchange = FakeExchange()
    exchange.set_account_identity("actual-uid")
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        expected_account_id="configured-uid",
        lock_path=tmp_path / "trading.lock",
    )
    with pytest.raises(RuntimeError, match="账户 UID"):
        runtime.start()
    assert journal.get_mode() is SystemMode.HALTED
    assert not runtime._started
    journal.close()


@pytest.mark.unit
def test_runtime_recovery_gate_allows_durable_protected_buy(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        assert runtime.ready
        intent = runtime.execution.submit(ExecutionRequest(
            inst_id="BTC-USDT",
            side="buy",
            base_qty=Decimal("0.01"),
            reserved_quote=Decimal("500"),
            stop_loss=Decimal("49000"),
            take_profit=Decimal("52000"),
        ))
        assert intent.state is OrderState.FILLED
        assert journal.has_active_protection("BTC-USDT", Decimal("0.01"))
        assert exchange.orders[0].cl_ord_id
    finally:
        runtime.stop()


@pytest.mark.unit
def test_same_completed_candle_is_durable_and_idempotent(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    candle_ts = time.time() - 3600
    valid, _ = runtime.validate_candle("ma:1", "BTC-USDT", "1H", candle_ts)
    assert valid
    decision_id = runtime.persist_decision(
        strategy_instance_id="ma:1",
        strategy_name="ma",
        strategy_version="a" * 64,
        inst_id="BTC-USDT",
        candle_ts=str(candle_ts),
        signal="buy",
        requested_size_pct=Decimal("0.1"),
        reason="fixture",
    )
    assert decision_id
    stored = journal._conn.execute(
        "SELECT strategy_version FROM decisions WHERE decision_id=?",
        (decision_id,),
    ).fetchone()
    assert stored["strategy_version"] == "a" * 64
    runtime.mark_candle_processed("ma:1", "BTC-USDT", "1H", candle_ts)
    valid, reason = runtime.validate_candle(
        "ma:1", "BTC-USDT", "1H", candle_ts
    )
    assert not valid and reason == "K 线已处理"
    assert runtime.persist_decision(
        strategy_instance_id="ma:1",
        strategy_name="ma",
        strategy_version="a" * 64,
        inst_id="BTC-USDT",
        candle_ts=str(candle_ts),
        signal="buy",
        requested_size_pct=Decimal("0.1"),
        reason="duplicate",
    ) is None
    journal.close()


@pytest.mark.unit
def test_strategy_timeout_is_routed_to_durable_warning(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    runtime.record_strategy_warning(
        strategy_name="llm_shadow",
        strategy_version="a" * 64,
        inst_id="BTC-USDT",
        warning_kind="timeout",
        detail="fixture timeout",
    )
    rows = journal.get_unpublished_outbox()
    assert rows[-1]["event_name"] == "warning.strategy_signal_timeout"
    assert json.loads(rows[-1]["payload_json"])["strategy_version"] == "a" * 64
    journal.close()


@pytest.mark.unit
def test_candle_watermark_rejects_short_cross_window_interval(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    previous = time.time() - 7200
    runtime.mark_candle_processed(
        "ma:cadence",
        "BTC-USDT",
        "1H",
        previous,
    )
    valid, reason = runtime.validate_candle(
        "ma:cadence",
        "BTC-USDT",
        "1H",
        previous + 600,
    )
    assert not valid
    assert reason == "K 线时间不连续"
    assert journal.get_mode() is SystemMode.DEGRADED
    journal.close()


@pytest.mark.unit
def test_signal_market_window_rejects_gap_and_excess_volatility(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    candle_ts = time.time() - 3600
    valid_window = pd.DataFrame({
        "ts": [candle_ts - 3600, candle_ts],
        "open": [50_000, 50_100],
        "high": [50_100, 50_200],
        "low": [49_900, 50_000],
        "close": [50_000, 50_100],
    })
    valid, reason = runtime.validate_candle(
        "ma:window",
        "BTC-USDT",
        "1H",
        candle_ts,
        market_data=valid_window,
    )
    assert valid, reason

    gapped = valid_window.copy()
    gapped.loc[0, "ts"] = candle_ts - 7200
    valid, reason = runtime.validate_candle(
        "ma:gap",
        "BTC-USDT",
        "1H",
        candle_ts,
        market_data=gapped,
    )
    assert not valid and "不连续" in reason
    assert journal.get_mode() is SystemMode.DEGRADED

    wrong_cadence = valid_window.copy()
    wrong_cadence.loc[0, "ts"] = candle_ts - 600
    valid, reason = runtime.validate_candle(
        "ma:cadence",
        "BTC-USDT",
        "1H",
        candle_ts,
        market_data=wrong_cadence,
    )
    assert not valid and "不连续" in reason

    volatile = valid_window.copy()
    volatile.loc[1, ["high", "low"]] = [60_000, 40_000]
    valid, reason = runtime.validate_candle(
        "ma:volatile",
        "BTC-USDT",
        "1H",
        candle_ts,
        market_data=volatile,
    )
    assert not valid and "波动率" in reason
    journal.close()


@pytest.mark.unit
def test_risk_limits_reject_values_above_compiled_hard_caps():
    with pytest.raises(ValueError, match="编译期硬上限"):
        ProductionRiskLimits(
            max_order_loss_usdt=Decimal("101")
        ).validate()
    with pytest.raises(ValueError, match="20%"):
        ProductionRiskLimits(
            max_candle_range_ratio=Decimal("0.21")
        ).validate()


@pytest.mark.unit
def test_portfolio_risk_rejects_wide_spread_before_intent(tmp_path):
    limits = ProductionRiskLimits(max_spread_ratio=Decimal("0.001"))
    exchange, journal, runtime = _runtime(tmp_path, limits=limits)
    exchange.set_ticker("BTC-USDT", last=50_000, bid=49_000, ask=51_000)
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match="spread"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                reserved_quote=Decimal("500"),
                stop_loss=Decimal("49000"),
            ))
        assert journal.recent_intent_count(0) == 0
        # 市场质量属于 REJECT_CANDIDATE，不要求人工 resume。
        assert journal.get_mode() is SystemMode.READY
    finally:
        runtime.stop()


@pytest.mark.unit
def test_existing_account_exposure_breach_halts_and_pages(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_holding("BTC", balance=2, available=2)
    exchange.set_ticker("BTC-USDT", last=100, bid=99, ask=101)
    exchange.set_ticker("ETH-USDT", last=100, bid=99, ask=101)
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("2"),
        reference_price=Decimal("100"),
        reason="fixture",
    )
    journal.set_mode(SystemMode.READY)
    service = ProductionRiskService(
        exchange,
        journal,
        ProductionRiskLimits(
            max_position_notional_usdt=Decimal("150"),
            max_total_exposure_usdt=Decimal("500"),
        ),
    )
    allowed, reason = service.check(ExecutionRequest(
        inst_id="ETH-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
        reserved_quote=Decimal("11"),
        stop_loss=Decimal("90"),
        take_profit=Decimal("120"),
    ))
    assert not allowed
    assert "已经超过" in reason
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.current_position_notional_limit"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("bid", "ask"),
    [(0, 0), (50_100, 50_000)],
)
def test_pretrade_rejects_missing_or_crossed_bbo_before_intent(
    tmp_path,
    bid,
    ask,
):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=bid,
        ask=ask,
    )
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match="bid/ask"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            ))
        assert exchange.orders == []
    finally:
        runtime.stop()


@pytest.mark.unit
def test_pretrade_enforces_production_instrument_allowlist(tmp_path):
    limits = ProductionRiskLimits(
        allowed_instruments=frozenset({"BTC-USDT"})
    )
    exchange, journal, runtime = _runtime(tmp_path, limits=limits)
    exchange.set_ticker(
        "UNAPPROVED-USDT",
        last=1,
        bid=Decimal("0.99"),
        ask=Decimal("1.01"),
    )
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match="allowlist"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="UNAPPROVED-USDT",
                side="buy",
                base_qty=Decimal("1"),
                stop_loss=Decimal("0.9"),
                take_profit=Decimal("1.1"),
            ))
        assert exchange.orders == []
    finally:
        runtime.stop()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("ticker_kwargs", "message"),
    [
        (
            {
                "timestamp": 1,
                "quote_volume_24h": 1_000_000,
            },
            "行情快照",
        ),
        (
            {
                "timestamp": None,
                "quote_volume_24h": 1,
            },
            "流动性",
        ),
    ],
)
def test_pretrade_rejects_stale_or_illiquid_market(
    tmp_path,
    ticker_kwargs,
    message,
):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
        **ticker_kwargs,
    )
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match=message):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            ))
        assert journal.recent_intent_count(0) == 0
    finally:
        runtime.stop()


@pytest.mark.unit
def test_pretrade_rejects_take_profit_below_worst_fill(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match="有效止盈"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("50100"),
            ))
        assert journal.recent_intent_count(0) == 0
    finally:
        runtime.stop()


@pytest.mark.unit
def test_consecutive_api_and_ws_errors_latch_halted(tmp_path):
    _, journal, runtime = _runtime(
        tmp_path,
    )
    journal.set_mode(SystemMode.READY)
    runtime._observe_api_request("/fixture", "OKX:0", 0.1)
    for _ in range(runtime.max_consecutive_infrastructure_errors):
        runtime._observe_api_request("/fixture", "OKX:50011", 0.1)
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.api_error_budget_exhausted"
        for row in journal.get_unpublished_outbox()
    )
    assert any(
        row["event_name"] == "warning.api_error_rate_elevated"
        for row in journal.get_unpublished_outbox()
    )

    _, hard_epoch = journal.get_mode_state()
    journal.set_mode(
        SystemMode.READY,
        allow_hard_release=True,
        expected_hard_epoch=hard_epoch,
    )
    for _ in range(runtime.max_consecutive_infrastructure_errors):
        runtime._on_ws_state("private", ConnectionState.BACKOFF)
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.ws_error_budget_exhausted"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_fill_slippage_is_durable_metric_and_warning(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.queue_order_outcome(
        state="filled",
        fill_size=Decimal("0.01"),
        fill_price=Decimal("51000"),
    )
    runtime.start()
    try:
        intent = runtime.execution.submit(ExecutionRequest(
            inst_id="BTC-USDT",
            side="buy",
            base_qty=Decimal("0.01"),
            stop_loss=Decimal("49000"),
            take_profit=Decimal("53000"),
        ))
        assert intent.submission_reference_price == Decimal("50010")
        assert journal.list_events("execution_slippage_sample")
        assert any(
            row["event_name"]
            == "warning.execution_slippage_exceeded"
            for row in journal.get_unpublished_outbox()
        )
        rendered = runtime.metrics.render()
        assert "execution_slippage_ratio" in rendered
        assert "protection_activation_latency_seconds_bucket" in rendered
    finally:
        runtime.stop()


@pytest.mark.unit
def test_consecutive_database_errors_latch_halted(tmp_path, monkeypatch):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    monkeypatch.setattr(journal, "health_check", lambda: False)

    for _ in range(runtime.max_consecutive_infrastructure_errors):
        healthy, detail = runtime._liveness()
        assert not healthy
        assert detail["database_healthy"] is False

    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.database_error_budget_exhausted"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_consecutive_database_write_errors_latch_halted(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    for _ in range(runtime.max_consecutive_infrastructure_errors):
        runtime._observe_database_write(
            False,
            OSError("disk I/O error"),
        )
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"]
        == "page.database_write_error_budget_exhausted"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unprotected_deadline_enters_emergency_and_attempts_exit(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.01"),
        reference_price=Decimal("50000"),
        reason="fixture",
    )
    calls = []
    monkeypatch.setattr(
        runtime.exit,
        "exit_position",
        lambda inst_id, reason: (
            calls.append((inst_id, reason))
            or SimpleNamespace(state=OrderState.FILLED)
        ),
    )

    runtime._enforce_unprotected_deadline(now=100)
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert any(
        row["event_name"] == "page.unprotected_position_detected"
        for row in journal.get_unpublished_outbox()
    )
    runtime._enforce_unprotected_deadline(
        now=100 + runtime.max_unprotected_position_s
    )

    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert calls == [
        ("BTC-USDT", "unprotected position deadline")
    ]
    assert any(
        row["event_name"] == "page.unprotected_position_deadline"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unprotected_deadline_retries_rejected_exit(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.01"),
        reference_price=Decimal("50000"),
        reason="fixture",
    )
    states = iter([OrderState.REJECTED, OrderState.FILLED])
    calls = []

    def exit_attempt(inst_id, reason):
        calls.append((inst_id, reason))
        return SimpleNamespace(state=next(states))

    monkeypatch.setattr(runtime.exit, "exit_position", exit_attempt)
    runtime._enforce_unprotected_deadline(now=100)
    deadline = 100 + runtime.max_unprotected_position_s
    runtime._enforce_unprotected_deadline(now=deadline)
    assert "BTC-USDT" not in runtime._unprotected_deadline_reported
    runtime._enforce_unprotected_deadline(now=deadline + 1)
    assert len(calls) == 2
    assert any(
        row["event_name"] == "page.emergency_exit_failed"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unprotected_watchdog_ignores_nontradable_dust(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
    )
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.000001"),
        reference_price=Decimal("50000"),
        reason="dust fixture",
    )
    journal.set_mode(SystemMode.READY)
    runtime._enforce_unprotected_deadline(now=100)
    assert journal.get_mode() is SystemMode.READY
    assert "BTC-USDT" not in runtime._unprotected_since
    assert not any(
        row["event_name"] == "page.unprotected_position_detected"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unprotected_watchdog_does_not_use_stale_low_mark_as_dust(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_ticker(
        "BTC-USDT",
        last=100,
        bid=99,
        ask=101,
        timestamp=1,
    )
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.001"),
        reference_price=Decimal("50000"),
        reason="material fixture",
    )
    journal.set_mode(SystemMode.READY)
    runtime._enforce_unprotected_deadline(now=100)
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert "BTC-USDT" in runtime._unprotected_since
    journal.close()


@pytest.mark.unit
def test_pretrade_refreshes_cash_and_enforces_lot_size(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_instrument(InstrumentInfo(
        inst_id="BTC-USDT",
        base_ccy="BTC",
        quote_ccy="USDT",
        lot_size=0.001,
        min_size=0.001,
    ))
    runtime.start()
    try:
        exchange.set_balance(total=10_000, quote_avail=1)
        with pytest.raises(RuntimeError, match="可用现金"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.001"),
                reserved_quote=Decimal("50"),
                stop_loss=Decimal("49000"),
            ))
        exchange.set_balance(total=10_000, quote_avail=10_000)
        with pytest.raises(RuntimeError, match="lot size"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.0015"),
                reserved_quote=Decimal("75"),
                stop_loss=Decimal("49000"),
            ))
        snapshot = journal.latest_account_snapshot()
        assert snapshot is not None and snapshot["source"] == "pre_trade"
    finally:
        runtime.stop()


@pytest.mark.unit
def test_pretrade_rejects_invalid_or_stale_account_snapshot(
    tmp_path,
    monkeypatch,
):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        exchange.set_balance(total=100, quote_avail=101)
        with pytest.raises(RuntimeError, match="账户快照"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.001"),
                reserved_quote=Decimal("51"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            ))

        exchange.set_balance(total=10_000, quote_avail=10_000)
        original = journal.latest_account_snapshot

        def stale_snapshot():
            snapshot = original()
            snapshot["captured_at"] = time.time() - 1000
            return snapshot

        monkeypatch.setattr(journal, "latest_account_snapshot", stale_snapshot)
        with pytest.raises(RuntimeError, match="账户快照过期"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.001"),
                reserved_quote=Decimal("51"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            ))
    finally:
        runtime.stop()


@pytest.mark.unit
def test_daily_realized_loss_cannot_be_hidden_by_flat_equity(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        monkeypatch.setattr(
            journal,
            "realized_pnl_since",
            lambda _since: Decimal("-300"),
        )
        with pytest.raises(RuntimeError, match="已实现亏损"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            ))
        assert journal.get_mode() is SystemMode.HALTED
        pages = [
            row
            for row in journal.get_unpublished_outbox()
            if row["event_name"] == "page.daily_realized_loss_limit"
        ]
        assert len(pages) == 1
        runtime.risk_service.enforce_account_hard_limits()
        assert len([
            row
            for row in journal.get_unpublished_outbox()
            if row["event_name"] == "page.daily_realized_loss_limit"
        ]) == 1
    finally:
        runtime.stop()


@pytest.mark.unit
def test_account_drawdown_halts_and_pages_without_waiting_for_buy(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    monkeypatch.setattr(
        journal,
        "realized_pnl_since",
        lambda _since: Decimal("0"),
    )
    monkeypatch.setattr(
        journal,
        "account_equities_since",
        lambda _since: [Decimal("10000"), Decimal("8000")],
    )
    within_limits, reason = runtime.risk_service.enforce_account_hard_limits()
    assert not within_limits
    assert "回撤" in reason
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.account_drawdown_limit"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unresolved_reconciliation_pages_once_per_incident(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    monkeypatch.setattr(
        runtime.reconciler,
        "run",
        lambda **_kwargs: ReconciliationResult(
            run_id="mismatch-run",
            mismatch_count=1,
            unresolved=["balance_mismatch:BTC-USDT"],
        ),
    )
    runtime._periodic_reconcile_once()
    runtime._periodic_reconcile_once()
    pages = [
        row
        for row in journal.get_unpublished_outbox()
        if row["event_name"] == "page.reconciliation_mismatch"
    ]
    assert len(pages) == 1
    assert journal.get_mode() is SystemMode.DEGRADED
    journal.close()


@pytest.mark.unit
def test_total_exposure_rejects_stale_existing_position_mark(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_holding("ETH", balance=20, available=20)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
    )
    exchange.set_ticker(
        "ETH-USDT",
        last=1,
        bid=Decimal("0.99"),
        ask=Decimal("1.01"),
        timestamp=1,
    )
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.reconcile_position(
        "ETH-USDT",
        Decimal("20"),
        reference_price=Decimal("1"),
        reason="fixture",
    )
    journal.set_mode(SystemMode.READY)
    service = ProductionRiskService(
        exchange,
        journal,
        ProductionRiskLimits(),
    )
    request = ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.01"),
        reserved_quote=Decimal("600"),
        stop_loss=Decimal("49000"),
        take_profit=Decimal("52000"),
    )
    allowed, reason = service.check(request)
    assert not allowed and "ETH-USDT 风险价格无效" in reason

    exchange.set_ticker(
        "ETH-USDT",
        last=400,
        bid=399,
        ask=401,
    )
    allowed, reason = service.check(request)
    assert not allowed and "账户硬限制" in reason
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_pretrade_rejects_reserve_computed_from_stale_lower_ticker(
    tmp_path,
    monkeypatch,
):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    original = exchange.get_ticker
    calls = 0

    def rising_ticker(inst_id):
        nonlocal calls
        calls += 1
        if calls == 1:
            exchange.set_ticker(inst_id, last=100, bid=100, ask=100)
        else:
            exchange.set_ticker(inst_id, last=200, bid=200, ask=200)
        return original(inst_id)

    monkeypatch.setattr(exchange, "get_ticker", rising_ticker)
    try:
        with pytest.raises(RuntimeError, match="风险预留不足"):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("1"),
                stop_loss=Decimal("150"),
            ))
        assert exchange.orders == []
    finally:
        runtime.stop()


@pytest.mark.unit
def test_pretrade_exposure_uses_authoritative_exchange_holdings(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_holding("BTC", balance=1, available=1)
    exchange.set_ticker("BTC-USDT", last=100)
    exchange.set_ticker("ETH-USDT", last=100)
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.READY)
    service = ProductionRiskService(
        exchange,
        journal,
        ProductionRiskLimits(
            max_position_notional_usdt=Decimal("150"),
            max_total_exposure_usdt=Decimal("150"),
        ),
    )
    allowed, reason = service.check(ExecutionRequest(
        inst_id="ETH-USDT",
        side="buy",
        base_qty=Decimal("1"),
        reserved_quote=Decimal("101"),
        stop_loss=Decimal("90"),
    ))
    assert not allowed
    assert "仓位与本地投影不一致" in reason
    assert journal.get_mode() is SystemMode.DEGRADED
    journal.close()


@pytest.mark.unit
def test_ws_disconnect_during_pretrade_never_posts_buy(
    tmp_path,
    monkeypatch,
):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    original_balance = exchange.get_balance

    def disconnect_then_balance():
        runtime._on_ws_state("private", ConnectionState.BACKOFF)
        return original_balance()

    monkeypatch.setattr(exchange, "get_balance", disconnect_then_balance)
    try:
        with pytest.raises(RuntimeError):
            runtime.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                stop_loss=Decimal("49000"),
            ))
        assert exchange.orders == []
        assert journal.get_mode() is SystemMode.DEGRADED
    finally:
        runtime.stop()


@pytest.mark.unit
def test_expired_exit_lease_does_not_duplicate_unknown_sell(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        runtime.execution.submit(ExecutionRequest(
            inst_id="BTC-USDT",
            side="buy",
            base_qty=Decimal("0.01"),
            reserved_quote=Decimal("500"),
            stop_loss=Decimal("49000"),
            take_profit=Decimal("52000"),
        ))
        exchange.set_holding("BTC", balance=0.01, available=0.01)
        exchange.queue_order_outcome(
            state="filled",
            fill_size=0.01,
            fill_price=49_900,
            lose_response=True,
        )
        first = runtime.exit.exit_position("BTC-USDT", "fixture")
        assert first is not None and first.state is OrderState.UNKNOWN
        journal._conn.execute("UPDATE exit_leases SET expires_at=0")
        second = runtime.exit.exit_position("BTC-USDT", "retry")
        assert second is not None and second.state is OrderState.FILLED
        assert [order.side for order in exchange.orders] == ["buy", "sell"]
    finally:
        runtime.stop()


@pytest.mark.unit
def test_strategy_exit_delegates_frozen_balance_to_protection_coordinator(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        runtime.execution.submit(ExecutionRequest(
            inst_id="BTC-USDT",
            side="buy",
            base_qty=Decimal("0.01"),
            reserved_quote=Decimal("500"),
            stop_loss=Decimal("49000"),
            take_profit=Decimal("52000"),
        ))
        exchange.set_holding("BTC", balance=0.01, available=0)
        original_cancel = exchange.cancel_algo_order

        def cancel_and_release(inst_id, algo_id):
            result = original_cancel(inst_id, algo_id)
            exchange.set_holding("BTC", balance=0.01, available=0.01)
            return result

        exchange.cancel_algo_order = cancel_and_release
        risk = RiskManager()
        risk.add_position(PositionInfo(
            "BTC-USDT", size=0.01, entry_price=50_000
        ))
        orders = OrderExecutor(
            exchange,
            "BTC-USDT",
            risk,
            production_runtime=runtime,
        )
        assert orders.sell(50_000, "strategy exit")
        assert [order.side for order in exchange.orders] == ["buy", "sell"]
    finally:
        runtime.stop()


@pytest.mark.unit
def test_order_executor_does_not_restore_position_after_emergency_exit(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        exchange.queue_algo_outcome(reject=True)
        risk = RiskManager()
        orders = OrderExecutor(
            exchange,
            "BTC-USDT",
            risk,
            production_runtime=runtime,
        )
        assert not orders.buy(
            price=50_000,
            size_coin=0.01,
            sl=49_000,
            tp=52_000,
            reason="fixture",
        )
        assert not risk.has_position("BTC-USDT")
        assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == 0
        assert [order.side for order in exchange.orders] == ["buy", "sell"]
    finally:
        runtime.stop()


@pytest.mark.unit
def test_flatten_control_runs_inside_single_writer(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        runtime.execution.submit(ExecutionRequest(
            inst_id="BTC-USDT",
            side="buy",
            base_qty=Decimal("0.01"),
            reserved_quote=Decimal("500"),
            stop_loss=Decimal("49000"),
            take_profit=Decimal("52000"),
        ))
        exchange.set_holding("BTC", balance=0.01, available=0.01)
        exchange.on_order(
            lambda order: exchange.set_holding("BTC", balance=0, available=0)
            if order.side == "sell"
            else None
        )
        command = enqueue_and_wait(
            journal,
            "flatten-and-cancel",
            {"instruments": ["BTC-USDT"], "actor": "test"},
            timeout_s=2,
        )
        assert command["status"] == "completed"
        assert journal.get_mode() is SystemMode.HALTED
        assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == 0
    finally:
        runtime.stop()


@pytest.mark.unit
def test_flatten_scope_never_cancels_unapproved_instrument(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.queue_order_outcome(state="live")
    btc = exchange.place_market_order(
        "BTC-USDT", "buy", 0.01, cl_ord_id="BTCFLATTENSCOPE01"
    )
    exchange.queue_order_outcome(state="live")
    eth = exchange.place_market_order(
        "ETH-USDT", "buy", 0.1, cl_ord_id="ETHFLATTENSCOPE01"
    )
    result = runtime._flatten_and_cancel(
        "c" * 32,
        {"instruments": ["BTC-USDT"], "actor": "operator"},
    )
    assert btc.ord_id in result["canceled_order_ids"]
    assert eth.ord_id not in result["canceled_order_ids"]
    assert exchange.get_order_status(
        "ETH-USDT", ord_id=eth.ord_id
    ).state is OrderState.LIVE
    journal.close()


@pytest.mark.unit
def test_unknown_flatten_scope_fails_without_exchange_side_effect(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.queue_order_outcome(state="live")
    eth = exchange.place_market_order(
        "ETH-USDT", "buy", 0.1, cl_ord_id="ETHFLATTENSCOPE02"
    )
    with pytest.raises(RuntimeError, match="不存在"):
        runtime._flatten_and_cancel(
            "d" * 32,
            {"instruments": ["BTC-USDT"], "actor": "operator"},
        )
    assert exchange.get_order_status(
        "ETH-USDT", ord_id=eth.ord_id
    ).state is OrderState.LIVE
    assert journal.get_mode() is SystemMode.STARTING
    journal.close()


@pytest.mark.unit
def test_flatten_all_recomputes_targets_after_baseline(tmp_path, monkeypatch):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_ticker("ETH-USDT", last=3_000)
    original_balance = exchange.get_balance
    calls = 0

    def holding_appears_during_baseline():
        nonlocal calls
        calls += 1
        if calls == 2:
            exchange.set_holding("ETH", balance=1, available=1)
        return original_balance()

    exchange.on_order(
        lambda order: exchange.set_holding("ETH", balance=0, available=0)
        if order.side == "sell" and order.inst_id == "ETH-USDT"
        else None
    )
    monkeypatch.setattr(
        exchange,
        "get_balance",
        holding_appears_during_baseline,
    )
    result = runtime._flatten_and_cancel(
        "e" * 32,
        {"instruments": [], "actor": "operator"},
    )
    assert result["exit_order_ids"]
    assert exchange.get_balance().holding("ETH").balance == 0
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_halted_runtime_resumes_only_after_two_person_safety_gate(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_account_identity("expected-uid")
    runtime.expected_account_id = "expected-uid"
    journal.set_mode(SystemMode.HALTED)
    runtime.start()
    try:
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"actor": "operator", "risk_approver": "risk"},
            timeout_s=2,
        )
        assert command["status"] == "completed"
        assert journal.get_mode() is SystemMode.READY
        assert runtime.ready
    finally:
        runtime.stop()


@pytest.mark.unit
def test_safety_only_ignores_shadow_and_permanently_rejects_resume(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
    )
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        shadow_mode=True,
        safety_only=True,
        lock_path=tmp_path / "trading.lock",
        reconciliation_interval_s=0.05,
    )
    runtime.start()
    try:
        assert not runtime.shadow_mode
        assert journal.get_mode() is SystemMode.HALTED
        assert journal.has_active_protection(
            "BTC-USDT",
            Decimal("0.1"),
        )
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"actor": "operator", "risk_approver": "risk"},
            timeout_s=2,
        )
        assert command["status"] == "failed"
        assert "safety-only" in command["result"]["error"]
        assert journal.get_mode() is SystemMode.HALTED
        assert not runtime.ready
        ready, detail = runtime._health()
        assert not ready
        assert detail["safety_only"] is True
    finally:
        runtime.stop()


@pytest.mark.unit
def test_safety_only_never_downgrades_emergency_exit(tmp_path):
    exchange, journal, _ = _runtime(tmp_path)
    journal.set_mode(SystemMode.EMERGENCY_EXIT)
    runtime = ProductionRuntime(
        exchange,
        journal,
        safety_only=True,
        lock_path=tmp_path / "safety-only.lock",
        reconciliation_interval_s=0.05,
    )
    runtime.start()
    try:
        assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"actor": "operator", "risk_approver": "risk"},
            timeout_s=2,
        )
        assert command["status"] == "failed"
        assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
        assert not runtime.ready
        with pytest.raises(AttributeError):
            runtime.safety_only = False
    finally:
        runtime.stop()


@pytest.mark.unit
def test_resume_failure_keeps_hard_halt_latched(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.HALTED)
    runtime.start()
    try:
        runtime.alerts.webhook_url = "https://alerts.example"
        runtime.alerts.consecutive_failures = 3
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"actor": "operator", "risk_approver": "risk"},
            timeout_s=2,
        )
        assert command["status"] == "failed"
        assert journal.get_mode() is SystemMode.HALTED
    finally:
        runtime.stop()


@pytest.mark.unit
def test_single_instance_lock_rejects_second_owner(tmp_path):
    first = SingleInstanceLock(tmp_path / "runtime.lock")
    second = SingleInstanceLock(tmp_path / "runtime.lock")
    first.acquire()
    try:
        with pytest.raises(RuntimeError, match="另一个交易实例"):
            second.acquire()
    finally:
        first.release()
