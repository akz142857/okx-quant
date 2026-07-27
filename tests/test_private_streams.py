"""私有 WebSocket 订单投影测试。"""

from decimal import Decimal

import pytest

from okx_quant.application.execution import ExecutionCoordinator, ExecutionRequest
from okx_quant.application.protection import ProtectionManager
from okx_quant.client.websocket import (
    WS_DISCONNECT_DETECTION_BOUND_SECONDS,
    ConnectionState,
    OKXWebSocketClient,
)
from okx_quant.domain.orders import OrderState, SystemMode
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.infrastructure.okx.streams import PrivateStreamService, map_order_event


@pytest.mark.unit
def test_websocket_blackhole_detection_bound_is_within_slo():
    assert WS_DISCONNECT_DETECTION_BOUND_SECONDS <= 20


@pytest.mark.unit
def test_map_order_event_uses_accumulated_fill_size():
    event = map_order_event({
        "instId": "BTC-USDT",
        "side": "buy",
        "state": "partially_filled",
        "ordId": "o1",
        "clOrdId": "c1",
        "sz": "0.1",
        "accFillSz": "0.08",
        "fillSz": "0.01",
        "avgPx": "50000",
    })
    assert event.acc_fill_qty == Decimal("0.08")
    assert event.state is OrderState.PARTIALLY_FILLED


@pytest.mark.unit
def test_malformed_filled_order_fact_halts_and_pages(tmp_path):
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    service = PrivateStreamService(
        OKXWebSocketClient(),
        ExecutionCoordinator(FakeExchange(), journal),
        journal,
    )
    with pytest.raises(ValueError, match="accFillSz"):
        service._on_orders([{
            "instId": "BTC-USDT",
            "side": "buy",
            "state": "filled",
            "ordId": "o-invalid",
            "clOrdId": "c-invalid",
            "sz": "1",
            "accFillSz": "malformed",
            "avgPx": "50000",
        }])
    assert journal.get_mode() is SystemMode.HALTED
    assert (
        journal.get_unpublished_outbox()[0]["event_name"]
        == "page.private_order_fact_invalid"
    )


@pytest.mark.unit
def test_any_order_subscription_dispatches_instrument_messages():
    ws = OKXWebSocketClient()
    received = []
    ws.subscribe_orders("ANY", "", lambda rows: received.extend(rows))
    ws._dispatch({
        "arg": {"channel": "orders", "instId": "BTC-USDT"},
        "data": [{"ordId": "o1"}],
    })
    assert received == [{"ordId": "o1"}]


@pytest.mark.unit
def test_duplicate_and_out_of_order_ws_updates_are_idempotent(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal)
    exchange.queue_order_outcome(state="live")
    intent = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    ws = OKXWebSocketClient()
    service = PrivateStreamService(ws, coordinator, journal)

    first = {
        "instId": "BTC-USDT", "side": "buy", "state": "partially_filled",
        "ordId": intent.exchange_ord_id, "clOrdId": intent.cl_ord_id,
        "sz": "0.1", "accFillSz": "0.08", "avgPx": "50000",
        "tradeId": "t1",
    }
    service._on_orders([first, first])
    stale = {**first, "accFillSz": "0.02", "tradeId": "t0"}
    service._on_orders([stale])
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("0.08")


@pytest.mark.unit
def test_external_ws_order_is_imported_and_degrades(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal)
    service = PrivateStreamService(OKXWebSocketClient(), coordinator, journal)
    service._on_orders([{
        "instId": "ETH-USDT", "side": "buy", "state": "live",
        "ordId": "external-1", "clOrdId": "EXT01", "sz": "1",
        "accFillSz": "0",
    }])
    assert journal.find_intent(exchange_ord_id="external-1") is not None
    assert journal.get_mode() is SystemMode.DEGRADED


@pytest.mark.unit
def test_external_filled_buy_from_ws_gets_immediate_exchange_protection(
    tmp_path,
):
    exchange = FakeExchange()
    exchange.set_ticker("BTC-USDT", last=50_000)
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal)
    ProtectionManager(exchange, journal).attach_to(coordinator)
    service = PrivateStreamService(
        OKXWebSocketClient(), coordinator, journal
    )
    service._on_orders([{
        "instId": "BTC-USDT",
        "side": "buy",
        "state": "filled",
        "ordId": "external-filled-1",
        "clOrdId": "MANUALBUY01",
        "sz": "0.1",
        "accFillSz": "0.1",
        "avgPx": "50000",
        "tradeId": "external-trade-1",
    }])
    assert Decimal(
        journal.get_position("BTC-USDT")["base_qty"]
    ) == Decimal("0.1")
    assert journal.has_active_protection(
        "BTC-USDT", Decimal("0.1")
    )
    assert journal.get_mode() is SystemMode.DEGRADED


@pytest.mark.unit
def test_ws_disconnect_freezes_entries_but_not_exit_semantics(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal)
    ws = OKXWebSocketClient()
    service = PrivateStreamService(ws, coordinator, journal)
    service._on_state("private", ConnectionState.BACKOFF)
    assert journal.get_mode() is SystemMode.DEGRADED
    with pytest.raises(RuntimeError):
        coordinator.submit(ExecutionRequest(
            inst_id="BTC-USDT", side="buy", base_qty=Decimal("0.1")
        ))
    sell = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT", side="sell", base_qty=Decimal("0.1")
    ))
    assert sell.state is OrderState.FILLED


@pytest.mark.unit
def test_algo_projection_failure_halts_and_pages(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal)

    def fail_projection(_rows):
        raise RuntimeError("projection failed")

    service = PrivateStreamService(
        OKXWebSocketClient(),
        coordinator,
        journal,
        on_algo_event=fail_projection,
    )
    with pytest.raises(RuntimeError, match="projection failed"):
        service._on_algos([{"algoId": "a1"}])
    assert journal.get_mode() is SystemMode.HALTED
    assert (
        journal.get_unpublished_outbox()[0]["event_name"]
        == "page.private_algo_projection_failed"
    )


@pytest.mark.unit
def test_private_event_is_not_ready_until_projection_finishes(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "journal.db")
    coordinator = ExecutionCoordinator(exchange, journal)
    ws = OKXWebSocketClient()
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    service = PrivateStreamService(ws, coordinator, journal)
    service.mark_baseline_complete()
    observed = []

    def inspect_inflight(_rows):
        observed.append((service.ready, service.event_sequence))

    monkeypatch.setattr(service, "_project_orders", inspect_inflight)
    service._on_orders([])
    assert observed == [(False, 1)]
    assert service.ready


@pytest.mark.unit
def test_balance_event_freezes_entries_until_rest_reconciliation(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    service = PrivateStreamService(
        OKXWebSocketClient(),
        ExecutionCoordinator(exchange, journal),
        journal,
    )
    service._on_balance([{"ccy": "BTC", "cashBal": "1"}])
    assert journal.get_mode() is SystemMode.DEGRADED
