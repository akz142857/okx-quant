"""单写者执行协调器和响应丢失故障测试。"""

from decimal import Decimal

import pytest
import requests

from okx_quant.application.execution import ExecutionCoordinator, ExecutionRequest
from okx_quant.domain.orders import OrderState, SystemMode
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal


def _coordinator(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    return ExecutionCoordinator(exchange, journal), exchange, journal


@pytest.mark.unit
def test_submit_persists_and_projects_filled_order(tmp_path):
    coordinator, exchange, journal = _coordinator(tmp_path)
    exchange.set_fill_price(50_000)
    intent = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
        reserved_quote=Decimal("5000"),
    ))
    assert intent.state is OrderState.FILLED
    assert exchange.orders[0].cl_ord_id == intent.cl_ord_id
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("0.1")


@pytest.mark.unit
def test_projection_failure_after_exchange_response_halts_new_risk(
    tmp_path,
    monkeypatch,
):
    coordinator, exchange, journal = _coordinator(tmp_path)
    original_apply = journal.apply_exchange_order
    calls = 0

    def fail_first_projection(order):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("disk full")
        return original_apply(order)

    monkeypatch.setattr(
        journal,
        "apply_exchange_order",
        fail_first_projection,
    )
    with pytest.raises(RuntimeError, match="投影失败"):
        coordinator.submit(ExecutionRequest(
            inst_id="BTC-USDT",
            side="buy",
            base_qty=Decimal("0.1"),
        ))
    assert len(exchange.orders) == 1
    assert not coordinator.projection_healthy
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"]
        == "page.order_projection_failed_after_exchange_response"
        for row in journal.get_unpublished_outbox()
    )
    with pytest.raises(RuntimeError, match="订单投影已失败"):
        coordinator.submit(ExecutionRequest(
            inst_id="ETH-USDT",
            side="buy",
            base_qty=Decimal("1"),
        ))
    assert len(exchange.orders) == 1


@pytest.mark.unit
def test_submit_passes_exchange_enforced_slippage_limit(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(
        exchange,
        journal,
        max_slippage_ratio=Decimal("0.0123"),
    )
    coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
    ))
    assert exchange.orders[0].max_slippage == Decimal("0.0123")


@pytest.mark.unit
def test_lost_response_becomes_unknown_and_is_not_retried(tmp_path):
    coordinator, exchange, journal = _coordinator(tmp_path)
    exchange.queue_order_outcome(
        state="filled",
        fill_size=0.1,
        fill_price=50_000,
        lose_response=True,
    )
    intent = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
        reserved_quote=Decimal("5000"),
    ))
    assert intent.state is OrderState.UNKNOWN
    assert len(exchange.orders) == 1
    assert journal.get_mode() is SystemMode.DEGRADED
    assert any(
        row["event_name"] == "page.order_submission_unknown"
        for row in journal.get_unpublished_outbox()
    )
    # 交易所其实已经接受，可通过 clOrdId 找到，证明此时重试会重复买入。
    remote = exchange.get_order_status("BTC-USDT", cl_ord_id=intent.cl_ord_id)
    assert remote.state is OrderState.FILLED


@pytest.mark.unit
@pytest.mark.parametrize("status_code", [408, 502])
def test_http_5xx_submission_is_ambiguous_and_keeps_reservation(
    tmp_path,
    monkeypatch,
    status_code,
):
    coordinator, exchange, journal = _coordinator(tmp_path)
    response = requests.Response()
    response.status_code = status_code
    error = requests.HTTPError("bad gateway", response=response)
    monkeypatch.setattr(
        exchange,
        "place_market_order",
        lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )
    intent = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.1"),
        reserved_quote=Decimal("5000"),
    ))
    assert intent.state is OrderState.UNKNOWN
    assert journal.get_mode() is SystemMode.DEGRADED
    assert journal.active_reserved_quote() == Decimal("5000")
    assert any(
        row["event_name"] == "page.order_submission_unknown"
        for row in journal.get_unpublished_outbox()
    )


@pytest.mark.unit
def test_buy_is_rejected_outside_ready_without_creating_intent(tmp_path):
    coordinator, _, journal = _coordinator(tmp_path)
    journal.set_mode(SystemMode.DEGRADED)
    with pytest.raises(RuntimeError, match="禁止新增风险"):
        coordinator.submit(ExecutionRequest(
            inst_id="BTC-USDT",
            side="buy",
            base_qty=Decimal("0.1"),
        ))
    assert journal.list_nonterminal_intents() == []


@pytest.mark.unit
def test_buy_rechecks_entry_guard_immediately_before_exchange_post(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "journal.db")
    journal.set_mode(SystemMode.READY)
    generation = [0]
    coordinator = ExecutionCoordinator(
        exchange,
        journal,
        entry_guard=lambda: (generation[0] == 0, generation[0]),
    )
    original_record = journal.record_event

    def record_and_disconnect(event_name, **kwargs):
        result = original_record(event_name, **kwargs)
        if event_name == "order_submitting":
            generation[0] += 1
        return result

    monkeypatch.setattr(journal, "record_event", record_and_disconnect)
    with pytest.raises(RuntimeError, match="门禁"):
        coordinator.submit(ExecutionRequest(
            inst_id="BTC-USDT",
            side="buy",
            base_qty=Decimal("0.1"),
        ))
    assert exchange.orders == []
    assert journal.intent_state_counts()["canceled"] == 1


@pytest.mark.unit
def test_sell_is_allowed_while_halted(tmp_path):
    coordinator, exchange, journal = _coordinator(tmp_path)
    journal.set_mode(SystemMode.HALTED)
    intent = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="sell",
        base_qty=Decimal("0.1"),
    ))
    assert intent.state is OrderState.FILLED
    assert exchange.orders[-1].side == "sell"


@pytest.mark.unit
def test_background_queue_has_single_execution_thread(tmp_path):
    coordinator, exchange, _ = _coordinator(tmp_path)
    coordinator.start()
    futures = [
        coordinator.enqueue(ExecutionRequest(
            inst_id=f"C{i}-USDT",
            side="sell",
            base_qty=Decimal("1"),
        ))
        for i in range(5)
    ]
    assert all(f.result(timeout=2).state is OrderState.FILLED for f in futures)
    coordinator.stop()
    assert len(exchange.orders) == 5
