"""Demo validation probe durable saga 与 UNKNOWN 恢复测试。"""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pandas as pd
import pytest
import requests

from okx_quant.application.demo_probe import (
    PROBE_SOURCE,
    DemoProbeSaga,
    probe_schedule_sha256,
    validate_formal_probe_schedule,
    validate_probe_schedule,
)
from okx_quant.application.execution import (
    ExecutionCoordinator,
    ExecutionRequest,
)
from okx_quant.application.protection import (
    ExitCoordinator,
    ProtectionManager,
)
from okx_quant.domain.orders import (
    OrderState,
    SystemMode,
    probe_client_order_ids,
)
from okx_quant.exchange import InstrumentInfo
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal
from scripts import generate_probe_schedule


def _saga(
    tmp_path,
    *,
    schedule_path="",
    require_formal_schedule=False,
    soak_epoch_id="",
):
    exchange = FakeExchange()
    exchange.set_account_identity("demo-account")
    exchange.set_balance(total=5000, quote_avail=5000)
    exchange.set_ticker(
        "BTC-USDT",
        last=50000,
        bid=49990,
        ask=50010,
    )
    exchange.set_fill_price(50000)
    exchange.set_instrument(InstrumentInfo(
        inst_id="BTC-USDT",
        base_ccy="BTC",
        quote_ccy="USDT",
        lot_size=Decimal("0.00001"),
        min_size=Decimal("0.00001"),
        tick_size=Decimal("0.1"),
    ))
    exchange.set_candles(
        "BTC-USDT",
        "1m",
        pd.DataFrame({
            "ts": range(30),
            "open": [50000] * 30,
            "high": [50000] * 30,
            "low": [50000] * 30,
            "close": [50000] * 30,
            "vol": [1] * 30,
            "vol_ccy": [50000] * 30,
        }),
    )

    def update_balance(order):
        if order.side == "buy":
            exchange.set_holding(
                "BTC",
                balance=order.size,
                available=order.size,
            )
        else:
            exchange.set_holding("BTC", balance=0, available=0)

    exchange.on_order(update_balance)
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.READY)
    execution = ExecutionCoordinator(exchange, journal)
    protection = ProtectionManager(exchange, journal)
    protection.attach_to(execution)
    exit_coordinator = ExitCoordinator(
        exchange,
        journal,
        execution,
        protection,
    )
    saga = DemoProbeSaga(
        exchange,
        journal,
        execution,
        protection,
        exit_coordinator,
        environment="demo",
        shadow_mode=False,
        account_uid="demo-account",
        allowed_instruments=("BTC-USDT",),
        probe_schedule_path=schedule_path,
        require_formal_schedule=require_formal_schedule,
        soak_epoch_id=soak_epoch_id,
    )
    return exchange, journal, saga


def _formal_schedule(first_day: datetime) -> dict:
    created = first_day.astimezone(UTC) - timedelta(days=1)
    spreads = ((0.0, 3.0), (3.0, 10.0))
    volatilities = ((0.0, 15.0), (15.0, 80.0))
    cells = [
        (time_bin, spread, volatility)
        for _cycle in range(2)
        for time_bin in range(4)
        for spread in spreads
        for volatility in volatilities
    ]
    cells.remove((0, spreads[0], volatilities[0]))
    cells.remove((1, spreads[1], volatilities[1]))
    slots = []
    for index, (time_bin, spread, volatility) in enumerate(cells):
        day = first_day.date() + timedelta(days=index)
        started = datetime.combine(
            day,
            datetime.min.time(),
            tzinfo=UTC,
        ) + timedelta(hours=time_bin * 6)
        slots.append({
            "day": day.isoformat(),
            "slot": 1,
            "inst_id": "BTC-USDT",
            "direction": "buy_then_exit",
            "window_start": started.isoformat(),
            "window_end": (started + timedelta(hours=4)).isoformat(),
            "spread_min_bps": spread[0],
            "spread_max_bps": spread[1],
            "volatility_min_bps": volatility[0],
            "volatility_max_bps": volatility[1],
        })
    return validate_formal_probe_schedule({
        "version": 2,
        "action": "precommit-demo-probe-schedule",
        "schedule_id": "formal-db-capability-fixture",
        "created_at": created.isoformat(),
        "slots": slots,
    })


def test_probe_requires_exact_precommitted_window_and_buckets(tmp_path):
    now = datetime.now(UTC)
    schedule = validate_probe_schedule({
        "version": 2,
        "action": "precommit-demo-probe-schedule",
        "schedule_id": "epoch-slot-fixture",
        "created_at": (now - timedelta(days=1)).isoformat(),
        "slots": [{
            "day": now.date().isoformat(),
            "slot": 1,
            "inst_id": "BTC-USDT",
            "direction": "buy_then_exit",
            "window_start": (now - timedelta(minutes=5)).isoformat(),
            "window_end": (now + timedelta(minutes=5)).isoformat(),
            "spread_min_bps": 0,
            "spread_max_bps": 10,
            "volatility_min_bps": 0,
            "volatility_max_bps": 10,
        }],
    })
    path = tmp_path / "probe-schedule.json"
    path.write_text(json.dumps(schedule), encoding="utf-8")
    _exchange, journal, saga = _saga(
        tmp_path,
        schedule_path=path,
    )

    row = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="1" * 32,
        now=now,
    )
    assert row["state"] == "PREPARED"
    sample = journal.list_events("probe_schedule_sample")[-1]["payload"]
    assert sample["compliant"] is True
    assert sample["schedule_sha256"] == probe_schedule_sha256(schedule)
    assert sample["probe_id"] == "1" * 32

    _other_exchange, other_journal, other_saga = _saga(
        tmp_path / "other",
        schedule_path=path,
    )
    with pytest.raises(RuntimeError, match="slot_not_precommitted"):
        other_saga.prepare(
            inst_id="BTC-USDT",
            nominal_usdt=Decimal("5"),
            slot=2,
            probe_id="2" * 32,
            now=now,
        )
    other_journal.close()
    journal.close()


def test_formal_probe_db_capability_binds_epoch_schedule_day_and_slot(
    tmp_path,
):
    first_day = datetime(2026, 7, 29, tzinfo=UTC)
    schedule = _formal_schedule(first_day)
    path = tmp_path / "formal-schedule.json"
    path.write_text(json.dumps(schedule), encoding="utf-8")
    _exchange, journal, saga = _saga(
        tmp_path,
        schedule_path=path,
        require_formal_schedule=True,
        soak_epoch_id="formal-epoch-2026-07",
    )
    target = next(
        slot
        for slot in schedule["slots"]
        if slot["spread_min_bps"] == 3.0
        and slot["volatility_min_bps"] == 0.0
    )
    now = datetime.fromisoformat(target["window_start"])
    now += timedelta(minutes=1)

    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="8" * 32,
        now=now,
    )
    assert prepared["state"] == "PREPARED"
    assert saga.advance(prepared["probe_id"], owner="formal-worker")[
        "state"
    ] == "DONE"

    with pytest.raises(RuntimeError, match="frozen epoch/schedule/day/slot"):
        journal.create_probe_run(
            probe_id="9" * 32,
            account_uid="demo-account",
            utc_day=now.date().isoformat(),
            slot=2,
            inst_id="BTC-USDT",
            nominal_usdt=Decimal("5"),
            buy_cl_ord_id="b" * 32,
            algo_cl_ord_id="a" * 32,
            baseline_base_balance=Decimal("0"),
            soak_epoch_id="formal-epoch-2026-07",
            formal_schedule_sha256=saga.probe_schedule_hash,
        )
    with pytest.raises(RuntimeError, match="配额已耗尽"):
        journal.create_probe_run(
            probe_id="7" * 32,
            account_uid="demo-account",
            utc_day=now.date().isoformat(),
            slot=1,
            inst_id="BTC-USDT",
            nominal_usdt=Decimal("5"),
            buy_cl_ord_id="c" * 32,
            algo_cl_ord_id="d" * 32,
            baseline_base_balance=Decimal("0"),
            soak_epoch_id="formal-epoch-2026-07",
            formal_schedule_sha256=saga.probe_schedule_hash,
        )
    with pytest.raises(RuntimeError, match="已冻结"):
        journal.bind_formal_probe_schedule(
            account_uid="demo-account",
            soak_epoch_id="other-epoch",
            schedule=schedule,
            schedule_sha256=saga.probe_schedule_hash,
        )
    journal.close()


def test_formal_schedule_forbids_missing_days_and_time_bucket_bias():
    created = datetime(2026, 7, 1, tzinfo=UTC)
    cells = [
        (time_bin, spread, volatility)
        for _cycle in range(2)
        for time_bin in range(4)
        for spread in ((0.0, 3.0), (3.0, 10.0))
        for volatility in ((0.0, 15.0), (15.0, 80.0))
    ]
    cells.remove((0, (0.0, 3.0), (0.0, 15.0)))
    cells.remove((1, (3.0, 10.0), (15.0, 80.0)))
    slots = []
    for index in range(30):
        day = (created + timedelta(days=index + 1)).date()
        time_bin, spread, volatility = cells[index]
        hour = time_bin * 6
        started = datetime.combine(
            day,
            datetime.min.time(),
            tzinfo=UTC,
        ) + timedelta(hours=hour)
        slots.append({
            "day": day.isoformat(),
            "slot": 1,
            "inst_id": "BTC-USDT",
            "direction": "buy_then_exit",
            "window_start": started.isoformat(),
            "window_end": (started + timedelta(minutes=30)).isoformat(),
            "spread_min_bps": spread[0],
            "spread_max_bps": spread[1],
            "volatility_min_bps": volatility[0],
            "volatility_max_bps": volatility[1],
        })
    schedule = {
        "version": 2,
        "action": "precommit-demo-probe-schedule",
        "schedule_id": "formal-fixture",
        "created_at": created.isoformat(),
        "slots": slots,
    }
    assert validate_formal_probe_schedule(schedule) == schedule
    biased = {**schedule, "slots": [
        {
            **slot,
            "window_start": (
                datetime.fromisoformat(slot["window_start"])
                .replace(hour=8)
                .isoformat()
            ),
            "window_end": (
                datetime.fromisoformat(slot["window_start"])
                .replace(hour=8, minute=30)
                .isoformat()
            ),
        }
        for slot in slots
    ]}
    with pytest.raises(ValueError, match="四个 UTC 时段"):
        validate_formal_probe_schedule(biased)

    uneven_hours = [0] * 21 + [6] * 3 + [12] * 3 + [18] * 3
    uneven_time_bins = {
        **schedule,
        "slots": [
            {
                **slot,
                "window_start": (
                    datetime.fromisoformat(slot["window_start"])
                    .replace(hour=uneven_hours[index])
                    .isoformat()
                ),
                "window_end": (
                    datetime.fromisoformat(slot["window_start"])
                    .replace(
                        hour=uneven_hours[index],
                        minute=30,
                    )
                    .isoformat()
                ),
            }
            for index, slot in enumerate(slots)
        ],
    }
    with pytest.raises(ValueError, match="四个 UTC 时段"):
        validate_formal_probe_schedule(uneven_time_bins)

    uneven_liquidity = {
        **schedule,
        "slots": [
            {
                **slot,
                "spread_min_bps": 0 if index < 21 else 3,
                "spread_max_bps": 3 if index < 21 else 10,
            }
            for index, slot in enumerate(slots)
        ],
    }
    with pytest.raises(ValueError, match="spread/volatility"):
        validate_formal_probe_schedule(uneven_liquidity)

    confounded = {
        **schedule,
        "slots": [
            {
                **slot,
                "spread_min_bps": 0 if index % 2 == 0 else 3,
                "spread_max_bps": 3 if index % 2 == 0 else 10,
                "volatility_min_bps": 0 if index % 2 == 0 else 15,
                "volatility_max_bps": 15 if index % 2 == 0 else 80,
            }
            for index, slot in enumerate(slots)
        ],
    }
    with pytest.raises(ValueError, match="joint strata"):
        validate_formal_probe_schedule(confounded)


def test_formal_schedule_generator_balances_joint_cells_without_crossing_day(
    tmp_path,
    monkeypatch,
):
    class LatestChoiceRandom:
        @staticmethod
        def sample(population, count):
            return list(population)[:count]

        @staticmethod
        def shuffle(_values):
            return None

        @staticmethod
        def randrange(start, stop=None):
            return (start - 1) if stop is None else (stop - 1)

    output = tmp_path / "formal-schedule.json"
    start_day = (datetime.now(UTC) + timedelta(days=2)).date()
    monkeypatch.setattr(
        generate_probe_schedule.secrets,
        "SystemRandom",
        lambda: LatestChoiceRandom(),
    )
    monkeypatch.setattr(sys, "argv", [
        "generate_probe_schedule.py",
        "--start-day",
        start_day.isoformat(),
        "--inst",
        "BTC-USDT",
        "--inst",
        "ETH-USDT",
        "--output",
        str(output),
    ])

    assert generate_probe_schedule.main() == 0
    schedule = json.loads(output.read_text(encoding="utf-8"))
    assert validate_formal_probe_schedule(schedule) == schedule
    assert all(
        datetime.fromisoformat(slot["window_start"]).date()
        == datetime.fromisoformat(slot["window_end"]).date()
        for slot in schedule["slots"]
    )


def test_probe_saga_uses_stable_ids_and_converges_without_duplicate_buy(
    tmp_path,
):
    exchange, journal, saga = _saga(tmp_path)
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="a" * 32,
    )
    assert (
        prepared["buy_cl_ord_id"],
        prepared["algo_cl_ord_id"],
    ) == probe_client_order_ids("a" * 32)

    result = saga.advance("a" * 32, owner="worker-a")

    assert result["state"] == "DONE", result
    assert len([order for order in exchange.orders if order.side == "buy"]) == 1
    assert len([order for order in exchange.orders if order.side == "sell"]) == 1
    intent = journal.find_intent(cl_ord_id=prepared["buy_cl_ord_id"])
    assert intent is not None
    assert intent.source == "demo_validation_probe"
    assert intent.probe_id == "a" * 32
    protection = journal.find_protection(
        algo_cl_ord_id=prepared["algo_cl_ord_id"]
    )
    assert protection is not None
    journal.close()


def test_reclaim_after_pre_post_barrier_never_replays_buy(tmp_path):
    exchange, journal, saga = _saga(tmp_path)
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="b" * 32,
    )
    lease = journal.acquire_probe_lease(
        prepared["probe_id"],
        "crashed-worker",
        ttl_s=1,
    )
    assert lease is not None
    token, row = lease
    journal.transition_probe_run(
        row["probe_id"],
        owner="crashed-worker",
        fencing_token=token,
        expected_states=("PREPARED",),
        new_state="BUY_SUBMITTING",
    )
    journal.release_probe_lease(
        row["probe_id"],
        owner="crashed-worker",
        fencing_token=token,
    )

    result = saga.reclaim_once(owner="recovery-worker")[0]

    assert result["state"] == "REJECTED"
    assert exchange.orders == []
    journal.close()


@pytest.mark.parametrize(
    ("exchange_state", "expected_cancel_count"),
    [
        ("acknowledged", 1),
        ("live", 1),
        ("canceled", 0),
    ],
)
def test_nonfilled_buy_is_queried_then_canceled_and_rejected(
    tmp_path,
    monkeypatch,
    exchange_state,
    expected_cancel_count,
):
    exchange, journal, saga = _saga(tmp_path)
    exchange.queue_order_outcome(state=exchange_state)
    original_cancel = exchange.cancel_order
    cancel_count = 0

    def observed_cancel(*args, **kwargs):
        nonlocal cancel_count
        cancel_count += 1
        return original_cancel(*args, **kwargs)

    monkeypatch.setattr(exchange, "cancel_order", observed_cancel)
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="e" * 32,
    )

    result = saga.advance(prepared["probe_id"], owner="worker")

    assert result["state"] == "REJECTED"
    assert cancel_count == expected_cancel_count
    assert len([item for item in exchange.orders if item.side == "buy"]) == 1
    intent = journal.find_intent(cl_ord_id=prepared["buy_cl_ord_id"])
    assert intent is not None
    assert intent.state in {OrderState.CANCELED, OrderState.REJECTED}
    assert intent.acc_fill_qty == 0
    journal.close()


@pytest.mark.parametrize("exchange_state", ["partially_filled", "canceled"])
def test_partial_or_canceled_fill_is_protected_then_cleaned(
    tmp_path,
    exchange_state,
):
    exchange, journal, saga = _saga(tmp_path)
    partial_qty = Decimal("0.00005")

    def update_partial_balance(order):
        if order.side == "buy":
            exchange.set_holding(
                "BTC",
                balance=partial_qty,
                available=partial_qty,
            )
        else:
            exchange.set_holding("BTC", balance=0, available=0)

    exchange.on_order(update_partial_balance)
    exchange.queue_order_outcome(
        state=exchange_state,
        fill_size=partial_qty,
        fill_price=Decimal("50000"),
    )
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="f" * 32,
    )

    result = saga.advance(prepared["probe_id"], owner="worker")

    assert result["state"] == "DONE", result
    assert [item.side for item in exchange.orders] == ["buy", "sell"]
    intent = journal.find_intent(cl_ord_id=prepared["buy_cl_ord_id"])
    assert intent is not None
    assert intent.acc_fill_qty == partial_qty
    protection = journal.find_protection(
        algo_cl_ord_id=prepared["algo_cl_ord_id"]
    )
    assert protection is not None
    samples = journal.list_events("protection_activation_slo_sample")
    assert len(samples) == 1
    assert samples[0]["payload"]["success"] is True
    assert samples[0]["payload"]["probe_id"] == prepared["probe_id"]

    saga.reclaim_once(owner="replay")
    assert len(journal.list_events("protection_activation_slo_sample")) == 1
    journal.close()


def test_reclaimer_protects_rest_discovered_partial_before_cancel(
    tmp_path,
    monkeypatch,
):
    exchange, journal, saga = _saga(tmp_path)
    partial_qty = Decimal("0.00005")
    exchange.queue_order_outcome(state="live")
    original_status = exchange.get_order_status
    original_cancel = exchange.cancel_order
    injected = False

    def reveal_partial(*args, **kwargs):
        nonlocal injected
        current = original_status(*args, **kwargs)
        if not injected:
            injected = True
            exchange.set_order_status(
                current.ord_id,
                state=OrderState.PARTIALLY_FILLED,
                acc_fill_size=partial_qty,
                fill_price=Decimal("50000"),
                trade_id="rest-partial",
            )
            exchange.set_holding(
                "BTC",
                balance=partial_qty,
                available=partial_qty,
            )
            current = original_status(*args, **kwargs)
        return current

    def assert_protected_then_cancel(*args, **kwargs):
        assert journal.has_active_protection("BTC-USDT", partial_qty)
        return original_cancel(*args, **kwargs)

    def update_sell_balance(order):
        if order.side == "sell":
            exchange.set_holding("BTC", balance=0, available=0)

    exchange.on_order(update_sell_balance)
    monkeypatch.setattr(exchange, "get_order_status", reveal_partial)
    monkeypatch.setattr(exchange, "cancel_order", assert_protected_then_cancel)
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="5" * 32,
    )

    result = saga.advance(prepared["probe_id"], owner="reclaimer")

    assert result["state"] == "DONE", result
    assert [item.side for item in exchange.orders] == ["buy", "sell"]
    assert journal.find_protection(
        algo_cl_ord_id=prepared["algo_cl_ord_id"]
    ) is not None
    journal.close()


def test_failed_protection_attempt_remains_in_slo_denominator(tmp_path):
    exchange, journal, saga = _saga(tmp_path)
    exchange.queue_algo_outcome(reject=True)
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="0" * 32,
    )

    result = saga.advance(prepared["probe_id"], owner="worker")

    assert result["state"] == "MANUAL_REVIEW"
    samples = journal.list_events("protection_activation_slo_sample")
    assert len(samples) == 1
    assert samples[0]["payload"]["success"] is False
    assert samples[0]["payload"]["probe_id"] == prepared["probe_id"]
    saga.reclaim_once(owner="replay")
    assert len(journal.list_events("protection_activation_slo_sample")) == 1
    journal.close()


def test_open_buy_cancel_resolution_is_bounded_without_reposting(
    tmp_path,
    monkeypatch,
):
    exchange, journal, saga = _saga(tmp_path)
    exchange.queue_order_outcome(state="live")
    cancel_count = 0

    def unresolved_cancel(*_args, **_kwargs):
        nonlocal cancel_count
        cancel_count += 1
        raise requests.Timeout("cancel acknowledgement lost")

    monkeypatch.setattr(exchange, "cancel_order", unresolved_cancel)
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="1" * 32,
    )
    unresolved = saga.advance(prepared["probe_id"], owner="worker")
    assert unresolved["state"] == "BUY_SUBMITTING"
    with journal.transaction() as connection:
        connection.execute(
            """
            UPDATE order_intents SET created_at=?, updated_at=?
            WHERE cl_ord_id=?
            """,
            (
                time.time() - 31,
                time.time() - 31,
                prepared["buy_cl_ord_id"],
            ),
        )

    final = saga.advance(prepared["probe_id"], owner="reclaimer")

    assert final["state"] == "MANUAL_REVIEW"
    assert journal.get_mode() is SystemMode.HALTED
    assert cancel_count == 2
    assert len([item for item in exchange.orders if item.side == "buy"]) == 1
    journal.close()


@pytest.mark.parametrize(
    "crash_state",
    [
        "PREPARED",
        "BUY_SUBMITTING",
        "BUY_UNKNOWN",
        "BUY_FILLED",
        "PROTECTING",
        "PROTECTED",
        "CLEANING",
    ],
)
def test_reclaimer_resumes_each_durable_barrier_with_fencing(
    tmp_path,
    crash_state,
):
    exchange, journal, saga = _saga(tmp_path)
    probe_id = "2" * 32
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id=probe_id,
    )
    if crash_state != "PREPARED":
        setup = journal.acquire_probe_lease(
            probe_id,
            "setup-worker",
            ttl_s=30,
        )
        assert setup is not None
        setup_token, setup_row = setup
        journal.transition_probe_run(
            probe_id,
            owner="setup-worker",
            fencing_token=setup_token,
            expected_states=(setup_row["state"],),
            new_state="BUY_SUBMITTING",
        )
        intent = saga.execution.submit(ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.0001"),
            cl_ord_id=prepared["buy_cl_ord_id"],
            source=PROBE_SOURCE,
            probe_id=probe_id,
                probe_lease_owner="setup-worker",
                probe_fencing_token=setup_token,
        ))
        assert intent.state is OrderState.FILLED
        journal.release_probe_lease(
            probe_id,
            owner="setup-worker",
            fencing_token=setup_token,
        )

    crashed = journal.acquire_probe_lease(
        probe_id,
        "crashed-worker",
        ttl_s=30,
    )
    assert crashed is not None
    crashed_token, crashed_row = crashed
    if crash_state not in {"PREPARED", "BUY_SUBMITTING"}:
        crashed_row = journal.transition_probe_run(
            probe_id,
            owner="crashed-worker",
            fencing_token=crashed_token,
            expected_states=("BUY_SUBMITTING",),
            new_state=crash_state,
            changes={"buy_intent_id": intent.intent_id},
        )
    with journal.transaction() as connection:
        connection.execute(
            "UPDATE probe_runs SET lease_expires_at=? WHERE probe_id=?",
            (time.time() - 1, probe_id),
        )

    reclaimed = saga.reclaim_once(owner="runtime-reclaimer")

    assert reclaimed[0]["state"] == "DONE", reclaimed
    final = journal.get_probe_run(probe_id)
    assert final is not None
    assert final["fencing_token"] > crashed_token
    assert final["lease_owner"] == ""
    assert [item.side for item in exchange.orders] == ["buy", "sell"]
    with pytest.raises(RuntimeError, match="lease/fence/state"):
        journal.transition_probe_run(
            probe_id,
            owner="crashed-worker",
            fencing_token=crashed_token,
            expected_states=(crashed_row["state"],),
            new_state="FAILED",
        )
    journal.close()


def test_lost_buy_ack_is_found_by_stable_clordid_without_second_buy(
    tmp_path,
):
    exchange, journal, saga = _saga(tmp_path)
    exchange.queue_order_outcome(
        state="filled",
        fill_price=50000,
        lose_response=True,
    )
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="c" * 32,
    )

    result = saga.advance(prepared["probe_id"], owner="worker")

    assert result["state"] == "DONE", result
    assert len([order for order in exchange.orders if order.side == "buy"]) == 1
    assert result["duplicate_buy_count"] == 0
    journal.close()


def test_probe_policy_rejects_non_demo_shadow_and_over_ten(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    execution = ExecutionCoordinator(exchange, journal)
    protection = ProtectionManager(exchange, journal)
    exit_coordinator = ExitCoordinator(
        exchange,
        journal,
        execution,
        protection,
    )
    with pytest.raises(ValueError, match="environment=demo"):
        DemoProbeSaga(
            exchange,
            journal,
            execution,
            protection,
            exit_coordinator,
            environment="production",
            shadow_mode=False,
            account_uid="account",
            allowed_instruments=("BTC-USDT",),
        )
    journal.close()


def test_uncertain_buy_stays_reserved_then_halts_for_manual_review(
    tmp_path,
    monkeypatch,
):
    exchange, journal, saga = _saga(tmp_path)

    def timeout_before_fact(*_args, **_kwargs):
        raise requests.Timeout("no response and no visible exchange fact")

    monkeypatch.setattr(exchange, "place_market_order", timeout_before_fact)
    prepared = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="d" * 32,
    )
    unresolved = saga.advance(prepared["probe_id"], owner="worker")
    assert unresolved["state"] == "BUY_UNKNOWN"
    assert journal.active_reserved_quote() >= 0
    with journal.transaction() as connection:
        connection.execute(
            """
            UPDATE order_intents SET updated_at=?
            WHERE cl_ord_id=?
            """,
            (time.time() - 31, prepared["buy_cl_ord_id"]),
        )

    final = saga.advance(prepared["probe_id"], owner="recovery")

    assert final["state"] == "MANUAL_REVIEW"
    assert journal.get_mode() is SystemMode.HALTED
    assert len([order for order in exchange.orders if order.side == "buy"]) == 0
    assert journal.get_unpublished_outbox()
    journal.close()
