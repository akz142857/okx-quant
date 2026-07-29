from __future__ import annotations

import json
import sys
from copy import deepcopy
from decimal import Decimal
from pathlib import Path

import pytest

from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.ops.stage_c_external_executors import (
    COLLECTION_REQUEST_SCHEMA,
    EXTERNAL_SCENARIOS,
    IMPLEMENTATION_MANIFEST_SCHEMA,
    STAGE_C_DEMO_CONFIRMATION,
    StageCExternalScenarioExecutor,
    external_scenario_implementation_manifest,
    stable_client_order_id,
    stable_control_command_id,
    validate_prepared_report_for_source,
)
from okx_quant.ops.stage_c_native_collectors import NativeAcquisition
from scripts import stage_c_external_scenario, stage_c_external_source


class FakeDemoActor:
    simulated = True

    def __init__(self):
        self.uid = "1234567890123456"
        self.orders: dict[str, dict] = {}
        self.algos: dict[str, dict] = {}
        self.events: list[dict] = []
        self.calls: list[tuple] = []
        self.cash_balance = Decimal("1")
        self.available = Decimal("1")
        self._next_order = 1
        self._next_algo = 1
        self.protection_links: dict[str, tuple[str, str]] = {}

    def account_uid(self) -> str:
        return self.uid

    def instrument(self, inst_id: str) -> dict:
        assert inst_id == "BTC-USDT"
        return {"lotSz": "0.001", "minSz": "0.001", "tickSz": "0.1"}

    def ticker(self, inst_id: str) -> dict:
        assert inst_id == "BTC-USDT"
        return {"last": "100"}

    def balance(self, ccy: str) -> dict:
        return {
            "details": [{
                "ccy": ccy,
                "eq": str(self.cash_balance),
                "cashBal": str(self.cash_balance),
                "availBal": str(self.available),
                "frozenBal": str(self.cash_balance - self.available),
            }]
        }

    def open_orders(self, inst_id: str) -> list[dict]:
        return [
            deepcopy(row)
            for row in self.orders.values()
            if row["state"] in {"live", "partially_filled"}
        ]

    def pending_algos(self, inst_id: str) -> list[dict]:
        return [
            deepcopy(row)
            for row in self.algos.values()
            if row["state"] == "live"
        ]

    def order(self, inst_id: str, cl_ord_id: str) -> dict:
        return deepcopy(self.orders.get(cl_ord_id, {}))

    def place_order(
        self,
        *,
        inst_id: str,
        side: str,
        ord_type: str,
        size: str,
        cl_ord_id: str,
        price: str = "",
        target_currency: str = "",
    ) -> dict:
        self.calls.append(("place", side, ord_type, cl_ord_id, size))
        assert cl_ord_id not in self.orders
        ord_id = f"ord-{self._next_order}"
        self._next_order += 1
        if ord_type == "market":
            fill = (
                Decimal(size) / Decimal("100")
                if side == "buy" and target_currency == "quote_ccy"
                else Decimal(size)
            )
            row = {
                "ordId": ord_id,
                "clOrdId": cl_ord_id,
                "instId": inst_id,
                "side": side,
                "ordType": ord_type,
                "sz": size,
                "px": "",
                "tgtCcy": target_currency,
                "state": "filled",
                "accFillSz": str(fill),
                "avgPx": "100",
                "fee": str(
                    -fill * Decimal("0.001")
                    if side == "buy"
                    else Decimal("0")
                ),
                "feeCcy": "BTC" if side == "buy" else "USDT",
            }
            if side == "buy":
                net_fill = fill + Decimal(row["fee"])
                self.cash_balance += net_fill
                self.available += net_fill
            else:
                self.cash_balance -= fill
                self.available -= fill
        else:
            row = {
                "ordId": ord_id,
                "clOrdId": cl_ord_id,
                "instId": inst_id,
                "side": side,
                "ordType": ord_type,
                "tgtCcy": target_currency,
                "state": "live",
                "accFillSz": "0",
                "fee": "0",
                "feeCcy": "",
                "px": price,
                "sz": size,
            }
            if side == "sell":
                self.available -= Decimal(size)
        self.orders[cl_ord_id] = row
        return deepcopy(row)

    def cancel_order(self, *, inst_id: str, cl_ord_id: str) -> dict:
        self.calls.append(("cancel-order", cl_ord_id))
        self.orders[cl_ord_id]["state"] = "canceled"
        if self.orders[cl_ord_id]["side"] == "sell":
            self.available += Decimal(self.orders[cl_ord_id]["sz"])
        return deepcopy(self.orders[cl_ord_id])

    def cancel_algo(self, *, inst_id: str, algo_id: str) -> dict:
        self.calls.append(("cancel-algo", algo_id))
        self.algos[algo_id]["state"] = "canceled"
        return deepcopy(self.algos[algo_id])

    def reconcile(
        self,
        *,
        command_id: str,
        scenario: str,
        challenge_id: str,
        targets: dict[str, str],
        timeout_s: float,
    ) -> dict:
        self.calls.append(("reconcile", scenario, command_id))
        if scenario == "external-pending-buy":
            self._event("runtime.entry_frozen", challenge_id)
        elif scenario in {
            "external-fill",
            "external-protection-cancel",
        }:
            if not targets.get("algo_id"):
                algo_id = f"algo-{self._next_algo}"
                self._next_algo += 1
                self.algos[algo_id] = {
                    "algoId": algo_id,
                    "algoClOrdId": f"SFAKE{self._next_algo:08d}",
                    "instId": "BTC-USDT",
                    "state": "live",
                    "sz": "0.050949",
                    "ordType": "oco",
                    "side": "sell",
                    "tdMode": "cash",
                }
                self.protection_links[str(targets["cl_ord_id"])] = (
                    str(targets["ord_id"]),
                    algo_id,
                )
            else:
                self._event("runtime.emergency_exit", challenge_id)
        elif scenario == "frozen-balance":
            self._event("journal.position_preserved", challenge_id)
        return {"command_id": command_id, "status": "completed", "result": {}}

    def protection_ownership(
        self,
        *,
        inst_id: str,
        parent_cl_ord_id: str,
        parent_ord_id: str,
    ) -> dict:
        link = self.protection_links.get(parent_cl_ord_id)
        if link is None or link[0] != parent_ord_id:
            return {}
        row = self.algos.get(link[1], {})
        if row.get("state") != "live" or row.get("instId") != inst_id:
            return {}
        return {
            "parent_intent_id": f"intent:{parent_cl_ord_id}",
            "parent_cl_ord_id": parent_cl_ord_id,
            "parent_ord_id": parent_ord_id,
            "inst_id": inst_id,
            "algo_cl_ord_id": row["algoClOrdId"],
            "algo_id": row["algoId"],
            "protected_qty": row["sz"],
        }

    def _event(self, event_name: str, challenge_id: str) -> None:
        self.events.append({
            "event_name": event_name,
            "correlation_id": challenge_id,
            "payload": {},
        })

    def postcondition_event(
        self,
        *,
        event_name: str,
        challenge_id: str,
    ) -> dict | None:
        matches = [
            event for event in self.events
            if event["event_name"] == event_name
            and event["correlation_id"] == challenge_id
        ]
        return deepcopy(matches[-1]) if matches else None


def _challenge(scenario: str) -> dict:
    return {
        "scenario": scenario,
        "challenge_id": "d" * 32,
        "identity": {"account_uid": "1234567890123456"},
    }


def _consumption(scenario: str) -> dict:
    return {
        "action": "attest-stage-c-global-challenge-consumption-v1",
        "scenario": scenario,
        "challenge_id": "d" * 32,
    }


@pytest.mark.parametrize("scenario", sorted(EXTERNAL_SCENARIOS))
def test_four_external_state_machines_prepare_collect_then_cleanup(scenario):
    actor = FakeDemoActor()
    executor = StageCExternalScenarioExecutor(
        actor,
        timeout_s=1,
        poll_interval_s=0.001,
    )
    report = executor.prepare(
        scenario=scenario,
        challenge=_challenge(scenario),
        inst_id="BTC-USDT",
        confirmation=STAGE_C_DEMO_CONFIRMATION,
    )
    assert report.status == "awaiting_independent_collection", report.errors
    assert report.phase == "prepared"
    assert report.stable_ids["fault_cl_ord_id"] == (
        stable_client_order_id(
            scenario=scenario,
            challenge_id="d" * 32,
            purpose="fault",
        )
    )
    requests = validate_prepared_report_for_source(report)
    assert requests
    assert all(item.schema == COLLECTION_REQUEST_SCHEMA for item in requests)
    assert all(item.derived_facts_forbidden for item in requests)
    assert not any(
        "facts" in item.parameters
        or "payload" in item.parameters
        or "result" in item.parameters
        for item in requests
    )

    cleaned = executor.cleanup(
        report,
        confirmation=STAGE_C_DEMO_CONFIRMATION,
        challenge=_challenge(scenario),
        consumption_claims=_consumption(scenario),
    )
    assert cleaned.status == "cleanup_completed", cleaned.errors
    assert any(
        step["action"].startswith("cleanup-")
        for step in cleaned.steps
    )


def test_external_actor_requires_exact_confirmation_demo_and_account():
    actor = FakeDemoActor()
    executor = StageCExternalScenarioExecutor(actor)
    with pytest.raises(ValueError, match="显式确认"):
        executor.prepare(
            scenario="external-fill",
            challenge=_challenge("external-fill"),
            inst_id="BTC-USDT",
            confirmation="yes",
        )
    assert actor.calls == []

    actor.simulated = False
    with pytest.raises(ValueError, match="simulated"):
        executor.prepare(
            scenario="external-fill",
            challenge=_challenge("external-fill"),
            inst_id="BTC-USDT",
            confirmation=STAGE_C_DEMO_CONFIRMATION,
        )
    assert actor.calls == []

    actor.simulated = True
    actor.uid = "wrong"
    with pytest.raises(ValueError, match="account UID"):
        executor.prepare(
            scenario="external-fill",
            challenge=_challenge("external-fill"),
            inst_id="BTC-USDT",
            confirmation=STAGE_C_DEMO_CONFIRMATION,
        )
    assert actor.calls == []


def test_stable_ids_are_scenario_purpose_bound_and_okx_compatible():
    first = stable_client_order_id(
        scenario="external-fill",
        challenge_id="a" * 32,
        purpose="fault",
    )
    assert first == stable_client_order_id(
        scenario="external-fill",
        challenge_id="a" * 32,
        purpose="fault",
    )
    assert len(first) == 28
    assert first.isalnum()
    assert first.startswith(f"SC{'a' * 16}".upper())
    assert first != stable_client_order_id(
        scenario="external-fill",
        challenge_id="a" * 32,
        purpose="cleanup",
    )
    assert stable_control_command_id(
        scenario="external-fill",
        challenge_id="a" * 32,
        phase="fault",
    ) != stable_control_command_id(
        scenario="external-fill",
        challenge_id="a" * 32,
        phase="import",
    )


def test_external_source_resolves_fills_from_exact_clordid_order(monkeypatch):
    cl_ord_id = stable_client_order_id(
        scenario="external-fill",
        challenge_id="a" * 32,
        purpose="fault",
    )
    calls = []

    def acquire(*, client, operation, parameters):
        calls.append((operation, dict(parameters)))
        body = (
            {
                "code": "0",
                "data": [{
                    "instId": "BTC-USDT",
                    "clOrdId": cl_ord_id,
                    "ordId": "owned-order",
                }],
            }
            if operation == "order"
            else {"code": "0", "data": []}
        )
        return NativeAcquisition(
            source="okx_collector",
            operation=operation,
            request_bytes=b"request",
            response_bytes=(
                b"HTTP/1.1 200\r\n\r\n"
                + json.dumps(body).encode()
            ),
            returncode=0,
        )

    monkeypatch.setattr(stage_c_external_source, "_okx_acquisition", acquire)
    request = type("Request", (), {
        "operations": ("order", "fills-history", "account-config"),
        "parameters": {
            "inst_id": "BTC-USDT",
            "cl_ord_id": cl_ord_id,
        },
    })()
    acquisitions = stage_c_external_source._okx_request_acquisitions(
        client=object(),
        request=request,
    )
    assert [item.acquisition.operation for item in acquisitions] == [
        "order",
        "fills-history",
        "account-config",
    ]
    assert calls[1] == (
        "fills-history",
        {
            "inst_id": "BTC-USDT",
            "cl_ord_id": cl_ord_id,
            "ord_id": "owned-order",
        },
    )


def test_external_source_rejects_foreign_order_locator(monkeypatch):
    cl_ord_id = stable_client_order_id(
        scenario="external-fill",
        challenge_id="a" * 32,
        purpose="fault",
    )

    def acquire(**_kwargs):
        return NativeAcquisition(
            source="okx_collector",
            operation="order",
            request_bytes=b"request",
            response_bytes=(
                b"HTTP/1.1 200\r\n\r\n"
                b'{"code":"0","data":[{"instId":"ETH-USDT",'
                b'"clOrdId":"foreign","ordId":"foreign-order"}]}'
            ),
            returncode=0,
        )

    monkeypatch.setattr(stage_c_external_source, "_okx_acquisition", acquire)
    request = type("Request", (), {
        "operations": ("order", "fills-history", "account-config"),
        "parameters": {
            "inst_id": "BTC-USDT",
            "cl_ord_id": cl_ord_id,
        },
    })()
    with pytest.raises(ValueError, match="未唯一绑定"):
        stage_c_external_source._okx_request_acquisitions(
            client=object(),
            request=request,
        )


def test_prepared_source_plan_is_recomputed_not_caller_extendable():
    actor = FakeDemoActor()
    report = StageCExternalScenarioExecutor(
        actor,
        timeout_s=1,
        poll_interval_s=0.001,
    ).prepare(
        scenario="external-fill",
        challenge=_challenge("external-fill"),
        inst_id="BTC-USDT",
        confirmation=STAGE_C_DEMO_CONFIRMATION,
    )
    report.native_acquisition_requests[0]["parameters"]["facts"] = {
        "forged": True
    }
    with pytest.raises(ValueError, match="固定重算"):
        validate_prepared_report_for_source(report)


def test_cleanup_recomputes_fill_and_rejects_tampered_quantity():
    actor = FakeDemoActor()
    executor = StageCExternalScenarioExecutor(
        actor,
        timeout_s=1,
        poll_interval_s=0.001,
    )
    report = executor.prepare(
        scenario="external-fill",
        challenge=_challenge("external-fill"),
        inst_id="BTC-USDT",
        confirmation=STAGE_C_DEMO_CONFIRMATION,
    )
    sell = next(
        item
        for item in report.cleanup_actions
        if item["action"] == "sell_net_base"
    )
    sell["quantity"] = "100"
    with pytest.raises(ValueError, match="inventory"):
        executor.cleanup(
            report,
            confirmation=STAGE_C_DEMO_CONFIRMATION,
            challenge=_challenge("external-fill"),
            consumption_claims=_consumption("external-fill"),
        )
    assert not any(
        call[:3] == ("place", "sell", "market")
        for call in actor.calls
    )


def test_existing_foreign_order_with_same_clordid_fails_closed():
    actor = FakeDemoActor()
    cl_ord_id = stable_client_order_id(
        scenario="external-fill",
        challenge_id="d" * 32,
        purpose="fault",
    )
    actor.orders[cl_ord_id] = {
        "ordId": "foreign-order",
        "clOrdId": cl_ord_id,
        "instId": "BTC-USDT",
        "side": "sell",
        "ordType": "market",
        "sz": "5.1",
        "px": "",
        "tgtCcy": "quote_ccy",
        "state": "filled",
        "accFillSz": "1",
        "avgPx": "100",
        "fee": "0",
        "feeCcy": "USDT",
    }
    result = StageCExternalScenarioExecutor(
        actor,
        timeout_s=1,
        poll_interval_s=0.001,
    ).prepare(
        scenario="external-fill",
        challenge=_challenge("external-fill"),
        inst_id="BTC-USDT",
        confirmation=STAGE_C_DEMO_CONFIRMATION,
    )
    assert result.status == "prepare_failed"
    assert any("order contract" in error for error in result.errors)
    assert not any(call[0] == "place" for call in actor.calls)
    assert not any(call[0] == "cancel-order" for call in actor.calls)


def test_protection_cancel_never_cancels_new_foreign_algo():
    class ForeignAlgoActor(FakeDemoActor):
        def reconcile(self, **kwargs) -> dict:
            self.calls.append(
                ("reconcile", kwargs["scenario"], kwargs["command_id"])
            )
            if kwargs["scenario"] == "external-protection-cancel":
                self.algos["foreign-new"] = {
                    "algoId": "foreign-new",
                    "state": "live",
                    "ordId": "foreign-order",
                    "sz": "1",
                }
            return {
                "command_id": kwargs["command_id"],
                "status": "completed",
                "result": {},
            }

    actor = ForeignAlgoActor()
    report = StageCExternalScenarioExecutor(
        actor,
        timeout_s=0.01,
        poll_interval_s=0.001,
    ).prepare(
        scenario="external-protection-cancel",
        challenge=_challenge("external-protection-cancel"),
        inst_id="BTC-USDT",
        confirmation=STAGE_C_DEMO_CONFIRMATION,
    )
    assert report.status == "prepare_failed"
    assert actor.algos["foreign-new"]["state"] == "live"
    assert ("cancel-algo", "foreign-new") not in actor.calls


def test_external_fill_ignores_unrelated_live_oco_and_cleans_owned_first():
    actor = FakeDemoActor()
    actor.algos["unrelated"] = {
        "algoId": "unrelated",
        "algoClOrdId": "UNRELATEDCLIENT",
        "instId": "BTC-USDT",
        "state": "live",
        "sz": "0.050949",
        "ordType": "oco",
        "side": "sell",
        "tdMode": "cash",
    }
    executor = StageCExternalScenarioExecutor(
        actor,
        timeout_s=1,
        poll_interval_s=0.001,
    )
    report = executor.prepare(
        scenario="external-fill",
        challenge=_challenge("external-fill"),
        inst_id="BTC-USDT",
        confirmation=STAGE_C_DEMO_CONFIRMATION,
    )
    assert report.status == "awaiting_independent_collection", report.errors
    owned_algo_id = report.stable_ids["fault_algo_id"]
    assert owned_algo_id != "unrelated"

    executor.cleanup(
        report,
        confirmation=STAGE_C_DEMO_CONFIRMATION,
        challenge=_challenge("external-fill"),
        consumption_claims=_consumption("external-fill"),
    )
    assert actor.algos["unrelated"]["state"] == "live"
    cancel_index = actor.calls.index(("cancel-algo", owned_algo_id))
    sell_index = next(
        index for index, call in enumerate(actor.calls)
        if call[:3] == ("place", "sell", "market")
    )
    assert cancel_index < sell_index


def test_frozen_balance_locks_and_sells_only_challenge_owned_fill():
    actor = FakeDemoActor()
    executor = StageCExternalScenarioExecutor(
        actor,
        timeout_s=1,
        poll_interval_s=0.001,
    )
    report = executor.prepare(
        scenario="frozen-balance",
        challenge=_challenge("frozen-balance"),
        inst_id="BTC-USDT",
        confirmation=STAGE_C_DEMO_CONFIRMATION,
    )
    assert report.status == "awaiting_independent_collection", report.errors
    locking = actor.orders[report.stable_ids["fault_cl_ord_id"]]
    assert Decimal(locking["sz"]) < Decimal("0.1")
    assert Decimal(locking["sz"]) < Decimal("1")
    assert actor.cash_balance > Decimal("1")
    assert actor.available >= Decimal("1")

    cleaned = executor.cleanup(
        report,
        confirmation=STAGE_C_DEMO_CONFIRMATION,
        challenge=_challenge("frozen-balance"),
        consumption_claims=_consumption("frozen-balance"),
    )
    assert cleaned.status == "cleanup_completed", cleaned.errors
    market_sells = [
        call
        for call in actor.calls
        if call[:3] == ("place", "sell", "market")
    ]
    assert len(market_sells) == 1
    assert Decimal(market_sells[0][4]) == Decimal(locking["sz"])
    assert actor.cash_balance >= Decimal("1")


def test_cleanup_refuses_old_balance_when_owned_fill_is_missing():
    actor = FakeDemoActor()
    executor = StageCExternalScenarioExecutor(
        actor,
        timeout_s=1,
        poll_interval_s=0.001,
    )
    report = executor.prepare(
        scenario="external-fill",
        challenge=_challenge("external-fill"),
        inst_id="BTC-USDT",
        confirmation=STAGE_C_DEMO_CONFIRMATION,
    )
    actor.cash_balance = Decimal("1")
    actor.available = Decimal("1")
    cleaned = executor.cleanup(
        report,
        confirmation=STAGE_C_DEMO_CONFIRMATION,
        challenge=_challenge("external-fill"),
        consumption_claims=_consumption("external-fill"),
    )
    assert cleaned.status == "cleanup_incomplete"
    assert any("归属/余额缺口" in error for error in cleaned.errors)
    assert not any(
        call[:3] == ("place", "sell", "market")
        for call in actor.calls
    )


def test_prepare_cli_fails_before_client_without_signed_authorization(
    tmp_path,
    monkeypatch,
):
    output = tmp_path / "capability.json"
    monkeypatch.setattr(
        stage_c_external_scenario,
        "make_client",
        lambda _cfg: pytest.fail("缺少授权时不得创建 OKX client"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "stage_c_external_scenario.py",
            "prepare",
            "--scenario",
            "frozen-balance",
            "--challenge",
            str(tmp_path / "missing-challenge.json"),
            "--registrar-public-key",
            str(tmp_path / "missing-public.pem"),
            "--consumption-receipt",
            str(tmp_path / "missing-consumption.json"),
            "--consumer-public-key",
            str(tmp_path / "missing-consumer.pem"),
            "--inst",
            "BTC-USDT",
            "--config",
            str(tmp_path / "missing-config.yaml"),
            "--confirm",
            STAGE_C_DEMO_CONFIRMATION,
            "--output",
            str(output),
        ],
    )
    with pytest.raises(TimeoutError, match="challenge/consumption"):
        stage_c_external_scenario.main()
    assert not output.exists()


def test_pre_intent_checkpoint_is_durable_idempotent_and_conflict_closed(
    tmp_path,
):
    journal = SQLiteJournal(tmp_path / "checkpoint.sqlite")
    challenge = _challenge("external-fill")
    claims = _consumption("external-fill")
    stage_c_external_scenario._record_pre_intent_checkpoint(
        journal,
        challenge=challenge,
        consumption_claims=claims,
        inst_id="BTC-USDT",
    )
    stage_c_external_scenario._record_pre_intent_checkpoint(
        journal,
        challenge=challenge,
        consumption_claims=claims,
        inst_id="BTC-USDT",
    )
    events = journal.list_events("stage_c_external_pre_intent_authorized")
    assert len(events) == 1
    assert events[0]["payload"]["state"] == (
        "authorized_before_exchange_mutation"
    )
    with pytest.raises(ValueError, match="checkpoint 冲突"):
        stage_c_external_scenario._record_pre_intent_checkpoint(
            journal,
            challenge=challenge,
            consumption_claims=claims,
            inst_id="ETH-USDT",
        )
    journal.close()


@pytest.mark.parametrize("scenario", sorted(EXTERNAL_SCENARIOS))
def test_implementation_manifest_stays_explicitly_open(scenario):
    manifest = external_scenario_implementation_manifest(scenario)
    assert manifest["schema"] == IMPLEMENTATION_MANIFEST_SCHEMA
    assert manifest["status"] == "EXTERNAL OPEN"
    assert manifest["production_capability_implemented"] is False
    assert manifest["checks"]["fixed_demo_actor_state_machine"] is True
    assert manifest["checks"]["challenge_attests_actor_workload_role"] is True
    assert manifest["checks"]["mutating_cli_globally_consumes_challenge"] is True
    assert manifest["checks"]["mutating_cli_has_durable_pre_intent_checkpoint"] is True
    assert (
        manifest["checks"][
            "runtime_emits_verified_challenge_bound_postcondition"
        ]
        is True
    )
    assert (
        manifest["checks"]["all_required_source_signer_units_shipped"]
        is True
    )
    assert (
        "all_required_source_signer_units_deployed"
        in manifest["blockers"]
    )
    assert "real_demo_worm_receipt_verified" in manifest["blockers"]


def test_external_systemd_roles_are_distinct_and_cleanup_is_bounded():
    root = Path(__file__).resolve().parents[1]
    systemd = root / "deploy/systemd"
    actor = (
        systemd
        / "okx-quant-stage-c-external-actor@.service"
    ).read_text()
    okx_source = (
        systemd
        / "okx-quant-stage-c-external-okx-source@.service"
    ).read_text()
    journal_source = (
        systemd
        / "okx-quant-stage-c-external-journal-source@.service"
    ).read_text()
    systemd_source = (
        systemd
        / "okx-quant-stage-c-external-systemd-source@.service"
    ).read_text()
    clock_source = (
        systemd
        / "okx-quant-stage-c-external-clock-source@.service"
    ).read_text()
    provider_source = (
        systemd
        / "okx-quant-stage-c-external-provider-source@.service"
    ).read_text()
    cleanup = (
        systemd
        / "okx-quant-stage-c-external-cleanup@.service"
    ).read_text()
    timer = (
        systemd
        / "okx-quant-stage-c-external-cleanup@.timer"
    ).read_text()
    assert "User=okxquant-stagec-actor" in actor
    assert "stage_c_external_scenario.py prepare" in actor
    assert "--consumption-receipt" in actor
    assert "--authorization-wait-seconds 300" in actor
    assert "--scenario %i" not in actor
    assert "--start-after-driver-ready" in actor
    assert "--hold-until" in actor
    assert "StateDirectory=" in actor
    assert "User=okxquant-stagec-okx-source" in okx_source
    assert "User=okxquant-stagec-journal-source" in journal_source
    assert "PrivateNetwork=yes" in journal_source
    assert "--role okx_collector" in okx_source
    assert "--role journal_collector" in journal_source
    assert "--acquirer-private-key %d/acquirer-private-key.pem" in okx_source
    assert "--acquirer-private-key %d/acquirer-private-key.pem" in journal_source
    assert "User=okxquant-stagec-systemd-source" in systemd_source
    assert "User=okxquant-stagec-clock-source" in clock_source
    assert "User=okxquant-stagec-provider-source" in provider_source
    assert "--driver-ready-output" in systemd_source
    assert "--role clock_collector" in clock_source
    assert "--role provider" in provider_source
    assert "stage_c_external_scenario.py cleanup" in cleanup
    assert "--required-collection" in cleanup
    assert "RuntimeDirectory=" in cleanup
    assert "StateDirectory=" not in cleanup
    assert "SupplementaryGroups=okxquant-data-chaos" in cleanup
    assert "OnActiveSec=120" in timer
    assert "external-okx-source.env" not in actor
    assert "external-actor.env" not in okx_source
    signer_users = set()
    for role in ("okx", "journal", "systemd", "clock", "provider"):
        signer = (
            systemd
            / f"okx-quant-stage-c-external-{role}-signer@.service"
        ).read_text()
        user = next(
            line.removeprefix("User=")
            for line in signer.splitlines()
            if line.startswith("User=")
        )
        signer_users.add(user)
        assert "stage_c_external_signer.py sign-fragment" in signer
        assert "LoadCredential=source-private-key.pem:" in signer
        assert "PrivateNetwork=yes" in signer
        assert "--input-wait-seconds 420" in signer
    assert len(signer_users) == 5
    assert not signer_users.intersection({
        "okxquant-stagec-okx-source",
        "okxquant-stagec-journal-source",
        "okxquant-stagec-systemd-source",
        "okxquant-stagec-clock-source",
        "okxquant-stagec-provider-source",
    })
    assembler = (
        systemd
        / "okx-quant-stage-c-external-assembler@.service"
    ).read_text()
    assert "User=okxquant-stagec-parser" in assembler
    assert "stage_c_external_signer.py assemble" in assembler
    assert "--source-public-key provider_receipt_authority=" in assembler
    assert "native-events.jsonl" in assembler
    sysusers = (
        root
        / "deploy/sysusers/okx-quant-stage-c-external.conf"
    ).read_text()
    for user in signer_users:
        assert f"u {user} " in sysusers


@pytest.mark.parametrize(
    "module",
    (stage_c_external_scenario, stage_c_external_source),
)
def test_mutating_and_source_json_readers_reject_duplicates_and_symlinks(
    module,
    tmp_path,
):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"challenge_id":"a","challenge_id":"b"}')
    with pytest.raises(ValueError, match="重复"):
        module._json(duplicate, label="test")

    valid = tmp_path / "valid.json"
    valid.write_text('{"challenge_id":"a"}')
    link = tmp_path / "link.json"
    link.symlink_to(valid)
    with pytest.raises(OSError):
        module._json(link, label="test")


@pytest.mark.parametrize(
    "module",
    (stage_c_external_scenario, stage_c_external_source),
)
def test_exclusive_json_handles_short_os_writes(module, tmp_path, monkeypatch):
    output = tmp_path / "artifact.json"
    native_write = module.os.write

    def short_write(descriptor, value):
        return native_write(descriptor, value[:3])

    monkeypatch.setattr(module.os, "write", short_write)
    module._exclusive_json(output, {"ok": True})
    assert output.read_text().endswith("\n")
    assert '"ok": true' in output.read_text()
