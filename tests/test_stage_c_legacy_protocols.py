"""Contract and bridge registration tests for the five legacy Stage-C drills."""

from __future__ import annotations

import hashlib

from okx_quant.application.approval import canonical_bytes
from okx_quant.ops import stage_c_implementation_inventory as inventory
from okx_quant.ops.stage_c_chaos_protocol import (
    LEGACY_NATIVE_PROTOCOLS,
    SCENARIO_PROTOCOLS,
    driver_contract_document,
    required_source_roles,
)
from okx_quant.ops.stage_c_external_bridge import (
    expected_live_event_kinds,
    expected_live_source_roles,
)


def test_legacy_contracts_are_explicit_and_bridge_addressable():
    assert set(LEGACY_NATIVE_PROTOCOLS) == set(
        inventory.LEGACY_REPOSITORY_PRODUCER_SCENARIOS
    )
    for scenario, protocol in LEGACY_NATIVE_PROTOCOLS.items():
        contract = driver_contract_document(scenario)
        assert contract["scenario"] == scenario
        assert contract["driver_id"] == protocol.driver_id
        assert contract["artifact_class"] == "exact_release_black_box"
        assert contract["required_native_events"][0] == "challenge.accepted"
        expected_events = tuple(dict.fromkeys(
            (
                "challenge.accepted",
                "driver.invoked",
                "clock.sample",
                "reconciliation.completed",
                "page.provider_receipt",
                "journal.integrity",
                "journal.duplicate_buy_audit",
                "journal.positions",
                "exchange.pending_orders",
                "exchange.pending_algos",
                "exchange.balances",
                "runtime.mode",
                "run.completed",
                *protocol.required_events,
            )
        ))
        assert tuple(contract["required_native_events"]) == expected_events
        assert set(expected_live_event_kinds(scenario)) == set(
            contract["required_native_events"][1:]
        )
        assert expected_live_source_roles(scenario) == frozenset(
            role for role in required_source_roles(scenario)
            if not role.endswith("_acquirer")
            and role not in {
                "parser_signer",
                "challenge_consumer",
                "fault_driver",
                "provider_receipt_authority",
            }
        )


def test_legacy_inventory_binds_contract_without_promotion():
    document = inventory.full_stage_c_inventory_document(
        {scenario: spec.artifact_class for scenario, spec in SCENARIO_PROTOCOLS.items()},
        {scenario: required_source_roles(scenario) for scenario in SCENARIO_PROTOCOLS},
        {
            scenario: hashlib.sha256(
                canonical_bytes(driver_contract_document(scenario))
            ).hexdigest()
            for scenario in SCENARIO_PROTOCOLS
        },
        "f" * 64,
    )
    rows = {
        row["scenario"]: row
        for row in document["records"]
        if row["scenario"] in LEGACY_NATIVE_PROTOCOLS
    }
    assert set(rows) == set(LEGACY_NATIVE_PROTOCOLS)
    for scenario, row in rows.items():
        assert row["executor_shipped"] is False
        assert row["capability_state"] == "REPOSITORY_PRODUCER / EXTERNAL OPEN"
        assert row["native_contract_sha256"] == hashlib.sha256(
            canonical_bytes(driver_contract_document(scenario))
        ).hexdigest()
        assert row["live_bridge"]["production_evidence"] is False
