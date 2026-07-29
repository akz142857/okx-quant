from __future__ import annotations

import copy
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from okx_quant.infrastructure.evidence import ed25519_public_key_fingerprint
from okx_quant.ops import stage_c_chaos_protocol as protocol
from okx_quant.ops.stage_c_exact_release_drivers import (
    TimedNativeAcquisition,
    attach_live_acquisition_attestation,
    build_live_acquisition_envelope,
)
from okx_quant.ops.stage_c_external_bridge import (
    RAW_COLLECTION_SCHEMA,
    build_external_signed_fragment,
    expected_live_event_kinds,
    expected_live_source_roles,
    validate_external_collection_set,
)
from okx_quant.ops.stage_c_native_collectors import NativeAcquisition


def _key_pair(tmp_path, name: str):
    private = tmp_path / f"{name}-private.pem"
    public = tmp_path / f"{name}-public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", private],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", private, "-pubout", "-out", public],
        check=True,
        capture_output=True,
    )
    return private, public


def _workload(role: str, index: int) -> dict:
    return {
        "host_id": f"stage-c-{role}",
        "boot_id": f"00000000-0000-4000-8000-{index:012d}",
        "systemd_invocation_id": (
            f"10000000-0000-4000-8000-{index:012d}"
        ),
        "pid": 3000 + index,
        "uid": 4000 + index,
        "cgroup": f"/system.slice/okx-stage-c-{role}.service",
        "executable_sha256": f"{index + 1:064x}",
        "parser_manifest_sha256": protocol.PARSER_MANIFEST_SHA256,
        "iam_principal_arn": (
            "arn:aws:sts::123456789012:"
            f"assumed-role/stage-c-{role}/session-{index}"
        ),
        "iam_account_id": "123456789012",
        "iam_session_id": f"session-{index}",
    }


def _context(tmp_path):
    scenario = "external-pending-buy"
    sources = expected_live_source_roles(scenario)
    acquirers = {
        protocol.acquisition_role_for_source(source)
        for source in sources
    }
    roles = sorted(sources | acquirers)
    pairs = {
        role: _key_pair(tmp_path, role)
        for role in roles
    }
    challenge = {
        "scenario": scenario,
        "challenge_id": "a" * 32,
        "identity": {"account_uid": "1234567890123456"},
        "source_key_fingerprints": {
            role: ed25519_public_key_fingerprint(pair[1])
            for role, pair in pairs.items()
        },
        "workloads": {
            role: _workload(role, index)
            for index, role in enumerate(roles, start=1)
        },
    }
    order = [
        "driver.invoked",
        "clock.sample",
        "exchange.order.external_pending",
        "runtime.entry_frozen",
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
    ]
    assert set(order) == set(expected_live_event_kinds(scenario))
    start = datetime.now(UTC)
    by_source = {source: [] for source in sources}
    for index, kind in enumerate(order, start=1):
        source = protocol._expected_source(scenario, kind)
        requested = start + timedelta(milliseconds=index * 10)
        completed = requested + timedelta(milliseconds=1)
        envelope = build_live_acquisition_envelope(
            scenario=scenario,
            kind=kind,
            acquisitions=[
                TimedNativeAcquisition(
                    acquisition=NativeAcquisition(
                        source=source,
                        operation=f"test-{kind}",
                        request_bytes=f"request:{kind}".encode(),
                        response_bytes=f"response:{kind}".encode(),
                        returncode=0,
                    ),
                    requested_at=requested.isoformat(),
                    response_completed_at=completed.isoformat(),
                    requested_monotonic_ns=index * 10_000_000,
                    response_completed_monotonic_ns=(
                        index * 10_000_000 + 1_000_000
                    ),
                )
            ],
            bindings=(
                {"capability_attestation": {"test": True}}
                if kind == "driver.invoked"
                else None
            ),
        )
        acquirer = protocol.acquisition_role_for_source(source)
        by_source[source].append({
            "kind": kind,
            "envelope": attach_live_acquisition_attestation(
                scenario=scenario,
                kind=kind,
                challenge=challenge,
                envelope=envelope,
                acquirer_private_key=pairs[acquirer][0],
            ),
        })
    collections = {
        source: {
            "schema": RAW_COLLECTION_SCHEMA,
            "scenario": scenario,
            "challenge_id": challenge["challenge_id"],
            "account_uid": challenge["identity"]["account_uid"],
            "source_role": source,
            "collector_workload_role": (
                protocol.acquisition_role_for_source(source)
            ),
            "contains_acquirer_attestations": True,
            "contains_signed_events": False,
            "facts_supplied_by_actor": False,
            "envelopes": envelopes,
        }
        for source, envelopes in by_source.items()
    }
    return challenge, pairs, collections


def test_external_bridge_separates_acquirer_and_event_signer(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        "okx_quant.ops.stage_c_exact_release_drivers._native_locator",
        lambda **_kwargs: {"test_locator": "bound-by-envelope"},
    )
    challenge, pairs, collections = _context(tmp_path)
    acquirer_public = {
        role: pair[1]
        for role, pair in pairs.items()
        if role.endswith("_acquirer")
    }
    assert validate_external_collection_set(
        collections,
        challenge=challenge,
        acquirer_public_keys=acquirer_public,
    ) == collections
    fragments = {
        source: build_external_signed_fragment(
            source_role=source,
            collections=collections,
            challenge=challenge,
            acquirer_public_keys=acquirer_public,
            source_private_key=pairs[source][0],
        )
        for source in expected_live_source_roles(challenge["scenario"])
    }
    events = sorted(
        (
            event
            for fragment in fragments.values()
            for event in fragment["events"]
        ),
        key=lambda event: event["seq"],
    )
    assert [event["seq"] for event in events] == list(
        range(1, len(events) + 1)
    )
    assert events[0]["kind"] == "driver.invoked"
    assert events[-1]["kind"] == "run.completed"
    assert all(
        event["payload"]["artifact"]["payload"]["source"] == event["source"]
        for event in events
    )


def test_external_bridge_rejects_tamper_wrong_key_and_partial_set(tmp_path):
    challenge, pairs, collections = _context(tmp_path)
    acquirer_public = {
        role: pair[1]
        for role, pair in pairs.items()
        if role.endswith("_acquirer")
    }
    tampered = copy.deepcopy(collections)
    tampered["okx_collector"]["envelopes"][0]["envelope"][
        "response_completed_at"
    ] = datetime.now(UTC).isoformat()
    with pytest.raises(ValueError, match="bytes/workload"):
        validate_external_collection_set(
            tampered,
            challenge=challenge,
            acquirer_public_keys=acquirer_public,
        )
    partial = dict(collections)
    partial.pop("provider")
    with pytest.raises(ValueError, match="roles"):
        validate_external_collection_set(
            partial,
            challenge=challenge,
            acquirer_public_keys=acquirer_public,
        )
    wrong_private, _wrong_public = _key_pair(tmp_path, "wrong-signer")
    with pytest.raises(ValueError, match="signer key"):
        build_external_signed_fragment(
            source_role="okx_collector",
            collections=collections,
            challenge=challenge,
            acquirer_public_keys=acquirer_public,
            source_private_key=wrong_private,
        )
