"""Parser-fixture event emitter for the isolated Stage-C scaffold.

This module accepts caller facts and therefore is categorically ineligible as
a live producer.  Production admission remains fail-closed until each role
ships a collector that acquires its own native bytes inside its own unit.
"""

from __future__ import annotations

import hashlib

from okx_quant.application.approval import canonical_bytes
from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.ops.stage_c_chaos_protocol import (
    NATIVE_EVENT_ACTION,
    RAW_EVENT_SCHEMA,
    _expected_source,
    _native_bytes_descriptor,
    _validate_native_request,
    validate_workload_attestation,
)


def emit_fixture_native_event(
    *,
    scenario: str,
    challenge_id: str,
    seq: int,
    observed_at: str,
    monotonic_ns: int,
    kind: str,
    facts: dict,
    workload: dict,
    native_request: dict,
    source_private_key,
) -> dict:
    """Sign one parser-fixture fact; never use this as live evidence."""
    source = _expected_source(scenario, kind)
    validate_workload_attestation(workload)
    _validate_native_request(
        native_request,
        source=source,
        kind=kind,
        observed_at=observed_at,
        workload=workload,
    )
    claims = {
        "version": 1,
        "action": NATIVE_EVENT_ACTION,
        "scenario": scenario,
        "challenge_id": challenge_id,
        "seq": seq,
        "observed_at": observed_at,
        "monotonic_ns": monotonic_ns,
        "source": source,
        "kind": kind,
        "workload_binding_sha256": hashlib.sha256(
            canonical_bytes(workload)
        ).hexdigest(),
        "native_request": _native_bytes_descriptor(native_request),
        "native_response": _native_bytes_descriptor(facts),
    }
    return {
        "schema": RAW_EVENT_SCHEMA,
        "scenario": scenario,
        "challenge_id": challenge_id,
        "seq": seq,
        "observed_at": observed_at,
        "monotonic_ns": monotonic_ns,
        "source": source,
        "kind": kind,
        "payload": {
            "artifact": sign_ed25519_payload(
                claims,
                source_private_key,
            )
        },
    }


def assemble_jsonl(challenge_event: dict, fragments: list[dict]) -> bytes:
    """Assemble, but never summarize, per-role signed event fragments."""
    events = [challenge_event, *fragments]
    if any(event.get("seq") != index for index, event in enumerate(events)):
        raise ValueError("Stage-C event fragments seq 不连续")
    return b"".join(canonical_bytes(event) + b"\n" for event in events)
