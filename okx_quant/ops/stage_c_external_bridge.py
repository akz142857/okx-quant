"""Independent acquirer -> signer -> JSONL bridge for Stage-C live bytes."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from okx_quant.application.approval import canonical_bytes
from okx_quant.infrastructure.evidence import ed25519_public_key_fingerprint
from okx_quant.ops.stage_c_chaos_protocol import (
    RAW_EVENT_SCHEMA,
    _expected_source,
    _verify_native_event_artifacts,
    acquisition_role_for_source,
    driver_contract_document,
    verify_stage_c_challenge,
    verify_stage_c_consumption_receipt,
)
from okx_quant.ops.stage_c_exact_release_drivers import (
    build_live_signed_native_event,
    verify_live_acquisition_attestation,
)

RAW_COLLECTION_SCHEMA = "okx-quant.stage-c-external-raw-collection/v2"
SIGNED_FRAGMENT_SCHEMA = "okx-quant.stage-c-external-signed-fragment/v1"
_COLLECTION_KEYS = {
    "schema",
    "scenario",
    "challenge_id",
    "account_uid",
    "source_role",
    "collector_workload_role",
    "contains_acquirer_attestations",
    "contains_signed_events",
    "facts_supplied_by_actor",
    "envelopes",
}
_FRAGMENT_KEYS = {
    "schema",
    "scenario",
    "challenge_id",
    "source_role",
    "collection_set_sha256",
    "event_count",
    "events",
}


def expected_live_event_kinds(scenario: str) -> tuple[str, ...]:
    kinds = tuple(driver_contract_document(scenario)["required_native_events"])
    if not kinds or kinds[0] != "challenge.accepted":
        raise ValueError("Stage-C driver contract 缺少 challenge.accepted")
    return kinds[1:]


def expected_live_source_roles(scenario: str) -> frozenset[str]:
    return frozenset(
        _expected_source(scenario, kind)
        for kind in expected_live_event_kinds(scenario)
    )


def _iso(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是带时区 ISO-8601")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} 非法") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} 缺少时区")
    return parsed.astimezone(UTC)


def _collection_set_sha256(collections: dict[str, dict]) -> str:
    return hashlib.sha256(
        canonical_bytes({
            role: collections[role]
            for role in sorted(collections)
        })
    ).hexdigest()


def validate_external_raw_collection(
    value: object,
    *,
    challenge: dict,
    source_role: str,
    acquirer_public_key: Path,
) -> dict:
    if not isinstance(value, dict) or set(value) != _COLLECTION_KEYS:
        raise ValueError("Stage-C external raw collection schema 非法")
    acquisition_role = acquisition_role_for_source(source_role)
    if (
        value["schema"] != RAW_COLLECTION_SCHEMA
        or value["scenario"] != challenge["scenario"]
        or value["challenge_id"] != challenge["challenge_id"]
        or value["account_uid"] != challenge["identity"]["account_uid"]
        or value["source_role"] != source_role
        or value["collector_workload_role"] != acquisition_role
        or value["contains_acquirer_attestations"] is not True
        or value["contains_signed_events"] is not False
        or value["facts_supplied_by_actor"] is not False
        or not isinstance(value["envelopes"], list)
        or not value["envelopes"]
    ):
        raise ValueError("Stage-C external raw collection identity 非法")
    expected_kinds = {
        kind
        for kind in expected_live_event_kinds(challenge["scenario"])
        if _expected_source(challenge["scenario"], kind) == source_role
    }
    observed_kinds: list[str] = []
    for item in value["envelopes"]:
        if not isinstance(item, dict) or set(item) != {"kind", "envelope"}:
            raise ValueError("Stage-C raw collection envelope item 非法")
        kind = item["kind"]
        if (
            not isinstance(kind, str)
            or _expected_source(challenge["scenario"], kind) != source_role
        ):
            raise ValueError("Stage-C raw collection kind/source 串线")
        verify_live_acquisition_attestation(
            scenario=challenge["scenario"],
            kind=kind,
            challenge=challenge,
            envelope=item["envelope"],
            acquirer_public_key=acquirer_public_key,
        )
        observed_kinds.append(kind)
    if len(observed_kinds) != len(set(observed_kinds)) or (
        set(observed_kinds) != expected_kinds
    ):
        raise ValueError("Stage-C raw collection 未精确覆盖 source event kinds")
    return value


def _ordered_envelopes(collections: dict[str, dict]) -> list[tuple[str, str, dict]]:
    rows = [
        (role, str(item["kind"]), item["envelope"])
        for role, collection in collections.items()
        for item in collection["envelopes"]
    ]
    rows.sort(
        key=lambda row: (
            _iso(row[2]["response_completed_at"], "response completed"),
            row[0],
            row[1],
            hashlib.sha256(canonical_bytes(row[2])).hexdigest(),
        )
    )
    return rows


def validate_external_collection_set(
    collections: object,
    *,
    challenge: dict,
    acquirer_public_keys: dict[str, Path],
) -> dict[str, dict]:
    if not isinstance(collections, dict):
        raise ValueError("Stage-C collection set 必须是 role map")
    expected_sources = expected_live_source_roles(challenge["scenario"])
    expected_acquirers = {
        acquisition_role_for_source(source)
        for source in expected_sources
    }
    if (
        set(collections) != set(expected_sources)
        or set(acquirer_public_keys) != expected_acquirers
    ):
        raise ValueError("Stage-C collection/acquirer roles 不完整")
    validated = {
        role: validate_external_raw_collection(
            collection,
            challenge=challenge,
            source_role=role,
            acquirer_public_key=acquirer_public_keys[
                acquisition_role_for_source(role)
            ],
        )
        for role, collection in collections.items()
    }
    ordered = _ordered_envelopes(validated)
    kinds = [kind for _role, kind, _envelope in ordered]
    if (
        set(kinds) != set(expected_live_event_kinds(challenge["scenario"]))
        or len(kinds) != len(set(kinds))
        or kinds[0] != "driver.invoked"
        or kinds[-1] != "run.completed"
    ):
        raise ValueError(
            "Stage-C collection set event inventory/order 非法；"
            "driver.invoked 必须最先且 run.completed 必须最后"
        )
    return validated


def build_external_signed_fragment(
    *,
    source_role: str,
    collections: dict[str, dict],
    challenge: dict,
    acquirer_public_keys: dict[str, Path],
    source_private_key: Path,
) -> dict:
    validated = validate_external_collection_set(
        collections,
        challenge=challenge,
        acquirer_public_keys=acquirer_public_keys,
    )
    if (
        source_role not in expected_live_source_roles(challenge["scenario"])
        or ed25519_public_key_fingerprint(
            source_private_key,
            private_key=True,
        )
        != challenge["source_key_fingerprints"][source_role]
    ):
        raise ValueError("Stage-C source signer key/role 未绑定 challenge")
    events = []
    for seq, (role, kind, envelope) in enumerate(
        _ordered_envelopes(validated),
        start=1,
    ):
        if role != source_role:
            continue
        events.append(
            build_live_signed_native_event(
                scenario=challenge["scenario"],
                challenge_id=challenge["challenge_id"],
                seq=seq,
                observed_at=envelope["response_completed_at"],
                monotonic_ns=envelope["response_completed_monotonic_ns"],
                kind=kind,
                envelope=envelope,
                workload=challenge["workloads"][source_role],
                source_private_key=source_private_key,
            )
        )
    return {
        "schema": SIGNED_FRAGMENT_SCHEMA,
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "source_role": source_role,
        "collection_set_sha256": _collection_set_sha256(validated),
        "event_count": len(events),
        "events": events,
    }


def assemble_external_raw_jsonl(
    *,
    challenge_artifact: dict,
    consumption_receipt: dict,
    registrar_public_key: Path,
    consumer_public_key: Path,
    capability_authority_public_key: Path,
    collections: dict[str, dict],
    fragments: dict[str, dict],
    source_public_keys: dict[str, Path],
    acquirer_public_keys: dict[str, Path],
) -> bytes:
    challenge = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=registrar_public_key,
        scenario=str(challenge_artifact.get("payload", {}).get("scenario", "")),
        now=None,
        enforce_current_window=False,
    )
    verify_stage_c_consumption_receipt(
        consumption_receipt,
        challenge_artifact=challenge_artifact,
        registrar_public_key=registrar_public_key,
        consumer_public_key=consumer_public_key,
    )
    validated = validate_external_collection_set(
        collections,
        challenge=challenge,
        acquirer_public_keys=acquirer_public_keys,
    )
    expected_sources = expected_live_source_roles(challenge["scenario"])
    if set(fragments) != set(expected_sources):
        raise ValueError("Stage-C signed fragments source roles 不完整")
    collection_sha = _collection_set_sha256(validated)
    events: list[dict] = []
    for role, fragment in fragments.items():
        if (
            not isinstance(fragment, dict)
            or set(fragment) != _FRAGMENT_KEYS
            or fragment["schema"] != SIGNED_FRAGMENT_SCHEMA
            or fragment["scenario"] != challenge["scenario"]
            or fragment["challenge_id"] != challenge["challenge_id"]
            or fragment["source_role"] != role
            or fragment["collection_set_sha256"] != collection_sha
            or fragment["event_count"] != len(fragment["events"])
            or not isinstance(fragment["events"], list)
        ):
            raise ValueError("Stage-C signed fragment schema/binding 非法")
        events.extend(fragment["events"])
    events.sort(key=lambda event: event["seq"])
    if [event["seq"] for event in events] != list(range(1, len(events) + 1)):
        raise ValueError("Stage-C signed fragments seq 缺失/重复")
    ordered = _ordered_envelopes(validated)
    if [
        (event["source"], event["kind"], event["observed_at"], event["monotonic_ns"])
        for event in events
    ] != [
        (
            role,
            kind,
            envelope["response_completed_at"],
            envelope["response_completed_monotonic_ns"],
        )
        for role, kind, envelope in ordered
    ]:
        raise ValueError("Stage-C signed fragments 未按 frozen collection 排序")
    first_at = _iso(events[0]["observed_at"], "first native event")
    accepted_at = datetime.fromtimestamp(challenge["not_before"], UTC)
    if accepted_at >= first_at:
        raise ValueError("Stage-C first acquisition 未晚于 challenge not_before")
    challenge_event = {
        "schema": RAW_EVENT_SCHEMA,
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "seq": 0,
        "observed_at": accepted_at.isoformat(),
        "monotonic_ns": 0,
        "source": "registrar",
        "kind": "challenge.accepted",
        "payload": {
            "artifact": challenge_artifact,
            "consumption_receipt": consumption_receipt,
        },
    }
    complete = [challenge_event, *events]
    _verify_native_event_artifacts(
        complete,
        challenge=challenge,
        source_public_keys=source_public_keys,
        require_live_exact_release=True,
    )
    # Ensure the capability key supplied to the final producer is exactly the
    # challenge-bound one before persisting a stream that appears complete.
    if (
        ed25519_public_key_fingerprint(capability_authority_public_key)
        != challenge["capability_authority_key_fingerprint"]
    ):
        raise ValueError("Stage-C capability authority key 未绑定 challenge")
    return b"".join(
        canonical_bytes(event) + b"\n"
        for event in complete
    )
