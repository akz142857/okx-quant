"""Machine-verifiable Stage-C fault-driver and raw-event protocol.

The protocol deliberately separates three facts:

* an independent registrar authorizes one exact drill invocation;
* native collectors append a strict JSONL event stream;
* a deterministic parser derives the receipt fields from those bytes.

No caller-supplied summary participates in the derivation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import secrets
import sqlite3
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.ops.stage_c_build_provenance import (
    verify_build_provenance,
)
from okx_quant.ops.stage_c_implementation_inventory import (
    build_parser_source_manifest,
    implementation_inventory_document,
    implementation_inventory_sha256,
    production_instrumented_scenarios,
    shipped_scenarios,
)

RAW_EVENT_SCHEMA = "okx-quant.stage-c-native-event/v1"
CHALLENGE_ACTION = "authorize-stage-c-chaos-invocation-v1"
CAPABILITY_ACTION = "attest-stage-c-driver-capability-v1"
NATIVE_EVENT_ACTION = "attest-stage-c-native-event-v1"
RAW_OBSERVATION_ACTION = "attest-stage-c-derived-raw-evidence-v2"
CONSUMPTION_ACTION = "attest-stage-c-global-challenge-consumption-v1"
PARSER_PROTOCOL = "okx-quant.stage-c-native-parser/v1"

_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[0-9a-f]{32}")
_UUID = re.compile(
    r"(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})"
)
_IAM_ARN = re.compile(r"arn:aws:sts::[0-9]{12}:assumed-role/.+")

_EVENT_KEYS = {
    "schema",
    "scenario",
    "challenge_id",
    "seq",
    "observed_at",
    "monotonic_ns",
    "source",
    "kind",
    "payload",
}
_IDENTITY_KEYS = {
    "git_commit",
    "git_tree_hash",
    "source_manifest_sha256",
    "artifact_sha256",
    "artifact_build_id",
    "config_sha256",
    "account_uid",
    "environment",
    "unit",
    "soak_epoch_id",
    "stage_c_chaos_deployment_identity_sha256",
    "workspace_clean",
    "test_hooks_present",
}
_WORKLOAD_KEYS = {
    "host_id",
    "boot_id",
    "systemd_invocation_id",
    "pid",
    "uid",
    "cgroup",
    "executable_sha256",
    "parser_manifest_sha256",
    "iam_principal_arn",
    "iam_account_id",
    "iam_session_id",
}
_CHALLENGE_KEYS = {
    "version",
    "action",
    "challenge_id",
    "scenario",
    "driver_contract_sha256",
    "parser_manifest_sha256",
    "capability_attestation_sha256",
    "capability_authority_key_fingerprint",
    "source_key_fingerprints",
    "identity",
    "workloads",
    "provider_key_fingerprint",
    "raw_observer_key_fingerprint",
    "barrier_attestor_key_fingerprint",
    "kill_controller_key_fingerprint",
    "okx_observer_bindings",
    "barrier_recovery_bindings",
    "barrier_nonce",
    "consumption_backend",
    "consumption_key_fingerprint",
    "issued_at",
    "not_before",
    "expires_at",
    "registrar_key_fingerprint",
}
_BARRIER_RECOVERY_BINDING_KEYS = {
    "observer_api_key_fingerprint",
    "tls_certificate_sha256",
    "tls_spki_sha256",
}
_OKX_OBSERVER_BINDING_KEYS = {
    "observer_api_key_fingerprint",
    "tls_certificate_sha256",
    "tls_spki_sha256",
}
_CONSUMPTION_BACKEND_KEYS = {
    "kind",
    "table_name",
    "region",
    "account_id",
}
_CONSUMPTION_CLAIM_KEYS = {
    "version",
    "action",
    "challenge_id",
    "challenge_sha256",
    "scenario",
    "backend",
    "item",
    "conditional_put_response",
    "consistent_read_response",
    "consumed_at",
    "consumer_key_fingerprint",
}
_CAPABILITY_KEYS = {
    "version",
    "action",
    "scenario",
    "identity",
    "workloads",
    "native_attestations",
    "source_key_fingerprints",
    "issued_at",
    "expires_at",
    "authority_key_fingerprint",
}
_NATIVE_ATTESTATION_KEYS = {
    "systemd_show",
    "proc_status",
    "proc_cgroup",
    "proc_exe",
    "boot_id",
    "machine_id",
    "executable_sha256sum",
    "sts_get_caller_identity",
}
_NATIVE_EVENT_CLAIM_KEYS = {
    "version",
    "action",
    "scenario",
    "challenge_id",
    "seq",
    "observed_at",
    "monotonic_ns",
    "source",
    "kind",
    "workload_binding_sha256",
    "native_request",
    "native_response",
}
_NATIVE_REQUEST_KEYS = {
    "operation",
    "target",
    "transport",
    "request_id",
    "requested_at",
    "response_completed_at",
    "locator",
}

_SOURCE_TRANSPORT = {
    "systemd_collector": "systemd-dbus",
    "clock_collector": "chrony-unix-socket",
    "journal_collector": "sqlite-read-transaction",
    "provider": "provider-https",
    "okx_collector": "okx-https",
    "fault_controller": "unix-control-socket",
    "restore_verifier": "s3-exact-version-get",
    "build_attestor": "build-manifest-read",
    "barrier_attestor": "instrumented-hook-attestation",
    "trader_http_collector": "socket-write-trace",
    "kill_controller": "systemd-dbus-kill",
}


@dataclass(frozen=True)
class ScenarioProtocol:
    scenario: str
    artifact_class: str
    driver_id: str
    transition_events: tuple[tuple[str, str], ...]
    required_events: tuple[str, ...]
    barrier_name: str = ""


def _protocol(
    scenario: str,
    artifact_class: str,
    driver_id: str,
    transition_events: Iterable[tuple[str, str]],
    required_events: Iterable[str],
    *,
    barrier_name: str = "",
) -> ScenarioProtocol:
    return ScenarioProtocol(
        scenario=scenario,
        artifact_class=artifact_class,
        driver_id=driver_id,
        transition_events=tuple(transition_events),
        required_events=tuple(required_events),
        barrier_name=barrier_name,
    )


SCENARIO_PROTOCOLS: dict[str, ScenarioProtocol] = {
    "ws-partial-fill-recovery": _protocol(
        "ws-partial-fill-recovery",
        "exact_release_black_box",
        "okx-partial-fill-private-ws-driver/v1",
        (
            ("partial-fill-to-disconnected", "gateway.disconnected"),
            (
                "cumulative-fill-to-protected",
                "exchange.protection.active",
            ),
        ),
        (
            "exchange.order.partial",
            "gateway.disconnected",
            "exchange.order.cumulative_fill",
            "gateway.rest_baseline.completed",
            "exchange.protection.active",
        ),
    ),
    "external-pending-buy": _protocol(
        "external-pending-buy",
        "exact_release_black_box",
        "okx-external-pending-buy-driver/v1",
        (("external-buy-to-entry-freeze", "runtime.entry_frozen"),),
        ("exchange.order.external_pending", "runtime.entry_frozen"),
    ),
    "external-fill": _protocol(
        "external-fill",
        "exact_release_black_box",
        "okx-external-fill-driver/v1",
        (
            (
                "external-fill-to-protection",
                "exchange.protection.active",
            ),
        ),
        (
            "exchange.fill.external",
            "exchange.protection.active",
            "journal.protection_ownership",
        ),
    ),
    "external-protection-cancel": _protocol(
        "external-protection-cancel",
        "exact_release_black_box",
        "okx-external-protection-cancel-driver/v1",
        (
            (
                "protection-cancel-to-emergency",
                "runtime.emergency_exit",
            ),
        ),
        (
            "exchange.protection.canceled",
            "journal.protection_ownership",
            "runtime.emergency_exit",
        ),
    ),
    "frozen-balance": _protocol(
        "frozen-balance",
        "exact_release_black_box",
        "okx-frozen-balance-driver/v1",
        (
            (
                "frozen-balance-to-position-preserved",
                "journal.position_preserved",
            ),
        ),
        ("exchange.balance.frozen", "journal.position_preserved"),
    ),
    "clordid-conflict": _protocol(
        "clordid-conflict",
        "exact_release_black_box",
        "okx-clordid-conflict-driver/v1",
        (
            (
                "clordid-conflict-to-manual-review",
                "runtime.manual_review",
            ),
        ),
        ("exchange.clordid_conflict", "runtime.manual_review"),
    ),
    "rest-5xx-429-unknown": _protocol(
        "rest-5xx-429-unknown",
        "exact_release_black_box",
        "rest-write-fault-proxy-driver/v1",
        (
            ("ambiguous-write-to-unknown", "journal.intent_unknown"),
            (
                "unknown-to-safe-resolution",
                "journal.intent_resolved",
            ),
        ),
        (
            "proxy.ambiguous_write",
            "journal.intent_unknown",
            "journal.intent_resolved",
        ),
    ),
    "oco-active-process-death": _protocol(
        "oco-active-process-death",
        "exact_release_black_box",
        "systemd-oco-survival-driver/v1",
        (
            (
                "process-death-protection-survives",
                "exchange.protection.after_process_death",
            ),
            ("restart-to-reconciled", "runtime.restart_reconciled"),
        ),
        (
            "exchange.protection.before_process_death",
            "systemd.process_killed",
            "exchange.protection.after_process_death",
            "runtime.restart_reconciled",
            "startup.reconciliation",
        ),
    ),
    "restart-while-ws-down": _protocol(
        "restart-while-ws-down",
        "exact_release_black_box",
        "systemd-restart-ws-fault-driver/v1",
        (
            ("restart-to-not-ready", "runtime.not_ready"),
            ("baseline-to-ready", "gateway.rest_baseline.completed"),
        ),
        (
            "gateway.fault_control.blocked",
            "systemd.restart_requested",
            "runtime.not_ready",
            "gateway.rest_baseline.completed",
            "startup.reconciliation",
        ),
    ),
    "backup-db-corruption": _protocol(
        "backup-db-corruption",
        "exact_release_black_box",
        "offline-corruption-exact-restore-driver/v1",
        (
            ("corruption-to-halted", "runtime.halted"),
            ("verified-restore-to-ready", "runtime.ready_after_restore"),
        ),
        (
            "journal.corruption_detected",
            "runtime.halted",
            "backup.exact_version_restored",
            "runtime.ready_after_restore",
        ),
    ),
    "barrier-buy-intent-before-post": _protocol(
        "barrier-buy-intent-before-post",
        "instrumented_test_only",
        "instrumented-probe-barrier-driver/v1",
        (
            ("durable-intent-to-crash", "systemd.process_killed"),
            (
                "reclaim-to-rejected",
                "journal.intent_rejected_no_exchange_order",
            ),
        ),
        (
            "build.instrumented_provenance",
            "barrier.armed",
            "journal.intent_persisted",
            "barrier.reached",
            "systemd.process_killed",
            "runtime.recovery_started",
            "exchange.order.absent",
            "journal.intent_rejected_no_exchange_order",
        ),
        barrier_name="buy-intent-before-post",
    ),
    "barrier-post-before-ack": _protocol(
        "barrier-post-before-ack",
        "instrumented_test_only",
        "instrumented-probe-barrier-driver/v1",
        (
            ("post-to-crash-before-ack", "systemd.process_killed"),
            (
                "reclaim-to-clordid-resolution",
                "journal.clordid_resolved_without_duplicate",
            ),
        ),
        (
            "build.instrumented_provenance",
            "barrier.armed",
            "http.order_post_written",
            "barrier.reached",
            "systemd.process_killed",
            "runtime.recovery_started",
            "exchange.order.by_clordid",
            "journal.clordid_resolved_without_duplicate",
        ),
        barrier_name="post-before-ack",
    ),
    "barrier-fill-before-projection": _protocol(
        "barrier-fill-before-projection",
        "instrumented_test_only",
        "instrumented-probe-barrier-driver/v1",
        (
            ("fill-to-crash-before-projection", "systemd.process_killed"),
            (
                "reclaim-to-protected",
                "journal.fill_projection_recovered",
            ),
        ),
        (
            "build.instrumented_provenance",
            "barrier.armed",
            "exchange.fill.observed",
            "journal.projection_absent",
            "barrier.reached",
            "systemd.process_killed",
            "runtime.recovery_started",
            "journal.fill_projection_recovered",
        ),
        barrier_name="fill-before-projection",
    ),
}

# The five WP4/WP5 producers predate the native Stage-C catalogue.  They are
# deliberately kept in a separate registry so adding a contract cannot by
# itself promote a repository producer to a shipped executor.  The registry
# is nevertheless consumed by the challenge, bridge and parser contract
# paths; this makes the legacy producers first-class protocol participants
# instead of an undocumented exception to the 18-scenario inventory.
LEGACY_NATIVE_PROTOCOLS: dict[str, ScenarioProtocol] = {
    "ws-public": _protocol(
        "ws-public",
        "exact_release_black_box",
        "okx-ws-public-fault-driver/v1",
        (
            ("ready-to-degraded", "runtime.not_ready"),
            ("baseline-to-ready", "gateway.rest_baseline.completed"),
        ),
        (
            "gateway.fault_control.blocked",
            "runtime.not_ready",
            "gateway.rest_baseline.completed",
        ),
    ),
    "ws-private": _protocol(
        "ws-private",
        "exact_release_black_box",
        "okx-ws-private-fault-driver/v1",
        (
            ("ready-to-degraded", "runtime.not_ready"),
            ("baseline-to-ready", "gateway.rest_baseline.completed"),
        ),
        (
            "gateway.fault_control.blocked",
            "runtime.not_ready",
            "gateway.rest_baseline.completed",
        ),
    ),
    "ws-business": _protocol(
        "ws-business",
        "exact_release_black_box",
        "okx-ws-business-fault-driver/v1",
        (
            ("ready-to-degraded", "runtime.not_ready"),
            ("baseline-to-ready", "gateway.rest_baseline.completed"),
        ),
        (
            "gateway.fault_control.blocked",
            "runtime.not_ready",
            "gateway.rest_baseline.completed",
        ),
    ),
    "restart-sigterm": _protocol(
        "restart-sigterm",
        "exact_release_black_box",
        "systemd-restart-sigterm-driver/v1",
        (
            ("running-to-restarting", "systemd.restart_requested"),
            ("restarting-to-ready", "gateway.rest_baseline.completed"),
        ),
        (
            "systemd.restart_requested",
            "runtime.not_ready",
            "gateway.rest_baseline.completed",
            "startup.reconciliation",
        ),
    ),
    "restart-sigkill": _protocol(
        "restart-sigkill",
        "exact_release_black_box",
        "systemd-restart-sigkill-driver/v1",
        (
            ("running-to-restarting", "systemd.restart_requested"),
            ("restarting-to-ready", "gateway.rest_baseline.completed"),
        ),
        (
            "systemd.restart_requested",
            "runtime.not_ready",
            "gateway.rest_baseline.completed",
            "startup.reconciliation",
        ),
    ),
}


def _protocol_for_scenario(scenario: str) -> ScenarioProtocol | None:
    """Resolve both native-parser and legacy producer contracts."""
    return SCENARIO_PROTOCOLS.get(scenario) or LEGACY_NATIVE_PROTOCOLS.get(
        scenario
    )


ALL_SCENARIO_PROTOCOLS = {**SCENARIO_PROTOCOLS, **LEGACY_NATIVE_PROTOCOLS}

_COMMON_REQUIRED_EVENTS = (
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
)

_SOURCE_BY_PREFIX = {
    "challenge.": "registrar",
    "driver.": "systemd_collector",
    "systemd.": "systemd_collector",
    "clock.": "clock_collector",
    "reconciliation.": "journal_collector",
    "page.": "provider",
    "journal.": "journal_collector",
    "exchange.": "okx_collector",
    "runtime.": "journal_collector",
    "gateway.": "fault_controller",
    "proxy.": "fault_controller",
    "backup.": "restore_verifier",
    "build.": "build_attestor",
    "barrier.": "barrier_attestor",
    "http.": "trader_http_collector",
    "startup.": "journal_collector",
    "run.": "systemd_collector",
}


def _expected_source(scenario: str, kind: str) -> str:
    spec = _protocol_for_scenario(scenario)
    if spec is None:
        raise ValueError(f"Stage-C scenario 未注册: {scenario}")
    if kind == "systemd.process_killed":
        return (
            "kill_controller"
            if spec.barrier_name
            else "systemd_collector"
        )
    for prefix, source in _SOURCE_BY_PREFIX.items():
        if kind.startswith(prefix):
            return source
    raise ValueError(f"Stage-C native event kind 未注册 source: {kind}")


def acquisition_role_for_source(source: str) -> str:
    """Return the independently attested raw-acquisition role for a source.

    The event source owns the key that signs the final native event.  The
    acquisition role owns a different key/workload and attests the native
    bytes before the event signer can consume them.
    """
    if source not in {
        "clock_collector",
        "fault_controller",
        "journal_collector",
        "okx_collector",
        "provider",
        "restore_verifier",
        "systemd_collector",
        "trader_http_collector",
    }:
        raise ValueError(f"Stage-C source 不支持独立 acquisition role: {source}")
    return f"{source}_acquirer"


def required_source_roles(scenario: str) -> frozenset[str]:
    spec = _protocol_for_scenario(scenario)
    if spec is None:
        raise ValueError(f"Stage-C scenario 未注册: {scenario}")
    kinds = set(_COMMON_REQUIRED_EVENTS + spec.required_events)
    roles = {
        _expected_source(scenario, kind)
        for kind in kinds
        if kind != "challenge.accepted"
    }
    # Exact-release live envelopes must prove that native acquisition and
    # event signing occurred in separate systemd/UID/STS/key domains.  Test
    # fixtures may carry these frozen roles without claiming live evidence;
    # production parsing additionally requires their per-envelope signature.
    if spec.artifact_class == "exact_release_black_box":
        roles.update(
            acquisition_role_for_source(source)
            for source in tuple(roles)
        )
    if "provider" in roles:
        roles.add("provider_receipt_authority")
    roles.add("parser_signer")
    roles.add("challenge_consumer")
    # The process being faulted is an independently attested workload.  It is
    # deliberately not the systemd collector: conflating those roles would
    # let the collector attest/kill itself while the trader remained
    # unbound.  The role also owns the activation key used by the isolated
    # driver, so it participates in the global key-separation invariant.
    roles.add("fault_driver")
    return frozenset(roles)


def driver_contract_document(scenario: str) -> dict:
    spec = _protocol_for_scenario(scenario)
    if spec is None:
        raise ValueError(f"Stage-C scenario 尚无 producer protocol: {scenario}")
    return {
        "version": 1,
        "protocol": "okx-quant.stage-c-fault-driver/v1",
        "scenario": scenario,
        "artifact_class": spec.artifact_class,
        "driver_id": spec.driver_id,
        "transport": {
            "kind": "systemd-credential-jsonl",
            "stdin": "signed registrar challenge",
            "stdout": RAW_EVENT_SCHEMA,
            "exit_success": 0,
        },
        "transition_bindings": [
            {"transition_id": transition_id, "native_event": event}
            for transition_id, event in spec.transition_events
        ],
        "required_native_events": list(
            dict.fromkeys(_COMMON_REQUIRED_EVENTS + spec.required_events)
        ),
        "barrier_name": spec.barrier_name or None,
    }


_EXPECTED_IMPLEMENTATION_CLASSES = {
    scenario: spec.artifact_class
    for scenario, spec in SCENARIO_PROTOCOLS.items()
}
_EXPECTED_IMPLEMENTATION_SOURCE_ROLES = {
    scenario: required_source_roles(scenario)
    for scenario in SCENARIO_PROTOCOLS
}
_EXPECTED_IMPLEMENTATION_ADAPTERS = {
    scenario: hashlib.sha256(
        canonical_bytes(driver_contract_document(scenario))
    ).hexdigest()
    for scenario in SCENARIO_PROTOCOLS
}
_EXPECTED_NATIVE_FRAME_SCHEMA_SHA256 = hashlib.sha256(
    canonical_bytes({
        "native_event_schema": RAW_EVENT_SCHEMA,
        "parser_protocol": PARSER_PROTOCOL,
    })
).hexdigest()
PARSER_SOURCE_MANIFEST = build_parser_source_manifest()
IMPLEMENTATION_INVENTORY = implementation_inventory_document(
    _EXPECTED_IMPLEMENTATION_CLASSES,
    _EXPECTED_IMPLEMENTATION_SOURCE_ROLES,
    _EXPECTED_IMPLEMENTATION_ADAPTERS,
    _EXPECTED_NATIVE_FRAME_SCHEMA_SHA256,
)
IMPLEMENTATION_INVENTORY_SHA256 = implementation_inventory_sha256(
    _EXPECTED_IMPLEMENTATION_CLASSES,
    _EXPECTED_IMPLEMENTATION_SOURCE_ROLES,
    _EXPECTED_IMPLEMENTATION_ADAPTERS,
    _EXPECTED_NATIVE_FRAME_SCHEMA_SHA256,
)
PARSER_MANIFEST = {
    "version": 1,
    "protocol": PARSER_PROTOCOL,
    "event_schema": RAW_EVENT_SCHEMA,
    "parser_source_manifest": PARSER_SOURCE_MANIFEST,
    "implementation_inventory_sha256": IMPLEMENTATION_INVENTORY_SHA256,
    "scenario_contract_sha256": {
        scenario: hashlib.sha256(
            canonical_bytes(driver_contract_document(scenario))
        ).hexdigest()
        for scenario in sorted(SCENARIO_PROTOCOLS)
    },
}
PARSER_MANIFEST_SHA256 = hashlib.sha256(
    canonical_bytes(PARSER_MANIFEST)
).hexdigest()


def implemented_stage_c_scenarios() -> frozenset[str]:
    """Return only scenarios with a shipped real driver and native collectors.

    The protocol/parser is necessary but not sufficient production evidence.
    A scenario stays fail-closed until an independently reviewable executor
    performs the fault and its collectors acquire native system bytes.  Never
    infer implementation merely from registered schemas or Python callables.
    """
    current = implementation_inventory_sha256(
        _EXPECTED_IMPLEMENTATION_CLASSES,
        _EXPECTED_IMPLEMENTATION_SOURCE_ROLES,
        _EXPECTED_IMPLEMENTATION_ADAPTERS,
        _EXPECTED_NATIVE_FRAME_SCHEMA_SHA256,
    )
    if current != IMPLEMENTATION_INVENTORY_SHA256:
        raise RuntimeError("Stage-C implementation inventory 运行时漂移")
    return shipped_scenarios(
        _EXPECTED_IMPLEMENTATION_CLASSES,
        _EXPECTED_IMPLEMENTATION_SOURCE_ROLES,
        _EXPECTED_IMPLEMENTATION_ADAPTERS,
        _EXPECTED_NATIVE_FRAME_SCHEMA_SHA256,
    )


def production_instrumented_stage_c_scenarios() -> frozenset[str]:
    """Return barriers with a shipped production raw-acquisition envelope.

    Canonical fixture facts and the isolated harness are parser/test assets,
    not production evidence.  A barrier must remain absent from this explicit
    allowlist until its producer seals independently acquired raw bytes.
    """
    current = implementation_inventory_sha256(
        _EXPECTED_IMPLEMENTATION_CLASSES,
        _EXPECTED_IMPLEMENTATION_SOURCE_ROLES,
        _EXPECTED_IMPLEMENTATION_ADAPTERS,
        _EXPECTED_NATIVE_FRAME_SCHEMA_SHA256,
    )
    if current != IMPLEMENTATION_INVENTORY_SHA256:
        raise RuntimeError("Stage-C implementation inventory 运行时漂移")
    return production_instrumented_scenarios(
        _EXPECTED_IMPLEMENTATION_CLASSES,
        _EXPECTED_IMPLEMENTATION_SOURCE_ROLES,
        _EXPECTED_IMPLEMENTATION_ADAPTERS,
        _EXPECTED_NATIVE_FRAME_SCHEMA_SHA256,
    )


def _iso(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是 ISO-8601 字符串")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} 非法") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} 必须带时区")
    return parsed.astimezone(UTC)


def _strict_dict(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} schema 非法")
    return value


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} 必须是正整数")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} 必须是非负整数")
    return value


def _decimal(value: object, label: str, *, positive: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"{label} 必须是规范十进制字符串/整数")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"{label} 非法") from exc
    if not result.is_finite() or (positive and result <= 0):
        raise ValueError(f"{label} 非法")
    return result


def validate_stage_c_identity(value: object) -> dict:
    identity = _strict_dict(value, _IDENTITY_KEYS, "Stage-C identity")
    if (
        not _SHA1.fullmatch(str(identity["git_commit"]))
        or not _SHA1.fullmatch(str(identity["git_tree_hash"]))
        or not _SHA256.fullmatch(str(identity["source_manifest_sha256"]))
        or not _SHA256.fullmatch(str(identity["artifact_sha256"]))
        or not _SHA256.fullmatch(str(identity["config_sha256"]))
        or not _SHA256.fullmatch(
            str(identity["stage_c_chaos_deployment_identity_sha256"])
        )
        or identity["environment"] != "demo"
        or identity["workspace_clean"] is not True
        or type(identity["test_hooks_present"]) is not bool
        or any(
            not str(identity[key]).strip()
            for key in (
                "artifact_build_id",
                "account_uid",
                "unit",
                "soak_epoch_id",
            )
        )
    ):
        raise ValueError("Stage-C identity 非法")
    return identity


def validate_workload_attestation(value: object) -> dict:
    workload = _strict_dict(value, _WORKLOAD_KEYS, "workload attestation")
    if (
        not str(workload["host_id"]).strip()
        or not _UUID.fullmatch(str(workload["boot_id"]).lower())
        or not _UUID.fullmatch(
            str(workload["systemd_invocation_id"]).lower()
        )
        or _positive_int(workload["pid"], "workload pid") <= 1
        or _positive_int(workload["uid"], "workload uid") == 0
        or not str(workload["cgroup"]).startswith("/system.slice/")
        or not _SHA256.fullmatch(str(workload["executable_sha256"]))
        or workload["parser_manifest_sha256"] != PARSER_MANIFEST_SHA256
        or not _IAM_ARN.fullmatch(str(workload["iam_principal_arn"]))
        or not re.fullmatch(r"[0-9]{12}", str(workload["iam_account_id"]))
        or not str(workload["iam_session_id"]).strip()
    ):
        raise ValueError("workload systemd/cgroup/STS attestation 非法")
    return workload


def _native_text(
    attestation: dict,
    key: str,
    *,
    maximum_bytes: int = 64 * 1024,
) -> str:
    raw = _decode_opaque_bytes(
        attestation[key],
        f"capability {key}",
    )
    if len(raw) > maximum_bytes or b"\x00" in raw:
        raise ValueError(f"capability {key} raw bytes 非法")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"capability {key} 必须是 UTF-8") from exc


def derive_workload_from_native_attestation(value: object) -> dict:
    attestation = _strict_dict(
        value,
        _NATIVE_ATTESTATION_KEYS,
        "native workload attestation",
    )
    systemd_text = _native_text(attestation, "systemd_show")
    systemd_values: dict[str, str] = {}
    for line in systemd_text.splitlines():
        key, separator, raw = line.partition("=")
        if separator and key:
            if key in systemd_values:
                raise ValueError("systemd show property 重复")
            systemd_values[key] = raw
    if set(systemd_values) != {
        "Id",
        "InvocationID",
        "MainPID",
        "ControlGroup",
    }:
        raise ValueError("systemd show raw properties 不完整")
    proc_status = _native_text(attestation, "proc_status")
    uid_lines = [
        line for line in proc_status.splitlines() if line.startswith("Uid:")
    ]
    pid_lines = [
        line for line in proc_status.splitlines() if line.startswith("Pid:")
    ]
    if len(uid_lines) != 1 or len(pid_lines) != 1:
        raise ValueError("/proc status 缺少唯一 Pid/Uid")
    uid_values = uid_lines[0].split()[1:]
    if len(uid_values) != 4 or len(set(uid_values)) != 1:
        raise ValueError("/proc status real/effective UID 不一致")
    proc_cgroup = _native_text(attestation, "proc_cgroup").strip()
    prefix, separator, cgroup = proc_cgroup.partition("::")
    if separator != "::" or prefix != "0":
        raise ValueError("/proc cgroup 必须是 cgroup v2")
    proc_exe = _native_text(attestation, "proc_exe").strip()
    boot_id = _native_text(attestation, "boot_id").strip().lower()
    machine_id = _native_text(attestation, "machine_id").strip().lower()
    sha_line = _native_text(
        attestation,
        "executable_sha256sum",
    ).strip()
    sha_parts = sha_line.split(maxsplit=1)
    if (
        len(sha_parts) != 2
        or not _SHA256.fullmatch(sha_parts[0])
        or sha_parts[1].lstrip("*") != proc_exe
    ):
        raise ValueError("executable sha256sum 未绑定 /proc exe")
    try:
        sts = json.loads(
            _decode_opaque_bytes(
                attestation["sts_get_caller_identity"],
                "capability sts_get_caller_identity",
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("STS raw response 非 JSON") from exc
    if (
        not isinstance(sts, dict)
        or set(sts) != {"UserId", "Account", "Arn"}
    ):
        raise ValueError("STS get-caller-identity schema 非法")
    workload = {
        "host_id": machine_id,
        "boot_id": boot_id,
        "systemd_invocation_id": systemd_values["InvocationID"].lower(),
        "pid": int(systemd_values["MainPID"]),
        "uid": int(uid_values[0]),
        "cgroup": cgroup,
        "executable_sha256": sha_parts[0],
        "parser_manifest_sha256": PARSER_MANIFEST_SHA256,
        "iam_principal_arn": sts["Arn"],
        "iam_account_id": sts["Account"],
        "iam_session_id": sts["UserId"],
    }
    if (
        systemd_values["ControlGroup"] != cgroup
        or int(pid_lines[0].split()[1]) != workload["pid"]
        or not systemd_values["Id"].strip()
    ):
        raise ValueError("systemd show 与 /proc cgroup 未绑定同一进程")
    return validate_workload_attestation(workload)


def build_stage_c_capability_attestation(
    *,
    scenario: str,
    identity: dict,
    native_attestations: dict[str, dict],
    source_public_keys: dict[str, Path],
    authority_private_key: Path,
    lifetime_seconds: int = 600,
    now: int | None = None,
) -> dict:
    """Sign an independently collected systemd/STS/source-key capability."""
    if _protocol_for_scenario(scenario) is None:
        raise ValueError("Stage-C capability scenario 未实现")
    identity = validate_stage_c_identity(identity)
    required_roles = required_source_roles(scenario)
    if (
        set(source_public_keys) != set(required_roles)
        or set(native_attestations) != set(required_roles)
    ):
        raise ValueError(
            "Stage-C capability source key/workload roles 不完整: "
            f"required={sorted(required_roles)}"
        )
    native_attestations = {
        role: _strict_dict(
            value,
            _NATIVE_ATTESTATION_KEYS,
            f"{role} native workload attestation",
        )
        for role, value in sorted(native_attestations.items())
    }
    workloads = {
        role: derive_workload_from_native_attestation(value)
        for role, value in native_attestations.items()
    }
    workload_domains = {
        (
            value["uid"],
            value["cgroup"],
            value["systemd_invocation_id"],
            value["iam_principal_arn"],
            value["iam_session_id"],
        )
        for value in workloads.values()
    }
    if len(workload_domains) != len(workloads):
        raise ValueError(
            "Stage-C native source roles 必须使用不同 UID/cgroup/"
            "InvocationID/STS workload"
        )
    source_fingerprints = {
        role: ed25519_public_key_fingerprint(path)
        for role, path in sorted(source_public_keys.items())
    }
    authority_fingerprint = ed25519_public_key_fingerprint(
        authority_private_key,
        private_key=True,
    )
    all_fingerprints = {
        authority_fingerprint,
        *source_fingerprints.values(),
    }
    if len(all_fingerprints) != len(source_fingerprints) + 1:
        raise ValueError(
            "capability authority 与所有 native source 必须完全分钥"
        )
    issued_at = int(datetime.now(UTC).timestamp()) if now is None else now
    if (
        type(issued_at) is not int
        or issued_at <= 0
        or type(lifetime_seconds) is not int
        or not 30 <= lifetime_seconds <= 900
    ):
        raise ValueError("Stage-C capability window 非法")
    return sign_ed25519_payload(
        {
            "version": 1,
            "action": CAPABILITY_ACTION,
            "scenario": scenario,
            "identity": identity,
            "workloads": workloads,
            "native_attestations": native_attestations,
            "source_key_fingerprints": source_fingerprints,
            "issued_at": issued_at,
            "expires_at": issued_at + lifetime_seconds,
            "authority_key_fingerprint": authority_fingerprint,
        },
        authority_private_key,
    )


def verify_stage_c_capability_attestation(
    artifact: object,
    *,
    scenario: str,
    authority_public_key: Path,
    now: int | None,
) -> dict:
    claims = verify_ed25519_artifact(
        artifact,
        authority_public_key,
        label=f"{scenario} Stage-C deployment capability",
    )
    _strict_dict(claims, _CAPABILITY_KEYS, "Stage-C capability claims")
    authority_fingerprint = ed25519_public_key_fingerprint(
        authority_public_key
    )
    source_fingerprints = claims.get("source_key_fingerprints")
    required_roles = required_source_roles(scenario)
    current = int(datetime.now(UTC).timestamp()) if now is None else now
    if (
        claims["version"] != 1
        or claims["action"] != CAPABILITY_ACTION
        or claims["scenario"] != scenario
        or claims["authority_key_fingerprint"] != authority_fingerprint
        or not isinstance(source_fingerprints, dict)
        or set(source_fingerprints) != set(required_roles)
        or any(
            not _SHA256.fullmatch(str(fingerprint))
            for fingerprint in source_fingerprints.values()
        )
        or len(
            {
                authority_fingerprint,
                *source_fingerprints.values(),
            }
        )
        != len(source_fingerprints) + 1
        or type(claims["issued_at"]) is not int
        or type(claims["expires_at"]) is not int
        or not (
            claims["issued_at"]
            <= current
            <= claims["expires_at"]
            <= claims["issued_at"] + 900
        )
    ):
        raise ValueError(
            "Stage-C capability signature/window/role separation 非法"
        )
    validate_stage_c_identity(claims["identity"])
    workloads = claims.get("workloads")
    if (
        not isinstance(workloads, dict)
        or set(workloads) != set(required_roles)
    ):
        raise ValueError("Stage-C capability workload roles 非法")
    validated_workloads = {
        role: validate_workload_attestation(value)
        for role, value in workloads.items()
    }
    native_attestations = claims.get("native_attestations")
    if (
        not isinstance(native_attestations, dict)
        or set(native_attestations) != set(required_roles)
        or {
            role: derive_workload_from_native_attestation(value)
            for role, value in native_attestations.items()
        }
        != validated_workloads
    ):
        raise ValueError(
            "Stage-C capability raw systemd/proc/STS 未派生出 signed workload"
        )
    workload_domains = {
        (
            value["uid"],
            value["cgroup"],
            value["systemd_invocation_id"],
            value["iam_principal_arn"],
            value["iam_session_id"],
        )
        for value in validated_workloads.values()
    }
    if len(workload_domains) != len(validated_workloads):
        raise ValueError("Stage-C capability workload roles 复用")
    return claims


def issue_stage_c_challenge(
    *,
    scenario: str,
    capability_attestation: dict,
    capability_authority_public_key: Path,
    registrar_private_key: Path,
    consumption_backend: dict,
    okx_observer_bindings: dict | None = None,
    barrier_recovery_bindings: dict | None = None,
    lifetime_seconds: int = 600,
    now: int | None = None,
) -> dict:
    spec = _protocol_for_scenario(scenario)
    if spec is None:
        raise ValueError(f"Stage-C scenario 尚无 driver/parser: {scenario}")
    capability = verify_stage_c_capability_attestation(
        capability_attestation,
        scenario=scenario,
        authority_public_key=capability_authority_public_key,
        now=now,
    )
    identity = capability["identity"]
    workloads = capability["workloads"]
    if type(lifetime_seconds) is not int or not 30 <= lifetime_seconds <= 900:
        raise ValueError("Stage-C challenge lifetime 必须位于 30..900 秒")
    issued_at = int(datetime.now(UTC).timestamp()) if now is None else now
    if type(issued_at) is not int or issued_at <= 0:
        raise ValueError("Stage-C challenge now 非法")
    registrar_fingerprint = ed25519_public_key_fingerprint(
        registrar_private_key,
        private_key=True,
    )
    source_fingerprints = capability["source_key_fingerprints"]
    provider_fingerprint = source_fingerprints[
        "provider_receipt_authority"
    ]
    observer_fingerprint = source_fingerprints["parser_signer"]
    consumption_fingerprint = source_fingerprints["challenge_consumer"]
    barrier_fingerprint = source_fingerprints.get("barrier_attestor")
    kill_fingerprint = source_fingerprints.get("kill_controller")
    capability_authority_fingerprint = ed25519_public_key_fingerprint(
        capability_authority_public_key
    )
    fingerprints = {
        registrar_fingerprint,
        capability_authority_fingerprint,
        provider_fingerprint,
        observer_fingerprint,
        *source_fingerprints.values(),
    }
    if len(fingerprints) != len(source_fingerprints) + 2:
        raise ValueError(
            "registrar/capability authority/native sources 必须完全分钥"
        )
    if spec.barrier_name:
        if okx_observer_bindings is not None:
            raise ValueError("barrier challenge 禁止 exact-release OKX bindings")
        if barrier_fingerprint is None or kill_fingerprint is None:
            raise ValueError("instrumented barrier 缺少 attestor/kill key")
        if (
            identity["test_hooks_present"] is not True
            or identity["artifact_sha256"]
            == identity["source_manifest_sha256"]
        ):
            raise ValueError("barrier challenge 必须绑定独立 test-only build")
        recovery_bindings = _strict_dict(
            barrier_recovery_bindings,
            _BARRIER_RECOVERY_BINDING_KEYS,
            "Stage-C barrier recovery bindings",
        )
        if (
            not _SHA256.fullmatch(
                str(recovery_bindings["observer_api_key_fingerprint"])
            )
            or (
                scenario == "barrier-post-before-ack"
                and not all(
                    _SHA256.fullmatch(str(recovery_bindings[key]))
                    for key in ("tls_certificate_sha256", "tls_spki_sha256")
                )
            )
            or (
                scenario != "barrier-post-before-ack"
                and any(
                    recovery_bindings[key] is not None
                    for key in ("tls_certificate_sha256", "tls_spki_sha256")
                )
            )
        ):
            raise ValueError("Stage-C barrier recovery credential/TLS binding 非法")
    else:
        if barrier_recovery_bindings is not None:
            raise ValueError("exact-release challenge 禁止 barrier recovery bindings")
        recovery_bindings = None
        observer_bindings = _strict_dict(
            okx_observer_bindings,
            _OKX_OBSERVER_BINDING_KEYS,
            "Stage-C exact-release OKX observer bindings",
        )
        if not all(
            _SHA256.fullmatch(str(observer_bindings[key]))
            for key in _OKX_OBSERVER_BINDING_KEYS
        ):
            raise ValueError("Stage-C exact-release OKX credential/TLS binding 非法")
    if spec.barrier_name:
        observer_bindings = None
    contract_sha = hashlib.sha256(
        canonical_bytes(driver_contract_document(scenario))
    ).hexdigest()
    payload = {
        "version": 1,
        "action": CHALLENGE_ACTION,
        "challenge_id": secrets.token_hex(16),
        "scenario": scenario,
        "driver_contract_sha256": contract_sha,
        "parser_manifest_sha256": PARSER_MANIFEST_SHA256,
        "capability_attestation_sha256": hashlib.sha256(
            canonical_bytes(capability_attestation)
        ).hexdigest(),
        "capability_authority_key_fingerprint": (
            capability_authority_fingerprint
        ),
        "source_key_fingerprints": source_fingerprints,
        "identity": identity,
        "workloads": workloads,
        "provider_key_fingerprint": provider_fingerprint,
        "raw_observer_key_fingerprint": observer_fingerprint,
        "barrier_attestor_key_fingerprint": barrier_fingerprint,
        "kill_controller_key_fingerprint": kill_fingerprint,
        "okx_observer_bindings": observer_bindings,
        "barrier_recovery_bindings": recovery_bindings,
        "barrier_nonce": (
            secrets.token_hex(16) if spec.barrier_name else None
        ),
        "consumption_backend": validate_consumption_backend(
            consumption_backend
        ),
        "consumption_key_fingerprint": consumption_fingerprint,
        "issued_at": issued_at,
        "not_before": issued_at,
        "expires_at": issued_at + lifetime_seconds,
        "registrar_key_fingerprint": registrar_fingerprint,
    }
    if (
        workloads["challenge_consumer"]["iam_account_id"]
        != payload["consumption_backend"]["account_id"]
    ):
        raise ValueError(
            "challenge consumer STS account 未绑定 global backend account"
        )
    return sign_ed25519_payload(payload, registrar_private_key)


def validate_consumption_backend(value: object) -> dict:
    backend = _strict_dict(
        value,
        _CONSUMPTION_BACKEND_KEYS,
        "Stage-C global consumption backend",
    )
    if (
        backend["kind"] != "dynamodb-conditional-put-v1"
        or not re.fullmatch(
            r"[A-Za-z0-9_.-]{3,255}",
            str(backend["table_name"]),
        )
        or not re.fullmatch(
            r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]",
            str(backend["region"]),
        )
        or not re.fullmatch(r"[0-9]{12}", str(backend["account_id"]))
    ):
        raise ValueError("Stage-C global consumption backend 非法")
    return backend


def verify_stage_c_challenge(
    artifact: object,
    *,
    registrar_public_key: Path,
    scenario: str,
    now: int | None,
    enforce_current_window: bool,
) -> dict:
    claims = verify_ed25519_artifact(
        artifact,
        registrar_public_key,
        label=f"{scenario} Stage-C registrar challenge",
    )
    _strict_dict(claims, _CHALLENGE_KEYS, "Stage-C challenge claims")
    registrar_fingerprint = ed25519_public_key_fingerprint(
        registrar_public_key
    )
    spec = _protocol_for_scenario(scenario)
    expected_contract = hashlib.sha256(
        canonical_bytes(driver_contract_document(scenario))
    ).hexdigest()
    if (
        claims["version"] != 1
        or claims["action"] != CHALLENGE_ACTION
        or claims["scenario"] != scenario
        or not _RUN_ID.fullmatch(str(claims["challenge_id"]))
        or claims["driver_contract_sha256"] != expected_contract
        or claims["parser_manifest_sha256"] != PARSER_MANIFEST_SHA256
        or not _SHA256.fullmatch(
            str(claims["capability_attestation_sha256"])
        )
        or not _SHA256.fullmatch(
            str(claims["capability_authority_key_fingerprint"])
        )
        or not isinstance(claims["source_key_fingerprints"], dict)
        or set(claims["source_key_fingerprints"])
        != set(required_source_roles(scenario))
        or any(
            not _SHA256.fullmatch(str(fingerprint))
            for fingerprint in claims["source_key_fingerprints"].values()
        )
        or claims["registrar_key_fingerprint"] != registrar_fingerprint
        or type(claims["issued_at"]) is not int
        or type(claims["not_before"]) is not int
        or type(claims["expires_at"]) is not int
        or not (
            claims["issued_at"]
            == claims["not_before"]
            < claims["expires_at"]
            <= claims["issued_at"] + 900
        )
    ):
        raise ValueError("Stage-C challenge identity/window 非法")
    validate_stage_c_identity(claims["identity"])
    validate_consumption_backend(claims["consumption_backend"])
    workloads = claims.get("workloads")
    if (
        not isinstance(workloads, dict)
        or set(workloads) != set(required_source_roles(scenario))
    ):
        raise ValueError("Stage-C challenge workload roles 非法")
    validated_workloads = {
        role: validate_workload_attestation(value)
        for role, value in workloads.items()
    }
    if len({
        (
            item["uid"],
            item["cgroup"],
            item["systemd_invocation_id"],
            item["iam_principal_arn"],
            item["iam_session_id"],
        )
        for item in validated_workloads.values()
    }) != len(validated_workloads):
        raise ValueError("Stage-C challenge workload roles 复用")
    for key in (
        "provider_key_fingerprint",
        "raw_observer_key_fingerprint",
    ):
        if not _SHA256.fullmatch(str(claims[key])):
            raise ValueError("Stage-C challenge key fingerprint 非法")
    if spec is None:
        raise ValueError("Stage-C challenge scenario 未实现")
    if spec.barrier_name:
        if claims["okx_observer_bindings"] is not None:
            raise ValueError("barrier challenge 携带 exact-release OKX bindings")
        if (
            not _SHA256.fullmatch(
                str(claims["barrier_attestor_key_fingerprint"])
            )
            or not _SHA256.fullmatch(
                str(claims["kill_controller_key_fingerprint"])
            )
            or not _RUN_ID.fullmatch(str(claims["barrier_nonce"]))
            or len({
                registrar_fingerprint,
                claims["capability_authority_key_fingerprint"],
                *claims["source_key_fingerprints"].values(),
                claims["provider_key_fingerprint"],
                claims["raw_observer_key_fingerprint"],
                claims["barrier_attestor_key_fingerprint"],
                claims["kill_controller_key_fingerprint"],
            })
            != len(claims["source_key_fingerprints"]) + 2
        ):
            raise ValueError("Stage-C barrier challenge role separation 非法")
        recovery_bindings = _strict_dict(
            claims["barrier_recovery_bindings"],
            _BARRIER_RECOVERY_BINDING_KEYS,
            "Stage-C barrier recovery bindings",
        )
        if (
            not _SHA256.fullmatch(
                str(recovery_bindings["observer_api_key_fingerprint"])
            )
            or (
                scenario == "barrier-post-before-ack"
                and not all(
                    _SHA256.fullmatch(str(recovery_bindings[key]))
                    for key in ("tls_certificate_sha256", "tls_spki_sha256")
                )
            )
            or (
                scenario != "barrier-post-before-ack"
                and any(
                    recovery_bindings[key] is not None
                    for key in ("tls_certificate_sha256", "tls_spki_sha256")
                )
            )
        ):
            raise ValueError("Stage-C barrier recovery credential/TLS binding 非法")
    else:
        if any(
            claims[key] is not None
            for key in (
                "barrier_attestor_key_fingerprint",
                "kill_controller_key_fingerprint",
                "barrier_nonce",
                "barrier_recovery_bindings",
            )
        ):
            raise ValueError("exact-release challenge 携带 barrier claims")
        observer_bindings = _strict_dict(
            claims["okx_observer_bindings"],
            _OKX_OBSERVER_BINDING_KEYS,
            "Stage-C exact-release OKX observer bindings",
        )
        if not all(
            _SHA256.fullmatch(str(observer_bindings[key]))
            for key in _OKX_OBSERVER_BINDING_KEYS
        ):
            raise ValueError("Stage-C exact-release OKX credential/TLS binding 非法")
    if (
        claims["provider_key_fingerprint"]
        != claims["source_key_fingerprints"][
            "provider_receipt_authority"
        ]
        or claims["raw_observer_key_fingerprint"]
        != claims["source_key_fingerprints"]["parser_signer"]
        or claims["consumption_key_fingerprint"]
        != claims["source_key_fingerprints"]["challenge_consumer"]
        or claims["barrier_attestor_key_fingerprint"]
        != claims["source_key_fingerprints"].get("barrier_attestor")
        or claims["kill_controller_key_fingerprint"]
        != claims["source_key_fingerprints"].get("kill_controller")
        or claims["workloads"]["challenge_consumer"]["iam_account_id"]
        != claims["consumption_backend"]["account_id"]
    ):
        raise ValueError("Stage-C challenge source role fingerprint 串线")
    current = int(datetime.now(UTC).timestamp()) if now is None else now
    if enforce_current_window and not (
        claims["not_before"] <= current <= claims["expires_at"]
    ):
        raise ValueError("Stage-C challenge 尚未生效或已经过期")
    return claims


def consume_stage_c_challenge(
    *,
    registry: Path,
    challenge_artifact: dict,
    registrar_public_key: Path,
    scenario: str,
    now: int | None = None,
) -> dict:
    claims = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=registrar_public_key,
        scenario=scenario,
        now=now,
        enforce_current_window=True,
    )
    if registry.exists() and registry.is_symlink():
        raise ValueError("challenge registry 禁止符号链接")
    registry.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(registry)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_challenges (
                challenge_id TEXT PRIMARY KEY,
                scenario TEXT NOT NULL,
                challenge_sha256 TEXT NOT NULL,
                consumed_at INTEGER NOT NULL
            )
            """
        )
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO consumed_challenges(
                        challenge_id, scenario, challenge_sha256, consumed_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        claims["challenge_id"],
                        scenario,
                        hashlib.sha256(
                            canonical_bytes(challenge_artifact)
                        ).hexdigest(),
                        int(datetime.now(UTC).timestamp())
                        if now is None
                        else now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"Stage-C challenge 已消费: {claims['challenge_id']}"
            ) from exc
    finally:
        connection.close()
    return claims


def _opaque_bytes_descriptor(raw: bytes) -> dict:
    if not raw:
        raise ValueError("native opaque bytes 不得为空")
    return {
        "encoding": "base64",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "payload_base64": base64.b64encode(raw).decode("ascii"),
    }


def _decode_opaque_bytes(value: object, label: str) -> bytes:
    descriptor = _strict_dict(
        value,
        {"encoding", "sha256", "bytes", "payload_base64"},
        label,
    )
    if (
        descriptor["encoding"] != "base64"
        or not _SHA256.fullmatch(str(descriptor["sha256"]))
        or type(descriptor["bytes"]) is not int
        or not 0 < descriptor["bytes"] <= 2 * 1024 * 1024
        or not isinstance(descriptor["payload_base64"], str)
    ):
        raise ValueError(f"{label} descriptor 非法")
    try:
        raw = base64.b64decode(
            descriptor["payload_base64"],
            validate=True,
        )
    except ValueError as exc:
        raise ValueError(f"{label} base64 非法") from exc
    if (
        len(raw) != descriptor["bytes"]
        or hashlib.sha256(raw).hexdigest() != descriptor["sha256"]
    ):
        raise ValueError(f"{label} bytes/hash 不一致")
    return raw


def _consumption_item(challenge_artifact: dict, challenge: dict) -> dict:
    return {
        "challenge_id": {"S": challenge["challenge_id"]},
        "challenge_sha256": {
            "S": hashlib.sha256(
                canonical_bytes(challenge_artifact)
            ).hexdigest()
        },
        "scenario": {"S": challenge["scenario"]},
        "expires_at": {"N": str(challenge["expires_at"])},
    }


def build_stage_c_consumption_receipt(
    *,
    challenge_artifact: dict,
    registrar_public_key: Path,
    consumer_private_key: Path,
    conditional_put_response: bytes,
    consistent_read_response: bytes,
    consumed_at: int,
) -> dict:
    """Sign a global conditional-write receipt from native AWS CLI bytes."""
    challenge = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=registrar_public_key,
        scenario=str(challenge_artifact.get("payload", {}).get("scenario", "")),
        now=consumed_at,
        enforce_current_window=True,
    )
    fingerprint = ed25519_public_key_fingerprint(
        consumer_private_key,
        private_key=True,
    )
    if fingerprint != challenge["consumption_key_fingerprint"]:
        raise ValueError("global challenge consumer key 未绑定 registrar")
    try:
        put_response = json.loads(conditional_put_response)
        get_response = json.loads(consistent_read_response)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("DynamoDB consumption native response 非 JSON") from exc
    expected_item = _consumption_item(challenge_artifact, challenge)
    if (
        not isinstance(put_response, dict)
        or put_response.get("ConsumedCapacity", {}).get("TableName")
        != challenge["consumption_backend"]["table_name"]
        or not isinstance(get_response, dict)
        or get_response.get("Item") != expected_item
    ):
        raise ValueError(
            "DynamoDB conditional put/consistent read 未证明全局单次消费"
        )
    claims = {
        "version": 1,
        "action": CONSUMPTION_ACTION,
        "challenge_id": challenge["challenge_id"],
        "challenge_sha256": expected_item["challenge_sha256"]["S"],
        "scenario": challenge["scenario"],
        "backend": challenge["consumption_backend"],
        "item": expected_item,
        "conditional_put_response": _opaque_bytes_descriptor(
            conditional_put_response
        ),
        "consistent_read_response": _opaque_bytes_descriptor(
            consistent_read_response
        ),
        "consumed_at": consumed_at,
        "consumer_key_fingerprint": fingerprint,
    }
    return sign_ed25519_payload(claims, consumer_private_key)


def verify_stage_c_consumption_receipt(
    artifact: object,
    *,
    challenge_artifact: dict,
    registrar_public_key: Path,
    consumer_public_key: Path,
) -> dict:
    challenge = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=registrar_public_key,
        scenario=str(challenge_artifact.get("payload", {}).get("scenario", "")),
        now=None,
        enforce_current_window=False,
    )
    claims = verify_ed25519_artifact(
        artifact,
        consumer_public_key,
        label="Stage-C global challenge consumption receipt",
    )
    _strict_dict(
        claims,
        _CONSUMPTION_CLAIM_KEYS,
        "Stage-C consumption claims",
    )
    put_raw = _decode_opaque_bytes(
        claims["conditional_put_response"],
        "DynamoDB conditional put response",
    )
    get_raw = _decode_opaque_bytes(
        claims["consistent_read_response"],
        "DynamoDB consistent read response",
    )
    try:
        put_response = json.loads(put_raw)
        get_response = json.loads(get_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("DynamoDB consumption response 非 JSON") from exc
    expected_item = _consumption_item(challenge_artifact, challenge)
    consumer_fingerprint = ed25519_public_key_fingerprint(
        consumer_public_key
    )
    if (
        claims["version"] != 1
        or claims["action"] != CONSUMPTION_ACTION
        or claims["challenge_id"] != challenge["challenge_id"]
        or claims["challenge_sha256"]
        != expected_item["challenge_sha256"]["S"]
        or claims["scenario"] != challenge["scenario"]
        or claims["backend"] != challenge["consumption_backend"]
        or claims["item"] != expected_item
        or type(claims["consumed_at"]) is not int
        or not (
            challenge["not_before"]
            <= claims["consumed_at"]
            <= challenge["expires_at"]
        )
        or claims["consumer_key_fingerprint"] != consumer_fingerprint
        or consumer_fingerprint != challenge["consumption_key_fingerprint"]
        or put_response.get("ConsumedCapacity", {}).get("TableName")
        != challenge["consumption_backend"]["table_name"]
        or get_response.get("Item") != expected_item
    ):
        raise ValueError("Stage-C global consumption receipt 未精确绑定")
    return claims


def consume_stage_c_challenge_globally(
    *,
    challenge_artifact: dict,
    registrar_public_key: Path,
    consumer_private_key: Path,
    aws_executable: Path = Path("/usr/bin/aws"),
    now: int | None = None,
    command_runner=None,
) -> dict:
    """Atomically consume a challenge in the registrar-bound DynamoDB table."""
    current = int(datetime.now(UTC).timestamp()) if now is None else now
    challenge = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=registrar_public_key,
        scenario=str(challenge_artifact.get("payload", {}).get("scenario", "")),
        now=current,
        enforce_current_window=True,
    )
    backend = challenge["consumption_backend"]
    item = _consumption_item(challenge_artifact, challenge)
    common = [
        str(aws_executable),
        "dynamodb",
    ]
    runner = subprocess.run if command_runner is None else command_runner
    put = runner(
        [
            *common,
            "put-item",
            "--table-name",
            backend["table_name"],
            "--region",
            backend["region"],
            "--item",
            json.dumps(item, sort_keys=True, separators=(",", ":")),
            "--condition-expression",
            "attribute_not_exists(challenge_id)",
            "--return-consumed-capacity",
            "TOTAL",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        capture_output=True,
        check=False,
        timeout=15,
    )
    if put.returncode != 0:
        raise ValueError(
            "Stage-C challenge global conditional consumption 失败"
        )
    get = runner(
        [
            *common,
            "get-item",
            "--table-name",
            backend["table_name"],
            "--region",
            backend["region"],
            "--key",
            json.dumps(
                {"challenge_id": item["challenge_id"]},
                sort_keys=True,
                separators=(",", ":"),
            ),
            "--consistent-read",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        capture_output=True,
        check=False,
        timeout=15,
    )
    if get.returncode != 0:
        raise ValueError("Stage-C challenge global consistent read 失败")
    return build_stage_c_consumption_receipt(
        challenge_artifact=challenge_artifact,
        registrar_public_key=registrar_public_key,
        consumer_private_key=consumer_private_key,
        conditional_put_response=put.stdout,
        consistent_read_response=get.stdout,
        consumed_at=current,
    )


def build_fixture_signed_native_event(
    *,
    scenario: str,
    challenge_id: str,
    seq: int,
    observed_at: str,
    monotonic_ns: int,
    source: str,
    kind: str,
    facts: dict,
    workload: dict,
    source_private_key: Path,
    native_request: dict,
) -> dict:
    """Build synthetic signed input for parser tests only.

    This is deliberately not a production collector API and never contributes
    to ``implemented_stage_c_scenarios``.  Live collectors must acquire and
    sign their native bytes in a separately reviewed service.
    """
    if source != _expected_source(scenario, kind):
        raise ValueError("native event source 与 kind contract 不匹配")
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
    artifact = sign_ed25519_payload(claims, source_private_key)
    return {
        "schema": RAW_EVENT_SCHEMA,
        "scenario": scenario,
        "challenge_id": challenge_id,
        "seq": seq,
        "observed_at": observed_at,
        "monotonic_ns": monotonic_ns,
        "source": source,
        "kind": kind,
        "payload": {"artifact": artifact},
    }


def build_fixture_native_request_evidence(
    *,
    source: str,
    kind: str,
    observed_at: str,
    workload: dict,
    request_id: str,
    locator: dict | None = None,
) -> dict:
    """Build synthetic request metadata for parser fixtures only."""
    validate_workload_attestation(workload)
    completed = _iso(observed_at, "native response_completed_at")
    if locator is None:
        locator = _default_native_locator(source, kind, workload)
    request = {
        "operation": kind,
        "target": source,
        "transport": _SOURCE_TRANSPORT.get(source, ""),
        "request_id": request_id,
        "requested_at": (completed - timedelta(milliseconds=100)).isoformat(),
        "response_completed_at": completed.isoformat(),
        "locator": locator,
    }
    _validate_native_request(
        request,
        source=source,
        kind=kind,
        observed_at=observed_at,
        workload=workload,
    )
    return request


def _default_native_locator(
    source: str,
    kind: str,
    workload: dict,
) -> dict:
    seed = hashlib.sha256(
        canonical_bytes({
            "source": source,
            "kind": kind,
            "invocation_id": workload["systemd_invocation_id"],
        })
    ).hexdigest()
    if source == "okx_collector":
        if "balance" in kind:
            path = "/api/v5/account/balance"
        elif "algo" in kind or "protection" in kind:
            path = "/api/v5/trade/orders-algo-pending"
        elif "fill" in kind:
            path = "/api/v5/trade/fills-history"
        else:
            path = "/api/v5/trade/orders-pending"
        return {
            "method": "GET",
            "path": path,
            "http_status": 200,
            "response_headers_sha256": seed,
        }
    if source == "journal_collector":
        return {
            "database_sha256": seed,
            "query_sha256": hashlib.sha256(
                canonical_bytes({"query": kind})
            ).hexdigest(),
            "snapshot_txid": f"sqlite-snapshot:{seed[:24]}",
        }
    if source in {"systemd_collector", "kill_controller"}:
        return {
            "unit": workload["cgroup"].removeprefix(
                "/system.slice/"
            ),
            "systemd_invocation_id": workload[
                "systemd_invocation_id"
            ],
            "pid": workload["pid"],
            "cgroup": workload["cgroup"],
        }
    if source == "provider":
        return {
            "provider_request_id": f"provider:{seed[:24]}",
            "endpoint_sha256": seed,
        }
    if source == "clock_collector":
        return {"tracking_output_sha256": seed}
    if source == "fault_controller":
        return {
            "control_inode": int(seed[:8], 16) + 1,
            "actor_invocation_id": workload["systemd_invocation_id"],
        }
    if source == "restore_verifier":
        return {
            "object_uri": f"s3://stage-c-evidence/{seed[:16]}",
            "version_id": f"version-{seed[16:32]}",
        }
    if source == "build_attestor":
        return {
            "manifest_sha256": seed,
            "sbom_sha256": hashlib.sha256(
                canonical_bytes({"sbom": kind})
            ).hexdigest(),
        }
    if source == "barrier_attestor":
        return {
            "hook_read_sha256": seed,
            "attestor_invocation_id": workload[
                "systemd_invocation_id"
            ],
        }
    if source == "trader_http_collector":
        return {
            "socket_trace_sha256": seed,
            "peer": "www.okx.com:443",
        }
    raise ValueError(f"native source 尚无 request locator: {source}")


def _validate_native_request(
    value: object,
    *,
    source: str,
    kind: str,
    observed_at: str,
    workload: dict,
) -> dict:
    request = _strict_dict(
        value,
        _NATIVE_REQUEST_KEYS,
        f"{source}/{kind} native request",
    )
    requested = _iso(request["requested_at"], "native requested_at")
    completed = _iso(
        request["response_completed_at"],
        "native response_completed_at",
    )
    observed = _iso(observed_at, "native event observed_at")
    locator = request["locator"]
    if (
        request["operation"] != kind
        or request["target"] != source
        or request["transport"] != _SOURCE_TRANSPORT.get(source)
        or not str(request["request_id"]).strip()
        or not isinstance(locator, dict)
        or requested > completed
        or completed != observed
        or (completed - requested).total_seconds() > 30
    ):
        raise ValueError(f"{source}/{kind} native request/timing 非法")
    if source == "okx_collector":
        locator = _strict_dict(
            locator,
            {
                "method",
                "path",
                "http_status",
                "response_headers_sha256",
            },
            "OKX native request locator",
        )
        if (
            locator["method"] not in {"GET", "POST"}
            or not str(locator["path"]).startswith("/api/v5/")
            or type(locator["http_status"]) is not int
            or not 100 <= locator["http_status"] <= 599
            or not _SHA256.fullmatch(
                str(locator["response_headers_sha256"])
            )
        ):
            raise ValueError("OKX native request/response metadata 非法")
    elif source == "journal_collector":
        locator = _strict_dict(
            locator,
            {"database_sha256", "query_sha256", "snapshot_txid"},
            "journal snapshot/query locator",
        )
        if (
            not _SHA256.fullmatch(str(locator["database_sha256"]))
            or not _SHA256.fullmatch(str(locator["query_sha256"]))
            or not str(locator["snapshot_txid"]).startswith(
                "sqlite-snapshot:"
            )
        ):
            raise ValueError("journal snapshot/query evidence 非法")
    elif source in {"systemd_collector", "kill_controller"}:
        locator = _strict_dict(
            locator,
            {"unit", "systemd_invocation_id", "pid", "cgroup"},
            "systemd native locator",
        )
        if locator != {
            "unit": workload["cgroup"].removeprefix(
                "/system.slice/"
            ),
            "systemd_invocation_id": workload[
                "systemd_invocation_id"
            ],
            "pid": workload["pid"],
            "cgroup": workload["cgroup"],
        }:
            raise ValueError("systemd InvocationID/PID/cgroup 未精确绑定")
    elif source == "provider":
        locator = _strict_dict(
            locator,
            {"provider_request_id", "endpoint_sha256"},
            "provider native locator",
        )
        if (
            not str(locator["provider_request_id"]).strip()
            or not _SHA256.fullmatch(str(locator["endpoint_sha256"]))
        ):
            raise ValueError("provider request locator 非法")
    elif source == "clock_collector":
        locator = _strict_dict(
            locator,
            {"tracking_output_sha256"},
            "clock native locator",
        )
        if not _SHA256.fullmatch(str(locator["tracking_output_sha256"])):
            raise ValueError("chrony tracking bytes hash 非法")
    elif source == "fault_controller":
        locator = _strict_dict(
            locator,
            {"control_inode", "actor_invocation_id"},
            "fault-control native locator",
        )
        if (
            _positive_int(locator["control_inode"], "control inode") <= 0
            or locator["actor_invocation_id"]
            != workload["systemd_invocation_id"]
        ):
            raise ValueError("fault-control actor/inode 未精确绑定")
    elif source == "restore_verifier":
        locator = _strict_dict(
            locator,
            {"object_uri", "version_id"},
            "restore native locator",
        )
        if (
            not str(locator["object_uri"]).startswith("s3://")
            or not str(locator["version_id"]).strip()
        ):
            raise ValueError("restore exact-version locator 非法")
    elif source == "build_attestor":
        locator = _strict_dict(
            locator,
            {"manifest_sha256", "sbom_sha256"},
            "build native locator",
        )
        if not all(_SHA256.fullmatch(str(locator[key])) for key in locator):
            raise ValueError("build manifest/SBOM locator 非法")
    elif source == "barrier_attestor":
        locator = _strict_dict(
            locator,
            {"hook_read_sha256", "attestor_invocation_id"},
            "barrier native locator",
        )
        if (
            not _SHA256.fullmatch(str(locator["hook_read_sha256"]))
            or locator["attestor_invocation_id"]
            != workload["systemd_invocation_id"]
        ):
            raise ValueError("barrier hook/attestor locator 非法")
    elif source == "trader_http_collector":
        locator = _strict_dict(
            locator,
            {"socket_trace_sha256", "peer"},
            "HTTP socket native locator",
        )
        if (
            not _SHA256.fullmatch(str(locator["socket_trace_sha256"]))
            or locator["peer"] != "www.okx.com:443"
        ):
            raise ValueError("HTTP socket trace locator 非法")
    else:
        raise ValueError(f"native source 尚无 request validator: {source}")
    return request


def _native_bytes_descriptor(value: dict) -> dict:
    if not isinstance(value, dict):
        raise ValueError("native request/response 必须是 JSON object")
    raw = canonical_bytes(value)
    return {
        "encoding": "canonical-json-base64",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "payload_base64": base64.b64encode(raw).decode("ascii"),
    }


def _decode_native_bytes(value: object, label: str) -> dict:
    descriptor = _strict_dict(
        value,
        {"encoding", "sha256", "bytes", "payload_base64"},
        label,
    )
    if (
        descriptor["encoding"] != "canonical-json-base64"
        or not _SHA256.fullmatch(str(descriptor["sha256"]))
        or type(descriptor["bytes"]) is not int
        or descriptor["bytes"] <= 0
        or not isinstance(descriptor["payload_base64"], str)
    ):
        raise ValueError(f"{label} descriptor 非法")
    try:
        raw = base64.b64decode(
            descriptor["payload_base64"],
            validate=True,
        )
        parsed = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} bytes/base64 非法") from exc
    if (
        len(raw) != descriptor["bytes"]
        or hashlib.sha256(raw).hexdigest() != descriptor["sha256"]
        or not isinstance(parsed, dict)
        or canonical_bytes(parsed) != raw
    ):
        raise ValueError(f"{label} bytes/hash/canonical JSON 不一致")
    return parsed


def _verify_native_event_artifacts(
    events: list[dict],
    *,
    challenge: dict,
    source_public_keys: dict[str, Path],
    require_live_exact_release: bool = False,
) -> list[dict]:
    required_roles = required_source_roles(challenge["scenario"])
    if set(source_public_keys) != set(required_roles):
        raise ValueError(
            "Stage-C parser source keys 不完整或含多余角色: "
            f"required={sorted(required_roles)}"
        )
    actual_fingerprints = {
        role: ed25519_public_key_fingerprint(path)
        for role, path in source_public_keys.items()
    }
    if actual_fingerprints != challenge["source_key_fingerprints"]:
        raise ValueError("Stage-C parser source keys 未绑定 challenge capability")
    verified: list[dict] = [events[0]]
    for event in events[1:]:
        source = event["source"]
        artifact_container = _strict_dict(
            event["payload"],
            {"artifact"},
            f"native event seq={event['seq']}",
        )
        claims = verify_ed25519_artifact(
            artifact_container["artifact"],
            source_public_keys[source],
            label=f"Stage-C native {source}/{event['kind']}",
        )
        _strict_dict(
            claims,
            _NATIVE_EVENT_CLAIM_KEYS,
            f"native event seq={event['seq']} claims",
        )
        expected_envelope = {
            key: event[key]
            for key in (
                "scenario",
                "challenge_id",
                "seq",
                "observed_at",
                "monotonic_ns",
                "source",
                "kind",
            )
        }
        workload_sha = hashlib.sha256(
            canonical_bytes(challenge["workloads"][source])
        ).hexdigest()
        native_request = _decode_native_bytes(
            claims["native_request"],
            f"native event seq={event['seq']} request",
        )
        native_response = _decode_native_bytes(
            claims["native_response"],
            f"native event seq={event['seq']} response",
        )
        _validate_native_request(
            native_request,
            source=source,
            kind=event["kind"],
            observed_at=event["observed_at"],
            workload=challenge["workloads"][source],
        )
        if (
            claims["version"] != 1
            or claims["action"] != NATIVE_EVENT_ACTION
            or {
                key: claims[key] for key in expected_envelope
            }
            != expected_envelope
            or claims["workload_binding_sha256"] != workload_sha
        ):
            raise ValueError(
                f"Stage-C native event seq={event['seq']} 签名/envelope 串线"
            )
        # Production black-box producers sign native request/response bytes,
        # never already-derived facts.  Import lazily to keep the protocol
        # fixture builder independent and to avoid an import cycle.
        from okx_quant.ops.stage_c_exact_release_drivers import (
            derive_live_native_facts,
            is_live_acquisition_envelope,
            verify_live_acquisition_attestation,
        )

        if is_live_acquisition_envelope(native_response):
            if require_live_exact_release:
                acquisition_role = acquisition_role_for_source(source)
                native_response = verify_live_acquisition_attestation(
                    scenario=challenge["scenario"],
                    kind=event["kind"],
                    challenge=challenge,
                    envelope=native_response,
                    acquirer_public_key=source_public_keys[
                        acquisition_role
                    ],
                )
            native_response = derive_live_native_facts(
                native_response,
                scenario=challenge["scenario"],
                kind=event["kind"],
                challenge=challenge,
                workload=challenge["workloads"][source],
                observed_at=event["observed_at"],
            )
        elif require_live_exact_release:
            raise ValueError(
                "production Stage-C parser 拒绝 fixture/canonical facts；"
                "必须封存并重算 live acquisition bytes"
            )
        verified.append({
            **event,
            "payload": native_response,
            "native_request": native_request,
        })
    return verified


def _parse_events(raw_bytes: bytes, scenario: str) -> list[dict]:
    if not raw_bytes or len(raw_bytes) > 8 * 1024 * 1024:
        raise ValueError("Stage-C raw events 必须为 1..8MiB")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Stage-C raw events 必须是 UTF-8 JSONL") from exc
    lines = text.splitlines()
    if not lines or len(lines) > 10_000 or any(not line.strip() for line in lines):
        raise ValueError("Stage-C raw events JSONL 行数/空行非法")
    events: list[dict] = []
    challenge_id = ""
    previous_at: datetime | None = None
    source_anchors: dict[str, tuple[datetime, int]] = {}
    source_previous_mono: dict[str, int] = {}
    for seq, line in enumerate(lines):
        # The JSONL envelope itself is part of the signed/immutable evidence
        # boundary.  Reject duplicate keys and non-canonical encodings before
        # interpreting any field; ``json.loads``' last-key-wins behaviour
        # would otherwise let two byte-distinct envelopes represent the same
        # event to the parser.
        def _reject_duplicate_keys(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate JSON key")
                value[key] = item
            return value

        try:
            event = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Stage-C raw event seq={seq} JSON 非法") from exc
        _strict_dict(event, _EVENT_KEYS, f"raw event seq={seq}")
        try:
            canonical_line = canonical_bytes(event).decode("utf-8")
        except (TypeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Stage-C raw event seq={seq} canonical JSON 非法") from exc
        if canonical_line != line:
            raise ValueError(
                f"Stage-C raw event seq={seq} 必须使用 canonical JSONL 编码"
            )
        if (
            event["schema"] != RAW_EVENT_SCHEMA
            or event["scenario"] != scenario
            or event["seq"] != seq
            or not _RUN_ID.fullmatch(str(event["challenge_id"]))
            or type(event["monotonic_ns"]) is not int
            or event["monotonic_ns"] < 0
            or not str(event["source"]).strip()
            or not str(event["kind"]).strip()
            or not isinstance(event["payload"], dict)
            or event["kind"] in {"summary", "receipt", "derived.summary"}
        ):
            raise ValueError(f"Stage-C raw event seq={seq} envelope 非法")
        if event["source"] != _expected_source(
            scenario,
            str(event["kind"]),
        ):
            raise ValueError(
                f"Stage-C raw event seq={seq} 非 native source/kind"
            )
        observed_at = _iso(event["observed_at"], f"raw event seq={seq}")
        if seq == 0:
            challenge_id = event["challenge_id"]
        if (
            event["challenge_id"] != challenge_id
            or (previous_at is not None and observed_at < previous_at)
        ):
            raise ValueError("Stage-C raw event challenge/time/sequence 倒退")
        source = str(event["source"])
        previous_source_mono = source_previous_mono.get(source)
        if (
            previous_source_mono is not None
            and event["monotonic_ns"] <= previous_source_mono
        ):
            raise ValueError("Stage-C raw event source monotonic 时间倒退")
        anchor_at, anchor_mono = source_anchors.setdefault(
            source,
            (observed_at, event["monotonic_ns"]),
        )
        wall_delta = (observed_at - anchor_at).total_seconds()
        mono_delta = (
            event["monotonic_ns"] - anchor_mono
        ) / 1_000_000_000
        if abs(wall_delta - mono_delta) > 1.0:
            raise ValueError(
                f"Stage-C raw event seq={seq} source wall/monotonic 时间伪造"
            )
        previous_at = observed_at
        source_previous_mono[source] = event["monotonic_ns"]
        events.append(event)
    return events


def _single(by_kind: dict[str, list[dict]], kind: str) -> dict:
    rows = by_kind.get(kind, [])
    if len(rows) != 1:
        raise ValueError(f"Stage-C raw events 要求恰好一个 {kind}")
    return rows[0]


def _payload(event: dict, keys: set[str]) -> dict:
    return _strict_dict(
        event["payload"],
        keys,
        f"{event['kind']} payload",
    )


def _event_ref(raw_sha256: str, event: dict) -> str:
    return f"raw-sha256:{raw_sha256}:seq:{event['seq']}"


def _verify_provider_receipt(
    event: dict,
    *,
    challenge: dict,
    provider_public_key: Path,
) -> dict:
    payload = _payload(event, {"artifact"})
    artifact = payload["artifact"]
    claims = verify_ed25519_artifact(
        artifact,
        provider_public_key,
        label="Stage-C provider receipt",
    )
    expected_keys = {
        "version",
        "action",
        "challenge_id",
        "event_id",
        "event_name",
        "fault_correlation",
        "provider_event_id",
        "provider_received_at",
        "human_ack_at",
    }
    _strict_dict(claims, expected_keys, "Stage-C provider receipt claims")
    provider_at = _iso(
        claims["provider_received_at"],
        "provider received_at",
    )
    human_ack = claims["human_ack_at"]
    if human_ack is not None:
        human_at = _iso(human_ack, "provider human_ack_at")
        if human_at < provider_at:
            raise ValueError("Stage-C human ACK 早于 provider receipt")
    if (
        claims["version"] != 1
        or claims["action"] != "attest-stage-c-provider-receipt-v1"
        or claims["challenge_id"] != challenge["challenge_id"]
        or not all(
            str(claims[key]).strip()
            for key in (
                "event_id",
                "event_name",
                "fault_correlation",
                "provider_event_id",
            )
        )
        or not str(claims["event_name"]).startswith("page.")
        or ed25519_public_key_fingerprint(provider_public_key)
        != challenge["provider_key_fingerprint"]
        or abs(
            (
                provider_at
                - _iso(event["observed_at"], "provider event observed_at")
            ).total_seconds()
        )
        > 1
    ):
        raise ValueError("Stage-C provider artifact 未绑定 challenge/raw event")
    return {
        "required": True,
        "event_id": claims["event_id"],
        "event_name": claims["event_name"],
        "fault_correlation": claims["fault_correlation"],
        "provider_event_id": claims["provider_event_id"],
        "provider_artifact_sha256": hashlib.sha256(
            canonical_bytes(artifact)
        ).hexdigest(),
        "provider_received_at": provider_at.timestamp(),
        "human_ack_at": (
            _iso(human_ack, "provider human_ack_at").timestamp()
            if human_ack is not None
            else None
        ),
    }


def _verify_common_facts(
    by_kind: dict[str, list[dict]],
    *,
    challenge: dict,
    provider_public_key: Path,
) -> tuple[dict, dict, dict]:
    clock = _payload(
        _single(by_kind, "clock.sample"),
        {"ntp_synchronized", "max_error_ms"},
    )
    if (
        clock["ntp_synchronized"] is not True
        or isinstance(clock["max_error_ms"], bool)
        or not isinstance(clock["max_error_ms"], (int, float))
        or not math.isfinite(float(clock["max_error_ms"]))
        or not 0 <= float(clock["max_error_ms"]) <= 1000
    ):
        raise ValueError("Stage-C clock sample 不可信")
    reconciliation = _payload(
        _single(by_kind, "reconciliation.completed"),
        {
            "run_id",
            "status",
            "mismatch_count",
            "repaired_count",
            "unresolved",
        },
    )
    if (
        not str(reconciliation["run_id"]).strip()
        or reconciliation["status"] != "ok"
        or not isinstance(reconciliation["unresolved"], list)
        or reconciliation["unresolved"]
    ):
        raise ValueError("Stage-C reconciliation 未安全收敛")
    mismatch = _nonnegative_int(
        reconciliation["mismatch_count"],
        "reconciliation mismatch_count",
    )
    repaired = _nonnegative_int(
        reconciliation["repaired_count"],
        "reconciliation repaired_count",
    )
    page = _verify_provider_receipt(
        _single(by_kind, "page.provider_receipt"),
        challenge=challenge,
        provider_public_key=provider_public_key,
    )
    integrity = _payload(
        _single(by_kind, "journal.integrity"),
        {"result", "database_sha256"},
    )
    if (
        integrity["result"] != "ok"
        or not _SHA256.fullmatch(str(integrity["database_sha256"]))
    ):
        raise ValueError("Stage-C journal integrity 非 ok")
    duplicate = _payload(
        _single(by_kind, "journal.duplicate_buy_audit"),
        {"count", "intent_ids"},
    )
    if (
        _nonnegative_int(duplicate["count"], "duplicate BUY count") != 0
        or duplicate["intent_ids"] != []
    ):
        raise ValueError("Stage-C duplicate BUY audit 非零")
    positions = _payload(
        _single(by_kind, "journal.positions"),
        {"positions"},
    )["positions"]
    if not isinstance(positions, list):
        raise ValueError("Stage-C positions 不是数组")
    uncovered: list[str] = []
    nonzero = 0
    for position in positions:
        _strict_dict(
            position,
            {"inst_id", "base_qty", "protection_state"},
            "Stage-C position",
        )
        quantity = _decimal(
            position["base_qty"],
            "Stage-C position base_qty",
        )
        if quantity > 0:
            nonzero += 1
            if position["protection_state"] not in {
                "active",
                "emergency_exit",
            }:
                uncovered.append(str(position["inst_id"]))
    pending_orders = _payload(
        _single(by_kind, "exchange.pending_orders"),
        {"order_ids"},
    )["order_ids"]
    pending_algos = _payload(
        _single(by_kind, "exchange.pending_algos"),
        {"algo_ids"},
    )["algo_ids"]
    if (
        not isinstance(pending_orders, list)
        or any(not str(item).strip() for item in pending_orders)
        or not isinstance(pending_algos, list)
        or any(not str(item).strip() for item in pending_algos)
    ):
        raise ValueError("Stage-C pending order/algo facts 非法")
    balances = _payload(
        _single(by_kind, "exchange.balances"),
        {"balances"},
    )["balances"]
    if not isinstance(balances, dict) or any(
        _decimal(quantity, f"balance {currency}") < 0
        for currency, quantity in balances.items()
    ):
        raise ValueError("Stage-C balance facts 非法")
    mode = _payload(
        _single(by_kind, "runtime.mode"),
        {"mode"},
    )["mode"]
    if mode not in {
        "ready",
        "halted",
        "manual_review",
        "emergency_exit",
    }:
        raise ValueError("Stage-C final runtime mode 非法")
    startup_event = by_kind.get("startup.reconciliation", [])
    startup_seconds = None
    if startup_event:
        startup_payload = _payload(
            _single(by_kind, "startup.reconciliation"),
            {"seconds"},
        )
        seconds = startup_payload["seconds"]
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not math.isfinite(float(seconds))
            or not 0 <= float(seconds) <= 1800
        ):
            raise ValueError("Stage-C startup reconciliation time 非法")
        startup_seconds = float(seconds)
    receipt_reconciliation = {
        "required": True,
        "run_ids": [reconciliation["run_id"]],
        "mismatch_count": mismatch,
        "repaired_count": repaired,
        "unresolved": [],
    }
    postcondition = {
        "journal_integrity": "ok",
        "mode": mode,
        "duplicate_buy_count": 0,
        "uncovered_instruments": uncovered,
        "pending_order_count": len(pending_orders),
        "pending_algo_count": len(pending_algos),
        "local_nonzero_position_count": nonzero,
        "balances": balances,
        "residual_risk": list(uncovered),
        "startup_reconciliation_seconds": startup_seconds,
    }
    return receipt_reconciliation, page, postcondition


def _validate_scenario_facts(
    scenario: str,
    by_kind: dict[str, list[dict]],
    challenge: dict,
    *,
    barrier_attestor_public_key: Path | None,
    kill_controller_public_key: Path | None,
) -> None:
    def one(kind: str, keys: set[str]) -> dict:
        return _payload(_single(by_kind, kind), keys)

    if scenario in {"ws-public", "ws-private", "ws-business"}:
        channel = scenario.removeprefix("ws-")
        control = one(
            "gateway.fault_control.blocked",
            {"channel", "state", "control_inode"},
        )
        not_ready = one(
            "runtime.not_ready",
            {"ready", "mode", "pid"},
        )
        baseline = one(
            "gateway.rest_baseline.completed",
            {"channel", "generation", "safe"},
        )
        if (
            control["channel"] != channel
            or control["state"] != "blocked"
            or not str(control["control_inode"]).strip()
            or not_ready["ready"] is not False
            or not_ready["mode"] not in {"degraded", "halted", "starting"}
            or _positive_int(not_ready["pid"], "WS degraded pid") <= 0
            or baseline["channel"] != channel
            or _positive_int(baseline["generation"], "WS generation") <= 0
            or baseline["safe"] is not True
        ):
            raise ValueError("legacy WS native facts 非法")
    elif scenario in {"restart-sigterm", "restart-sigkill"}:
        restart = one(
            "systemd.restart_requested",
            {"old_pid", "systemd_invocation_id", "signal"},
        )
        not_ready = one(
            "runtime.not_ready",
            {"ready", "mode", "pid"},
        )
        baseline = one(
            "gateway.rest_baseline.completed",
            {"channel", "generation", "safe"},
        )
        startup = one("startup.reconciliation", {"seconds"})
        expected_signal = "SIGTERM" if scenario == "restart-sigterm" else "SIGKILL"
        if (
            restart["signal"] != expected_signal
            or _positive_int(restart["old_pid"], "restart old pid") <= 0
            or not str(restart["systemd_invocation_id"]).strip()
            or not_ready["ready"] is not False
            or not_ready["mode"] not in {"restarting", "starting", "halted"}
            or _positive_int(not_ready["pid"], "restart new pid") <= 0
            or not isinstance(baseline["channel"], str)
            or baseline["channel"] not in {"public", "private", "business"}
            or _positive_int(baseline["generation"], "restart generation") <= 0
            or baseline["safe"] is not True
            or isinstance(startup["seconds"], bool)
            or not isinstance(startup["seconds"], (int, float))
            or not math.isfinite(float(startup["seconds"]))
            or float(startup["seconds"]) < 0
            or float(startup["seconds"]) > 60
        ):
            raise ValueError("legacy restart native facts 非法")
    elif scenario == "ws-partial-fill-recovery":
        partial = one(
            "exchange.order.partial",
            {"ord_id", "cl_ord_id", "acc_fill_qty", "state"},
        )
        cumulative = one(
            "exchange.order.cumulative_fill",
            {"ord_id", "acc_fill_qty", "trade_ids"},
        )
        disconnected = one(
            "gateway.disconnected",
            {"channel", "generation"},
        )
        baseline = one(
            "gateway.rest_baseline.completed",
            {"channel", "generation", "safe"},
        )
        protection = one(
            "exchange.protection.active",
            {"algo_id", "ord_id", "protected_qty", "state"},
        )
        if (
            partial["state"] != "partially_filled"
            or partial["ord_id"] != cumulative["ord_id"]
            or _decimal(
                cumulative["acc_fill_qty"],
                "cumulative fill",
                positive=True,
            )
            <= _decimal(partial["acc_fill_qty"], "partial fill", positive=True)
            or not isinstance(cumulative["trade_ids"], list)
            or len(set(cumulative["trade_ids"])) != len(
                cumulative["trade_ids"]
            )
            or disconnected["channel"] != "private"
            or baseline != {
                "channel": "private",
                "generation": disconnected["generation"] + 1,
                "safe": True,
            }
            or protection["ord_id"] != partial["ord_id"]
            or protection["state"] != "live"
            or _decimal(protection["protected_qty"], "protected qty")
            != _decimal(cumulative["acc_fill_qty"], "cumulative fill")
        ):
            raise ValueError("partial-fill recovery native facts 不闭合")
    elif scenario == "external-pending-buy":
        order = one(
            "exchange.order.external_pending",
            {"ord_id", "cl_ord_id", "side", "state", "origin"},
        )
        frozen = one(
            "runtime.entry_frozen",
            {"mode", "new_buy_count"},
        )
        if (
            order["side"] != "buy"
            or order["state"] not in {"live", "partially_filled"}
            or order["origin"] != "external"
            or frozen["mode"] not in {"halted", "manual_review"}
            or frozen["new_buy_count"] != 0
        ):
            raise ValueError("external pending BUY native facts 非法")
    elif scenario == "external-fill":
        fill = one(
            "exchange.fill.external",
            {
                "ord_id",
                "cl_ord_id",
                "inst_id",
                "trade_ids",
                "side",
                "qty",
                "origin",
            },
        )
        protection = one(
            "exchange.protection.active",
            {
                "algo_id",
                "algo_cl_ord_id",
                "inst_id",
                "position_qty",
                "protected_qty",
                "lot_size",
                "state",
            },
        )
        ownership = one(
            "journal.protection_ownership",
            {
                "parent_intent_id",
                "parent_cl_ord_id",
                "parent_ord_id",
                "inst_id",
                "algo_cl_ord_id",
                "algo_id",
                "protected_qty",
                "state",
                "updated_at",
                "snapshot_sha256",
            },
        )
        if (
            fill["side"] != "buy"
            or fill["origin"] != "external"
            or not isinstance(fill["trade_ids"], list)
            or not fill["trade_ids"]
            or len(set(fill["trade_ids"])) != len(fill["trade_ids"])
            or not all(str(item).strip() for item in fill["trade_ids"])
            or ownership["parent_ord_id"] != fill["ord_id"]
            or ownership["parent_cl_ord_id"] != fill["cl_ord_id"]
            or protection["inst_id"] != fill["inst_id"]
            or ownership["inst_id"] != fill["inst_id"]
            or ownership["algo_id"] != protection["algo_id"]
            or ownership["algo_cl_ord_id"]
            != protection["algo_cl_ord_id"]
            or _decimal(
                ownership["protected_qty"],
                "journal protected qty",
                positive=True,
            )
            != _decimal(
                protection["protected_qty"],
                "exchange protected qty",
                positive=True,
            )
            or not str(ownership["parent_cl_ord_id"]).strip()
            or not str(ownership["parent_intent_id"]).strip()
            or not _SHA256.fullmatch(str(ownership["snapshot_sha256"]))
            or not str(protection["algo_cl_ord_id"]).strip()
            or protection["state"] != "live"
            or _decimal(fill["qty"], "external fill qty", positive=True)
            != _decimal(protection["position_qty"], "position qty", positive=True)
            or _decimal(
                protection["protected_qty"],
                "external protected qty",
                positive=True,
            )
            > _decimal(fill["qty"], "external fill qty", positive=True)
            or _decimal(fill["qty"], "external fill qty", positive=True)
            - _decimal(
                protection["protected_qty"],
                "external protected qty",
                positive=True,
            )
            >= _decimal(protection["lot_size"], "lot size", positive=True)
        ):
            raise ValueError("external fill/protection native facts 不闭合")
    elif scenario == "external-protection-cancel":
        canceled = one(
            "exchange.protection.canceled",
            {
                "algo_id",
                "algo_cl_ord_id",
                "inst_id",
                "observed_order_id",
                "observed_cl_ord_id",
                "state",
                "origin",
            },
        )
        ownership = one(
            "journal.protection_ownership",
            {
                "parent_intent_id",
                "parent_cl_ord_id",
                "parent_ord_id",
                "inst_id",
                "algo_cl_ord_id",
                "algo_id",
                "protected_qty",
                "state",
                "updated_at",
                "snapshot_sha256",
            },
        )
        emergency = one(
            "runtime.emergency_exit",
            {"mode", "algo_id"},
        )
        if (
            canceled["state"] != "canceled"
            or canceled["origin"] != "external"
            or not str(canceled["algo_cl_ord_id"]).strip()
            or ownership["algo_id"] != canceled["algo_id"]
            or ownership["algo_cl_ord_id"]
            != canceled["algo_cl_ord_id"]
            or ownership["inst_id"] != canceled["inst_id"]
            or ownership["parent_ord_id"]
            != canceled["observed_order_id"]
            or ownership["parent_cl_ord_id"]
            != canceled["observed_cl_ord_id"]
            or not _SHA256.fullmatch(str(ownership["snapshot_sha256"]))
            or emergency
            != {"mode": "emergency_exit", "algo_id": canceled["algo_id"]}
        ):
            raise ValueError("external protection cancel native facts 非法")
    elif scenario == "frozen-balance":
        balance = one(
            "exchange.balance.frozen",
            {
                "inst_id",
                "ccy",
                "total",
                "available",
                "locking_order_ids",
            },
        )
        preserved = one(
            "journal.position_preserved",
            {"inst_id", "base_qty"},
        )
        if (
            _decimal(balance["total"], "frozen total", positive=True) <= 0
            or balance["inst_id"] != preserved["inst_id"]
            or balance["ccy"].upper()
            != preserved["inst_id"].split("-", 1)[0].upper()
            or _decimal(balance["available"], "frozen available") != 0
            or not isinstance(balance["locking_order_ids"], list)
            or not balance["locking_order_ids"]
            or _decimal(
                preserved["base_qty"],
                "preserved position",
                positive=True,
            )
            <= 0
            or _decimal(
                balance["total"],
                "challenge frozen quantity",
                positive=True,
            )
            > _decimal(
                preserved["base_qty"],
                "preserved position",
                positive=True,
            )
        ):
            raise ValueError("frozen balance native facts 非法")
    elif scenario == "clordid-conflict":
        conflict = one(
            "exchange.clordid_conflict",
            {"cl_ord_id", "local_intent_id", "exchange_ord_id"},
        )
        manual = one(
            "runtime.manual_review",
            {"mode", "retry_count", "cl_ord_id"},
        )
        if (
            manual["mode"] != "manual_review"
            or manual["retry_count"] != 0
            or manual["cl_ord_id"] != conflict["cl_ord_id"]
        ):
            raise ValueError("clOrdId conflict native facts 非法")
    elif scenario == "rest-5xx-429-unknown":
        proxy = one(
            "proxy.ambiguous_write",
            {
                "method",
                "status_code",
                "request_id",
                "bytes_sent",
                "response_ambiguous",
            },
        )
        unknown = one(
            "journal.intent_unknown",
            {"cl_ord_id", "state", "retry_count"},
        )
        resolved = one(
            "journal.intent_resolved",
            {"cl_ord_id", "state", "duplicate_buy_count"},
        )
        if (
            proxy["method"] != "POST"
            or proxy["status_code"] not in {429, 500, 502, 503, 504}
            or proxy["bytes_sent"] is not True
            or proxy["response_ambiguous"] is not True
            or unknown
            != {
                "cl_ord_id": resolved["cl_ord_id"],
                "state": "unknown",
                "retry_count": 0,
            }
            or resolved["state"]
            not in {"acknowledged", "filled", "rejected", "manual_review"}
            or resolved["duplicate_buy_count"] != 0
        ):
            raise ValueError("ambiguous REST/UNKNOWN native facts 非法")
    elif scenario == "oco-active-process-death":
        before = one(
            "exchange.protection.before_process_death",
            {"algo_id", "state"},
        )
        killed = one(
            "systemd.process_killed",
            {"old_pid", "signal", "systemd_invocation_id"},
        )
        after = one(
            "exchange.protection.after_process_death",
            {"algo_id", "state", "verified_by"},
        )
        restart = one(
            "runtime.restart_reconciled",
            {"old_pid", "new_pid", "mode", "run_id"},
        )
        if (
            before["state"] != "live"
            or after
            != {
                "algo_id": before["algo_id"],
                "state": "live",
                "verified_by": "okx_rest",
            }
            or killed["signal"] != "SIGKILL"
            or killed["old_pid"] != restart["old_pid"]
            or restart["new_pid"] == restart["old_pid"]
            or restart["mode"] not in {"ready", "halted"}
        ):
            raise ValueError("OCO process-death native facts 非法")
    elif scenario == "restart-while-ws-down":
        control = one(
            "gateway.fault_control.blocked",
            {"channel", "state", "control_inode"},
        )
        restart = one(
            "systemd.restart_requested",
            {"old_pid", "systemd_invocation_id"},
        )
        not_ready = one(
            "runtime.not_ready",
            {"ready", "mode", "pid"},
        )
        baseline = one(
            "gateway.rest_baseline.completed",
            {"channel", "generation", "safe"},
        )
        if (
            control["state"] != "blocked"
            or control["channel"] not in {"public", "private", "business"}
            or not_ready["ready"] is not False
            or not_ready["mode"] not in {"starting", "halted"}
            or not_ready["pid"] == restart["old_pid"]
            or baseline["channel"] != control["channel"]
            or baseline["safe"] is not True
        ):
            raise ValueError("restart while WS down native facts 非法")
    elif scenario == "backup-db-corruption":
        corrupt = one(
            "journal.corruption_detected",
            {"database_sha256", "integrity_result"},
        )
        halted = one("runtime.halted", {"mode", "reason"})
        restore = one(
            "backup.exact_version_restored",
            {
                "object_uri",
                "version_id",
                "sha256",
                "bytes",
                "kms_key_id",
                "retain_until",
                "restored_database_sha256",
                "integrity_result",
            },
        )
        ready = one(
            "runtime.ready_after_restore",
            {"mode", "database_sha256"},
        )
        if (
            corrupt["integrity_result"] == "ok"
            or halted["mode"] != "halted"
            or not str(restore["object_uri"]).startswith("s3://")
            or not str(restore["version_id"]).strip()
            or not _SHA256.fullmatch(str(restore["sha256"]))
            or _positive_int(restore["bytes"], "restore bytes") <= 0
            or not str(restore["kms_key_id"]).strip()
            or _iso(restore["retain_until"], "restore retain_until")
            <= _iso(
                _single(by_kind, "run.completed")["observed_at"],
                "run completed",
            )
            or restore["integrity_result"] != "ok"
            or ready
            != {
                "mode": "ready",
                "database_sha256": restore[
                    "restored_database_sha256"
                ],
            }
        ):
            raise ValueError("backup corruption/restore native facts 非法")
    else:
        _validate_barrier_facts(
            scenario,
            by_kind,
            challenge,
            barrier_attestor_public_key=barrier_attestor_public_key,
            kill_controller_public_key=kill_controller_public_key,
        )


def _verify_role_attestation(
    artifact: object,
    public_key: Path,
    *,
    action: str,
    challenge: dict,
    extra: dict[str, object],
    label: str,
) -> dict:
    claims = verify_ed25519_artifact(artifact, public_key, label=label)
    expected = {
        "version": 1,
        "action": action,
        "challenge_id": challenge["challenge_id"],
        **extra,
    }
    if claims != expected:
        raise ValueError(f"{label} claims 未精确绑定 challenge/native fact")
    return claims


def _validate_barrier_facts(
    scenario: str,
    by_kind: dict[str, list[dict]],
    challenge: dict,
    *,
    barrier_attestor_public_key: Path | None,
    kill_controller_public_key: Path | None,
) -> None:
    spec = _protocol_for_scenario(scenario)
    if spec is None:
        raise ValueError(f"Stage-C scenario 未注册: {scenario}")
    if (
        barrier_attestor_public_key is None
        or kill_controller_public_key is None
    ):
        raise ValueError("instrumented barrier parser 缺少角色公钥")
    if (
        ed25519_public_key_fingerprint(barrier_attestor_public_key)
        != challenge["barrier_attestor_key_fingerprint"]
        or ed25519_public_key_fingerprint(kill_controller_public_key)
        != challenge["kill_controller_key_fingerprint"]
    ):
        raise ValueError("instrumented barrier role key 未绑定 challenge")
    provenance = _payload(
        _single(by_kind, "build.instrumented_provenance"),
        {
            "source_manifest_sha256",
            "artifact_sha256",
            "artifact_build_id",
            "sbom_sha256",
            "hook_sha256",
            "test_hooks_present",
            "production_env_enableable",
            "instrumented_artifact",
            "instrumented_manifest",
            "instrumented_sbom",
            "exact_release_artifact",
            "exact_release_manifest",
            "exact_release_sbom",
        },
    )
    identity = challenge["identity"]
    recomputed_build = verify_build_provenance(
        instrumented_archive=_decode_opaque_bytes(
            provenance["instrumented_artifact"],
            "instrumented artifact bytes",
        ),
        instrumented_manifest=_decode_opaque_bytes(
            provenance["instrumented_manifest"],
            "instrumented manifest bytes",
        ),
        instrumented_sbom=_decode_opaque_bytes(
            provenance["instrumented_sbom"],
            "instrumented SBOM bytes",
        ),
        exact_release_archive=_decode_opaque_bytes(
            provenance["exact_release_artifact"],
            "exact-release artifact bytes",
        ),
        exact_release_manifest=_decode_opaque_bytes(
            provenance["exact_release_manifest"],
            "exact-release manifest bytes",
        ),
        exact_release_sbom=_decode_opaque_bytes(
            provenance["exact_release_sbom"],
            "exact-release SBOM bytes",
        ),
        identity=identity,
        executable_sha256=challenge["identity"]["artifact_sha256"],
    )
    if (
        provenance["source_manifest_sha256"]
        != identity["source_manifest_sha256"]
        or provenance["artifact_sha256"] != identity["artifact_sha256"]
        or provenance["artifact_build_id"]
        != identity["artifact_build_id"]
        or provenance["source_manifest_sha256"]
        != recomputed_build["source_manifest_sha256"]
        or provenance["artifact_sha256"]
        != recomputed_build["instrumented_artifact_sha256"]
        or provenance["sbom_sha256"] != recomputed_build["sbom_sha256"]
        or provenance["hook_sha256"] != recomputed_build["hook_sha256"]
        or recomputed_build["production_hook_absent"] is not True
        or provenance["test_hooks_present"] is not True
        or provenance["production_env_enableable"] is not False
    ):
        raise ValueError("instrumented build/SBOM/hook provenance 非法")
    armed = _payload(
        _single(by_kind, "barrier.armed"),
        {"barrier", "nonce", "hook_sha256"},
    )
    reached = _payload(
        _single(by_kind, "barrier.reached"),
        {"attestation"},
    )
    if (
        armed["barrier"] != spec.barrier_name
        or armed["nonce"] != challenge["barrier_nonce"]
        or armed["hook_sha256"] != provenance["hook_sha256"]
    ):
        raise ValueError("barrier arm 未绑定 challenge nonce/hook")
    reached_event = _single(by_kind, "barrier.reached")
    reached_claims = verify_ed25519_artifact(
        reached["attestation"],
        barrier_attestor_public_key,
        label="Stage-C barrier reached attestation",
    )
    reached_expected_keys = {
        "version",
        "action",
        "challenge_id",
        "scenario",
        "barrier",
        "nonce",
        "artifact_sha256",
        "pid",
        "systemd_invocation_id",
        "observed_at",
        "monotonic_ns",
        "marker_sha256",
        "boundary_proof_sha256",
        "phase_consumption_sha256",
    }
    driver = challenge["workloads"]["fault_driver"]
    if (
        not isinstance(reached_claims, dict)
        or set(reached_claims) != reached_expected_keys
        or reached_claims["version"] != 2
        or reached_claims["action"]
        != "attest-stage-c-barrier-reached-v2"
        or reached_claims["challenge_id"] != challenge["challenge_id"]
        or reached_claims["scenario"] != scenario
        or reached_claims["barrier"] != spec.barrier_name
        or reached_claims["nonce"] != challenge["barrier_nonce"]
        or reached_claims["artifact_sha256"]
        != challenge["identity"]["artifact_sha256"]
        or reached_claims["pid"] != driver["pid"]
        or reached_claims["systemd_invocation_id"]
        != driver["systemd_invocation_id"]
        or reached_claims["observed_at"] != reached_event["observed_at"]
        or type(reached_claims["monotonic_ns"]) is not int
        or reached_claims["monotonic_ns"] <= 0
        or any(
            not _SHA256.fullmatch(str(reached_claims[key]))
            for key in (
                "marker_sha256",
                "boundary_proof_sha256",
                "phase_consumption_sha256",
            )
        )
    ):
        raise ValueError("Stage-C barrier reached v2 chain 非法")
    killed_event = _single(by_kind, "systemd.process_killed")
    killed = _payload(killed_event, {"attestation"})
    killed_claims = verify_ed25519_artifact(
        killed["attestation"],
        kill_controller_public_key,
        label="Stage-C kill controller attestation",
    )
    kill_expected_keys = {
        "version",
        "action",
        "challenge_id",
        "scenario",
        "barrier",
        "nonce",
        "artifact_sha256",
        "old_pid",
        "signal",
        "reached_artifact_sha256",
        "reached_consumption_sha256",
        "kill_consumption_sha256",
        "kill_command",
        "kill_response",
        "inactive_systemd_show",
        "old_process_inactive",
        "observed_at",
    }
    try:
        inactive_show = _decode_opaque_bytes(
            killed_claims["inactive_systemd_show"],
            "Stage-C kill inactive systemd show",
        ).decode()
        _decode_opaque_bytes(
            killed_claims["kill_command"],
            "Stage-C kill command",
        )
        _decode_opaque_bytes(
            killed_claims["kill_response"],
            "Stage-C kill response",
        )
        inactive_values = dict(
            line.split("=", 1)
            for line in inactive_show.splitlines()
            if "=" in line
        )
    except (KeyError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Stage-C kill v2 raw descriptors 非法") from exc
    if (
        not isinstance(killed_claims, dict)
        or set(killed_claims) != kill_expected_keys
        or killed_claims["version"] != 2
        or killed_claims["action"] != "attest-stage-c-process-kill-v2"
        or killed_claims["challenge_id"] != challenge["challenge_id"]
        or killed_claims["scenario"] != scenario
        or killed_claims["barrier"] != spec.barrier_name
        or killed_claims["nonce"] != challenge["barrier_nonce"]
        or killed_claims["artifact_sha256"]
        != challenge["identity"]["artifact_sha256"]
        or killed_claims["old_pid"] != driver["pid"]
        or killed_claims["signal"] != "SIGKILL"
        or killed_claims["reached_artifact_sha256"]
        != hashlib.sha256(
            canonical_bytes(reached["attestation"])
        ).hexdigest()
        or any(
            not _SHA256.fullmatch(str(killed_claims[key]))
            for key in (
                "reached_consumption_sha256",
                "kill_consumption_sha256",
            )
        )
        or killed_claims["old_process_inactive"] is not True
        or killed_claims["observed_at"] != killed_event["observed_at"]
        or int(inactive_values.get("MainPID", driver["pid"])) == driver["pid"]
        or inactive_values.get("ActiveState") == "active"
    ):
        raise ValueError("Stage-C process kill v2 chain 非法")
    recovery = _payload(
        _single(by_kind, "runtime.recovery_started"),
        {
            "old_pid",
            "new_pid",
            "boot_id",
            "systemd_invocation_id",
            "snapshot_sha256",
        },
    )
    if (
        recovery["old_pid"]
        != challenge["workloads"]["fault_driver"]["pid"]
        or _positive_int(recovery["new_pid"], "recovery new_pid")
        == recovery["old_pid"]
        or not _UUID.fullmatch(str(recovery["boot_id"]).lower())
        or not _UUID.fullmatch(
            str(recovery["systemd_invocation_id"]).lower()
        )
        or recovery["systemd_invocation_id"]
        == challenge["workloads"]["fault_driver"][
            "systemd_invocation_id"
        ]
        or not _SHA256.fullmatch(str(recovery["snapshot_sha256"]))
    ):
        raise ValueError("barrier recovery process facts 非法")
    provenance_event = _single(by_kind, "build.instrumented_provenance")
    armed_event = _single(by_kind, "barrier.armed")
    reached_event = _single(by_kind, "barrier.reached")
    killed_event = _single(by_kind, "systemd.process_killed")
    recovery_event = _single(by_kind, "runtime.recovery_started")
    if not (
        provenance_event["seq"]
        < armed_event["seq"]
        < reached_event["seq"]
        < killed_event["seq"]
        < recovery_event["seq"]
    ):
        raise ValueError("barrier build/arm/reach/kill/recovery 因果顺序非法")
    if scenario == "barrier-buy-intent-before-post":
        intent_event = _single(by_kind, "journal.intent_persisted")
        absent_event = _single(by_kind, "exchange.order.absent")
        rejected_event = _single(
            by_kind,
            "journal.intent_rejected_no_exchange_order",
        )
        intent = _payload(
            intent_event,
            {"cl_ord_id", "state", "db_committed"},
        )
        absent = _payload(
            absent_event,
            {"cl_ord_id", "lookup_sources"},
        )
        rejected = _payload(
            rejected_event,
            {"cl_ord_id", "state", "buy_post_count"},
        )
        if (
            not (
                armed_event["seq"]
                < intent_event["seq"]
                < reached_event["seq"]
                < killed_event["seq"]
                < recovery_event["seq"]
                < absent_event["seq"]
                < rejected_event["seq"]
            )
            or _iso(absent_event["observed_at"], "order absent observed_at")
            <= _iso(killed_event["observed_at"], "process killed observed_at")
            or intent["state"] != "BUY_SUBMITTING"
            or intent["db_committed"] is not True
            or absent["cl_ord_id"] != intent["cl_ord_id"]
            or set(absent["lookup_sources"])
            != {"pending", "history", "fills"}
            or rejected
            != {
                "cl_ord_id": intent["cl_ord_id"],
                "state": "REJECTED",
                "buy_post_count": 0,
            }
        ):
            raise ValueError("before-POST barrier recovery facts 非法")
    elif scenario == "barrier-post-before-ack":
        posted_event = _single(by_kind, "http.order_post_written")
        found_event = _single(by_kind, "exchange.order.by_clordid")
        resolved_event = _single(
            by_kind,
            "journal.clordid_resolved_without_duplicate",
        )
        posted = _payload(
            posted_event,
            {"cl_ord_id", "request_sha256", "socket_write_completed"},
        )
        found = _payload(
            found_event,
            {"cl_ord_id", "ord_id", "state"},
        )
        resolved = _payload(
            resolved_event,
            {"cl_ord_id", "ord_id", "duplicate_buy_count"},
        )
        if (
            not (
                armed_event["seq"]
                < posted_event["seq"]
                < reached_event["seq"]
                < killed_event["seq"]
                < recovery_event["seq"]
                < found_event["seq"]
                < resolved_event["seq"]
            )
            or _iso(found_event["observed_at"], "clOrdId observed_at")
            <= _iso(killed_event["observed_at"], "process killed observed_at")
            or posted["socket_write_completed"] is not True
            or not _SHA256.fullmatch(str(posted["request_sha256"]))
            or found["cl_ord_id"] != posted["cl_ord_id"]
            or resolved
            != {
                "cl_ord_id": posted["cl_ord_id"],
                "ord_id": found["ord_id"],
                "duplicate_buy_count": 0,
            }
        ):
            raise ValueError("POST-before-ACK barrier recovery facts 非法")
    else:
        fill_event = _single(by_kind, "exchange.fill.observed")
        absent_event = _single(by_kind, "journal.projection_absent")
        recovered_event = _single(
            by_kind,
            "journal.fill_projection_recovered",
        )
        fill = _payload(
            fill_event,
            {"ord_id", "trade_id", "qty"},
        )
        absent = _payload(
            absent_event,
            {"ord_id", "fill_apply_count"},
        )
        recovered = _payload(
            recovered_event,
            {
                "ord_id",
                "trade_id",
                "fill_apply_count",
                "protection_state",
            },
        )
        if (
            not (
                armed_event["seq"]
                < fill_event["seq"]
                < absent_event["seq"]
                < reached_event["seq"]
                < killed_event["seq"]
                < recovery_event["seq"]
                < recovered_event["seq"]
            )
            or _iso(
                recovered_event["observed_at"],
                "fill recovery observed_at",
            )
            <= _iso(killed_event["observed_at"], "process killed observed_at")
            or _decimal(fill["qty"], "barrier fill qty", positive=True) <= 0
            or absent
            != {"ord_id": fill["ord_id"], "fill_apply_count": 0}
            or recovered["ord_id"] != fill["ord_id"]
            or recovered["trade_id"] != fill["trade_id"]
            or recovered["fill_apply_count"] != 1
            or recovered["protection_state"]
            not in {"active", "emergency_exit"}
        ):
            raise ValueError("fill-before-projection recovery facts 非法")


def derive_stage_c_raw_observation(
    raw_bytes: bytes,
    *,
    scenario: str,
    registrar_public_key: Path,
    capability_authority_public_key: Path,
    provider_public_key: Path,
    raw_observer_public_key: Path,
    source_public_keys: dict[str, Path],
    barrier_attestor_public_key: Path | None = None,
    kill_controller_public_key: Path | None = None,
    require_live_exact_release: bool = False,
    require_production_evidence: bool = False,
) -> dict:
    spec = _protocol_for_scenario(scenario)
    if spec is None:
        raise ValueError(f"Stage-C scenario 尚无 raw parser: {scenario}")
    if (
        require_production_evidence
        and spec.artifact_class == "instrumented_test_only"
        and scenario
        not in production_instrumented_stage_c_scenarios()
    ):
        raise ValueError(
            "production Stage-C barrier 拒绝 canonical fixture/harness "
            "facts；尚无 allowlisted production raw acquisition producer"
        )
    events = _parse_events(raw_bytes, scenario)
    by_kind: dict[str, list[dict]] = {}
    for event in events:
        by_kind.setdefault(event["kind"], []).append(event)
    missing = sorted(
        set(_COMMON_REQUIRED_EVENTS + spec.required_events) - set(by_kind)
    )
    if missing:
        raise ValueError(f"Stage-C raw events 缺少 native facts: {missing}")
    challenge_event = _single(by_kind, "challenge.accepted")
    challenge_payload = _payload(
        challenge_event,
        {"artifact", "consumption_receipt"},
    )
    challenge = verify_stage_c_challenge(
        challenge_payload["artifact"],
        registrar_public_key=registrar_public_key,
        scenario=scenario,
        now=None,
        enforce_current_window=False,
    )
    if (
        events[0] is not challenge_event
        or challenge_event["source"] != "registrar"
        or challenge_event["challenge_id"] != challenge["challenge_id"]
        or ed25519_public_key_fingerprint(raw_observer_public_key)
        != challenge["raw_observer_key_fingerprint"]
    ):
        raise ValueError("Stage-C event stream 未从 registrar challenge 开始")
    verify_stage_c_consumption_receipt(
        challenge_payload["consumption_receipt"],
        challenge_artifact=challenge_payload["artifact"],
        registrar_public_key=registrar_public_key,
        consumer_public_key=source_public_keys["challenge_consumer"],
    )
    if (
        ed25519_public_key_fingerprint(
            capability_authority_public_key
        )
        != challenge["capability_authority_key_fingerprint"]
    ):
        raise ValueError("Stage-C capability authority key 未绑定 challenge")
    events = _verify_native_event_artifacts(
        events,
        challenge=challenge,
        source_public_keys=source_public_keys,
        require_live_exact_release=(
            require_live_exact_release or require_production_evidence
        ),
    )
    by_kind = {}
    for event in events:
        by_kind.setdefault(event["kind"], []).append(event)
    started_at = _iso(challenge_event["observed_at"], "challenge accepted")
    completed_event = _single(by_kind, "run.completed")
    completed = _iso(completed_event["observed_at"], "run completed")
    if (
        started_at.timestamp() < challenge["not_before"]
        or completed.timestamp() > challenge["expires_at"]
        or completed_event is not events[-1]
    ):
        raise ValueError("Stage-C raw event stream 超出 challenge window")
    invocation = _payload(
        _single(by_kind, "driver.invoked"),
        {
            "driver_id",
            "workload",
            "driver_contract_sha256",
            "capability_attestation",
        },
    )
    capability = verify_stage_c_capability_attestation(
        invocation["capability_attestation"],
        scenario=scenario,
        authority_public_key=capability_authority_public_key,
        now=int(started_at.timestamp()),
    )
    if (
        invocation["driver_id"] != spec.driver_id
        or invocation["workload"]
        != challenge["workloads"]["fault_driver"]
        or invocation["driver_contract_sha256"]
        != challenge["driver_contract_sha256"]
        or hashlib.sha256(
            canonical_bytes(invocation["capability_attestation"])
        ).hexdigest()
        != challenge["capability_attestation_sha256"]
        or capability["identity"] != challenge["identity"]
        or capability["workloads"] != challenge["workloads"]
        or capability["source_key_fingerprints"]
        != challenge["source_key_fingerprints"]
    ):
        raise ValueError("Stage-C driver invocation/capability 未绑定 challenge")
    completed_payload = _payload(completed_event, {"outcome"})
    if completed_payload["outcome"] != "completed":
        raise ValueError("Stage-C driver 未完成")
    _validate_scenario_facts(
        scenario,
        by_kind,
        challenge,
        barrier_attestor_public_key=barrier_attestor_public_key,
        kill_controller_public_key=kill_controller_public_key,
    )
    reconciliation, page, postcondition = _verify_common_facts(
        by_kind,
        challenge=challenge,
        provider_public_key=provider_public_key,
    )
    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    transitions = []
    previous = challenge_event
    from okx_quant.ops.demo_chaos_evidence import (
        expected_transitions_for,
    )

    expected_by_id = {
        item["transition_id"]: item
        for item in expected_transitions_for(scenario)
    }
    for transition_id, event_kind in spec.transition_events:
        event = _single(by_kind, event_kind)
        if event["seq"] <= previous["seq"]:
            raise ValueError("Stage-C transition native facts 顺序非法")
        expected = expected_by_id[transition_id]
        transitions.append({
            "transition_id": transition_id,
            "from_state": expected["from_state"],
            "to_state": expected["to_state"],
            "observed_at": event["observed_at"],
            "evidence_ids": [_event_ref(raw_sha256, event)],
        })
        previous = event
    provider_at = datetime.fromtimestamp(page["provider_received_at"], UTC)
    if (provider_at - started_at).total_seconds() > 60:
        raise ValueError("Stage-C provider receipt 超过 60 秒")
    return {
        "scenario": scenario,
        "challenge_id": challenge["challenge_id"],
        "consumption_receipt_sha256": hashlib.sha256(
            canonical_bytes(challenge_payload["consumption_receipt"])
        ).hexdigest(),
        "driver_contract_sha256": challenge["driver_contract_sha256"],
        "parser_manifest_sha256": PARSER_MANIFEST_SHA256,
        "identity": challenge["identity"],
        "workloads": challenge["workloads"],
        "started_at": started_at.isoformat(),
        "completed_at": completed.isoformat(),
        "fault_mechanism": spec.driver_id,
        "actual_transitions": transitions,
        "reconciliation": reconciliation,
        "page_receipt": page,
        "postcondition": postcondition,
        "errors": [],
        "passed": True,
        "raw_sha256": raw_sha256,
        "raw_bytes": len(raw_bytes),
        "expected_observer_key_fingerprint": challenge[
            "raw_observer_key_fingerprint"
        ],
    }


def build_stage_c_raw_observation_artifact(
    derived: dict,
    *,
    source: dict,
    observer_id: str,
    observer_private_key: Path,
) -> dict:
    if (
        not isinstance(source, dict)
        or set(source)
        != {"collector", "object_uri", "version_id", "sha256", "bytes"}
        or not observer_id.strip()
        or not str(source["collector"]).strip()
        or not str(source["object_uri"]).startswith("s3://")
        or not str(source["version_id"]).strip()
        or source["sha256"] != derived["raw_sha256"]
        or source["bytes"] != derived["raw_bytes"]
    ):
        raise ValueError("Stage-C raw source locator 未绑定 parsed bytes")
    observer_fingerprint = ed25519_public_key_fingerprint(
        observer_private_key,
        private_key=True,
    )
    if observer_fingerprint != derived[
        "expected_observer_key_fingerprint"
    ]:
        raise ValueError("Stage-C observer private key 未绑定 registrar challenge")
    payload = {
        "version": 2,
        "action": RAW_OBSERVATION_ACTION,
        "scenario": derived["scenario"],
        "challenge_id": derived["challenge_id"],
        "consumption_receipt_sha256": derived[
            "consumption_receipt_sha256"
        ],
        "observer_id": observer_id,
        "observer_key_fingerprint": observer_fingerprint,
        "source": source,
        "raw_event_protocol": RAW_EVENT_SCHEMA,
        "driver_contract_sha256": derived["driver_contract_sha256"],
        "parser_manifest_sha256": derived["parser_manifest_sha256"],
        "identity": derived["identity"],
        "workloads": derived["workloads"],
        "started_at": derived["started_at"],
        "completed_at": derived["completed_at"],
        "fault_mechanism": derived["fault_mechanism"],
        "actual_transitions": derived["actual_transitions"],
        "reconciliation": derived["reconciliation"],
        "page_receipt": derived["page_receipt"],
        "postcondition": derived["postcondition"],
        "errors": derived["errors"],
        "passed": derived["passed"],
    }
    return sign_ed25519_payload(payload, observer_private_key)


def build_stage_c_drill_receipt(
    derived: dict,
    *,
    raw_observation_artifact: dict,
) -> dict:
    """Build the strict receipt only from deterministic parser output."""
    scenario = str(derived.get("scenario", ""))
    spec = _protocol_for_scenario(scenario)
    if spec is None:
        raise ValueError("Stage-C derived scenario 未实现")
    identity = validate_stage_c_identity(derived["identity"])
    workloads = derived["workloads"]
    if not isinstance(workloads, dict):
        raise ValueError("Stage-C derived workloads 非法")
    workload = validate_workload_attestation(workloads["fault_driver"])
    result = {
        "version": 2,
        "action": "attest-demo-chaos-drill-v2",
        "scenario": scenario,
        "work_package": (
            "WP4"
            if scenario
            in {
                "ws-public",
                "ws-private",
                "ws-business",
                "ws-partial-fill-recovery",
                "external-pending-buy",
                "external-fill",
                "external-protection-cancel",
                "frozen-balance",
                "clordid-conflict",
                "rest-5xx-429-unknown",
            }
            else "WP5"
        ),
        "artifact_class": spec.artifact_class,
        "started_at": derived["started_at"],
        "completed_at": derived["completed_at"],
        "identity": identity,
        "execution": {
            "run_id": derived["challenge_id"],
            "executor": (
                "systemd:"
                f"{workload['systemd_invocation_id']}:"
                f"pid={workload['pid']}:uid={workload['uid']}"
            ),
            "host_id": (
                f"{workload['host_id']}:boot={workload['boot_id']}"
            ),
            "fault_mechanism": derived["fault_mechanism"],
            "evidence_origin": (
                "real_demo_black_box"
                if spec.artifact_class == "exact_release_black_box"
                else "instrumented_harness"
            ),
            "adapter": (
                "independent_raw_observation"
                if spec.artifact_class == "exact_release_black_box"
                else "instrumented_barrier_protocol"
            ),
            "raw_observation": raw_observation_artifact,
        },
        "expected_transitions": [],
        "actual_transitions": derived["actual_transitions"],
        "reconciliation": derived["reconciliation"],
        "page_receipt": derived["page_receipt"],
        "postcondition": derived["postcondition"],
        "errors": derived["errors"],
        "passed": derived["passed"],
    }
    from okx_quant.ops.demo_chaos_evidence import (
        expected_transitions_for,
        validate_drill_receipt,
    )

    result["expected_transitions"] = expected_transitions_for(scenario)
    return validate_drill_receipt(result)
