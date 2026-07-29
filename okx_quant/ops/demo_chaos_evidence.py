"""Strict WP4/WP5 drill receipts and Stage-C matrix coverage verification."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
)
from okx_quant.infrastructure.immutable_bundle import validate_bundle_manifest
from okx_quant.ops.stage_c_chaos_protocol import (
    PARSER_MANIFEST_SHA256,
    PARSER_PROTOCOL,
    SCENARIO_PROTOCOLS,
    build_stage_c_drill_receipt,
    derive_stage_c_raw_observation,
    driver_contract_document,
    implemented_stage_c_scenarios,
    required_source_roles,
)
from okx_quant.ops.stage_c_deployment_identity import (
    stage_c_chaos_deployment_identity_sha256,
    validate_stage_c_chaos_deployment_identity,
)

_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[0-9a-f]{32}")


class DrillArtifactClass(StrEnum):
    EXACT_RELEASE_BLACK_BOX = "exact_release_black_box"
    INSTRUMENTED_TEST_ONLY = "instrumented_test_only"


class StageCCapabilityLayer(StrEnum):
    """Append-only production capability lifecycle for raw Stage-C drills."""

    PARSER_READY = "PARSER_READY"
    EXECUTOR_SHIPPED = "EXECUTOR_SHIPPED"
    DEPLOYMENT_ATTESTED = "DEPLOYMENT_ATTESTED"
    REPOSITORY_PRODUCER = "REPOSITORY_PRODUCER"


@dataclass(frozen=True)
class DrillScenario:
    name: str
    work_package: str
    artifact_class: DrillArtifactClass
    expected_transitions: tuple[tuple[str, str, str, float], ...]
    reconciliation_required: bool = True
    page_receipt_required: bool = True
    startup_ready_max_seconds: float | None = None


def _transitions(
    *items: tuple[str, str, str, float],
) -> tuple[tuple[str, str, str, float], ...]:
    return items


# This is the stable, append-only WP4/WP5 acceptance catalogue. Renaming or
# removing an item invalidates the Stage-C coverage input rather than silently
# weakening the matrix.
DRILL_SCENARIOS: tuple[DrillScenario, ...] = (
    DrillScenario(
        "ws-public",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            ("ready-to-degraded", "ready", "degraded_or_halted", 20),
            ("baseline-to-ready", "degraded_or_halted", "ready", 60),
        ),
    ),
    DrillScenario(
        "ws-private",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            ("ready-to-degraded", "ready", "degraded_or_halted", 20),
            ("baseline-to-ready", "degraded_or_halted", "ready", 60),
        ),
    ),
    DrillScenario(
        "ws-business",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            ("ready-to-degraded", "ready", "degraded_or_halted", 20),
            ("baseline-to-ready", "degraded_or_halted", "ready", 60),
        ),
    ),
    DrillScenario(
        "ws-partial-fill-recovery",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "partial-fill-to-disconnected",
                "partially_filled",
                "degraded_or_halted",
                20,
            ),
            (
                "cumulative-fill-to-protected",
                "degraded_or_halted",
                "protected_or_emergency_exit",
                60,
            ),
        ),
    ),
    DrillScenario(
        "external-pending-buy",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "external-buy-to-entry-freeze",
                "external_pending_buy",
                "halted_or_manual_review",
                20,
            ),
        ),
    ),
    DrillScenario(
        "external-fill",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "external-fill-to-protection",
                "external_fill",
                "protected_or_emergency_exit",
                10,
            ),
        ),
    ),
    DrillScenario(
        "external-protection-cancel",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "protection-cancel-to-emergency",
                "protected",
                "emergency_exit",
                10,
            ),
        ),
    ),
    DrillScenario(
        "frozen-balance",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "frozen-balance-to-position-preserved",
                "available_zero_total_positive",
                "position_preserved",
                30,
            ),
        ),
    ),
    DrillScenario(
        "clordid-conflict",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "clordid-conflict-to-manual-review",
                "clordid_conflict",
                "manual_review",
                20,
            ),
        ),
    ),
    DrillScenario(
        "rest-5xx-429-unknown",
        "WP4",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "ambiguous-write-to-unknown",
                "submitting",
                "unknown",
                20,
            ),
            (
                "unknown-to-safe-resolution",
                "unknown",
                "resolved_or_manual_review",
                60,
            ),
        ),
    ),
    DrillScenario(
        "restart-sigterm",
        "WP5",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            ("running-to-restarting", "running_flat", "restarting", 30),
            ("restarting-to-ready", "restarting", "ready", 60),
        ),
        startup_ready_max_seconds=60,
    ),
    DrillScenario(
        "restart-sigkill",
        "WP5",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            ("running-to-restarting", "running_flat", "restarting", 30),
            ("restarting-to-ready", "restarting", "ready", 60),
        ),
        startup_ready_max_seconds=60,
    ),
    DrillScenario(
        "oco-active-process-death",
        "WP5",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "process-death-protection-survives",
                "oco_active",
                "exchange_protection_active",
                10,
            ),
            (
                "restart-to-reconciled",
                "exchange_protection_active",
                "ready_or_halted_safe",
                60,
            ),
        ),
        startup_ready_max_seconds=60,
    ),
    DrillScenario(
        "restart-while-ws-down",
        "WP5",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "restart-to-not-ready",
                "ws_disconnected",
                "starting_or_halted",
                20,
            ),
            (
                "baseline-to-ready",
                "starting_or_halted",
                "ready",
                60,
            ),
        ),
        startup_ready_max_seconds=60,
    ),
    DrillScenario(
        "backup-db-corruption",
        "WP5",
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX,
        _transitions(
            (
                "corruption-to-halted",
                "database_corrupt",
                "halted",
                20,
            ),
            (
                "verified-restore-to-ready",
                "halted",
                "ready",
                1800,
            ),
        ),
    ),
    DrillScenario(
        "barrier-buy-intent-before-post",
        "WP5",
        DrillArtifactClass.INSTRUMENTED_TEST_ONLY,
        _transitions(
            (
                "durable-intent-to-crash",
                "buy_submitting_pre_post",
                "process_crashed",
                5,
            ),
            (
                "reclaim-to-rejected",
                "process_crashed",
                "rejected_no_exchange_order",
                60,
            ),
        ),
    ),
    DrillScenario(
        "barrier-post-before-ack",
        "WP5",
        DrillArtifactClass.INSTRUMENTED_TEST_ONLY,
        _transitions(
            (
                "post-to-crash-before-ack",
                "post_sent",
                "process_crashed",
                5,
            ),
            (
                "reclaim-to-clordid-resolution",
                "process_crashed",
                "resolved_without_duplicate_buy",
                60,
            ),
        ),
    ),
    DrillScenario(
        "barrier-fill-before-projection",
        "WP5",
        DrillArtifactClass.INSTRUMENTED_TEST_ONLY,
        _transitions(
            (
                "fill-to-crash-before-projection",
                "exchange_filled",
                "process_crashed",
                5,
            ),
            (
                "reclaim-to-protected",
                "process_crashed",
                "protected_or_emergency_exit",
                60,
            ),
        ),
    ),
)

SCENARIO_BY_NAME = {item.name: item for item in DRILL_SCENARIOS}
if len(SCENARIO_BY_NAME) != len(DRILL_SCENARIOS):  # pragma: no cover
    raise RuntimeError("WP4/WP5 drill scenario 名称重复")

AUTOMATED_EXACT_RELEASE_SCENARIOS = frozenset({
    "ws-public",
    "ws-private",
    "ws-business",
    "restart-sigterm",
    "restart-sigkill",
})
INDEPENDENT_OBSERVATION_SCENARIOS = frozenset(
    item.name
    for item in DRILL_SCENARIOS
    if (
        item.artifact_class is DrillArtifactClass.EXACT_RELEASE_BLACK_BOX
        and item.name not in AUTOMATED_EXACT_RELEASE_SCENARIOS
    )
)
INSTRUMENTED_BARRIER_SCENARIOS = frozenset(
    item.name
    for item in DRILL_SCENARIOS
    if item.artifact_class is DrillArtifactClass.INSTRUMENTED_TEST_ONLY
)
RAW_RECOMPUTED_SCENARIOS = frozenset(
    INDEPENDENT_OBSERVATION_SCENARIOS | INSTRUMENTED_BARRIER_SCENARIOS
)
IMPLEMENTED_RAW_RECOMPUTED_SCENARIOS = implemented_stage_c_scenarios()
RAW_EXTERNAL_OPEN_SCENARIOS = frozenset(
    RAW_RECOMPUTED_SCENARIOS - IMPLEMENTED_RAW_RECOMPUTED_SCENARIOS
)
# Production admission covers all 18 scenarios.  The five legacy automated
# producers remain useful repository test assets, but do not have the
# challenge/workload/native semantic chain required of a shipped executor.
EXTERNAL_OPEN_SCENARIOS = frozenset(SCENARIO_BY_NAME)

# Stable, append-only capability requirements.  A parser contract alone never
# promotes a scenario beyond PARSER_READY.  New scenarios must be appended
# with their own executable and deployment requirements; generic wording is
# deliberately insufficient for an admission decision.
_RAW_CAPABILITY_REQUIREMENTS: tuple[tuple[str, str, str], ...] = (
    (
        "ws-partial-fill-recovery",
        "ship deterministic partial-fill/private-WS disconnect executor",
        "attest OKX liquidity plan, WS fault controller, journal and source roles",
    ),
    (
        "external-pending-buy",
        "ship external live BUY placement and entry-freeze executor",
        "attest external-order identity, OKX and journal collector roles",
    ),
    (
        "external-fill",
        "ship external fill creation and protection-observation executor",
        "attest external-fill identity, OKX and protection collector roles",
    ),
    (
        "external-protection-cancel",
        "ship external protection cancel and emergency-exit executor",
        "attest cancel identity, Page provider and emergency collector roles",
    ),
    (
        "frozen-balance",
        "ship balance-freeze fixture/order executor with positive total balance",
        "attest locking orders, balance and local-position collector roles",
    ),
    (
        "clordid-conflict",
        "ship deterministic duplicate-clOrdId conflict executor",
        "attest conflicting order identity and manual-review journal roles",
    ),
    (
        "rest-5xx-429-unknown",
        "ship ambiguous REST write fault proxy and safe-resolution executor",
        "attest proxy bytes-sent trace, OKX lookup and journal collector roles",
    ),
    (
        "oco-active-process-death",
        "ship SIGKILL/restart executor while an exchange OCO remains ACTIVE",
        "attest systemd kill, surviving OKX OCO and startup reconcile roles",
    ),
    (
        "restart-while-ws-down",
        "ship private-WS block plus systemd restart executor",
        "attest fault controller, new process and REST-baseline collector roles",
    ),
    (
        "backup-db-corruption",
        "ship offline corruption and exact-version restore executor",
        "attest corrupt DB, S3 exact-version restore and ready DB hashes",
    ),
    (
        "barrier-buy-intent-before-post",
        "ship isolated test-only durable-intent-before-POST barrier producer",
        "attest instrumented build, barrier, kill and exchange-absence roles",
    ),
    (
        "barrier-post-before-ack",
        "ship isolated test-only POST-before-ACK barrier producer",
        "attest socket-write, barrier, kill and clOrdId-resolution roles",
    ),
    (
        "barrier-fill-before-projection",
        "ship isolated test-only fill-before-projection barrier producer",
        "attest fill, absent projection, barrier, kill and recovery roles",
    ),
)
_RAW_CAPABILITY_REQUIREMENT_BY_SCENARIO = {
    scenario: {
        "executor": executor,
        "deployment": deployment,
    }
    for scenario, executor, deployment in _RAW_CAPABILITY_REQUIREMENTS
}
if (
    len(_RAW_CAPABILITY_REQUIREMENT_BY_SCENARIO)
    != len(_RAW_CAPABILITY_REQUIREMENTS)
    or set(_RAW_CAPABILITY_REQUIREMENT_BY_SCENARIO)
    != set(RAW_RECOMPUTED_SCENARIOS)
):  # pragma: no cover - import-time catalogue invariant
    raise RuntimeError(
        "Stage-C raw capability requirement catalogue must exactly cover "
        "the append-only raw scenario set"
    )

_RECEIPT_KEYS = {
    "version",
    "action",
    "scenario",
    "work_package",
    "artifact_class",
    "started_at",
    "completed_at",
    "identity",
    "execution",
    "expected_transitions",
    "actual_transitions",
    "reconciliation",
    "page_receipt",
    "postcondition",
    "errors",
    "passed",
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
_EXECUTION_KEYS = {
    "run_id",
    "executor",
    "host_id",
    "fault_mechanism",
    "evidence_origin",
    "adapter",
    "raw_observation",
}
_EXPECTED_TRANSITION_KEYS = {
    "transition_id",
    "from_state",
    "to_state",
    "deadline_seconds",
}
_ACTUAL_TRANSITION_KEYS = {
    "transition_id",
    "from_state",
    "to_state",
    "observed_at",
    "evidence_ids",
}
_RECONCILIATION_KEYS = {
    "required",
    "run_ids",
    "mismatch_count",
    "repaired_count",
    "unresolved",
}
_PAGE_RECEIPT_KEYS = {
    "required",
    "event_id",
    "event_name",
    "fault_correlation",
    "provider_event_id",
    "provider_artifact_sha256",
    "provider_received_at",
    "human_ack_at",
}
_POSTCONDITION_KEYS = {
    "journal_integrity",
    "mode",
    "duplicate_buy_count",
    "uncovered_instruments",
    "pending_order_count",
    "pending_algo_count",
    "local_nonzero_position_count",
    "balances",
    "residual_risk",
    "startup_reconciliation_seconds",
}
_BUNDLE_RECEIPT_KEYS = {
    "version",
    "action",
    "manifest_uri",
    "manifest_version_id",
    "manifest_sha256",
    "manifest_bytes",
    "verified_at",
}
_INDEPENDENT_READBACK_KEYS = {
    "version",
    "action",
    "scenario",
    "manifest_uri",
    "manifest_version_id",
    "manifest_sha256",
    "manifest_bytes",
    "manifest_signing_key_fingerprint",
    "verifier_key_id",
    "verifier_key_fingerprint",
    "result_uri",
    "result_version_id",
    "result_sha256",
    "result_bytes",
    "raw_observation_source",
    "raw_recompute",
    "verified_at",
}
_RAW_RECOMPUTE_KEYS = {
    "protocol",
    "parser_manifest_sha256",
    "raw_sha256",
    "raw_bytes",
    "recomputed_result_sha256",
}
_RAW_OBSERVATION_KEYS = {
    "version",
    "action",
    "scenario",
    "challenge_id",
    "consumption_receipt_sha256",
    "observer_id",
    "observer_key_fingerprint",
    "source",
    "raw_event_protocol",
    "driver_contract_sha256",
    "parser_manifest_sha256",
    "identity",
    "workloads",
    "started_at",
    "completed_at",
    "fault_mechanism",
    "actual_transitions",
    "reconciliation",
    "page_receipt",
    "postcondition",
    "errors",
    "passed",
}
_RAW_OBSERVATION_SOURCE_KEYS = {
    "collector",
    "object_uri",
    "version_id",
    "sha256",
    "bytes",
}
_STAGE_C_TRUST_MANIFEST_KEYS = {
    "version",
    "action",
    "parser_manifest_sha256",
    "raw_events_dir",
    "scenarios",
}
_STAGE_C_TRUST_SCENARIO_KEYS = {
    "trust_state",
    "driver_contract_sha256",
    "raw_events_file",
    "raw_events_sha256",
    "raw_events_bytes",
    "registrar_public_key",
    "capability_authority_public_key",
    "source_public_keys",
}
_STAGE_C_TRUST_KEY_KEYS = {"path", "fingerprint_sha256"}


def scenario_names(
    artifact_class: DrillArtifactClass | None = None,
) -> tuple[str, ...]:
    return tuple(
        item.name
        for item in DRILL_SCENARIOS
        if artifact_class is None or item.artifact_class is artifact_class
    )


def stage_c_capability_inventory(
    scenarios: Iterable[DrillScenario] | None = None,
) -> list[dict]:
    selected = DRILL_SCENARIOS if scenarios is None else tuple(scenarios)
    implemented_now = implemented_stage_c_scenarios()
    inventory: list[dict] = []
    for spec in selected:
        if spec.name in RAW_RECOMPUTED_SCENARIOS:
            requirements = _RAW_CAPABILITY_REQUIREMENT_BY_SCENARIO[
                spec.name
            ]
            parser_ready = spec.name in SCENARIO_PROTOCOLS
            executor_shipped = spec.name in implemented_now
            # Deployment attestation is deliberately never caller supplied.
            # It is established per evidence run only after the production
            # loader verifies the signed capability/workload/raw chain.
            is_deployment_attested = False
            if executor_shipped:
                layer = StageCCapabilityLayer.EXECUTOR_SHIPPED
            else:
                layer = StageCCapabilityLayer.PARSER_READY
            missing_requirements = []
            if not parser_ready:
                missing_requirements.append(
                    "register deterministic native parser contract"
                )
            if not executor_shipped:
                missing_requirements.append(requirements["executor"])
            if not is_deployment_attested:
                missing_requirements.append(requirements["deployment"])
            status = "EXTERNAL OPEN"
            requirement = "; ".join(missing_requirements)
            inventory.append({
                "scenario": spec.name,
                "work_package": spec.work_package,
                "artifact_class": spec.artifact_class.value,
                "status": status,
                "requirement": requirement,
                "capability_layer": layer.value,
                "parser_ready": parser_ready,
                "executor_shipped": executor_shipped,
                "deployment_attested": is_deployment_attested,
                "repository_producer": False,
                "missing_requirements": missing_requirements,
            })
            continue
        status = "EXTERNAL OPEN"
        requirement = (
            "repository producer exists; integrate immutable implementation "
            "inventory, challenge/workload identity, native semantic verifier "
            "and per-run deployment attestation"
        )
        inventory.append({
            "scenario": spec.name,
            "work_package": spec.work_package,
            "artifact_class": spec.artifact_class.value,
            "status": status,
            "requirement": requirement,
            "capability_layer": (
                StageCCapabilityLayer.REPOSITORY_PRODUCER.value
            ),
            "parser_ready": False,
            "executor_shipped": False,
            "deployment_attested": False,
            "repository_producer": True,
            "missing_requirements": [requirement],
        })
    return inventory


def require_stage_c_production_capabilities(
    scenarios: Iterable[DrillScenario],
) -> None:
    inventory = stage_c_capability_inventory(scenarios)
    blocked = [
        (
            f"{item['scenario']}[{item['capability_layer']}: "
            f"{'; '.join(item['missing_requirements'])}]"
        )
        for item in inventory
        if not item["parser_ready"] or not item["executor_shipped"]
    ]
    if blocked:
        raise ValueError(
            "Stage-C 生产证据能力仍为 EXTERNAL OPEN，禁止用签名摘要、"
            "raw locator 或手工 receipt 代替真实 driver/parser/producer: "
            + ", ".join(blocked)
        )


def expected_transitions_for(scenario: str) -> list[dict]:
    spec = SCENARIO_BY_NAME.get(scenario)
    if spec is None:
        raise ValueError(f"未知 WP4/WP5 drill scenario: {scenario}")
    return [
        {
            "transition_id": transition_id,
            "from_state": from_state,
            "to_state": to_state,
            "deadline_seconds": deadline,
        }
        for transition_id, from_state, to_state, deadline in (
            spec.expected_transitions
        )
    ]


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是 ISO-8601 字符串")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} 非法") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} 必须带时区")
    return parsed.astimezone(UTC)


def _nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} 必须是非负整数")
    return value


def _optional_positive_timestamp(value: object, label: str) -> float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError(f"{label} 必须是正有限 Unix timestamp 或 null")
    return float(value)


def _expected_adapter(spec: DrillScenario) -> str:
    if spec.name in AUTOMATED_EXACT_RELEASE_SCENARIOS:
        return "automated_control"
    if spec.name in INDEPENDENT_OBSERVATION_SCENARIOS:
        return "independent_raw_observation"
    return "instrumented_barrier_protocol"


def _validate_raw_observation_source(value: object) -> dict:
    source_uri = (
        urlparse(str(value.get("object_uri", "")))
        if isinstance(value, dict)
        else urlparse("")
    )
    if (
        not isinstance(value, dict)
        or set(value) != _RAW_OBSERVATION_SOURCE_KEYS
        or not str(value["collector"]).strip()
        or source_uri.scheme != "s3"
        or not source_uri.netloc
        or not str(value["version_id"]).strip()
        or not _SHA256.fullmatch(str(value["sha256"]))
        or type(value["bytes"]) is not int
        or value["bytes"] <= 0
    ):
        raise ValueError("independent raw observation source 非法")
    return value


def _raw_observation_claims_shape(
    artifact: object,
    *,
    scenario: str,
) -> dict:
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"payload", "signature"}
        or not isinstance(artifact["signature"], str)
        or not artifact["signature"].strip()
        or not isinstance(artifact["payload"], dict)
        or set(artifact["payload"]) != _RAW_OBSERVATION_KEYS
    ):
        raise ValueError(
            f"{scenario} independent raw observation artifact 非法"
        )
    claims = artifact["payload"]
    source = claims.get("source")
    _validate_raw_observation_source(source)
    if (
        claims["version"] != 2
        or claims["action"]
        != "attest-stage-c-derived-raw-evidence-v2"
        or claims["scenario"] != scenario
        or not _RUN_ID.fullmatch(str(claims["challenge_id"]))
        or not _SHA256.fullmatch(
            str(claims["consumption_receipt_sha256"])
        )
        or not str(claims["observer_id"]).strip()
        or not _SHA256.fullmatch(
            str(claims["observer_key_fingerprint"])
        )
        or claims["raw_event_protocol"]
        != "okx-quant.stage-c-native-event/v1"
        or not _SHA256.fullmatch(
            str(claims["driver_contract_sha256"])
        )
        or not _SHA256.fullmatch(
            str(claims["parser_manifest_sha256"])
        )
        or not isinstance(claims["workloads"], dict)
        or not str(claims["fault_mechanism"]).strip()
        or type(claims["passed"]) is not bool
        or not isinstance(claims["errors"], list)
    ):
        raise ValueError(
            f"{scenario} independent raw observation claims 非法"
        )
    _timestamp(claims["started_at"], "raw observation started_at")
    _timestamp(claims["completed_at"], "raw observation completed_at")
    return claims


def validate_drill_receipt(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != _RECEIPT_KEYS:
        raise ValueError("WP4/WP5 drill receipt schema 非法")
    scenario = str(value["scenario"])
    spec = SCENARIO_BY_NAME.get(scenario)
    if (
        spec is None
        or value["version"] != 2
        or value["action"] != "attest-demo-chaos-drill-v2"
        or value["work_package"] != spec.work_package
        or value["artifact_class"] != spec.artifact_class.value
    ):
        raise ValueError("WP4/WP5 drill receipt identity 非法")
    started = _timestamp(value["started_at"], "drill started_at")
    completed = _timestamp(value["completed_at"], "drill completed_at")
    if completed < started:
        raise ValueError("drill completed_at 早于 started_at")

    identity = value["identity"]
    if not isinstance(identity, dict) or set(identity) != _IDENTITY_KEYS:
        raise ValueError("drill artifact identity schema 非法")
    if (
        not _SHA1.fullmatch(str(identity["git_commit"]))
        or not _SHA1.fullmatch(str(identity["git_tree_hash"]))
        or not _SHA256.fullmatch(str(identity["source_manifest_sha256"]))
        or not _SHA256.fullmatch(str(identity["artifact_sha256"]))
        or not _SHA256.fullmatch(str(identity["config_sha256"]))
        or not _SHA256.fullmatch(
            str(identity["stage_c_chaos_deployment_identity_sha256"])
        )
        or not all(
            str(identity[key]).strip()
            for key in (
                "artifact_build_id",
                "account_uid",
                "unit",
                "soak_epoch_id",
            )
        )
        or identity["environment"] != "demo"
        or identity["workspace_clean"] is not True
        or type(identity["test_hooks_present"]) is not bool
    ):
        raise ValueError("drill artifact identity 非法")
    if spec.artifact_class is DrillArtifactClass.EXACT_RELEASE_BLACK_BOX:
        if (
            identity["test_hooks_present"] is not False
            or identity["artifact_sha256"]
            != identity["source_manifest_sha256"]
            or not str(identity["artifact_build_id"]).startswith(
                "exact-release:"
            )
            or "chaos" not in str(identity["unit"])
        ):
            raise ValueError(
                "exact-release drill 禁止 test hook 且必须绑定 Chaos release"
            )
    elif (
        identity["test_hooks_present"] is not True
        or identity["artifact_sha256"] == identity["source_manifest_sha256"]
        or not str(identity["artifact_build_id"]).startswith("test-only:")
    ):
        raise ValueError(
            "instrumented barrier 必须使用不同 test-only artifact identity"
        )

    execution = value["execution"]
    expected_origin = (
        "real_demo_black_box"
        if spec.artifact_class is DrillArtifactClass.EXACT_RELEASE_BLACK_BOX
        else "instrumented_harness"
    )
    expected_adapter = _expected_adapter(spec)
    if (
        not isinstance(execution, dict)
        or set(execution) != _EXECUTION_KEYS
        or not _RUN_ID.fullmatch(str(execution["run_id"]))
        or not all(
            str(execution[key]).strip()
            for key in ("executor", "host_id", "fault_mechanism")
        )
        or execution["evidence_origin"] != expected_origin
        or execution["adapter"] != expected_adapter
    ):
        raise ValueError("drill execution identity/origin 非法")
    raw_observation = execution["raw_observation"]
    if scenario in RAW_RECOMPUTED_SCENARIOS:
        raw_claims = _raw_observation_claims_shape(
            raw_observation,
            scenario=scenario,
        )
        if (
            raw_claims["challenge_id"] != execution["run_id"]
            or raw_claims["identity"] != identity
            or raw_claims["started_at"] != value["started_at"]
            or raw_claims["completed_at"] != value["completed_at"]
            or raw_claims["fault_mechanism"]
            != execution["fault_mechanism"]
            or raw_claims["actual_transitions"]
            != value["actual_transitions"]
            or raw_claims["reconciliation"] != value["reconciliation"]
            or raw_claims["page_receipt"] != value["page_receipt"]
            or raw_claims["postcondition"] != value["postcondition"]
            or raw_claims["errors"] != value["errors"]
            or raw_claims["passed"] is not value["passed"]
        ):
            raise ValueError(
                f"{scenario} raw observation 未精确绑定 drill receipt"
            )
    elif raw_observation is not None:
        raise ValueError(
            f"{scenario} adapter 禁止携带 independent raw observation"
        )

    expected = value["expected_transitions"]
    canonical_expected = expected_transitions_for(scenario)
    if expected != canonical_expected:
        raise ValueError("drill expected transitions 未绑定稳定场景目录")
    actual = value["actual_transitions"]
    if not isinstance(actual, list):
        raise ValueError("drill actual_transitions 必须是数组")
    expected_by_id = {
        item["transition_id"]: item for item in canonical_expected
    }
    seen_transition_ids: set[str] = set()
    previous_transition_at = started
    for item in actual:
        if (
            not isinstance(item, dict)
            or set(item) != _ACTUAL_TRANSITION_KEYS
            or item["transition_id"] in seen_transition_ids
            or item["transition_id"] not in expected_by_id
            or item["from_state"]
            != expected_by_id[item["transition_id"]]["from_state"]
            or item["to_state"]
            != expected_by_id[item["transition_id"]]["to_state"]
            or not isinstance(item["evidence_ids"], list)
            or not item["evidence_ids"]
            or any(not str(event_id).strip() for event_id in item["evidence_ids"])
        ):
            raise ValueError("drill actual transition 非法")
        observed = _timestamp(
            item["observed_at"],
            f"{item['transition_id']} observed_at",
        )
        if observed < started or observed > completed:
            raise ValueError("drill actual transition 时间超出执行窗口")
        if observed < previous_transition_at:
            raise ValueError("drill actual transition 观测时间倒退")
        elapsed = (observed - previous_transition_at).total_seconds()
        if elapsed > float(
            expected_by_id[item["transition_id"]]["deadline_seconds"]
        ):
            raise ValueError(
                f"{item['transition_id']} 超过场景 transition deadline"
            )
        previous_transition_at = observed
        seen_transition_ids.add(item["transition_id"])
    actual_transition_ids = [
        item["transition_id"] for item in actual
    ]
    expected_transition_ids = [
        item["transition_id"] for item in canonical_expected
    ]
    if actual_transition_ids != expected_transition_ids[
        : len(actual_transition_ids)
    ]:
        raise ValueError("drill actual transitions 顺序非法")

    reconciliation = value["reconciliation"]
    if (
        not isinstance(reconciliation, dict)
        or set(reconciliation) != _RECONCILIATION_KEYS
        or reconciliation["required"] is not spec.reconciliation_required
        or not isinstance(reconciliation["run_ids"], list)
        or any(not str(run_id).strip() for run_id in reconciliation["run_ids"])
        or not isinstance(reconciliation["unresolved"], list)
        or any(not str(item).strip() for item in reconciliation["unresolved"])
    ):
        raise ValueError("drill reconciliation schema 非法")
    _nonnegative_int(reconciliation["mismatch_count"], "mismatch_count")
    _nonnegative_int(reconciliation["repaired_count"], "repaired_count")

    page = value["page_receipt"]
    if (
        not isinstance(page, dict)
        or set(page) != _PAGE_RECEIPT_KEYS
        or page["required"] is not spec.page_receipt_required
        or any(
            not isinstance(page[key], str)
            for key in (
                "event_id",
                "event_name",
                "fault_correlation",
                "provider_event_id",
                "provider_artifact_sha256",
            )
        )
    ):
        raise ValueError("drill Page receipt schema 非法")
    provider_received = _optional_positive_timestamp(
        page["provider_received_at"],
        "provider_received_at",
    )
    human_ack = _optional_positive_timestamp(
        page["human_ack_at"],
        "human_ack_at",
    )
    if human_ack is not None and (
        provider_received is None or human_ack < provider_received
    ):
        raise ValueError("human_ack_at 必须晚于 provider_received_at")
    if provider_received is not None:
        provider_datetime = datetime.fromtimestamp(
            provider_received,
            UTC,
        )
        if (
            provider_datetime < started
            or provider_datetime > completed
            or (provider_datetime - started).total_seconds() > 60
        ):
            raise ValueError(
                "Page provider_received_at 必须位于执行窗口且故障后不超过 60 秒"
            )
    if human_ack is not None and datetime.fromtimestamp(
        human_ack,
        UTC,
    ) > completed:
        raise ValueError("Page human_ack_at 超出 drill 执行窗口")

    postcondition = value["postcondition"]
    if (
        not isinstance(postcondition, dict)
        or set(postcondition) != _POSTCONDITION_KEYS
        or not isinstance(postcondition["mode"], str)
        or not isinstance(postcondition["uncovered_instruments"], list)
        or not isinstance(postcondition["balances"], dict)
        or not isinstance(postcondition["residual_risk"], list)
        or any(
            not isinstance(item, str)
            for item in (
                postcondition["uncovered_instruments"]
                + postcondition["residual_risk"]
            )
        )
    ):
        raise ValueError("drill postcondition schema 非法")
    for key in (
        "duplicate_buy_count",
        "pending_order_count",
        "pending_algo_count",
        "local_nonzero_position_count",
    ):
        _nonnegative_int(postcondition[key], key)
    startup_seconds = postcondition["startup_reconciliation_seconds"]
    if startup_seconds is not None and (
        isinstance(startup_seconds, bool)
        or not isinstance(startup_seconds, (int, float))
        or not math.isfinite(float(startup_seconds))
        or float(startup_seconds) < 0
    ):
        raise ValueError("startup_reconciliation_seconds 非法")

    errors = value["errors"]
    if (
        not isinstance(errors, list)
        or any(not isinstance(error, str) or not error for error in errors)
        or type(value["passed"]) is not bool
        or value["passed"] is not (not errors)
    ):
        raise ValueError("drill errors/passed 非法")
    if value["passed"]:
        if seen_transition_ids != set(expected_by_id):
            raise ValueError("通过的 drill 缺少实际状态迁移")
        if (
            spec.reconciliation_required
            and not reconciliation["run_ids"]
        ):
            raise ValueError("通过的 drill 缺少 reconciliation run")
        if reconciliation["unresolved"]:
            raise ValueError("通过的 drill 存在 unresolved reconciliation")
        if spec.page_receipt_required and (
            not str(page["event_id"]).strip()
            or not str(page["event_name"]).startswith("page.")
            or not str(page["fault_correlation"]).strip()
            or not str(page["provider_event_id"]).strip()
            or not _SHA256.fullmatch(
                str(page["provider_artifact_sha256"])
            )
            or provider_received is None
        ):
            raise ValueError("通过的 drill 缺少 provider Page receipt")
        if (
            execution["adapter"] == "automated_control"
            and (
                (
                    scenario.startswith("ws-")
                    and page["event_name"]
                    != "page.ws_error_budget_exhausted"
                )
                or (
                    scenario.startswith("restart-")
                    and page["event_name"] != "page.external_watchdog"
                )
            )
        ):
            raise ValueError(
                "automated drill Page receipt 未绑定预期故障告警"
            )
        if (
            postcondition["journal_integrity"] != "ok"
            or postcondition["duplicate_buy_count"] != 0
            or postcondition["uncovered_instruments"]
            or postcondition["residual_risk"]
        ):
            raise ValueError("通过的 drill postcondition 不安全")
        if (
            spec.startup_ready_max_seconds is not None
            and (
                startup_seconds is None
                or float(startup_seconds)
                > spec.startup_ready_max_seconds
            )
        ):
            raise ValueError("restart/startup reconciliation 超过场景 SLO")
    return value


def _regular_json(path: Path, *, label: str) -> bytes:
    return _regular_bytes(
        path,
        label=label,
        maximum_bytes=2 * 1024 * 1024,
    )


def _regular_bytes(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(
            f"{label} 必须是 {maximum_bytes} bytes 内非符号链接普通文件"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum_bytes
        ):
            raise ValueError(
                f"{label} 必须是 {maximum_bytes} bytes 内非符号链接普通文件"
            )
        chunks = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) != metadata.st_size
        or after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
        or after.st_mtime_ns != metadata.st_mtime_ns
    ):
        raise ValueError(
            f"{label} 在同一 fd 读取期间发生变化"
        )
    return raw


def _validate_bundle_receipt(value: object, manifest_bytes: bytes) -> dict:
    if not isinstance(value, dict) or set(value) != _BUNDLE_RECEIPT_KEYS:
        raise ValueError("drill bundle receipt schema 非法")
    parsed = urlparse(str(value["manifest_uri"]))
    if (
        value["version"] != 1
        or value["action"] != "verify-immutable-evidence-bundle"
        or parsed.scheme != "s3"
        or not parsed.netloc
        or not str(value["manifest_version_id"]).strip()
        or value["manifest_sha256"]
        != hashlib.sha256(manifest_bytes).hexdigest()
        or value["manifest_bytes"] != len(manifest_bytes)
    ):
        raise ValueError("drill bundle receipt identity/hash 非法")
    _timestamp(value["verified_at"], "bundle verified_at")
    return value


def build_independent_drill_readback_claims(
    *,
    scenario: str,
    manifest_uri: str,
    manifest_version_id: str,
    manifest_bytes: bytes,
    manifest_signing_public_key: Path,
    verifier_key_id: str,
    verifier_private_key: Path,
    result_uri: str,
    result_version_id: str,
    result_bytes: bytes,
    verified_at: datetime,
    raw_observation_source: dict | None = None,
    raw_recomputed: bool = False,
) -> dict:
    if scenario not in SCENARIO_BY_NAME or not verifier_key_id.strip():
        raise ValueError("independent drill readback scenario/verifier 非法")
    if scenario in RAW_RECOMPUTED_SCENARIOS:
        _validate_raw_observation_source(raw_observation_source)
        if raw_recomputed is not True:
            raise ValueError(
                f"{scenario} independent verifier 未声明 raw recomputation"
            )
    elif raw_observation_source is not None:
        raise ValueError(
            f"{scenario} 不得绑定 independent raw observation source"
        )
    elif raw_recomputed is not False:
        raise ValueError(f"{scenario} 不使用 raw recomputation")
    manifest_fingerprint = ed25519_public_key_fingerprint(
        manifest_signing_public_key
    )
    verifier_fingerprint = ed25519_public_key_fingerprint(
        verifier_private_key,
        private_key=True,
    )
    if manifest_fingerprint == verifier_fingerprint:
        raise ValueError(
            "independent drill verifier 必须不同于 bundle publisher"
        )
    for uri, label in (
        (manifest_uri, "manifest_uri"),
        (result_uri, "result_uri"),
    ):
        parsed = urlparse(uri)
        if parsed.scheme != "s3" or not parsed.netloc:
            raise ValueError(f"independent drill {label} 非法")
    if (
        not manifest_version_id.strip()
        or not result_version_id.strip()
        or not manifest_bytes
        or not result_bytes
        or verified_at.tzinfo is None
        or verified_at.utcoffset() is None
    ):
        raise ValueError("independent drill readback bytes/version/time 非法")
    raw_recompute = None
    if scenario in RAW_RECOMPUTED_SCENARIOS:
        try:
            result_receipt = validate_drill_receipt(
                json.loads(result_bytes)
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(
                "raw-recomputed drill result JSON 非法"
            ) from exc
        raw_claims = result_receipt["execution"][
            "raw_observation"
        ]["payload"]
        raw_recompute = {
            "protocol": PARSER_PROTOCOL,
            "parser_manifest_sha256": PARSER_MANIFEST_SHA256,
            "raw_sha256": raw_observation_source["sha256"],
            "raw_bytes": raw_observation_source["bytes"],
            "recomputed_result_sha256": hashlib.sha256(
                result_bytes
            ).hexdigest(),
        }
        if (
            raw_claims["parser_manifest_sha256"]
            != raw_recompute["parser_manifest_sha256"]
            or raw_claims["source"] != raw_observation_source
        ):
            raise ValueError(
                "raw recomputation parser/source 未绑定 drill result"
            )
    return {
        "version": 1,
        "action": "attest-independent-drill-exact-version-readback",
        "scenario": scenario,
        "manifest_uri": manifest_uri,
        "manifest_version_id": manifest_version_id,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "manifest_bytes": len(manifest_bytes),
        "manifest_signing_key_fingerprint": manifest_fingerprint,
        "verifier_key_id": verifier_key_id,
        "verifier_key_fingerprint": verifier_fingerprint,
        "result_uri": result_uri,
        "result_version_id": result_version_id,
        "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "result_bytes": len(result_bytes),
        "raw_observation_source": raw_observation_source,
        "raw_recompute": raw_recompute,
        "verified_at": verified_at.astimezone(UTC).isoformat(),
    }


def verify_independent_raw_observation_artifact(
    artifact: object,
    *,
    receipt: dict,
    observer_public_key: Path,
    publisher_key: Path,
    publisher_key_is_private: bool = False,
) -> dict:
    scenario = str(receipt.get("scenario", ""))
    if scenario not in RAW_RECOMPUTED_SCENARIOS:
        raise ValueError(
            f"{scenario} 不使用 independent raw observation adapter"
        )
    shaped = _raw_observation_claims_shape(
        artifact,
        scenario=scenario,
    )
    claims = verify_ed25519_artifact(
        artifact,
        observer_public_key,
        label=f"{scenario} independent raw observation",
    )
    if claims != shaped:
        raise ValueError(f"{scenario} raw observation payload 变化")
    observer_fingerprint = ed25519_public_key_fingerprint(
        observer_public_key
    )
    publisher_fingerprint = ed25519_public_key_fingerprint(
        publisher_key,
        private_key=publisher_key_is_private,
    )
    if (
        observer_fingerprint == publisher_fingerprint
        or claims["observer_key_fingerprint"] != observer_fingerprint
        or receipt["execution"]["raw_observation"] != artifact
    ):
        raise ValueError(
            f"{scenario} raw observation 必须由独立于 publisher 的身份签署"
        )
    validate_drill_receipt(receipt)
    return claims


def verify_independent_drill_readback_artifact(
    artifact: object,
    *,
    scenario: str,
    verifier_public_key: Path,
    manifest_signing_public_key: Path,
    manifest_receipt: dict,
    manifest_bytes: bytes,
    result_component: dict,
    result_bytes: bytes,
) -> dict:
    claims = verify_ed25519_artifact(
        artifact,
        verifier_public_key,
        label=f"{scenario} independent exact-version drill readback",
    )
    manifest_fingerprint = ed25519_public_key_fingerprint(
        manifest_signing_public_key
    )
    verifier_fingerprint = ed25519_public_key_fingerprint(
        verifier_public_key
    )
    verified_at = _timestamp(
        claims.get("verified_at") if isinstance(claims, dict) else None,
        "independent drill verified_at",
    )
    manifest_verified_at = _timestamp(
        manifest_receipt["verified_at"],
        "bundle verified_at",
    )
    expected_raw_source = None
    expected_raw_recompute = None
    if scenario in RAW_RECOMPUTED_SCENARIOS:
        result_receipt = json.loads(result_bytes)
        raw_claims = result_receipt["execution"]["raw_observation"][
            "payload"
        ]
        expected_raw_source = raw_claims["source"]
        expected_raw_recompute = {
            "protocol": PARSER_PROTOCOL,
            "parser_manifest_sha256": PARSER_MANIFEST_SHA256,
            "raw_sha256": expected_raw_source["sha256"],
            "raw_bytes": expected_raw_source["bytes"],
            "recomputed_result_sha256": hashlib.sha256(
                result_bytes
            ).hexdigest(),
        }
    if (
        not isinstance(claims, dict)
        or set(claims) != _INDEPENDENT_READBACK_KEYS
        or claims["version"] != 1
        or claims["action"]
        != "attest-independent-drill-exact-version-readback"
        or claims["scenario"] != scenario
        or claims["manifest_uri"] != manifest_receipt["manifest_uri"]
        or claims["manifest_version_id"]
        != manifest_receipt["manifest_version_id"]
        or claims["manifest_sha256"]
        != hashlib.sha256(manifest_bytes).hexdigest()
        or claims["manifest_bytes"] != len(manifest_bytes)
        or claims["manifest_signing_key_fingerprint"]
        != manifest_fingerprint
        or claims["verifier_key_fingerprint"] != verifier_fingerprint
        or not str(claims["verifier_key_id"]).strip()
        or verifier_fingerprint == manifest_fingerprint
        or claims["result_uri"] != result_component["object_uri"]
        or claims["result_version_id"] != result_component["version_id"]
        or claims["result_sha256"]
        != hashlib.sha256(result_bytes).hexdigest()
        or claims["result_sha256"] != result_component["sha256"]
        or claims["result_bytes"] != len(result_bytes)
        or claims["result_bytes"] != result_component["bytes"]
        or claims["raw_observation_source"] != expected_raw_source
        or claims["raw_recompute"] != expected_raw_recompute
        or verified_at < manifest_verified_at
    ):
        raise ValueError(
            f"{scenario} independent exact-version readback 未绑定 WORM bytes"
        )
    return claims


def locally_recompute_stage_c_receipt(
    receipt: object,
    *,
    raw_events_path: Path,
    registrar_public_key: Path,
    capability_authority_public_key: Path,
    raw_observer_public_key: Path,
    source_public_keys: dict[str, Path],
) -> dict:
    """Recompute one raw scenario inside the production loader domain."""
    validated = validate_drill_receipt(receipt)
    scenario = validated["scenario"]
    if scenario not in RAW_RECOMPUTED_SCENARIOS:
        raise ValueError(f"{scenario} 不使用 Stage-C raw recomputation")
    expected_roles = required_source_roles(scenario)
    if set(source_public_keys) != set(expected_roles):
        raise ValueError(
            f"{scenario} loader source public keys 不完整或含多余角色"
        )
    raw_bytes = _regular_bytes(
        raw_events_path,
        label=f"{scenario} local frozen raw events",
        maximum_bytes=8 * 1024 * 1024,
    )
    raw_source = validated["execution"]["raw_observation"]["payload"][
        "source"
    ]
    if (
        hashlib.sha256(raw_bytes).hexdigest() != raw_source["sha256"]
        or len(raw_bytes) != raw_source["bytes"]
    ):
        raise ValueError(
            f"{scenario} local raw bytes 未绑定 WORM raw locator"
        )
    derived = derive_stage_c_raw_observation(
        raw_bytes,
        scenario=scenario,
        registrar_public_key=registrar_public_key,
        capability_authority_public_key=capability_authority_public_key,
        provider_public_key=source_public_keys["provider"],
        raw_observer_public_key=raw_observer_public_key,
        source_public_keys=source_public_keys,
        barrier_attestor_public_key=source_public_keys.get(
            "barrier_attestor"
        ),
        kill_controller_public_key=source_public_keys.get(
            "kill_controller"
        ),
        require_production_evidence=True,
    )
    recomputed = build_stage_c_drill_receipt(
        derived,
        raw_observation_artifact=validated["execution"][
            "raw_observation"
        ],
    )
    if recomputed != validated:
        raise ValueError(
            f"{scenario} production loader 本地重算 receipt 不一致"
        )
    return recomputed


@dataclass(frozen=True)
class StageCProductionTrust:
    """Frozen local trust roots used by the production recomputation domain."""

    raw_events_dir: Path
    registrar_public_keys: dict[str, Path]
    capability_authority_public_keys: dict[str, Path]
    source_public_keys: dict[str, dict[str, Path]]
    trust_root_fingerprints: frozenset[str]
    parser_signer_fingerprint: str


def _safe_stage_c_path(
    value: object,
    *,
    label: str,
    directory: bool,
) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} path 非法")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{label} 必须是绝对路径")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} 不存在") from exc
    if resolved != path:
        raise ValueError(f"{label} 不允许符号链接或非规范路径")
    valid_kind = path.is_dir() if directory else path.is_file()
    if not valid_kind or path.is_symlink():
        kind = "目录" if directory else "普通文件"
        raise ValueError(f"{label} 必须是非符号链接{kind}")
    if path.stat().st_mode & 0o022:
        raise ValueError(f"{label} 不允许 group/world 写权限")
    return path


def _stage_c_trust_key(value: object, *, label: str) -> Path:
    if not isinstance(value, dict) or set(value) != _STAGE_C_TRUST_KEY_KEYS:
        raise ValueError(f"{label} trust root schema 非法")
    path = _safe_stage_c_path(
        value["path"],
        label=label,
        directory=False,
    )
    fingerprint = value["fingerprint_sha256"]
    if (
        not isinstance(fingerprint, str)
        or not _SHA256.fullmatch(fingerprint)
        or ed25519_public_key_fingerprint(path) != fingerprint
    ):
        raise ValueError(f"{label} public key fingerprint 不一致")
    return path


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Stage-C trust manifest JSON 重复字段: {key}")
        value[key] = item
    return value


def load_stage_c_production_trust_manifest(
    path: Path,
) -> StageCProductionTrust:
    """Load one strict trust manifest instead of accepting ad-hoc CLI maps."""
    manifest_path = _safe_stage_c_path(
        str(path),
        label="Stage-C trust manifest",
        directory=False,
    )
    raw = _regular_json(
        manifest_path,
        label="Stage-C trust manifest",
    )
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_strict_json_object,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Stage-C trust manifest JSON 非法") from exc
    if (
        not isinstance(value, dict)
        or set(value) != _STAGE_C_TRUST_MANIFEST_KEYS
        or value["version"] != 1
        or value["action"] != "configure-stage-c-production-trust-v1"
        or value["parser_manifest_sha256"] != PARSER_MANIFEST_SHA256
        or not isinstance(value["scenarios"], dict)
        or set(value["scenarios"]) != set(RAW_RECOMPUTED_SCENARIOS)
    ):
        raise ValueError(
            "Stage-C trust manifest schema/parser/scenario set 非法"
        )
    raw_events_dir = _safe_stage_c_path(
        value["raw_events_dir"],
        label="Stage-C frozen raw events",
        directory=True,
    )
    registrar_public_keys: dict[str, Path] = {}
    capability_authority_public_keys: dict[str, Path] = {}
    source_public_keys: dict[str, dict[str, Path]] = {}
    all_trust_fingerprints: dict[str, str] = {}
    for scenario in sorted(RAW_RECOMPUTED_SCENARIOS):
        entry = value["scenarios"][scenario]
        if (
            not isinstance(entry, dict)
            or set(entry) != _STAGE_C_TRUST_SCENARIO_KEYS
            or entry["trust_state"] != "TRUST_CONFIGURED"
        ):
            raise ValueError(
                f"{scenario} Stage-C trust entry schema/state 非法"
            )
        expected_contract_sha256 = hashlib.sha256(
            canonical_bytes(driver_contract_document(scenario))
        ).hexdigest()
        expected_filename = f"{scenario}.jsonl"
        if (
            entry["driver_contract_sha256"]
            != expected_contract_sha256
            or entry["raw_events_file"] != expected_filename
            or not isinstance(entry["raw_events_sha256"], str)
            or not _SHA256.fullmatch(entry["raw_events_sha256"])
            or type(entry["raw_events_bytes"]) is not int
            or not 0 < entry["raw_events_bytes"] <= 8 * 1024 * 1024
        ):
            raise ValueError(
                f"{scenario} Stage-C trust contract/raw binding 非法"
            )
        raw_events_path = _safe_stage_c_path(
            str(raw_events_dir / expected_filename),
            label=f"{scenario} frozen raw events",
            directory=False,
        )
        raw_bytes = _regular_bytes(
            raw_events_path,
            label=f"{scenario} frozen raw events",
            maximum_bytes=8 * 1024 * 1024,
        )
        if (
            hashlib.sha256(raw_bytes).hexdigest()
            != entry["raw_events_sha256"]
            or len(raw_bytes) != entry["raw_events_bytes"]
        ):
            raise ValueError(
                f"{scenario} Stage-C frozen raw bytes/hash 不一致"
            )
        registrar = _stage_c_trust_key(
            entry["registrar_public_key"],
            label=f"{scenario} registrar",
        )
        authority = _stage_c_trust_key(
            entry["capability_authority_public_key"],
            label=f"{scenario} capability authority",
        )
        sources = entry["source_public_keys"]
        expected_roles = required_source_roles(scenario)
        if (
            not isinstance(sources, dict)
            or set(sources) != set(expected_roles)
        ):
            raise ValueError(
                f"{scenario} Stage-C source trust roles 不完整或含多余角色"
            )
        resolved_sources = {
            role: _stage_c_trust_key(
                sources[role],
                label=f"{scenario} source role {role}",
            )
            for role in sorted(expected_roles)
        }
        fingerprints = [
            ed25519_public_key_fingerprint(registrar),
            ed25519_public_key_fingerprint(authority),
            *(
                ed25519_public_key_fingerprint(key)
                for key in resolved_sources.values()
            ),
        ]
        if len(set(fingerprints)) != len(fingerprints):
            raise ValueError(
                f"{scenario} registrar/capability/source trust roots 必须分钥"
            )
        labels_and_fingerprints = {
            f"{scenario}:registrar": fingerprints[0],
            f"{scenario}:capability_authority": fingerprints[1],
            **{
                f"{scenario}:{role}": (
                    ed25519_public_key_fingerprint(key)
                )
                for role, key in resolved_sources.items()
            },
        }
        for label, fingerprint in labels_and_fingerprints.items():
            previous = next(
                (
                    prior_label
                    for prior_label, prior_fingerprint
                    in all_trust_fingerprints.items()
                    if prior_fingerprint == fingerprint
                ),
                None,
            )
            if previous is not None:
                repeated_parser_signer = (
                    previous.endswith(":parser_signer")
                    and label.endswith(":parser_signer")
                )
                if not repeated_parser_signer:
                    raise ValueError(
                        "Stage-C trust roots 禁止跨场景/角色复用: "
                        f"{previous}, {label}"
                    )
            all_trust_fingerprints[label] = fingerprint
        registrar_public_keys[scenario] = registrar
        capability_authority_public_keys[scenario] = authority
        source_public_keys[scenario] = resolved_sources
    parser_signer_fingerprints = {
        all_trust_fingerprints[f"{scenario}:parser_signer"]
        for scenario in RAW_RECOMPUTED_SCENARIOS
    }
    if len(parser_signer_fingerprints) != 1:
        raise ValueError(
            "Stage-C 所有场景 parser_signer 必须绑定同一个 global raw observer"
        )
    return StageCProductionTrust(
        raw_events_dir=raw_events_dir,
        registrar_public_keys=registrar_public_keys,
        capability_authority_public_keys=(
            capability_authority_public_keys
        ),
        source_public_keys=source_public_keys,
        trust_root_fingerprints=frozenset(
            all_trust_fingerprints.values()
        ),
        parser_signer_fingerprint=next(
            iter(parser_signer_fingerprints)
        ),
    )


def load_verified_stage_c_receipts(
    *,
    receipts_dir: Path,
    manifests_dir: Path,
    bundle_receipts_dir: Path,
    bundle_signing_public_key: Path,
    independent_attestations_dir: Path,
    raw_observer_public_key: Path,
    independent_verifier_public_key: Path,
    trust_manifest_path: Path | None = None,
    raw_events_dir: Path | None = None,
    registrar_public_keys: dict[str, Path] | None = None,
    capability_authority_public_keys: dict[str, Path] | None = None,
    source_public_keys: dict[str, dict[str, Path]] | None = None,
) -> list[dict]:
    for directory, label in (
        (receipts_dir, "drill receipts"),
        (manifests_dir, "drill manifests"),
        (bundle_receipts_dir, "drill bundle receipts"),
        (
            independent_attestations_dir,
            "independent drill readback attestations",
        ),
    ):
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError(f"{label} 目录不存在或不安全")
    publisher_fingerprint = ed25519_public_key_fingerprint(
        bundle_signing_public_key
    )
    raw_observer_fingerprint = ed25519_public_key_fingerprint(
        raw_observer_public_key
    )
    verifier_fingerprint = ed25519_public_key_fingerprint(
        independent_verifier_public_key
    )
    if len({
        publisher_fingerprint,
        raw_observer_fingerprint,
        verifier_fingerprint,
    }) != 3:
        raise ValueError(
            "Stage-C bundle publisher、raw observer 与 WORM readback "
            "verifier 必须使用三个不同 Ed25519 身份"
        )
    # Capability code must exist before any receipt or trust-root material is
    # read.  This prevents a hand-written manifest/receipt from upgrading a
    # PARSER_READY scenario to production evidence.
    require_stage_c_production_capabilities(
        DRILL_SCENARIOS,
    )
    raw_scenarios = {
        spec.name
        for spec in DRILL_SCENARIOS
        if spec.name in RAW_RECOMPUTED_SCENARIOS
    }
    if raw_scenarios:
        if any(
            value is not None
            for value in (
                raw_events_dir,
                registrar_public_keys,
                capability_authority_public_keys,
                source_public_keys,
            )
        ):
            raise ValueError(
                "Stage-C production loader 禁止用 ad-hoc 参数绕过 trust manifest"
            )
        if trust_manifest_path is None:
            raise ValueError(
                "Stage-C production loader 缺少 frozen raw directory 与 "
                "registrar/capability/source trust manifest"
            )
        trust = load_stage_c_production_trust_manifest(
            trust_manifest_path
        )
        global_identities = {
            publisher_fingerprint,
            raw_observer_fingerprint,
            verifier_fingerprint,
        }
        overlap = (
            (
                trust.trust_root_fingerprints
                - {trust.parser_signer_fingerprint}
            )
            & global_identities
        )
        if (
            trust.parser_signer_fingerprint
            != raw_observer_fingerprint
        ):
            raise ValueError(
                "Stage-C 所有 parser_signer 必须精确绑定 global raw observer"
            )
        if overlap:
            raise ValueError(
                "Stage-C registrar/capability/native source trust roots 必须与 "
                "bundle publisher、raw observer、WORM readback verifier "
                f"完全分钥: overlap={sorted(overlap)}"
            )
        raw_events_dir = trust.raw_events_dir
        registrar_public_keys = trust.registrar_public_keys
        capability_authority_public_keys = (
            trust.capability_authority_public_keys
        )
        source_public_keys = trust.source_public_keys
    deployment_attested: set[str] = set()
    receipts: list[dict] = []
    for spec in DRILL_SCENARIOS:
        result_path = receipts_dir / f"{spec.name}.json"
        manifest_path = manifests_dir / f"{spec.name}.json"
        bundle_receipt_path = bundle_receipts_dir / f"{spec.name}.json"
        result_bytes = _regular_json(
            result_path,
            label=f"{spec.name} drill result",
        )
        try:
            receipt = validate_drill_receipt(json.loads(result_bytes))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"{spec.name} drill result JSON 非法") from exc
        if spec.name in RAW_RECOMPUTED_SCENARIOS:
            verify_independent_raw_observation_artifact(
                receipt["execution"]["raw_observation"],
                receipt=receipt,
                observer_public_key=raw_observer_public_key,
                publisher_key=bundle_signing_public_key,
            )
            assert raw_events_dir is not None
            assert registrar_public_keys is not None
            assert capability_authority_public_keys is not None
            assert source_public_keys is not None
            locally_recompute_stage_c_receipt(
                receipt,
                raw_events_path=raw_events_dir / f"{spec.name}.jsonl",
                registrar_public_key=registrar_public_keys[spec.name],
                capability_authority_public_key=(
                    capability_authority_public_keys[spec.name]
                ),
                raw_observer_public_key=raw_observer_public_key,
                source_public_keys=source_public_keys[spec.name],
            )
            # Only the successful local verification of the registrar,
            # short-lived capability, native workload identities, source
            # signatures and exact raw bytes establishes this state.
            deployment_attested.add(spec.name)
        manifest_bytes = _regular_json(
            manifest_path,
            label=f"{spec.name} signed manifest",
        )
        try:
            artifact = json.loads(manifest_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"{spec.name} signed manifest JSON 非法") from exc
        claims = verify_ed25519_artifact(
            artifact,
            bundle_signing_public_key,
            label=f"{spec.name} immutable drill bundle",
        )
        manifest = validate_bundle_manifest(claims)
        expected_bundle_identity = {
            "git_commit": receipt["identity"]["git_commit"],
            "config_sha256": receipt["identity"]["config_sha256"],
            "account_uid": receipt["identity"]["account_uid"],
            "environment": "demo",
            "unit": receipt["identity"]["unit"],
            "soak_epoch_id": receipt["identity"]["soak_epoch_id"],
            "phase": "chaos",
        }
        component = manifest["components"].get("drill-result")
        expected_kind = "chaos" if spec.work_package == "WP4" else "restart"
        if (
            manifest["identity"] != expected_bundle_identity
            or manifest["kind"] != expected_kind
            or set(manifest["components"]) != {"drill-result"}
            or component["sha256"] != hashlib.sha256(result_bytes).hexdigest()
            or component["bytes"] != len(result_bytes)
            or not str(component["version_id"]).strip()
        ):
            raise ValueError(
                f"{spec.name} signed bundle 未精确绑定 drill result/identity"
            )
        bundle_receipt_bytes = _regular_json(
            bundle_receipt_path,
            label=f"{spec.name} bundle receipt",
        )
        try:
            bundle_receipt = _validate_bundle_receipt(
                json.loads(bundle_receipt_bytes),
                manifest_bytes,
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"{spec.name} bundle receipt JSON 非法") from exc
        manifest_uri = urlparse(bundle_receipt["manifest_uri"])
        component_uri = urlparse(str(component["object_uri"]))
        if (
            manifest_uri.netloc != component_uri.netloc
            or not manifest_uri.path.rsplit("/", 1)[0]
            == component_uri.path.rsplit("/", 1)[0]
        ):
            raise ValueError(
                f"{spec.name} manifest/component 不属于同一 WORM bundle"
            )
        independent_bytes = _regular_json(
            independent_attestations_dir / f"{spec.name}.json",
            label=f"{spec.name} independent readback attestation",
        )
        try:
            independent_artifact = json.loads(independent_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(
                f"{spec.name} independent readback JSON 非法"
            ) from exc
        verify_independent_drill_readback_artifact(
            independent_artifact,
            scenario=spec.name,
            verifier_public_key=independent_verifier_public_key,
            manifest_signing_public_key=bundle_signing_public_key,
            manifest_receipt=bundle_receipt,
            manifest_bytes=manifest_bytes,
            result_component=component,
            result_bytes=result_bytes,
        )
        receipts.append(receipt)
    if deployment_attested != raw_scenarios:
        raise ValueError(
            "Stage-C deployment attestation coverage 不完整: "
            f"expected={sorted(raw_scenarios)}, "
            f"verified={sorted(deployment_attested)}"
        )
    return receipts


def verify_stage_c_coverage(
    receipts: Iterable[object],
    *,
    expected_release_identity: dict,
    expected_soak_epoch_id: str,
    release_frozen_at: datetime,
    epoch_started_at: datetime,
    expected_stage_c_deployment_identity: dict,
) -> dict:
    if release_frozen_at.tzinfo is None or release_frozen_at.utcoffset() is None:
        raise ValueError("release_frozen_at 必须带时区")
    release_frozen_at = release_frozen_at.astimezone(UTC)
    if epoch_started_at.tzinfo is None or epoch_started_at.utcoffset() is None:
        raise ValueError("epoch_started_at 必须带时区")
    epoch_started_at = epoch_started_at.astimezone(UTC)
    candidate = validate_stage_c_chaos_deployment_identity(
        expected_stage_c_deployment_identity
    )
    candidate_sha256 = stage_c_chaos_deployment_identity_sha256(candidate)
    required_release_keys = {
        "git_commit",
        "git_tree_hash",
        "source_manifest_sha256",
    }
    if (
        not isinstance(expected_release_identity, dict)
        or not required_release_keys <= set(expected_release_identity)
        or not _SHA1.fullmatch(
            str(expected_release_identity["git_commit"])
        )
        or not _SHA1.fullmatch(
            str(expected_release_identity["git_tree_hash"])
        )
        or not _SHA256.fullmatch(
            str(expected_release_identity["source_manifest_sha256"])
        )
        or not expected_soak_epoch_id.strip()
    ):
        raise ValueError("Stage-C expected release/epoch identity 非法")
    by_scenario: dict[str, dict] = {}
    receipt_hashes: dict[str, str] = {}
    exact_deployment: tuple[str, str, str] | None = None
    for raw in receipts:
        receipt = validate_drill_receipt(raw)
        scenario = receipt["scenario"]
        if scenario in by_scenario:
            raise ValueError(f"Stage-C drill scenario 重复: {scenario}")
        if not receipt["passed"]:
            raise ValueError(f"Stage-C drill 未通过: {scenario}")
        identity = receipt["identity"]
        if (
            identity["git_commit"]
            != expected_release_identity["git_commit"]
            or identity["git_tree_hash"]
            != expected_release_identity["git_tree_hash"]
            or identity["source_manifest_sha256"]
            != expected_release_identity["source_manifest_sha256"]
            or identity["soak_epoch_id"] != expected_soak_epoch_id
            or identity["stage_c_chaos_deployment_identity_sha256"]
            != candidate_sha256
        ):
            raise ValueError(
                f"Stage-C drill 未绑定最终候选 release/epoch: {scenario}"
            )
        drill_started_at = _timestamp(
            receipt["started_at"], "drill started_at"
        )
        drill_completed_at = _timestamp(
            receipt["completed_at"], "drill completed_at"
        )
        if drill_started_at < release_frozen_at:
            raise ValueError(
                f"Stage-C drill 早于最终 release freeze: {scenario}"
            )
        spec = SCENARIO_BY_NAME[scenario]
        candidate_class = candidate[
            "exact_release"
            if spec.artifact_class
            is DrillArtifactClass.EXACT_RELEASE_BLACK_BOX
            else "instrumented"
        ]
        if (
            drill_completed_at > epoch_started_at
            or identity["account_uid"] != candidate_class["account_uid"]
            or identity["config_sha256"] != candidate_class["config_sha256"]
            or identity["unit"] != candidate_class["unit"]
            or identity["artifact_sha256"]
            != candidate_class["artifact_sha256"]
        ):
            raise ValueError(
                f"Stage-C drill candidate deployment/timing 不匹配: {scenario}"
            )
        if spec.artifact_class is DrillArtifactClass.EXACT_RELEASE_BLACK_BOX:
            deployment = (
                identity["config_sha256"],
                identity["account_uid"],
                identity["unit"],
            )
            if exact_deployment is None:
                exact_deployment = deployment
            elif deployment != exact_deployment:
                raise ValueError(
                    "exact-release black-box receipts 必须来自同一 Chaos deployment"
                )
        receipt_hashes[scenario] = hashlib.sha256(
            json.dumps(
                receipt,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        by_scenario[scenario] = receipt
    missing = sorted(set(SCENARIO_BY_NAME) - set(by_scenario))
    extra = sorted(set(by_scenario) - set(SCENARIO_BY_NAME))
    if missing or extra:
        raise ValueError(
            f"Stage-C drill coverage 非完整矩阵: missing={missing}, extra={extra}"
        )
    exact_names = scenario_names(
        DrillArtifactClass.EXACT_RELEASE_BLACK_BOX
    )
    instrumented_names = scenario_names(
        DrillArtifactClass.INSTRUMENTED_TEST_ONLY
    )
    return {
        "version": 1,
        "action": "verify-stage-c-wp4-wp5-coverage",
        "release_frozen_at": release_frozen_at.isoformat(),
        "epoch_started_at": epoch_started_at.isoformat(),
        "stage_c_chaos_deployment_identity_sha256": candidate_sha256,
        "release_identity": {
            key: expected_release_identity[key]
            for key in sorted(required_release_keys)
        },
        "soak_epoch_id": expected_soak_epoch_id,
        "scenario_count": len(by_scenario),
        "exact_release_black_box_scenarios": list(exact_names),
        "instrumented_test_only_scenarios": list(instrumented_names),
        "receipt_sha256": {
            name: receipt_hashes[name] for name in sorted(receipt_hashes)
        },
    }
