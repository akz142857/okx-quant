"""由 durable SQLite facts 重算的 Demo/Shadow SLO v2。"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pandas as pd

from okx_quant.application.approval import canonical_bytes
from okx_quant.ops.backup_receipt import validate_backup_slo_sample
from okx_quant.research.costs import DynamicCostModel

SLO_V2_SCHEMA = "okx-quant.demo-slo/v2"
SLO_V2_POLICY = {
    "version": 2,
    "expected_channels": ["public", "private", "business"],
    "websocket_state_sample_max_gap_seconds": 90,
    "resource_sample_max_gap_seconds": 300,
    "heartbeat_sample_max_gap_seconds": 90,
    "runtime_min_readiness_ratio": 0.995,
    "runtime_max_nonready_seconds": 60,
    "websocket_min_availability_ratio": 0.995,
    "websocket_max_disconnect_seconds": 60,
    "max_unobservable_seconds": 432,
    "max_evidence_gap_seconds": 300,
    "reconciliation_interval_seconds": 30,
    "reconciliation_min_success_ratio": 0.999,
    "reconciliation_max_completion_gap_seconds": 90,
    "protection_p95_seconds": 3,
    "protection_max_seconds": 10,
    "protection_p99_min_samples": 300,
    "startup_max_seconds": 60,
    "p0_provider_received_seconds": 60,
    "p1_provider_received_seconds": 300,
    "p0_ack_or_escalation_required": True,
    "backup_max_recovery_point_age_seconds": 300,
    "backup_component_restore_max_seconds": 300,
    "clock_max_absolute_offset_seconds": 1,
    "probe_minimum_daily_done": 1,
    "probe_maximum_daily_done": 1,
    "probe_formal_lineage_required": True,
    "aggregate_required_clean_days": 30,
    "aggregate_required_residual_clusters": 30,
}
SLO_V2_POLICY_HASH = hashlib.sha256(
    canonical_bytes(SLO_V2_POLICY)
).hexdigest()

REPORT_KEYS = {
    "version",
    "schema",
    "policy_hash",
    "soak_epoch_id",
    "phase",
    "day",
    "window",
    "websocket",
    "reconciliation",
    "runtime",
    "alerts",
    "backups",
    "resources",
    "clock",
    "probes",
    "protection",
    "execution_slippage",
    "integrity",
}


def _quantile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def _one_sided_upper_95(values: list[float]) -> float:
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    if len(values) == 1:
        return mean
    variance = sum((value - mean) ** 2 for value in values) / (
        len(values) - 1
    )
    return mean + 1.6448536269514722 * math.sqrt(
        variance / len(values)
    )


def _finite_nonnegative(value: object, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} 必须为有限非负数")
    rendered = float(value)
    if not math.isfinite(rendered) or rendered < 0:
        raise ValueError(f"{label} 必须为有限非负数")
    return rendered


def _payload(raw: str, event_name: str) -> dict:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{event_name} payload JSON 损坏") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{event_name} payload 必须是对象")
    return value


def _event_rows(
    connection: sqlite3.Connection,
    name: str,
    started: float,
    ended: float,
) -> list[tuple[float, str, dict]]:
    rows = connection.execute(
        """
        SELECT created_at, event_id, payload_json
        FROM system_events
        WHERE event_name=? AND created_at>=? AND created_at<?
        ORDER BY created_at, event_id
        """,
        (name, started, ended),
    ).fetchall()
    return [
        (float(ts), str(event_id), _payload(raw, name))
        for ts, event_id, raw in rows
    ]


def _numeric_samples(
    connection: sqlite3.Connection,
    name: str,
    field: str,
    started: float,
    ended: float,
) -> tuple[list[float], list[dict]]:
    values: list[float] = []
    payloads: list[dict] = []
    for _ts, _event_id, payload in _event_rows(
        connection,
        name,
        started,
        ended,
    ):
        if field not in payload:
            raise ValueError(f"{name}.{field} 缺失")
        values.append(_finite_nonnegative(payload[field], f"{name}.{field}"))
        payloads.append(payload)
    return values, payloads


def _distribution(values: list[float]) -> dict:
    return {
        "sample_count": len(values),
        "p50_seconds": _quantile(values, 0.50),
        "p95_seconds": _quantile(values, 0.95),
        "p99_seconds": _quantile(values, 0.99),
        "max_seconds": max(values, default=0),
    }


def _channel_distributions(
    payloads: list[dict],
    *,
    value_field: str,
) -> tuple[dict[str, dict], int]:
    values = {
        channel: []
        for channel in SLO_V2_POLICY["expected_channels"]
    }
    invalid = 0
    for payload in payloads:
        channel = payload.get("channel")
        if channel not in values or value_field not in payload:
            invalid += 1
            continue
        try:
            values[channel].append(
                _finite_nonnegative(
                    payload[value_field],
                    f"{channel}.{value_field}",
                )
            )
        except (TypeError, ValueError, OverflowError):
            invalid += 1
    return {
        channel: _distribution(samples)
        for channel, samples in values.items()
    }, invalid


def _evidence_coverage(
    timestamps: list[float],
    *,
    started: float,
    ended: float,
    max_gap: float,
) -> dict:
    points = [started, *sorted(set(timestamps)), ended]
    gaps = [
        max(points[index + 1] - points[index], 0)
        for index in range(len(points) - 1)
    ]
    unobservable = sum(max(gap - max_gap, 0) for gap in gaps)
    return {
        "sample_count": len(timestamps),
        "actual_observable_seconds": max((ended - started) - unobservable, 0),
        "unobservable_seconds": unobservable,
        "max_evidence_gap_seconds": max(gaps, default=ended - started),
    }


def _websocket_channel(
    connection: sqlite3.Connection,
    channel: str,
    *,
    started: float,
    ended: float,
) -> dict:
    prior = connection.execute(
        """
        SELECT payload_json
        FROM system_events
        WHERE event_name='websocket_state_transition'
          AND created_at<?
        ORDER BY created_at DESC, event_id DESC
        """,
        (started,),
    ).fetchall()
    initial = "unknown"
    initial_generation: int | None = None
    has_prior = False
    for (raw,) in prior:
        payload = _payload(raw, "websocket_state_transition")
        if payload.get("channel") == channel:
            initial = str(payload.get("new_state", "unknown")).lower()
            candidate_generation = payload.get("generation")
            if (
                type(candidate_generation) is not int
                or candidate_generation < 0
            ):
                raise ValueError(
                    f"websocket_state_transition {channel} prior generation 非法"
                )
            initial_generation = candidate_generation
            has_prior = True
            break
    transitions = [
        (ts, event_id, payload)
        for ts, event_id, payload in _event_rows(
            connection,
            "websocket_state_transition",
            started,
            ended,
        )
        if payload.get("channel") == channel
    ]
    state_samples = _event_rows(
        connection,
        "websocket_liveness_sample",
        started,
        ended,
    )
    allowed_states = {
        "disconnected",
        "connecting",
        "authenticating",
        "subscribing",
        "ready",
        "stale",
        "backoff",
    }
    samples: list[tuple[float, str, int]] = []
    for ts, _event_id, payload in state_samples:
        states = payload.get("states")
        generations_payload = payload.get("generations")
        if (
            not isinstance(states, dict)
            or set(states) != set(SLO_V2_POLICY["expected_channels"])
            or not isinstance(generations_payload, dict)
            or set(generations_payload)
            != set(SLO_V2_POLICY["expected_channels"])
            or payload.get("baseline_safe") is not True
        ):
            raise ValueError("websocket_liveness_sample schema/baseline 非法")
        sampled_state = str(states[channel]).lower()
        generation = generations_payload[channel]
        if (
            sampled_state not in allowed_states
            or type(generation) is not int
            or generation < 0
        ):
            raise ValueError(
                f"websocket_liveness_sample {channel} 状态非法"
            )
        samples.append((ts, sampled_state, generation))
    if not has_prior:
        if transitions:
            first_payload = transitions[0][2]
            initial = str(first_payload.get("old_state", "unknown")).lower()
            first_generation = first_payload.get("generation")
            if type(first_generation) is int and first_generation >= 0:
                initial_generation = (
                    0
                    if str(first_payload.get("new_state", "")).lower()
                    == "connecting"
                    else first_generation
                )
        elif samples:
            initial = samples[0][1]
            initial_generation = samples[0][2]
    if (
        initial not in allowed_states
        or initial_generation is None
        or initial_generation < 0
    ):
        raise ValueError(
            f"websocket_state_transition {channel} 缺少可证明的日界状态"
        )
    state = initial
    generation_cursor = initial_generation
    cursor = started
    ready_seconds = 0.0
    disconnects = 0
    disconnect_started = started if state != "ready" else None
    disconnect_durations: list[float] = []
    generations: set[int] = set()
    transition_index = 0
    sampled_state = initial
    sampled_generation = initial_generation
    for sample_ts, sample_state, sample_generation in samples:
        while (
            transition_index < len(transitions)
            and transitions[transition_index][0] <= sample_ts
        ):
            transition_payload = transitions[transition_index][2]
            sampled_state = str(
                transition_payload.get("new_state", "unknown")
            ).lower()
            sampled_generation = int(
                transition_payload.get("generation", -1)
            )
            transition_index += 1
        if (
            sample_state != sampled_state
            or sample_generation != sampled_generation
        ):
            raise ValueError(
                f"websocket_liveness_sample {channel} 与 transition 不一致"
            )
        generations.add(sample_generation)
    sample_coverage = _evidence_coverage(
        [item[0] for item in samples],
        started=started,
        ended=ended,
        max_gap=float(
            SLO_V2_POLICY["websocket_state_sample_max_gap_seconds"]
        ),
    )
    for ts, _event_id, payload in transitions:
        old_state = str(payload.get("old_state", "")).lower()
        new_state = str(payload.get("new_state", "")).lower()
        generation = payload.get("generation")
        expected_generation = (
            generation_cursor + 1
            if new_state == "connecting"
            else generation_cursor
        )
        if (
            set(payload)
            != {"channel", "old_state", "new_state", "generation"}
            or payload.get("channel") != channel
            or old_state != state
            or new_state
            not in {
                "disconnected",
                "connecting",
                "authenticating",
                "subscribing",
                "ready",
                "stale",
                "backoff",
            }
            or type(generation) is not int
            or generation < 0
            or generation != expected_generation
        ):
            raise ValueError(
                f"websocket_state_transition {channel} 状态链非法"
            )
        generations.add(generation)
        if state == "ready":
            ready_seconds += max(ts - cursor, 0)
        if state == "ready" and new_state != "ready":
            disconnects += 1
            disconnect_started = ts
        elif state != "ready" and new_state == "ready":
            if disconnect_started is not None:
                disconnect_durations.append(ts - disconnect_started)
            disconnect_started = None
        state = new_state
        generation_cursor = generation
        cursor = ts
    if state == "ready":
        ready_seconds += max(ended - cursor, 0)
    elif disconnect_started is not None:
        disconnect_durations.append(ended - disconnect_started)
    expected = ended - started
    unavailable = max(expected - ready_seconds, 0)
    return {
        "transition_count": len(transitions),
        "state_sample_count": len(samples),
        "max_state_sample_gap_seconds": sample_coverage[
            "max_evidence_gap_seconds"
        ],
        "generation_count": len(generations),
        "ready_seconds": ready_seconds,
        "unavailable_seconds": unavailable,
        "availability_ratio": ready_seconds / expected if expected else 0,
        "disconnect_count": disconnects,
        "max_disconnect_seconds": max(disconnect_durations, default=unavailable),
    }


def _latest_prior_ws_boundary(
    connection: sqlite3.Connection,
    channel: str,
    *,
    started: float,
) -> tuple[str, int, float | None] | None:
    rows = connection.execute(
        """
        SELECT payload_json, created_at
        FROM system_events
        WHERE event_name='websocket_state_transition'
          AND created_at<?
        ORDER BY created_at DESC, event_id DESC
        """,
        (started,),
    ).fetchall()
    selected: tuple[str, int] | None = None
    failure_started_at: float | None = None
    failure_states = {"backoff", "disconnected", "stale"}
    for raw, created_at in rows:
        payload = _payload(raw, "websocket_state_transition")
        if payload.get("channel") != channel:
            continue
        generation = payload.get("generation")
        state = str(payload.get("new_state", "")).lower()
        if type(generation) is not int or generation < 0 or not state:
            raise ValueError(f"{channel} prior websocket state 非法")
        if selected is None:
            selected = (state, generation)
            if state == "ready":
                return state, generation, None
        # Runtime uses setdefault when entering a failure state.  The first
        # failure after the last READY transition is therefore the exact
        # incident start used by websocket_recovery_completed, even when it
        # falls on the previous UTC day.
        if state in failure_states:
            failure_started_at = float(created_at)
        if state == "ready":
            break
    if selected is None:
        return None
    return selected[0], selected[1], failure_started_at


def _validate_ws_lifecycle_correlations(
    connection: sqlite3.Connection,
    *,
    started: float,
    ended: float,
) -> list[str]:
    """Require one subscription/recovery fact for each matching WS lifecycle."""
    reasons: list[str] = []
    transitions = _event_rows(
        connection,
        "websocket_state_transition",
        started,
        ended,
    )
    subscriptions = _event_rows(
        connection,
        "websocket_subscription_ready",
        started,
        ended,
    )
    recoveries = _event_rows(
        connection,
        "websocket_recovery_completed",
        started,
        ended,
    )
    for channel in SLO_V2_POLICY["expected_channels"]:
        channel_transitions = [
            row for row in transitions if row[2].get("channel") == channel
        ]
        channel_subscriptions = [
            row for row in subscriptions if row[2].get("channel") == channel
        ]
        channel_recoveries = [
            row for row in recoveries if row[2].get("channel") == channel
        ]
        prior = _latest_prior_ws_boundary(
            connection,
            channel,
            started=started,
        )
        state = prior[0] if prior is not None else None
        connecting_at_by_generation: dict[int, float] = {}
        ready_rows_by_generation: dict[
            int,
            list[tuple[float, str, dict]],
        ] = {}
        recovery_incidents: dict[
            int,
            list[tuple[float | None, float]],
        ] = {}
        disconnect_started = prior[2] if prior is not None else None
        for ts, event_id, payload in channel_transitions:
            old_state = str(payload.get("old_state", "")).lower()
            new_state = str(payload.get("new_state", "")).lower()
            generation = payload.get("generation")
            if type(generation) is not int or generation < 0:
                reasons.append(f"WS_GENERATION_INVALID:{channel}")
                continue
            if state is None:
                state = old_state
            if new_state == "connecting":
                if generation in connecting_at_by_generation:
                    reasons.append(
                        f"WS_CONNECTING_GENERATION_DUPLICATE:{channel}"
                    )
                connecting_at_by_generation[generation] = ts
            if state == "ready" and new_state != "ready":
                disconnect_started = ts
            if state != "ready" and new_state == "ready":
                ready_rows_by_generation.setdefault(generation, []).append(
                    (ts, event_id, payload)
                )
                if disconnect_started is not None:
                    recovery_incidents.setdefault(generation, []).append(
                        (disconnect_started, ts)
                    )
                    disconnect_started = None
            state = new_state

        subscriptions_by_generation: dict[
            int,
            list[tuple[float, str, dict]],
        ] = {}
        for row in channel_subscriptions:
            ts, _event_id, payload = row
            generation = payload.get("generation")
            if (
                set(payload)
                != {
                    "channel",
                    "generation",
                    "connect_subscribe_latency_seconds",
                }
                or type(generation) is not int
                or generation < 0
            ):
                reasons.append(f"WS_SUBSCRIPTION_SCHEMA_INVALID:{channel}")
                continue
            subscriptions_by_generation.setdefault(generation, []).append(row)
            connecting_at = connecting_at_by_generation.get(generation)
            if connecting_at is not None:
                latency = _finite_nonnegative(
                    payload["connect_subscribe_latency_seconds"],
                    "websocket_subscription_ready.connect_subscribe_latency_seconds",
                )
                if not math.isclose(
                    latency,
                    max(ts - connecting_at, 0),
                    rel_tol=0,
                    abs_tol=5,
                ):
                    reasons.append(
                        f"WS_SUBSCRIPTION_DURATION_MISMATCH:{channel}"
                    )
        for generation, ready_rows in ready_rows_by_generation.items():
            if (
                len(ready_rows) != 1
                or len(subscriptions_by_generation.get(generation, [])) != 1
            ):
                reasons.append(f"WS_SUBSCRIPTION_ASSOCIATION:{channel}")
        if any(
            generation not in ready_rows_by_generation
            for generation in subscriptions_by_generation
        ):
            reasons.append(f"WS_SUBSCRIPTION_ORPHAN:{channel}")

        recoveries_by_generation: dict[
            int,
            list[tuple[float, str, dict]],
        ] = {}
        for row in channel_recoveries:
            ts, _event_id, payload = row
            generation = payload.get("generation")
            if (
                set(payload)
                != {
                    "channel",
                    "generation",
                    "disconnect_duration_seconds",
                    "rest_baseline_duration_seconds",
                    "safe",
                }
                or type(generation) is not int
                or generation < 0
                or payload.get("safe") is not True
            ):
                reasons.append(f"WS_RECOVERY_SCHEMA_INVALID:{channel}")
                continue
            recoveries_by_generation.setdefault(generation, []).append(row)
            incidents = recovery_incidents.get(generation, [])
            if len(incidents) == 1:
                disconnect_started_at, ready_at = incidents[0]
                duration = _finite_nonnegative(
                    payload["disconnect_duration_seconds"],
                    "websocket_recovery_completed.disconnect_duration_seconds",
                )
                if (
                    ts < ready_at
                    or disconnect_started_at is None
                    or not math.isclose(
                        duration,
                        max(ts - disconnect_started_at, 0),
                        rel_tol=0,
                        abs_tol=5,
                    )
                ):
                    reasons.append(
                        f"WS_RECOVERY_DURATION_MISMATCH:{channel}"
                    )
        for generation, incidents in recovery_incidents.items():
            if (
                len(incidents) != 1
                or len(recoveries_by_generation.get(generation, [])) != 1
            ):
                reasons.append(f"WS_RECOVERY_ASSOCIATION:{channel}")
        if any(
            generation not in recovery_incidents
            for generation in recoveries_by_generation
        ):
            reasons.append(f"WS_RECOVERY_ORPHAN:{channel}")
    return reasons


_RUNTIME_MODES = {
    "starting",
    "ready",
    "degraded",
    "halted",
    "emergency_exit",
    "maintenance",
}
_RUNTIME_HARD_MODES = {
    "halted",
    "emergency_exit",
    "maintenance",
}


def _runtime_readiness_summary(
    connection: sqlite3.Connection,
    readiness_rows: list[tuple[float, str, dict]],
    heartbeat_rows: list[tuple[float, str, dict]],
    *,
    started: float,
    ended: float,
) -> tuple[dict, list[str]]:
    reasons: list[str] = []
    prior = connection.execute(
        """
        SELECT payload_json
        FROM system_events
        WHERE event_name='runtime_readiness_transition'
          AND created_at<?
        ORDER BY created_at DESC, event_id DESC
        LIMIT 1
        """,
        (started,),
    ).fetchone()
    mode: str | None = None
    if prior is not None:
        prior_payload = _payload(
            prior[0],
            "runtime_readiness_transition",
        )
        mode = str(prior_payload.get("new_mode", "")).lower()
    elif readiness_rows:
        mode = str(readiness_rows[0][2].get("old_mode", "")).lower()
    if mode not in _RUNTIME_MODES:
        reasons.append("RUNTIME_READINESS_BOUNDARY_UNKNOWN")
        mode = "starting"

    cursor = started
    ready_seconds = 0.0
    nonready_durations: list[float] = []
    nonready_started = started if mode != "ready" else None
    ready_transition_count = 0
    hard_transition_count = 0
    readiness_durations: list[float] = []
    transition_states: list[tuple[float, str]] = []
    for ts, _event_id, payload in readiness_rows:
        try:
            if set(payload) != {
                "old_mode",
                "new_mode",
                "reason",
                "previous_mode_duration_seconds",
            }:
                raise ValueError("schema 非法")
            old_mode = str(payload["old_mode"]).lower()
            new_mode = str(payload["new_mode"]).lower()
            if (
                old_mode != mode
                or old_mode not in _RUNTIME_MODES
                or new_mode not in _RUNTIME_MODES
                or new_mode == old_mode
                or not str(payload["reason"]).strip()
            ):
                raise ValueError("mode chain/reason 非法")
            readiness_durations.append(
                _finite_nonnegative(
                    payload["previous_mode_duration_seconds"],
                    "runtime_readiness_transition.previous_mode_duration_seconds",
                )
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            reasons.append("RUNTIME_READINESS_TRANSITION_INVALID")
            continue
        if mode == "ready":
            ready_seconds += max(ts - cursor, 0)
        if mode == "ready" and new_mode != "ready":
            nonready_started = ts
        elif mode != "ready" and new_mode == "ready":
            if nonready_started is not None:
                nonready_durations.append(ts - nonready_started)
            nonready_started = None
        ready_transition_count += new_mode == "ready"
        hard_transition_count += new_mode in _RUNTIME_HARD_MODES
        mode = new_mode
        cursor = ts
        transition_states.append((ts, mode))
    if mode == "ready":
        ready_seconds += max(ended - cursor, 0)
    elif nonready_started is not None:
        nonready_durations.append(ended - nonready_started)

    mode_cursor = (
        str(prior_payload.get("new_mode", "")).lower()
        if prior is not None
        else (
            str(readiness_rows[0][2].get("old_mode", "")).lower()
            if readiness_rows
            else "starting"
        )
    )
    transition_index = 0
    for heartbeat_ts, _event_id, heartbeat in heartbeat_rows:
        while (
            transition_index < len(transition_states)
            and transition_states[transition_index][0] <= heartbeat_ts
        ):
            mode_cursor = transition_states[transition_index][1]
            transition_index += 1
        if str(heartbeat.get("mode", "")).lower() != mode_cursor:
            reasons.append("RUNTIME_HEARTBEAT_READINESS_MISMATCH")
    expected = ended - started
    nonready_seconds = max(expected - ready_seconds, 0)
    return {
        "readiness_transition_count": len(readiness_rows),
        "ready_transition_count": ready_transition_count,
        "hard_transition_count": hard_transition_count,
        "max_previous_mode_duration_seconds": max(
            readiness_durations,
            default=0,
        ),
        "readiness_ready_seconds": ready_seconds,
        "readiness_nonready_seconds": nonready_seconds,
        "readiness_ratio": ready_seconds / expected if expected else 0,
        "readiness_max_nonready_seconds": max(
            nonready_durations,
            default=nonready_seconds,
        ),
    }, reasons


def _reconciliation(
    connection: sqlite3.Connection,
    *,
    started: float,
    ended: float,
) -> dict:
    rows = connection.execute(
        """
        SELECT run_id, status, mismatch_count, repaired_count, details_json,
               started_at, completed_at
        FROM reconciliation_runs
        WHERE started_at>=? AND started_at<?
        ORDER BY started_at, run_id
        """,
        (started, ended),
    ).fetchall()
    completed_times: list[float] = []
    success = 0
    auto_repaired = 0
    unresolved = 0
    failures = 0
    for (
        _run_id,
        status,
        _mismatch_count,
        repaired_count,
        details_raw,
        _run_started,
        completed_at,
    ) in rows:
        details = _payload(details_raw, "reconciliation_runs.details")
        unresolved_rows = details.get("unresolved", [])
        if not isinstance(unresolved_rows, list):
            raise ValueError("reconciliation unresolved 必须是数组")
        unresolved += len(unresolved_rows)
        auto_repaired += int(repaired_count)
        if status == "completed" and completed_at is not None:
            success += 1
            completed_times.append(float(completed_at))
        else:
            failures += 1
    points = [started, *completed_times, ended]
    gaps = [
        points[index + 1] - points[index]
        for index in range(len(points) - 1)
    ]
    expected = math.floor(
        (ended - started)
        / SLO_V2_POLICY["reconciliation_interval_seconds"]
    )
    attempts = len(rows)
    return {
        "expected_count": expected,
        "attempt_count": attempts,
        "success_count": success,
        "failure_count": failures,
        "success_ratio": success / attempts if attempts else 0,
        "maximum_completion_gap_seconds": max(gaps, default=ended - started),
        "auto_repaired_count": auto_repaired,
        "unresolved_count": unresolved,
    }


def _resource_summary(payloads: list[dict]) -> dict:
    fields = (
        "rss_bytes",
        "fd_count",
        "threads",
        "pids_current",
        "db_bytes",
        "wal_bytes",
        "disk_free_bytes",
        "disk_free_inodes",
        "memory_high_bytes",
        "memory_max_bytes",
        "limit_nofile",
        "tasks_max",
        "max_database_bytes",
        "max_wal_bytes",
        "wal_checkpoint_age_seconds",
        "max_wal_checkpoint_age_seconds",
        "wal_checkpoint_busy",
        "wal_checkpoint_log_frames",
        "wal_checkpointed_frames",
        "wal_checkpoint_backlog_frames",
        "wal_checkpoint_page_size_bytes",
        "wal_checkpoint_backlog_bytes",
        "max_database_growth_bytes_per_day",
        "min_free_bytes",
        "min_free_inodes",
        "oom_kill_count",
        "cpu_nr_throttled",
        "cpu_throttled_usec",
    )
    summary: dict[str, Any] = {
        "sample_count": len(payloads),
        "identity_mismatch_count": 0,
        "warning_sample_count": 0,
        "breach_sample_count": 0,
    }
    identities = {
        (
            str(payload.get("boot_id", "")),
            int(payload.get("pid", 0)),
            str(payload.get("release_identity", "")),
            str(payload.get("config_identity", "")),
        )
        for payload in payloads
    }
    if payloads and (
        any(not all(identity) for identity in identities)
        or len({item[2:] for item in identities}) != 1
    ):
        summary["identity_mismatch_count"] = len(payloads)
    summary["warning_sample_count"] = sum(
        bool(payload.get("warning_codes")) for payload in payloads
    )
    summary["breach_sample_count"] = sum(
        bool(payload.get("breach_codes")) for payload in payloads
    )
    for payload in payloads:
        log_frames = payload.get("wal_checkpoint_log_frames")
        checkpointed_frames = payload.get("wal_checkpointed_frames")
        backlog_frames = payload.get("wal_checkpoint_backlog_frames")
        page_size = payload.get("wal_checkpoint_page_size_bytes")
        backlog_bytes = payload.get("wal_checkpoint_backlog_bytes")
        if (
            type(log_frames) is not int
            or type(checkpointed_frames) is not int
            or type(backlog_frames) is not int
            or type(page_size) is not int
            or type(backlog_bytes) is not int
            or min(
                log_frames,
                checkpointed_frames,
                backlog_frames,
                backlog_bytes,
            )
            < 0
            or page_size <= 0
            or checkpointed_frames > log_frames
            or backlog_frames != log_frames - checkpointed_frames
            or backlog_bytes != backlog_frames * (page_size + 24)
            or payload.get("wal_checkpoint_busy") not in {0, 1}
        ):
            raise ValueError("process_resource_sample WAL checkpoint 事实非法")
    for field in fields:
        if payloads and any(field not in payload for payload in payloads):
            raise ValueError(f"process_resource_sample.{field} 缺失")
        values = [
            _finite_nonnegative(
                payload[field],
                f"process_resource_sample.{field}",
            )
            for payload in payloads
        ]
        summary[field] = {
            "first": values[0] if values else 0,
            "last": values[-1] if values else 0,
            "min": min(values, default=0),
            "max": max(values, default=0),
            "growth": values[-1] - values[0] if values else 0,
        }
    return summary


def _table_exists(connection: sqlite3.Connection, name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def build_slo_v2_report(
    connection: sqlite3.Connection,
    day: date,
    *,
    soak_epoch_id: str,
    phase: str,
) -> dict:
    if phase not in {"shadow", "burn-in", "soak", "chaos"}:
        raise ValueError("phase 必须是 shadow/burn-in/soak/chaos")
    if not soak_epoch_id.strip():
        raise ValueError("soak_epoch_id 不能为空")
    started_dt = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
    ended_dt = started_dt + timedelta(days=1)
    started = started_dt.timestamp()
    ended = ended_dt.timestamp()
    invalid_reasons: list[str] = []

    resource_rows = _event_rows(
        connection,
        "process_resource_sample",
        started,
        ended,
    )
    coverage = _evidence_coverage(
        [row[0] for row in resource_rows],
        started=started,
        ended=ended,
        max_gap=float(
            SLO_V2_POLICY["resource_sample_max_gap_seconds"]
        ),
    )
    channels = {}
    for channel in SLO_V2_POLICY["expected_channels"]:
        try:
            channels[channel] = _websocket_channel(
                connection,
                channel,
                started=started,
                ended=ended,
            )
        except ValueError as exc:
            invalid_reasons.append(f"INVALID_WS_EVENT:{channel}:{exc}")
            channels[channel] = {
                "transition_count": 0,
                "state_sample_count": 0,
                "max_state_sample_gap_seconds": ended - started,
                "generation_count": 0,
                "ready_seconds": 0,
                "unavailable_seconds": ended - started,
                "availability_ratio": 0,
                "disconnect_count": 0,
                "max_disconnect_seconds": ended - started,
            }
    invalid_reasons.extend(
        _validate_ws_lifecycle_correlations(
            connection,
            started=started,
            ended=ended,
        )
    )
    recovery, recovery_payloads = _numeric_samples(
        connection,
        "websocket_recovery_completed",
        "disconnect_duration_seconds",
        started,
        ended,
    )
    orphan_recovery = sum(
        1
        for payload in recovery_payloads
        if payload.get("channel") not in SLO_V2_POLICY["expected_channels"]
        or type(payload.get("generation")) is not int
        or payload.get("safe") is not True
    )
    if orphan_recovery:
        invalid_reasons.append("ORPHAN_OR_UNSAFE_WS_RECOVERY")
    recovery_by_channel, invalid_recovery_channel_count = (
        _channel_distributions(
            recovery_payloads,
            value_field="disconnect_duration_seconds",
        )
    )
    if invalid_recovery_channel_count:
        invalid_reasons.append("WS_RECOVERY_CHANNEL_SAMPLE_INVALID")
    subscription, subscription_payloads = _numeric_samples(
        connection,
        "websocket_subscription_ready",
        "connect_subscribe_latency_seconds",
        started,
        ended,
    )
    subscription_by_channel, invalid_subscription_count = (
        _channel_distributions(
            subscription_payloads,
            value_field="connect_subscribe_latency_seconds",
        )
    )
    if invalid_subscription_count:
        invalid_reasons.append("WS_SUBSCRIPTION_SAMPLE_INVALID")

    protection, protection_payloads = _numeric_samples(
        connection,
        "protection_activation_slo_sample",
        "latency_seconds",
        started,
        ended,
    )
    protection_failures = sum(
        1 for payload in protection_payloads if payload.get("success", True) is not True
    )
    protection_probe_ids = {
        str(payload["probe_id"])
        for payload in protection_payloads
        if str(payload.get("probe_id", "")).strip()
    }
    slippage, slippage_payloads = _numeric_samples(
        connection,
        "execution_slippage_sample",
        "adverse_slippage_ratio",
        started,
        ended,
    )
    slippage_probe_ids = {
        str(payload["probe_id"])
        for payload in slippage_payloads
        if str(payload.get("probe_id", "")).strip()
    }
    slippage_residuals: list[float] = []
    model_slippage_values: set[float] = set()
    cost_model_hashes: set[str] = set()
    probe_residuals: dict[str, list[float]] = {}
    for payload in slippage_payloads:
        raw_model = payload.get("expected_model_slippage_ratio")
        if raw_model is None:
            continue
        try:
            model = _finite_nonnegative(
                raw_model,
                "slippage.expected_model_slippage_ratio",
            )
            adverse = _finite_nonnegative(
                payload.get("adverse_slippage_ratio"),
                "slippage.adverse_slippage_ratio",
            )
        except (TypeError, ValueError, OverflowError):
            invalid_reasons.append("SLIPPAGE_MODEL_PAIR_INVALID")
            continue
        if model > 1 or adverse > 1:
            invalid_reasons.append("SLIPPAGE_MODEL_PAIR_INVALID")
            continue
        cost_hash = str(payload.get("cost_model_hash", ""))
        if phase == "soak" and not cost_hash:
            invalid_reasons.append(
                "SLIPPAGE_DYNAMIC_MODEL_PROVENANCE_MISSING"
            )
            continue
        if cost_hash:
            try:
                manifest = payload["cost_model_manifest"]
                inputs = payload["cost_model_inputs"]
                if (
                    not isinstance(manifest, dict)
                    or not isinstance(inputs, dict)
                    or set(inputs)
                    != {
                        "side",
                        "notional",
                        "close",
                        "high",
                        "low",
                        "vol",
                        "vol_ccy",
                    }
                ):
                    raise ValueError("dynamic cost payload schema 非法")
                dynamic = DynamicCostModel(**{
                    key: value
                    for key, value in manifest.items()
                    if key != "model"
                })
                if (
                    dynamic.manifest() != manifest
                    or dynamic.manifest_hash() != cost_hash
                ):
                    raise ValueError("dynamic cost manifest/hash 非法")
                _fee, recomputed = dynamic(
                    str(inputs["side"]),
                    pd.Series({
                        "close": inputs["close"],
                        "high": inputs["high"],
                        "low": inputs["low"],
                        "vol": inputs["vol"],
                        "vol_ccy": inputs["vol_ccy"],
                    }),
                    float(inputs["notional"]),
                )
                if not math.isclose(
                    model,
                    recomputed,
                    rel_tol=0,
                    abs_tol=1e-15,
                ):
                    raise ValueError("dynamic cost output 不可重算")
            except (KeyError, TypeError, ValueError, OverflowError):
                invalid_reasons.append("SLIPPAGE_MODEL_RECOMPUTATION_FAILED")
                continue
            cost_model_hashes.add(cost_hash)
        probe_id = str(payload.get("probe_id", "")).strip()
        if phase == "soak" and (
            not re.fullmatch(r"[0-9a-f]{32}", probe_id)
            or payload.get("source") != "demo_validation_probe"
            or payload.get("side") not in {"buy", "sell"}
        ):
            invalid_reasons.append("SLIPPAGE_PROBE_LINEAGE_INVALID")
            continue
        model_slippage_values.add(model)
        residual = adverse - model
        slippage_residuals.append(residual)
        if probe_id:
            probe_residuals.setdefault(probe_id, []).append(residual)
    if (
        slippage_payloads
        and len(slippage_residuals) != len(slippage_payloads)
    ):
        invalid_reasons.append("SLIPPAGE_MODEL_PAIRING_INCOMPLETE")
    if phase == "soak" and len(cost_model_hashes) != 1:
        invalid_reasons.append("SLIPPAGE_DYNAMIC_MODEL_IDENTITY_INVALID")
    clustered_residuals = [
        sum(values) / len(values)
        for values in probe_residuals.values()
        if values
    ]
    residual_cluster_ids = sorted(probe_residuals)
    startup, _ = _numeric_samples(
        connection,
        "startup_reconciliation_slo_sample",
        "duration_seconds",
        started,
        ended,
    )
    readiness_rows = _event_rows(
        connection,
        "runtime_readiness_transition",
        started,
        ended,
    )
    heartbeat_rows = _event_rows(
        connection,
        "runtime_heartbeat_sample",
        started,
        ended,
    )
    unhealthy_heartbeat_count = 0
    heartbeat_invalid = 0
    shadow_write_counts: list[int] = []
    shadow_heartbeat_counts_by_runtime: dict[str, int] = {}
    heartbeat_identity_by_runtime: dict[str, tuple[object, ...]] = {}
    heartbeat_keys = {
        "healthy",
        "mode",
        "pid",
        "boot_id",
        "runtime_instance_id",
        "account_uid",
        "deployment_unit",
        "soak_epoch_id",
        "shadow_mode",
        "shadow_write_attempt_count",
    }
    for _ts, _event_id, payload in heartbeat_rows:
        runtime_instance_id = str(
            payload.get("runtime_instance_id", "")
        )
        identity = (
            payload.get("pid"),
            str(payload.get("boot_id", "")),
            str(payload.get("account_uid", "")),
            str(payload.get("deployment_unit", "")),
            str(payload.get("soak_epoch_id", "")),
        )
        if (
            set(payload) != heartbeat_keys
            or type(payload.get("healthy")) is not bool
            or str(payload.get("mode", "")).lower()
            not in _RUNTIME_MODES
            or type(payload.get("pid")) is not int
            or payload.get("pid", 0) <= 0
            or not str(payload.get("boot_id", "")).strip()
            or not runtime_instance_id
            or not str(payload.get("account_uid", "")).strip()
            or not str(payload.get("deployment_unit", "")).strip()
            or payload.get("soak_epoch_id") != soak_epoch_id
        ):
            heartbeat_invalid += 1
        else:
            previous_identity = heartbeat_identity_by_runtime.setdefault(
                runtime_instance_id,
                identity,
            )
            if previous_identity != identity:
                heartbeat_invalid += 1
            if payload["healthy"] is not True:
                unhealthy_heartbeat_count += 1
        shadow_mode = payload.get("shadow_mode")
        write_count = payload.get("shadow_write_attempt_count")
        if phase == "shadow":
            if (
                shadow_mode is not True
                or type(write_count) is not int
                or write_count < 0
                or not runtime_instance_id
            ):
                heartbeat_invalid += 1
            else:
                shadow_write_counts.append(write_count)
                shadow_heartbeat_counts_by_runtime[
                    runtime_instance_id
                ] = max(
                    shadow_heartbeat_counts_by_runtime.get(
                        runtime_instance_id,
                        0,
                    ),
                    write_count,
                )
        elif shadow_mode is not None or write_count is not None:
            if (
                type(shadow_mode) is not bool
                or type(write_count) is not int
                or write_count < 0
            ):
                heartbeat_invalid += 1
            elif shadow_mode:
                invalid_reasons.append(
                    "NON_SHADOW_PHASE_HAS_SHADOW_RUNTIME"
                )
    heartbeat_coverage = _evidence_coverage(
        [row[0] for row in heartbeat_rows],
        started=started,
        ended=ended,
        max_gap=float(
            SLO_V2_POLICY["heartbeat_sample_max_gap_seconds"]
        ),
    )
    if heartbeat_invalid:
        invalid_reasons.append("RUNTIME_HEARTBEAT_SAMPLE_INVALID")
    readiness, readiness_reasons = _runtime_readiness_summary(
        connection,
        readiness_rows,
        heartbeat_rows,
        started=started,
        ended=ended,
    )
    invalid_reasons.extend(readiness_reasons)
    shadow_rows = _event_rows(
        connection,
        "shadow_order_intent",
        started,
        ended,
    )
    if any(
        not str(payload.get("inst_id", "")).strip()
        or payload.get("side") not in {"buy", "sell"}
        or not str(payload.get("source", "")).strip()
        for _ts, _event_id, payload in shadow_rows
    ):
        invalid_reasons.append("SHADOW_INTENT_SAMPLE_INVALID")
    shadow_write_rows = _event_rows(
        connection,
        "shadow_write_endpoint_attempt",
        started,
        ended,
    )
    shadow_direct_max_by_runtime: dict[str, int] = {}
    for _ts, _event_id, payload in shadow_write_rows:
        if set(payload) != {
            "method",
            "endpoint",
            "attempt_count",
            "account_uid",
            "deployment_unit",
            "soak_epoch_id",
            "runtime_instance_id",
            "boot_id",
        }:
            invalid_reasons.append(
                "SHADOW_WRITE_ATTEMPT_SAMPLE_INVALID"
            )
            continue
        runtime_instance_id = str(payload["runtime_instance_id"])
        attempt_count = payload["attempt_count"]
        if (
            payload["method"] not in {"POST", "PUT", "PATCH", "DELETE"}
            or not str(payload["endpoint"]).strip()
            or type(attempt_count) is not int
            or attempt_count < 1
            or not str(payload["account_uid"]).strip()
            or not str(payload["deployment_unit"]).strip()
            or not str(payload["soak_epoch_id"]).strip()
            or not runtime_instance_id
            or not str(payload["boot_id"]).strip()
        ):
            invalid_reasons.append(
                "SHADOW_WRITE_ATTEMPT_SAMPLE_INVALID"
            )
            continue
        shadow_direct_max_by_runtime[runtime_instance_id] = max(
            shadow_direct_max_by_runtime.get(runtime_instance_id, 0),
            attempt_count,
        )
    shadow_counter_mismatch_count = sum(
        shadow_heartbeat_counts_by_runtime.get(runtime_id, 0)
        < direct_count
        for runtime_id, direct_count
        in shadow_direct_max_by_runtime.items()
    )

    alert_samples: list[tuple[str, dict]] = []
    if _table_exists(connection, "alert_deliveries"):
        rows = connection.execute(
            """
            SELECT d.event_id, d.priority, d.state, d.attempt_count,
                   d.created_at, d.ingestion_accepted_at,
                   d.provider_received_at, d.human_ack_at,
                   d.escalation_at, d.dlq_at,
                   d.provider_artifact_sha256,
                   d.human_ack_artifact_sha256, o.event_name
            FROM alert_deliveries AS d
            JOIN outbox_events AS o USING(event_id)
            WHERE d.created_at>=? AND d.created_at<?
            ORDER BY d.created_at, d.event_id
            """,
            (started, ended),
        ).fetchall()
        for row in rows:
            event_id = str(row[0])
            alert_samples.append(
                (
                    event_id,
                    {
                        "event_id": event_id,
                        "priority": row[1],
                        "state": row[2],
                        "attempt_count": row[3],
                        "enqueue_at": row[4],
                        "ingestion_accepted_at": row[5],
                        "provider_received_at": row[6],
                        "human_ack_at": row[7],
                        "escalation_at": row[8],
                        "dlq_at": row[9],
                        "provider_artifact_sha256": row[10],
                        "human_ack_artifact_sha256": row[11],
                        "event_name": row[12],
                    },
                )
            )
    p0_provider: list[float] = []
    p1_provider: list[float] = []
    human_ack_count = 0
    delivery_failures = 0
    alert_attempt_count = 0
    ingestion_accepted_count = 0
    dlq_count = 0
    escalation_count = 0
    unacknowledged_p0_count = 0
    incident_count = 0
    synthetic_challenge_count = 0
    synthetic_provider_received_count = 0
    for event_id, payload in alert_samples:
        if str(payload.get("event_id", "")) != event_id:
            invalid_reasons.append("ALERT_EVENT_ID_MISMATCH")
        priority = payload.get("priority")
        synthetic = (
            payload.get("event_name")
            == "warning.synthetic_alert_delivery_challenge"
        )
        if synthetic:
            synthetic_challenge_count += 1
        else:
            incident_count += 1
        enqueue = _finite_nonnegative(payload.get("enqueue_at"), "alert.enqueue_at")
        alert_attempt_count += int(payload.get("attempt_count", 1))
        if payload.get("ingestion_accepted_at") is not None:
            ingestion_accepted_count += 1
        if payload.get("dlq_at") is not None or payload.get("state") == "dlq":
            dlq_count += 1
        if payload.get("escalation_at") is not None:
            escalation_count += 1
        provider = payload.get("provider_received_at")
        if provider is None:
            delivery_failures += 1
            if priority == "P0" and payload.get("escalation_at") is None:
                unacknowledged_p0_count += 1
            continue
        if not re.fullmatch(
            r"[0-9a-f]{64}",
            str(payload.get("provider_artifact_sha256", "")),
        ):
            invalid_reasons.append("ALERT_PROVIDER_PROVENANCE_INVALID")
            delivery_failures += 1
            continue
        if synthetic:
            synthetic_provider_received_count += 1
        latency = max(
            _finite_nonnegative(provider, "alert.provider_received_at")
            - enqueue,
            0,
        )
        if priority == "P0":
            p0_provider.append(latency)
        elif priority == "P1":
            p1_provider.append(latency)
        else:
            invalid_reasons.append("ALERT_PRIORITY_INVALID")
        if payload.get("human_ack_at") is not None:
            if not re.fullmatch(
                r"[0-9a-f]{64}",
                str(payload.get("human_ack_artifact_sha256", "")),
            ):
                invalid_reasons.append(
                    "ALERT_HUMAN_ACK_PROVENANCE_INVALID"
                )
            else:
                human_ack_count += 1
        elif priority == "P0" and payload.get("escalation_at") is None:
            unacknowledged_p0_count += 1

    backup_rows = _event_rows(
        connection,
        "backup_slo_sample",
        started,
        ended,
    )
    local_ages: list[float] = []
    offsite_ages: list[float] = []
    backup_failures = 0
    component_restore: list[float] = []
    prior_backup_rows = connection.execute(
        """
        SELECT created_at, event_id, payload_json
        FROM system_events
        WHERE event_name='backup_slo_sample' AND created_at<?
        ORDER BY created_at DESC, event_id DESC
        """,
        (started,),
    ).fetchall()
    latest_local_snapshot: float | None = None
    latest_offsite_snapshot: float | None = None
    for prior_ts, _event_id, raw in prior_backup_rows:
        prior_payload = _payload(raw, "backup_slo_sample")
        try:
            validate_backup_slo_sample(
                prior_payload,
                event_created_at=float(prior_ts),
            )
        except (TypeError, ValueError):
            continue
        candidate = _finite_nonnegative(
            prior_payload.get("snapshot_completed_at"),
            "backup.snapshot_completed_at",
        )
        if latest_local_snapshot is None:
            latest_local_snapshot = candidate
        if (
            latest_offsite_snapshot is None
            and prior_payload.get("offsite_readback_at") is not None
            and str(prior_payload.get("version_id", "")).strip()
        ):
            latest_offsite_snapshot = candidate
        if (
            latest_local_snapshot is not None
            and latest_offsite_snapshot is not None
        ):
            break
    if latest_local_snapshot is not None:
        local_ages.append(max(started - latest_local_snapshot, 0))
    if latest_offsite_snapshot is not None:
        offsite_ages.append(max(started - latest_offsite_snapshot, 0))
    for ts, _event_id, payload in backup_rows:
        if latest_local_snapshot is not None:
            local_ages.append(max(ts - latest_local_snapshot, 0))
        if latest_offsite_snapshot is not None:
            offsite_ages.append(max(ts - latest_offsite_snapshot, 0))
        try:
            validate_backup_slo_sample(
                payload,
                event_created_at=ts,
            )
        except (TypeError, ValueError):
            backup_failures += 1
            invalid_reasons.append("BACKUP_SAMPLE_INVALID")
            continue
        roundtrip_started = _finite_nonnegative(
            payload["roundtrip_started_at"],
            "backup.roundtrip_started_at",
        )
        roundtrip_completed = _finite_nonnegative(
            payload["roundtrip_completed_at"],
            "backup.roundtrip_completed_at",
        )
        component_restore.append(
            roundtrip_completed - roundtrip_started
        )
        snapshot_completed = _finite_nonnegative(
            payload.get("snapshot_completed_at"),
            "backup.snapshot_completed_at",
        )
        if snapshot_completed > ts + 5:
            backup_failures += 1
            invalid_reasons.append("BACKUP_TIME_CHAIN_INVALID")
            continue
        local_ages.append(max(ts - snapshot_completed, 0))
        latest_local_snapshot = max(
            latest_local_snapshot or 0,
            snapshot_completed,
        )
        readback = payload.get("offsite_readback_at")
        if (
            readback is not None
            and str(payload.get("version_id", "")).strip()
        ):
            readback_value = _finite_nonnegative(
                readback,
                "backup.offsite_readback_at",
            )
            if not snapshot_completed <= readback_value <= ts + 5:
                backup_failures += 1
                invalid_reasons.append("BACKUP_TIME_CHAIN_INVALID")
                continue
            offsite_ages.append(
                max(
                    readback_value - snapshot_completed,
                    0,
                )
            )
            latest_offsite_snapshot = max(
                latest_offsite_snapshot or 0,
                snapshot_completed,
            )
        else:
            backup_failures += 1
    if latest_local_snapshot is not None:
        local_ages.append(max(ended - latest_local_snapshot, 0))
    if latest_offsite_snapshot is not None:
        offsite_ages.append(max(ended - latest_offsite_snapshot, 0))

    clock_rows = _event_rows(
        connection,
        "clock_quality_sample",
        started,
        ended,
    )
    clock_offsets = [
        abs(float(payload.get("okx_midpoint_offset_seconds", math.inf)))
        for _ts, _event_id, payload in clock_rows
    ]
    if any(not math.isfinite(value) for value in clock_offsets):
        invalid_reasons.append("CLOCK_SAMPLE_INVALID")

    probe_counts = {
        "attempt_count": 0,
        "done_count": 0,
        "failed_count": 0,
        "unknown_count": 0,
        "manual_review_count": 0,
        "duplicate_buy_count": 0,
        "fully_correlated_count": 0,
        "schedule_sample_count": 0,
        "schedule_compliant_count": 0,
        "schedule_violation_count": 0,
        "schedule_sha256": "",
        "formal_probe_ids": [],
        "done_probe_ids": [],
    }
    schedule_rows = _event_rows(
        connection,
        "probe_schedule_sample",
        started,
        ended,
    )
    schedule_hashes = {
        str(payload.get("schedule_sha256", ""))
        for _ts, _event_id, payload in schedule_rows
        if re.fullmatch(
            r"[0-9a-f]{64}",
            str(payload.get("schedule_sha256", "")),
        )
    }
    probe_counts["schedule_sample_count"] = len(schedule_rows)
    probe_counts["schedule_compliant_count"] = sum(
        payload.get("compliant") is True
        for _ts, _event_id, payload in schedule_rows
    )
    probe_counts["schedule_violation_count"] = sum(
        payload.get("compliant") is not True
        for _ts, _event_id, payload in schedule_rows
    )
    probe_counts["schedule_sha256"] = (
        next(iter(schedule_hashes)) if len(schedule_hashes) == 1 else ""
    )
    if len(schedule_hashes) != 1 and schedule_rows:
        invalid_reasons.append("PROBE_SCHEDULE_IDENTITY_INVALID")
    formal_probe_id_samples = [
        str(payload.get("probe_id", "")).strip()
        for _ts, _event_id, payload in schedule_rows
        if payload.get("compliant") is True
        and re.fullmatch(
            r"[0-9a-f]{32}",
            str(payload.get("probe_id", "")).strip(),
        )
    ]
    formal_probe_ids = set(formal_probe_id_samples)
    probe_counts["formal_probe_ids"] = sorted(formal_probe_ids)
    done_probe_ids: set[str] = set()
    attempted_probe_ids: set[str] = set()
    if _table_exists(connection, "probe_runs"):
        rows = connection.execute(
            """
            SELECT probe_id, state, duplicate_buy_count
            FROM probe_runs
            WHERE created_at>=? AND created_at<?
            """,
            (started, ended),
        ).fetchall()
        probe_counts["attempt_count"] = len(rows)
        for probe_id, state, duplicate_count in rows:
            attempted_probe_ids.add(str(probe_id))
            normalized = str(state)
            if normalized == "DONE":
                probe_counts["done_count"] += 1
                done_probe_ids.add(str(probe_id))
            elif normalized in {
                "PREPARED",
                "BUY_SUBMITTING",
                "BUY_UNKNOWN",
                "BUY_FILLED",
                "PROTECTING",
                "PROTECTED",
                "CLEANING",
            }:
                probe_counts["unknown_count"] += 1
            elif normalized == "MANUAL_REVIEW":
                probe_counts["manual_review_count"] += 1
            elif normalized in {"REJECTED", "FAILED"}:
                probe_counts["failed_count"] += 1
            else:
                probe_counts["unknown_count"] += 1
            probe_counts["duplicate_buy_count"] += int(duplicate_count)
    probe_counts["done_probe_ids"] = sorted(done_probe_ids)
    if phase == "soak" and (
        len(formal_probe_id_samples) != len(schedule_rows)
        or len(formal_probe_id_samples) != len(formal_probe_ids)
        or formal_probe_ids != attempted_probe_ids
    ):
        invalid_reasons.append("PROBE_SCHEDULE_LINEAGE_INVALID")
    fact_channels: dict[str, set[str]] = {}
    for _ts, _event_id, payload in _event_rows(
        connection,
        "exchange_fact_consumed",
        started,
        ended,
    ):
        probe_id = str(payload.get("probe_id", ""))
        channel = str(payload.get("channel", ""))
        if probe_id:
            fact_channels.setdefault(probe_id, set()).add(channel)
    probe_counts["fully_correlated_count"] = sum(
        1
        for probe_id in done_probe_ids
        if {"private", "business"} <= fact_channels.get(probe_id, set())
        and probe_id in protection_probe_ids
        and probe_id in slippage_probe_ids
    )

    reconciliation = _reconciliation(
        connection,
        started=started,
        ended=ended,
    )
    if coverage["sample_count"] == 0:
        invalid_reasons.append("NO_RESOURCE_OBSERVABILITY_SAMPLES")
    if any(
        channels[channel]["state_sample_count"] == 0
        for channel in SLO_V2_POLICY["expected_channels"]
    ):
        invalid_reasons.append("NO_WS_STATE_EVIDENCE")
    if reconciliation["attempt_count"] == 0:
        invalid_reasons.append("NO_RECONCILIATION_ATTEMPTS")
    if not clock_rows:
        invalid_reasons.append("NO_CLOCK_QUALITY_SAMPLES")
    if not backup_rows:
        invalid_reasons.append("NO_BACKUP_SLO_SAMPLES")
    elif not component_restore:
        invalid_reasons.append(
            "NO_BACKUP_COMPONENT_RESTORE_SAMPLES"
        )
    if not heartbeat_rows:
        invalid_reasons.append("NO_RUNTIME_HEARTBEAT_SAMPLES")
    if synthetic_challenge_count == 0:
        invalid_reasons.append("NO_SYNTHETIC_ALERT_CHALLENGE")
    elif synthetic_provider_received_count != synthetic_challenge_count:
        invalid_reasons.append("SYNTHETIC_ALERT_CHALLENGE_UNVERIFIED")
    if phase == "soak" and probe_counts["attempt_count"] == 0:
        invalid_reasons.append("NO_PROBE_ATTEMPTS")
    if phase == "soak" and (
        probe_counts["schedule_sample_count"]
        != probe_counts["attempt_count"]
        or probe_counts["schedule_compliant_count"]
        != probe_counts["attempt_count"]
        or probe_counts["schedule_violation_count"] != 0
    ):
        invalid_reasons.append("PROBE_SCHEDULE_NONCOMPLIANT")
    if (
        probe_counts["done_count"]
        != probe_counts["fully_correlated_count"]
    ):
        invalid_reasons.append("PROBE_WS_FACT_ASSOCIATION_INCOMPLETE")
    if phase == "soak" and (
        len(done_probe_ids) != 1
        or formal_probe_ids != done_probe_ids
        or set(residual_cluster_ids) != done_probe_ids
    ):
        invalid_reasons.append("PROBE_RESIDUAL_LINEAGE_INVALID")

    report = {
        "version": 2,
        "schema": SLO_V2_SCHEMA,
        "policy_hash": SLO_V2_POLICY_HASH,
        "soak_epoch_id": soak_epoch_id,
        "phase": phase,
        "day": day.isoformat(),
        "window": {
            "started_at": started_dt.isoformat(),
            "ended_at": ended_dt.isoformat(),
            "expected_seconds": ended - started,
            **coverage,
        },
        "websocket": {
            "channels": channels,
            "recovery": {
                "sample_count": len(recovery),
                "p50_seconds": _quantile(recovery, 0.50),
                "p95_seconds": _quantile(recovery, 0.95),
                "p99_seconds": _quantile(recovery, 0.99),
                "max_seconds": max(recovery, default=0),
                "orphan_or_unsafe_count": orphan_recovery,
            },
            "recovery_by_channel": recovery_by_channel,
            "subscription_ready": {
                **_distribution(subscription),
                "invalid_count": invalid_subscription_count,
            },
            "subscription_ready_by_channel": subscription_by_channel,
        },
        "reconciliation": reconciliation,
        "runtime": {
            "startup_count": len(startup),
            "startup_max_seconds": max(startup, default=0),
            **readiness,
            "heartbeat_sample_count": len(heartbeat_rows),
            "heartbeat_max_gap_seconds": heartbeat_coverage[
                "max_evidence_gap_seconds"
            ],
            "unhealthy_heartbeat_count": unhealthy_heartbeat_count,
            "shadow_intent_count": len(shadow_rows),
            "shadow_write_audit_sample_count": len(
                shadow_write_counts
            ),
            "shadow_write_attempt_event_count": len(
                shadow_write_rows
            ),
            "shadow_write_attempt_count": max(
                [
                    *shadow_write_counts,
                    *shadow_direct_max_by_runtime.values(),
                ],
                default=0,
            ),
            "shadow_write_counter_mismatch_count": (
                shadow_counter_mismatch_count
            ),
        },
        "alerts": {
            "sample_count": len(alert_samples),
            "incident_count": incident_count,
            "synthetic_challenge_count": synthetic_challenge_count,
            "synthetic_provider_received_count": (
                synthetic_provider_received_count
            ),
            "attempt_count": alert_attempt_count,
            "ingestion_accepted_count": ingestion_accepted_count,
            "p0_provider_received_max_seconds": max(p0_provider, default=0),
            "p1_provider_received_max_seconds": max(p1_provider, default=0),
            "provider_failure_count": delivery_failures,
            "dlq_count": dlq_count,
            "human_ack_count": human_ack_count,
            "escalation_count": escalation_count,
            "unacknowledged_p0_count": unacknowledged_p0_count,
        },
        "backups": {
            "sample_count": len(backup_rows),
            "failure_count": backup_failures,
            "local_max_recovery_point_age_seconds": max(
                local_ages,
                default=ended - started,
            ),
            "offsite_max_recovery_point_age_seconds": max(
                offsite_ages,
                default=ended - started,
            ),
            "component_restore_sample_count": len(component_restore),
            "component_restore_max_seconds": max(
                component_restore,
                default=0,
            ),
        },
        "resources": _resource_summary(
            [payload for _ts, _event_id, payload in resource_rows]
        ),
        "clock": {
            "sample_count": len(clock_rows),
            "max_absolute_offset_seconds": max(
                clock_offsets,
                default=ended - started,
            ),
        },
        "probes": probe_counts,
        "protection": {
            "attempt_count": len(protection_payloads),
            "success_count": len(protection) - protection_failures,
            "failure_count": protection_failures,
            "independent_probe_count": len(protection_probe_ids),
            "p50_seconds": _quantile(protection, 0.50),
            "p95_seconds": _quantile(protection, 0.95),
            "p99_seconds": _quantile(protection, 0.99),
            "max_seconds": max(protection, default=0),
            "p99_is_gate": len(protection) >= int(
                SLO_V2_POLICY["protection_p99_min_samples"]
            ),
        },
        "execution_slippage": {
            "attempt_count": len(slippage_payloads),
            "sample_count": len(slippage),
            "independent_probe_count": len(slippage_probe_ids),
            "p95_ratio": _quantile(slippage, 0.95),
            "p99_ratio": _quantile(slippage, 0.99),
            "max_ratio": max(slippage, default=0),
            "model_paired_count": len(slippage_residuals),
            "expected_model_ratio": (
                sum(model_slippage_values) / len(model_slippage_values)
                if model_slippage_values
                else 0
            ),
            "cost_model_hash": (
                next(iter(cost_model_hashes))
                if len(cost_model_hashes) == 1
                else ""
            ),
            "residual_sum_ratio": sum(slippage_residuals),
            "residual_sum_squares_ratio": sum(
                value * value for value in slippage_residuals
            ),
            "residual_upper_95_ratio": _one_sided_upper_95(
                slippage_residuals
            ),
            "residual_cluster_count": len(clustered_residuals),
            "residual_cluster_ids": residual_cluster_ids,
            "cluster_residual_sum_ratio": sum(clustered_residuals),
            "cluster_residual_sum_squares_ratio": sum(
                value * value for value in clustered_residuals
            ),
            "cluster_residual_upper_95_ratio": _one_sided_upper_95(
                clustered_residuals
            ),
        },
        "integrity": {
            "valid": not invalid_reasons,
            "invalid_event_count": len(set(invalid_reasons)),
            "reason_codes": sorted(set(invalid_reasons)),
        },
    }
    validate_slo_v2_report(report)
    return report


def _exact_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} schema 不完整或含未知字段")
    return value


def validate_slo_v2_report(report: object) -> dict:
    report = _exact_keys(report, REPORT_KEYS, "SLO v2")
    if (
        report["version"] != 2
        or report["schema"] != SLO_V2_SCHEMA
        or report["policy_hash"] != SLO_V2_POLICY_HASH
        or report["phase"] not in {"shadow", "burn-in", "soak", "chaos"}
        or not str(report["soak_epoch_id"]).strip()
    ):
        raise ValueError("SLO v2 version/policy/epoch/phase 非法")
    day = date.fromisoformat(str(report["day"]))
    window = _exact_keys(
        report["window"],
        {
            "started_at",
            "ended_at",
            "expected_seconds",
            "sample_count",
            "actual_observable_seconds",
            "unobservable_seconds",
            "max_evidence_gap_seconds",
        },
        "SLO v2 window",
    )
    started = datetime.fromisoformat(str(window["started_at"]))
    ended = datetime.fromisoformat(str(window["ended_at"]))
    if (
        started.tzinfo is None
        or ended.tzinfo is None
        or started.astimezone(UTC)
        != datetime.combine(day, datetime.min.time(), tzinfo=UTC)
        or ended - started != timedelta(days=1)
        or float(window["expected_seconds"]) != 86400
    ):
        raise ValueError("SLO v2 必须绑定完整 UTC 24 小时")
    websocket = _exact_keys(
        report["websocket"],
        {
            "channels",
            "recovery",
            "recovery_by_channel",
            "subscription_ready",
            "subscription_ready_by_channel",
        },
        "SLO v2 websocket",
    )
    channels = websocket["channels"]
    if (
        not isinstance(channels, dict)
        or set(channels) != set(SLO_V2_POLICY["expected_channels"])
    ):
        raise ValueError("SLO v2 websocket channels 非法")
    for channel, metrics in channels.items():
        _exact_keys(
            metrics,
            {
                "transition_count",
                "state_sample_count",
                "max_state_sample_gap_seconds",
                "generation_count",
                "ready_seconds",
                "unavailable_seconds",
                "availability_ratio",
                "disconnect_count",
                "max_disconnect_seconds",
            },
            f"SLO v2 websocket.{channel}",
        )
    _exact_keys(
        websocket["recovery"],
        {
            "sample_count",
            "p50_seconds",
            "p95_seconds",
            "p99_seconds",
            "max_seconds",
            "orphan_or_unsafe_count",
        },
        "SLO v2 websocket.recovery",
    )
    distribution_keys = {
        "sample_count",
        "p50_seconds",
        "p95_seconds",
        "p99_seconds",
        "max_seconds",
    }
    for field_name in (
        "recovery_by_channel",
        "subscription_ready_by_channel",
    ):
        by_channel = websocket[field_name]
        if (
            not isinstance(by_channel, dict)
            or set(by_channel)
            != set(SLO_V2_POLICY["expected_channels"])
        ):
            raise ValueError(f"SLO v2 websocket.{field_name} 非法")
        for channel, metrics in by_channel.items():
            _exact_keys(
                metrics,
                distribution_keys,
                f"SLO v2 websocket.{field_name}.{channel}",
            )
    _exact_keys(
        websocket["subscription_ready"],
        distribution_keys | {"invalid_count"},
        "SLO v2 websocket.subscription_ready",
    )
    for label, metrics in (
        ("subscription_ready", websocket["subscription_ready"]),
        *(
            (f"recovery_by_channel.{channel}", channel_metrics)
            for channel, channel_metrics in websocket[
                "recovery_by_channel"
            ].items()
        ),
        *(
            (
                f"subscription_ready_by_channel.{channel}",
                channel_metrics,
            )
            for channel, channel_metrics in websocket[
                "subscription_ready_by_channel"
            ].items()
        ),
    ):
        if not (
            metrics["p50_seconds"]
            <= metrics["p95_seconds"]
            <= metrics["p99_seconds"]
            <= metrics["max_seconds"]
        ):
            raise ValueError(
                f"SLO v2 websocket.{label} 分位数不闭合"
            )
    _exact_keys(
        report["reconciliation"],
        {
            "expected_count",
            "attempt_count",
            "success_count",
            "failure_count",
            "success_ratio",
            "maximum_completion_gap_seconds",
            "auto_repaired_count",
            "unresolved_count",
        },
        "SLO v2 reconciliation",
    )
    _exact_keys(
        report["runtime"],
        {
            "startup_count",
            "startup_max_seconds",
            "readiness_transition_count",
            "ready_transition_count",
            "hard_transition_count",
            "max_previous_mode_duration_seconds",
            "readiness_ready_seconds",
            "readiness_nonready_seconds",
            "readiness_ratio",
            "readiness_max_nonready_seconds",
            "heartbeat_sample_count",
            "heartbeat_max_gap_seconds",
            "unhealthy_heartbeat_count",
            "shadow_intent_count",
            "shadow_write_audit_sample_count",
            "shadow_write_attempt_event_count",
            "shadow_write_attempt_count",
            "shadow_write_counter_mismatch_count",
        },
        "SLO v2 runtime",
    )
    _exact_keys(
        report["alerts"],
        {
            "sample_count",
            "incident_count",
            "synthetic_challenge_count",
            "synthetic_provider_received_count",
            "attempt_count",
            "ingestion_accepted_count",
            "p0_provider_received_max_seconds",
            "p1_provider_received_max_seconds",
            "provider_failure_count",
            "dlq_count",
            "human_ack_count",
            "escalation_count",
            "unacknowledged_p0_count",
        },
        "SLO v2 alerts",
    )
    _exact_keys(
        report["backups"],
        {
            "sample_count",
            "failure_count",
            "local_max_recovery_point_age_seconds",
            "offsite_max_recovery_point_age_seconds",
            "component_restore_sample_count",
            "component_restore_max_seconds",
        },
        "SLO v2 backups",
    )
    resources = _exact_keys(
        report["resources"],
        {
            "sample_count",
            "identity_mismatch_count",
            "warning_sample_count",
            "breach_sample_count",
            "rss_bytes",
            "fd_count",
            "threads",
            "pids_current",
            "db_bytes",
            "wal_bytes",
            "disk_free_bytes",
            "disk_free_inodes",
            "memory_high_bytes",
            "memory_max_bytes",
            "limit_nofile",
            "tasks_max",
            "max_database_bytes",
            "max_wal_bytes",
            "wal_checkpoint_age_seconds",
            "max_wal_checkpoint_age_seconds",
            "wal_checkpoint_busy",
            "wal_checkpoint_log_frames",
            "wal_checkpointed_frames",
            "wal_checkpoint_backlog_frames",
            "wal_checkpoint_page_size_bytes",
            "wal_checkpoint_backlog_bytes",
            "max_database_growth_bytes_per_day",
            "min_free_bytes",
            "min_free_inodes",
            "oom_kill_count",
            "cpu_nr_throttled",
            "cpu_throttled_usec",
        },
        "SLO v2 resources",
    )
    for field in (
        "rss_bytes",
        "fd_count",
        "threads",
        "pids_current",
        "db_bytes",
        "wal_bytes",
        "disk_free_bytes",
        "disk_free_inodes",
        "memory_high_bytes",
        "memory_max_bytes",
        "limit_nofile",
        "tasks_max",
        "max_database_bytes",
        "max_wal_bytes",
        "wal_checkpoint_age_seconds",
        "max_wal_checkpoint_age_seconds",
        "wal_checkpoint_busy",
        "wal_checkpoint_log_frames",
        "wal_checkpointed_frames",
        "wal_checkpoint_backlog_frames",
        "wal_checkpoint_page_size_bytes",
        "wal_checkpoint_backlog_bytes",
        "max_database_growth_bytes_per_day",
        "min_free_bytes",
        "min_free_inodes",
        "oom_kill_count",
        "cpu_nr_throttled",
        "cpu_throttled_usec",
    ):
        _exact_keys(
            resources[field],
            {"first", "last", "min", "max", "growth"},
            f"SLO v2 resources.{field}",
        )
        for key in ("first", "last", "min", "max"):
            _finite_nonnegative(
                resources[field][key],
                f"SLO v2 resources.{field}.{key}",
            )
        growth = float(resources[field]["growth"])
        if not math.isfinite(growth):
            raise ValueError(f"SLO v2 resources.{field}.growth 非法")
    busy = resources["wal_checkpoint_busy"]
    if any(busy[key] not in {0, 1} for key in ("first", "last", "min", "max")):
        raise ValueError("SLO v2 resources.wal_checkpoint_busy 必须是 0/1")
    if busy["growth"] not in {-1, 0, 1}:
        raise ValueError("SLO v2 resources.wal_checkpoint_busy.growth 非法")
    if (
        resources["sample_count"]
        and resources["wal_checkpoint_page_size_bytes"]["min"] <= 0
    ):
        raise ValueError("SLO v2 WAL page size 必须为正数")
    for key in (
        "sample_count",
        "identity_mismatch_count",
        "warning_sample_count",
        "breach_sample_count",
    ):
        _finite_nonnegative(resources[key], f"SLO v2 resources.{key}")
    _exact_keys(
        report["clock"],
        {"sample_count", "max_absolute_offset_seconds"},
        "SLO v2 clock",
    )
    _exact_keys(
        report["probes"],
        {
            "attempt_count",
            "done_count",
            "failed_count",
            "unknown_count",
            "manual_review_count",
            "duplicate_buy_count",
            "fully_correlated_count",
            "schedule_sample_count",
            "schedule_compliant_count",
            "schedule_violation_count",
            "schedule_sha256",
            "formal_probe_ids",
            "done_probe_ids",
        },
        "SLO v2 probes",
    )
    _exact_keys(
        report["protection"],
        {
            "attempt_count",
            "success_count",
            "failure_count",
            "independent_probe_count",
            "p50_seconds",
            "p95_seconds",
            "p99_seconds",
            "max_seconds",
            "p99_is_gate",
        },
        "SLO v2 protection",
    )
    _exact_keys(
        report["execution_slippage"],
        {
            "attempt_count",
            "sample_count",
            "independent_probe_count",
            "p95_ratio",
            "p99_ratio",
            "max_ratio",
            "model_paired_count",
            "expected_model_ratio",
            "cost_model_hash",
            "residual_sum_ratio",
            "residual_sum_squares_ratio",
            "residual_upper_95_ratio",
            "residual_cluster_count",
            "residual_cluster_ids",
            "cluster_residual_sum_ratio",
            "cluster_residual_sum_squares_ratio",
            "cluster_residual_upper_95_ratio",
        },
        "SLO v2 execution_slippage",
    )
    _exact_keys(
        report["integrity"],
        {"valid", "invalid_event_count", "reason_codes"},
        "SLO v2 integrity",
    )
    if (
        type(report["integrity"]["valid"]) is not bool
        or type(report["integrity"]["invalid_event_count"]) is not int
        or not isinstance(report["integrity"]["reason_codes"], list)
    ):
        raise ValueError("SLO v2 integrity 类型非法")
    numeric_groups = (
        window,
        *channels.values(),
        websocket["recovery"],
        websocket["subscription_ready"],
        *websocket["recovery_by_channel"].values(),
        *websocket["subscription_ready_by_channel"].values(),
        report["reconciliation"],
        report["runtime"],
        report["alerts"],
        report["backups"],
        report["clock"],
        report["probes"],
        report["protection"],
        report["execution_slippage"],
    )
    for group in numeric_groups:
        for key, value in group.items():
            if key in {
                "started_at",
                "ended_at",
                "p99_is_gate",
                "residual_sum_ratio",
                "residual_upper_95_ratio",
                "cluster_residual_sum_ratio",
                "cluster_residual_upper_95_ratio",
                "schedule_sha256",
                "cost_model_hash",
                "formal_probe_ids",
                "done_probe_ids",
                "residual_cluster_ids",
            }:
                continue
            _finite_nonnegative(value, f"SLO v2.{key}")
    probes = report["probes"]
    slippage = report["execution_slippage"]
    for values, label in (
        (probes["formal_probe_ids"], "formal_probe_ids"),
        (probes["done_probe_ids"], "done_probe_ids"),
        (slippage["residual_cluster_ids"], "residual_cluster_ids"),
    ):
        if (
            not isinstance(values, list)
            or values != sorted(set(values))
            or any(
                not re.fullmatch(r"[0-9a-f]{32}", str(value))
                for value in values
            )
        ):
            raise ValueError(f"SLO v2 {label} 必须是有序唯一 probe ID")
    if not math.isclose(
        float(window["actual_observable_seconds"])
        + float(window["unobservable_seconds"]),
        86400,
        abs_tol=1e-6,
    ):
        raise ValueError("SLO v2 observable/unobservable 分母不闭合")
    integer_fields = (
        (window, ("sample_count",)),
        *(
            (
                metrics,
                (
                    "transition_count",
                    "state_sample_count",
                    "generation_count",
                    "disconnect_count",
                ),
            )
            for metrics in channels.values()
        ),
        (
            websocket["recovery"],
            ("sample_count", "orphan_or_unsafe_count"),
        ),
        (
            websocket["subscription_ready"],
            ("sample_count", "invalid_count"),
        ),
        *(
            (metrics, ("sample_count",))
            for metrics in (
                *websocket["recovery_by_channel"].values(),
                *websocket["subscription_ready_by_channel"].values(),
            )
        ),
        (
            report["reconciliation"],
            (
                "expected_count",
                "attempt_count",
                "success_count",
                "failure_count",
                "auto_repaired_count",
                "unresolved_count",
            ),
        ),
        (
            report["runtime"],
            (
                "startup_count",
                "readiness_transition_count",
                "ready_transition_count",
                "hard_transition_count",
                "heartbeat_sample_count",
                "unhealthy_heartbeat_count",
                "shadow_intent_count",
                "shadow_write_audit_sample_count",
                "shadow_write_attempt_event_count",
                "shadow_write_attempt_count",
                "shadow_write_counter_mismatch_count",
            ),
        ),
        (
            report["alerts"],
            (
                "sample_count",
                "incident_count",
                "synthetic_challenge_count",
                "synthetic_provider_received_count",
                "attempt_count",
                "ingestion_accepted_count",
                "provider_failure_count",
                "dlq_count",
                "human_ack_count",
                "escalation_count",
                "unacknowledged_p0_count",
            ),
        ),
        (
            report["backups"],
            (
                "sample_count",
                "failure_count",
                "component_restore_sample_count",
            ),
        ),
        (
            resources,
            (
                "sample_count",
                "identity_mismatch_count",
                "warning_sample_count",
                "breach_sample_count",
            ),
        ),
        (report["clock"], ("sample_count",)),
        (
            report["probes"],
            (
                "attempt_count",
                "done_count",
                "failed_count",
                "unknown_count",
                "manual_review_count",
                "duplicate_buy_count",
                "fully_correlated_count",
                "schedule_sample_count",
                "schedule_compliant_count",
                "schedule_violation_count",
            ),
        ),
        (
            report["protection"],
            (
                "attempt_count",
                "success_count",
                "failure_count",
                "independent_probe_count",
            ),
        ),
        (
            report["execution_slippage"],
            (
                "attempt_count",
                "sample_count",
                "independent_probe_count",
                "model_paired_count",
                "residual_cluster_count",
            ),
        ),
    )
    for group, fields in integer_fields:
        for field in fields:
            if type(group[field]) is not int:
                raise ValueError(f"SLO v2 {field} 必须是整数计数")
    for channel, metrics in channels.items():
        ready = float(metrics["ready_seconds"])
        unavailable = float(metrics["unavailable_seconds"])
        if (
            not math.isclose(ready + unavailable, 86400, abs_tol=1e-6)
            or not math.isclose(
                float(metrics["availability_ratio"]),
                ready / 86400,
                abs_tol=1e-12,
            )
            or float(metrics["max_disconnect_seconds"]) > unavailable + 1e-6
        ):
            raise ValueError(f"SLO v2 websocket.{channel} 分母不闭合")
    runtime = report["runtime"]
    readiness_ready = float(runtime["readiness_ready_seconds"])
    readiness_nonready = float(runtime["readiness_nonready_seconds"])
    if (
        not math.isclose(
            readiness_ready + readiness_nonready,
            86400,
            abs_tol=1e-6,
        )
        or not math.isclose(
            float(runtime["readiness_ratio"]),
            readiness_ready / 86400,
            abs_tol=1e-12,
        )
        or float(runtime["readiness_max_nonready_seconds"])
        > readiness_nonready + 1e-6
    ):
        raise ValueError("SLO v2 runtime readiness 分母不闭合")
    reconciliation = report["reconciliation"]
    if (
        reconciliation["success_count"]
        + reconciliation["failure_count"]
        != reconciliation["attempt_count"]
        or not math.isclose(
            float(reconciliation["success_ratio"]),
            (
                reconciliation["success_count"]
                / reconciliation["attempt_count"]
                if reconciliation["attempt_count"]
                else 0
            ),
            abs_tol=1e-12,
        )
    ):
        raise ValueError("SLO v2 reconciliation 分母不闭合")
    alerts = report["alerts"]
    if (
        alerts["incident_count"] + alerts["synthetic_challenge_count"]
        != alerts["sample_count"]
        or alerts["synthetic_provider_received_count"]
        > alerts["synthetic_challenge_count"]
        or any(
            alerts[field] > alerts["sample_count"]
            for field in (
                "ingestion_accepted_count",
                "provider_failure_count",
                "dlq_count",
                "human_ack_count",
                "escalation_count",
                "unacknowledged_p0_count",
            )
        )
    ):
        raise ValueError("SLO v2 alert 分母不闭合")
    backups = report["backups"]
    if (
        backups["failure_count"] > backups["sample_count"]
        or backups["component_restore_sample_count"]
        > backups["sample_count"]
    ):
        raise ValueError("SLO v2 backup 分母不闭合")
    if (
        probes["done_count"]
        + probes["failed_count"]
        + probes["unknown_count"]
        + probes["manual_review_count"]
        != probes["attempt_count"]
        or probes["fully_correlated_count"] > probes["done_count"]
        or probes["schedule_compliant_count"]
        + probes["schedule_violation_count"]
        != probes["schedule_sample_count"]
        or (
            probes["schedule_sample_count"]
            and not re.fullmatch(
                r"[0-9a-f]{64}",
                str(probes["schedule_sha256"]),
            )
        )
        or len(probes["done_probe_ids"]) != probes["done_count"]
    ):
        raise ValueError("SLO v2 probe 分母不闭合")
    protection = report["protection"]
    if (
        protection["success_count"] + protection["failure_count"]
        != protection["attempt_count"]
        or protection["independent_probe_count"]
        > protection["success_count"]
        or not (
            protection["p50_seconds"]
            <= protection["p95_seconds"]
            <= protection["p99_seconds"]
            <= protection["max_seconds"]
        )
    ):
        raise ValueError("SLO v2 protection 分母/分位数不闭合")
    for key in (
        "residual_sum_ratio",
        "residual_upper_95_ratio",
        "cluster_residual_sum_ratio",
        "cluster_residual_upper_95_ratio",
    ):
        value = slippage[key]
        if isinstance(value, bool) or not math.isfinite(float(value)):
            raise ValueError(f"SLO v2 slippage {key} 必须为有限数")
    if (
        slippage["sample_count"] != slippage["attempt_count"]
        or slippage["independent_probe_count"] > slippage["sample_count"]
            or slippage["model_paired_count"] > slippage["sample_count"]
            or len(slippage["residual_cluster_ids"])
            != slippage["residual_cluster_count"]
            or slippage["residual_cluster_count"]
            > slippage["independent_probe_count"]
            or (
                report["integrity"]["valid"]
                and slippage["residual_cluster_count"]
                != slippage["independent_probe_count"]
            )
        or (
            slippage["cost_model_hash"]
            and not re.fullmatch(
                r"[0-9a-f]{64}",
                str(slippage["cost_model_hash"]),
            )
        )
        or (
            slippage["model_paired_count"] == 0
            and (
                slippage["residual_sum_ratio"] != 0
                or slippage["residual_sum_squares_ratio"] != 0
                or slippage["residual_upper_95_ratio"] != 0
            )
        )
        or not (
            slippage["p95_ratio"]
            <= slippage["p99_ratio"]
            <= slippage["max_ratio"]
        )
    ):
        raise ValueError("SLO v2 slippage 分母/分位数不闭合")
    if (
        report["phase"] == "soak"
        and report["integrity"]["valid"]
        and (
            probes["formal_probe_ids"] != probes["done_probe_ids"]
            or probes["done_probe_ids"]
            != slippage["residual_cluster_ids"]
        )
    ):
        raise ValueError("SLO v2 formal probe/residual lineage 不闭合")
    if (
        report["backups"]["failure_count"]
        > report["backups"]["sample_count"]
        or report["integrity"]["invalid_event_count"]
        != len(set(report["integrity"]["reason_codes"]))
        or report["integrity"]["valid"]
        is bool(report["integrity"]["reason_codes"])
    ):
        raise ValueError("SLO v2 backup/integrity 分母不闭合")
    if (
        report["integrity"]["valid"]
        and (
            window["sample_count"] == 0
            or resources["sample_count"] == 0
            or any(
                metrics["state_sample_count"] == 0
                for metrics in channels.values()
            )
            or report["reconciliation"]["attempt_count"] == 0
            or (
                report["phase"] == "soak"
                and report["probes"]["attempt_count"] == 0
            )
        )
    ):
        raise ValueError("SLO v2 零预期采样不能标记 integrity valid")
    expected_p99_gate = (
        report["protection"]["attempt_count"]
        >= SLO_V2_POLICY["protection_p99_min_samples"]
    )
    if report["protection"]["p99_is_gate"] is not expected_p99_gate:
        raise ValueError("SLO v2 protection p99 gate 样本条件非法")
    return report


def evaluate_slo_v2_day(
    report: dict,
    *,
    max_slippage_ratio: float,
) -> tuple[str, list[str]]:
    """返回 clean/invalid/burn-in 及稳定 reason codes。"""
    validate_slo_v2_report(report)
    reasons = list(report["integrity"]["reason_codes"])
    window = report["window"]
    if window["unobservable_seconds"] > SLO_V2_POLICY["max_unobservable_seconds"]:
        reasons.append("EVIDENCE_UNOBSERVABLE_BUDGET_EXCEEDED")
    if window["max_evidence_gap_seconds"] > SLO_V2_POLICY["max_evidence_gap_seconds"]:
        reasons.append("EVIDENCE_GAP_EXCEEDED")
    for channel, metrics in report["websocket"]["channels"].items():
        if metrics["max_state_sample_gap_seconds"] > SLO_V2_POLICY[
            "websocket_state_sample_max_gap_seconds"
        ]:
            reasons.append(f"WS_STATE_EVIDENCE_GAP:{channel}")
        if metrics["availability_ratio"] < SLO_V2_POLICY[
            "websocket_min_availability_ratio"
        ]:
            reasons.append(f"WS_AVAILABILITY:{channel}")
        if metrics["max_disconnect_seconds"] > SLO_V2_POLICY[
            "websocket_max_disconnect_seconds"
        ]:
            reasons.append(f"WS_DISCONNECT_MAX:{channel}")
    reconciliation = report["reconciliation"]
    if (
        reconciliation["success_ratio"]
        < SLO_V2_POLICY["reconciliation_min_success_ratio"]
    ):
        reasons.append("RECONCILIATION_SUCCESS_RATIO")
    if reconciliation["maximum_completion_gap_seconds"] > SLO_V2_POLICY[
        "reconciliation_max_completion_gap_seconds"
    ]:
        reasons.append("RECONCILIATION_COMPLETION_GAP")
    if reconciliation["unresolved_count"]:
        reasons.append("RECONCILIATION_UNRESOLVED")
    if (
        report["runtime"]["startup_max_seconds"]
        > SLO_V2_POLICY["startup_max_seconds"]
    ):
        reasons.append("STARTUP_RECONCILIATION_SLO")
    if (
        report["runtime"]["readiness_ratio"]
        < SLO_V2_POLICY["runtime_min_readiness_ratio"]
    ):
        reasons.append("RUNTIME_READINESS_AVAILABILITY")
    if (
        report["runtime"]["readiness_max_nonready_seconds"]
        > SLO_V2_POLICY["runtime_max_nonready_seconds"]
    ):
        reasons.append("RUNTIME_READINESS_MAX_NONREADY")
    if report["runtime"]["hard_transition_count"]:
        reasons.append("RUNTIME_HARD_TRANSITION")
    if (
        report["runtime"]["heartbeat_max_gap_seconds"]
        > SLO_V2_POLICY["heartbeat_sample_max_gap_seconds"]
    ):
        reasons.append("RUNTIME_HEARTBEAT_GAP")
    if report["runtime"]["unhealthy_heartbeat_count"]:
        reasons.append("RUNTIME_HEARTBEAT_UNHEALTHY")
    if report["phase"] == "shadow":
        if (
            report["runtime"]["shadow_write_audit_sample_count"]
            != report["runtime"]["heartbeat_sample_count"]
        ):
            reasons.append("SHADOW_WRITE_AUDIT_GAP")
        if report["runtime"]["shadow_write_attempt_count"]:
            reasons.append("SHADOW_WRITE_ENDPOINT_ATTEMPT")
        if report["runtime"]["shadow_write_attempt_event_count"]:
            reasons.append("SHADOW_WRITE_ENDPOINT_ATTEMPT")
        if report["runtime"]["shadow_write_counter_mismatch_count"]:
            reasons.append("SHADOW_WRITE_AUDIT_COUNTER_MISMATCH")
    alerts = report["alerts"]
    if alerts["provider_failure_count"] or alerts["dlq_count"]:
        reasons.append("ALERT_PROVIDER_DELIVERY_FAILURE")
    if (
        alerts["p0_provider_received_max_seconds"]
        > SLO_V2_POLICY["p0_provider_received_seconds"]
    ):
        reasons.append("ALERT_P0_PROVIDER_LATENCY")
    if (
        alerts["p1_provider_received_max_seconds"]
        > SLO_V2_POLICY["p1_provider_received_seconds"]
    ):
        reasons.append("ALERT_P1_PROVIDER_LATENCY")
    if alerts["unacknowledged_p0_count"]:
        reasons.append("ALERT_P0_UNACKNOWLEDGED")
    protection = report["protection"]
    if protection["failure_count"] or (
        protection["attempt_count"]
        and (
            protection["p95_seconds"]
            > SLO_V2_POLICY["protection_p95_seconds"]
            or protection["max_seconds"]
            > SLO_V2_POLICY["protection_max_seconds"]
        )
    ):
        reasons.append("PROTECTION_SLO")
    if report["execution_slippage"]["max_ratio"] > max_slippage_ratio:
        reasons.append("SLIPPAGE_MAX")
    if report["probes"]["duplicate_buy_count"]:
        reasons.append("DUPLICATE_BUY")
    if report["probes"]["schedule_violation_count"]:
        reasons.append("PROBE_SCHEDULE_VIOLATION")
    if report["phase"] == "soak" and (
        report["probes"]["schedule_sample_count"]
        != report["probes"]["attempt_count"]
        or report["probes"]["schedule_compliant_count"]
        != report["probes"]["attempt_count"]
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(report["probes"]["schedule_sha256"]),
        )
    ):
        reasons.append("PROBE_SCHEDULE_NONCOMPLIANT")
    if report["phase"] == "soak" and not (
        SLO_V2_POLICY["probe_minimum_daily_done"]
        <= report["probes"]["done_count"]
        <= SLO_V2_POLICY["probe_maximum_daily_done"]
    ):
        reasons.append("PROBE_DAILY_COUNT")
    if report["phase"] == "soak" and (
        len(report["probes"]["formal_probe_ids"]) != 1
        or report["probes"]["formal_probe_ids"]
        != report["probes"]["done_probe_ids"]
        or report["probes"]["done_probe_ids"]
        != report["execution_slippage"]["residual_cluster_ids"]
    ):
        reasons.append("PROBE_RESIDUAL_LINEAGE_INVALID")
    if report["probes"]["failed_count"]:
        reasons.append("PROBE_FAILURE")
    if (
        report["probes"]["done_count"]
        != report["probes"]["fully_correlated_count"]
    ):
        reasons.append("PROBE_ASSOCIATION_INCOMPLETE")
    if report["probes"]["unknown_count"] or report["probes"]["manual_review_count"]:
        reasons.append("PROBE_UNRESOLVED")
    if report["backups"]["local_max_recovery_point_age_seconds"] > 300:
        reasons.append("LOCAL_BACKUP_RPO")
    if report["backups"]["offsite_max_recovery_point_age_seconds"] > 300:
        reasons.append("OFFSITE_BACKUP_RPO")
    if report["backups"]["failure_count"]:
        reasons.append("BACKUP_VERIFICATION_FAILURE")
    if (
        report["backups"]["component_restore_max_seconds"]
        > SLO_V2_POLICY["backup_component_restore_max_seconds"]
    ):
        reasons.append("BACKUP_COMPONENT_RESTORE")
    if (
        report["clock"]["max_absolute_offset_seconds"]
        > SLO_V2_POLICY["clock_max_absolute_offset_seconds"]
    ):
        reasons.append("CLOCK_SKEW")
    resources = report["resources"]
    if resources["identity_mismatch_count"]:
        reasons.append("RESOURCE_IDENTITY_MISMATCH")
    if resources["breach_sample_count"]:
        reasons.append("RESOURCE_HARD_BREACH")
    if (
        resources["sample_count"]
        and resources["rss_bytes"]["max"]
        >= resources["memory_high_bytes"]["last"] * 0.85
    ):
        reasons.append("RESOURCE_RSS_PAGE")
    if (
        resources["sample_count"]
        and resources["fd_count"]["max"]
        >= resources["limit_nofile"]["last"] * 0.80
    ):
        reasons.append("RESOURCE_FD_PAGE")
    if (
        resources["sample_count"]
        and resources["pids_current"]["max"]
        >= resources["tasks_max"]["last"]
    ):
        reasons.append("RESOURCE_TASKS_MAX")
    if (
        resources["sample_count"]
        and (
            resources["db_bytes"]["max"]
            >= resources["max_database_bytes"]["last"]
            or resources["db_bytes"]["growth"]
            > resources["max_database_growth_bytes_per_day"]["last"]
        )
    ):
        reasons.append("RESOURCE_DATABASE_GROWTH")
    if (
        resources["sample_count"]
        and resources["wal_bytes"]["max"]
        >= resources["max_wal_bytes"]["last"]
    ):
        reasons.append("RESOURCE_WAL_LIMIT")
    if (
        resources["sample_count"]
        and (
            resources["wal_checkpoint_age_seconds"]["max"]
            >= resources["max_wal_checkpoint_age_seconds"]["last"]
            or resources["wal_checkpoint_busy"]["max"] > 0
        )
    ):
        reasons.append("RESOURCE_WAL_CHECKPOINT_STALE")
    if (
        resources["sample_count"]
        and (
            resources["disk_free_bytes"]["min"]
            < resources["min_free_bytes"]["last"]
            or resources["disk_free_inodes"]["min"]
            < resources["min_free_inodes"]["last"]
        )
    ):
        reasons.append("RESOURCE_FILESYSTEM_LOW")
    if resources["oom_kill_count"]["growth"] > 0:
        reasons.append("RESOURCE_OOM_KILL")
    reasons = sorted(set(reasons))
    if report["phase"] != "soak":
        return "burn-in", reasons
    return ("invalid" if reasons else "clean"), reasons
