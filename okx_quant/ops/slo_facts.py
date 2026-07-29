"""Canonical raw fact slices used to independently recompute SLO v2."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from okx_quant.application.approval import canonical_bytes
from okx_quant.ops.backup_receipt import validate_backup_slo_sample
from okx_quant.ops.slo import build_slo_v2_report

SLO_FACTS_SCHEMA = "okx-quant.demo-slo-facts/v2"
_EVENT_NAMES = {
    "backup_slo_sample",
    "clock_quality_sample",
    "exchange_fact_consumed",
    "execution_slippage_sample",
    "process_resource_sample",
    "probe_schedule_sample",
    "protection_activation_slo_sample",
    "runtime_heartbeat_sample",
    "runtime_readiness_transition",
    "shadow_order_intent",
    "shadow_write_endpoint_attempt",
    "startup_reconciliation_slo_sample",
    "websocket_liveness_sample",
    "websocket_recovery_completed",
    "websocket_subscription_ready",
    "websocket_state_transition",
}


def _rows(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple = (),
) -> list[dict]:
    cursor = connection.execute(query, parameters)
    names = [item[0] for item in cursor.description]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def export_slo_v2_facts(
    database: str | Path,
    day: date,
) -> dict:
    """Export the complete allowlisted input needed to rebuild one UTC day."""
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    ended = (
        datetime.combine(day, datetime.min.time(), tzinfo=UTC)
        + timedelta(days=1)
    ).timestamp()
    connection = sqlite3.connect(
        f"file:{Path(database)}?mode=ro",
        uri=True,
    )
    try:
        connection.execute("BEGIN")
        placeholders = ",".join("?" for _ in _EVENT_NAMES)
        events = _rows(
            connection,
            f"""
            SELECT event_id, event_name, severity, correlation_id,
                   payload_json, created_at
            FROM system_events
            WHERE event_name IN ({placeholders})
              AND created_at>=? AND created_at<?
            ORDER BY created_at, event_id
            """,
            (*sorted(_EVENT_NAMES), started, ended),
        )
        # Only the last prior WS/readiness states and the latest valid local /
        # offsite restore points can affect this day's initial denominator.
        prior: dict[str, dict] = {}
        for channel in ("public", "private", "business"):
            history = _rows(
                connection,
                """
                SELECT event_id, event_name, severity, correlation_id,
                       payload_json, created_at
                FROM system_events
                WHERE event_name='websocket_state_transition'
                  AND created_at<?
                  AND json_extract(payload_json, '$.channel')=?
                ORDER BY created_at DESC, event_id DESC
                """,
                (started, channel),
            )
            if history:
                prior[f"websocket:{channel}"] = history[0]
                latest_payload = json.loads(history[0]["payload_json"])
                if latest_payload.get("new_state") != "ready":
                    # Preserve the exact first failure fact of an incident
                    # crossing midnight.  Recovery duration is measured from
                    # this timestamp, not from the report-day boundary.
                    failure_started: dict | None = None
                    for row in history:
                        payload = json.loads(row["payload_json"])
                        if payload.get("new_state") in {
                            "backoff",
                            "disconnected",
                            "stale",
                        }:
                            failure_started = row
                        if payload.get("new_state") == "ready":
                            break
                    if (
                        failure_started is not None
                        and failure_started["event_id"]
                        != history[0]["event_id"]
                    ):
                        prior[
                            f"websocket-incident:{channel}"
                        ] = failure_started
        selected_readiness = _rows(
            connection,
            """
            SELECT event_id, event_name, severity, correlation_id,
                   payload_json, created_at
            FROM system_events
            WHERE event_name='runtime_readiness_transition'
              AND created_at<?
            ORDER BY created_at DESC, event_id DESC
            LIMIT 1
            """,
            (started,),
        )
        if selected_readiness:
            prior["runtime:readiness"] = selected_readiness[0]
        prior_backups: dict[str, dict] = {}
        candidates = _rows(
            connection,
            """
            SELECT event_id, event_name, severity, correlation_id,
                   payload_json, created_at
            FROM system_events
            WHERE event_name='backup_slo_sample' AND created_at<?
            ORDER BY created_at DESC, event_id DESC
            """,
            (started,),
        )
        for row in candidates:
            try:
                payload = json.loads(row["payload_json"])
                validate_backup_slo_sample(
                    payload,
                    event_created_at=float(row["created_at"]),
                )
            except (TypeError, ValueError):
                continue
            prior_backups = {"local": row, "offsite": row}
            break
        events = sorted(
            [
                *prior.values(),
                *{
                    row["event_id"]: row
                    for row in prior_backups.values()
                }.values(),
                *events,
            ],
            key=lambda row: (float(row["created_at"]), row["event_id"]),
        )
        facts = {
            "version": 2,
            "schema": SLO_FACTS_SCHEMA,
            "day": day.isoformat(),
            "window": {
                "started_at": datetime.fromtimestamp(
                    started,
                    tz=UTC,
                ).isoformat(),
                "ended_at": datetime.fromtimestamp(
                    ended,
                    tz=UTC,
                ).isoformat(),
            },
            "tables": {
                "system_events": events,
                "reconciliation_runs": _rows(
                    connection,
                    """
                    SELECT run_id, status, mismatch_count, repaired_count,
                           details_json, started_at, completed_at
                    FROM reconciliation_runs
                    WHERE started_at>=? AND started_at<?
                    ORDER BY started_at, run_id
                    """,
                    (started, ended),
                ),
                "alerts": _rows(
                    connection,
                    """
                    SELECT d.event_id, d.priority, d.state,
                           d.attempt_count, d.created_at,
                           d.ingestion_accepted_at,
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
                ),
                "probe_runs": _rows(
                    connection,
                    """
                    SELECT probe_id, state, duplicate_buy_count, created_at
                    FROM probe_runs
                    WHERE created_at>=? AND created_at<?
                    ORDER BY created_at, probe_id
                    """,
                    (started, ended),
                ),
            },
        }
        connection.execute("COMMIT")
        validate_slo_v2_facts(facts)
        return facts
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def validate_slo_v2_facts(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "version",
        "schema",
        "day",
        "window",
        "tables",
    }:
        raise ValueError("SLO facts v2 root schema 非法")
    if value["version"] != 2 or value["schema"] != SLO_FACTS_SCHEMA:
        raise ValueError("SLO facts v2 version/schema 非法")
    day = date.fromisoformat(str(value["day"]))
    window = value["window"]
    if not isinstance(window, dict) or set(window) != {
        "started_at",
        "ended_at",
    }:
        raise ValueError("SLO facts v2 window schema 非法")
    started = datetime.fromisoformat(str(window["started_at"]))
    ended = datetime.fromisoformat(str(window["ended_at"]))
    if (
        started.tzinfo is None
        or ended.tzinfo is None
        or started.astimezone(UTC)
        != datetime.combine(day, datetime.min.time(), tzinfo=UTC)
        or ended - started != timedelta(days=1)
    ):
        raise ValueError("SLO facts v2 window 非完整 UTC 日")
    tables = value["tables"]
    expected = {
        "system_events": {
            "event_id",
            "event_name",
            "severity",
            "correlation_id",
            "payload_json",
            "created_at",
        },
        "reconciliation_runs": {
            "run_id",
            "status",
            "mismatch_count",
            "repaired_count",
            "details_json",
            "started_at",
            "completed_at",
        },
        "alerts": {
            "event_id",
            "priority",
            "state",
            "attempt_count",
            "created_at",
            "ingestion_accepted_at",
            "provider_received_at",
            "human_ack_at",
            "escalation_at",
            "dlq_at",
            "provider_artifact_sha256",
            "human_ack_artifact_sha256",
            "event_name",
        },
        "probe_runs": {
            "probe_id",
            "state",
            "duplicate_buy_count",
            "created_at",
        },
    }
    if not isinstance(tables, dict) or set(tables) != set(expected):
        raise ValueError("SLO facts v2 tables schema 非法")
    for table, keys in expected.items():
        rows = tables[table]
        if (
            not isinstance(rows, list)
            or any(not isinstance(row, dict) or set(row) != keys for row in rows)
        ):
            raise ValueError(f"SLO facts v2 {table} rows 非法")
    for row in tables["system_events"]:
        if row["event_name"] not in _EVENT_NAMES:
            raise ValueError("SLO facts v2 包含非 allowlist event")
        payload = json.loads(row["payload_json"])
        if not isinstance(payload, dict):
            raise ValueError("SLO facts v2 event payload 非对象")
    return value


def report_from_slo_v2_facts(
    facts: object,
    *,
    soak_epoch_id: str,
    phase: str,
) -> dict:
    """Rebuild the exact SLO report without access to the trader database."""
    payload = validate_slo_v2_facts(facts)
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(
            """
            CREATE TABLE system_events(
                event_id TEXT PRIMARY KEY,
                event_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE reconciliation_runs(
                run_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                mismatch_count INTEGER NOT NULL,
                repaired_count INTEGER NOT NULL,
                details_json TEXT NOT NULL,
                started_at REAL NOT NULL,
                completed_at REAL
            );
            CREATE TABLE outbox_events(
                event_id TEXT PRIMARY KEY,
                event_name TEXT NOT NULL
            );
            CREATE TABLE alert_deliveries(
                event_id TEXT PRIMARY KEY,
                priority TEXT NOT NULL,
                state TEXT NOT NULL,
                attempt_count INTEGER NOT NULL,
                created_at REAL NOT NULL,
                ingestion_accepted_at REAL,
                provider_received_at REAL,
                human_ack_at REAL,
                escalation_at REAL,
                dlq_at REAL,
                provider_artifact_sha256 TEXT NOT NULL,
                human_ack_artifact_sha256 TEXT NOT NULL
            );
            CREATE TABLE probe_runs(
                probe_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                duplicate_buy_count INTEGER NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )
        tables = payload["tables"]
        for row in tables["system_events"]:
            connection.execute(
                """
                INSERT INTO system_events VALUES(?,?,?,?,?,?)
                """,
                tuple(row[key] for key in (
                    "event_id",
                    "event_name",
                    "severity",
                    "correlation_id",
                    "payload_json",
                    "created_at",
                )),
            )
        for row in tables["reconciliation_runs"]:
            connection.execute(
                "INSERT INTO reconciliation_runs VALUES(?,?,?,?,?,?,?)",
                tuple(row[key] for key in (
                    "run_id",
                    "status",
                    "mismatch_count",
                    "repaired_count",
                    "details_json",
                    "started_at",
                    "completed_at",
                )),
            )
        for row in tables["alerts"]:
            connection.execute(
                "INSERT INTO outbox_events VALUES(?,?)",
                (row["event_id"], row["event_name"]),
            )
            connection.execute(
                """
                INSERT INTO alert_deliveries
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                tuple(row[key] for key in (
                    "event_id",
                    "priority",
                    "state",
                    "attempt_count",
                    "created_at",
                    "ingestion_accepted_at",
                    "provider_received_at",
                    "human_ack_at",
                    "escalation_at",
                    "dlq_at",
                    "provider_artifact_sha256",
                    "human_ack_artifact_sha256",
                )),
            )
        for row in tables["probe_runs"]:
            connection.execute(
                "INSERT INTO probe_runs VALUES(?,?,?,?)",
                tuple(row[key] for key in (
                    "probe_id",
                    "state",
                    "duplicate_buy_count",
                    "created_at",
                )),
            )
        return build_slo_v2_report(
            connection,
            date.fromisoformat(payload["day"]),
            soak_epoch_id=soak_epoch_id,
            phase=phase,
        )
    finally:
        connection.close()


def verify_daily_slo_components(
    components: dict[str, bytes],
    *,
    identity: dict,
) -> dict:
    """Recompute a daily report from exact-version raw facts."""
    if set(components) != {"slo-facts-v2", "slo-report-v2"}:
        raise RuntimeError(
            "daily bundle 必须且只能包含 raw facts 与派生 SLO report"
        )
    facts = json.loads(components["slo-facts-v2"])
    claimed_report = json.loads(components["slo-report-v2"])
    rebuilt = report_from_slo_v2_facts(
        facts,
        soak_epoch_id=str(identity["soak_epoch_id"]),
        phase=str(identity["phase"]),
    )
    if canonical_bytes(rebuilt) != canonical_bytes(claimed_report):
        raise RuntimeError("daily bundle 的 SLO report 无法由 raw facts 重算")
    return {
        "day": rebuilt["day"],
        "report_sha256": hashlib.sha256(
            components["slo-report-v2"]
        ).hexdigest(),
        "facts_sha256": hashlib.sha256(
            components["slo-facts-v2"]
        ).hexdigest(),
    }
