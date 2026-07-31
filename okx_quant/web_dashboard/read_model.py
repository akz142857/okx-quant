"""Read-only projections used by the local Web Dashboard."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from okx_quant.infrastructure.db.sqlite import LATEST_SCHEMA_VERSION

_OPEN_ORDER_STATES = (
    "created",
    "persisted",
    "submitting",
    "acknowledged",
    "live",
    "partially_filled",
    "unknown",
    "manual_review",
)
_UNSAFE_ORDER_STATES = ("unknown", "manual_review")
_ACTIVE_PROTECTION_STATES = ("active", "triggered")
_SECRET_MARKERS = (
    "api_key",
    "apikey",
    "secret",
    "passphrase",
    "password",
    "authorization",
    "credential",
    "private_key",
    "token",
    "account_id",
    "account_uid",
    "config_hash",
)


def _finite_float(value: object) -> float:
    try:
        parsed = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    return parsed if math.isfinite(parsed) else 0.0


def _parse_json(value: object) -> Any:
    if not isinstance(value, str) or not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return {}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(marker in normalized for marker in _SECRET_MARKERS):
                result[str(key)] = "[REDACTED]"
            else:
                result[str(key)] = _redact(item)
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value[:50]]
    if isinstance(value, str):
        return value[:500]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:500]


def _masked_identity(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


class DashboardReadModel:
    """Short-lived query service that never opens the journal for writes."""

    def __init__(self, database: str | Path):
        requested = Path(database).expanduser()
        if requested.is_symlink():
            raise ValueError("Dashboard 数据源禁止使用符号链接")
        self.database = requested.resolve()
        self._validate_path()
        path_stat = self.database.lstat()
        self._path_identity = (path_stat.st_dev, path_stat.st_ino)

    def _validate_path(self) -> None:
        path_stat = self.database.lstat()
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or self.database.is_symlink()
            or path_stat.st_size <= 0
        ):
            raise ValueError("Dashboard 数据源必须是非空、非符号链接普通文件")
        if (
            hasattr(self, "_path_identity")
            and (path_stat.st_dev, path_stat.st_ino) != self._path_identity
        ):
            raise RuntimeError("Dashboard 数据源 inode 已变化，必须人工重启确认")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._validate_path()
        uri = self.database.as_uri() + "?mode=ro"
        connection = sqlite3.connect(
            uri,
            uri=True,
            timeout=0.5,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA busy_timeout=500")
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
        finally:
            connection.close()

    def validate_schema(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT MAX(version) AS version FROM schema_migrations"
            ).fetchone()
        version = int(row["version"] or 0)
        if version != LATEST_SCHEMA_VERSION:
            raise RuntimeError(
                f"Dashboard 要求 schema v{LATEST_SCHEMA_VERSION}，当前为 v{version}"
            )
        return version

    def overview(self) -> dict[str, Any]:
        now = time.time()
        with self._connection() as connection:
            state_rows = connection.execute(
                "SELECT key, value, updated_at FROM system_state"
            ).fetchall()
            state = {row["key"]: row["value"] for row in state_rows}
            state_updated = max(
                (_finite_float(row["updated_at"]) for row in state_rows),
                default=0,
            )
            identity = connection.execute(
                "SELECT account_id FROM journal_identity WHERE singleton=1"
            ).fetchone()
            snapshot = connection.execute(
                """
                SELECT total_equity_quote, available_quote, holdings_json,
                       source, captured_at
                FROM account_snapshots
                ORDER BY captured_at DESC
                LIMIT 1
                """
            ).fetchone()
            positions = connection.execute(
                """
                SELECT inst_id, base_qty, available_qty, avg_entry_px,
                       realized_pnl, protection_status, updated_at
                FROM positions
                WHERE CAST(base_qty AS REAL) > 0
                ORDER BY inst_id
                """
            ).fetchall()
            order_counts = connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN state IN (
                        'created','persisted','submitting','acknowledged','live',
                        'partially_filled','unknown','manual_review'
                    ) THEN 1 ELSE 0 END) AS open_count,
                    SUM(CASE WHEN state IN ('unknown','manual_review')
                        THEN 1 ELSE 0 END) AS unsafe_count,
                    SUM(CASE WHEN state='rejected' THEN 1 ELSE 0 END)
                        AS rejected_count
                FROM order_intents
                """
            ).fetchone()
            alert_counts = connection.execute(
                """
                SELECT
                    SUM(CASE WHEN priority='P0' AND state != 'acknowledged'
                        THEN 1 ELSE 0 END) AS p0_open,
                    SUM(CASE WHEN priority='P1' AND state != 'acknowledged'
                        THEN 1 ELSE 0 END) AS p1_open
                FROM alert_deliveries
                """
            ).fetchone()
            reconciliation = connection.execute(
                """
                SELECT status, mismatch_count, repaired_count,
                       started_at, completed_at
                FROM reconciliation_runs
                ORDER BY started_at DESC
                LIMIT 1
                """
            ).fetchone()
            equity_rows = connection.execute(
                """
                SELECT total_equity_quote, available_quote, captured_at
                FROM account_snapshots
                ORDER BY captured_at DESC
                LIMIT 240
                """
            ).fetchall()
            latest_event = connection.execute(
                "SELECT MAX(created_at) AS created_at FROM system_events"
            ).fetchone()
            latest_order = connection.execute(
                "SELECT MAX(updated_at) AS updated_at FROM order_intents"
            ).fetchone()

        snapshot_age = (
            max(0.0, now - _finite_float(snapshot["captured_at"]))
            if snapshot
            else None
        )
        unsafe_positions = sum(
            1
            for row in positions
            if str(row["protection_status"]).lower()
            not in _ACTIVE_PROTECTION_STATES
        )
        realized_pnl = sum(_finite_float(row["realized_pnl"]) for row in positions)
        latest_source_at = max(
            state_updated,
            _finite_float(latest_event["created_at"]),
            _finite_float(latest_order["updated_at"]),
            _finite_float(snapshot["captured_at"]) if snapshot else 0,
            max(
                (_finite_float(row["updated_at"]) for row in positions),
                default=0,
            ),
        )
        mode = str(state.get("mode", "unknown")).lower()
        health = "healthy"
        if (
            mode in {"halted", "emergency_exit", "maintenance"}
            or int(order_counts["unsafe_count"] or 0) > 0
            or unsafe_positions > 0
            or int(alert_counts["p0_open"] or 0) > 0
        ):
            health = "critical"
        elif (
            mode in {"starting", "degraded", "unknown"}
            or snapshot_age is None
            or snapshot_age > 120
            or int(alert_counts["p1_open"] or 0) > 0
        ):
            health = "degraded"

        equity_series = [
            {
                "timestamp": _finite_float(row["captured_at"]),
                "equity": _finite_float(row["total_equity_quote"]),
                "available": _finite_float(row["available_quote"]),
            }
            for row in reversed(equity_rows)
        ]
        holdings = _parse_json(snapshot["holdings_json"]) if snapshot else {}
        if not isinstance(holdings, (dict, list)):
            holdings = {}

        return {
            "generated_at": now,
            "database": self.database.name,
            "schema_version": LATEST_SCHEMA_VERSION,
            "data_class": str(
                state.get("dashboard_data_class", "durable_journal")
            ),
            "health": health,
            "mode": mode,
            "mode_reason": str(state.get("mode_reason", ""))[:240],
            "mode_epoch": int(state.get("mode_epoch", 0) or 0),
            "account_fingerprint": _masked_identity(
                str(identity["account_id"]) if identity else ""
            ),
            "source_age_seconds": (
                max(0.0, now - latest_source_at) if latest_source_at else None
            ),
            "account": {
                "equity": _finite_float(snapshot["total_equity_quote"])
                if snapshot
                else 0,
                "available": _finite_float(snapshot["available_quote"])
                if snapshot
                else 0,
                "realized_pnl": realized_pnl,
                "snapshot_age_seconds": snapshot_age,
                "snapshot_source": str(snapshot["source"]) if snapshot else "",
                "holdings_count": len(holdings),
            },
            "risk": {
                "open_positions": len(positions),
                "unprotected_positions": unsafe_positions,
                "open_orders": int(order_counts["open_count"] or 0),
                "unsafe_orders": int(order_counts["unsafe_count"] or 0),
                "rejected_orders": int(order_counts["rejected_count"] or 0),
                "p0_alerts": int(alert_counts["p0_open"] or 0),
                "p1_alerts": int(alert_counts["p1_open"] or 0),
            },
            "reconciliation": (
                {
                    "status": str(reconciliation["status"]),
                    "mismatches": int(reconciliation["mismatch_count"]),
                    "repaired": int(reconciliation["repaired_count"]),
                    "started_at": _finite_float(reconciliation["started_at"]),
                    "completed_at": _finite_float(
                        reconciliation["completed_at"]
                    ),
                }
                if reconciliation
                else None
            ),
            "equity_series": equity_series,
        }

    def positions(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT p.inst_id, p.base_qty, p.available_qty, p.avg_entry_px,
                       p.realized_pnl, p.highest_since_entry,
                       p.protection_status, p.updated_at,
                       po.kind AS protection_kind,
                       po.trigger_px, po.take_profit_px,
                       po.state AS protection_order_state
                FROM positions p
                LEFT JOIN protective_orders po ON po.protection_id = (
                    SELECT protection_id
                    FROM protective_orders
                    WHERE inst_id = p.inst_id
                    ORDER BY updated_at DESC
                    LIMIT 1
                )
                WHERE CAST(p.base_qty AS REAL) > 0
                ORDER BY p.updated_at DESC, p.inst_id
                """
            ).fetchall()
        return [
            {
                "instrument": str(row["inst_id"]),
                "quantity": _finite_float(row["base_qty"]),
                "available_quantity": _finite_float(row["available_qty"]),
                "average_entry_price": _finite_float(row["avg_entry_px"]),
                "realized_pnl": _finite_float(row["realized_pnl"]),
                "highest_since_entry": _finite_float(
                    row["highest_since_entry"]
                ),
                "protection_status": str(row["protection_status"]),
                "protection": {
                    "kind": str(row["protection_kind"] or ""),
                    "state": str(row["protection_order_state"] or ""),
                    "stop_loss": _finite_float(row["trigger_px"]),
                    "take_profit": _finite_float(row["take_profit_px"]),
                },
                "updated_at": _finite_float(row["updated_at"]),
            }
            for row in rows
        ]

    def orders(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 250))
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT intent_id, cl_ord_id, inst_id, side,
                       requested_base_qty, state, exchange_ord_id,
                       exchange_state, acc_fill_qty, avg_fill_px,
                       fee, fee_ccy, source, last_error_code,
                       last_error_message, created_at, updated_at
                FROM order_intents
                ORDER BY updated_at DESC, intent_id DESC
                LIMIT ?
                """,
                (bounded_limit,),
            ).fetchall()
        return [
            {
                "intent_id": str(row["intent_id"]),
                "client_order_id": str(row["cl_ord_id"]),
                "exchange_order_id": str(row["exchange_ord_id"] or ""),
                "instrument": str(row["inst_id"]),
                "side": str(row["side"]),
                "quantity": _finite_float(row["requested_base_qty"]),
                "state": str(row["state"]),
                "exchange_state": str(row["exchange_state"]),
                "filled_quantity": _finite_float(row["acc_fill_qty"]),
                "average_fill_price": _finite_float(row["avg_fill_px"]),
                "fee": _finite_float(row["fee"]),
                "fee_currency": str(row["fee_ccy"]),
                "source": str(row["source"]),
                "error_code": str(row["last_error_code"]),
                "error_message": str(row["last_error_message"])[:240],
                "created_at": _finite_float(row["created_at"]),
                "updated_at": _finite_float(row["updated_at"]),
            }
            for row in rows
        ]

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 250))
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT event_id, event_name, severity, correlation_id,
                       payload_json, created_at
                FROM system_events
                ORDER BY created_at DESC, event_id DESC
                LIMIT ?
                """,
                (bounded_limit,),
            ).fetchall()
        return [
            {
                "event_id": str(row["event_id"]),
                "name": str(row["event_name"]),
                "severity": str(row["severity"]).lower(),
                "correlation_id": str(row["correlation_id"]),
                "payload": _redact(_parse_json(row["payload_json"])),
                "created_at": _finite_float(row["created_at"]),
            }
            for row in rows
        ]
