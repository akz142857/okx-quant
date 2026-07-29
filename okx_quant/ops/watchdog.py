"""独立于交易进程的心跳/仓位安全告警器。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

import requests


def inspect(
    heartbeat: Path,
    database: Path,
    stale_after_s: float,
    *,
    min_free_bytes: int = 1024 * 1024 * 1024,
    min_free_ratio: float = 0.05,
    min_free_inode_ratio: float = 0.05,
) -> dict:
    if (
        min_free_bytes < 0
        or not 0 <= min_free_ratio <= 1
        or not 0 <= min_free_inode_ratio <= 1
    ):
        raise ValueError("watchdog 磁盘阈值非法")
    now = time.time()
    heartbeat_data = {}
    try:
        heartbeat_data = json.loads(heartbeat.read_text(encoding="utf-8"))
        heartbeat_age = now - float(heartbeat_data["timestamp"])
    except Exception:
        heartbeat_age = float("inf")

    mode = "unknown"
    positions: list[dict] = []
    nonterminal_orders: list[dict] = []
    active_reservations: list[dict] = []
    database_error = ""
    if database.exists():
        try:
            connection = sqlite3.connect(
                f"file:{database}?mode=ro", uri=True
            )
            connection.row_factory = sqlite3.Row
            try:
                row = connection.execute(
                    "SELECT value FROM system_state WHERE key='mode'"
                ).fetchone()
                mode = row["value"] if row else "unknown"
                position_rows = connection.execute(
                    """
                    SELECT inst_id, base_qty, protection_status, updated_at
                    FROM positions
                    """
                ).fetchall()
                positions = [
                    dict(row)
                    for row in position_rows
                    if _positive_decimal(row["base_qty"])
                ]
                nonterminal_orders = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT intent_id, inst_id, side, state, updated_at
                        FROM order_intents
                        WHERE state NOT IN ('filled','canceled','rejected')
                        """
                    ).fetchall()
                ]
                active_reservations = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT intent_id, inst_id, reserved_quote, created_at
                        FROM risk_reservations
                        WHERE released_at IS NULL
                        """
                    ).fetchall()
                ]
            finally:
                connection.close()
        except Exception as exc:  # watchdog must remain alive on DB corruption
            database_error = f"{type(exc).__name__}: {exc}"
    else:
        database_error = "database missing"
    disk_error = ""
    free_bytes = 0
    free_ratio = 0.0
    free_inode_ratio = 0.0
    try:
        volume = database.parent
        usage = shutil.disk_usage(volume)
        free_bytes = usage.free
        free_ratio = usage.free / usage.total if usage.total else 0
        vfs = os.statvfs(volume)
        free_inode_ratio = (
            vfs.f_favail / vfs.f_files
            if vfs.f_files
            else 1.0
        )
    except OSError as exc:
        disk_error = f"{type(exc).__name__}: {exc}"
    disk_unsafe = bool(
        disk_error
        or free_bytes < min_free_bytes
        or free_ratio < min_free_ratio
        or free_inode_ratio < min_free_inode_ratio
    )
    heartbeat_fresh = -1 <= heartbeat_age <= stale_after_s
    stale = not heartbeat_fresh
    unhealthy_heartbeat = heartbeat_data.get("healthy") is False
    unsafe_positions = [
        row for row in positions
        if row["protection_status"] not in {"active", "triggered"}
    ]
    stale_with_position = stale and bool(positions)
    stale_with_pending_risk = stale and bool(
        nonterminal_orders or active_reservations
    )
    overdue_unknown_buys = [
        row
        for row in nonterminal_orders
        if row["side"] == "buy"
        and row["state"] in {"unknown", "manual_review"}
        and now - float(row["updated_at"]) > 30
    ]
    return {
        "ok": (
            not database_error
            and not disk_unsafe
            and heartbeat_fresh
            and not stale_with_position
            and not stale_with_pending_risk
            and not unsafe_positions
            and not overdue_unknown_buys
            and not unhealthy_heartbeat
        ),
        "heartbeat_age_seconds": heartbeat_age,
        "heartbeat_fresh": heartbeat_fresh,
        "stale_with_position": stale_with_position,
        "stale_with_pending_risk": stale_with_pending_risk,
        "heartbeat": heartbeat_data,
        "unhealthy_heartbeat": unhealthy_heartbeat,
        "mode": mode,
        "database_error": database_error,
        "disk_error": disk_error,
        "disk_unsafe": disk_unsafe,
        "database_volume_free_bytes": free_bytes,
        "database_volume_free_ratio": free_ratio,
        "database_volume_free_inode_ratio": free_inode_ratio,
        "positions": positions,
        "unsafe_positions": unsafe_positions,
        "nonterminal_orders": nonterminal_orders,
        "active_reservations": active_reservations,
        "overdue_unknown_buys": overdue_unknown_buys,
    }


def send_alert(webhook: str, report: dict) -> None:
    event_id = str(report.get("event_id", ""))
    if not event_id:
        raise RuntimeError("watchdog Page 缺少稳定 event_id")
    response = requests.post(
        webhook,
        json={
            "event_name": "page.external_watchdog",
            "event_id": event_id,
            "payload": report,
        },
        timeout=5,
    )
    response.raise_for_status()


def _incident_fingerprint(report: dict) -> str:
    return json.dumps(
        {
            "heartbeat_stale": not report["heartbeat_fresh"],
            "unhealthy_heartbeat": report["unhealthy_heartbeat"],
            "mode": report["mode"],
            "database_error": report["database_error"],
            "disk_unsafe": report["disk_unsafe"],
            "unsafe_instruments": [
                row["inst_id"] for row in report["unsafe_positions"]
            ],
            "overdue_unknown_buys": [
                row["intent_id"]
                for row in report["overdue_unknown_buys"]
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _load_incident_state(path: Path) -> dict:
    empty = {
        "version": 1,
        "generation": 0,
        "fingerprint": "",
        "event_id": "",
        "delivered": False,
    }
    if not path.exists():
        return empty
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_mode & 0o077:
        raise RuntimeError("watchdog incident state 必须是 owner-only 普通文件")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or set(payload) != set(empty)
        or payload["version"] != 1
        or type(payload["generation"]) is not int
        or payload["generation"] < 0
        or type(payload["delivered"]) is not bool
        or not isinstance(payload["fingerprint"], str)
        or not isinstance(payload["event_id"], str)
    ):
        raise RuntimeError("watchdog incident state schema 非法")
    return payload


def _save_incident_state(path: Path, state: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise RuntimeError("watchdog incident state 父目录不得是符号链接")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(
            descriptor,
            (
                json.dumps(
                    state,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode(),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _advance_incident(
    report: dict,
    state: dict,
    *,
    identity: str,
) -> tuple[dict, bool]:
    if report["ok"]:
        if state["fingerprint"] or state["event_id"]:
            state = {
                **state,
                "fingerprint": "",
                "event_id": "",
                "delivered": False,
            }
        return state, False
    fingerprint = _incident_fingerprint(report)
    if fingerprint != state["fingerprint"]:
        generation = int(state["generation"]) + 1
        event_id = hashlib.sha256(
            (
                "okx-quant/watchdog-incident/v1\0"
                f"{identity}\0{generation}\0{fingerprint}"
            ).encode()
        ).hexdigest()
        state = {
            "version": 1,
            "generation": generation,
            "fingerprint": fingerprint,
            "event_id": event_id,
            "delivered": False,
        }
    return state, not state["delivered"]


def _positive_decimal(value: object) -> bool:
    """精确解析数据库中的 TEXT 数量；损坏值按不安全仓位保守保留。"""
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return True
    return not parsed.is_finite() or parsed > 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--heartbeat", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--webhook", default="")
    parser.add_argument(
        "--webhook-env",
        default="OKX_QUANT_ALERT_WEBHOOK",
    )
    parser.add_argument("--stale-after", type=float, default=20)
    parser.add_argument(
        "--min-free-bytes",
        type=int,
        default=1024 * 1024 * 1024,
    )
    parser.add_argument("--min-free-ratio", type=float, default=0.05)
    parser.add_argument(
        "--min-free-inode-ratio",
        type=float,
        default=0.05,
    )
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--incident-state", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    webhook = args.webhook or os.environ.get(args.webhook_env, "")
    if not webhook:
        raise SystemExit(
            f"缺少 watchdog webhook: --webhook 或环境变量 {args.webhook_env}"
        )

    incident_state = _load_incident_state(args.incident_state)
    incident_identity = hashlib.sha256(
        (
            f"{args.heartbeat.resolve()}\0{args.database.resolve()}"
        ).encode()
    ).hexdigest()
    while True:
        report = inspect(
            args.heartbeat,
            args.database,
            args.stale_after,
            min_free_bytes=args.min_free_bytes,
            min_free_ratio=args.min_free_ratio,
            min_free_inode_ratio=args.min_free_inode_ratio,
        )
        incident_state, should_send = _advance_incident(
            report,
            incident_state,
            identity=incident_identity,
        )
        _save_incident_state(args.incident_state, incident_state)
        if not report["ok"]:
            report["event_id"] = incident_state["event_id"]
            report["incident_generation"] = incident_state[
                "generation"
            ]
        if should_send:
            send_alert(webhook, report)
            incident_state = {
                **incident_state,
                "delivered": True,
            }
            _save_incident_state(args.incident_state, incident_state)
        if args.once:
            print(json.dumps(report, ensure_ascii=False, default=str))
            raise SystemExit(0 if report["ok"] else 2)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
