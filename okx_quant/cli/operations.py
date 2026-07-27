"""生产运维命令：状态、审计、halt、flatten 与在线备份。"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from okx_quant.domain.orders import SystemMode
from okx_quant.infrastructure.db import JournalRepository


def status(journal: JournalRepository) -> dict:
    snapshot = journal.latest_account_snapshot()
    return {
        "mode": journal.get_mode().value,
        "database_integrity": journal.integrity_check(),
        "latest_account_snapshot_at": (
            snapshot["captured_at"] if snapshot else None
        ),
        "positions": journal.list_positions(),
        "nonterminal_orders": [
            {
                "intent_id": item.intent_id,
                "cl_ord_id": item.cl_ord_id,
                "inst_id": item.inst_id,
                "side": item.side,
                "state": item.state.value,
                "acc_fill_qty": str(item.acc_fill_qty),
            }
            for item in journal.list_nonterminal_intents()
        ],
        "active_protections": [
            {
                "protection_id": item.protection_id,
                "inst_id": item.inst_id,
                "algo_id": item.exchange_algo_id,
                "state": item.state.value,
                "protected_qty": str(item.protected_qty),
            }
            for item in journal.list_protections(active_only=True)
        ],
        "unpublished_alerts": len(journal.get_unpublished_outbox()),
    }


def halt_entries(
    journal: JournalRepository,
    *,
    actor: str,
    timeout_s: float = 30,
) -> dict:
    """先同步锁存 HALTED，再由运行时单写者完成控制命令审计。"""
    journal.set_mode(SystemMode.HALTED)
    journal.record_event(
        "halt_requested",
        severity="critical",
        payload={"actor": actor},
    )
    return enqueue_and_wait(
        journal,
        "halt-entries",
        {"actor": actor},
        timeout_s=timeout_s,
    )


def enqueue_and_wait(
    journal: JournalRepository,
    command_type: str,
    payload: dict,
    *,
    timeout_s: float,
    command_id: str | None = None,
) -> dict:
    command_id = journal.enqueue_control_command(
        command_type,
        payload,
        command_id=command_id,
    )
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        command = journal.get_control_command(command_id)
        if command and command["status"] in {"completed", "failed"}:
            return command
        time.sleep(0.25)
    return {
        "command_id": command_id,
        "status": "pending",
        "result": {
            "message": "交易进程尚未确认命令；命令已持久化，将在运行时处理"
        },
    }


def backup_now(journal: JournalRepository, backup_dir: str | Path) -> Path:
    destination_dir = Path(backup_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / (
        time.strftime("trading-%Y%m%dT%H%M%SZ", time.gmtime()) + ".db"
    )
    journal.backup(destination)
    verify = sqlite3.connect(f"file:{destination}?mode=ro", uri=True)
    try:
        row = verify.execute("PRAGMA integrity_check").fetchone()
        if not row or row[0] != "ok":
            raise RuntimeError("备份 integrity_check 失败")
    finally:
        verify.close()
    journal.record_event(
        "online_backup_verified",
        payload={"destination": str(destination)},
    )
    return destination


def render_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)
