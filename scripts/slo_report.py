#!/usr/bin/env python3
"""从 durable system_events 生成不可手填的运行 SLO 日报告。"""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path


def _quantile(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("没有可用于分位数计算的样本")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def _samples(
    connection: sqlite3.Connection,
    event_name: str,
    field: str,
    *,
    started_at: float,
    ended_at: float,
) -> list[float]:
    rows = connection.execute(
        """
        SELECT payload_json
        FROM system_events
        WHERE event_name=? AND created_at>=? AND created_at<?
        ORDER BY created_at, event_id
        """,
        (event_name, started_at, ended_at),
    ).fetchall()
    values = []
    for (payload_json,) in rows:
        try:
            value = float(json.loads(payload_json)[field])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"{event_name}.{field} 含损坏样本"
            ) from exc
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{event_name}.{field} 必须为有限非负数")
        values.append(value)
    return values


def build_report(database: Path, day: date) -> dict:
    started = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
    ended = started + timedelta(days=1)
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        protection = _samples(
            connection,
            "protection_activation_slo_sample",
            "latency_seconds",
            started_at=started.timestamp(),
            ended_at=ended.timestamp(),
        )
        startup = _samples(
            connection,
            "startup_reconciliation_slo_sample",
            "duration_seconds",
            started_at=started.timestamp(),
            ended_at=ended.timestamp(),
        )
        slippage = _samples(
            connection,
            "execution_slippage_sample",
            "adverse_slippage_ratio",
            started_at=started.timestamp(),
            ended_at=ended.timestamp(),
        )
        reconciliation_rows = connection.execute(
            """
            SELECT status, details_json
            FROM reconciliation_runs
            WHERE completed_at>=? AND completed_at<?
            ORDER BY completed_at, run_id
            """,
            (started.timestamp(), ended.timestamp()),
        ).fetchall()
    finally:
        connection.close()
    unexplained = 0
    for status, details_json in reconciliation_rows:
        try:
            details = json.loads(details_json)
            unresolved = details.get("unresolved", [])
        except (AttributeError, json.JSONDecodeError) as exc:
            raise ValueError("reconciliation details 含损坏样本") from exc
        if not isinstance(unresolved, list):
            raise ValueError("reconciliation unresolved 必须是数组")
        unexplained += len(unresolved)
        if status == "failed":
            unexplained += 1
    return {
        "version": 1,
        "day": day.isoformat(),
        "window_started_at": started.isoformat(),
        "window_ended_at": ended.isoformat(),
        "protection_activation": {
            "sample_count": len(protection),
            "p50_seconds": (
                _quantile(protection, 0.50) if protection else 0
            ),
            "p95_seconds": (
                _quantile(protection, 0.95) if protection else 0
            ),
            "p99_seconds": (
                _quantile(protection, 0.99) if protection else 0
            ),
            "max_seconds": max(protection, default=0),
            "p95_within_3_seconds": (
                not protection or _quantile(protection, 0.95) <= 3
            ),
            "p99_within_10_seconds": (
                not protection or _quantile(protection, 0.99) <= 10
            ),
        },
        "startup_reconciliation": {
            "sample_count": len(startup),
            "max_seconds": max(startup, default=0),
            "all_within_60_seconds": all(value <= 60 for value in startup),
        },
        "execution_slippage": {
            "sample_count": len(slippage),
            "p99_ratio": (
                _quantile(slippage, 0.99) if slippage else 0
            ),
            "max_ratio": max(slippage, default=0),
        },
        "reconciliation": {
            "run_count": len(reconciliation_rows),
            "unexplained_mismatches": unexplained,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--day", required=True, type=date.fromisoformat)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = build_report(args.database, args.day)
    if args.output.exists():
        raise ValueError(f"拒绝覆盖既有 SLO 报告: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
