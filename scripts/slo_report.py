#!/usr/bin/env python3
"""从 durable SQLite facts 生成严格的 Demo/Shadow SLO v2 日报告。"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import date
from pathlib import Path

from okx_quant.ops.slo import build_slo_v2_report


def build_report(
    database: Path,
    day: date,
    *,
    soak_epoch_id: str = "burn-in-unassigned",
    phase: str = "burn-in",
) -> dict:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        # Pin every SELECT in the report to one SQLite read snapshot. Without
        # an explicit transaction, a live WAL writer could make later queries
        # observe a different commit from earlier queries.
        connection.execute("BEGIN")
        report = build_slo_v2_report(
            connection,
            day,
            soak_epoch_id=soak_epoch_id,
            phase=phase,
        )
        connection.execute("COMMIT")
        return report
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--day", required=True, type=date.fromisoformat)
    parser.add_argument("--soak-epoch-id", required=True)
    parser.add_argument(
        "--phase",
        required=True,
        choices=("shadow", "burn-in", "soak", "chaos"),
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = build_report(
        args.database,
        args.day,
        soak_epoch_id=args.soak_epoch_id,
        phase=args.phase,
    )
    if args.output.exists():
        raise ValueError(f"拒绝覆盖既有 SLO 报告: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
