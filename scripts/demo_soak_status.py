#!/usr/bin/env python3
"""复核单日 SLO v2 或正式 epoch ledger 的当前状态。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from okx_quant.ops.slo import evaluate_slo_v2_day, validate_slo_v2_report
from okx_quant.research.demo_soak import DemoObservationLedgerV2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--epoch-payload", type=Path)
    parser.add_argument("--observation-public-key", type=Path)
    parser.add_argument("--max-slippage", required=True, type=float)
    args = parser.parse_args()
    if (args.report is None) == (args.ledger is None):
        raise SystemExit("必须且只能提供 --report 或 --ledger")
    if args.report is not None:
        report = validate_slo_v2_report(
            json.loads(args.report.read_text(encoding="utf-8"))
        )
        status, reasons = evaluate_slo_v2_day(
            report,
            max_slippage_ratio=args.max_slippage,
        )
        result = {
            "day": report["day"],
            "phase": report["phase"],
            "status": status,
            "reason_codes": reasons,
        }
    else:
        if args.epoch_payload is None or args.observation_public_key is None:
            raise SystemExit(
                "--ledger 必须提供 --epoch-payload 和 "
                "--observation-public-key"
            )
        epoch = json.loads(
            args.epoch_payload.read_text(encoding="utf-8")
        )
        ledger = DemoObservationLedgerV2(
            args.ledger,
            epoch_payload=epoch,
            anchor_public_key=args.observation_public_key,
        )
        rows = ledger.load()
        result = {
            "soak_epoch_id": epoch["soak_epoch_id"],
            "row_count": len(rows),
            "head_hash": rows[-1]["entry_hash"] if rows else "GENESIS",
            "latest": rows[-1] if rows else None,
        }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status", "clean") != "invalid" else 2


if __name__ == "__main__":
    raise SystemExit(main())
