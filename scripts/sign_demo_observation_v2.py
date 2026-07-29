#!/usr/bin/env python3
"""独立 monitor 对完整 SLO v2 hard metrics 和 immutable source 签名。"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.ops.slo import evaluate_slo_v2_day, validate_slo_v2_report
from okx_quant.research.demo_soak import hard_metrics_from_report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slo-report", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--monitor", required=True)
    parser.add_argument("--previous-hash", required=True)
    parser.add_argument("--source-uri", required=True)
    parser.add_argument("--source-version-id", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--max-slippage", required=True, type=float)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        not args.private_key.is_file()
        or args.private_key.is_symlink()
        or args.private_key.stat().st_mode & 0o077
    ):
        raise SystemExit("observation 私钥必须是 owner-only 普通文件")
    if args.output.exists():
        raise SystemExit(f"拒绝覆盖既有 observation anchor: {args.output}")
    report_bytes = args.slo_report.read_bytes()
    report = validate_slo_v2_report(json.loads(report_bytes))
    status, reasons = evaluate_slo_v2_day(
        report,
        max_slippage_ratio=args.max_slippage,
    )
    claims = {
        "version": 2,
        "action": "anchor-demo-day-v2",
        "day": report["day"],
        "soak_epoch_id": report["soak_epoch_id"],
        "phase": report["phase"],
        "status": status,
        "reason_codes": reasons,
        "previous_hash": args.previous_hash,
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "source_uri": args.source_uri,
        "source_version_id": args.source_version_id,
        "source_sha256": args.source_sha256,
        "hard_metrics": hard_metrics_from_report(report),
        "monitor": args.monitor,
        "issued_at": int(time.time()),
    }
    artifact = sign_ed25519_payload(claims, args.private_key)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
