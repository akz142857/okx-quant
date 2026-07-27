#!/usr/bin/env python3
"""Root-only first activation of an immutable production release."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from pathlib import Path

from okx_quant.research.admission import (
    AdmissionApprovalVerifier,
    DemoObservationLedger,
)

if __package__:
    from scripts.deployment_receipt import (
        build_deployment_receipt,
        validate_deployment_receipt,
    )
    from scripts.launch_manifest import load_launch_manifest
    from scripts.production_gate import _actual_runtime_identity, _evaluate
else:
    from deployment_receipt import (
        build_deployment_receipt,
        validate_deployment_receipt,
    )
    from launch_manifest import load_launch_manifest
    from production_gate import _actual_runtime_identity, _evaluate


def _atomic_write_receipt(path: Path, receipt: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # Receipt contains hashes/identities, not secrets. World-readable and
        # root-owned avoids a root:root group mismatch blocking the trader.
        temporary.chmod(0o644)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--release-commit-file", required=True, type=Path)
    parser.add_argument("--launch-manifest", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--max-slippage", required=True, type=float)
    parser.add_argument("--approved-max-stress-loss", required=True, type=float)
    parser.add_argument("--observation-public-key", required=True, type=Path)
    parser.add_argument("--research-public-key", required=True, type=Path)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--approval-public-key", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("deployment receipt 只能由 root 激活")
    launch = load_launch_manifest(args.launch_manifest)
    identity = _actual_runtime_identity(
        config_path=args.config,
        release_commit_file=args.release_commit_file,
        strategy=launch["strategy"],
        bar=launch["bar"],
        instruments=launch["instruments"],
        interval=float(launch["interval_seconds"]),
        research_public_key=args.research_public_key,
    )
    if args.receipt.exists():
        try:
            validate_deployment_receipt(
                args.receipt,
                identity=identity,
                approval_path=args.approval,
                approval_public_key=args.approval_public_key,
                evidence_path=args.evidence,
            )
            print(f"existing deployment receipt valid: {args.receipt}")
            return 0
        except ValueError:
            pass
    ledger = DemoObservationLedger(
        args.ledger,
        anchor_public_key=args.observation_public_key,
    )
    evidence, result, evidence_sha256, ledger_head_hash = _evaluate(
        ledger=ledger,
        evidence_path=args.evidence,
        max_slippage=args.max_slippage,
        approved_max_stress_loss=args.approved_max_stress_loss,
        config_path=args.config,
        release_commit_file=args.release_commit_file,
        strategy=launch["strategy"],
        bar=launch["bar"],
        instruments=launch["instruments"],
        interval=float(launch["interval_seconds"]),
    )
    if not result["admitted"]:
        raise RuntimeError(f"生产准入门禁未通过: {result['failed']}")
    approval_bytes = args.approval.read_bytes()
    approval = json.loads(approval_bytes)
    claims = AdmissionApprovalVerifier(args.approval_public_key).verify(
        approval,
        evidence=evidence,
        evidence_sha256=evidence_sha256,
        ledger_head_hash=ledger_head_hash,
        approved_max_stress_loss_usdt=args.approved_max_stress_loss,
    )
    receipt = build_deployment_receipt(
        identity=identity,
        approval_claims=claims,
        approval_bytes=approval_bytes,
        evidence_sha256=evidence_sha256,
        ledger_head_hash=ledger_head_hash,
        activated_at=int(time.time()),
    )
    _atomic_write_receipt(args.receipt, receipt)
    print(f"activated deployment receipt: {args.receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
