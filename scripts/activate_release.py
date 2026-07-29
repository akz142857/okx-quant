#!/usr/bin/env python3
"""Root-only first activation of an immutable production release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from okx_quant.application.approval import canonical_bytes
from okx_quant.research.admission import (
    NOT_APPLICABLE_CANARY_READINESS_SHA256,
    AdmissionApprovalVerifier,
)
from okx_quant.research.canary import (
    DEFAULT_CANARY_CAPABILITY_REPLAY_STATE,
    consume_canary_capability_reservation,
)
from okx_quant.research.demo_soak import (
    DemoObservationLedgerV2,
    verify_dual_signed_soak_epoch,
)

if __package__:
    from scripts.deployment_receipt import (
        build_deployment_receipt,
        validate_deployment_receipt,
    )
    from scripts.launch_manifest import load_launch_manifest
    from scripts.production_gate import (
        _actual_runtime_identity,
        _evaluate,
    )
    from scripts.production_gate import (
        _aware_datetime as production_gate_aware_datetime,
    )
else:
    from deployment_receipt import (
        build_deployment_receipt,
        validate_deployment_receipt,
    )
    from launch_manifest import load_launch_manifest
    from production_gate import (
        _actual_runtime_identity,
        _evaluate,
    )
    from production_gate import (
        _aware_datetime as production_gate_aware_datetime,
    )


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
    parser.add_argument("--soak-epoch", required=True, type=Path)
    parser.add_argument(
        "--epoch-monitor-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--epoch-risk-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument("--research-public-key", required=True, type=Path)
    parser.add_argument(
        "--bundle-signing-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--independent-verifier-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--stage-c-raw-observer-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--stage-c-trust-manifest",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--independent-verifier-attestations-dir",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--stage-c-drill-receipts-dir",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--stage-c-drill-manifests-dir",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--stage-c-drill-bundle-receipts-dir",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--stage-c-drill-independent-attestations-dir",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--stage-c-release-frozen-at",
        required=True,
        type=str,
    )
    parser.add_argument(
        "--empty-host-restore-evidence",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--empty-host-restore-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--empty-host-restore-key-id",
        required=True,
    )
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
    epoch_artifact = json.loads(
        args.soak_epoch.read_text(encoding="utf-8")
    )
    epoch = verify_dual_signed_soak_epoch(
        epoch_artifact,
        monitor_public_key=args.epoch_monitor_public_key,
        risk_public_key=args.epoch_risk_public_key,
    )
    ledger = DemoObservationLedgerV2(
        args.ledger,
        epoch_payload=epoch,
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
        research_public_key=args.research_public_key,
        bundle_signing_public_key=args.bundle_signing_public_key,
        stage_c_raw_observer_public_key=(
            args.stage_c_raw_observer_public_key
        ),
        stage_c_trust_manifest=args.stage_c_trust_manifest,
        independent_verifier_public_key=(
            args.independent_verifier_public_key
        ),
        independent_verifier_attestations_dir=(
            args.independent_verifier_attestations_dir
        ),
        stage_c_drill_receipts_dir=args.stage_c_drill_receipts_dir,
        stage_c_drill_manifests_dir=args.stage_c_drill_manifests_dir,
        stage_c_drill_bundle_receipts_dir=(
            args.stage_c_drill_bundle_receipts_dir
        ),
        stage_c_drill_independent_attestations_dir=(
            args.stage_c_drill_independent_attestations_dir
        ),
        stage_c_release_frozen_at=production_gate_aware_datetime(
            args.stage_c_release_frozen_at
        ),
        empty_host_restore_evidence=args.empty_host_restore_evidence,
        empty_host_restore_public_key=(
            args.empty_host_restore_public_key
        ),
        empty_host_restore_key_id=args.empty_host_restore_key_id,
        canary_reservation_mode="assert-reserved",
    )
    if not result["admitted"]:
        raise RuntimeError(f"生产准入门禁未通过: {result['failed']}")
    approval_bytes = args.approval.read_bytes()
    approval = json.loads(approval_bytes)
    stage_c_coverage_sha256 = hashlib.sha256(
        canonical_bytes(result["stage_c_drill_coverage"])
    ).hexdigest()
    claims = AdmissionApprovalVerifier(args.approval_public_key).verify(
        approval,
        evidence=evidence,
        evidence_sha256=evidence_sha256,
        ledger_head_hash=ledger_head_hash,
        empty_host_restore_sha256=result[
            "empty_host_restore"
        ]["artifact_sha256"],
        stage_c_coverage_sha256=stage_c_coverage_sha256,
        canary_readiness_sha256=result[
            "canary_producer_capability"
        ]["artifact_sha256"],
        approved_max_stress_loss_usdt=args.approved_max_stress_loss,
    )
    receipt = build_deployment_receipt(
        identity=identity,
        approval_claims=claims,
        approval_bytes=approval_bytes,
        evidence_sha256=evidence_sha256,
        ledger_head_hash=ledger_head_hash,
        empty_host_restore_sha256=result[
            "empty_host_restore"
        ]["artifact_sha256"],
        stage_c_coverage=result["stage_c_drill_coverage"],
        canary_readiness_sha256=result[
            "canary_producer_capability"
        ]["artifact_sha256"],
        activated_at=int(time.time()),
    )
    if (
        receipt["canary_readiness_sha256"]
        != NOT_APPLICABLE_CANARY_READINESS_SHA256
    ):
        consume_canary_capability_reservation(
            DEFAULT_CANARY_CAPABILITY_REPLAY_STATE,
            bundle_sha256=receipt["canary_readiness_sha256"],
            approval_sha256=receipt["approval_sha256"],
            consumed_at=receipt["activated_at"],
        )
    _atomic_write_receipt(args.receipt, receipt)
    print(f"activated deployment receipt: {args.receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
