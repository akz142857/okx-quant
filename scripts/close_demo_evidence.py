#!/usr/bin/env python3
"""Close one UTC Demo day into immutable evidence and the v2 ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import time
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from okx_quant.config import load_yaml
from okx_quant.infrastructure.evidence import (
    redacted_config_hash,
    sign_ed25519_payload,
)
from okx_quant.infrastructure.immutable_bundle import (
    build_bundle_manifest,
    build_bundle_receipt,
    put_locked_object,
    scan_json_evidence,
    sign_bundle_manifest,
    verify_locked_object,
)
from okx_quant.ops.demo_preflight import DemoDeploymentProfile
from okx_quant.ops.slo import (
    SLO_V2_POLICY,
    evaluate_slo_v2_day,
    validate_slo_v2_report,
)
from okx_quant.ops.slo_facts import (
    export_slo_v2_facts,
    report_from_slo_v2_facts,
)
from okx_quant.research.demo_soak import (
    DemoObservationLedgerV2,
    hard_metrics_from_report,
    verify_dual_signed_soak_epoch,
)


def _exclusive_json(path: Path, value: object) -> bytes:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"拒绝覆盖既有证据: {path}")
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode()
    scan_json_evidence(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return payload


def _durable_replace(source: Path, destination: Path) -> None:
    os.replace(source, destination)
    directory = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _s3(prefix: str, *parts: str) -> str:
    if not prefix.startswith("s3://"):
        raise ValueError("evidence offsite URI 必须是 s3://")
    return prefix.rstrip("/") + "/" + "/".join(
        part.strip("/") for part in parts
    )


def _private_key(path: Path) -> None:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size <= 0
        or path.stat().st_mode & 0o077
    ):
        raise RuntimeError("monitor private key 必须是 owner-only 普通文件")


def _anchor(
    *,
    report: dict,
    report_bytes: bytes,
    private_key: Path,
    monitor: str,
    previous_hash: str,
    source_uri: str,
    source_version_id: str,
    source_sha256: str,
    max_slippage: float,
) -> tuple[dict, str, list[str]]:
    status, reasons = evaluate_slo_v2_day(
        report,
        max_slippage_ratio=max_slippage,
    )
    claims = {
        "version": 2,
        "action": "anchor-demo-day-v2",
        "day": report["day"],
        "soak_epoch_id": report["soak_epoch_id"],
        "phase": report["phase"],
        "status": status,
        "reason_codes": reasons,
        "previous_hash": previous_hash,
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "source_uri": source_uri,
        "source_version_id": source_version_id,
        "source_sha256": source_sha256,
        "hard_metrics": hard_metrics_from_report(report),
        "monitor": monitor,
        "issued_at": int(time.time()),
    }
    return sign_ed25519_payload(claims, private_key), status, reasons


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--epoch", required=True, type=Path)
    parser.add_argument("--epoch-monitor-public-key", required=True, type=Path)
    parser.add_argument("--epoch-risk-public-key", required=True, type=Path)
    parser.add_argument("--monitor-public-key", required=True, type=Path)
    parser.add_argument(
        "--phase",
        required=True,
        choices=("shadow", "burn-in", "soak", "chaos"),
    )
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--monitor-private-key", required=True, type=Path)
    parser.add_argument("--monitor-key-id", required=True)
    parser.add_argument("--offsite-uri", required=True)
    parser.add_argument("--kms-key-id", required=True)
    parser.add_argument("--retention-days", type=int, default=400)
    parser.add_argument("--max-slippage", required=True, type=float)
    parser.add_argument("--day", type=date.fromisoformat)
    args = parser.parse_args()
    if args.retention_days < 365:
        raise RuntimeError("Demo daily evidence retention 不能少于 365 天")
    if not 0 <= args.max_slippage <= 1:
        raise RuntimeError("max slippage 必须位于 [0,1]")
    _private_key(args.monitor_private_key)
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    if policy != SLO_V2_POLICY:
        raise RuntimeError("日结 policy 与代码内冻结 SLO v2 policy 不一致")
    cfg = load_yaml(args.config)
    profile = DemoDeploymentProfile.from_config(cfg)
    epoch_artifact = json.loads(args.epoch.read_text(encoding="utf-8"))
    epoch = verify_dual_signed_soak_epoch(
        epoch_artifact,
        monitor_public_key=args.epoch_monitor_public_key,
        risk_public_key=args.epoch_risk_public_key,
    )
    observed_day = args.day or (datetime.now(UTC).date() - timedelta(days=1))
    day_started = datetime.combine(
        observed_day,
        datetime.min.time(),
        tzinfo=UTC,
    )
    if datetime.fromisoformat(epoch["started_at"]).astimezone(UTC) > day_started:
        raise RuntimeError("soak epoch 未覆盖完整 UTC 日，拒绝日结")
    deployment = epoch["deployment_identity"]
    release = epoch["release_identity"]
    revision_file = profile.release_root / "REVISION"
    revision = (
        revision_file.read_text(encoding="utf-8").strip().lower()
        if revision_file.is_file()
        else ""
    )
    if (
        deployment["account_uid"] != profile.account_uid
        or deployment["unit"] != profile.unit_name
        or deployment["environment"] != "demo"
        or deployment["config_sha256"] != redacted_config_hash(cfg)
        or revision != release["git_commit"]
    ):
        raise RuntimeError("当前 deployment/release 与双签 soak epoch 不一致")

    final_day_dir = args.output_dir / observed_day.isoformat()
    if final_day_dir.exists() or final_day_dir.is_symlink():
        raise RuntimeError(f"拒绝重复关闭 UTC 日: {observed_day}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    retain_until = datetime.now(UTC).replace(
        microsecond=0
    ) + timedelta(days=args.retention_days)
    ledger_path = args.output_dir / "soak-ledger-v2.json"
    ledger = DemoObservationLedgerV2(
        ledger_path,
        epoch_payload=epoch,
        anchor_public_key=args.monitor_public_key,
    )
    existing_rows = ledger.load()
    if (
        existing_rows
        and existing_rows[-1]["day"] == observed_day.isoformat()
    ):
        recovery_dirs = sorted(
            path
            for path in args.output_dir.glob(
                f".closing-{observed_day}-*"
            )
            if path.is_dir() and not path.is_symlink()
        )
        if len(recovery_dirs) != 1:
            raise RuntimeError(
                "ledger 已提交但本地日目录未完成，且恢复目录不唯一"
            )
        recovery_dir = recovery_dirs[0]
        publication = json.loads(
            (recovery_dir / "remote-publication.json").read_text(
                encoding="utf-8"
            )
        )
        row = existing_rows[-1]
        report_bytes = (
            recovery_dir / "slo-report-v2.json"
        ).read_bytes()
        anchor_artifact = json.loads(
            (recovery_dir / "observation-anchor-v2.json").read_text(
                encoding="utf-8"
            )
        )
        if (
            hashlib.sha256(report_bytes).hexdigest()
            != row["report_sha256"]
            or publication["manifest_uri"] != row["source_uri"]
            or publication["manifest_version_id"]
            != row["source_version_id"]
            or anchor_artifact != row["anchor"]
        ):
            raise RuntimeError("ledger crash-recovery 本地/远端身份不一致")
        _exclusive_json(
            recovery_dir / "closure.json",
            {
                "version": 1,
                "action": "close-demo-utc-day",
                "day": observed_day.isoformat(),
                "status": row["status"],
                "reason_codes": row["reason_codes"],
                "bundle_id": publication["bundle_id"],
                "manifest_uri": publication["manifest_uri"],
                "manifest_version_id": publication["manifest_version_id"],
                "anchor_uri": publication["anchor_uri"],
                "anchor_version_id": publication["anchor_version_id"],
                "ledger_entry_hash": row["entry_hash"],
                "closed_at": datetime.now(UTC).isoformat(),
            },
        )
        _durable_replace(recovery_dir, final_day_dir)
        print(final_day_dir)
        return 0 if row["status"] in {"clean", "burn-in"} else 2
    previous_hash = (
        existing_rows[-1]["entry_hash"] if existing_rows else "GENESIS"
    )
    temporary_root = Path(tempfile.mkdtemp(
        prefix=f".closing-{observed_day}-",
        dir=args.output_dir,
    ))
    ledger_committed = False
    try:
        facts = export_slo_v2_facts(
            profile.state_dir / "trading.db",
            observed_day,
        )
        report = validate_slo_v2_report(report_from_slo_v2_facts(
            facts,
            soak_epoch_id=epoch["soak_epoch_id"],
            phase=args.phase,
        ))
        facts_path = temporary_root / "slo-facts-v2.json"
        facts_bytes = _exclusive_json(facts_path, facts)
        report_path = temporary_root / "slo-report-v2.json"
        report_bytes = _exclusive_json(report_path, report)
        bundle_id = uuid.uuid4().hex
        report_uri = _s3(
            args.offsite_uri,
            epoch["soak_epoch_id"],
            observed_day.isoformat(),
            bundle_id,
            "slo-report-v2.json",
        )
        report_version_id = put_locked_object(
            source=report_path,
            object_uri=report_uri,
            retain_until=retain_until,
            kms_key_id=args.kms_key_id,
        )
        report_sha256 = hashlib.sha256(report_bytes).hexdigest()
        verify_locked_object(
            object_uri=report_uri,
            version_id=report_version_id,
            expected_sha256=report_sha256,
            expected_bytes=len(report_bytes),
            minimum_retain_until=retain_until,
            expected_kms_key_id=args.kms_key_id,
        )
        facts_uri = _s3(
            args.offsite_uri,
            epoch["soak_epoch_id"],
            observed_day.isoformat(),
            bundle_id,
            "slo-facts-v2.json",
        )
        facts_version_id = put_locked_object(
            source=facts_path,
            object_uri=facts_uri,
            retain_until=retain_until,
            kms_key_id=args.kms_key_id,
        )
        verify_locked_object(
            object_uri=facts_uri,
            version_id=facts_version_id,
            expected_sha256=hashlib.sha256(facts_bytes).hexdigest(),
            expected_bytes=len(facts_bytes),
            minimum_retain_until=retain_until,
            expected_kms_key_id=args.kms_key_id,
        )
        identity = {
            "git_commit": release["git_commit"],
            "config_sha256": deployment["config_sha256"],
            "account_uid": deployment["account_uid"],
            "environment": "demo",
            "unit": deployment["unit"],
            "soak_epoch_id": epoch["soak_epoch_id"],
            "phase": args.phase,
        }
        _exclusive_json(temporary_root / "identity.json", identity)
        manifest = build_bundle_manifest(
            bundle_id=bundle_id,
            kind="daily",
            identity=identity,
            components={
                "slo-report-v2": (
                    report_bytes,
                    report_uri,
                    report_version_id,
                ),
                "slo-facts-v2": (
                    facts_bytes,
                    facts_uri,
                    facts_version_id,
                ),
            },
            retain_until=retain_until,
            signing_key_id=args.monitor_key_id,
            created_at=datetime.now(UTC),
        )
        manifest_artifact = sign_bundle_manifest(
            manifest,
            args.monitor_private_key,
        )
        manifest_path = temporary_root / "bundle-manifest.json"
        manifest_bytes = _exclusive_json(
            manifest_path,
            manifest_artifact,
        )
        manifest_uri = _s3(
            args.offsite_uri,
            epoch["soak_epoch_id"],
            observed_day.isoformat(),
            bundle_id,
            "manifest.json",
        )
        manifest_version_id = put_locked_object(
            source=manifest_path,
            object_uri=manifest_uri,
            retain_until=retain_until,
            kms_key_id=args.kms_key_id,
        )
        verify_locked_object(
            object_uri=manifest_uri,
            version_id=manifest_version_id,
            expected_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            expected_bytes=len(manifest_bytes),
            minimum_retain_until=retain_until,
            expected_kms_key_id=args.kms_key_id,
        )
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        _exclusive_json(
            temporary_root / "bundle-receipt.json",
            build_bundle_receipt(
                manifest_uri=manifest_uri,
                manifest_version_id=manifest_version_id,
                manifest_bytes=manifest_bytes,
                verified_at=datetime.now(UTC),
            ),
        )
        anchor_artifact, status, reasons = _anchor(
            report=report,
            report_bytes=report_bytes,
            private_key=args.monitor_private_key,
            monitor=args.monitor_key_id,
            previous_hash=previous_hash,
            source_uri=manifest_uri,
            source_version_id=manifest_version_id,
            source_sha256=manifest_sha256,
            max_slippage=args.max_slippage,
        )
        anchor_path = temporary_root / "observation-anchor-v2.json"
        anchor_bytes = _exclusive_json(anchor_path, anchor_artifact)
        anchor_uri = _s3(
            args.offsite_uri,
            epoch["soak_epoch_id"],
            observed_day.isoformat(),
            bundle_id,
            "observation-anchor-v2.json",
        )
        anchor_version_id = put_locked_object(
            source=anchor_path,
            object_uri=anchor_uri,
            retain_until=retain_until,
            kms_key_id=args.kms_key_id,
        )
        verify_locked_object(
            object_uri=anchor_uri,
            version_id=anchor_version_id,
            expected_sha256=hashlib.sha256(anchor_bytes).hexdigest(),
            expected_bytes=len(anchor_bytes),
            minimum_retain_until=retain_until,
            expected_kms_key_id=args.kms_key_id,
        )
        _exclusive_json(
            temporary_root / "remote-publication.json",
            {
                "version": 1,
                "action": "record-demo-day-remote-publication",
                "bundle_id": bundle_id,
                "report_uri": report_uri,
                "report_version_id": report_version_id,
                "facts_uri": facts_uri,
                "facts_version_id": facts_version_id,
                "manifest_uri": manifest_uri,
                "manifest_version_id": manifest_version_id,
                "anchor_uri": anchor_uri,
                "anchor_version_id": anchor_version_id,
                "retain_until": retain_until.isoformat(),
                "kms_key_id": args.kms_key_id,
            },
        )
        row = ledger.append_report(
            report=report,
            report_bytes=report_bytes,
            source_uri=manifest_uri,
            source_version_id=manifest_version_id,
            source_sha256=manifest_sha256,
            anchor=anchor_artifact,
            max_slippage_ratio=args.max_slippage,
        )
        ledger_committed = True
        _exclusive_json(
            temporary_root / "closure.json",
            {
                "version": 1,
                "action": "close-demo-utc-day",
                "day": observed_day.isoformat(),
                "status": status,
                "reason_codes": reasons,
                "bundle_id": bundle_id,
                "manifest_uri": manifest_uri,
                "manifest_version_id": manifest_version_id,
                "anchor_uri": anchor_uri,
                "anchor_version_id": anchor_version_id,
                "ledger_entry_hash": row["entry_hash"],
                "closed_at": datetime.now(UTC).isoformat(),
            },
        )
        _durable_replace(temporary_root, final_day_dir)
    except BaseException:
        if temporary_root.exists() and not ledger_committed:
            shutil.rmtree(temporary_root)
        raise
    print(final_day_dir)
    return 0 if status in {"clean", "burn-in"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
