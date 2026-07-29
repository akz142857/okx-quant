#!/usr/bin/env python3
"""Restore the exact immutable S3 versions named by a signed backup receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.infrastructure.immutable_bundle import verify_locked_object
from scripts.daily_archive import validate_offsite_receipt
from scripts.restore_drill import verify_manifest


def _load_env_file(path: Path) -> None:
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"环境文件第 {line_number} 行缺少 '='")
            key, value = line.split("=", 1)
            key = key.strip()
            if (
                not key
                or not key.replace("_", "").isalnum()
                or not key[0].isalpha()
            ):
                raise ValueError(f"环境文件第 {line_number} 行变量名非法")
            value = value.strip()
            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in {"'", '"'}
            ):
                value = value[1:-1]
            os.environ.setdefault(key, value)


def _load_signed_receipt(path: Path, public_key: Path) -> tuple[dict, str]:
    artifact_bytes = path.read_bytes()
    artifact = json.loads(artifact_bytes)
    claims = validate_offsite_receipt(
        verify_ed25519_artifact(
            artifact,
            public_key,
            label="offsite backup receipt",
        )
    )
    return claims, hashlib.sha256(artifact_bytes).hexdigest()


def _assert_manifest_receipt_binding(manifest: dict, receipt: dict) -> None:
    offsite = manifest.get("offsite_archive")
    archive = receipt["archive"]
    if (
        manifest.get("version") != 2
        or manifest.get("file") != receipt["file"]
        or manifest.get("account_id") != receipt["account_id"]
        or manifest.get("schema_version") != receipt["schema_version"]
        or manifest.get("snapshot_completed_at")
        != receipt["snapshot_completed_at"]
        or manifest.get("signing_key_id") != receipt["signing_key_id"]
        or manifest.get("encryption_key_id") != receipt["encryption_key_id"]
        or not isinstance(offsite, dict)
        or offsite.get("object_uri") != archive["object_uri"]
        or offsite.get("version_id") != archive["version_id"]
        or offsite.get("bytes") != archive["bytes"]
        or offsite.get("kms_key_id") != receipt["kms_key_id"]
        or manifest.get("sha256") != archive["sha256"]
    ):
        raise RuntimeError("signed manifest 与 signed offsite receipt 绑定不一致")


def _materialize_verified_restore(
    *,
    destination: Path,
    archive_name: str,
    archive_payload: bytes,
    manifest_payload: bytes,
    receipt_payload: bytes,
) -> Path:
    """Atomically publish exact-version recovery inputs for cold restore."""
    if Path(archive_name).name != archive_name or not archive_name.endswith(
        ".db.enc"
    ):
        raise RuntimeError("恢复物化 archive 文件名非法")
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise RuntimeError(f"拒绝覆盖恢复物化目录: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    parent_stat = destination.parent.lstat()
    if (
        destination.parent.is_symlink()
        or not stat.S_ISDIR(parent_stat.st_mode)
    ):
        raise RuntimeError("恢复物化父路径必须是普通目录")
    temporary = Path(tempfile.mkdtemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    ))
    try:
        files = {
            archive_name: archive_payload,
            f"{archive_name}.manifest.json": manifest_payload,
            f"{archive_name}.offsite-receipt.json": receipt_payload,
        }
        for name, payload in files.items():
            path = temporary / name
            with path.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            path.chmod(0o600)
        directory_fd = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.replace(temporary, destination)
        parent_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return destination / archive_name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup-env", required=True, type=Path)
    parser.add_argument("--local-backup-dir", required=True, type=Path)
    parser.add_argument("--manifest-public-key", required=True, type=Path)
    parser.add_argument(
        "--receipt",
        type=Path,
        help="指定 signed receipt；空主机演练必须显式固定此文件",
    )
    parser.add_argument(
        "--materialize-dir",
        type=Path,
        help="原子保存已验证 exact-version archive/manifest/receipt",
    )
    parser.add_argument("--evidence-private-key", required=True, type=Path)
    parser.add_argument("--evidence-public-key", required=True, type=Path)
    parser.add_argument("--evidence-key-id", default="")
    parser.add_argument("--minimum-remaining-retention-days", type=int, default=30)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.minimum_remaining_retention_days < 1:
        raise RuntimeError("minimum remaining retention 必须至少为 1 天")
    manifest_fingerprint = ed25519_public_key_fingerprint(
        args.manifest_public_key
    )
    evidence_public_fingerprint = ed25519_public_key_fingerprint(
        args.evidence_public_key
    )
    evidence_private_fingerprint = ed25519_public_key_fingerprint(
        args.evidence_private_key,
        private_key=True,
    )
    if (
        manifest_fingerprint == evidence_public_fingerprint
        or evidence_public_fingerprint != evidence_private_fingerprint
    ):
        raise RuntimeError(
            "backup publisher 与 restore verifier 必须使用不同且配对的公钥"
        )
    _load_env_file(args.backup_env)
    work_dir = args.output.parent.absolute()
    work_dir.mkdir(parents=True, exist_ok=True)
    work_info = work_dir.lstat()
    if (
        work_dir.is_symlink()
        or not stat.S_ISDIR(work_info.st_mode)
        or stat.S_IMODE(work_info.st_mode) & 0o022
    ):
        raise RuntimeError("restore verifier 工作目录必须是不可组写/公开写的普通目录")
    stale_temporary_cutoff = time.time() - 3600
    for temporary in work_dir.glob(".offsite-restore-*"):
        if temporary.stat().st_mtime < stale_temporary_cutoff:
            if temporary.is_dir() and not temporary.is_symlink():
                shutil.rmtree(temporary)
            else:
                temporary.unlink(missing_ok=True)
    required_env = {
        key: os.environ.get(key, "")
        for key in (
            "OKX_QUANT_ACCOUNT_ID",
            "OKX_QUANT_BACKUP_PASSPHRASE",
            "OKX_QUANT_BACKUP_SIGNING_KEY_ID",
            "OKX_QUANT_BACKUP_ENCRYPTION_KEY_ID",
            "OKX_QUANT_BACKUP_KMS_KEY_ID",
        )
    }
    missing = [key for key, value in required_env.items() if not value]
    if missing:
        raise RuntimeError(f"offsite restore check 缺少环境变量: {missing}")
    evidence_key_id = (
        args.evidence_key_id
        or required_env["OKX_QUANT_BACKUP_SIGNING_KEY_ID"]
    )
    if args.receipt:
        receipt_path = args.receipt.absolute()
        if (
            receipt_path.is_symlink()
            or not receipt_path.is_file()
            or not receipt_path.name.endswith(
                ".db.enc.offsite-receipt.json"
            )
        ):
            raise RuntimeError("指定 receipt 必须是 signed receipt 普通文件")
    else:
        ready = sorted(
            args.local_backup_dir.glob(
                "trading-*.db.enc.offsite-receipt.json"
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not ready:
            raise RuntimeError("没有 signed offsite backup receipt")
        receipt_path = ready[0]
    receipt_artifact_bytes = receipt_path.read_bytes()
    receipt, receipt_sha256 = _load_signed_receipt(
        receipt_path,
        args.manifest_public_key,
    )
    if (
        receipt["account_id"] != required_env["OKX_QUANT_ACCOUNT_ID"]
        or receipt["signing_key_id"]
        != required_env["OKX_QUANT_BACKUP_SIGNING_KEY_ID"]
        or receipt["encryption_key_id"]
        != required_env["OKX_QUANT_BACKUP_ENCRYPTION_KEY_ID"]
        or receipt["kms_key_id"]
        != required_env["OKX_QUANT_BACKUP_KMS_KEY_ID"]
    ):
        raise RuntimeError("offsite receipt 的账户或 key 身份与部署环境不一致")
    minimum_retain_until = datetime.now(UTC) + timedelta(
        days=args.minimum_remaining_retention_days
    )
    claimed_retain_until = datetime.fromisoformat(
        receipt["retention"]["retain_until"]
    )
    if claimed_retain_until < minimum_retain_until:
        raise RuntimeError("offsite backup 剩余 COMPLIANCE retention 不足")

    started = time.time()
    archive_payload = verify_locked_object(
        object_uri=receipt["archive"]["object_uri"],
        version_id=receipt["archive"]["version_id"],
        expected_sha256=receipt["archive"]["sha256"],
        expected_bytes=receipt["archive"]["bytes"],
        minimum_retain_until=minimum_retain_until,
        expected_kms_key_id=receipt["kms_key_id"],
    )
    manifest_payload = verify_locked_object(
        object_uri=receipt["manifest"]["object_uri"],
        version_id=receipt["manifest"]["version_id"],
        expected_sha256=receipt["manifest"]["sha256"],
        expected_bytes=receipt["manifest"]["bytes"],
        minimum_retain_until=minimum_retain_until,
        expected_kms_key_id=receipt["kms_key_id"],
    )
    with tempfile.TemporaryDirectory(
        prefix=".offsite-restore-",
        dir=work_dir,
    ) as directory:
        temporary = Path(directory)
        archive = temporary / receipt["file"]
        manifest = archive.with_suffix(archive.suffix + ".manifest.json")
        archive.write_bytes(archive_payload)
        manifest.write_bytes(manifest_payload)
        manifest_claims = verify_manifest(
            archive,
            args.manifest_public_key,
        )
        _assert_manifest_receipt_binding(manifest_claims, receipt)
        component_output = temporary / "component-restore.json"
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("restore_drill.py")),
                str(archive),
                "--expected-account-id",
                required_env["OKX_QUANT_ACCOUNT_ID"],
                "--manifest-public-key",
                str(args.manifest_public_key),
                "--expected-signing-key-id",
                required_env["OKX_QUANT_BACKUP_SIGNING_KEY_ID"],
                "--expected-encryption-key-id",
                required_env["OKX_QUANT_BACKUP_ENCRYPTION_KEY_ID"],
                "--output",
                str(component_output),
            ],
            check=True,
            timeout=300,
        )
        restore = json.loads(component_output.read_text(encoding="utf-8"))
        if args.materialize_dir:
            _materialize_verified_restore(
                destination=args.materialize_dir,
                archive_name=receipt["file"],
                archive_payload=archive_payload,
                manifest_payload=manifest_payload,
                receipt_payload=receipt_artifact_bytes,
            )
    completed = time.time()
    restore["source"] = receipt["archive"]["object_uri"]
    evidence = {
        "version": 1,
        "action": "attest-offsite-backup-restore",
        "evidence_key_id": evidence_key_id,
        "account_id": receipt["account_id"],
        "schema_version": receipt["schema_version"],
        "receipt_sha256": receipt_sha256,
        "archive_uri": receipt["archive"]["object_uri"],
        "archive_version_id": receipt["archive"]["version_id"],
        "archive_sha256": receipt["archive"]["sha256"],
        "archive_bytes": receipt["archive"]["bytes"],
        "manifest_uri": receipt["manifest"]["object_uri"],
        "manifest_version_id": receipt["manifest"]["version_id"],
        "manifest_sha256": receipt["manifest"]["sha256"],
        "manifest_bytes": receipt["manifest"]["bytes"],
        "snapshot_completed_at": receipt["snapshot_completed_at"],
        "roundtrip_started_at": started,
        "roundtrip_completed_at": completed,
        "restore": restore,
        "backup_slo_sample": {
            "integrity": "ok",
            "snapshot_completed_at": receipt["snapshot_completed_at"],
            "offsite_readback_at": completed,
            "version_id": receipt["archive"]["version_id"],
        },
    }
    artifact = sign_ed25519_payload(evidence, args.evidence_private_key)
    if (
        verify_ed25519_artifact(
            artifact,
            args.evidence_public_key,
            label="offsite restore evidence",
        )
        != evidence
    ):
        raise RuntimeError("offsite restore evidence 签名回验不一致")
    serialized = (
        json.dumps(
            artifact,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    temporary_fd, temporary_name = tempfile.mkstemp(
        prefix=f".{args.output.name}.",
        dir=args.output.parent,
    )
    temporary_output = Path(temporary_name)
    try:
        with os.fdopen(temporary_fd, "wb") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_output.chmod(0o640)
        os.replace(temporary_output, args.output)
        parent_fd = os.open(args.output.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        temporary_output.unlink(missing_ok=True)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
