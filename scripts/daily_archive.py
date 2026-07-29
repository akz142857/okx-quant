#!/usr/bin/env python3
"""生成 SQLite 在线快照、AES-256 加密，并可选上传 S3。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import requests

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)
from okx_quant.infrastructure.immutable_bundle import (
    put_locked_object,
    verify_locked_object,
)

_BACKUP_COMPONENT_KEYS = {
    "object_uri",
    "version_id",
    "sha256",
    "bytes",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_OFFSITE_RECEIPT_KEYS = {
    "version",
    "action",
    "file",
    "account_id",
    "schema_version",
    "snapshot_completed_at",
    "readback_completed_at",
    "signing_key_id",
    "encryption_key_id",
    "kms_key_id",
    "retention",
    "archive",
    "manifest",
}


def _page_failure(webhook_env: str, error: BaseException) -> None:
    webhook = os.environ.get(webhook_env, "")
    if not webhook:
        return
    try:
        response = requests.post(
            webhook,
            json={
                "event_name": "daily_archive_failed",
                "severity": "critical",
                "error": str(error),
            },
            timeout=10,
        )
        response.raise_for_status()
    except Exception:
        pass


def _verify_snapshot(
    snapshot: Path,
    *,
    expected_account_id: str,
    expected_schema_version: int,
) -> None:
    probe = sqlite3.connect(f"file:{snapshot}?mode=ro", uri=True)
    try:
        integrity = probe.execute("PRAGMA integrity_check").fetchone()
        version = probe.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()
        identity = probe.execute(
            "SELECT account_id FROM journal_identity WHERE singleton=1"
        ).fetchone()
    finally:
        probe.close()
    if not integrity or integrity[0] != "ok":
        raise RuntimeError("daily archive snapshot integrity_check 失败")
    if not version or version[0] != expected_schema_version:
        raise RuntimeError("daily archive snapshot schema 版本不匹配")
    if not identity or identity[0] != expected_account_id:
        raise RuntimeError("daily archive snapshot 账户身份不匹配")


def _sign_manifest(payload: dict, private_key: Path) -> dict:
    key_stat = private_key.lstat()
    if (
        not stat.S_ISREG(key_stat.st_mode)
        or private_key.is_symlink()
        or key_stat.st_size <= 0
        or stat.S_IMODE(key_stat.st_mode) not in {0o600, 0o640}
    ):
        raise RuntimeError(
            "备份签名私钥必须是受控的 0600/0640 普通文件"
        )
    with (
        tempfile.NamedTemporaryFile() as message,
        tempfile.NamedTemporaryFile() as signature,
    ):
        message.write(canonical_bytes(payload))
        message.flush()
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                message.name,
                "-out",
                signature.name,
            ],
            check=True,
            timeout=10,
        )
        encoded = base64.b64encode(Path(signature.name).read_bytes()).decode("ascii")
    return {"payload": payload, "signature": encoded}


def _s3_object_uri(prefix_uri: str, name: str) -> str:
    parsed = urlparse(prefix_uri)
    if parsed.scheme != "s3" or not parsed.netloc:
        raise ValueError("--offsite-uri 必须是 s3://bucket/prefix")
    prefix = parsed.path.strip("/")
    key = "/".join(part for part in (prefix, name) if part)
    if not key:
        raise ValueError("S3 object key 不能为空")
    return f"s3://{parsed.netloc}/{key}"


def validate_offsite_receipt(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != _OFFSITE_RECEIPT_KEYS:
        raise RuntimeError("offsite backup receipt schema 非法")
    if (
        payload["version"] != 1
        or payload["action"] != "attest-offsite-backup-publication"
        or not str(payload["file"]).endswith(".db.enc")
        or not str(payload["account_id"]).strip()
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] <= 0
        or type(payload["snapshot_completed_at"]) not in {int, float}
        or type(payload["readback_completed_at"]) not in {int, float}
        or not math.isfinite(float(payload["snapshot_completed_at"]))
        or not math.isfinite(float(payload["readback_completed_at"]))
        or payload["snapshot_completed_at"] <= 0
        or payload["readback_completed_at"] < payload["snapshot_completed_at"]
        or not all(
            str(payload[key]).strip()
            for key in (
                "signing_key_id",
                "encryption_key_id",
                "kms_key_id",
            )
        )
    ):
        raise RuntimeError("offsite backup receipt identity/time 非法")
    retention = payload["retention"]
    if (
        not isinstance(retention, dict)
        or set(retention) != {"mode", "retain_until"}
        or retention["mode"] != "COMPLIANCE"
    ):
        raise RuntimeError("offsite backup receipt retention 非法")
    retain_until = datetime.fromisoformat(str(retention["retain_until"]))
    if retain_until.tzinfo is None or retain_until.utcoffset() is None:
        raise RuntimeError("offsite backup receipt retain_until 必须带时区")
    for name in ("archive", "manifest"):
        component = payload[name]
        if (
            not isinstance(component, dict)
            or set(component) != _BACKUP_COMPONENT_KEYS
            or not str(component["version_id"]).strip()
            or type(component["bytes"]) is not int
            or component["bytes"] <= 0
            or not _SHA256.fullmatch(str(component["sha256"]))
        ):
            raise RuntimeError(f"offsite backup receipt {name} 非法")
        _s3_object_uri(str(component["object_uri"]), "probe")
    return payload


def _decrypt_for_verification(
    encrypted: Path,
    destination: Path,
    passphrase_env: str,
) -> None:
    subprocess.run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-in",
            str(encrypted),
            "-out",
            str(destination),
            "-pass",
            f"env:{passphrase_env}",
        ],
        check=True,
        timeout=120,
    )


def _prune(output_dir: Path, *, retention_days: int, now: float) -> None:
    """Keep all 24h points, then hourly for 7d, then daily."""
    stale_temporary_cutoff = now - 3600
    for pattern in (
        ".okx-daily-backup-*",
        ".trading-*.tmp",
    ):
        for temporary in output_dir.glob(pattern):
            if temporary.stat().st_mtime >= stale_temporary_cutoff:
                continue
            if temporary.is_dir() and not temporary.is_symlink():
                shutil.rmtree(temporary)
            else:
                temporary.unlink(missing_ok=True)
    keep_buckets: set[tuple[str, str]] = set()
    candidates = sorted(
        output_dir.glob("trading-*.db.enc"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for candidate in candidates:
        age = max(now - candidate.stat().st_mtime, 0)
        delete = age > max(retention_days, 30) * 86400
        if not delete and age > 86400:
            stamp = time.gmtime(candidate.stat().st_mtime)
            bucket = (
                ("hour", time.strftime("%Y%m%d%H", stamp))
                if age <= 7 * 86400
                else ("day", time.strftime("%Y%m%d", stamp))
            )
            delete = bucket in keep_buckets
            keep_buckets.add(bucket)
        if delete:
            candidate.unlink(missing_ok=True)
            for suffix in (
                ".manifest.json",
                ".offsite-receipt.json",
                ".offsite-publication.json",
            ):
                candidate.with_suffix(
                    candidate.suffix + suffix
                ).unlink(missing_ok=True)


def _durable_replace(source: Path, destination: Path) -> None:
    """fsync content and directory so a success survives power loss."""
    with source.open("rb") as handle:
        os.fsync(handle.fileno())
    os.replace(source, destination)
    parent_fd = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--offsite-uri", default="")
    parser.add_argument("--kms-key-id", default="")
    parser.add_argument("--object-lock-retention-days", type=int, default=35)
    parser.add_argument("--retention-days", type=int, default=30)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-schema-version", type=int, default=11)
    parser.add_argument(
        "--manifest-private-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--manifest-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--encryption-key-id", required=True)
    parser.add_argument(
        "--min-free-bytes",
        type=int,
        default=1_073_741_824,
    )
    parser.add_argument(
        "--alert-webhook-env",
        default="OKX_QUANT_ALERT_WEBHOOK",
    )
    parser.add_argument(
        "--passphrase-env", default="OKX_QUANT_BACKUP_PASSPHRASE"
    )
    args = parser.parse_args()
    try:
        for label, key_id in {
            "signing": args.signing_key_id,
            "encryption": args.encryption_key_id,
        }.items():
            if not key_id or not all(
                char.isalnum() or char in "._-" for char in key_id
            ):
                raise RuntimeError(f"{label} key id 非法")
        if args.offsite_uri:
            _s3_object_uri(args.offsite_uri, "probe")
            if not args.kms_key_id.strip():
                raise RuntimeError("offsite backup 必须指定 --kms-key-id")
            if args.object_lock_retention_days < 35:
                raise RuntimeError(
                    "offsite backup Object Lock retention 不能少于 35 天"
                )
        if not os.environ.get(args.passphrase_env):
            raise RuntimeError(
                f"缺少加密口令环境变量: {args.passphrase_env}"
            )
        args.output_dir.mkdir(parents=True, exist_ok=True)
        _prune(
            args.output_dir,
            retention_days=args.retention_days,
            now=time.time(),
        )
        required_free = max(
            args.min_free_bytes,
            args.database.stat().st_size * 3,
        )
        if (
            args.min_free_bytes < 0
            or shutil.disk_usage(args.output_dir).free < required_free
        ):
            raise RuntimeError(
                "归档文件系统剩余空间低于固定门槛或数据库三倍临时空间"
            )
    except Exception as exc:
        _page_failure(args.alert_webhook_env, exc)
        raise
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    encrypted = args.output_dir / f"trading-{stamp}.db.enc"
    manifest = encrypted.with_suffix(encrypted.suffix + ".manifest.json")
    receipt = encrypted.with_suffix(
        encrypted.suffix + ".offsite-receipt.json"
    )
    publication = encrypted.with_suffix(
        encrypted.suffix + ".offsite-publication.json"
    )
    temporary_encrypted = args.output_dir / (
        f".{encrypted.name}.{uuid.uuid4().hex}.tmp"
    )
    temporary_manifest = args.output_dir / (
        f".{manifest.name}.{uuid.uuid4().hex}.tmp"
    )
    temporary_receipt = args.output_dir / (
        f".{receipt.name}.{uuid.uuid4().hex}.tmp"
    )
    temporary_publication = args.output_dir / (
        f".{publication.name}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix=".okx-daily-backup-",
            dir=args.output_dir,
        ) as directory:
            snapshot = Path(directory) / "snapshot.db"
            snapshot_started_at = int(time.time())
            source = sqlite3.connect(
                f"file:{args.database}?mode=ro", uri=True
            )
            target = sqlite3.connect(snapshot)
            try:
                source.backup(target)
            finally:
                target.close()
                source.close()
            snapshot_completed_at = int(time.time())
            _verify_snapshot(
                snapshot,
                expected_account_id=args.expected_account_id,
                expected_schema_version=args.expected_schema_version,
            )
            subprocess.run(
                [
                    "openssl",
                    "enc",
                    "-aes-256-cbc",
                    "-salt",
                    "-pbkdf2",
                    "-in",
                    str(snapshot),
                    "-out",
                    str(temporary_encrypted),
                    "-pass",
                    f"env:{args.passphrase_env}",
                ],
                check=True,
                timeout=120,
            )
            restored = Path(directory) / "restored-verification.db"
            _decrypt_for_verification(
                temporary_encrypted,
                restored,
                args.passphrase_env,
            )
            _verify_snapshot(
                restored,
                expected_account_id=args.expected_account_id,
                expected_schema_version=args.expected_schema_version,
            )
        encrypted_bytes = temporary_encrypted.read_bytes()
        encrypted_sha256 = hashlib.sha256(encrypted_bytes).hexdigest()
        retain_until: datetime | None = None
        archive_uri = ""
        archive_version_id = ""
        archive_readback_at = 0
        if args.offsite_uri:
            retain_until = datetime.now(UTC).replace(
                microsecond=0
            ) + timedelta(days=args.object_lock_retention_days)
            archive_uri = _s3_object_uri(args.offsite_uri, encrypted.name)
            archive_version_id = put_locked_object(
                source=temporary_encrypted,
                object_uri=archive_uri,
                retain_until=retain_until,
                kms_key_id=args.kms_key_id,
                content_type="application/octet-stream",
            )
            verify_locked_object(
                object_uri=archive_uri,
                version_id=archive_version_id,
                expected_sha256=encrypted_sha256,
                expected_bytes=len(encrypted_bytes),
                minimum_retain_until=retain_until,
                expected_kms_key_id=args.kms_key_id,
            )
            archive_readback_at = int(time.time())
        payload = {
            "version": 1,
            "action": "publish-encrypted-sqlite-backup",
            "file": encrypted.name,
            "sha256": encrypted_sha256,
            "snapshot_started_at": snapshot_started_at,
            "snapshot_completed_at": snapshot_completed_at,
            "published_at": int(time.time()),
            "account_id": args.expected_account_id,
            "schema_version": args.expected_schema_version,
            "signing_key_id": args.signing_key_id,
            "encryption_key_id": args.encryption_key_id,
        }
        if retain_until is not None:
            payload.update({
                "version": 2,
                "offsite_archive": {
                    "object_uri": archive_uri,
                    "version_id": archive_version_id,
                    "bytes": len(encrypted_bytes),
                    "retain_until": retain_until.isoformat(),
                    "kms_key_id": args.kms_key_id,
                    "readback_at": archive_readback_at,
                },
            })
        artifact = _sign_manifest(payload, args.manifest_private_key)
        verified = verify_ed25519_artifact(
            artifact,
            args.manifest_public_key,
            label="备份 manifest",
        )
        if verified != payload:
            raise RuntimeError("备份 manifest 签名回验 payload 不一致")
        temporary_manifest.write_text(
            json.dumps(
                artifact,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        _durable_replace(temporary_encrypted, encrypted)
        # The signed manifest is the ready marker and is always published last.
        _durable_replace(temporary_manifest, manifest)
        if args.offsite_uri:
            if retain_until is None:
                raise AssertionError("offsite retention 未初始化")
            manifest_bytes = manifest.read_bytes()
            manifest_uri = _s3_object_uri(args.offsite_uri, manifest.name)
            manifest_version_id = put_locked_object(
                source=manifest,
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
            readback_completed_at = int(time.time())
            receipt_claims = validate_offsite_receipt({
                "version": 1,
                "action": "attest-offsite-backup-publication",
                "file": encrypted.name,
                "account_id": args.expected_account_id,
                "schema_version": args.expected_schema_version,
                "snapshot_completed_at": snapshot_completed_at,
                "readback_completed_at": readback_completed_at,
                "signing_key_id": args.signing_key_id,
                "encryption_key_id": args.encryption_key_id,
                "kms_key_id": args.kms_key_id,
                "retention": {
                    "mode": "COMPLIANCE",
                    "retain_until": retain_until.isoformat(),
                },
                "archive": {
                    "object_uri": archive_uri,
                    "version_id": archive_version_id,
                    "sha256": encrypted_sha256,
                    "bytes": len(encrypted_bytes),
                },
                "manifest": {
                    "object_uri": manifest_uri,
                    "version_id": manifest_version_id,
                    "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                    "bytes": len(manifest_bytes),
                },
            })
            receipt_artifact = _sign_manifest(
                receipt_claims,
                args.manifest_private_key,
            )
            if (
                validate_offsite_receipt(
                    verify_ed25519_artifact(
                        receipt_artifact,
                        args.manifest_public_key,
                        label="offsite backup receipt",
                    )
                )
                != receipt_claims
            ):
                raise RuntimeError("offsite backup receipt 签名回验不一致")
            temporary_receipt.write_text(
                json.dumps(
                    receipt_artifact,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            receipt_bytes = temporary_receipt.read_bytes()
            receipt_uri = _s3_object_uri(args.offsite_uri, receipt.name)
            receipt_version_id = put_locked_object(
                source=temporary_receipt,
                object_uri=receipt_uri,
                retain_until=retain_until,
                kms_key_id=args.kms_key_id,
            )
            verify_locked_object(
                object_uri=receipt_uri,
                version_id=receipt_version_id,
                expected_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
                expected_bytes=len(receipt_bytes),
                minimum_retain_until=retain_until,
                expected_kms_key_id=args.kms_key_id,
            )
            temporary_publication.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "action": "verify-offsite-backup-receipt-storage",
                        "receipt_uri": receipt_uri,
                        "receipt_version_id": receipt_version_id,
                        "receipt_sha256": hashlib.sha256(
                            receipt_bytes
                        ).hexdigest(),
                        "receipt_bytes": len(receipt_bytes),
                        "verified_at": int(time.time()),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            _durable_replace(temporary_receipt, receipt)
            _durable_replace(temporary_publication, publication)
    except Exception as exc:
        temporary_encrypted.unlink(missing_ok=True)
        temporary_manifest.unlink(missing_ok=True)
        temporary_receipt.unlink(missing_ok=True)
        temporary_publication.unlink(missing_ok=True)
        _page_failure(args.alert_webhook_env, exc)
        raise
    finally:
        _prune(
            args.output_dir,
            retention_days=args.retention_days,
            now=time.time(),
        )
    print(encrypted)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
