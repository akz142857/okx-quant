#!/usr/bin/env python3
"""生成 SQLite 在线快照、AES-256 加密，并可选上传 S3。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import requests

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)


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
        or key_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise RuntimeError("备份签名私钥必须是非空普通文件且不能被 group/other 写入")
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
            candidate.with_suffix(
                candidate.suffix + ".manifest.json"
            ).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--offsite-uri", default="")
    parser.add_argument("--retention-days", type=int, default=30)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-schema-version", type=int, default=9)
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
    temporary_encrypted = args.output_dir / (
        f".{encrypted.name}.{uuid.uuid4().hex}.tmp"
    )
    temporary_manifest = args.output_dir / (
        f".{manifest.name}.{uuid.uuid4().hex}.tmp"
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
        payload = {
            "version": 1,
            "action": "publish-encrypted-sqlite-backup",
            "file": encrypted.name,
            "sha256": hashlib.sha256(
                temporary_encrypted.read_bytes()
            ).hexdigest(),
            "snapshot_started_at": snapshot_started_at,
            "snapshot_completed_at": snapshot_completed_at,
            "published_at": int(time.time()),
            "account_id": args.expected_account_id,
            "schema_version": args.expected_schema_version,
            "signing_key_id": args.signing_key_id,
            "encryption_key_id": args.encryption_key_id,
        }
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
        os.replace(temporary_encrypted, encrypted)
        # The signed manifest is the ready marker and is always published last.
        os.replace(temporary_manifest, manifest)
    except Exception as exc:
        temporary_encrypted.unlink(missing_ok=True)
        temporary_manifest.unlink(missing_ok=True)
        _page_failure(args.alert_webhook_env, exc)
        raise
    try:
        if args.offsite_uri:
            if not args.offsite_uri.startswith("s3://"):
                raise ValueError("--offsite-uri 当前仅支持 s3://")
            destination = args.offsite_uri.rstrip("/") + "/"
            subprocess.run(
                ["aws", "s3", "cp", str(encrypted), destination],
                check=True,
                timeout=120,
            )
            subprocess.run(
                ["aws", "s3", "cp", str(manifest), destination],
                check=True,
                timeout=120,
            )
    except Exception as exc:
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
