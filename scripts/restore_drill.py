#!/usr/bin/env python3
"""在隔离临时目录恢复 SQLite 备份，并生成可审计演练证据。"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from okx_quant.application.approval import verify_ed25519_artifact

REQUIRED_TABLES = {
    "account_snapshots",
    "candle_watermarks",
    "control_commands",
    "decisions",
    "exit_leases",
    "order_intents",
    "order_events",
    "fills",
    "journal_identity",
    "outbox_events",
    "positions",
    "protective_orders",
    "realized_pnl_events",
    "reconciliation_adjustments",
    "reconciliation_runs",
    "risk_reservations",
    "system_events",
    "system_state",
    "schema_migrations",
}


def decrypt(source: Path, destination: Path, passphrase_env: str) -> None:
    subprocess.run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-in",
            str(source),
            "-out",
            str(destination),
            "-pass",
            f"env:{passphrase_env}",
        ],
        check=True,
        timeout=120,
    )


def verify_manifest(source: Path, public_key: Path) -> dict:
    manifest = source.with_suffix(source.suffix + ".manifest.json")
    if not manifest.exists():
        raise RuntimeError(f"加密备份缺少签名 ready manifest: {manifest}")
    artifact = json.loads(manifest.read_text(encoding="utf-8"))
    claims = verify_ed25519_artifact(
        artifact,
        public_key,
        label="备份 manifest",
    )
    required = {
        "version",
        "action",
        "file",
        "sha256",
        "snapshot_started_at",
        "snapshot_completed_at",
        "published_at",
        "account_id",
        "schema_version",
        "signing_key_id",
        "encryption_key_id",
    }
    if set(claims) != required:
        raise RuntimeError("备份 manifest 字段不完整或包含未知字段")
    if (
        claims["version"] != 1
        or claims["action"] != "publish-encrypted-sqlite-backup"
        or claims["file"] != source.name
    ):
        raise RuntimeError("备份 manifest 版本、action 或文件名不匹配")
    actual = hashlib.sha256(source.read_bytes()).hexdigest()
    if actual != claims["sha256"]:
        raise RuntimeError("加密备份 SHA-256 校验失败")
    return claims


def verify(
    database: Path,
    *,
    expected_account_id: str,
    expected_schema_version: int,
) -> dict:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        missing = sorted(REQUIRED_TABLES - tables)
        counts = {
            table: connection.execute(
                f"SELECT COUNT(*) FROM {table}"  # nosec B608
            ).fetchone()[0]
            for table in sorted(REQUIRED_TABLES - {"schema_migrations"})
            if table in tables
        }
        version = (
            connection.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()[0]
            if "schema_migrations" in tables
            else None
        )
        account_id = (
            connection.execute(
                "SELECT account_id FROM journal_identity WHERE singleton=1"
            ).fetchone()[0]
            if "journal_identity" in tables
            and connection.execute(
                "SELECT COUNT(*) FROM journal_identity WHERE singleton=1"
            ).fetchone()[0]
            == 1
            else None
        )
    finally:
        connection.close()
    return {
        "integrity_check": integrity,
        "schema_version": version,
        "account_id": account_id,
        "missing_tables": missing,
        "row_counts": counts,
        "database_ok": (
            integrity == "ok"
            and not missing
            and version == expected_schema_version
            and account_id == expected_account_id
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("backup", type=Path)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-schema-version", type=int, default=9)
    parser.add_argument("--max-rto-seconds", type=float, default=300)
    parser.add_argument("--max-backup-age-seconds", type=float, default=172800)
    parser.add_argument("--passphrase-env", default="OKX_QUANT_BACKUP_PASSPHRASE")
    parser.add_argument(
        "--manifest-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument("--expected-signing-key-id", required=True)
    parser.add_argument("--expected-encryption-key-id", required=True)
    parser.add_argument("--output", type=Path, default=Path("restore-drill.json"))
    args = parser.parse_args()
    started = time.time()
    if args.backup.suffix != ".enc":
        raise SystemExit("恢复演练只接受带 checksum 的加密 .enc 备份")
    if args.max_rto_seconds <= 0 or args.max_backup_age_seconds <= 0:
        raise SystemExit("RTO/备份年龄预算必须大于 0")
    checksum_verified = False
    manifest = verify_manifest(args.backup, args.manifest_public_key)
    snapshot_started_at = manifest["snapshot_started_at"]
    snapshot_completed_at = manifest["snapshot_completed_at"]
    published_at = manifest["published_at"]
    if (
        any(
            type(value) is not int
            for value in (
                snapshot_started_at,
                snapshot_completed_at,
                published_at,
            )
        )
        or not snapshot_started_at <= snapshot_completed_at <= published_at
        or published_at > started + 300
    ):
        raise SystemExit("备份 manifest 时间链非法或位于未来")
    if (
        manifest["account_id"] != args.expected_account_id
        or manifest["schema_version"] != args.expected_schema_version
        or manifest["signing_key_id"] != args.expected_signing_key_id
        or manifest["encryption_key_id"] != args.expected_encryption_key_id
    ):
        raise SystemExit("备份 manifest 账户、schema 或 key 身份不匹配")
    source_age_seconds = max(started - snapshot_started_at, 0)
    with tempfile.TemporaryDirectory(prefix="okx-restore-drill-") as directory:
        source = args.backup
        restored = Path(directory) / "restored.db"
        checksum_verified = True
        decrypt(source, restored, args.passphrase_env)
        result = verify(
            restored,
            expected_account_id=args.expected_account_id,
            expected_schema_version=args.expected_schema_version,
        )
    completed_at = time.time()
    elapsed_seconds = completed_at - started
    result.update({
        "measurement_scope": "database_restore_component_only",
        "source": str(args.backup),
        "checksum_verified": checksum_verified,
        "started_at": started,
        "completed_at": completed_at,
        "elapsed_seconds": elapsed_seconds,
        "max_rto_seconds": args.max_rto_seconds,
        "source_age_seconds": source_age_seconds,
        "max_backup_age_seconds": args.max_backup_age_seconds,
    })
    result["ok"] = bool(
        result["database_ok"]
        and checksum_verified
        and elapsed_seconds <= args.max_rto_seconds
        and source_age_seconds <= args.max_backup_age_seconds
    )
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
