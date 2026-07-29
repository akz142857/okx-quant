#!/usr/bin/env python3
"""Sign an exact-version locator for a frozen raw SQLite journal snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import stat
from datetime import date
from pathlib import Path

from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.ops.slo_facts import export_slo_v2_facts


def _day(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("day 必须为 YYYY-MM-DD") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--day", required=True, type=_day)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--object-uri", required=True)
    parser.add_argument("--version-id", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise RuntimeError("拒绝覆盖 journal snapshot locator")
    snapshot_info = args.snapshot.lstat()
    key_info = args.private_key.lstat()
    if (
        not stat.S_ISREG(snapshot_info.st_mode)
        or args.snapshot.is_symlink()
        or snapshot_info.st_size <= 0
        or not stat.S_ISREG(key_info.st_mode)
        or args.private_key.is_symlink()
        or stat.S_IMODE(key_info.st_mode) != 0o600
    ):
        raise RuntimeError("snapshot/private key 文件安全属性非法")
    if (
        not args.object_uri.startswith("s3://")
        or not args.version_id.strip()
        or not args.account_id.strip()
    ):
        raise RuntimeError("snapshot exact-version identity 非法")
    connection = sqlite3.connect(
        f"file:{args.snapshot.resolve()}?mode=ro",
        uri=True,
    )
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        identity = connection.execute(
            "SELECT account_id FROM journal_identity WHERE singleton=1"
        ).fetchone()
    finally:
        connection.close()
    if (
        integrity is None
        or integrity[0] != "ok"
        or identity is None
        or identity[0] != args.account_id
    ):
        raise RuntimeError("journal snapshot integrity/account identity 非法")
    # Fail before signing if this exact raw DB cannot reconstruct the day.
    export_slo_v2_facts(args.snapshot, args.day)
    snapshot_bytes = args.snapshot.read_bytes()
    artifact = sign_ed25519_payload(
        {
            "version": 1,
            "action": "attest-exact-journal-snapshot",
            "day": args.day.isoformat(),
            "account_id": args.account_id,
            "object_uri": args.object_uri,
            "version_id": args.version_id,
            "sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
            "bytes": len(snapshot_bytes),
        },
        args.private_key,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            artifact,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
