#!/usr/bin/env python3
"""Sign one daily aggregate of raw external-source evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
from datetime import date
from pathlib import Path

from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.infrastructure.immutable_bundle import scan_json_evidence

_SOURCES = {
    "journal_snapshot",
    "external_monitor",
    "alert_receipts",
    "backup_receipts",
}


def _day(value: str) -> str:
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise argparse.ArgumentTypeError("day 必须为 YYYY-MM-DD") from exc


def build_external_daily_source(
    *,
    day: str,
    source: str,
    artifacts: list[object],
    signing_key_id: str,
) -> dict:
    if (
        source not in _SOURCES
        or not artifacts
        or not signing_key_id.strip()
        or any(
            not isinstance(item, dict)
            or set(item) != {"sha256", "bytes_base64"}
            or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"]))
            or not isinstance(item["bytes_base64"], str)
            for item in artifacts
        )
    ):
        raise ValueError("external daily source/source artifacts/key id 非法")
    date.fromisoformat(day)
    return {
        "version": 1,
        "action": "attest-daily-external-source-artifacts",
        "day": day,
        "source": source,
        "signing_key_id": signing_key_id,
        "artifacts": artifacts,
        "all_signatures_valid": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--day", required=True, type=_day)
    parser.add_argument("--source", required=True, choices=sorted(_SOURCES))
    parser.add_argument(
        "--artifact",
        required=True,
        action="append",
        type=Path,
    )
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--secret-env", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise RuntimeError("拒绝覆盖 external daily source artifact")
    key_info = args.private_key.lstat()
    if (
        not stat.S_ISREG(key_info.st_mode)
        or args.private_key.is_symlink()
        or stat.S_IMODE(key_info.st_mode) != 0o600
        or key_info.st_size <= 0
    ):
        raise RuntimeError("external source 私钥必须为 owner-only 0600 普通文件")
    forbidden = tuple(os.environ.get(name, "") for name in args.secret_env)
    artifacts = []
    for path in args.artifact:
        payload = path.read_bytes()
        scan_json_evidence(payload, forbidden_values=forbidden)
        artifacts.append({
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes_base64": base64.b64encode(payload).decode("ascii"),
        })
    signed = sign_ed25519_payload(
        build_external_daily_source(
            day=args.day,
            source=args.source,
            artifacts=artifacts,
            signing_key_id=args.signing_key_id,
        ),
        args.private_key,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            signed,
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
