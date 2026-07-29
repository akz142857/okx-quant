#!/usr/bin/env python3
"""Drop a signed alert receipt for ingestion by the runtime single writer."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import uuid
from pathlib import Path

from okx_quant.ops.alert_control import build_receipt_request


def _atomic_request(inbox: Path, payload: dict) -> Path:
    inbox.mkdir(parents=True, exist_ok=True)
    output = inbox / f"receipt-{uuid.uuid4().hex}.json"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".alert-request-",
        dir=inbox,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                payload,
                handle,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, output)
        parent_fd = os.open(inbox, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "kind",
        choices=("provider", "human-ack", "escalation"),
    )
    parser.add_argument("--inbox", required=True, type=Path)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    args = parser.parse_args()
    artifact_info = args.artifact.lstat()
    if (
        args.artifact.is_symlink()
        or not args.artifact.is_file()
        or artifact_info.st_size <= 0
        or artifact_info.st_size > 524_288
    ):
        raise RuntimeError("alert receipt 必须是 512KiB 内的普通文件")
    request = build_receipt_request(
        account_id=args.expected_account_id,
        kind=args.kind,
        artifact_bytes=args.artifact.read_bytes(),
    )
    output = _atomic_request(args.inbox, request)
    print(json.dumps(
        {"request": str(output), "kind": args.kind},
        ensure_ascii=False,
        sort_keys=True,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
