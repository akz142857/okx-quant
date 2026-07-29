#!/usr/bin/env python3
"""Drop a daily alert challenge request for the runtime single writer."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import uuid
from datetime import UTC, date, datetime
from pathlib import Path

from okx_quant.ops.alert_control import build_challenge_request


def _atomic_request(inbox: Path, payload: dict) -> Path:
    inbox.mkdir(parents=True, exist_ok=True)
    output = inbox / f"challenge-{uuid.uuid4().hex}.json"
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
    parser.add_argument("--inbox", required=True, type=Path)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument(
        "--role",
        required=True,
        choices=("shadow", "active", "chaos"),
    )
    parser.add_argument("--day", type=date.fromisoformat)
    args = parser.parse_args()
    challenge_day = args.day or datetime.now(UTC).date()
    request = build_challenge_request(
        account_id=args.expected_account_id,
        role=args.role,
        day=challenge_day.isoformat(),
    )
    output = _atomic_request(args.inbox, request)
    print(json.dumps(
        {
            "request": str(output),
            "day": challenge_day.isoformat(),
        },
        ensure_ascii=False,
        sort_keys=True,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
