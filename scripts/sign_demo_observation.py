#!/usr/bin/env python3
"""由独立监控身份签署单日 demo 观测锚。"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from okx_quant.application.approval import canonical_bytes
from okx_quant.research.admission import _OBSERVATION_ANCHOR_KEYS


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        not args.request.is_file()
        or args.request.is_symlink()
        or not args.private_key.is_file()
        or args.private_key.is_symlink()
    ):
        raise SystemExit("request/private-key 必须是普通文件且不能是符号链接")
    if args.private_key.stat().st_mode & 0o077:
        raise SystemExit("监控签名私钥权限过宽；必须仅 owner 可读写")
    claims = json.loads(args.request.read_text(encoding="utf-8"))
    if (
        not isinstance(claims, dict)
        or set(claims) != _OBSERVATION_ANCHOR_KEYS
        or claims.get("version") != 1
        or claims.get("action") != "anchor-demo-day"
        or not str(claims.get("monitor", "")).strip()
    ):
        raise SystemExit("request 不是严格的 demo 日观测锚请求")
    if (
        type(claims["unexplained_mismatches"]) is not int
        or claims["unexplained_mismatches"] < 0
    ):
        raise SystemExit("unexplained_mismatches 必须是非负整数")
    now = datetime.now(UTC)
    try:
        observed_day = date.fromisoformat(str(claims["day"]))
        started_raw = datetime.fromisoformat(
            str(claims["observation_started_at"])
        )
        ended_raw = datetime.fromisoformat(
            str(claims["observation_ended_at"])
        )
        if (
            started_raw.tzinfo is None
            or started_raw.utcoffset() is None
            or ended_raw.tzinfo is None
            or ended_raw.utcoffset() is None
        ):
            raise ValueError("timezone required")
        started = started_raw.astimezone(UTC)
        ended = ended_raw.astimezone(UTC)
        issued_at = int(claims["issued_at"])
    except (TypeError, ValueError) as exc:
        raise SystemExit("demo 日观测锚时间字段非法") from exc
    if (
        observed_day not in {now.date(), now.date() - timedelta(days=1)}
        or ended <= started
        or ended - started < timedelta(hours=20)
        or ended > now + timedelta(minutes=5)
        or now - ended > timedelta(days=1, minutes=5)
        or abs(time.time() - issued_at) > 300
    ):
        raise SystemExit("拒绝签署历史回填、未来或观测窗口不足的 demo 日证据")
    with tempfile.NamedTemporaryFile() as message_file:
        message_file.write(canonical_bytes(claims))
        message_file.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(args.private_key),
                "-in",
                message_file.name,
            ],
            capture_output=True,
            timeout=5,
            check=False,
        )
    if result.returncode != 0 or len(result.stdout) != 64:
        sys.stderr.buffer.write(result.stderr)
        raise SystemExit("Ed25519 签名失败")
    if args.output.exists():
        raise SystemExit(f"拒绝覆盖既有 anchor: {args.output}")
    args.output.write_text(
        json.dumps(
            {
                "payload": claims,
                "signature": base64.b64encode(result.stdout).decode("ascii"),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
