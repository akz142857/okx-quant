#!/usr/bin/env python3
"""由独立 monitor 与 risk approver 双签正式 Demo soak epoch。"""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.research.demo_soak import validate_soak_epoch


def _private_key(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size <= 0:
        raise SystemExit(f"{label} 必须是非空普通文件且不能为符号链接")
    if path.stat().st_mode & 0o077:
        raise SystemExit(f"{label} 权限过宽；必须仅 owner 可访问")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--monitor-private-key", required=True, type=Path)
    parser.add_argument("--risk-private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    _private_key(args.monitor_private_key, "monitor private key")
    _private_key(args.risk_private_key, "risk private key")
    if args.output.exists():
        raise SystemExit(f"拒绝覆盖既有 soak epoch: {args.output}")
    payload = validate_soak_epoch(
        json.loads(args.request.read_text(encoding="utf-8"))
    )
    current = int(time.time())
    started_at = datetime.fromisoformat(payload["started_at"]).astimezone(UTC)
    if (
        not payload["issued_at"] - 5 <= current <= payload["issued_at"] + 300
        or current >= int(started_at.timestamp())
    ):
        raise SystemExit("soak epoch 必须在短效 request 窗口内且正式开始前完成双签")
    monitor_fingerprint = ed25519_public_key_fingerprint(
        args.monitor_private_key,
        private_key=True,
    )
    risk_fingerprint = ed25519_public_key_fingerprint(
        args.risk_private_key,
        private_key=True,
    )
    if monitor_fingerprint == risk_fingerprint:
        raise SystemExit("monitor/risk private key 派生为同一公钥")
    if (
        monitor_fingerprint != payload["monitor_key_fingerprint"]
        or risk_fingerprint != payload["risk_key_fingerprint"]
    ):
        raise SystemExit("monitor/risk private key 与 epoch request 指纹不匹配")
    monitor = sign_ed25519_payload(payload, args.monitor_private_key)
    risk = sign_ed25519_payload(payload, args.risk_private_key)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "payload": payload,
                "monitor_signature": monitor["signature"],
                "risk_signature": risk["signature"],
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
