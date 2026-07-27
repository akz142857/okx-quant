#!/usr/bin/env python3
"""Last-resort Page notification for a failed systemd production unit."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import requests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--webhook-env", default="OKX_QUANT_ALERT_WEBHOOK")
    parser.add_argument("--env-file", type=Path)
    args = parser.parse_args()
    if args.env_file:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from main import load_env_file

        load_env_file(str(args.env_file))
    webhook = os.environ.get(args.webhook_env, "")
    if not webhook:
        raise SystemExit(f"缺少 Page webhook 环境变量: {args.webhook_env}")
    response = requests.post(
        webhook,
        json={
            "event_name": "page.systemd_unit_failed",
            "severity": "critical",
            "service": args.service,
        },
        timeout=10,
    )
    response.raise_for_status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
