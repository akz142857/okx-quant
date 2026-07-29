#!/usr/bin/env python3
"""Verify the independent external Demo deployment attestation.

This command is intentionally verification-only.  It never upgrades the
Stage-C inventory and never creates an attestation from local files.
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

# Keep ``python scripts/<command>.py`` working from a clean checkout.  Python
# otherwise puts only ``scripts/`` on sys.path for a direct script invocation.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from okx_quant.ops.external_deployment_attestation import (  # noqa: E402
    verify_signed_external_deployment_attestation,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--expected-candidate-sha256", default="")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    if not args.attestation.is_file() or args.attestation.is_symlink():
        raise SystemExit("attestation 必须是非符号链接普通文件")
    try:
        artifact = json.loads(args.attestation.read_text(encoding="utf-8"))
        claims = verify_signed_external_deployment_attestation(
            artifact,
            args.public_key,
            now=None if args.offline else datetime.now(UTC),
        )
        expected = args.expected_candidate_sha256.lower()
        if expected and claims["candidate_sha256"] != expected:
            raise ValueError("candidate deployment identity SHA-256 不匹配")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"拒绝 external deployment attestation: {exc}") from exc
    print(json.dumps({
        "verified": True,
        "schema": claims["schema"],
        "candidate_sha256": claims["candidate_sha256"],
        "account_roles": sorted(item["role"] for item in claims["accounts"]),
        "failure_domain_roles": sorted(item["role"] for item in claims["failure_domains"]),
        "responsibility_roles": sorted(item["role"] for item in claims["responsibilities"]),
        "evidence_roles": sorted(claims["evidence"]),
        "offline": args.offline,
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
