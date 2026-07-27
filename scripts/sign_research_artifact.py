#!/usr/bin/env python3
"""Sign a pre-registered research policy or independent stress-run result."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from okx_quant.application.approval import canonical_bytes

_POLICY_KEYS = {
    "version",
    "action",
    "policy_id",
    "commit_sha",
    "strategy_family_hash",
    "parameter_grid_hash",
    "stress_scenario_manifest_hash",
    "dataset_sources",
    "evaluation_started_at",
    "issued_at",
}
_ATTESTATION_KEYS = {
    "version",
    "action",
    "policy_id",
    "commit_sha",
    "dataset_hash",
    "cost_model_hash",
    "portfolio_evaluation_manifest_hash",
    "scenario_manifest_hash",
    "stress_evidence_sha256",
    "runner",
    "issued_at",
}


def _validate(claims: object) -> dict:
    if not isinstance(claims, dict) or claims.get("version") != 1:
        raise ValueError("research claims 版本或结构非法")
    action = claims.get("action")
    expected = (
        _POLICY_KEYS
        if action == "pre-register-research-policy"
        else _ATTESTATION_KEYS
        if action == "attest-stress-run"
        else set()
    )
    if not expected or set(claims) != expected:
        raise ValueError("research claims action/字段非法")
    now = datetime.now(UTC)
    issued_at = claims["issued_at"]
    if (
        type(issued_at) is not int
        or abs(time.time() - issued_at) > 300
        or not str(claims["policy_id"]).strip()
    ):
        raise ValueError("research claims 签发时间或 policy_id 非法")
    if action == "pre-register-research-policy":
        started = datetime.fromisoformat(
            str(claims["evaluation_started_at"])
        )
        if started.tzinfo is None or started.utcoffset() is None:
            raise ValueError("evaluation_started_at 必须包含时区")
        started = started.astimezone(UTC)
        if not now <= started <= now + timedelta(days=7):
            raise ValueError("研究 policy 只能预注册未来 7 日内的评估")
        sources = claims["dataset_sources"]
        if (
            not isinstance(sources, dict)
            or set(sources) != {"walk_forward", "portfolio"}
        ):
            raise ValueError("研究 policy dataset_sources 非法")
        for source in sources.values():
            if (
                not isinstance(source, dict)
                or set(source)
                != {"source_uri", "source_version_id", "source_sha256"}
                or not str(source["source_uri"]).startswith("s3://")
                or not str(source["source_version_id"]).strip()
            ):
                raise ValueError("研究 policy 必须绑定 exact S3 version")
    return claims


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
        or args.private_key.stat().st_mode & 0o077
    ):
        raise SystemExit(
            "request/private-key 必须是普通文件，私钥必须仅 owner 可访问"
        )
    claims = _validate(json.loads(args.request.read_text(encoding="utf-8")))
    with tempfile.NamedTemporaryFile() as message:
        message.write(canonical_bytes(claims))
        message.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(args.private_key),
                "-in",
                message.name,
            ],
            capture_output=True,
            timeout=5,
            check=False,
        )
    if result.returncode != 0 or len(result.stdout) != 64:
        raise SystemExit("research Ed25519 签名失败")
    if args.output.exists():
        raise SystemExit(f"拒绝覆盖既有 research artifact: {args.output}")
    artifact = {
        "payload": claims,
        "signature": base64.b64encode(result.stdout).decode("ascii"),
    }
    args.output.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(args.output, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
