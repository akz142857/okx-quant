#!/usr/bin/env python3
"""Sign an independently reviewed end-to-end empty-host restore claim."""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.infrastructure.immutable_bundle import verify_locked_object
from okx_quant.ops.empty_host_restore import (
    validate_empty_host_restore_claims,
)


def _aware_datetime(raw: str) -> datetime:
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "时间必须是 ISO-8601"
        ) from exc
    if value.tzinfo is None or value.utcoffset() is None:
        raise argparse.ArgumentTypeError("时间必须带时区")
    return value.astimezone(UTC)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--evidence-key-id", required=True)
    parser.add_argument(
        "--minimum-retain-until",
        required=True,
        type=_aware_datetime,
    )
    parser.add_argument("--kms-key-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise RuntimeError(f"拒绝覆盖 empty-host evidence: {args.output}")
    if (
        not args.request.is_file()
        or args.request.is_symlink()
        or args.request.stat().st_size <= 0
        or args.request.stat().st_size > 1_048_576
    ):
        raise ValueError("empty-host request 必须是受控普通文件")
    request = json.loads(args.request.read_text(encoding="utf-8"))
    signer_fields = {
        "evidence_key_id",
        "exact_version_verified_at",
        "minimum_retain_until",
        "kms_key_id",
    }
    if (
        not isinstance(request, dict)
        or signer_fields & set(request)
    ):
        raise ValueError("empty-host request schema 非法")
    verified_at = time.time()
    claims = {
        **request,
        "evidence_key_id": args.evidence_key_id,
        "exact_version_verified_at": verified_at,
        "minimum_retain_until": (
            args.minimum_retain_until.astimezone(UTC).isoformat()
        ),
        "kms_key_id": args.kms_key_id,
    }
    validate_empty_host_restore_claims(
        claims,
        expected_account_id=str(claims.get("account_id", "")),
        expected_release_identity=str(
            claims.get("release_identity", "")
        ),
        expected_config_sha256=str(claims.get("config_sha256", "")),
        expected_deployment_unit=str(
            claims.get("deployment_unit", "")
        ),
        expected_soak_epoch_id=str(
            claims.get("soak_epoch_id", "")
        ),
        expected_key_id=args.evidence_key_id,
        now=verified_at,
    )
    verify_locked_object(
        object_uri=claims["archive_uri"],
        version_id=claims["archive_version_id"],
        expected_sha256=claims["archive_sha256"],
        expected_bytes=claims["archive_bytes"],
        minimum_retain_until=args.minimum_retain_until,
        expected_kms_key_id=args.kms_key_id,
    )
    verify_locked_object(
        object_uri=claims["manifest_uri"],
        version_id=claims["manifest_version_id"],
        expected_sha256=claims["manifest_sha256"],
        expected_bytes=claims["manifest_bytes"],
        minimum_retain_until=args.minimum_retain_until,
        expected_kms_key_id=args.kms_key_id,
    )
    artifact = sign_ed25519_payload(claims, args.private_key)
    if (
        verify_ed25519_artifact(
            artifact,
            args.public_key,
            label="empty-host restore evidence",
        )
        != claims
    ):
        raise RuntimeError("empty-host evidence 签名回验失败")
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
