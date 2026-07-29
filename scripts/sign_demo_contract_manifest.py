#!/usr/bin/env python3
"""由独立证据身份补齐并签署 Demo contract immutable manifest。"""

from __future__ import annotations

import argparse
import json
import stat
from pathlib import Path

from okx_quant.infrastructure.evidence import (
    complete_demo_contract_manifest,
    sign_ed25519_payload,
    validate_demo_contract_manifest_payload,
)


def _safe_input(path: Path, label: str, *, private: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SystemExit(f"{label} 不存在") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size <= 0:
        raise SystemExit(f"{label} 必须是非空普通文件且不能是符号链接")
    if private and info.st_mode & 0o077:
        raise SystemExit(f"{label} 权限过宽；必须仅 owner 可访问")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--evidence-uri", required=True)
    parser.add_argument("--evidence-version-id", required=True)
    parser.add_argument("--fixture-uri", required=True)
    parser.add_argument("--fixture-version-id", required=True)
    parser.add_argument("--retain-until", required=True)
    parser.add_argument("--kms-key-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    _safe_input(args.request, "manifest request")
    _safe_input(args.private_key, "签名私钥", private=True)
    if args.output.exists():
        raise SystemExit(f"拒绝覆盖既有 signed manifest: {args.output}")
    request = json.loads(args.request.read_text(encoding="utf-8"))
    validate_demo_contract_manifest_payload(
        request,
        require_immutable=False,
    )
    payload = complete_demo_contract_manifest(
        request,
        evidence_uri=args.evidence_uri,
        evidence_version_id=args.evidence_version_id,
        fixture_uri=args.fixture_uri,
        fixture_version_id=args.fixture_version_id,
        retain_until=args.retain_until,
        kms_key_id=args.kms_key_id,
        signing_key_id=args.signing_key_id,
    )
    artifact = sign_ed25519_payload(payload, args.private_key)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
