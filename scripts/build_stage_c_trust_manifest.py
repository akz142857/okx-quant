#!/usr/bin/env python3
"""Build the strict Stage-C production trust configuration.

Expected key layout:

  <key-root>/global/parser-signer-public.pem
  <key-root>/<scenario>/registrar-public.pem
  <key-root>/<scenario>/capability-authority-public.pem
  <key-root>/<scenario>/sources/<role>-public.pem

The builder computes all hashes, fingerprints and exact role sets.  It never
accepts a deployment-attested flag and refuses to overwrite an existing file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from okx_quant.application.approval import canonical_bytes
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
)
from okx_quant.ops.demo_chaos_evidence import RAW_RECOMPUTED_SCENARIOS
from okx_quant.ops.stage_c_chaos_protocol import (
    PARSER_MANIFEST_SHA256,
    driver_contract_document,
    required_source_roles,
)


def _safe_existing_path(
    path: Path,
    *,
    label: str,
    directory: bool,
) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} 必须是绝对路径")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} 不存在") from exc
    if resolved != path or path.is_symlink():
        raise ValueError(f"{label} 不允许符号链接或非规范路径")
    if (path.is_dir() if directory else path.is_file()) is not True:
        raise ValueError(f"{label} 类型非法")
    if path.stat().st_mode & 0o022:
        raise ValueError(f"{label} 不允许 group/world 写权限")
    return path


def _key_ref(path: Path, *, label: str) -> tuple[dict, str]:
    path = _safe_existing_path(path, label=label, directory=False)
    fingerprint = ed25519_public_key_fingerprint(path)
    return (
        {
            "path": str(path),
            "fingerprint_sha256": fingerprint,
        },
        fingerprint,
    )


def build_manifest(*, raw_events_dir: Path, key_root: Path) -> dict:
    raw_events_dir = _safe_existing_path(
        raw_events_dir,
        label="Stage-C raw events directory",
        directory=True,
    )
    key_root = _safe_existing_path(
        key_root,
        label="Stage-C key root",
        directory=True,
    )
    scenarios = {}
    fingerprint_owner: dict[str, str] = {}
    global_parser_signer = (
        key_root / "global" / "parser-signer-public.pem"
    )
    for scenario in sorted(RAW_RECOMPUTED_SCENARIOS):
        raw_path = _safe_existing_path(
            raw_events_dir / f"{scenario}.jsonl",
            label=f"{scenario} raw events",
            directory=False,
        )
        raw_bytes = raw_path.read_bytes()
        if not raw_bytes or len(raw_bytes) > 8 * 1024 * 1024:
            raise ValueError(f"{scenario} raw events 必须为 1..8MiB")
        scenario_root = key_root / scenario
        registrar, registrar_fingerprint = _key_ref(
            scenario_root / "registrar-public.pem",
            label=f"{scenario} registrar public key",
        )
        authority, authority_fingerprint = _key_ref(
            scenario_root / "capability-authority-public.pem",
            label=f"{scenario} capability authority public key",
        )
        sources = {}
        labeled_fingerprints = {
            f"{scenario}:registrar": registrar_fingerprint,
            f"{scenario}:capability_authority": authority_fingerprint,
        }
        for role in sorted(required_source_roles(scenario)):
            role_path = (
                global_parser_signer
                if role == "parser_signer"
                else scenario_root
                / "sources"
                / f"{role}-public.pem"
            )
            key, fingerprint = _key_ref(
                role_path,
                label=f"{scenario} source role {role}",
            )
            sources[role] = key
            labeled_fingerprints[f"{scenario}:{role}"] = fingerprint
        for label, fingerprint in labeled_fingerprints.items():
            if fingerprint in fingerprint_owner:
                previous = fingerprint_owner[fingerprint]
                repeated_parser_signer = (
                    previous.endswith(":parser_signer")
                    and label.endswith(":parser_signer")
                )
                if not repeated_parser_signer:
                    raise ValueError(
                        "Stage-C trust root 复用: "
                        f"{previous}, {label}"
                    )
            fingerprint_owner[fingerprint] = label
        scenarios[scenario] = {
            "trust_state": "TRUST_CONFIGURED",
            "driver_contract_sha256": hashlib.sha256(
                canonical_bytes(driver_contract_document(scenario))
            ).hexdigest(),
            "raw_events_file": raw_path.name,
            "raw_events_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "raw_events_bytes": len(raw_bytes),
            "registrar_public_key": registrar,
            "capability_authority_public_key": authority,
            "source_public_keys": sources,
        }
    return {
        "version": 1,
        "action": "configure-stage-c-production-trust-v1",
        "parser_manifest_sha256": PARSER_MANIFEST_SHA256,
        "raw_events_dir": str(raw_events_dir),
        "scenarios": scenarios,
    }


def write_manifest(path: Path, value: dict) -> None:
    if not path.is_absolute():
        raise ValueError("Stage-C trust manifest output 必须是绝对路径")
    _safe_existing_path(
        path.parent,
        label="Stage-C trust manifest output directory",
        directory=True,
    )
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--raw-events-dir",
        required=True,
        type=Path,
    )
    parser.add_argument("--key-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    manifest = build_manifest(
        raw_events_dir=args.raw_events_dir,
        key_root=args.key_root,
    )
    write_manifest(args.output, manifest)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
