#!/usr/bin/env python3
"""Independently GET and attest exact WORM versions for WP4/WP5 drills."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.infrastructure.immutable_bundle import (
    validate_bundle_manifest,
    verify_bundle_artifact,
    verify_locked_object,
)
from okx_quant.ops.demo_chaos_evidence import (
    RAW_RECOMPUTED_SCENARIOS,
    build_independent_drill_readback_claims,
    scenario_names,
    validate_drill_receipt,
    verify_independent_raw_observation_artifact,
)
from okx_quant.ops.stage_c_chaos_protocol import (
    build_stage_c_drill_receipt,
    derive_stage_c_raw_observation,
    required_source_roles,
)


def _aware_datetime(raw: str) -> datetime:
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("时间必须是 ISO-8601") from exc
    if value.tzinfo is None or value.utcoffset() is None:
        raise argparse.ArgumentTypeError("时间必须带时区")
    return value.astimezone(UTC)


def _assignments(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for raw in values:
        name, separator, path = raw.partition("=")
        if (
            not separator
            or not name.strip()
            or not path.strip()
            or name in result
        ):
            raise ValueError(f"非法/重复 source key assignment: {raw}")
        result[name] = Path(path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True, choices=scenario_names())
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-uri", required=True)
    parser.add_argument("--manifest-version-id", required=True)
    parser.add_argument(
        "--bundle-signing-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--independent-verifier-private-key",
        required=True,
        type=Path,
    )
    parser.add_argument("--independent-verifier-key-id", required=True)
    parser.add_argument(
        "--minimum-retain-until",
        required=True,
        type=_aware_datetime,
    )
    parser.add_argument("--kms-key-id", required=True)
    parser.add_argument("--registrar-public-key", type=Path)
    parser.add_argument("--capability-authority-public-key", type=Path)
    parser.add_argument("--raw-observer-public-key", type=Path)
    parser.add_argument(
        "--source-public-key",
        action="append",
        default=[],
        metavar="ROLE=PATH",
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise RuntimeError(f"拒绝覆盖 independent readback: {args.output}")
    if (
        not args.manifest.is_file()
        or args.manifest.is_symlink()
        or args.manifest.stat().st_size <= 0
        or args.manifest.stat().st_size > 2 * 1024 * 1024
    ):
        raise RuntimeError("signed manifest 必须是 2MiB 内普通文件")
    manifest_bytes = args.manifest.read_bytes()
    artifact = json.loads(manifest_bytes)
    manifest = validate_bundle_manifest(
        verify_ed25519_artifact(
            artifact,
            args.bundle_signing_public_key,
            label=f"{args.scenario} immutable drill bundle",
        )
    )
    exact_manifest_bytes = verify_locked_object(
        object_uri=args.manifest_uri,
        version_id=args.manifest_version_id,
        expected_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        expected_bytes=len(manifest_bytes),
        minimum_retain_until=args.minimum_retain_until,
        expected_kms_key_id=args.kms_key_id,
    )
    if exact_manifest_bytes != manifest_bytes:
        raise RuntimeError("WORM exact-version manifest bytes 与本地签名制品不一致")
    components = verify_bundle_artifact(
        artifact,
        public_key=args.bundle_signing_public_key,
        expected_identity=manifest["identity"],
        minimum_retain_until=args.minimum_retain_until,
        expected_kms_key_id=args.kms_key_id,
    )
    if set(components) != {"drill-result"}:
        raise RuntimeError("drill WORM bundle 必须精确包含 drill-result")
    result_bytes = components["drill-result"]
    receipt = validate_drill_receipt(json.loads(result_bytes))
    if receipt["scenario"] != args.scenario:
        raise RuntimeError("WORM drill-result scenario 不匹配")
    raw_observation_source = None
    if args.scenario in RAW_RECOMPUTED_SCENARIOS:
        if (
            args.registrar_public_key is None
            or args.capability_authority_public_key is None
            or args.raw_observer_public_key is None
        ):
            raise RuntimeError(
                "raw-recomputed scenario 缺少 registrar/capability/"
                "raw-observer 公钥"
            )
        source_public_keys = _assignments(args.source_public_key)
        if set(source_public_keys) != set(
            required_source_roles(args.scenario)
        ):
            raise RuntimeError(
                "raw-recomputed scenario 的 source public keys "
                "不完整或含多余角色"
            )
        trust_fingerprints = {
            ed25519_public_key_fingerprint(
                args.bundle_signing_public_key
            ),
            ed25519_public_key_fingerprint(
                args.independent_verifier_private_key,
                private_key=True,
            ),
            ed25519_public_key_fingerprint(
                args.registrar_public_key
            ),
            ed25519_public_key_fingerprint(
                args.capability_authority_public_key
            ),
            *(
                ed25519_public_key_fingerprint(path)
                for path in source_public_keys.values()
            ),
        }
        if len(trust_fingerprints) != len(source_public_keys) + 4:
            raise RuntimeError(
                "publisher/readback verifier/registrar/capability/"
                "native sources 必须完全分钥"
            )
        if (
            source_public_keys["parser_signer"]
            != args.raw_observer_public_key
            and ed25519_public_key_fingerprint(
                source_public_keys["parser_signer"]
            )
            != ed25519_public_key_fingerprint(
                args.raw_observer_public_key
            )
        ):
            raise RuntimeError(
                "raw observer public key 与 parser_signer source key 不同"
            )
        verify_independent_raw_observation_artifact(
            receipt["execution"]["raw_observation"],
            receipt=receipt,
            observer_public_key=args.raw_observer_public_key,
            publisher_key=args.bundle_signing_public_key,
        )
        raw_observation_source = receipt["execution"][
            "raw_observation"
        ]["payload"]["source"]
        raw_bytes = verify_locked_object(
            object_uri=raw_observation_source["object_uri"],
            version_id=raw_observation_source["version_id"],
            expected_sha256=raw_observation_source["sha256"],
            expected_bytes=raw_observation_source["bytes"],
            minimum_retain_until=args.minimum_retain_until,
            expected_kms_key_id=args.kms_key_id,
        )
        derived = derive_stage_c_raw_observation(
            raw_bytes,
            scenario=args.scenario,
            registrar_public_key=args.registrar_public_key,
            capability_authority_public_key=(
                args.capability_authority_public_key
            ),
            provider_public_key=source_public_keys["provider"],
            raw_observer_public_key=args.raw_observer_public_key,
            source_public_keys=source_public_keys,
            barrier_attestor_public_key=source_public_keys.get(
                "barrier_attestor"
            ),
            kill_controller_public_key=source_public_keys.get(
                "kill_controller"
            ),
            require_production_evidence=True,
        )
        recomputed_receipt = build_stage_c_drill_receipt(
            derived,
            raw_observation_artifact=receipt["execution"][
                "raw_observation"
            ],
        )
        if recomputed_receipt != receipt:
            raise RuntimeError(
                "独立 parser 从 WORM raw bytes 重算的 receipt 不一致"
            )
    component = manifest["components"]["drill-result"]
    claims = build_independent_drill_readback_claims(
        scenario=args.scenario,
        manifest_uri=args.manifest_uri,
        manifest_version_id=args.manifest_version_id,
        manifest_bytes=manifest_bytes,
        manifest_signing_public_key=args.bundle_signing_public_key,
        verifier_key_id=args.independent_verifier_key_id,
        verifier_private_key=args.independent_verifier_private_key,
        result_uri=component["object_uri"],
        result_version_id=component["version_id"],
        result_bytes=result_bytes,
        verified_at=datetime.now(UTC),
        raw_observation_source=raw_observation_source,
        raw_recomputed=args.scenario in RAW_RECOMPUTED_SCENARIOS,
    )
    signed = sign_ed25519_payload(
        claims,
        args.independent_verifier_private_key,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(signed, ensure_ascii=False, indent=2, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
