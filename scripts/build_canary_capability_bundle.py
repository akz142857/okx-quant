#!/usr/bin/env python3
"""Assemble and sign the short-lived 12-producer Canary readiness root."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import tempfile
import time
import uuid
from pathlib import Path

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.research.canary import (
    CANARY_CAPABILITY_MAX_LIFETIME_SECONDS,
    canary_readiness_id,
    identity_sha256,
    validate_canary_capability_bundle,
    verify_transition,
)
from okx_quant.research.demo_soak import (
    CANARY_SOURCE_PRODUCER_NAMES,
    canary_source_producer_inventory_sha256,
    verify_dual_signed_soak_epoch,
)

_MANIFEST_PATH_KEYS = {
    "soak_epoch",
    "epoch_monitor_public_key",
    "epoch_risk_public_key",
    "transition",
    "operator_public_key",
    "risk_public_key",
    "deployment_verifier",
    "iam_public_key",
    "worm_readback_public_key",
    "deployment_verifier_public_key",
}
_MANIFEST_MAP_KEYS = {
    "producer_readiness",
    "source_public_key",
    "iam_sts_receipt",
    "worm_readback_receipt",
}
_MANIFEST_VALUE_MAP_KEYS = {"worm_version_id"}
_MANIFEST_KEYS = (
    _MANIFEST_PATH_KEYS
    | _MANIFEST_MAP_KEYS
    | _MANIFEST_VALUE_MAP_KEYS
)


def _named_path(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or name not in CANARY_SOURCE_PRODUCER_NAMES:
        raise argparse.ArgumentTypeError("必须使用 PRODUCER=/absolute/path")
    return name, Path(path)


def _named_value(value: str) -> tuple[str, str]:
    name, separator, raw = value.partition("=")
    if (
        not separator
        or name not in CANARY_SOURCE_PRODUCER_NAMES
        or not raw.strip()
    ):
        raise argparse.ArgumentTypeError(
            "必须使用 PRODUCER=non-empty-value"
        )
    return name, raw


def _secure_bytes(path: Path, *, owner_only: bool = False) -> bytes:
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_size <= 0
        or info.st_size > 16 * 1024 * 1024
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (
            owner_only
            and (
                not info.st_mode & stat.S_IRUSR
                or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            )
        )
    ):
        raise ValueError(f"不安全或超限文件: {path}")
    return path.read_bytes()


def _exact_map(rows: list[tuple[str, Path]], label: str) -> dict[str, Path]:
    mapped = dict(rows)
    if (
        len(mapped) != len(rows)
        or set(mapped) != CANARY_SOURCE_PRODUCER_NAMES
    ):
        raise ValueError(f"{label} 必须精确覆盖 12 producers")
    return mapped


def _exact_value_map(
    rows: list[tuple[str, str]],
    label: str,
) -> dict[str, str]:
    mapped = dict(rows)
    if (
        len(mapped) != len(rows)
        or set(mapped) != CANARY_SOURCE_PRODUCER_NAMES
    ):
        raise ValueError(f"{label} 必须精确覆盖 12 producers")
    return mapped


def _atomic_new(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"拒绝覆盖 readiness bundle: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        raw = (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("readiness bundle write 无进展")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _load_manifest(path: Path) -> dict:
    value = json.loads(_secure_bytes(path))
    if not isinstance(value, dict) or set(value) != _MANIFEST_KEYS:
        raise ValueError("capability manifest schema 非法")
    result: dict = {}
    for name in _MANIFEST_PATH_KEYS:
        candidate = Path(value[name])
        if not candidate.is_absolute():
            raise ValueError(f"capability manifest {name} 必须是绝对路径")
        result[name] = candidate
    for name in _MANIFEST_MAP_KEYS:
        mapping = value[name]
        if (
            not isinstance(mapping, dict)
            or set(mapping) != CANARY_SOURCE_PRODUCER_NAMES
        ):
            raise ValueError(f"capability manifest {name} 必须精确覆盖 12 producers")
        paths = []
        for producer_name, raw_path in mapping.items():
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                raise ValueError(
                    f"capability manifest {name}.{producer_name} 必须是绝对路径"
                )
            paths.append((producer_name, candidate))
        result[name] = paths
    for name in _MANIFEST_VALUE_MAP_KEYS:
        mapping = value[name]
        if (
            not isinstance(mapping, dict)
            or set(mapping) != CANARY_SOURCE_PRODUCER_NAMES
            or any(
                not isinstance(item, str) or not item.strip()
                for item in mapping.values()
            )
        ):
            raise ValueError(
                f"capability manifest {name} 必须精确覆盖 12 producers"
            )
        result[name] = list(mapping.items())
    return result


def _check_inputs(args: argparse.Namespace) -> None:
    for name in _MANIFEST_PATH_KEYS:
        _secure_bytes(getattr(args, name))
    for name in _MANIFEST_MAP_KEYS:
        mapping = _exact_map(
            getattr(args, name),
            f"capability manifest {name}",
        )
        for path in mapping.values():
            _secure_bytes(path)
    _exact_value_map(
        args.worm_version_id,
        "capability manifest WORM version IDs",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--soak-epoch", type=Path)
    parser.add_argument("--epoch-monitor-public-key", type=Path)
    parser.add_argument("--epoch-risk-public-key", type=Path)
    parser.add_argument("--transition", type=Path)
    parser.add_argument("--operator-public-key", type=Path)
    parser.add_argument("--risk-public-key", type=Path)
    parser.add_argument(
        "--producer-readiness",
        action="append",
        type=_named_path,
    )
    parser.add_argument(
        "--source-public-key",
        action="append",
        type=_named_path,
    )
    parser.add_argument(
        "--iam-sts-receipt",
        action="append",
        type=_named_path,
    )
    parser.add_argument(
        "--worm-readback-receipt",
        action="append",
        type=_named_path,
        help="独立 WORM exact-GET verifier 的签名 receipt",
    )
    parser.add_argument(
        "--worm-version-id",
        action="append",
        type=_named_value,
    )
    parser.add_argument("--deployment-verifier", type=Path)
    parser.add_argument("--iam-public-key", type=Path)
    parser.add_argument("--worm-readback-public-key", type=Path)
    parser.add_argument("--deployment-verifier-public-key", type=Path)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-inputs-only", action="store_true")
    args = parser.parse_args()
    if args.manifest is not None:
        if any(
            getattr(args, name) is not None
            for name in _MANIFEST_KEYS
        ):
            parser.error("--manifest 不得与展开的 capability 输入参数混用")
        for name, value in _load_manifest(args.manifest).items():
            setattr(args, name, value)
    elif any(
        getattr(args, name) is None
        for name in _MANIFEST_KEYS
    ):
        parser.error("必须提供 --manifest 或完整展开的 capability 输入参数")
    if args.check_inputs_only:
        _check_inputs(args)
        print("Canary capability stage-2 inputs: READY")
        return 0
    if args.private_key is None or args.output is None:
        parser.error("构建 capability 必须提供 --private-key 与 --output")

    epoch = verify_dual_signed_soak_epoch(
        json.loads(_secure_bytes(args.soak_epoch)),
        monitor_public_key=args.epoch_monitor_public_key,
        risk_public_key=args.epoch_risk_public_key,
    )
    transition = verify_transition(
        json.loads(_secure_bytes(args.transition)),
        operator_public_key=args.operator_public_key,
        risk_public_key=args.risk_public_key,
    )
    readiness_paths = _exact_map(
        args.producer_readiness,
        "producer readiness",
    )
    source_keys = _exact_map(args.source_public_key, "source public keys")
    iam_paths = _exact_map(args.iam_sts_receipt, "IAM receipts")
    worm_paths = _exact_map(
        args.worm_readback_receipt,
        "WORM readback receipts",
    )
    worm_versions = _exact_value_map(
        args.worm_version_id,
        "WORM version IDs",
    )
    deployment_verifier_raw = _secure_bytes(args.deployment_verifier)
    inventory = transition["source_producer_inventory"]
    inventory_sha256 = canary_source_producer_inventory_sha256(
        inventory
    )
    target = transition["target_deployment_identity"]
    now = int(time.time())
    producer_entries = {}
    expires_at: int | None = None
    for name in sorted(CANARY_SOURCE_PRODUCER_NAMES):
        source_key = _secure_bytes(source_keys[name])
        readiness_raw = _secure_bytes(readiness_paths[name])
        readiness_artifact = json.loads(readiness_raw)
        with tempfile.NamedTemporaryFile() as source_key_file:
            source_key_file.write(source_key)
            source_key_file.flush()
            source_fingerprint = ed25519_public_key_fingerprint(
                source_key_file.name
            )
            readiness = verify_ed25519_artifact(
                readiness_artifact,
                source_key_file.name,
                label=f"Canary readiness {name}",
            )
        if source_fingerprint != inventory[name]["source_key_fingerprint"]:
            raise ValueError(f"{name} source key 未绑定 inventory")
        if expires_at is None:
            expires_at = readiness["expires_at"]
        elif expires_at != readiness["expires_at"]:
            raise ValueError("12 producer readiness expiry 必须一致")
        iam_raw = _secure_bytes(iam_paths[name])
        worm_receipt_raw = _secure_bytes(worm_paths[name])
        producer_entries[name] = {
            "source_public_key_pem_base64": base64.b64encode(
                source_key
            ).decode("ascii"),
            "source_key_fingerprint": source_fingerprint,
            "producer_attestation_bytes_base64": base64.b64encode(
                readiness_raw
            ).decode("ascii"),
            "producer_attestation_sha256": hashlib.sha256(
                readiness_raw
            ).hexdigest(),
            "iam_sts_receipt_bytes_base64": base64.b64encode(
                iam_raw
            ).decode("ascii"),
            "iam_sts_receipt_sha256": hashlib.sha256(
                iam_raw
            ).hexdigest(),
            "pre_start_source_artifact_sha256": (
                transition["pre_start_checks"][name][
                    "evidence_sha256"
                ]
                if name in transition["pre_start_checks"]
                else ""
            ),
            "worm_readback_receipt_bytes_base64": base64.b64encode(
                worm_receipt_raw
            ).decode("ascii"),
            "worm_readback_receipt_sha256": hashlib.sha256(
                worm_receipt_raw
            ).hexdigest(),
            "worm_version_id": worm_versions[name],
        }
    if (
        expires_at is None
        or not 60
        <= expires_at - now
        <= CANARY_CAPABILITY_MAX_LIFETIME_SECONDS
    ):
        raise ValueError("readiness expiry 非法")
    capability_fingerprint = ed25519_public_key_fingerprint(
        args.private_key,
        private_key=True,
    )
    iam_key_bytes = _secure_bytes(args.iam_public_key)
    iam_fingerprint = ed25519_public_key_fingerprint(
        args.iam_public_key
    )
    worm_key_bytes = _secure_bytes(args.worm_readback_public_key)
    worm_fingerprint = ed25519_public_key_fingerprint(
        args.worm_readback_public_key
    )
    deployment_key_bytes = _secure_bytes(
        args.deployment_verifier_public_key
    )
    deployment_fingerprint = ed25519_public_key_fingerprint(
        args.deployment_verifier_public_key
    )
    payload = {
        "version": 1,
        "action": "attest-canary-external-producer-capabilities",
        "readiness_id": canary_readiness_id(
            demo_soak_epoch_id=epoch["soak_epoch_id"],
            target_deployment_identity_sha256=identity_sha256(target),
            source_producer_inventory_sha256=inventory_sha256,
        ),
        "nonce": uuid.uuid4().hex,
        "issued_at": now,
        "expires_at": expires_at,
        "release_identity_sha256": identity_sha256(
            transition["release_identity"]
        ),
        "release_commit": transition["release_identity"]["git_commit"],
        "config_sha256": target["config_sha256"],
        "account_uid": target["account_uid"],
        "demo_soak_epoch_id": epoch["soak_epoch_id"],
        "target_deployment_identity_sha256": identity_sha256(target),
        "transition_sha256": identity_sha256(transition),
        "pre_start_challenge": transition["pre_start_challenge"],
        "source_producer_inventory": inventory,
        "source_producer_inventory_sha256": inventory_sha256,
        "capability_authority_key_fingerprint": capability_fingerprint,
        "iam_authority_key_fingerprint": iam_fingerprint,
        "worm_readback_authority_key_fingerprint": worm_fingerprint,
        "deployment_verifier_key_fingerprint": deployment_fingerprint,
        "deployment_verifier_artifact_bytes_base64": base64.b64encode(
            deployment_verifier_raw
        ).decode("ascii"),
        "deployment_verifier_artifact_sha256": hashlib.sha256(
            deployment_verifier_raw
        ).hexdigest(),
        "producers": producer_entries,
    }
    disallowed = {
        epoch["monitor_key_fingerprint"],
        epoch["risk_key_fingerprint"],
        epoch["observation_key_fingerprint"],
        *epoch["external_source_key_fingerprints"].values(),
        *(
            item["source_key_fingerprint"]
            for item in inventory.values()
        ),
        ed25519_public_key_fingerprint(args.operator_public_key),
        ed25519_public_key_fingerprint(args.risk_public_key),
        transition["post_start_verifier_key_fingerprint"],
    }
    validate_canary_capability_bundle(
        payload,
        epoch=epoch,
        transition=transition,
        capability_key_fingerprint=capability_fingerprint,
        iam_key_fingerprint=iam_fingerprint,
        iam_public_key_bytes=iam_key_bytes,
        worm_readback_key_fingerprint=worm_fingerprint,
        worm_readback_public_key_bytes=worm_key_bytes,
        deployment_verifier_key_fingerprint=(
            deployment_fingerprint
        ),
        deployment_verifier_public_key_bytes=deployment_key_bytes,
        disallowed_key_fingerprints=disallowed,
        now=now,
    )
    _secure_bytes(args.private_key, owner_only=True)
    _atomic_new(
        args.output,
        sign_ed25519_payload(payload, args.private_key),
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
