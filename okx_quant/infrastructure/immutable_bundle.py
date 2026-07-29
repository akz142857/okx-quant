"""Strict JSON evidence bundles published and read back by exact S3 version."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)

_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMPONENT_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}")
_FORBIDDEN_KEYS = {
    "apikey",
    "secret",
    "secretkey",
    "passphrase",
    "password",
    "privatekey",
    "token",
    "authorization",
}
_BUNDLE_KEYS = {
    "version",
    "action",
    "bundle_id",
    "kind",
    "created_at",
    "identity",
    "components",
    "retention",
    "signing_key_id",
}
_IDENTITY_KEYS = {
    "git_commit",
    "config_sha256",
    "account_uid",
    "environment",
    "unit",
    "soak_epoch_id",
    "phase",
}
_COMPONENT_KEYS = {
    "name",
    "sha256",
    "bytes",
    "object_uri",
    "version_id",
}
_RECEIPT_KEYS = {
    "version",
    "action",
    "manifest_uri",
    "manifest_version_id",
    "manifest_sha256",
    "manifest_bytes",
    "verified_at",
}
_INDEPENDENT_ATTESTATION_KEYS = {
    "version",
    "action",
    "bundle_id",
    "manifest_uri",
    "manifest_version_id",
    "manifest_sha256",
    "manifest_signing_key_id",
    "manifest_signing_key_fingerprint",
    "verifier_key_id",
    "verifier_key_fingerprint",
    "identity",
    "day",
    "report_sha256",
    "facts_sha256",
    "external_verification",
    "verified_at",
}
_EXTERNAL_VERIFICATION_KEYS = {
    "version",
    "action",
    "day",
    "journal_snapshot",
    "external_monitor",
    "alert_receipts",
    "backup_receipts",
}
_EXTERNAL_COMPONENT_KEYS = {
    "object_uri",
    "version_id",
    "sha256",
    "bytes",
    "signing_key_fingerprint",
    "artifact_count",
    "all_signatures_valid",
}


def _normalized(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def scan_json_evidence(
    payload: bytes,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> object:
    """Require JSON and reject secret-shaped fields or embedded known secrets."""
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("evidence component 必须是合法 UTF-8 JSON") from exc
    forbidden = tuple(item for item in forbidden_values if len(item) >= 4)

    def walk(item: object, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if _normalized(key) in _FORBIDDEN_KEYS:
                    raise ValueError(f"evidence 包含禁止 secret 字段: {path}.{key}")
                walk(child, f"{path}.{key}")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")
        elif isinstance(item, str):
            lowered = item.lower()
            if (
                "-----begin private key-----" in lowered
                or "ok-access-sign" in lowered
                or any(secret in item for secret in forbidden)
            ):
                raise ValueError(f"evidence component 命中 secret scanner: {path}")

    walk(value, "$")
    return value


def _parse_s3(uri: str) -> tuple[str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
        raise ValueError("必须使用完整 s3://bucket/key URI")
    return parsed.netloc, parsed.path.lstrip("/")


def _run_json(
    argv: list[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict:
    completed = runner(
        argv,
        text=True,
        capture_output=True,
        check=True,
        timeout=120,
    )
    value = json.loads(completed.stdout or "{}")
    if not isinstance(value, dict):
        raise RuntimeError("AWS CLI 未返回 JSON object")
    return value


def put_locked_object(
    *,
    source: Path,
    object_uri: str,
    retain_until: datetime,
    kms_key_id: str,
    content_type: str = "application/json",
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> str:
    bucket, key = _parse_s3(object_uri)
    if retain_until.tzinfo is None or retain_until.utcoffset() is None:
        raise ValueError("retain_until 必须带时区")
    if not kms_key_id.strip():
        raise ValueError("KMS key ID 不能为空")
    if not content_type.strip() or any(
        character.isspace() for character in content_type
    ):
        raise ValueError("content_type 非法")
    result = _run_json(
        [
            "aws",
            "s3api",
            "put-object",
            "--bucket",
            bucket,
            "--key",
            key,
            "--body",
            str(source),
            "--content-type",
            content_type,
            "--server-side-encryption",
            "aws:kms",
            "--ssekms-key-id",
            kms_key_id,
            "--object-lock-mode",
            "COMPLIANCE",
            "--object-lock-retain-until-date",
            retain_until.astimezone(UTC).isoformat(),
            "--output",
            "json",
        ],
        runner=runner,
    )
    version_id = str(result.get("VersionId", "")).strip()
    if not version_id:
        raise RuntimeError("S3 put-object 未返回 VersionId")
    return version_id


def verify_locked_object(
    *,
    object_uri: str,
    version_id: str,
    expected_sha256: str,
    expected_bytes: int,
    minimum_retain_until: datetime,
    expected_kms_key_id: str,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> bytes:
    bucket, key = _parse_s3(object_uri)
    if not version_id:
        raise ValueError("exact S3 version ID 不能为空")
    head = _run_json(
        [
            "aws",
            "s3api",
            "head-object",
            "--bucket",
            bucket,
            "--key",
            key,
            "--version-id",
            version_id,
            "--output",
            "json",
        ],
        runner=runner,
    )
    retained = datetime.fromisoformat(str(head.get("ObjectLockRetainUntilDate", "")))
    if (
        head.get("ObjectLockMode") != "COMPLIANCE"
        or retained.astimezone(UTC) < minimum_retain_until.astimezone(UTC)
        or head.get("ServerSideEncryption") != "aws:kms"
        or str(head.get("SSEKMSKeyId", "")) != expected_kms_key_id
        or head.get("ContentLength") != expected_bytes
    ):
        raise RuntimeError("S3 exact version retention/KMS/bytes 验证失败")
    with tempfile.NamedTemporaryFile() as destination:
        _run_json(
            [
                "aws",
                "s3api",
                "get-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--version-id",
                version_id,
                destination.name,
                "--output",
                "json",
            ],
            runner=runner,
        )
        payload = Path(destination.name).read_bytes()
    if (
        len(payload) != expected_bytes
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise RuntimeError("S3 exact version GET 内容 hash/bytes 不匹配")
    return payload


def validate_bundle_manifest(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != _BUNDLE_KEYS:
        raise ValueError("evidence bundle manifest schema 非法")
    if (
        payload["version"] != 1
        or payload["action"] != "attest-immutable-evidence-bundle"
        or not re.fullmatch(r"[0-9a-f]{32}", str(payload["bundle_id"]))
        or payload["kind"] not in {"daily", "chaos", "restart"}
    ):
        raise ValueError("evidence bundle version/action/id/kind 非法")
    created = datetime.fromisoformat(str(payload["created_at"]))
    if created.tzinfo is None or created.utcoffset() is None:
        raise ValueError("evidence bundle created_at 必须带时区")
    identity = payload["identity"]
    if (
        not isinstance(identity, dict)
        or set(identity) != _IDENTITY_KEYS
        or not _SHA1.fullmatch(str(identity["git_commit"]))
        or not _SHA256.fullmatch(str(identity["config_sha256"]))
        or identity["environment"] != "demo"
        or identity["phase"] not in {"shadow", "burn-in", "soak", "chaos"}
        or not all(
            str(identity[key]).strip()
            for key in ("account_uid", "unit", "soak_epoch_id")
        )
    ):
        raise ValueError("evidence bundle identity 非法")
    components = payload["components"]
    if not isinstance(components, dict) or not components:
        raise ValueError("evidence bundle components 不能为空")
    for label, component in components.items():
        if (
            not _COMPONENT_NAME.fullmatch(str(label))
            or not isinstance(component, dict)
            or set(component) != _COMPONENT_KEYS
            or component["name"] != label
            or not _SHA256.fullmatch(str(component["sha256"]))
            or type(component["bytes"]) is not int
            or component["bytes"] <= 0
            or not str(component["version_id"]).strip()
        ):
            raise ValueError(f"evidence bundle component 非法: {label}")
        _parse_s3(str(component["object_uri"]))
    retention = payload["retention"]
    if (
        not isinstance(retention, dict)
        or set(retention) != {"mode", "retain_until"}
        or retention["mode"] != "COMPLIANCE"
    ):
        raise ValueError("evidence bundle retention 非法")
    retained = datetime.fromisoformat(str(retention["retain_until"]))
    if retained.tzinfo is None or retained.utcoffset() is None:
        raise ValueError("evidence bundle retain_until 必须带时区")
    if not str(payload["signing_key_id"]).strip():
        raise ValueError("evidence bundle signing_key_id 不能为空")
    return payload


def build_bundle_manifest(
    *,
    bundle_id: str,
    kind: str,
    identity: dict,
    components: Mapping[str, tuple[bytes, str, str]],
    retain_until: datetime,
    signing_key_id: str,
    created_at: datetime,
) -> dict:
    manifest = {
        "version": 1,
        "action": "attest-immutable-evidence-bundle",
        "bundle_id": bundle_id,
        "kind": kind,
        "created_at": created_at.astimezone(UTC).isoformat(),
        "identity": identity,
        "components": {
            name: {
                "name": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "object_uri": uri,
                "version_id": version_id,
            }
            for name, (payload, uri, version_id) in components.items()
        },
        "retention": {
            "mode": "COMPLIANCE",
            "retain_until": retain_until.astimezone(UTC).isoformat(),
        },
        "signing_key_id": signing_key_id,
    }
    return validate_bundle_manifest(manifest)


def verify_bundle_artifact(
    artifact: object,
    *,
    public_key: Path,
    expected_identity: dict,
    minimum_retain_until: datetime,
    expected_kms_key_id: str,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict[str, bytes]:
    claims = verify_ed25519_artifact(
        artifact,
        public_key,
        label="immutable evidence bundle",
    )
    manifest = validate_bundle_manifest(claims)
    if manifest["identity"] != expected_identity:
        raise RuntimeError("evidence bundle identity 与当前 epoch/deployment 不一致")
    verified: dict[str, bytes] = {}
    for name, component in manifest["components"].items():
        payload = verify_locked_object(
            object_uri=component["object_uri"],
            version_id=component["version_id"],
            expected_sha256=component["sha256"],
            expected_bytes=component["bytes"],
            minimum_retain_until=minimum_retain_until,
            expected_kms_key_id=expected_kms_key_id,
            runner=runner,
        )
        scan_json_evidence(payload)
        verified[name] = payload
    return verified


def build_bundle_receipt(
    *,
    manifest_uri: str,
    manifest_version_id: str,
    manifest_bytes: bytes,
    verified_at: datetime,
) -> dict:
    receipt = {
        "version": 1,
        "action": "verify-immutable-evidence-bundle",
        "manifest_uri": manifest_uri,
        "manifest_version_id": manifest_version_id,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "manifest_bytes": len(manifest_bytes),
        "verified_at": verified_at.astimezone(UTC).isoformat(),
    }
    if (
        set(receipt) != _RECEIPT_KEYS
        or not manifest_version_id
        or not _SHA256.fullmatch(receipt["manifest_sha256"])
    ):
        raise RuntimeError("bundle verification receipt 非法")
    _parse_s3(manifest_uri)
    return receipt


def sign_bundle_manifest(manifest: dict, private_key: Path) -> dict:
    validate_bundle_manifest(manifest)
    info = private_key.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or private_key.is_symlink()
        or info.st_size <= 0
        or info.st_mode & 0o077
    ):
        raise RuntimeError("bundle Ed25519 私钥必须是 owner-only 普通文件")
    return sign_ed25519_payload(manifest, private_key)


def validate_external_daily_verification(value: object) -> dict:
    """Validate the verifier's exact-version raw external evidence statement."""
    if not isinstance(value, dict) or set(value) != _EXTERNAL_VERIFICATION_KEYS:
        raise ValueError("daily external verification schema 非法")
    try:
        datetime.fromisoformat(f"{value['day']}T00:00:00+00:00")
    except (TypeError, ValueError) as exc:
        raise ValueError("daily external verification day 非法") from exc
    if (
        value["version"] != 1
        or value["action"]
        != "verify-daily-external-source-artifacts"
    ):
        raise ValueError("daily external verification identity 非法")
    for name in (
        "journal_snapshot",
        "external_monitor",
        "alert_receipts",
        "backup_receipts",
    ):
        component = value[name]
        if (
            not isinstance(component, dict)
            or set(component) != _EXTERNAL_COMPONENT_KEYS
            or not _SHA256.fullmatch(str(component["sha256"]))
            or not _SHA256.fullmatch(
                str(component["signing_key_fingerprint"])
            )
            or type(component["bytes"]) is not int
            or component["bytes"] <= 0
            or type(component["artifact_count"]) is not int
            or component["artifact_count"] <= 0
            or component["all_signatures_valid"] is not True
            or not str(component["version_id"]).strip()
        ):
            raise ValueError(
                f"daily external verification {name} 非法"
            )
        _parse_s3(str(component["object_uri"]))
    return value


def sign_independent_bundle_verification(
    *,
    manifest: dict,
    manifest_uri: str,
    manifest_version_id: str,
    manifest_bytes: bytes,
    recomputation: dict,
    manifest_signing_public_key: Path,
    verifier_key_id: str,
    verifier_private_key: Path,
    verified_at: datetime,
) -> dict:
    """Sign the second-fault-domain exact-version recomputation result."""
    if (
        not verifier_key_id.strip()
        or set(recomputation)
        != {
            "day",
            "report_sha256",
            "facts_sha256",
            "external_verification",
        }
        or any(
            not _SHA256.fullmatch(str(recomputation[key]))
            for key in ("report_sha256", "facts_sha256")
        )
    ):
        raise ValueError("independent verifier identity/recomputation 非法")
    external_verification = validate_external_daily_verification(
        recomputation["external_verification"]
    )
    if external_verification["day"] != recomputation["day"]:
        raise ValueError("外部事实复验日与 SLO 重算日不一致")
    _parse_s3(manifest_uri)
    validate_bundle_manifest(manifest)
    info = verifier_private_key.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or verifier_private_key.is_symlink()
        or info.st_size <= 0
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise RuntimeError("verifier private key 必须是 owner-only 0600 普通文件")
    manifest_fingerprint = ed25519_public_key_fingerprint(
        manifest_signing_public_key
    )
    verifier_fingerprint = ed25519_public_key_fingerprint(
        verifier_private_key,
        private_key=True,
    )
    external_fingerprints = {
        external_verification[name]["signing_key_fingerprint"]
        for name in (
            "journal_snapshot",
            "external_monitor",
            "alert_receipts",
            "backup_receipts",
        )
    }
    if manifest_fingerprint == verifier_fingerprint:
        raise ValueError(
            "独立 verifier 必须使用不同于 bundle publisher 的 Ed25519 key"
        )
    if (
        len(external_fingerprints) != 4
        or external_fingerprints
        & {manifest_fingerprint, verifier_fingerprint}
    ):
        raise ValueError(
            "四类 external source、publisher 与 verifier key 必须隔离"
        )
    payload = {
        "version": 1,
        "action": "attest-independent-daily-bundle-recomputation",
        "bundle_id": manifest["bundle_id"],
        "manifest_uri": manifest_uri,
        "manifest_version_id": manifest_version_id,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "manifest_signing_key_id": manifest["signing_key_id"],
        "manifest_signing_key_fingerprint": manifest_fingerprint,
        "verifier_key_id": verifier_key_id,
        "verifier_key_fingerprint": verifier_fingerprint,
        "identity": manifest["identity"],
        "day": recomputation["day"],
        "report_sha256": recomputation["report_sha256"],
        "facts_sha256": recomputation["facts_sha256"],
        "external_verification": external_verification,
        "verified_at": verified_at.astimezone(UTC).isoformat(),
    }
    return sign_ed25519_payload(payload, verifier_private_key)


def verify_independent_bundle_verification(
    artifact: object,
    *,
    verifier_public_key: Path,
    manifest_signing_public_key: Path,
    expected_manifest_uri: str,
    expected_manifest_version_id: str,
    expected_manifest_sha256: str,
    expected_day: str,
    expected_identity: dict,
) -> dict:
    """Verify the independent exact-version recomputation used by admission."""
    claims = verify_ed25519_artifact(
        artifact,
        verifier_public_key,
        label="independent daily bundle verifier",
    )
    verifier_fingerprint = ed25519_public_key_fingerprint(
        verifier_public_key
    )
    manifest_fingerprint = ed25519_public_key_fingerprint(
        manifest_signing_public_key
    )
    try:
        verified_at = datetime.fromisoformat(str(claims["verified_at"]))
        external_verification = validate_external_daily_verification(
            claims["external_verification"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("独立 verifier attestation 时间非法") from exc
    external_fingerprints = {
        external_verification[name]["signing_key_fingerprint"]
        for name in (
            "journal_snapshot",
            "external_monitor",
            "alert_receipts",
            "backup_receipts",
        )
    }
    if (
        not isinstance(claims, dict)
        or set(claims) != _INDEPENDENT_ATTESTATION_KEYS
        or claims["version"] != 1
        or claims["action"]
        != "attest-independent-daily-bundle-recomputation"
        or claims["manifest_uri"] != expected_manifest_uri
        or claims["manifest_version_id"] != expected_manifest_version_id
        or claims["manifest_sha256"] != expected_manifest_sha256
        or claims["day"] != expected_day
        or external_verification["day"] != expected_day
        or claims["identity"] != expected_identity
        or claims["manifest_signing_key_fingerprint"]
        != manifest_fingerprint
        or claims["verifier_key_fingerprint"] != verifier_fingerprint
        or manifest_fingerprint == verifier_fingerprint
        or len(external_fingerprints) != 4
        or external_fingerprints
        & {manifest_fingerprint, verifier_fingerprint}
        or not str(claims["manifest_signing_key_id"]).strip()
        or not str(claims["verifier_key_id"]).strip()
        or claims["manifest_signing_key_id"] == claims["verifier_key_id"]
        or any(
            not _SHA256.fullmatch(str(claims[key]))
            for key in (
                "manifest_sha256",
                "report_sha256",
                "facts_sha256",
                "manifest_signing_key_fingerprint",
                "verifier_key_fingerprint",
            )
        )
        or verified_at.tzinfo is None
        or verified_at.utcoffset() is None
    ):
        raise ValueError("独立 verifier attestation 未绑定当前 daily bundle")
    _parse_s3(expected_manifest_uri)
    return claims
