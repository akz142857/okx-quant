"""Independent signed evidence for the monthly empty-host recovery SLO."""

from __future__ import annotations

import hashlib
import json
import math
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from okx_quant.application.approval import verify_ed25519_artifact

EMPTY_HOST_RTO_SECONDS = 1800
EMPTY_HOST_MAX_AGE_SECONDS = 31 * 86_400
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHA1 = re.compile(r"[0-9a-f]{40}")
_CLAIM_KEYS = {
    "version",
    "action",
    "evidence_key_id",
    "drill_id",
    "account_id",
    "release_identity",
    "config_sha256",
    "deployment_unit",
    "soak_epoch_id",
    "measurement_scope",
    "started_at",
    "completed_at",
    "elapsed_seconds",
    "empty_host_verified",
    "dependencies_installed",
    "configuration_restored",
    "exact_version_get_verified",
    "database_integrity",
    "account_identity_verified",
    "maintenance_latched",
    "read_only_reconciliation_completed",
    "entries_enabled",
    "archive_uri",
    "archive_version_id",
    "archive_sha256",
    "archive_bytes",
    "manifest_uri",
    "manifest_version_id",
    "manifest_sha256",
    "manifest_bytes",
    "exact_version_verified_at",
    "minimum_retain_until",
    "kms_key_id",
    "component_restore_evidence_sha256",
    "host_image_sha256",
    "operator",
}


def _positive_finite(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError(f"{label} 必须是正有限数")
    return float(value)


def validate_empty_host_restore_claims(
    payload: object,
    *,
    expected_account_id: str,
    expected_release_identity: str,
    expected_config_sha256: str,
    expected_deployment_unit: str,
    expected_soak_epoch_id: str,
    expected_key_id: str,
    now: float,
) -> dict:
    if not isinstance(payload, dict) or set(payload) != _CLAIM_KEYS:
        raise ValueError("empty-host restore evidence schema 非法")
    started = _positive_finite(payload["started_at"], "started_at")
    completed = _positive_finite(payload["completed_at"], "completed_at")
    elapsed = _positive_finite(
        payload["elapsed_seconds"],
        "elapsed_seconds",
    )
    exact_verified_at = _positive_finite(
        payload["exact_version_verified_at"],
        "exact_version_verified_at",
    )
    current = _positive_finite(now, "now")
    try:
        minimum_retain_until = datetime.fromisoformat(
            str(payload["minimum_retain_until"])
        )
    except ValueError as exc:
        raise ValueError(
            "empty-host minimum_retain_until 非法"
        ) from exc
    archive_uri = urlparse(str(payload["archive_uri"]))
    manifest_uri = urlparse(str(payload["manifest_uri"]))
    if (
        payload["version"] != 1
        or payload["action"]
        != "attest-empty-host-disaster-recovery"
        or payload["evidence_key_id"] != expected_key_id
        or payload["account_id"] != expected_account_id
        or payload["release_identity"] != expected_release_identity
        or payload["config_sha256"] != expected_config_sha256
        or payload["deployment_unit"] != expected_deployment_unit
        or payload["soak_epoch_id"] != expected_soak_epoch_id
        or payload["measurement_scope"] != "empty_host_end_to_end"
        or not _SHA1.fullmatch(str(payload["release_identity"]))
        or not _SHA256.fullmatch(str(payload["config_sha256"]))
        or not str(payload["drill_id"]).strip()
        or completed < started
        or not math.isclose(
            elapsed,
            completed - started,
            abs_tol=0.01,
        )
        or elapsed >= EMPTY_HOST_RTO_SECONDS
        or completed > current + 300
        or current - completed > EMPTY_HOST_MAX_AGE_SECONDS
        or exact_verified_at < completed
        or exact_verified_at > current + 300
        or minimum_retain_until.tzinfo is None
        or minimum_retain_until.utcoffset() is None
        or minimum_retain_until.astimezone(UTC)
        < datetime.fromtimestamp(completed, UTC) + timedelta(days=35)
        or payload["empty_host_verified"] is not True
        or payload["dependencies_installed"] is not True
        or payload["configuration_restored"] is not True
        or payload["exact_version_get_verified"] is not True
        or payload["database_integrity"] != "ok"
        or payload["account_identity_verified"] is not True
        or payload["maintenance_latched"] is not True
        or payload["read_only_reconciliation_completed"] is not True
        or payload["entries_enabled"] is not False
        or archive_uri.scheme != "s3"
        or not archive_uri.netloc
        or not archive_uri.path.strip("/")
        or not str(payload["archive_version_id"]).strip()
        or type(payload["archive_bytes"]) is not int
        or payload["archive_bytes"] <= 0
        or manifest_uri.scheme != "s3"
        or not manifest_uri.netloc
        or not manifest_uri.path.strip("/")
        or not str(payload["manifest_version_id"]).strip()
        or type(payload["manifest_bytes"]) is not int
        or payload["manifest_bytes"] <= 0
        or not str(payload["kms_key_id"]).strip()
        or any(
            not _SHA256.fullmatch(str(payload[name]))
            for name in (
                "archive_sha256",
                "manifest_sha256",
                "component_restore_evidence_sha256",
                "host_image_sha256",
            )
        )
        or not str(payload["operator"]).strip()
    ):
        raise ValueError(
            "empty-host restore evidence identity/scope/RTO 非法"
        )
    return payload


def read_verified_empty_host_restore(
    artifact_path: Path,
    *,
    public_key: Path,
    expected_account_id: str,
    expected_release_identity: str,
    expected_config_sha256: str,
    expected_deployment_unit: str,
    expected_soak_epoch_id: str,
    expected_key_id: str,
    now: float,
) -> tuple[dict, str]:
    info = artifact_path.lstat()
    if (
        artifact_path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_size <= 0
        or info.st_size > 1_048_576
        or info.st_mode & 0o022
    ):
        raise ValueError(
            "empty-host restore evidence 必须是受控普通文件"
        )
    raw = artifact_path.read_bytes()
    claims = validate_empty_host_restore_claims(
        verify_ed25519_artifact(
            json.loads(raw),
            public_key,
            label="empty-host restore evidence",
        ),
        expected_account_id=expected_account_id,
        expected_release_identity=expected_release_identity,
        expected_config_sha256=expected_config_sha256,
        expected_deployment_unit=expected_deployment_unit,
        expected_soak_epoch_id=expected_soak_epoch_id,
        expected_key_id=expected_key_id,
        now=now,
    )
    return claims, hashlib.sha256(raw).hexdigest()
