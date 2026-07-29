"""Signed offsite-backup receipt validation shared by runtime and tooling."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

from okx_quant.application.approval import verify_ed25519_artifact

_EVIDENCE_KEYS = {
    "version",
    "action",
    "evidence_key_id",
    "account_id",
    "schema_version",
    "receipt_sha256",
    "archive_uri",
    "archive_version_id",
    "archive_sha256",
    "archive_bytes",
    "manifest_uri",
    "manifest_version_id",
    "manifest_sha256",
    "manifest_bytes",
    "snapshot_completed_at",
    "roundtrip_started_at",
    "roundtrip_completed_at",
    "restore",
    "backup_slo_sample",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SLO_SAMPLE_KEYS = {
    "integrity",
    "snapshot_completed_at",
    "offsite_readback_at",
    "version_id",
    "roundtrip_started_at",
    "roundtrip_completed_at",
    "evidence_artifact_sha256",
    "evidence_key_id",
}


def _finite_timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError(f"{label} 必须是正有限 Unix timestamp")
    return float(value)


def validate_backup_slo_sample(
    payload: object,
    *,
    event_created_at: float,
) -> dict:
    """Validate the durable projection of a signed exact-version restore."""
    created_at = _finite_timestamp(event_created_at, "event_created_at")
    if not isinstance(payload, dict) or set(payload) != _SLO_SAMPLE_KEYS:
        raise ValueError("backup_slo_sample schema 非法")
    snapshot = _finite_timestamp(
        payload["snapshot_completed_at"],
        "backup_slo_sample.snapshot_completed_at",
    )
    readback = _finite_timestamp(
        payload["offsite_readback_at"],
        "backup_slo_sample.offsite_readback_at",
    )
    started = _finite_timestamp(
        payload["roundtrip_started_at"],
        "backup_slo_sample.roundtrip_started_at",
    )
    completed = _finite_timestamp(
        payload["roundtrip_completed_at"],
        "backup_slo_sample.roundtrip_completed_at",
    )
    if (
        payload["integrity"] != "ok"
        or not str(payload["version_id"]).strip()
        or not _SHA256.fullmatch(
            str(payload["evidence_artifact_sha256"])
        )
        or not str(payload["evidence_key_id"]).strip()
        or not snapshot <= started <= completed
        or not snapshot <= readback <= completed + 5
        or completed > created_at + 5
        or created_at - completed > 86_400
    ):
        raise ValueError(
            "backup_slo_sample provenance/time-chain 非法"
        )
    return payload


def validate_restore_evidence(
    payload: object,
    *,
    expected_account_id: str,
    expected_key_id: str,
    now: float,
) -> dict:
    """Validate an exact-version offsite restore statement."""
    if not isinstance(payload, dict) or set(payload) != _EVIDENCE_KEYS:
        raise ValueError("offsite restore evidence schema 非法")
    started = _finite_timestamp(
        payload["roundtrip_started_at"],
        "roundtrip_started_at",
    )
    completed = _finite_timestamp(
        payload["roundtrip_completed_at"],
        "roundtrip_completed_at",
    )
    if (
        payload["version"] != 1
        or payload["action"] != "attest-offsite-backup-restore"
        or payload["account_id"] != expected_account_id
        or payload["evidence_key_id"] != expected_key_id
        or type(payload["schema_version"]) is not int
        or completed < started
        or completed > now + 300
        or now - completed > 86400
        or not str(payload["archive_uri"]).startswith("s3://")
        or not str(payload["manifest_uri"]).startswith("s3://")
        or not str(payload["archive_version_id"]).strip()
        or not str(payload["manifest_version_id"]).strip()
        or not _SHA256.fullmatch(str(payload["archive_sha256"]))
        or not _SHA256.fullmatch(str(payload["manifest_sha256"]))
        or type(payload["archive_bytes"]) is not int
        or payload["archive_bytes"] <= 0
        or type(payload["manifest_bytes"]) is not int
        or payload["manifest_bytes"] <= 0
        or not _SHA256.fullmatch(str(payload["receipt_sha256"]))
    ):
        raise ValueError("offsite restore evidence identity/time/version 非法")
    restore = payload["restore"]
    if (
        not isinstance(restore, dict)
        or restore.get("ok") is not True
        or restore.get("database_ok") is not True
        or restore.get("checksum_verified") is not True
        or restore.get("integrity_check") != "ok"
        or restore.get("account_id") != expected_account_id
        or restore.get("schema_version") != payload["schema_version"]
    ):
        raise ValueError("offsite restore evidence 未证明完整恢复成功")
    sample = payload["backup_slo_sample"]
    snapshot_completed = _finite_timestamp(
        sample.get("snapshot_completed_at")
        if isinstance(sample, dict)
        else None,
        "backup_slo_sample.snapshot_completed_at",
    )
    readback = _finite_timestamp(
        sample.get("offsite_readback_at")
        if isinstance(sample, dict)
        else None,
        "backup_slo_sample.offsite_readback_at",
    )
    if (
        not isinstance(sample, dict)
        or set(sample)
        != {
            "integrity",
            "snapshot_completed_at",
            "offsite_readback_at",
            "version_id",
        }
        or sample["integrity"] != "ok"
        or sample["version_id"] != payload["archive_version_id"]
        or snapshot_completed != float(payload["snapshot_completed_at"])
        or not snapshot_completed <= readback <= completed + 5
    ):
        raise ValueError("offsite restore backup_slo_sample 非法")
    return payload


def read_verified_restore_evidence(
    artifact_path: Path,
    *,
    public_key: Path,
    expected_account_id: str,
    expected_key_id: str,
    now: float,
) -> tuple[dict, str]:
    """Read once, verify the signature, and return claims plus byte digest."""
    artifact_bytes = artifact_path.read_bytes()
    claims = validate_restore_evidence(
        verify_ed25519_artifact(
            json.loads(artifact_bytes),
            public_key,
            label="offsite restore evidence",
        ),
        expected_account_id=expected_account_id,
        expected_key_id=expected_key_id,
        now=now,
    )
    return claims, hashlib.sha256(artifact_bytes).hexdigest()
