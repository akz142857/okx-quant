import json
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta

import pytest

from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.ops.empty_host_restore import (
    read_verified_empty_host_restore,
    validate_empty_host_restore_claims,
)
from scripts import sign_empty_host_restore


def _keys(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", private],
        check=True,
        capture_output=True,
    )
    private.chmod(0o600)
    subprocess.run(
        ["openssl", "pkey", "-in", private, "-pubout", "-out", public],
        check=True,
        capture_output=True,
    )
    return private, public


def _claims(now):
    return {
        "version": 1,
        "action": "attest-empty-host-disaster-recovery",
        "evidence_key_id": "empty-host-v1",
        "drill_id": "drill-2026-07",
        "account_id": "demo-account",
        "release_identity": "a" * 40,
        "config_sha256": "f" * 64,
        "deployment_unit": "okx-quant-demo-active.service",
        "soak_epoch_id": "epoch-0001",
        "measurement_scope": "empty_host_end_to_end",
        "started_at": now - 1200,
        "completed_at": now - 1,
        "elapsed_seconds": 1199,
        "empty_host_verified": True,
        "dependencies_installed": True,
        "configuration_restored": True,
        "exact_version_get_verified": True,
        "database_integrity": "ok",
        "account_identity_verified": True,
        "maintenance_latched": True,
        "read_only_reconciliation_completed": True,
        "entries_enabled": False,
        "archive_uri": "s3://backup/archive.enc",
        "archive_version_id": "archive-v1",
        "archive_sha256": "b" * 64,
        "archive_bytes": 4096,
        "manifest_uri": "s3://backup/archive.enc.manifest.json",
        "manifest_version_id": "manifest-v1",
        "manifest_sha256": "c" * 64,
        "manifest_bytes": 1024,
        "exact_version_verified_at": now,
        "minimum_retain_until": (
            datetime.fromtimestamp(now, UTC) + timedelta(days=40)
        ).isoformat(),
        "kms_key_id": "kms-empty-host-v1",
        "component_restore_evidence_sha256": "d" * 64,
        "host_image_sha256": "e" * 64,
        "operator": "dr@example",
    }


def _validate(claims, now):
    return validate_empty_host_restore_claims(
        claims,
        expected_account_id="demo-account",
        expected_release_identity="a" * 40,
        expected_config_sha256="f" * 64,
        expected_deployment_unit="okx-quant-demo-active.service",
        expected_soak_epoch_id="epoch-0001",
        expected_key_id="empty-host-v1",
        now=now,
    )


def test_signed_recent_empty_host_restore_is_accepted(tmp_path):
    now = time.time()
    private, public = _keys(tmp_path)
    claims = _claims(now)
    artifact_path = tmp_path / "empty-host.json"
    artifact_path.write_text(
        json.dumps(sign_ed25519_payload(claims, private)),
        encoding="utf-8",
    )

    verified, digest = read_verified_empty_host_restore(
        artifact_path,
        public_key=public,
        expected_account_id="demo-account",
        expected_release_identity="a" * 40,
        expected_config_sha256="f" * 64,
        expected_deployment_unit="okx-quant-demo-active.service",
        expected_soak_epoch_id="epoch-0001",
        expected_key_id="empty-host-v1",
        now=now,
    )
    assert verified == claims
    assert len(digest) == 64


def test_component_restore_cannot_impersonate_empty_host_rto():
    now = time.time()
    claims = _claims(now)
    claims["measurement_scope"] = "database_restore_component_only"
    claims["empty_host_verified"] = False
    with pytest.raises(ValueError, match="identity/scope/RTO"):
        _validate(claims, now)


def test_empty_host_evidence_is_bound_to_exact_config():
    now = time.time()
    claims = _claims(now)
    claims["config_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="identity/scope/RTO"):
        _validate(claims, now)


def test_independent_signer_exact_gets_archive_and_manifest(
    tmp_path,
    monkeypatch,
):
    now = time.time()
    private, public = _keys(tmp_path)
    claims = _claims(now)
    signer_fields = {
        "evidence_key_id",
        "exact_version_verified_at",
        "minimum_retain_until",
        "kms_key_id",
    }
    request = {
        key: value
        for key, value in claims.items()
        if key not in signer_fields
    }
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    observed = []

    def verify_locked(**kwargs):
        observed.append(kwargs)
        return b"verified"

    monkeypatch.setattr(
        sign_empty_host_restore,
        "verify_locked_object",
        verify_locked,
    )
    output = tmp_path / "signed.json"
    retain_until = datetime.fromisoformat(
        claims["minimum_retain_until"]
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sign_empty_host_restore.py",
            "--request",
            str(request_path),
            "--private-key",
            str(private),
            "--public-key",
            str(public),
            "--evidence-key-id",
            claims["evidence_key_id"],
            "--minimum-retain-until",
            retain_until.isoformat(),
            "--kms-key-id",
            claims["kms_key_id"],
            "--output",
            str(output),
        ],
    )

    assert sign_empty_host_restore.main() == 0
    assert {
        (item["object_uri"], item["version_id"])
        for item in observed
    } == {
        (claims["archive_uri"], claims["archive_version_id"]),
        (claims["manifest_uri"], claims["manifest_version_id"]),
    }
    assert all(
        item["expected_kms_key_id"] == claims["kms_key_id"]
        and item["minimum_retain_until"] == retain_until
        for item in observed
    )

    def reject_manifest(**kwargs):
        if kwargs["version_id"] == claims["manifest_version_id"]:
            raise RuntimeError("manifest exact-version mismatch")
        return b"verified"

    monkeypatch.setattr(
        sign_empty_host_restore,
        "verify_locked_object",
        reject_manifest,
    )
    rejected = tmp_path / "rejected.json"
    sys.argv[-1] = str(rejected)
    with pytest.raises(RuntimeError, match="exact-version mismatch"):
        sign_empty_host_restore.main()
    assert not rejected.exists()


@pytest.mark.parametrize("failure", ["rto", "stale", "entries"])
def test_empty_host_gate_rejects_unsafe_or_stale_claim(failure):
    now = time.time()
    claims = _claims(now)
    if failure == "rto":
        claims["started_at"] = now - 1801
        claims["elapsed_seconds"] = 1800
    elif failure == "stale":
        claims["started_at"] = now - 32 * 86_400 - 1200
        claims["completed_at"] = now - 32 * 86_400
        claims["elapsed_seconds"] = 1200
    else:
        claims["entries_enabled"] = True
    with pytest.raises(ValueError, match="identity/scope/RTO"):
        _validate(claims, now)
