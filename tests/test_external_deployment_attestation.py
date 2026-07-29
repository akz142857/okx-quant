from __future__ import annotations

import copy
import subprocess
from pathlib import Path

import pytest

from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.ops.external_deployment_attestation import (
    ACTION,
    SCHEMA,
    validate_external_deployment_attestation,
    verify_signed_external_deployment_attestation,
)


def _keypair(directory: Path, name: str) -> tuple[Path, Path]:
    private = directory / f"{name}.pem"
    public = directory / f"{name}.pub.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        capture_output=True,
    )
    private.chmod(0o600)
    subprocess.run(
        ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        check=True,
        capture_output=True,
    )
    return private, public


def _payload(tmp_path: Path) -> tuple[dict, Path, Path]:
    verifier, public = _keypair(tmp_path, "verifier")
    hashes = [f"{index:064x}" for index in range(1, 30)]
    payload = {
        "version": 1,
        "schema": SCHEMA,
        "action": ACTION,
        "candidate_sha256": hashes[0],
        "environment": "OKX demo",
        "accounts": [
            {
                "role": role,
                "account_uid": f"uid-{role}",
                "api_domain": "https://www.okx.com",
                "simulated": True,
                "key_fingerprint": hashes[index],
                "permission_profile": "read-only" if role == "demo-shadow" else "validation-trade",
            }
            for index, role in enumerate(("demo-shadow", "demo-active", "demo-chaos"), 1)
        ],
        "failure_domains": [
            {
                "role": role,
                "host_id": f"host-{role}",
                "network_namespace_sha256": hashes[index + 3],
                "cgroup_policy_sha256": hashes[index + 6],
                "credential_namespace_sha256": hashes[index + 9],
            }
            for index, role in enumerate(("demo-shadow", "demo-active", "demo-chaos"))
        ],
        "responsibilities": [
            {
                "role": role,
                "principal_arn": f"arn:aws:iam::123456789012:role/{role}",
                "sts_session_id": f"session-{role}",
                "key_fingerprint": (
                    ed25519_public_key_fingerprint(verifier, private_key=True)
                    if role == "deployment_verifier"
                    else hashes[index + 12]
                ),
            }
            for index, role in enumerate((
                "bundle_publisher",
                "raw_observer",
                "deployment_verifier",
                "fleet_admission_gate",
                "worm_readback_verifier",
            ))
        ],
        "evidence": {},
        "issued_at": "2026-07-29T00:00:00+00:00",
        "expires_at": "2026-07-30T00:00:00+00:00",
        "verifier_key_fingerprint": ed25519_public_key_fingerprint(verifier, private_key=True),
    }
    for index, role in enumerate(("iam_sts", "worm_manifest", "exact_version_readback", "second_fault_domain")):
        payload["evidence"][role] = {
            "sha256": hashes[index + 20],
            "bytes": 128 + index,
            "object_uri": f"s3://audit/{role}.json",
            "version_id": f"v-{role}",
            "retention_mode": "COMPLIANCE" if role == "worm_manifest" else "",
            "retain_until": "2026-08-01T00:00:00+00:00" if role == "worm_manifest" else "",
            "kms_key_id": "arn:aws:kms:ap-southeast-1:123456789012:key/demo" if role == "worm_manifest" else "",
            "verifier_key_fingerprint": payload["verifier_key_fingerprint"],
            "verified_at": "2026-07-29T00:01:00+00:00",
        }
    return payload, verifier, public


def test_external_attestation_requires_all_external_boundaries(tmp_path):
    payload, private, public = _payload(tmp_path)
    artifact = sign_ed25519_payload(payload, private)
    claims = verify_signed_external_deployment_attestation(
        artifact,
        public,
    )
    assert claims["action"] == ACTION
    assert len(claims["accounts"]) == 3


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("accounts", 1, "simulated"), False),
        (("failure_domains", 2, "host_id"), "host-demo-shadow"),
        (("evidence", "worm_manifest", "retention_mode"), "GOVERNANCE"),
        (("evidence", "iam_sts", "object_uri"), "https://audit.invalid/iam"),
    ],
)
def test_external_attestation_rejects_tampering(tmp_path, path, value):
    payload, _private, _public = _payload(tmp_path)
    changed = copy.deepcopy(payload)
    cursor = changed
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value
    with pytest.raises(ValueError):
        validate_external_deployment_attestation(changed)


def test_external_attestation_rejects_reused_responsibility_key(tmp_path):
    payload, _private, _public = _payload(tmp_path)
    payload["responsibilities"][1]["key_fingerprint"] = payload["responsibilities"][0]["key_fingerprint"]
    with pytest.raises(ValueError, match="独立 key"):
        validate_external_deployment_attestation(payload)
