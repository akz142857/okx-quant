"""Demo contract v2 identity、detached manifest 和 tamper 测试。"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from okx_quant.infrastructure.evidence import (
    build_demo_contract_manifest_request,
    build_deployment_identity,
    complete_demo_contract_manifest,
    redacted_config_hash,
    sha256_bytes,
    sign_ed25519_payload,
)
from okx_quant.infrastructure.okx.contract_fixture import (
    build_redacted_contract_fixture,
    validate_contract_fixture,
)
from scripts import verify_demo_contract
from scripts.verify_demo_contract import verify_contract_bundle


def _release(*, clean: bool = True) -> dict:
    return {
        "git_commit": "1" * 40,
        "git_tree_hash": "2" * 40,
        "workspace_clean": clean,
        "source_manifest_sha256": "3" * 64,
    }


def _deployment() -> dict:
    return {
        "account_uid": "demo-account",
        "api_domain": "https://www.okx.com",
        "simulated": True,
        "config_sha256": "4" * 64,
        "key_fingerprint": "5" * 64,
    }


def _signed_bundle(tmp_path, *, clean: bool = True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    private_key.chmod(0o600)
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )
    contract = {
        "environment": "OKX demo",
        "inst_id": "BTC-USDT",
        "started_at": 1,
        "completed_at": 2,
        "route_b_ok": True,
        "attached_probe_conclusive": True,
        "cleanup_errors": [],
        "ok": True,
        "independent_parent": {"ordId": "order-1"},
    }
    fixture = build_redacted_contract_fixture(contract)
    fixture_bytes = (
        json.dumps(fixture, ensure_ascii=False, indent=2) + "\n"
    ).encode()
    release = _release(clean=clean)
    deployment = _deployment()
    evidence = {
        "version": 2,
        "artifact_type": "okx-demo-contract",
        "contract_run_id": "a" * 32,
        "script_version": 2,
        "started_at": "1970-01-01T00:00:01+00:00",
        "completed_at": "1970-01-01T00:00:02+00:00",
        "release_identity": release,
        "deployment_identity": deployment,
        "fixture_sha256": sha256_bytes(fixture_bytes),
        "contract": contract,
    }
    evidence_bytes = (
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
    ).encode()
    request = build_demo_contract_manifest_request(
        contract_run_id="a" * 32,
        release_identity=release,
        deployment_identity=deployment,
        evidence_name="evidence.json",
        evidence_bytes=evidence_bytes,
        fixture_name="fixture.json",
        fixture_bytes=fixture_bytes,
        created_at=datetime.now(UTC).isoformat(),
    )
    payload = complete_demo_contract_manifest(
        request,
        evidence_uri="s3://audit/evidence.json",
        evidence_version_id="e-version",
        fixture_uri="s3://audit/fixture.json",
        fixture_version_id="f-version",
        retain_until=(datetime.now(UTC) + timedelta(days=365)).isoformat(),
        kms_key_id="arn:aws:kms:ap-southeast-1:123456789012:key/audit",
        signing_key_id="monitor-2026",
    )
    return (
        sign_ed25519_payload(payload, private_key),
        public_key,
        evidence_bytes,
        fixture_bytes,
    )


def test_exact_contract_get_rejects_wrong_kms_before_download(monkeypatch):
    monkeypatch.setattr(
        verify_demo_contract,
        "_aws_json",
        lambda _args: {
            "VersionId": "v1",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": "2099-01-01T00:00:00+00:00",
            "ContentLength": 1,
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": "wrong-key",
        },
    )
    with pytest.raises(ValueError, match="KMS"):
        verify_demo_contract.exact_version_get(
            {
                "name": "evidence",
                "sha256": "0" * 64,
                "bytes": 1,
                "object_uri": "s3://audit/evidence.json",
                "version_id": "v1",
            },
            retain_until="2098-01-01T00:00:00+00:00",
            expected_kms_key_id="expected-key",
        )


def test_config_hash_redacts_secret_values_but_binds_presence():
    first = {
        "okx": {
            "api_key": "first",
            "secret_key": "secret-a",
            "passphrase": "pass-a",
            "simulated": True,
        },
    }
    second = {
        "okx": {
            "api_key": "second",
            "secret_key": "secret-b",
            "passphrase": "pass-b",
            "simulated": True,
        },
    }
    assert redacted_config_hash(first) == redacted_config_hash(second)
    second["okx"]["simulated"] = False
    assert redacted_config_hash(first) != redacted_config_hash(second)


def test_deployment_identity_requires_demo_uid_and_https():
    config = {
        "okx": {
            "api_key": "key",
            "secret_key": "secret",
            "passphrase": "pass",
            "base_url": "https://www.okx.com",
            "simulated": True,
        },
    }
    identity = build_deployment_identity(
        config=config,
        account_config={"uid": "uid-1"},
    )
    assert identity["account_uid"] == "uid-1"
    serialized = json.dumps(identity)
    assert '"api_key"' not in serialized
    assert '"secret"' not in serialized
    assert '"pass"' not in serialized
    with pytest.raises(ValueError, match="uid"):
        build_deployment_identity(config=config, account_config={})


def test_signed_contract_bundle_rejects_tamper_and_dirty_release(tmp_path):
    artifact, public_key, evidence, fixture = _signed_bundle(tmp_path)
    result = verify_contract_bundle(
        artifact=artifact,
        public_key=public_key,
        evidence_bytes=evidence,
        fixture_bytes=fixture,
        expected_commit="1" * 40,
        expected_config_sha256="4" * 64,
        expected_account_uid="demo-account",
    )
    assert result["verified"]
    with pytest.raises(ValueError, match="bytes|SHA-256"):
        verify_contract_bundle(
            artifact=artifact,
            public_key=public_key,
            evidence_bytes=evidence + b" ",
            fixture_bytes=fixture,
        )

    dirty_artifact, dirty_public, dirty_evidence, dirty_fixture = (
        _signed_bundle(tmp_path / "dirty", clean=False)
    )
    with pytest.raises(ValueError, match="干净工作树"):
        verify_contract_bundle(
            artifact=dirty_artifact,
            public_key=dirty_public,
            evidence_bytes=dirty_evidence,
            fixture_bytes=dirty_fixture,
        )


def test_immutable_verifier_requires_expected_deployment_identity(
    monkeypatch,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "verify_demo_contract.py",
            "--manifest",
            "manifest.json",
            "--public-key",
            "public.pem",
        ],
    )
    with pytest.raises(SystemExit, match="expected-commit"):
        verify_demo_contract.main()


def test_tracked_demo_contract_fixture_is_redacted_and_valid():
    fixture_path = (
        Path(__file__).parent
        / "fixtures"
        / "okx-demo-contract-fixture.v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    validate_contract_fixture(fixture)
    serialized = fixture_path.read_text(encoding="utf-8").lower()
    assert "api_key" not in serialized
    assert "secret_key" not in serialized
    assert "passphrase" not in serialized
