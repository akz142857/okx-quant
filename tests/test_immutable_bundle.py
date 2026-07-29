import base64
import copy
import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.immutable_bundle import (
    build_bundle_manifest,
    put_locked_object,
    scan_json_evidence,
    sign_bundle_manifest,
    sign_independent_bundle_verification,
    validate_bundle_manifest,
    verify_independent_bundle_verification,
    verify_locked_object,
)
from scripts import immutable_evidence_bundle
from scripts.sign_external_daily_source import build_external_daily_source


def _keys(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "Ed25519",
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
    return private_key, public_key


def _identity():
    return {
        "git_commit": "a" * 40,
        "config_sha256": "b" * 64,
        "account_uid": "demo-account",
        "environment": "demo",
        "unit": "okx-quant-demo-active.service",
        "soak_epoch_id": "epoch-0001",
        "phase": "soak",
    }


def _external_verification():
    def component(name: str, marker: str) -> dict:
        return {
            "object_uri": f"s3://evidence/day/{name}.json",
            "version_id": "exact-v1",
            "sha256": "c" * 64,
            "bytes": 123,
            "signing_key_fingerprint": marker * 64,
            "artifact_count": 1,
            "all_signatures_valid": True,
        }

    return {
        "version": 1,
        "action": "verify-daily-external-source-artifacts",
        "day": "2026-07-28",
        "journal_snapshot": component("journal", "1"),
        "external_monitor": component("monitor", "2"),
        "alert_receipts": component("alerts", "3"),
        "backup_receipts": component("backups", "4"),
    }


def _monitor_claims(observed_at: datetime) -> dict:
    identity = _identity()
    target = "demo-active"
    completed_at = observed_at.timestamp()
    signal_max_age = {
        "host": 120,
        "service": 60,
        "provider": 900,
        "evidence-close": 90_000,
        "backup": 300,
    }
    event_identity = {
        "target": target,
        "release": identity["git_commit"],
        "config": identity["config_sha256"],
        "account_uid": identity["account_uid"],
        "unit": identity["unit"],
        "soak_epoch_id": identity["soak_epoch_id"],
        "failures": [],
    }
    endpoint = {
        "status": 200,
        "latency_seconds": 0.1,
        "live": True,
        "ready": True,
        "release_identity": identity["git_commit"],
        "config_identity": identity["config_sha256"],
        "account_uid": identity["account_uid"],
        "deployment_unit": identity["unit"],
        "soak_epoch_id": identity["soak_epoch_id"],
    }
    signals = {}
    for name, maximum_age in signal_max_age.items():
        signals[name] = {
            "status": 200,
            "latency_seconds": 0.1,
            "ok": True,
            "signal": name,
            "observed_at": completed_at - 1,
            "age_seconds": 0,
            "maximum_age_seconds": maximum_age,
            "deadman_id": f"{name}-deadman",
            "target": target,
            "release_identity": identity["git_commit"],
            "config_identity": identity["config_sha256"],
            "account_uid": identity["account_uid"],
            "deployment_unit": identity["unit"],
            "soak_epoch_id": identity["soak_epoch_id"],
        }
    return {
        "version": 1,
        "action": "attest-external-demo-synthetic",
        "target": target,
        "event_id": hashlib.sha256(
            json.dumps(
                event_identity,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "signing_key_id": "external-v1",
        "expected_release": identity["git_commit"],
        "expected_config": identity["config_sha256"],
        "expected_account_uid": identity["account_uid"],
        "expected_unit": identity["unit"],
        "soak_epoch_id": identity["soak_epoch_id"],
        "started_at": completed_at - 1,
        "completed_at": completed_at,
        "endpoints": {
            "health": copy.deepcopy(endpoint),
            "ready": copy.deepcopy(endpoint),
        },
        "signals": signals,
        "clock": {
            "status": 200,
            "latency_seconds": 0.1,
            "midpoint_offset_seconds": 0.1,
        },
        "failures": [],
        "deliveries": [],
        "ok": True,
    }


def test_external_daily_source_requires_nonempty_exact_source():
    payload = build_external_daily_source(
        day="2026-07-28",
        source="external_monitor",
        artifacts=[{
            "sha256": hashlib.sha256(b"{}").hexdigest(),
            "bytes_base64": base64.b64encode(b"{}").decode(),
        }],
        signing_key_id="external-monitor-v1",
    )
    assert payload["source"] == "external_monitor"
    assert len(payload["artifacts"]) == 1
    with pytest.raises(ValueError):
        build_external_daily_source(
            day="2026-07-28",
            source="external_monitor",
            artifacts=[],
            signing_key_id="external-monitor-v1",
        )


def _monitor_day(
    *,
    mutate: str | None = None,
) -> list[tuple[bytes, dict, str]]:
    day_started = datetime(2026, 7, 28, tzinfo=UTC)
    claims = [
        _monitor_claims(day_started + timedelta(minutes=minute))
        for minute in range(1, 1_437, 5)
    ]
    row = claims[0]["signals"]["backup"]
    if mutate == "name":
        row["signal"] = "provider"
    elif mutate == "identity":
        row["account_uid"] = "other-account"
    elif mutate == "age":
        row["age_seconds"] = 301
    elif mutate == "maximum_age":
        row["maximum_age_seconds"] = 301
    elif mutate == "status":
        row["status"] = 503
    elif mutate == "ok":
        row["ok"] = False
    elif mutate == "deadman":
        row["deadman_id"] = claims[0]["signals"]["host"]["deadman_id"]
    return [
        (b"", payload, "unused")
        for payload in claims
    ]


def test_monitor_artifacts_verify_all_five_signed_deadman_claims(
    tmp_path,
    monkeypatch,
):
    _private_key, public_key = _keys(tmp_path)
    monkeypatch.setattr(
        immutable_evidence_bundle,
        "verify_ed25519_artifact",
        lambda artifact, *_args, **_kwargs: artifact,
    )
    immutable_evidence_bundle._verify_monitor_artifacts(
        _monitor_day(),
        public_key=public_key,
        day="2026-07-28",
        identity=_identity(),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "name",
        "identity",
        "age",
        "maximum_age",
        "status",
        "ok",
        "deadman",
    ],
)
def test_monitor_artifacts_reject_tampered_deadman_claims(
    tmp_path,
    monkeypatch,
    mutation,
):
    _private_key, public_key = _keys(tmp_path)
    monkeypatch.setattr(
        immutable_evidence_bundle,
        "verify_ed25519_artifact",
        lambda artifact, *_args, **_kwargs: artifact,
    )
    with pytest.raises(
        RuntimeError,
        match="external monitor endpoint/clock 事实非法",
    ):
        immutable_evidence_bundle._verify_monitor_artifacts(
            _monitor_day(mutate=mutation),
            public_key=public_key,
            day="2026-07-28",
            identity=_identity(),
        )


def test_bundle_manifest_binds_exact_versions_and_signature(tmp_path):
    now = datetime.now(UTC)
    report = b'{"version":2,"safe":"redacted"}\n'
    manifest = build_bundle_manifest(
        bundle_id="c" * 32,
        kind="daily",
        identity=_identity(),
        components={
            "slo-report": (
                report,
                "s3://evidence/epoch/day/report.json",
                "version-1",
            )
        },
        retain_until=now + timedelta(days=365),
        signing_key_id="monitor-v1",
        created_at=now,
    )
    private_key, public_key = _keys(tmp_path)
    artifact = sign_bundle_manifest(manifest, private_key)
    assert verify_ed25519_artifact(
        artifact,
        public_key,
        label="test bundle",
    ) == manifest
    assert validate_bundle_manifest(manifest)["components"]["slo-report"][
        "version_id"
    ] == "version-1"


def test_independent_verifier_signs_exact_manifest_and_recomputation(tmp_path):
    now = datetime.now(UTC)
    report = b'{"report":true}\n'
    facts = b'{"facts":true}\n'
    manifest = build_bundle_manifest(
        bundle_id="e" * 32,
        kind="daily",
        identity=_identity(),
        components={
            "slo-report-v2": (
                report,
                "s3://evidence/day/report.json",
                "report-v1",
            ),
            "slo-facts-v2": (
                facts,
                "s3://evidence/day/facts.json",
                "facts-v1",
            ),
        },
        retain_until=now + timedelta(days=365),
        signing_key_id="publisher-v1",
        created_at=now,
    )
    private_key, public_key = _keys(tmp_path)
    manifest_artifact = sign_bundle_manifest(manifest, private_key)
    manifest_bytes = json.dumps(manifest_artifact).encode()
    verifier_root = tmp_path / "verifier"
    verifier_root.mkdir()
    verifier_private, verifier_public = _keys(verifier_root)

    attestation = sign_independent_bundle_verification(
        manifest=manifest,
        manifest_uri="s3://evidence/day/manifest.json",
        manifest_version_id="manifest-v1",
        manifest_bytes=manifest_bytes,
        recomputation={
            "day": "2026-07-28",
            "report_sha256": hashlib.sha256(report).hexdigest(),
            "facts_sha256": hashlib.sha256(facts).hexdigest(),
            "external_verification": _external_verification(),
        },
        manifest_signing_public_key=public_key,
        verifier_key_id="verifier-v1",
        verifier_private_key=verifier_private,
        verified_at=now,
    )

    claims = verify_ed25519_artifact(
        attestation,
        verifier_public,
        label="independent verifier",
    )
    assert claims["manifest_version_id"] == "manifest-v1"
    assert claims["manifest_signing_key_id"] == "publisher-v1"
    assert public_key.read_bytes() != verifier_public.read_bytes()
    assert verify_independent_bundle_verification(
        attestation,
        verifier_public_key=verifier_public,
        manifest_signing_public_key=public_key,
        expected_manifest_uri="s3://evidence/day/manifest.json",
        expected_manifest_version_id="manifest-v1",
        expected_manifest_sha256=hashlib.sha256(
            manifest_bytes
        ).hexdigest(),
        expected_day="2026-07-28",
        expected_identity=_identity(),
    ) == claims


def test_independent_verifier_rejects_publisher_key_reuse(tmp_path):
    now = datetime.now(UTC)
    private_key, public_key = _keys(tmp_path)
    manifest = build_bundle_manifest(
        bundle_id="f" * 32,
        kind="daily",
        identity=_identity(),
        components={
            "slo-report-v2": (
                b"{}",
                "s3://evidence/day/report.json",
                "report-v1",
            ),
            "slo-facts-v2": (
                b"{}",
                "s3://evidence/day/facts.json",
                "facts-v1",
            ),
        },
        retain_until=now + timedelta(days=365),
        signing_key_id="publisher-v1",
        created_at=now,
    )
    with pytest.raises(ValueError, match="不同于 bundle publisher"):
        sign_independent_bundle_verification(
            manifest=manifest,
            manifest_uri="s3://evidence/day/manifest.json",
            manifest_version_id="manifest-v1",
            manifest_bytes=b"manifest",
            recomputation={
                "day": "2026-07-28",
                "report_sha256": "a" * 64,
                "facts_sha256": "b" * 64,
                "external_verification": _external_verification(),
            },
            manifest_signing_public_key=public_key,
            verifier_key_id="verifier-v1",
            verifier_private_key=private_key,
            verified_at=now,
        )


def test_secret_scanner_rejects_secret_fields_and_known_values():
    with pytest.raises(ValueError, match="secret 字段"):
        scan_json_evidence(json.dumps({"api_key": "redacted"}).encode())
    with pytest.raises(ValueError, match="secret scanner"):
        scan_json_evidence(
            json.dumps({"message": "prefix-real-secret-suffix"}).encode(),
            forbidden_values=("real-secret",),
        )
    assert scan_json_evidence(b'{"message":"safe","count":1}') == {
        "message": "safe",
        "count": 1,
    }


def test_manifest_rejects_non_compliance_or_missing_version():
    now = datetime.now(UTC)
    manifest = build_bundle_manifest(
        bundle_id="d" * 32,
        kind="chaos",
        identity={**_identity(), "phase": "chaos"},
        components={
            "result": (
                b"{}",
                "s3://evidence/chaos/result.json",
                "v1",
            )
        },
        retain_until=now + timedelta(days=30),
        signing_key_id="chaos-v1",
        created_at=now,
    )
    manifest["components"]["result"]["version_id"] = ""
    with pytest.raises(ValueError, match="component"):
        validate_bundle_manifest(manifest)


def test_locked_object_put_and_readback_use_returned_exact_version(tmp_path):
    payload = b"encrypted-backup-bytes"
    source = tmp_path / "archive.enc"
    source.write_bytes(payload)
    retain_until = datetime.now(UTC).replace(microsecond=0) + timedelta(days=35)
    observed: list[list[str]] = []

    def runner(argv, **_kwargs):
        observed.append(argv)
        operation = argv[2]
        if operation == "put-object":
            assert argv[argv.index("--content-type") + 1] == (
                "application/octet-stream"
            )
            return SimpleNamespace(stdout='{"VersionId":"version-exact"}')
        if operation == "head-object":
            assert argv[argv.index("--version-id") + 1] == "version-exact"
            return SimpleNamespace(
                stdout=json.dumps({
                    "ObjectLockMode": "COMPLIANCE",
                    "ObjectLockRetainUntilDate": retain_until.isoformat(),
                    "ServerSideEncryption": "aws:kms",
                    "SSEKMSKeyId": "kms-key",
                    "ContentLength": len(payload),
                })
            )
        if operation == "get-object":
            assert argv[argv.index("--version-id") + 1] == "version-exact"
            Path(argv[-3]).write_bytes(payload)
            return SimpleNamespace(stdout="{}")
        raise AssertionError(argv)

    version_id = put_locked_object(
        source=source,
        object_uri="s3://backup/archive.enc",
        retain_until=retain_until,
        kms_key_id="kms-key",
        content_type="application/octet-stream",
        runner=runner,
    )
    assert version_id == "version-exact"
    assert verify_locked_object(
        object_uri="s3://backup/archive.enc",
        version_id=version_id,
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        expected_bytes=len(payload),
        minimum_retain_until=retain_until,
        expected_kms_key_id="kms-key",
        runner=runner,
    ) == payload
    assert [command[2] for command in observed] == [
        "put-object",
        "head-object",
        "get-object",
    ]
