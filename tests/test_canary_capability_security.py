import base64
import hashlib
import json
import multiprocessing as mp
import os
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from okx_quant.infrastructure.evidence import (
    credential_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.ops.canary_producer import _okx_auth_headers
from okx_quant.research.canary import (
    _reserve_canary_capability,
    _validate_deployment_verifier,
    _validate_worm_readback_receipt,
    _verify_embedded_ed25519,
    consume_canary_capability_reservation,
    validate_canary_control_key_separation,
    validate_collection_receipt,
)
from scripts.canary_worm_readback_verifier import (
    _atomic_new as _atomic_worm_receipt,
)
from scripts.canary_worm_readback_verifier import _aws_sigv4_headers

_AUTHORITIES = {
    "account_uid_verified": "okx_authenticated_account_api",
    "api_key_read_trade_only": "okx_api_key_admin_api",
    "api_key_withdraw_disabled": "okx_api_key_admin_api",
    "ip_allowlist_verified": "okx_api_key_admin_api",
    "journal_identity_verified": "sqlite_snapshot_readonly",
    "limits_match_policy": "root_owned_target_config",
    "release_identity_verified": "root_owned_release_tree",
    "alert_challenge_received": "alert_provider_api",
    "backup_exact_version_restored": "object_store_exact_version_get",
    "protected_position_or_flat": "okx_account_and_business_ws",
    "rest_ws_reconciliation_safe": "sqlite_snapshot_readonly",
    "runtime_safety_kernel_live_within_60s": "systemd_runtime_status",
}
_TARGET_KEY = "a" * 64


def _reserve_once(state, arguments, barrier, results):
    barrier.wait()
    try:
        _reserve_canary_capability(state, **arguments)
        results.put("ok")
    except ValueError:
        results.put("rejected")


def _consume_once(
    state,
    bundle_sha256,
    approval_sha256,
    barrier,
    results,
):
    barrier.wait()
    try:
        consume_canary_capability_reservation(
            state,
            bundle_sha256=bundle_sha256,
            approval_sha256=approval_sha256,
            consumed_at=1200,
        )
        results.put("ok")
    except ValueError:
        results.put("rejected")


def _keypair(root, name):
    private = root / f"{name}-private.pem"
    public = root / f"{name}-public.pem"
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


def _request(name: str) -> dict:
    if name == "backup_exact_version_restored":
        adapter = "s3-version"
        uri = "https://bucket.s3.example/backup.db?versionId=v1"
        secondary_uri = (
            "https://bucket.s3.example/backup.manifest.json"
            "?versionId=manifest-v1"
        )
        object_uri = "s3://evidence/backup.db"
        secondary_object_uri = "s3://evidence/backup.manifest.json"
        headers = {
            "x-amz-version-id": "v1",
            "x-amz-server-side-encryption": "aws:kms",
            "x-amz-server-side-encryption-aws-kms-key-id": "kms-key-1",
            "x-amz-object-lock-mode": "COMPLIANCE",
            "x-amz-object-lock-retain-until-date": (
                "2100-01-01T00:00:00Z"
            ),
        }
        secondary_headers = {
            **headers,
            "x-amz-version-id": "manifest-v1",
        }
    else:
        adapter = "https"
        uri = f"https://collector.example/{name}"
        secondary_uri = ""
        object_uri = ""
        secondary_object_uri = ""
        headers = {"date": "Mon, 01 Jan 2026 00:00:00 GMT"}
        secondary_headers = {}
    target_authenticated = (
        _AUTHORITIES[name]
        in {
            "okx_authenticated_account_api",
            "okx_api_key_admin_api",
            "okx_account_and_business_ws",
        }
    )
    return {
        "version": 1,
        "producer_name": name,
        "adapter": adapter,
        "method": "GET",
        "source_uri": uri,
        "source_object_uri": object_uri,
        "source_version_id": "v1",
        "secondary_source_uri": secondary_uri,
        "secondary_source_object_uri": secondary_object_uri,
        "secondary_source_version_id": (
            "manifest-v1" if secondary_uri else ""
        ),
        "target_credential_fingerprint": _TARGET_KEY,
        "auth_mode": "okx-v5" if target_authenticated else "static",
        "okx_auth_credentials": (
            {
                "api_key": "okx-api-key",
                "secret_key": "okx-secret-key",
                "passphrase": "okx-passphrase",
            }
            if target_authenticated
            else {}
        ),
        "headers_from_credentials": {},
        "required_response_headers": headers,
        "secondary_required_response_headers": secondary_headers,
        "timeout_seconds": 5,
    }


def _inventory() -> dict:
    result = {}
    for index, name in enumerate(sorted(_AUTHORITIES)):
        request = _request(name)
        result[name] = {
            "source_key_fingerprint": hashlib.sha256(
                f"key:{name}".encode()
            ).hexdigest(),
            "collector_unix_user": f"oqc{index:02d}",
            "signer_unix_user": f"oqs{index:02d}",
            "collector_systemd_unit": (
                f"okx-quant-canary-c{index:02d}.service"
            ),
            "signer_systemd_unit": (
                f"okx-quant-canary-s{index:02d}.service"
            ),
            "iam_principal": (
                f"arn:aws:iam::123456789012:role/canary-{index:02d}"
            ),
            "source_authority": _AUTHORITIES[name],
            "source_request_sha256": hashlib.sha256(
                json.dumps(
                    request,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            "collector_executable_sha256": "a" * 64,
            "signer_executable_sha256": "b" * 64,
            "parser_sha256": "c" * 64,
            "worm_object_uri": (
                f"s3://okx-canary-evidence/{name}.json"
            ),
            "worm_request_origin": (
                "https://okx-canary-evidence.s3."
                "ap-southeast-1.amazonaws.com"
            ),
            "worm_kms_key_id": (
                "arn:aws:kms:ap-southeast-1:123456789012:"
                "key/11111111-1111-1111-1111-111111111111"
            ),
            "worm_aws_region": "ap-southeast-1",
            "worm_reader_access_key_fingerprint": "d" * 64,
            "raw_source_path": (
                "/var/lib/okx-quant-canary-sources/raw/"
                f"{index:02d}/evidence.raw"
            ),
            "artifact_output_path": (
                "/var/lib/okx-quant-canary-sources/signed/"
                f"{index:02d}/source.json"
            ),
        }
    return result


def _receipt(name: str, raw: bytes, now: int) -> dict:
    inventory = _inventory()
    item = inventory[name]
    request = _request(name)
    token = hashlib.sha256(name.encode()).hexdigest()
    return {
        "version": 1,
        "action": "collect-canary-native-source",
        "producer_name": name,
        "source_authority": item["source_authority"],
        "source_request_sha256": item["source_request_sha256"],
        "collector_request": request,
        "adapter": request["adapter"],
        "source_uri": request["source_uri"],
        "source_version_id": request["source_version_id"],
        "request_method": "GET",
        "request_auth_timestamp": (
            datetime.fromtimestamp(now - 1, tz=UTC).isoformat()
            if request["auth_mode"] == "okx-v5"
            else ""
        ),
        "actual_target_credential_fingerprint": (
            _TARGET_KEY if request["auth_mode"] == "okx-v5" else ""
        ),
        "requested_at": now - 1,
        "response_status": 200,
        "response_headers": request["required_response_headers"],
        "received_at": now,
        "secondary_source_uri": request["secondary_source_uri"],
        "secondary_source_version_id": request[
            "secondary_source_version_id"
        ],
        "secondary_response_status": (
            200 if request["adapter"] == "s3-version" else 0
        ),
        "secondary_response_headers": request[
            "secondary_required_response_headers"
        ],
        "secondary_received_at": (
            now if request["adapter"] == "s3-version" else 0
        ),
        "source_device": 0,
        "source_inode": 0,
        "source_mode": 0,
        "source_uid": 0,
        "source_mount_id": "",
        "proc_fd_target": "",
        "raw_path": item["raw_source_path"],
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes": len(raw),
        "collected_at": now,
        "collector_unix_user": item["collector_unix_user"],
        "collector_uid": 10000,
        "collector_systemd_unit": item["collector_systemd_unit"],
        "collector_invocation_id": token[:32],
        "collector_cgroup": (
            f"/system.slice/{item['collector_systemd_unit']}"
        ),
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "mount_namespace_id": "mnt:[4026533001]",
    }


def _backup_bundle(now: int) -> bytes:
    request = _request("backup_exact_version_restored")
    archive = b"sqlite-exact-version-native-bytes"
    manifest = json.dumps(
        {
            "archive_object_uri": request["source_object_uri"],
            "archive_request_uri": request["source_uri"],
            "archive_version_id": request["source_version_id"],
            "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "archive_bytes": len(archive),
            "manifest_object_uri": request[
                "secondary_source_object_uri"
            ],
            "manifest_request_uri": request["secondary_source_uri"],
            "manifest_version_id": request[
                "secondary_source_version_id"
            ],
            "backup_completed_at": now - 10,
        },
        sort_keys=True,
    ).encode()
    return json.dumps(
        {
            "archive_get": {
                "request_uri": request["source_uri"],
                "version_id": request["source_version_id"],
                "response_headers": request[
                    "required_response_headers"
                ],
                "payload_sha256": hashlib.sha256(archive).hexdigest(),
                "payload_bytes": len(archive),
                "payload_base64": base64.b64encode(archive).decode(),
            },
            "manifest_get": {
                "request_uri": request["secondary_source_uri"],
                "version_id": request["secondary_source_version_id"],
                "response_headers": request[
                    "secondary_required_response_headers"
                ],
                "payload_sha256": hashlib.sha256(manifest).hexdigest(),
                "payload_bytes": len(manifest),
                "payload_base64": base64.b64encode(manifest).decode(),
            },
            "restore_requested_at": now,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_collection_receipt_rejects_endpoint_and_request_substitution():
    now = 1000
    name = "account_uid_verified"
    raw = b'{"code":"0","data":[{"uid":"target"}],"msg":""}'
    inventory = _inventory()
    receipt = _receipt(name, raw, now)
    validate_collection_receipt(
        receipt,
        producer_name=name,
        inventory=inventory,
        raw=raw,
        target_key_fingerprint=_TARGET_KEY,
        now=now,
    )

    changed_uri = json.loads(json.dumps(receipt))
    changed_uri["source_uri"] = "https://attacker.example/facts"
    with pytest.raises(ValueError, match="provenance"):
        validate_collection_receipt(
            changed_uri,
            producer_name=name,
            inventory=inventory,
            raw=raw,
            target_key_fingerprint=_TARGET_KEY,
            now=now,
        )

    changed_request = json.loads(json.dumps(receipt))
    changed_request["collector_request"]["source_uri"] = (
        "https://attacker.example/facts"
    )
    changed_request["source_uri"] = (
        "https://attacker.example/facts"
    )
    with pytest.raises(ValueError, match="provenance"):
        validate_collection_receipt(
            changed_request,
            producer_name=name,
            inventory=inventory,
            raw=raw,
            target_key_fingerprint=_TARGET_KEY,
            now=now,
        )


def test_s3_receipt_requires_exact_version_kms_and_object_lock():
    now = 1000
    name = "backup_exact_version_restored"
    raw = _backup_bundle(now)
    inventory = _inventory()
    receipt = _receipt(name, raw, now)
    validate_collection_receipt(
        receipt,
        producer_name=name,
        inventory=inventory,
        raw=raw,
        target_key_fingerprint=_TARGET_KEY,
        now=now,
    )
    for field, replacement in {
        "x-amz-version-id": "attacker-version",
        "x-amz-server-side-encryption": "AES256",
        "x-amz-object-lock-mode": "",
        "x-amz-object-lock-retain-until-date": (
            "1970-01-01T00:00:00Z"
        ),
    }.items():
        tampered = json.loads(json.dumps(receipt))
        tampered["response_headers"][field] = replacement
        with pytest.raises(ValueError):
            validate_collection_receipt(
                tampered,
                producer_name=name,
                inventory=inventory,
                raw=raw,
                target_key_fingerprint=_TARGET_KEY,
                now=now,
            )


def test_file_receipt_requires_root_owned_regular_source():
    name = "journal_identity_verified"
    inventory = _inventory()
    request = _request(name)
    request.update(
        {
            "adapter": "file",
            "method": "READ",
            "source_uri": "file:///var/lib/okx-quant/native/journal.db",
            "source_object_uri": "",
            "secondary_source_uri": "",
            "secondary_source_object_uri": "",
            "secondary_source_version_id": "",
            "auth_mode": "none",
            "okx_auth_credentials": {},
            "headers_from_credentials": {},
            "required_response_headers": {},
            "secondary_required_response_headers": {},
        }
    )
    inventory[name]["source_request_sha256"] = hashlib.sha256(
        json.dumps(
            request,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    raw = b"sqlite-native-snapshot"
    receipt = _receipt("account_uid_verified", raw, 1000)
    receipt.update(
        {
            "producer_name": name,
            "source_authority": inventory[name]["source_authority"],
            "source_request_sha256": inventory[name][
                "source_request_sha256"
            ],
            "collector_request": request,
            "adapter": "file",
            "source_uri": request["source_uri"],
            "request_method": "READ",
            "request_auth_timestamp": "",
            "actual_target_credential_fingerprint": "",
            "response_status": 0,
            "response_headers": {},
            "secondary_source_uri": "",
            "secondary_source_version_id": "",
            "secondary_response_status": 0,
            "secondary_response_headers": {},
            "secondary_received_at": 0,
            "source_device": 2049,
            "source_inode": 42,
            "source_mode": stat.S_IFREG | 0o400,
            "source_uid": 0,
            "source_mount_id": (
                f"{os.major(2049)}:{os.minor(2049)}"
            ),
            "proc_fd_target": "/var/lib/okx-quant/native/journal.db",
            "raw_path": inventory[name]["raw_source_path"],
            "collector_unix_user": inventory[name][
                "collector_unix_user"
            ],
            "collector_systemd_unit": inventory[name][
                "collector_systemd_unit"
            ],
            "collector_cgroup": (
                "/system.slice/"
                f"{inventory[name]['collector_systemd_unit']}"
            ),
        }
    )
    validate_collection_receipt(
        receipt,
        producer_name=name,
        inventory=inventory,
        raw=raw,
        target_key_fingerprint=_TARGET_KEY,
        now=1000,
    )
    receipt["source_uid"] = 1000
    with pytest.raises(ValueError, match="device/inode/fd"):
        validate_collection_receipt(
            receipt,
            producer_name=name,
            inventory=inventory,
            raw=raw,
            target_key_fingerprint=_TARGET_KEY,
            now=1000,
        )


def test_readiness_requires_reserve_then_single_consumption(tmp_path):
    state = tmp_path / "replay.json"
    state.chmod(0o700) if state.exists() else None
    arguments = {
        "readiness_id": "a" * 32,
        "bundle_sha256": "b" * 64,
        "transition_sha256": "c" * 64,
        "expires_at": 1300,
    }
    _reserve_canary_capability(state, **arguments)
    with pytest.raises(ValueError, match="reservation/replay"):
        _reserve_canary_capability(state, **arguments)
    consume_canary_capability_reservation(
        state,
        bundle_sha256=arguments["bundle_sha256"],
        approval_sha256="e" * 64,
        consumed_at=1200,
    )
    with pytest.raises(ValueError, match="已消费"):
        consume_canary_capability_reservation(
            state,
            bundle_sha256=arguments["bundle_sha256"],
            approval_sha256="f" * 64,
            consumed_at=1201,
        )
    with pytest.raises(ValueError, match="reservation/replay"):
        _reserve_canary_capability(
            state,
            **{
                **arguments,
                "bundle_sha256": "d" * 64,
            },
        )


def test_replay_state_serializes_concurrent_reserve_and_consume(
    tmp_path,
):
    state = tmp_path / "replay.json"
    arguments = {
        "readiness_id": "a" * 32,
        "bundle_sha256": "b" * 64,
        "transition_sha256": "c" * 64,
        "expires_at": 1300,
    }
    context = mp.get_context("fork")
    reserve_barrier = context.Barrier(2)
    reserve_results = context.Queue()
    reservers = [
        context.Process(
            target=_reserve_once,
            args=(
                state,
                arguments,
                reserve_barrier,
                reserve_results,
            ),
        )
        for _ in range(2)
    ]
    for process in reservers:
        process.start()
    for process in reservers:
        process.join(timeout=10)
        assert process.exitcode == 0
    assert sorted(reserve_results.get(timeout=1) for _ in range(2)) == [
        "ok",
        "rejected",
    ]

    consume_barrier = context.Barrier(2)
    consume_results = context.Queue()
    consumers = [
        context.Process(
            target=_consume_once,
            args=(
                state,
                arguments["bundle_sha256"],
                marker * 64,
                consume_barrier,
                consume_results,
            ),
        )
        for marker in ("d", "e")
    ]
    for process in consumers:
        process.start()
    for process in consumers:
        process.join(timeout=10)
        assert process.exitcode == 0
    assert sorted(consume_results.get(timeout=1) for _ in range(2)) == [
        "ok",
        "rejected",
    ]


def test_systemd_capability_enforces_two_stage_evidence_boundary():
    root = Path(__file__).parents[1]
    systemd = root / "deploy" / "systemd"
    capability = (
        systemd / "okx-quant-canary-capability@.service"
    ).read_text()
    deployment = (
        systemd / "okx-quant-canary-deployment-verifier.service"
    ).read_text()
    collector = (
        systemd / "okx-quant-canary-source-collector@.service"
    ).read_text()
    signer = (
        systemd / "okx-quant-canary-source-signer@.service"
    ).read_text()
    for index in range(12):
        suffix = f"{index:02d}.service"
        assert (
            f"okx-quant-canary-worm-readback@{suffix}"
            in capability
        )
        assert (
            f"okx-quant-canary-source-signer@{suffix}"
            not in deployment
        )
        assert (
            f"okx-quant-canary-source-signer@{suffix}"
            not in capability
        )
    assert (
        "Requires=okx-quant-canary-deployment-verifier.service"
        in capability
    )
    for credential in (
        "okx-api-key",
        "okx-secret-key",
        "okx-passphrase",
        "source-authorization",
    ):
        assert f"LoadCredential={credential}:" in collector
    worm_unit = (
        systemd / "okx-quant-canary-worm-readback@.service"
    ).read_text()
    assert "okx-quant-canary-source-signer@" not in worm_unit
    for credential in (
        "aws-access-key-id",
        "aws-secret-access-key",
        "aws-session-token",
    ):
        assert f"LoadCredential={credential}:" in worm_unit
    assert "object-authorization" not in worm_unit
    assert "--check-inputs-only" in capability
    assert "--iam-output" in signer
    for filename in (
        "okx-quant-canary-source-collector@.service",
        "okx-quant-canary-source-signer@.service",
        "okx-quant-canary-worm-readback@.service",
        "okx-quant-canary-deployment-verifier.service",
        "okx-quant-canary-capability@.service",
    ):
        assert "RemainAfterExit=yes" in (systemd / filename).read_text()

    manifest = json.loads(
        (
            root
            / "deploy"
            / "canary-producers"
            / "capability-manifest.json.example"
        ).read_text()
    )
    inventory = json.loads(
        (
            root
            / "deploy"
            / "canary-producers"
            / "inventory.json.example"
        ).read_text()
    )
    inventory = json.loads(
        (
            root
            / "deploy"
            / "canary-producers"
            / "inventory.json.example"
        ).read_text()
    )
    expected = set(_AUTHORITIES)
    assert set(manifest["producer_readiness"]) == expected
    assert set(manifest["iam_sts_receipt"]) == expected
    assert set(manifest["worm_readback_receipt"]) == expected
    assert set(manifest["worm_version_id"]) == expected
    for index, name in enumerate(sorted(expected)):
        marker = f"{index:02d}"
        assert inventory[name]["collector_unix_user"].endswith(marker)
        assert inventory[name]["signer_unix_user"].endswith(marker)
        assert f"@{marker}.service" in inventory[name][
            "collector_systemd_unit"
        ]
        assert f"@{marker}.service" in inventory[name][
            "signer_systemd_unit"
        ]
        assert f"/{marker}/" in inventory[name]["raw_source_path"]
        assert f"/{marker}/" in inventory[name]["artifact_output_path"]
        assert f"/{marker}/" in manifest["producer_readiness"][name]
        assert f"/{marker}/" in manifest["iam_sts_receipt"][name]
        assert f"/{marker}/" in manifest["worm_readback_receipt"][name]
        assert manifest["worm_version_id"][name].endswith(marker)
        assert inventory[name]["collector_unix_user"].endswith(marker)
        assert inventory[name]["signer_unix_user"].endswith(marker)


def test_worm_receipt_atomic_write_handles_partial_failure_and_race(
    tmp_path,
    monkeypatch,
):
    output = tmp_path / "receipt.json"
    original_write = os.write
    write_calls = 0

    def partial_then_fail(descriptor, value):
        nonlocal write_calls
        write_calls += 1
        if write_calls == 1:
            return original_write(
                descriptor,
                bytes(value[: max(1, len(value) // 2)]),
            )
        raise OSError("injected write failure")

    monkeypatch.setattr(os, "write", partial_then_fail)
    with pytest.raises(OSError, match="injected"):
        _atomic_worm_receipt(output, {"receipt": "value"})
    assert not output.exists()
    assert list(tmp_path.glob(".*.tmp")) == []

    monkeypatch.setattr(os, "write", original_write)
    original_link = os.link

    def racing_link(source, destination, **kwargs):
        Path(destination).write_text("racing-writer")
        return original_link(source, destination, **kwargs)

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(FileExistsError):
        _atomic_worm_receipt(output, {"receipt": "value"})
    assert output.read_text() == "racing-writer"
    assert list(tmp_path.glob(".*.tmp")) == []


def test_aws_s3_sigv4_matches_official_get_object_vector():
    access_key = "AKIAIOSFODNN7EXAMPLE"
    expected_fingerprint = credential_fingerprint(access_key)
    arguments = {
        "request_uri": (
            "https://examplebucket.s3.amazonaws.com/test.txt"
        ),
        "access_key_id": access_key,
        "secret_access_key": (
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ),
        "session_token": "",
        "region": "us-east-1",
        "timestamp": datetime(2013, 5, 24, tzinfo=UTC),
        "expected_access_key_fingerprint": expected_fingerprint,
        "extra_headers": {"range": "bytes=0-9"},
    }
    headers = _aws_sigv4_headers(**arguments)
    assert headers["x-amz-date"] == "20130524T000000Z"
    assert headers["x-amz-content-sha256"] == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )
    assert headers["Authorization"] == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIAIOSFODNN7EXAMPLE/"
        "20130524/us-east-1/s3/aws4_request,"
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310"
        "bd44f0170aba48dd91039c6036bdb41"
    )

    wrong_secret = _aws_sigv4_headers(
        **{**arguments, "secret_access_key": "wrong-secret"}
    )
    assert (
        wrong_secret["Authorization"]
        != headers["Authorization"]
    )
    wrong_region = _aws_sigv4_headers(
        **{**arguments, "region": "ap-southeast-1"}
    )
    assert (
        wrong_region["Authorization"]
        != headers["Authorization"]
    )
    with pytest.raises(ValueError, match="identity/region"):
        _aws_sigv4_headers(
            **{
                **arguments,
                "access_key_id": "AKIAWRONGKEYEXAMPLE",
            }
        )


def test_collector_rejects_wrong_actual_okx_credential(
    tmp_path,
    monkeypatch,
):
    for name, value in {
        "okx-api-key": "wrong-key",
        "okx-secret-key": "secret",
        "okx-passphrase": "passphrase",
    }.items():
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    request = _request("account_uid_verified")
    request["target_credential_fingerprint"] = credential_fingerprint(
        "expected-key"
    )
    with pytest.raises(ValueError, match="实际 OKX API key"):
        _okx_auth_headers(request)


def _worm_receipt(attestation: bytes, expected: dict) -> dict:
    policy = _inventory()["account_uid_verified"]
    return {
        "version": 1,
        "action": "attest-canary-worm-exact-get",
        "receipt_id": "1" * 32,
        "producer_name": "account_uid_verified",
        "readiness_id": expected["readiness_id"],
        "demo_soak_epoch_id": expected["demo_soak_epoch_id"],
        "target_deployment_identity_sha256": expected[
            "target_deployment_identity_sha256"
        ],
        "transition_sha256": expected["transition_sha256"],
        "requested_at": 995,
        "retrieved_at": 996,
        "request_method": "GET",
        "object_uri": policy["worm_object_uri"],
        "request_uri": (
            f"{policy['worm_request_origin']}/"
            "account_uid_verified.json?versionId=version-1"
        ),
        "version_id": "version-1",
        "expected_kms_key_id": policy["worm_kms_key_id"],
        "aws_region": policy["worm_aws_region"],
        "reader_access_key_fingerprint": policy[
            "worm_reader_access_key_fingerprint"
        ],
        "request_header_names": ["authorization"],
        "request_headers_sha256": "2" * 64,
        "response_status": 200,
        "response_headers": {
            "x-amz-version-id": "version-1",
            "x-amz-server-side-encryption": "aws:kms",
            "x-amz-server-side-encryption-aws-kms-key-id": (
                policy["worm_kms_key_id"]
            ),
            "x-amz-object-lock-mode": "COMPLIANCE",
            "x-amz-object-lock-retain-until-date": (
                "2100-01-01T00:00:00Z"
            ),
        },
        "readback_sha256": hashlib.sha256(attestation).hexdigest(),
        "readback_bytes": len(attestation),
        "readback_bytes_base64": base64.b64encode(attestation).decode(),
        "verifier_unix_user": "oqc-worm",
        "verifier_uid": 12001,
        "verifier_systemd_unit": (
            "okx-quant-canary-worm-readback@00.service"
        ),
        "verifier_invocation_id": "3" * 32,
        "verifier_cgroup": (
            "/system.slice/"
            "okx-quant-canary-worm-readback@00.service"
        ),
        "host_image_sha256": "4" * 64,
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "mount_namespace_id": "mnt:[4026534001]",
        "verifier_executable_sha256": "5" * 64,
        "nonce": "6" * 32,
    }


def _deployment_claims(inventory: dict, expected: dict) -> dict:
    permission = {
        "collector_can_write_raw_directory": True,
        "signer_can_read_raw_artifact": True,
        "signer_can_write_raw_artifact": False,
        "signer_can_write_signed_directory": True,
        "capability_can_read_signed_artifact": True,
        "capability_can_write_signed_artifact": False,
        "raw_directory_mode": "0750",
        "raw_artifact_mode": "0640",
        "signed_directory_mode": "0750",
        "signed_artifact_mode": "0640",
    }
    units = {
        name: {
            "producer_name": name,
            "collector_systemd_unit": item["collector_systemd_unit"],
            "collector_fragment_path": f"/etc/systemd/{name}-c.service",
            "collector_fragment_sha256": "7" * 64,
            "collector_exec_start_sha256": "8" * 64,
            "collector_executable_sha256": item[
                "collector_executable_sha256"
            ],
            "collector_user": item["collector_unix_user"],
            "signer_systemd_unit": item["signer_systemd_unit"],
            "signer_fragment_path": f"/etc/systemd/{name}-s.service",
            "signer_fragment_sha256": "9" * 64,
            "signer_exec_start_sha256": "a" * 64,
            "signer_executable_sha256": item[
                "signer_executable_sha256"
            ],
            "signer_user": item["signer_unix_user"],
            "parser_sha256": item["parser_sha256"],
            "permission_probe": permission,
        }
        for name, item in inventory.items()
    }
    return {
        "version": 1,
        "action": "attest-canary-deployment-units",
        "verifier_id": f"deployment-{'b' * 32}",
        **expected,
        "verifier_unix_user": "oqc-deploy-verify",
        "verifier_uid": 12002,
        "verifier_systemd_unit": (
            "okx-quant-canary-deployment-verifier.service"
        ),
        "verifier_invocation_id": "c" * 32,
        "verifier_cgroup": (
            "/system.slice/"
            "okx-quant-canary-deployment-verifier.service"
        ),
        "host_image_sha256": "d" * 64,
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "mount_namespace_id": "mnt:[4026534002]",
        "systemd_version": "systemd 255",
        "verifier_executable_sha256": "e" * 64,
        "producer_units": units,
        "observed_at": 999,
        "nonce": "f" * 32,
    }


def test_independent_worm_and_deployment_signatures_reject_tampering(
    tmp_path,
):
    worm_private, worm_public = _keypair(tmp_path, "worm")
    deployment_private, deployment_public = _keypair(
        tmp_path,
        "deployment",
    )
    expected = {
        "readiness_id": "1" * 32,
        "release_identity_sha256": "2" * 64,
        "config_sha256": "3" * 64,
        "account_uid": "canary-account",
        "demo_soak_epoch_id": "epoch-fixture-1",
        "target_deployment_identity_sha256": "4" * 64,
        "transition_sha256": "5" * 64,
        "source_producer_inventory_sha256": "6" * 64,
    }
    inventory = _inventory()
    worm_policy = inventory["account_uid_verified"]
    attestation = b'{"signed":"readiness"}'
    worm_claims = _worm_receipt(attestation, expected)
    worm_artifact = sign_ed25519_payload(worm_claims, worm_private)
    verified_worm = _verify_embedded_ed25519(
        worm_artifact,
        worm_public.read_bytes(),
        label="test WORM",
    )
    _validate_worm_readback_receipt(
        verified_worm,
        producer_name="account_uid_verified",
        attestation_raw=attestation,
        expected=expected,
        worm_policy=worm_policy,
        expected_version_id="version-1",
        issued_at=1000,
    )
    hostile = dict(verified_worm)
    hostile["request_uri"] = (
        "https://attacker.example/account_uid_verified.json"
        "?versionId=version-1"
    )
    hostile = _verify_embedded_ed25519(
        sign_ed25519_payload(hostile, worm_private),
        worm_public.read_bytes(),
        label="attacker-controlled HTTPS WORM",
    )
    with pytest.raises(ValueError, match="WORM exact GET receipt"):
        _validate_worm_readback_receipt(
            hostile,
            producer_name="account_uid_verified",
            attestation_raw=attestation,
            expected=expected,
            worm_policy=worm_policy,
            expected_version_id="version-1",
            issued_at=1000,
        )
    wrong_region = {
        **verified_worm,
        "aws_region": "us-east-1",
    }
    wrong_region = _verify_embedded_ed25519(
        sign_ed25519_payload(wrong_region, worm_private),
        worm_public.read_bytes(),
        label="wrong-region WORM",
    )
    with pytest.raises(ValueError, match="WORM exact GET receipt"):
        _validate_worm_readback_receipt(
            wrong_region,
            producer_name="account_uid_verified",
            attestation_raw=attestation,
            expected=expected,
            worm_policy=worm_policy,
            expected_version_id="version-1",
            issued_at=1000,
        )
    worm_artifact["payload"]["response_headers"][
        "x-amz-version-id"
    ] = "attacker-version"
    with pytest.raises(ValueError, match="签名"):
        _verify_embedded_ed25519(
            worm_artifact,
            worm_public.read_bytes(),
            label="test WORM",
        )

    deployment_expected = dict(expected)
    deployment_claims = _deployment_claims(
        inventory,
        deployment_expected,
    )
    target = {"host_image_sha256": "d" * 64}
    artifact = sign_ed25519_payload(
        deployment_claims,
        deployment_private,
    )
    verified = _verify_embedded_ed25519(
        artifact,
        deployment_public.read_bytes(),
        label="test deployment",
    )
    _validate_deployment_verifier(
        verified,
        inventory=inventory,
        expected=deployment_expected,
        target=target,
        issued_at=1000,
    )
    artifact["payload"]["producer_units"][
        "account_uid_verified"
    ]["permission_probe"]["signer_can_write_raw_artifact"] = True
    with pytest.raises(ValueError, match="签名"):
        _verify_embedded_ed25519(
            artifact,
            deployment_public.read_bytes(),
            label="test deployment",
        )


def test_canary_control_authority_key_reuse_is_rejected():
    distinct = {
        "capability": "1" * 64,
        "iam": "2" * 64,
        "worm_readback": "3" * 64,
        "deployment_verifier": "4" * 64,
    }
    validate_canary_control_key_separation(
        distinct,
        producer_fingerprints={"5" * 64},
        disallowed_key_fingerprints={"6" * 64},
    )
    with pytest.raises(ValueError, match="必须全部分离"):
        validate_canary_control_key_separation(
            {
                **distinct,
                "deployment_verifier": distinct["worm_readback"],
            },
            producer_fingerprints={"5" * 64},
            disallowed_key_fingerprints={"6" * 64},
        )
