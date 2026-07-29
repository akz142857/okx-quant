import base64
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import time
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from okx_quant.application.approval import (
    production_config_hash,
)
from okx_quant.config import ProductionSettings
from okx_quant.infrastructure.evidence import (
    credential_fingerprint,
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.research.canary import (
    _POST_START_EVIDENCE_KINDS,
    _PRE_START_EVIDENCE_KINDS,
    ALLOWED_DEPLOYMENT_DIFFERENCES,
    REQUIRED_POST_START_CHECKS,
    REQUIRED_PRE_START_CHECKS,
    _validate_post_start_source_facts,
    build_source_evidence,
    canary_limits_from_settings,
    canary_readiness_id,
    derive_post_start_facts,
    derive_pre_start_facts,
    identity_sha256,
    okx_ip_allowlist_sha256,
    target_identity_from_runtime,
    validate_canary_policy,
    validate_canary_runtime,
    validate_post_start_activation,
    validate_pre_start_source_claims,
    validate_transition,
    verify_post_start_activation,
    verify_transition,
)
from okx_quant.research.demo_soak import (
    canary_source_producer_inventory_sha256,
)
from scripts.canary_artifact import (
    _combine_signatures,
    _sign,
    _sign_role,
)
from scripts.production_gate import _actual_canary_release_identity

_CANARY_AUTHORITIES = {
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
_TARGET_KEY_FINGERPRINT = credential_fingerprint("canary-api-key")


def _collector_request(name: str) -> dict:
    if name in {
        "journal_identity_verified",
        "limits_match_policy",
        "release_identity_verified",
        "rest_ws_reconciliation_safe",
        "runtime_safety_kernel_live_within_60s",
    }:
        adapter = "file"
        method = "READ"
        source_uri = f"file:///var/lib/okx-quant/native/{name}"
        source_object_uri = ""
        secondary_source_uri = ""
        secondary_source_object_uri = ""
        required_headers = {}
        secondary_headers = {}
    elif name == "backup_exact_version_restored":
        adapter = "s3-version"
        method = "GET"
        source_uri = (
            "https://evidence.example/backup.db?versionId=version-1"
        )
        secondary_source_uri = (
            "https://evidence.example/backup.manifest.json"
            "?versionId=manifest-version-1"
        )
        source_object_uri = "s3://evidence/backup.db"
        secondary_source_object_uri = (
            "s3://evidence/backup.manifest.json"
        )
        required_headers = {
            "x-amz-version-id": "version-1",
            "x-amz-server-side-encryption": "aws:kms",
            "x-amz-server-side-encryption-aws-kms-key-id": (
                "arn:aws:kms:us-east-1:123456789012:key/test"
            ),
            "x-amz-object-lock-mode": "COMPLIANCE",
            "x-amz-object-lock-retain-until-date": (
                "2100-01-01T00:00:00Z"
            ),
        }
        secondary_headers = {
            **required_headers,
            "x-amz-version-id": "manifest-version-1",
        }
    else:
        adapter = "https"
        method = "GET"
        source_uri = f"https://evidence.example/{name}"
        secondary_source_uri = ""
        source_object_uri = ""
        secondary_source_object_uri = ""
        required_headers = {"date": "Mon, 01 Jan 2026 00:00:00 GMT"}
        secondary_headers = {}
    return {
        "version": 1,
        "producer_name": name,
        "adapter": adapter,
        "method": method,
        "source_uri": source_uri,
        "source_object_uri": source_object_uri,
        "source_version_id": "version-1",
        "secondary_source_uri": secondary_source_uri,
        "secondary_source_object_uri": secondary_source_object_uri,
        "secondary_source_version_id": (
            "manifest-version-1" if secondary_source_uri else ""
        ),
        "target_credential_fingerprint": _TARGET_KEY_FINGERPRINT,
        "auth_mode": (
            "okx-v5"
            if _CANARY_AUTHORITIES[name]
            in {
                "okx_authenticated_account_api",
                "okx_api_key_admin_api",
                "okx_account_and_business_ws",
            }
            else ("none" if adapter == "file" else "static")
        ),
        "okx_auth_credentials": (
            {
                "api_key": "okx-api-key",
                "secret_key": "okx-secret-key",
                "passphrase": "okx-passphrase",
            }
            if _CANARY_AUTHORITIES[name]
            in {
                "okx_authenticated_account_api",
                "okx_api_key_admin_api",
                "okx_account_and_business_ws",
            }
            else {}
        ),
        "headers_from_credentials": {},
        "required_response_headers": required_headers,
        "secondary_required_response_headers": secondary_headers,
        "timeout_seconds": 5,
    }


def _producer_inventory(fingerprints: dict) -> dict:
    return {
        name: {
            "source_key_fingerprint": fingerprints[name],
            "collector_unix_user": f"canaryc{index:02d}",
            "signer_unix_user": f"canarys{index:02d}",
            "collector_systemd_unit": (f"okx-quant-canary-c{index:02d}.service"),
            "signer_systemd_unit": (f"okx-quant-canary-s{index:02d}.service"),
            "iam_principal": f"canary-source-{index:02d}",
            "source_authority": _CANARY_AUTHORITIES[name],
            "source_request_sha256": hashlib.sha256(
                json.dumps(
                    _collector_request(name),
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
            "raw_source_path": (f"/var/lib/okx-quant-canary-sources/raw/{index:02d}.evidence"),
            "artifact_output_path": (f"/var/lib/okx-quant-canary-sources/signed/{index:02d}.json"),
        }
        for index, name in enumerate(sorted(fingerprints))
    }


def _producer_execution(
    name: str,
    inventory: dict,
    *,
    raw: bytes,
    now: int,
    epoch_id: str,
    target_sha256: str,
) -> dict:
    item = inventory[name]
    readiness_id = canary_readiness_id(
        demo_soak_epoch_id=epoch_id,
        target_deployment_identity_sha256=target_sha256,
        source_producer_inventory_sha256=(
            canary_source_producer_inventory_sha256(inventory)
        ),
    )
    token = hashlib.sha256(name.encode()).hexdigest()
    return {
        "version": 1,
        "producer_name": name,
        "readiness_id": readiness_id,
        "inventory_sha256": canary_source_producer_inventory_sha256(
            inventory
        ),
        "source_key_fingerprint": item["source_key_fingerprint"],
        "collector_unix_user": item["collector_unix_user"],
        "collector_uid": 10000 + list(sorted(inventory)).index(name) * 2,
        "collector_systemd_unit": item["collector_systemd_unit"],
        "collector_invocation_id": token[:32],
        "collector_cgroup": (
            f"/system.slice/{item['collector_systemd_unit']}"
        ),
        "signer_unix_user": item["signer_unix_user"],
        "signer_uid": 10001 + list(sorted(inventory)).index(name) * 2,
        "signer_systemd_unit": item["signer_systemd_unit"],
        "signer_invocation_id": token[32:],
        "signer_cgroup": (
            f"/system.slice/{item['signer_systemd_unit']}"
        ),
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "host_image_sha256": "2" * 64,
        "collector_mount_namespace_id": "mnt:[4026533001]",
        "signer_mount_namespace_id": "mnt:[4026533002]",
        "iam_principal": item["iam_principal"],
        "iam_sts_receipt_sha256": "9" * 64,
        "collector_executable_sha256": "a" * 64,
        "signer_executable_sha256": "b" * 64,
        "parser_sha256": "c" * 64,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes": len(raw),
        "collected_at": now,
        "signed_at": now,
        "nonce": hashlib.sha256(f"nonce:{name}".encode()).hexdigest()[:32],
    }


def _collection_receipt(
    name: str,
    inventory: dict,
    *,
    raw: bytes,
    now: int,
) -> dict:
    item = inventory[name]
    request = _collector_request(name)
    file_source = request["adapter"] == "file"
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
        "request_method": request["method"],
        "request_auth_timestamp": (
            datetime.fromtimestamp(now - 1, tz=UTC).isoformat()
            if request["auth_mode"] == "okx-v5"
            else ""
        ),
        "actual_target_credential_fingerprint": (
            _TARGET_KEY_FINGERPRINT
            if request["auth_mode"] == "okx-v5"
            else ""
        ),
        "requested_at": now - 1,
        "response_status": 0 if file_source else 200,
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
        "source_device": 2049 if file_source else 0,
        "source_inode": 42 if file_source else 0,
        "source_mode": (stat.S_IFREG | 0o400) if file_source else 0,
        "source_uid": 0,
        "source_mount_id": (
            f"{os.major(2049)}:{os.minor(2049)}"
            if file_source
            else ""
        ),
        "proc_fd_target": (
            request["source_uri"].removeprefix("file://")
            if file_source
            else ""
        ),
        "raw_path": item["raw_source_path"],
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes": len(raw),
        "collected_at": now,
        "collector_unix_user": item["collector_unix_user"],
        "collector_uid": 10000 + list(sorted(inventory)).index(name) * 2,
        "collector_systemd_unit": item["collector_systemd_unit"],
        "collector_invocation_id": token[:32],
        "collector_cgroup": (
            f"/system.slice/{item['collector_systemd_unit']}"
        ),
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "mount_namespace_id": "mnt:[4026533001]",
    }


def _keypair(tmp_path, name):
    private = tmp_path / f"{name}-private.pem"
    public = tmp_path / f"{name}-public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)],
        check=True,
        capture_output=True,
    )
    private.chmod(0o600)
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private),
            "-pubout",
            "-out",
            str(public),
        ],
        check=True,
        capture_output=True,
    )
    return private, public


def _dual(payload, operator_private, risk_private):
    return {
        "payload": payload,
        "operator_signature": sign_ed25519_payload(
            payload,
            operator_private,
        )["signature"],
        "risk_signature": sign_ed25519_payload(
            payload,
            risk_private,
        )["signature"],
    }


def _canary_config() -> dict:
    return {
        "okx": {
            "api_key": "canary-api-key",
            "base_url": "https://openapi.okx.com",
            "simulated": False,
        },
        "production": {
            "enabled": True,
            "environment": "production",
            "deployment_tier": "canary",
            "account_id": "canary-account",
            "journal_path": "/var/lib/okx-quant/production/trading.db",
            "lock_path": "/var/lib/okx-quant/production/trading.lock",
            "backup_dir": "/var/lib/okx-quant/production/backups",
            "heartbeat_path": "/var/lib/okx-quant/production/heartbeat",
            "allowed_instruments": ["BTC-USDT"],
            "max_order_loss_usdt": 2,
            "max_position_notional_usdt": 25,
            "max_total_exposure_usdt": 50,
            "max_open_positions": 1,
            "max_daily_loss_usdt": 5,
            "max_drawdown_ratio": 0.02,
            "max_order_intents_per_hour": 6,
            "max_slippage_ratio": 0.005,
        },
    }


def _post_start_source(
    tmp_path,
    *,
    name: str,
    source_private,
    source_public,
    inventory: dict,
    now: int,
    runtime_instance_id: str,
    boot_id: str,
    account_uid: str,
    deployment_unit: str,
    demo_soak_epoch_id: str,
    transition_sha256: str,
    policy_sha256: str,
    target_sha256: str,
    startup_nonce: str,
    startup_hard_epoch: int,
):
    if name == "runtime_safety_kernel_live_within_60s":
        raw_value = {
            "request": {
                "unit": deployment_unit,
                "runtime_instance_id": runtime_instance_id,
                "boot_id": boot_id,
                "startup_nonce": startup_nonce,
                "startup_hard_epoch": startup_hard_epoch,
                "requested_at": now - 1,
            },
            "response": {
                "observed_at": now,
                "systemd_show": {
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 123,
                    "InvocationID": "1" * 32,
                    "ControlGroup": (
                        f"/system.slice/{deployment_unit}"
                    ),
                    "ExecMainStartTimestampMonotonic": 123456,
                },
                "health_body": {
                    "live": True,
                    "runtime_started_at": now - 5,
                    "runtime_instance_id": runtime_instance_id,
                    "boot_id": boot_id,
                    "startup_nonce": startup_nonce,
                    "startup_hard_epoch": startup_hard_epoch,
                },
            },
        }
    elif name == "alert_challenge_received":
        raw_value = {
            "challenge": {
                "challenge_id": "challenge-1",
                "severity": "P0",
                "triggered_at": now - 2,
                "runtime_instance_id": runtime_instance_id,
                "startup_nonce": startup_nonce,
            },
            "provider_receipt": {
                "receipt_id": "provider-receipt-1",
                "challenge_id": "challenge-1",
                "severity": "P0",
                "provider_received_at": now - 1,
                "provider": "pager",
                "status": "delivered",
            },
        }
    elif name == "backup_exact_version_restored":
        database = tmp_path / "restore-native.db"
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE proof(value TEXT NOT NULL)")
        connection.execute("INSERT INTO proof VALUES('native')")
        connection.commit()
        connection.close()
        download = database.read_bytes()
        request = _collector_request(name)
        manifest = json.dumps(
            {
                "archive_object_uri": request["source_object_uri"],
                "archive_request_uri": request["source_uri"],
                "archive_version_id": request["source_version_id"],
                "archive_sha256": hashlib.sha256(download).hexdigest(),
                "archive_bytes": len(download),
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
        raw_value = {
            "archive_get": {
                "request_uri": request["source_uri"],
                "version_id": request["source_version_id"],
                "response_headers": request[
                    "required_response_headers"
                ],
                "payload_sha256": hashlib.sha256(download).hexdigest(),
                "payload_bytes": len(download),
                "payload_base64": base64.b64encode(download).decode(),
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
            "restore_requested_at": now - 5,
        }
    elif name == "protected_position_or_flat":
        raw_value = {
            "account_config_response": {
                "code": "0",
                "msg": "",
                "data": [{"uid": account_uid}],
            },
            "positions_response": {
                "code": "0",
                "msg": "",
                "data": [],
            },
            "algo_orders_response": {
                "code": "0",
                "msg": "",
                "data": [],
            },
            "business_ws_subscription": {
                "subscribed_at": now - 2,
                "channels": ["orders-algo", "positions"],
                "confirmed": True,
            },
            "business_ws_events": [
                {
                    "arg": {"channel": "positions"},
                    "data": [],
                    "seqId": 1,
                    "received_at": now - 1,
                },
                {
                    "arg": {"channel": "orders-algo"},
                    "data": [],
                    "seqId": 2,
                    "received_at": now - 1,
                },
            ],
        }
    else:
        raw_value = {
            "run": {
                "reconciliation_run_id": "reconcile-1",
                "runtime_instance_id": runtime_instance_id,
                "startup_nonce": startup_nonce,
                "started_at": now - 2,
                "completed_at": now - 1,
                "ws_generation_before": 7,
                "ws_generation_after": 7,
            },
            "rest_open_orders_response": {
                "code": "0",
                "msg": "",
                "data": [],
            },
            "ws_subscription": {
                "channel": "orders",
                "confirmed": True,
                "subscribed_at": now - 3,
                "subscription_id": "orders-sub-1",
            },
            "ws_order_events": [],
            "journal_open_orders": [],
        }
    collected_raw = json.dumps(raw_value, sort_keys=True).encode()
    if name != "runtime_safety_kernel_live_within_60s":
        raw_value = {
            "runtime_binding": {
                "runtime_instance_id": runtime_instance_id,
                "boot_id": boot_id,
                "deployment_unit": deployment_unit,
                "startup_nonce": startup_nonce,
                "startup_hard_epoch": startup_hard_epoch,
            },
            "native_payload_base64": base64.b64encode(
                collected_raw
            ).decode(),
            "native_sha256": hashlib.sha256(collected_raw).hexdigest(),
            "native_bytes": len(collected_raw),
        }
    else:
        raw_value = json.loads(collected_raw)
    evidence_raw = json.dumps(raw_value, sort_keys=True).encode()
    evidence = build_source_evidence(
        _POST_START_EVIDENCE_KINDS[name],
        evidence_raw,
    )
    source_artifact = sign_ed25519_payload(
        {
            "version": 1,
            "action": "attest-canary-post-start-source",
            "check": name,
            "observed_at": now,
            "runtime_instance_id": runtime_instance_id,
            "boot_id": boot_id,
            "account_uid": account_uid,
            "deployment_unit": deployment_unit,
            "demo_soak_epoch_id": demo_soak_epoch_id,
            "transition_sha256": transition_sha256,
            "policy_sha256": policy_sha256,
            "target_deployment_identity_sha256": target_sha256,
            "startup_nonce": startup_nonce,
            "expected_startup_hard_epoch": startup_hard_epoch,
            "producer_execution": _producer_execution(
                name,
                inventory,
                raw=collected_raw,
                now=now,
                epoch_id=demo_soak_epoch_id,
                target_sha256=target_sha256,
            ),
            "collection_receipt": _collection_receipt(
                name,
                inventory,
                raw=collected_raw,
                now=now,
            ),
            "source_evidence": evidence,
            "facts": derive_post_start_facts(name, evidence),
        },
        source_private,
    )
    source_raw = json.dumps(
        source_artifact,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return source_raw, source_public


def _pre_start_raw(
    tmp_path,
    check: str,
    target: dict,
    release: dict,
    config_raw: bytes,
    observed_at: int,
) -> bytes:
    if check == "account_uid_verified":
        return json.dumps(
            {
                "code": "0",
                "msg": "",
                "data": [{"uid": target["account_uid"]}],
            }
        ).encode()
    if check in {
        "api_key_read_trade_only",
        "api_key_withdraw_disabled",
        "ip_allowlist_verified",
    }:
        return json.dumps(
            {
                "code": "0",
                "msg": "",
                "data": [
                    {
                        "apiKey": "canary-api-key",
                        "perm": "read,trade",
                        "ip": "127.0.0.1",
                    }
                ],
            }
        ).encode()
    if check == "journal_identity_verified":
        snapshot = tmp_path / "canary-journal-snapshot.db"
        connection = sqlite3.connect(snapshot)
        connection.execute(
            """
            CREATE TABLE journal_identity(
                singleton INTEGER PRIMARY KEY,
                account_id TEXT NOT NULL,
                initial_config_hash TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO journal_identity VALUES(1, ?, ?)",
            (target["account_uid"], target["config_sha256"]),
        )
        connection.commit()
        connection.close()
        return snapshot.read_bytes()
    if check == "limits_match_policy":
        return config_raw
    return json.dumps(
        {
            "release_identity": release,
            "release_commit": target["release_commit"],
            "deployed_source_sha256": target["deployed_source_sha256"],
        }
    ).encode()


def _pre_start_evidence(
    tmp_path,
    *,
    target: dict,
    release: dict,
    epoch_id: str,
    now: int,
    config_raw: bytes,
    keys: dict,
    inventory: dict,
    pre_start_challenge: str,
) -> tuple[dict, dict, dict]:
    checks = {}
    fingerprints = {}
    for name in REQUIRED_PRE_START_CHECKS:
        private, public = keys[name]
        raw_source = _pre_start_raw(
            tmp_path,
            name,
            target,
            release,
            config_raw,
            now,
        )
        evidence = build_source_evidence(
            _PRE_START_EVIDENCE_KINDS[name],
            raw_source,
        )
        source = {
            "version": 1,
            "action": "attest-canary-pre-start-source",
            "check": name,
            "observed_at": now,
            "account_uid": target["account_uid"],
            "deployment_unit": target["unit"],
            "demo_soak_epoch_id": epoch_id,
            "release_identity_sha256": identity_sha256(release),
            "release_commit": target["release_commit"],
            "deployed_source_sha256": target["deployed_source_sha256"],
            "config_sha256": target["config_sha256"],
            "target_deployment_identity_sha256": identity_sha256(target),
            "pre_start_challenge": pre_start_challenge,
            "producer_execution": _producer_execution(
                name,
                inventory,
                raw=raw_source,
                now=now,
                epoch_id=epoch_id,
                target_sha256=identity_sha256(target),
            ),
            "collection_receipt": _collection_receipt(
                name,
                inventory,
                raw=raw_source,
                now=now,
            ),
            "source_evidence": evidence,
            "facts": derive_pre_start_facts(
                name,
                evidence,
                target=target,
                release_identity=release,
            ),
        }
        validate_pre_start_source_claims(
            source,
            check=name,
            target=target,
            release_identity=release,
            demo_soak_epoch_id=epoch_id,
            producer_inventory=inventory,
            pre_start_challenge=pre_start_challenge,
            now=now,
        )
        artifact = sign_ed25519_payload(source, private)
        raw = json.dumps(
            artifact,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        checks[name] = {
            "observed_at": now,
            "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "evidence_bytes": len(raw),
            "artifact_bytes_base64": base64.b64encode(raw).decode(),
            "source_public_key_pem_base64": base64.b64encode(public.read_bytes()).decode(),
        }
        fingerprints[name] = ed25519_public_key_fingerprint(public)
        keys[name] = (private, public)
    return checks, fingerprints, keys


def test_canary_transition_binds_demo_release_target_and_short_lived_limits(
    tmp_path,
):
    now = int(time.time())
    operator_private, operator_public = _keypair(tmp_path, "operator")
    risk_private, risk_public = _keypair(tmp_path, "risk")
    _verifier_private, verifier_public = _keypair(
        tmp_path,
        "post-start-verifier",
    )
    release = {
        "git_commit": "a" * 40,
        "git_tree_hash": "b" * 40,
        "source_manifest_sha256": "c" * 64,
        "dependency_lock_sha256": "d" * 64,
        "interpreter_sha256": "e" * 64,
    }
    config = _canary_config()
    config_settings = ProductionSettings.from_config(
        config,
        require_credentials=False,
        require_external_controls=False,
    )
    config_raw = json.dumps(config, sort_keys=True).encode()
    runtime_identity = {
        "commit_sha": release["git_commit"],
        "deployed_source_sha256": "f" * 64,
        "config_hash": production_config_hash(config_settings, config),
        "account_id": "canary-account",
        "environment": "production",
        "release_identity": release,
    }
    strategy_identity = {
        "strategy": "ma_cross",
        "bar": "1H",
        "instruments": ["BTC-USDT"],
        "interval_seconds": 60.0,
        "risk_parameters_sha256": "6" * 64,
    }
    runtime_identity["strategy_identity"] = strategy_identity
    pre_keys = {
        name: _keypair(tmp_path, f"pre-source-{name}")
        for name in REQUIRED_PRE_START_CHECKS
    }
    pre_start_fingerprints = {
        name: ed25519_public_key_fingerprint(public)
        for name, (_private, public) in pre_keys.items()
    }
    post_start_fingerprints = {
        name: hashlib.sha256(name.encode()).hexdigest()
        for name in REQUIRED_POST_START_CHECKS
    }
    inventory = _producer_inventory(
        {
            **pre_start_fingerprints,
            **post_start_fingerprints,
        }
    )
    target = target_identity_from_runtime(
        release_identity=release,
        strategy_identity=strategy_identity,
        source_producer_inventory=inventory,
        actual_runtime_identity=runtime_identity,
        config=config,
        host_image_sha256="2" * 64,
        ip_allowlist_sha256=okx_ip_allowlist_sha256("127.0.0.1"),
        api_permissions=("read", "trade"),
        deployment_unit="okx-quant.service",
        allowed_instruments=("BTC-USDT",),
    )
    pre_start_checks, pre_start_fingerprints, pre_keys = _pre_start_evidence(
        tmp_path,
        target=target,
        release=release,
        epoch_id="epoch-fixture-1",
        now=now - 1,
        config_raw=config_raw,
        keys=pre_keys,
        inventory=inventory,
        pre_start_challenge="7" * 32,
    )
    wrong_key_raw = json.loads(
        _pre_start_raw(
            tmp_path,
            "api_key_withdraw_disabled",
            target,
            release,
            config_raw,
            now - 1,
        )
    )
    wrong_key_raw["data"][0]["apiKey"] = "attacker-key"
    wrong_key_evidence = build_source_evidence(
        _PRE_START_EVIDENCE_KINDS[
            "api_key_withdraw_disabled"
        ],
        json.dumps(wrong_key_raw).encode(),
    )
    with pytest.raises(ValueError, match="OKX response"):
        derive_pre_start_facts(
            "api_key_withdraw_disabled",
            wrong_key_evidence,
            target=target,
            release_identity=release,
        )
    for field in release:
        replacement = "9" * 40 if field in {"git_commit", "git_tree_hash"} else "9" * 64
        with pytest.raises(ValueError, match="exact release"):
            target_identity_from_runtime(
                release_identity=release,
                strategy_identity=strategy_identity,
                source_producer_inventory=inventory,
                actual_runtime_identity={
                    **runtime_identity,
                    "release_identity": {
                        **release,
                        field: replacement,
                    },
                },
                config=config,
                host_image_sha256="2" * 64,
                ip_allowlist_sha256=okx_ip_allowlist_sha256(
                    "127.0.0.1"
                ),
                api_permissions=("read", "trade"),
                deployment_unit="okx-quant.service",
                allowed_instruments=("BTC-USDT",),
            )
    strategy_replacements = {
        "strategy": "breakout",
        "bar": "4H",
        "instruments": ["ETH-USDT"],
        "interval_seconds": 120.0,
        "risk_parameters_sha256": "9" * 64,
    }
    for field, replacement in strategy_replacements.items():
        with pytest.raises(ValueError, match="strategy identity"):
            target_identity_from_runtime(
                release_identity=release,
                strategy_identity=strategy_identity,
                source_producer_inventory=inventory,
                actual_runtime_identity={
                    **runtime_identity,
                    "strategy_identity": {
                        **strategy_identity,
                        field: replacement,
                    },
                },
                config=config,
                host_image_sha256="2" * 64,
                ip_allowlist_sha256=okx_ip_allowlist_sha256(
                    "127.0.0.1"
                ),
                api_permissions=("read", "trade"),
                deployment_unit="okx-quant.service",
                allowed_instruments=("BTC-USDT",),
            )
    transition = validate_transition(
        {
            "version": 1,
            "action": "authorize-demo-to-canary-transition",
            "transition_id": "transition-fixture-1",
            "issued_at": now - 1,
            "expires_at": now + 3600,
            "demo_soak_epoch_id": "epoch-fixture-1",
            "demo_ledger_head_hash": "4" * 64,
            "release_identity": release,
            "strategy_identity": strategy_identity,
            "target_deployment_identity": target,
            "allowed_deployment_differences": ALLOWED_DEPLOYMENT_DIFFERENCES,
            "required_pre_start_checks": REQUIRED_PRE_START_CHECKS,
            "pre_start_checks": pre_start_checks,
            "pre_start_source_key_fingerprints": pre_start_fingerprints,
            "canary_limits": canary_limits_from_settings(config_settings),
            "required_post_start_checks": REQUIRED_POST_START_CHECKS,
            "post_start_verifier_key_fingerprint": (
                ed25519_public_key_fingerprint(verifier_public)
            ),
            "post_start_source_key_fingerprints": (post_start_fingerprints),
            "source_producer_inventory": inventory,
            "source_producer_inventory_sha256": (
                canary_source_producer_inventory_sha256(inventory)
            ),
            "pre_start_challenge": "7" * 32,
            "operator": "operator-a",
            "risk_approver": "risk-b",
        }
    )
    wrong_release_transition = {
        **transition,
        "target_deployment_identity": {
            **target,
            "release_commit": "9" * 40,
        },
    }
    with pytest.raises(ValueError, match="exact release"):
        validate_transition(wrong_release_transition)
    with pytest.raises(ValueError, match="identity/checks"):
        validate_transition(
            {
                **transition,
                "post_start_source_key_fingerprints": {
                    name: "8" * 64 for name in REQUIRED_POST_START_CHECKS
                },
            }
        )
    missing_pre_start = dict(transition)
    missing_pre_start["pre_start_checks"] = {
        key: value
        for key, value in transition["pre_start_checks"].items()
        if key != "api_key_withdraw_disabled"
    }
    with pytest.raises(ValueError, match="pre-start"):
        validate_transition(missing_pre_start)
    tampered_pre_start = json.loads(json.dumps(transition))
    locator = tampered_pre_start["pre_start_checks"]["ip_allowlist_verified"]
    locator["evidence_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash/time"):
        validate_transition(tampered_pre_start)
    forged_facts_transition = json.loads(json.dumps(transition))
    forged_locator = forged_facts_transition["pre_start_checks"]["api_key_withdraw_disabled"]
    forged_artifact = json.loads(base64.b64decode(forged_locator["artifact_bytes_base64"]))
    forged_source = {
        **forged_artifact["payload"],
        "facts": {
            "withdraw_enabled": True,
            "checked_via": "okx_api_key_metadata",
        },
    }
    forged_raw = json.dumps(
        sign_ed25519_payload(
            forged_source,
            pre_keys["api_key_withdraw_disabled"][0],
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    forged_locator.update(
        {
            "evidence_sha256": hashlib.sha256(forged_raw).hexdigest(),
            "evidence_bytes": len(forged_raw),
            "artifact_bytes_base64": base64.b64encode(forged_raw).decode(),
        }
    )
    with pytest.raises(ValueError, match="raw evidence 重算"):
        validate_transition(forged_facts_transition)
    wrong_inventory = json.loads(json.dumps(transition))
    wrong_inventory["source_producer_inventory"]["account_uid_verified"][
        "source_key_fingerprint"
    ] = "8" * 64
    with pytest.raises(ValueError, match="预注册 producer"):
        validate_transition(wrong_inventory)
    changed_inventory_metadata = json.loads(json.dumps(transition))
    changed_inventory_metadata["source_producer_inventory"][
        "account_uid_verified"
    ]["iam_principal"] = "other-independent-principal"
    with pytest.raises(ValueError, match="canonical hash"):
        validate_transition(changed_inventory_metadata)
    policy = validate_canary_policy(
        {
            "version": 1,
            "action": "authorize-short-lived-canary",
            "policy_id": "canary-policy-fixture",
            "issued_at": now - 1,
            "expires_at": now + 1800,
            "transition_sha256": identity_sha256(transition),
            "target_deployment_identity_sha256": identity_sha256(target),
            "allowed_instruments": ["BTC-USDT"],
            "max_order_notional_usdt": 25,
            "max_order_intents_per_hour": 6,
            "max_concurrent_positions": 1,
            "max_total_exposure_usdt": 50,
            "max_order_loss_usdt": 2,
            "max_daily_loss_usdt": 5,
            "max_drawdown_ratio": 0.02,
            "max_slippage_ratio": 0.005,
            "auto_halt": {
                "unknown_buy_seconds": 30,
                "infrastructure_error_count": 3,
                "backup_rpo_seconds": 300,
                "clock_offset_seconds": 1,
            },
            "auto_flatten": {
                "unprotected_position_seconds": 10,
                "emergency_exit_without_approval": True,
                "ordinary_flatten_requires_dual_approval": True,
            },
            "operator": "operator-a",
            "risk_approver": "risk-b",
            "rollback_owner": "rollback-c",
            "production_promotion": "forbidden",
        }
    )
    transition_path = tmp_path / "transition.json"
    transition_path.write_text(json.dumps(_dual(transition, operator_private, risk_private)))
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_dual(policy, operator_private, risk_private)))
    settings = SimpleNamespace(
        environment="production",
        deployment_tier="canary",
        canary_transition_path=str(transition_path),
        canary_policy_path=str(policy_path),
        canary_operator_public_key=str(operator_public),
        canary_risk_public_key=str(risk_public),
        canary_check_verifier_public_key=str(verifier_public),
        api_permissions=("read", "trade"),
        ip_allowlist_sha256=okx_ip_allowlist_sha256("127.0.0.1"),
        deployment_unit="okx-quant.service",
        host_image_sha256="2" * 64,
        allowed_instruments=("BTC-USDT",),
        max_position_notional_usdt=25,
        max_total_exposure_usdt=50,
        max_order_loss_usdt=2,
        max_daily_loss_usdt=5,
        max_drawdown_ratio=0.02,
        max_slippage_ratio=0.005,
        max_order_intents_per_hour=6,
        max_open_positions=1,
        max_unprotected_position_s=10,
        max_consecutive_infrastructure_errors=3,
        max_clock_skew_s=1,
    )
    verified_transition, verified_policy = validate_canary_runtime(
        settings=settings,
        config=config,
        actual_runtime_identity=runtime_identity,
        deployment_receipt={"ledger_head_hash": "4" * 64},
        now=now,
    )
    assert verified_transition == transition
    assert verified_policy["production_promotion"] == "forbidden"

    wider_policy = {
        **policy,
        "max_total_exposure_usdt": 51,
    }
    policy_path.write_text(json.dumps(_dual(wider_policy, operator_private, risk_private)))
    with pytest.raises(ValueError, match="绑定不一致"):
        validate_canary_runtime(
            settings=settings,
            config=config,
            actual_runtime_identity=runtime_identity,
            deployment_receipt={"ledger_head_hash": "4" * 64},
            now=now,
        )
    policy_path.write_text(json.dumps(_dual(policy, operator_private, risk_private)))

    mismatched_release = {
        **runtime_identity,
        "release_identity": {
            **release,
            "source_manifest_sha256": "7" * 64,
        },
    }
    with pytest.raises(ValueError, match="exact release"):
        validate_canary_runtime(
            settings=settings,
            config=config,
            actual_runtime_identity=mismatched_release,
            deployment_receipt={"ledger_head_hash": "4" * 64},
            now=now,
        )
    mismatched_strategy = {
        **runtime_identity,
        "strategy_identity": {
            **strategy_identity,
            "risk_parameters_sha256": "8" * 64,
        },
    }
    with pytest.raises(ValueError, match="strategy/risk"):
        validate_canary_runtime(
            settings=settings,
            config=config,
            actual_runtime_identity=mismatched_strategy,
            deployment_receipt={"ledger_head_hash": "4" * 64},
            now=now,
        )
    with pytest.raises(ValueError, match="不同公钥"):
        verify_transition(
            _dual(transition, operator_private, operator_private),
            operator_public_key=operator_public,
            risk_public_key=operator_public,
            now=now,
        )

    settings.max_total_exposure_usdt = 101
    with pytest.raises(ValueError, match="超过"):
        validate_canary_runtime(
            settings=settings,
            config=config,
            actual_runtime_identity=runtime_identity,
            deployment_receipt={"ledger_head_hash": "4" * 64},
            now=now,
        )


def test_canary_policy_cannot_authorize_full_production():
    payload = {"production_promotion": "automatic"}
    with pytest.raises(ValueError, match="schema"):
        validate_canary_policy(payload)


def test_canary_post_start_activation_binds_runtime_and_all_evidence(
    tmp_path,
):
    now = int(time.time())
    operator_private, operator_public = _keypair(tmp_path, "post-operator")
    risk_private, risk_public = _keypair(tmp_path, "post-risk")
    verifier_private, verifier_public = _keypair(
        tmp_path,
        "post-check-verifier",
    )
    runtime_instance_id = "e" * 32
    boot_id = "12345678-1234-1234-1234-123456789abc"
    account_uid = "canary-account"
    deployment_unit = "okx-quant.service"
    demo_soak_epoch_id = "epoch-fixture-1"
    transition_sha256 = "b" * 64
    policy_sha256 = "c" * 64
    target_sha256 = "d" * 64
    checks = {}
    source_keys = {
        name: _keypair(tmp_path, f"source-{name}")
        for name in REQUIRED_POST_START_CHECKS
    }
    source_key_fingerprints = {
        name: ed25519_public_key_fingerprint(public)
        for name, (_private, public) in source_keys.items()
    }
    inventory = _producer_inventory(
        {
            **{
                name: hashlib.sha256(
                    f"unused-pre:{name}".encode()
                ).hexdigest()
                for name in REQUIRED_PRE_START_CHECKS
            },
            **source_key_fingerprints,
        }
    )
    for name in REQUIRED_POST_START_CHECKS:
        source_private, source_public = source_keys[name]
        source_raw, source_public = _post_start_source(
            tmp_path,
            name=name,
            source_private=source_private,
            source_public=source_public,
            inventory=inventory,
            now=now,
            runtime_instance_id=runtime_instance_id,
            boot_id=boot_id,
            account_uid=account_uid,
            deployment_unit=deployment_unit,
            demo_soak_epoch_id=demo_soak_epoch_id,
            transition_sha256=transition_sha256,
            policy_sha256=policy_sha256,
            target_sha256=target_sha256,
            startup_nonce="f" * 32,
            startup_hard_epoch=7,
        )
        source_fingerprint = ed25519_public_key_fingerprint(source_public)
        check_artifact = sign_ed25519_payload(
            {
                "version": 1,
                "action": "attest-canary-post-start-check",
                "check": name,
                "passed": True,
                "observed_at": now,
                "runtime_instance_id": runtime_instance_id,
                "boot_id": boot_id,
                "account_uid": account_uid,
                "deployment_unit": deployment_unit,
                "demo_soak_epoch_id": demo_soak_epoch_id,
                "transition_sha256": transition_sha256,
                "policy_sha256": policy_sha256,
                "target_deployment_identity_sha256": target_sha256,
                "source_evidence_sha256": hashlib.sha256(source_raw).hexdigest(),
                "source_key_fingerprint": source_fingerprint,
                "source_artifact_bytes_base64": base64.b64encode(source_raw).decode(),
                "source_public_key_pem_base64": base64.b64encode(
                    source_public.read_bytes()
                ).decode(),
            },
            verifier_private,
        )
        raw = json.dumps(
            check_artifact,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        checks[name] = {
            "passed": True,
            "observed_at": now,
            "evidence_uri": f"s3://evidence/post-start/{name}.json",
            "evidence_version_id": f"{name}-v1",
            "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "evidence_bytes": len(raw),
            "artifact_bytes_base64": base64.b64encode(raw).decode(),
        }
    payload = validate_post_start_activation(
        {
            "version": 1,
            "action": "activate-canary-entries-after-post-start",
            "issued_at": now,
            "expires_at": now + 600,
            "transition_sha256": transition_sha256,
            "policy_sha256": policy_sha256,
            "target_deployment_identity_sha256": target_sha256,
            "runtime_instance_id": runtime_instance_id,
            "boot_id": boot_id,
            "expected_startup_hard_epoch": 7,
            "startup_nonce": "f" * 32,
            "latch_reason": "canary_post_start_activation_pending",
            "checks_verifier_key_fingerprint": (ed25519_public_key_fingerprint(verifier_public)),
            "source_key_fingerprints": source_key_fingerprints,
            "checks": checks,
            "operator": "operator-a",
            "risk_approver": "risk-b",
        }
    )
    artifact = _dual(payload, operator_private, risk_private)

    assert (
        verify_post_start_activation(
            artifact,
            operator_public_key=operator_public,
            risk_public_key=risk_public,
            checks_verifier_public_key=verifier_public,
            source_key_fingerprints=source_key_fingerprints,
            producer_inventory=inventory,
            target_key_fingerprint=_TARGET_KEY_FINGERPRINT,
            transition_sha256=transition_sha256,
            policy_sha256=policy_sha256,
            target_deployment_identity_sha256=target_sha256,
            account_uid=account_uid,
            deployment_unit=deployment_unit,
            demo_soak_epoch_id=demo_soak_epoch_id,
            runtime_instance_id=runtime_instance_id,
            boot_id=boot_id,
            expected_startup_hard_epoch=7,
            startup_nonce="f" * 32,
            latch_reason="canary_post_start_activation_pending",
            now=now,
        )
        == payload
    )

    request_path = tmp_path / "activation-request.json"
    request_path.write_text(json.dumps(payload), encoding="utf-8")
    operator_partial = _sign_role(
        SimpleNamespace(
            role="operator",
            request=request_path,
            private_key=operator_private,
        )
    )
    risk_partial = _sign_role(
        SimpleNamespace(
            role="risk",
            request=request_path,
            private_key=risk_private,
        )
    )
    operator_partial_path = tmp_path / "operator-partial.json"
    risk_partial_path = tmp_path / "risk-partial.json"
    operator_partial_path.write_text(json.dumps(operator_partial))
    risk_partial_path.write_text(json.dumps(risk_partial))
    assert (
        _combine_signatures(
            SimpleNamespace(
                request=request_path,
                operator_signature=operator_partial_path,
                risk_signature=risk_partial_path,
                operator_public_key=operator_public,
                risk_public_key=risk_public,
            )
        )
        == artifact
    )

    with pytest.raises(ValueError, match="claims|未绑定"):
        verify_post_start_activation(
            artifact,
            operator_public_key=operator_public,
            risk_public_key=risk_public,
                checks_verifier_public_key=verifier_public,
                source_key_fingerprints=source_key_fingerprints,
                producer_inventory=inventory,
                target_key_fingerprint=_TARGET_KEY_FINGERPRINT,
                transition_sha256=transition_sha256,
            policy_sha256=policy_sha256,
            target_deployment_identity_sha256=target_sha256,
            account_uid=account_uid,
            deployment_unit=deployment_unit,
            demo_soak_epoch_id=demo_soak_epoch_id,
            runtime_instance_id="f" * 32,
            boot_id=boot_id,
            expected_startup_hard_epoch=7,
            startup_nonce="f" * 32,
            latch_reason="canary_post_start_activation_pending",
            now=now,
        )


def test_canary_legacy_dual_private_key_signing_is_disabled(tmp_path):
    private, _public = _keypair(tmp_path, "shared")
    copied = tmp_path / "copied-private.pem"
    copied.write_bytes(private.read_bytes())
    copied.chmod(0o600)
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "action": "authorize-demo-to-canary-transition",
            }
        )
    )
    with pytest.raises(RuntimeError, match="双私钥同进程签名已禁用"):
        _sign(
            SimpleNamespace(
                operator_private_key=private,
                risk_private_key=copied,
                request=request,
            )
        )


def test_canary_non_raw_post_summary_fails_closed():
    facts = {
        "challenge_id": "challenge-1",
        "severity": "P0",
        "triggered_at": 100,
        "provider_received_at": 101,
        "provider": "pager",
    }
    evidence = build_source_evidence(
        _POST_START_EVIDENCE_KINDS["alert_challenge_received"],
        json.dumps(facts).encode(),
    )
    with pytest.raises(ValueError, match="startup binding"):
        derive_post_start_facts(
            "alert_challenge_received",
            evidence,
        )


def test_canary_backup_recomputes_downloaded_bytes():
    raw = {
        "get_request": {
            "object_uri": "s3://evidence/backup.db",
            "version_id": "version-1",
        },
        "get_response": {
            "object_uri": "s3://evidence/backup.db",
            "version_id": "version-1",
            "sha256": hashlib.sha256(b"expected").hexdigest(),
            "bytes": len(b"expected"),
            "backup_completed_at": 90,
        },
        "restore_result": {
            "restored_at": 95,
            "download_payload_base64": base64.b64encode(
                b"tampered"
            ).decode(),
        },
    }
    evidence = build_source_evidence(
        _POST_START_EVIDENCE_KINDS[
            "backup_exact_version_restored"
        ],
        json.dumps(raw).encode(),
    )
    with pytest.raises(ValueError, match="startup binding"):
        derive_post_start_facts(
            "backup_exact_version_restored",
            evidence,
        )


def _wrapped_post_evidence(check: str, native: dict) -> dict:
    native_raw = json.dumps(
        native,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    wrapper = {
        "runtime_binding": {
            "runtime_instance_id": "1" * 32,
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "deployment_unit": "okx-quant.service",
            "startup_nonce": "2" * 32,
            "startup_hard_epoch": 7,
        },
        "native_payload_base64": base64.b64encode(native_raw).decode(),
        "native_sha256": hashlib.sha256(native_raw).hexdigest(),
        "native_bytes": len(native_raw),
    }
    return build_source_evidence(
        _POST_START_EVIDENCE_KINDS[check],
        json.dumps(wrapper, sort_keys=True).encode(),
    )


def test_position_protection_rejects_wrong_side_tiny_non_reduce_algo():
    position = {
        "instId": "BTC-USDT-SWAP",
        "posId": "position-1",
        "pos": "100",
        "posSide": "long",
    }
    bad_algo = {
        "instId": "BTC-USDT-SWAP",
        "posId": "position-1",
        "algoId": "algo-1",
        "state": "live",
        "ordType": "conditional",
        "side": "buy",
        "sz": "0.001",
        "accFillSz": "0",
        "reduceOnly": False,
        "closeFraction": "0.00001",
        "triggerPx": "50000",
    }
    facts = derive_post_start_facts(
        "protected_position_or_flat",
        _wrapped_post_evidence(
            "protected_position_or_flat",
            {
                "account_config_response": {
                    "code": "0",
                    "msg": "",
                    "data": [{"uid": "canary-account"}],
                },
                "positions_response": {
                    "code": "0",
                    "msg": "",
                    "data": [position],
                },
                "algo_orders_response": {
                    "code": "0",
                    "msg": "",
                    "data": [bad_algo],
                },
                "business_ws_subscription": {
                    "subscribed_at": 100,
                    "channels": ["orders-algo", "positions"],
                    "confirmed": True,
                },
                "business_ws_events": [
                    {
                        "arg": {"channel": "positions"},
                        "data": [position],
                        "seqId": 1,
                        "received_at": 101,
                    },
                    {
                        "arg": {"channel": "orders-algo"},
                        "data": [bad_algo],
                        "seqId": 2,
                        "received_at": 102,
                    },
                ],
            },
        ),
    )
    assert facts["active_protection_count"] == 0
    assert facts["unprotected_position_count"] == 1
    assert facts["position_state"] == "unprotected"


def test_reconciliation_requires_ws_payload_coverage_of_open_order():
    facts = derive_post_start_facts(
        "rest_ws_reconciliation_safe",
        _wrapped_post_evidence(
            "rest_ws_reconciliation_safe",
            {
                "run": {
                    "reconciliation_run_id": "run-1",
                    "runtime_instance_id": "1" * 32,
                    "startup_nonce": "2" * 32,
                    "started_at": 101,
                    "completed_at": 102,
                    "ws_generation_before": 9,
                    "ws_generation_after": 9,
                },
                "rest_open_orders_response": {
                    "code": "0",
                    "msg": "",
                    "data": [{"ordId": "o1", "state": "live"}],
                },
                "ws_subscription": {
                    "channel": "orders",
                    "confirmed": True,
                    "subscribed_at": 100,
                    "subscription_id": "sub-1",
                },
                "ws_order_events": [
                    {
                        "arg": {"channel": "orders"},
                        "data": [],
                        "seqId": 1,
                        "received_at": 101,
                    }
                ],
                "journal_open_orders": [
                    {
                        "exchange_order_id": "o1",
                        "state": "ACKNOWLEDGED",
                    }
                ],
            },
        ),
    )
    assert facts["rest_baseline_safe"] is True
    assert facts["ws_generation_safe"] is False
    assert facts["unresolved_count"] == 1


def test_reconciliation_rejects_ws_terminal_state_for_open_order():
    facts = derive_post_start_facts(
        "rest_ws_reconciliation_safe",
        _wrapped_post_evidence(
            "rest_ws_reconciliation_safe",
            {
                "run": {
                    "reconciliation_run_id": "run-state-conflict",
                    "runtime_instance_id": "1" * 32,
                    "startup_nonce": "2" * 32,
                    "started_at": 101,
                    "completed_at": 103,
                    "ws_generation_before": 9,
                    "ws_generation_after": 9,
                },
                "rest_open_orders_response": {
                    "code": "0",
                    "msg": "",
                    "data": [{"ordId": "o1", "state": "live"}],
                },
                "ws_subscription": {
                    "channel": "orders",
                    "confirmed": True,
                    "subscribed_at": 100,
                    "subscription_id": "sub-1",
                },
                "ws_order_events": [
                    {
                        "arg": {"channel": "orders"},
                        "data": [
                            {"ordId": "o1", "state": "canceled"}
                        ],
                        "seqId": 1,
                        "received_at": 102,
                    }
                ],
                "journal_open_orders": [
                    {
                        "exchange_order_id": "o1",
                        "state": "ACKNOWLEDGED",
                    }
                ],
            },
        ),
    )
    assert facts["rest_baseline_safe"] is True
    assert facts["ws_generation_safe"] is False
    assert facts["unresolved_count"] == 1


def test_position_protection_rejects_ws_canceled_algo():
    position = {
        "instId": "BTC-USDT-SWAP",
        "posId": "position-1",
        "pos": "100",
        "posSide": "long",
    }
    algo = {
        "instId": "BTC-USDT-SWAP",
        "posId": "position-1",
        "algoId": "algo-1",
        "state": "live",
        "ordType": "conditional",
        "side": "sell",
        "sz": "100",
        "accFillSz": "0",
        "reduceOnly": True,
        "closeFraction": "1",
        "triggerPx": "50000",
    }
    facts = derive_post_start_facts(
        "protected_position_or_flat",
        _wrapped_post_evidence(
            "protected_position_or_flat",
            {
                "account_config_response": {
                    "code": "0",
                    "msg": "",
                    "data": [{"uid": "canary-account"}],
                },
                "positions_response": {
                    "code": "0",
                    "msg": "",
                    "data": [position],
                },
                "algo_orders_response": {
                    "code": "0",
                    "msg": "",
                    "data": [algo],
                },
                "business_ws_subscription": {
                    "subscribed_at": 100,
                    "channels": ["orders-algo", "positions"],
                    "confirmed": True,
                },
                "business_ws_events": [
                    {
                        "arg": {"channel": "positions"},
                        "data": [position],
                        "seqId": 1,
                        "received_at": 101,
                    },
                    {
                        "arg": {"channel": "orders-algo"},
                        "data": [{**algo, "state": "canceled"}],
                        "seqId": 2,
                        "received_at": 102,
                    },
                ],
            },
        ),
    )
    assert facts["active_protection_count"] == 0
    assert facts["unprotected_position_count"] == 1
    assert facts["position_state"] == "unprotected"


def test_position_snapshot_rejects_ws_quantity_mismatch():
    position = {
        "instId": "BTC-USDT-SWAP",
        "posId": "position-1",
        "pos": "100",
        "posSide": "long",
    }
    with pytest.raises(ValueError, match="size/side snapshot"):
        derive_post_start_facts(
            "protected_position_or_flat",
            _wrapped_post_evidence(
                "protected_position_or_flat",
                {
                    "account_config_response": {
                        "code": "0",
                        "msg": "",
                        "data": [{"uid": "canary-account"}],
                    },
                    "positions_response": {
                        "code": "0",
                        "msg": "",
                        "data": [position],
                    },
                    "algo_orders_response": {
                        "code": "0",
                        "msg": "",
                        "data": [],
                    },
                    "business_ws_subscription": {
                        "subscribed_at": 100,
                        "channels": ["orders-algo", "positions"],
                        "confirmed": True,
                    },
                    "business_ws_events": [
                        {
                            "arg": {"channel": "positions"},
                            "data": [{**position, "pos": "200"}],
                            "seqId": 1,
                            "received_at": 101,
                        },
                        {
                            "arg": {"channel": "orders-algo"},
                            "data": [],
                            "seqId": 2,
                            "received_at": 102,
                        },
                    ],
                },
            ),
        )


def test_reconciliation_requires_exact_normalized_state():
    facts = derive_post_start_facts(
        "rest_ws_reconciliation_safe",
        _wrapped_post_evidence(
            "rest_ws_reconciliation_safe",
            {
                "run": {
                    "reconciliation_run_id": "run-state-watermark",
                    "runtime_instance_id": "1" * 32,
                    "startup_nonce": "2" * 32,
                    "started_at": 101,
                    "completed_at": 103,
                    "ws_generation_before": 9,
                    "ws_generation_after": 9,
                },
                "rest_open_orders_response": {
                    "code": "0",
                    "msg": "",
                    "data": [
                        {
                            "ordId": "o1",
                            "state": "partially_filled",
                        }
                    ],
                },
                "ws_subscription": {
                    "channel": "orders",
                    "confirmed": True,
                    "subscribed_at": 100,
                    "subscription_id": "sub-1",
                },
                "ws_order_events": [
                    {
                        "arg": {"channel": "orders"},
                        "data": [{"ordId": "o1", "state": "live"}],
                        "seqId": 1,
                        "received_at": 102,
                    }
                ],
                "journal_open_orders": [
                    {
                        "exchange_order_id": "o1",
                        "state": "ACKNOWLEDGED",
                    }
                ],
            },
        ),
    )
    assert facts["rest_baseline_safe"] is False
    assert facts["ws_generation_safe"] is False
    assert facts["unresolved_count"] == 1


def test_reconciliation_rejects_pre_run_ws_event():
    with pytest.raises(ValueError, match="private WS order"):
        derive_post_start_facts(
            "rest_ws_reconciliation_safe",
            _wrapped_post_evidence(
                "rest_ws_reconciliation_safe",
                {
                    "run": {
                        "reconciliation_run_id": "run-stale-event",
                        "runtime_instance_id": "1" * 32,
                        "startup_nonce": "2" * 32,
                        "started_at": 101,
                        "completed_at": 103,
                        "ws_generation_before": 9,
                        "ws_generation_after": 9,
                    },
                    "rest_open_orders_response": {
                        "code": "0",
                        "msg": "",
                        "data": [{"ordId": "o1", "state": "live"}],
                    },
                    "ws_subscription": {
                        "channel": "orders",
                        "confirmed": True,
                        "subscribed_at": 90,
                        "subscription_id": "sub-1",
                    },
                    "ws_order_events": [
                        {
                            "arg": {"channel": "orders"},
                            "data": [
                                {"ordId": "o1", "state": "live"}
                            ],
                            "seqId": 1,
                            "received_at": 100,
                        }
                    ],
                    "journal_open_orders": [
                        {
                            "exchange_order_id": "o1",
                            "state": "ACKNOWLEDGED",
                        }
                    ],
                },
            ),
        )


def test_position_source_rejects_stale_ws_channel_snapshots():
    evidence = _wrapped_post_evidence(
        "protected_position_or_flat",
        {
            "account_config_response": {
                "code": "0",
                "msg": "",
                "data": [{"uid": "canary-account"}],
            },
            "positions_response": {
                "code": "0",
                "msg": "",
                "data": [],
            },
            "algo_orders_response": {
                "code": "0",
                "msg": "",
                "data": [],
            },
            "business_ws_subscription": {
                "subscribed_at": 99,
                "channels": ["orders-algo", "positions"],
                "confirmed": True,
            },
            "business_ws_events": [
                {
                    "arg": {"channel": "positions"},
                    "data": [],
                    "seqId": 1,
                    "received_at": 100,
                },
                {
                    "arg": {"channel": "orders-algo"},
                    "data": [],
                    "seqId": 2,
                    "received_at": 101,
                },
            ],
        },
    )
    facts = derive_post_start_facts(
        "protected_position_or_flat",
        evidence,
    )
    with pytest.raises(ValueError, match="flat 或全部仓位已保护"):
        _validate_post_start_source_facts(
            "protected_position_or_flat",
            facts,
            source_evidence=evidence,
            observed_at=200,
            account_uid="canary-account",
        )


def test_reconciliation_source_rejects_stale_completion():
    evidence = _wrapped_post_evidence(
        "rest_ws_reconciliation_safe",
        {
            "run": {
                "reconciliation_run_id": "run-stale-completion",
                "runtime_instance_id": "1" * 32,
                "startup_nonce": "2" * 32,
                "started_at": 99,
                "completed_at": 100,
                "ws_generation_before": 9,
                "ws_generation_after": 9,
            },
            "rest_open_orders_response": {
                "code": "0",
                "msg": "",
                "data": [],
            },
            "ws_subscription": {
                "channel": "orders",
                "confirmed": True,
                "subscribed_at": 98,
                "subscription_id": "sub-1",
            },
            "ws_order_events": [],
            "journal_open_orders": [],
        },
    )
    facts = derive_post_start_facts(
        "rest_ws_reconciliation_safe",
        evidence,
    )
    with pytest.raises(ValueError, match="reconciliation safe"):
        _validate_post_start_source_facts(
            "rest_ws_reconciliation_safe",
            facts,
            source_evidence=evidence,
            observed_at=200,
            account_uid="canary-account",
        )


def test_actual_canary_release_identity_hashes_deployed_bytes(tmp_path):
    revision = tmp_path / "REVISION"
    revision.write_text("a" * 40, encoding="ascii")
    (tmp_path / "non-live-validation.json").write_text("{}")
    lock = tmp_path / "uv.lock"
    lock.write_bytes(b"locked-dependencies")
    interpreter = tmp_path / "python"
    interpreter.write_bytes(b"exact-interpreter")
    evidence = {
        "git_commit": "a" * 40,
        "git_tree_hash": "b" * 40,
        "source_manifest_sha256": "c" * 64,
    }
    observed = {}

    def verify(evidence_path, revision_path):
        observed.update(
            {
                "evidence_path": evidence_path,
                "revision_path": revision_path,
            }
        )
        return evidence

    assert _actual_canary_release_identity(
        release_root=tmp_path,
        release_commit_file=revision,
        interpreter=interpreter,
        evidence_verifier=verify,
    ) == {
        **evidence,
        "dependency_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "interpreter_sha256": hashlib.sha256(interpreter.read_bytes()).hexdigest(),
    }
    assert observed == {
        "evidence_path": tmp_path / "non-live-validation.json",
        "revision_path": revision,
    }
