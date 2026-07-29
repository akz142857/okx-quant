"""生产运行时、组合风控和控制命令集成测试。"""

import base64
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import threading
import time
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace

import pandas as pd
import pytest

from okx_quant.application.execution import ExecutionRequest
from okx_quant.application.reconciliation import ReconciliationResult
from okx_quant.application.risk_service import (
    ProductionRiskLimits,
    ProductionRiskService,
)
from okx_quant.application.runtime import ProductionRuntime, SingleInstanceLock
from okx_quant.cli.operations import enqueue_and_wait
from okx_quant.client.websocket import ConnectionState, OKXWebSocketClient
from okx_quant.domain.orders import OrderState, SystemMode
from okx_quant.exchange import InstrumentInfo
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.research.canary import (
    _POST_START_EVIDENCE_KINDS,
    REQUIRED_POST_START_CHECKS,
    REQUIRED_PRE_START_CHECKS,
    build_source_evidence,
    canary_readiness_id,
    derive_post_start_facts,
)
from okx_quant.research.demo_soak import (
    canary_source_producer_inventory_sha256,
)
from okx_quant.risk.manager import PositionInfo, RiskManager
from okx_quant.trading.orders import OrderExecutor


def _runtime(tmp_path, *, limits=None):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=50_000, bid=49_990, ask=50_010)
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        risk_limits=limits,
        lock_path=tmp_path / "trading.lock",
        reconciliation_interval_s=0.05,
    )
    return exchange, journal, runtime


def _ed25519_pair(root, name):
    private_key = root / f"{name}-private.pem"
    public_key = root / f"{name}-public.pem"
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
_CANARY_TARGET_KEY = "d" * 64


def _canary_request(name):
    file_source = name in {
        "journal_identity_verified",
        "limits_match_policy",
        "release_identity_verified",
        "rest_ws_reconciliation_safe",
        "runtime_safety_kernel_live_within_60s",
    }
    if name == "backup_exact_version_restored":
        adapter = "s3-version"
        uri = "https://evidence.example/backup.db?versionId=v1"
        secondary_uri = (
            "https://evidence.example/backup.manifest.json"
            "?versionId=manifest-v1"
        )
        object_uri = "s3://evidence/backup.db"
        secondary_object_uri = "s3://evidence/backup.manifest.json"
        headers = {
            "x-amz-version-id": "v1",
            "x-amz-server-side-encryption": "aws:kms",
            "x-amz-server-side-encryption-aws-kms-key-id": "kms-test",
            "x-amz-object-lock-mode": "COMPLIANCE",
            "x-amz-object-lock-retain-until-date": (
                "2100-01-01T00:00:00Z"
            ),
        }
        secondary_headers = {
            **headers,
            "x-amz-version-id": "manifest-v1",
        }
    elif file_source:
        adapter = "file"
        uri = f"file:///var/lib/okx-quant/native/{name}"
        secondary_uri = ""
        object_uri = ""
        secondary_object_uri = ""
        headers = {}
        secondary_headers = {}
    else:
        adapter = "https"
        uri = f"https://evidence.example/{name}"
        secondary_uri = ""
        object_uri = ""
        secondary_object_uri = ""
        headers = {"date": "Mon, 01 Jan 2026 00:00:00 GMT"}
        secondary_headers = {}
    return {
        "version": 1,
        "producer_name": name,
        "adapter": adapter,
        "method": "READ" if adapter == "file" else "GET",
        "source_uri": uri,
        "source_object_uri": object_uri,
        "source_version_id": "v1",
        "secondary_source_uri": secondary_uri,
        "secondary_source_object_uri": secondary_object_uri,
        "secondary_source_version_id": (
            "manifest-v1" if secondary_uri else ""
        ),
        "target_credential_fingerprint": _CANARY_TARGET_KEY,
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
        "required_response_headers": headers,
        "secondary_required_response_headers": secondary_headers,
        "timeout_seconds": 5,
    }


def _canary_inventory(source_keys):
    fingerprints = {
        **{
            name: hashlib.sha256(f"pre:{name}".encode()).hexdigest()
            for name in REQUIRED_PRE_START_CHECKS
        },
        **{
            name: ed25519_public_key_fingerprint(keys[1])
            for name, keys in source_keys.items()
        },
    }
    result = {}
    for index, name in enumerate(sorted(fingerprints)):
        request = _canary_request(name)
        result[name] = {
            "source_key_fingerprint": fingerprints[name],
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
            "source_authority": _CANARY_AUTHORITIES[name],
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


def _canary_execution_and_receipt(runtime, name, raw, now):
    inventory = runtime.canary_source_producer_inventory
    item = inventory[name]
    index = list(sorted(inventory)).index(name)
    token = hashlib.sha256(name.encode()).hexdigest()
    request = _canary_request(name)
    file_source = request["adapter"] == "file"
    execution = {
        "version": 1,
        "producer_name": name,
        "readiness_id": canary_readiness_id(
            demo_soak_epoch_id=runtime.soak_epoch_id,
            target_deployment_identity_sha256=(
                runtime.canary_target_sha256
            ),
            source_producer_inventory_sha256=(
                canary_source_producer_inventory_sha256(inventory)
            ),
        ),
        "inventory_sha256": (
            canary_source_producer_inventory_sha256(inventory)
        ),
        "source_key_fingerprint": item["source_key_fingerprint"],
        "collector_unix_user": item["collector_unix_user"],
        "collector_uid": 10000 + index * 2,
        "collector_systemd_unit": item["collector_systemd_unit"],
        "collector_invocation_id": token[:32],
        "collector_cgroup": (
            f"/system.slice/{item['collector_systemd_unit']}"
        ),
        "signer_unix_user": item["signer_unix_user"],
        "signer_uid": 10001 + index * 2,
        "signer_systemd_unit": item["signer_systemd_unit"],
        "signer_invocation_id": token[32:],
        "signer_cgroup": f"/system.slice/{item['signer_systemd_unit']}",
        "boot_id": runtime.runtime_boot_id,
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
    receipt = {
        "version": 1,
        "action": "collect-canary-native-source",
        "producer_name": name,
        "source_authority": item["source_authority"],
        "source_request_sha256": item["source_request_sha256"],
        "collector_request": request,
        "adapter": request["adapter"],
        "source_uri": request["source_uri"],
        "source_version_id": "v1",
        "request_method": request["method"],
        "request_auth_timestamp": (
            datetime.fromtimestamp(now - 1, tz=UTC).isoformat()
            if request["auth_mode"] == "okx-v5"
            else ""
        ),
        "actual_target_credential_fingerprint": (
            _CANARY_TARGET_KEY
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
        "source_mode": stat.S_IFREG | 0o400 if file_source else 0,
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
        "collector_uid": 10000 + index * 2,
        "collector_systemd_unit": item["collector_systemd_unit"],
        "collector_invocation_id": token[:32],
        "collector_cgroup": (
            f"/system.slice/{item['collector_systemd_unit']}"
        ),
        "boot_id": runtime.runtime_boot_id,
        "mount_namespace_id": "mnt:[4026533001]",
    }
    return execution, receipt


def _backup_restore_evidence(now: float) -> dict:
    return {
        "version": 1,
        "action": "attest-offsite-backup-restore",
        "evidence_key_id": "backup-signing-v1",
        "account_id": "demo-account",
        "schema_version": 11,
        "receipt_sha256": "a" * 64,
        "archive_uri": "s3://backup/archive.enc",
        "archive_version_id": "archive-version-1",
        "archive_sha256": "b" * 64,
        "archive_bytes": 123,
        "manifest_uri": "s3://backup/archive.enc.manifest.json",
        "manifest_version_id": "manifest-version-1",
        "manifest_sha256": "c" * 64,
        "manifest_bytes": 456,
        "snapshot_completed_at": now - 2,
        "roundtrip_started_at": now - 1,
        "roundtrip_completed_at": now,
        "restore": {
            "ok": True,
            "database_ok": True,
            "checksum_verified": True,
            "integrity_check": "ok",
            "account_id": "demo-account",
            "schema_version": 11,
        },
        "backup_slo_sample": {
            "integrity": "ok",
            "snapshot_completed_at": now - 2,
            "offsite_readback_at": now,
            "version_id": "archive-version-1",
        },
    }


def _canary_post_raw(runtime, root, name, now):
    if name == "runtime_safety_kernel_live_within_60s":
        return {
            "request": {
                "unit": runtime.deployment_unit,
                "runtime_instance_id": runtime.runtime_instance_id,
                "boot_id": runtime.runtime_boot_id,
                "startup_nonce": runtime._canary_startup_nonce,
                "startup_hard_epoch": (
                    runtime._canary_startup_hard_epoch
                ),
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
                        f"/system.slice/{runtime.deployment_unit}"
                    ),
                    "ExecMainStartTimestampMonotonic": 123456,
                },
                "health_body": {
                    "live": True,
                    "runtime_started_at": now - 5,
                    "runtime_instance_id": runtime.runtime_instance_id,
                    "boot_id": runtime.runtime_boot_id,
                    "startup_nonce": runtime._canary_startup_nonce,
                    "startup_hard_epoch": (
                        runtime._canary_startup_hard_epoch
                    ),
                },
            },
        }
    if name == "alert_challenge_received":
        return {
            "runtime_binding": {
                "runtime_instance_id": runtime.runtime_instance_id,
                "boot_id": runtime.runtime_boot_id,
                "deployment_unit": runtime.deployment_unit,
                "startup_nonce": runtime._canary_startup_nonce,
                "startup_hard_epoch": (
                    runtime._canary_startup_hard_epoch
                ),
            },
            "native": {
                "challenge": {
                    "challenge_id": "challenge-1",
                    "severity": "P0",
                    "triggered_at": now - 2,
                    "runtime_instance_id": runtime.runtime_instance_id,
                    "startup_nonce": runtime._canary_startup_nonce,
                },
                "provider_receipt": {
                    "receipt_id": "provider-receipt-1",
                    "challenge_id": "challenge-1",
                    "severity": "P0",
                    "provider_received_at": now - 1,
                    "provider": "pager",
                    "status": "delivered",
                },
            },
        }
    if name == "backup_exact_version_restored":
        database = root / "canary-backup-native.db"
        connection = sqlite3.connect(database)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS proof(value TEXT NOT NULL)"
        )
        connection.commit()
        connection.close()
        download = database.read_bytes()
        request = _canary_request(name)
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
        return {
            "runtime_binding": {
                "runtime_instance_id": runtime.runtime_instance_id,
                "boot_id": runtime.runtime_boot_id,
                "deployment_unit": runtime.deployment_unit,
                "startup_nonce": runtime._canary_startup_nonce,
                "startup_hard_epoch": (
                    runtime._canary_startup_hard_epoch
                ),
            },
            "native": {
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
                    "version_id": request[
                        "secondary_source_version_id"
                    ],
                    "response_headers": request[
                        "secondary_required_response_headers"
                    ],
                    "payload_sha256": hashlib.sha256(manifest).hexdigest(),
                    "payload_bytes": len(manifest),
                    "payload_base64": base64.b64encode(manifest).decode(),
                },
                "restore_requested_at": now - 5,
            },
        }
    if name == "protected_position_or_flat":
        native = {
            "account_config_response": {
                "code": "0",
                "msg": "",
                "data": [{"uid": runtime.expected_account_id}],
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
        native = {
        "run": {
            "reconciliation_run_id": "reconcile-1",
            "runtime_instance_id": runtime.runtime_instance_id,
            "startup_nonce": runtime._canary_startup_nonce,
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
    return {
        "runtime_binding": {
            "runtime_instance_id": runtime.runtime_instance_id,
            "boot_id": runtime.runtime_boot_id,
            "deployment_unit": runtime.deployment_unit,
            "startup_nonce": runtime._canary_startup_nonce,
            "startup_hard_epoch": runtime._canary_startup_hard_epoch,
        },
        "native": native,
    }


def _write_canary_activation(
    runtime,
    path,
    operator_private,
    risk_private,
    verifier_private,
    source_keys,
    *,
    now,
    hard_epoch=None,
):
    payload = {
        "version": 1,
        "action": "activate-canary-entries-after-post-start",
        "issued_at": now,
        "expires_at": now + 600,
        "transition_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "target_deployment_identity_sha256": "c" * 64,
        "runtime_instance_id": runtime.runtime_instance_id,
        "boot_id": runtime.runtime_boot_id,
        "expected_startup_hard_epoch": (
            runtime._canary_startup_hard_epoch if hard_epoch is None else hard_epoch
        ),
        "startup_nonce": runtime._canary_startup_nonce,
        "latch_reason": runtime._canary_startup_latch_reason,
        "checks_verifier_key_fingerprint": (
            ed25519_public_key_fingerprint(
                verifier_private,
                private_key=True,
            )
        ),
        "source_key_fingerprints": runtime.canary_source_key_fingerprints,
        "checks": {},
        "operator": "operator",
        "risk_approver": "risk",
    }
    for name in REQUIRED_POST_START_CHECKS:
        source_private, source_public = source_keys[name]
        raw_value = _canary_post_raw(runtime, path.parent, name, now)
        if name == "runtime_safety_kernel_live_within_60s":
            collected_raw = json.dumps(
                raw_value,
                sort_keys=True,
            ).encode()
            evidence_raw = collected_raw
        else:
            collected_raw = json.dumps(
                raw_value["native"],
                sort_keys=True,
            ).encode()
            evidence_raw = json.dumps(
                {
                    "runtime_binding": raw_value["runtime_binding"],
                    "native_payload_base64": base64.b64encode(
                        collected_raw
                    ).decode(),
                    "native_sha256": hashlib.sha256(
                        collected_raw
                    ).hexdigest(),
                    "native_bytes": len(collected_raw),
                },
                sort_keys=True,
            ).encode()
        source_evidence = build_source_evidence(
            _POST_START_EVIDENCE_KINDS[name],
            evidence_raw,
        )
        facts = derive_post_start_facts(name, source_evidence)
        execution, collection_receipt = _canary_execution_and_receipt(
            runtime,
            name,
            collected_raw,
            now,
        )
        source_artifact = sign_ed25519_payload(
            {
                "version": 1,
                "action": "attest-canary-post-start-source",
                "check": name,
                "observed_at": now,
                "runtime_instance_id": runtime.runtime_instance_id,
                "boot_id": runtime.runtime_boot_id,
                "account_uid": runtime.expected_account_id,
                "deployment_unit": runtime.deployment_unit,
                "demo_soak_epoch_id": runtime.soak_epoch_id,
                "transition_sha256": runtime.canary_transition_sha256,
                "policy_sha256": runtime.canary_policy_sha256,
                "target_deployment_identity_sha256": runtime.canary_target_sha256,
                "startup_nonce": runtime._canary_startup_nonce,
                "expected_startup_hard_epoch": payload[
                    "expected_startup_hard_epoch"
                ],
                "producer_execution": execution,
                "collection_receipt": collection_receipt,
                "source_evidence": source_evidence,
                "facts": facts,
            },
            source_private,
        )
        source_raw = json.dumps(
            source_artifact,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        check_artifact = sign_ed25519_payload(
            {
                "version": 1,
                "action": "attest-canary-post-start-check",
                "check": name,
                "passed": True,
                "observed_at": now,
                "runtime_instance_id": runtime.runtime_instance_id,
                "boot_id": runtime.runtime_boot_id,
                "account_uid": runtime.expected_account_id,
                "deployment_unit": runtime.deployment_unit,
                "demo_soak_epoch_id": runtime.soak_epoch_id,
                "transition_sha256": runtime.canary_transition_sha256,
                "policy_sha256": runtime.canary_policy_sha256,
                "target_deployment_identity_sha256": runtime.canary_target_sha256,
                "source_evidence_sha256": hashlib.sha256(source_raw).hexdigest(),
                "source_key_fingerprint": runtime.canary_source_key_fingerprints[name],
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
        payload["checks"][name] = {
            "passed": True,
            "observed_at": now,
            "evidence_uri": f"s3://evidence/canary/{name}.json",
            "evidence_version_id": f"{name}-v1",
            "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "evidence_bytes": len(raw),
            "artifact_bytes_base64": base64.b64encode(raw).decode(),
        }
    operator = sign_ed25519_payload(payload, operator_private)
    risk = sign_ed25519_payload(payload, risk_private)
    path.write_text(
        json.dumps(
            {
                "payload": payload,
                "operator_signature": operator["signature"],
                "risk_signature": risk["signature"],
            }
        )
    )


@pytest.mark.unit
def test_canary_entries_stay_halted_until_runtime_bound_dual_activation(
    tmp_path,
):
    operator_private, operator_public = _ed25519_pair(
        tmp_path,
        "operator",
    )
    risk_private, risk_public = _ed25519_pair(tmp_path, "risk")
    verifier_private, verifier_public = _ed25519_pair(
        tmp_path,
        "check-verifier",
    )
    source_keys = {
        name: _ed25519_pair(tmp_path, f"source-{index}")
        for index, name in enumerate(REQUIRED_POST_START_CHECKS)
    }
    source_inventory = _canary_inventory(source_keys)
    activation_path = tmp_path / "post-start-activation.json"
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "canary.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        canary_activation_path=activation_path,
        canary_operator_public_key=operator_public,
        canary_risk_public_key=risk_public,
        canary_check_verifier_public_key=verifier_public,
        canary_source_key_fingerprints={
            name: ed25519_public_key_fingerprint(keys[1]) for name, keys in source_keys.items()
        },
        canary_source_producer_inventory=source_inventory,
        canary_target_key_fingerprint=_CANARY_TARGET_KEY,
        canary_transition_sha256="a" * 64,
        canary_policy_sha256="b" * 64,
        canary_target_sha256="c" * 64,
        expected_account_id="canary-account",
        deployment_unit="okx-quant.service",
        soak_epoch_id="epoch-fixture-1",
        runtime_boot_id="12345678-1234-1234-1234-123456789abc",
    )
    assert runtime._install_canary_activation_hold() is True
    assert runtime._canary_startup_hard_epoch is not None
    startup_epoch = runtime._canary_startup_hard_epoch
    runtime._enforce_canary_activation(now=time.time())
    assert journal.get_mode_state()[1] == startup_epoch
    assert journal.get_mode_reason() == runtime._canary_startup_latch_reason
    assert runtime._promote_ready_if_safe(True) is False
    assert runtime._try_activate_canary_entries() is False
    assert journal.get_mode() is SystemMode.HALTED

    now = int(time.time())
    _write_canary_activation(
        runtime,
        activation_path,
        operator_private,
        risk_private,
        verifier_private,
        source_keys,
        now=now,
    )

    assert runtime._try_activate_canary_entries() is True
    assert journal.get_mode() is SystemMode.READY
    assert runtime._canary_activation_valid(now=now + 3600) is True
    journal.set_mode(SystemMode.HALTED, reason="operator_halt")
    runtime._enforce_canary_activation(now=now + 3600)
    assert runtime._try_activate_canary_entries() is False
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_canary_activation_cannot_release_a_later_hard_incident(tmp_path):
    operator_private, operator_public = _ed25519_pair(
        tmp_path,
        "operator-later-halt",
    )
    risk_private, risk_public = _ed25519_pair(
        tmp_path,
        "risk-later-halt",
    )
    verifier_private, verifier_public = _ed25519_pair(
        tmp_path,
        "later-halt-check-verifier",
    )
    source_keys = {
        name: _ed25519_pair(tmp_path, f"later-source-{index}")
        for index, name in enumerate(REQUIRED_POST_START_CHECKS)
    }
    source_inventory = _canary_inventory(source_keys)
    activation_path = tmp_path / "later-halt-activation.json"
    journal = SQLiteJournal(tmp_path / "later-halt.db")
    runtime = ProductionRuntime(
        FakeExchange(),
        journal,
        canary_activation_path=activation_path,
        canary_operator_public_key=operator_public,
        canary_risk_public_key=risk_public,
        canary_check_verifier_public_key=verifier_public,
        canary_source_key_fingerprints={
            name: ed25519_public_key_fingerprint(keys[1]) for name, keys in source_keys.items()
        },
        canary_source_producer_inventory=source_inventory,
        canary_target_key_fingerprint=_CANARY_TARGET_KEY,
        canary_transition_sha256="a" * 64,
        canary_policy_sha256="b" * 64,
        canary_target_sha256="c" * 64,
        expected_account_id="canary-account",
        deployment_unit="okx-quant.service",
        soak_epoch_id="epoch-fixture-1",
        runtime_boot_id="12345678-1234-1234-1234-123456789abc",
    )
    assert runtime._install_canary_activation_hold() is True
    startup_epoch = runtime._canary_startup_hard_epoch
    _write_canary_activation(
        runtime,
        activation_path,
        operator_private,
        risk_private,
        verifier_private,
        source_keys,
        now=int(time.time()),
        hard_epoch=startup_epoch,
    )

    runtime._latch_halted("ws_error_budget_exhausted")

    assert journal.get_mode_state()[1] > startup_epoch
    assert journal.get_mode_reason() == "ws_error_budget_exhausted"
    assert runtime._try_activate_canary_entries() is False
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_liveness_fails_when_safety_loop_has_stalled(tmp_path):
    journal = SQLiteJournal(tmp_path / "safety-freshness.db")
    journal.set_mode(SystemMode.READY)
    runtime = ProductionRuntime(
        FakeExchange(),
        journal,
        reconciliation_interval_s=0.05,
        lock_path=tmp_path / "safety-freshness.lock",
    )
    runtime.start()
    try:
        runtime._last_safety_completed_monotonic = time.monotonic() - 6

        live, details = runtime._liveness()

        assert live is False
        assert details["safety_loop_fresh"] is False
        assert details["safety_loop_age_seconds"] >= 5
    finally:
        runtime.stop()
        journal.close()


@pytest.mark.unit
def test_active_demo_runtime_reclaims_probes_at_startup_and_periodically(
    tmp_path,
):
    exchange = FakeExchange()
    exchange.set_account_identity("demo-account")
    exchange.set_balance(total=5000, quote_avail=5000)
    exchange.set_ticker(
        "BTC-USDT",
        last=50000,
        bid=49990,
        ask=50010,
    )
    exchange.set_instrument(
        InstrumentInfo(
            inst_id="BTC-USDT",
            base_ccy="BTC",
            quote_ccy="USDT",
            lot_size=Decimal("0.00001"),
            min_size=Decimal("0.00001"),
            tick_size=Decimal("0.1"),
        )
    )
    journal = SQLiteJournal(tmp_path / "demo-runtime.db")
    journal.set_mode(SystemMode.READY)
    runtime = ProductionRuntime(
        exchange,
        journal,
        environment="demo",
        expected_account_id="demo-account",
        allowed_instruments=("BTC-USDT",),
        lock_path=tmp_path / "demo-runtime.lock",
        reconciliation_interval_s=0.05,
    )
    assert runtime.demo_probe is not None

    def crash_before_intent(probe_id):
        acquired = journal.acquire_probe_lease(
            probe_id,
            "crashed-worker",
            ttl_s=30,
        )
        assert acquired is not None
        token, row = acquired
        journal.transition_probe_run(
            probe_id,
            owner="crashed-worker",
            fencing_token=token,
            expected_states=(row["state"],),
            new_state="BUY_SUBMITTING",
        )
        journal.release_probe_lease(
            probe_id,
            owner="crashed-worker",
            fencing_token=token,
        )

    startup_probe = runtime.demo_probe.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="3" * 32,
    )
    crash_before_intent(startup_probe["probe_id"])

    runtime.start()
    try:
        startup_result = journal.get_probe_run(startup_probe["probe_id"])
        assert startup_result is not None
        assert startup_result["state"] == "REJECTED"

        periodic_probe = runtime.demo_probe.prepare(
            inst_id="BTC-USDT",
            nominal_usdt=Decimal("5"),
            slot=2,
            probe_id="4" * 32,
        )
        crash_before_intent(periodic_probe["probe_id"])
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            result = journal.get_probe_run(periodic_probe["probe_id"])
            if result is not None and result["state"] == "REJECTED":
                break
            time.sleep(0.01)
        assert result is not None
        assert result["state"] == "REJECTED"
        assert exchange.orders == []
    finally:
        runtime.stop()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("shadow_mode", "safety_only"),
    [(True, False), (False, True), (True, True)],
)
def test_demo_reclaimer_is_absent_from_shadow_and_safety_only(
    tmp_path,
    shadow_mode,
    safety_only,
):
    exchange = FakeExchange()
    exchange.set_account_identity("demo-account")
    journal = SQLiteJournal(tmp_path / f"disabled-{shadow_mode}-{safety_only}.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        environment="demo",
        expected_account_id="demo-account",
        allowed_instruments=("BTC-USDT",),
        shadow_mode=shadow_mode,
        safety_only=safety_only,
        lock_path=tmp_path / f"disabled-{shadow_mode}-{safety_only}.lock",
    )

    assert runtime.demo_probe is None
    assert runtime._reclaim_demo_probes_once("test") == []
    journal.close()


@pytest.mark.unit
def test_shadow_transport_denies_and_durably_audits_write_attempt(
    tmp_path,
):
    exchange = FakeExchange()
    exchange.set_account_identity("shadow-account")
    journal = SQLiteJournal(tmp_path / "shadow.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        environment="demo",
        expected_account_id="shadow-account",
        deployment_unit="okx-quant-demo-shadow.service",
        soak_epoch_id="shadow-epoch",
        allowed_instruments=("BTC-USDT",),
        shadow_mode=True,
        lock_path=tmp_path / "shadow.lock",
    )

    with pytest.raises(PermissionError, match="Shadow transport deny"):
        exchange.place_market_order(
            "BTC-USDT",
            "buy",
            Decimal("0.001"),
            cl_ord_id="must-not-reach-exchange",
        )
    assert exchange.orders == []
    attempts = journal.list_events(
        event_name="shadow_write_endpoint_attempt",
    )
    assert len(attempts) == 1
    payload = attempts[0]["payload"]
    assert payload["method"] == "POST"
    assert payload["endpoint"] == "place_market_order"
    assert payload["attempt_count"] == 1
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.shadow_write_endpoint_attempt"
        for row in journal.get_unpublished_outbox()
    )

    runtime._update_metrics()
    heartbeat = journal.list_events(
        event_name="runtime_heartbeat_sample",
    )[-1]
    heartbeat_payload = heartbeat["payload"]
    assert heartbeat_payload["shadow_mode"] is True
    assert heartbeat_payload["shadow_write_attempt_count"] == 1
    journal.close()


@pytest.mark.unit
def test_unresolved_demo_reclaim_closes_runtime_readiness(tmp_path):
    exchange = FakeExchange()
    exchange.set_account_identity("demo-account")
    journal = SQLiteJournal(tmp_path / "pending-probe.db")
    journal.set_mode(SystemMode.READY)
    runtime = ProductionRuntime(
        exchange,
        journal,
        environment="demo",
        expected_account_id="demo-account",
        allowed_instruments=("BTC-USDT",),
        lock_path=tmp_path / "pending-probe.lock",
    )

    runtime._set_demo_probe_reclaim_pending(
        [
            {"state": "BUY_UNKNOWN"},
        ]
    )

    assert journal.get_mode() is SystemMode.DEGRADED
    assert runtime._demo_probe_reclaim_pending
    assert not runtime._promote_ready_if_safe(True)

    runtime._set_demo_probe_reclaim_pending(
        [
            {"state": "REJECTED"},
        ]
    )
    assert runtime._promote_ready_if_safe(True)
    assert journal.get_mode() is SystemMode.READY
    journal.close()


@pytest.mark.unit
def test_external_protection_loss_freezes_waiting_buy_before_callback_returns(
    tmp_path,
    monkeypatch,
):
    exchange, journal, runtime = _runtime(tmp_path)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.1"),
        available_qty=Decimal("0.1"),
        reference_price=Decimal("50000"),
        reason="fixture",
    )
    active = runtime.protection.ensure_for_position(
        "BTC-USDT",
        Decimal("0.1"),
        reference_price=Decimal("50000"),
    )
    journal.set_mode(SystemMode.READY)

    # Isolate the operation-lock/mode invariant. Without the callback freeze,
    # this BUY is otherwise allowed to reach the exchange.
    runtime.execution.pre_trade_check = None
    runtime.execution.entry_guard = None
    runtime.execution.atomic_risk_guard = None

    manager_projected = threading.Event()
    allow_callback_to_continue = threading.Event()
    buy_lock_attempted = threading.Event()
    original_process = runtime.protection.process_algo_events
    original_lock = runtime.operation_lock

    class ObservableLock:
        def __enter__(self):
            if threading.current_thread().name == "waiting-buy":
                buy_lock_attempted.set()
            original_lock.acquire()
            return self

        def __exit__(self, *_args):
            original_lock.release()

    observable_lock = ObservableLock()
    runtime.operation_lock = observable_lock
    runtime.execution.operation_lock = observable_lock

    def project_then_pause(rows):
        losses = original_process(rows)
        manager_projected.set()
        assert allow_callback_to_continue.wait(timeout=2)
        return losses

    monkeypatch.setattr(
        runtime.protection,
        "process_algo_events",
        project_then_pause,
    )
    row = {
        "algoId": active.exchange_algo_id,
        "algoClOrdId": active.algo_cl_ord_id,
        "state": "canceled",
        "sz": str(active.protected_qty),
        "slTriggerPx": str(active.trigger_px),
        "tpTriggerPx": str(active.take_profit_px),
    }
    callback_errors = []
    callback_return_modes = []
    buy_errors = []

    def callback_worker():
        try:
            runtime._process_algo_events([row])
            callback_return_modes.append(journal.get_mode())
        except BaseException as exc:  # noqa: BLE001
            callback_errors.append(exc)

    def buy_worker():
        try:
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.01"),
                )
            )
        except BaseException as exc:  # noqa: BLE001
            buy_errors.append(exc)

    callback_thread = threading.Thread(target=callback_worker)
    buy_thread = threading.Thread(target=buy_worker, name="waiting-buy")
    callback_thread.start()
    try:
        assert manager_projected.wait(timeout=2)
        assert journal.get_mode() is SystemMode.READY
        buy_thread.start()
        assert buy_lock_attempted.wait(timeout=2)
        assert exchange.orders == []
    finally:
        allow_callback_to_continue.set()

    callback_thread.join(timeout=2)
    buy_thread.join(timeout=2)
    assert not callback_thread.is_alive()
    assert not buy_thread.is_alive()
    assert callback_errors == []
    assert callback_return_modes == [SystemMode.EMERGENCY_EXIT]
    assert len(buy_errors) == 1
    assert isinstance(buy_errors[0], RuntimeError)
    assert exchange.orders == []
    assert "BTC-USDT" in runtime._unprotected_since

    # A replayed terminal event may update its projection, but cannot Page or
    # record the loss fact a second time.
    monkeypatch.setattr(
        runtime.protection,
        "process_algo_events",
        original_process,
    )
    runtime._process_algo_events([row])
    assert (
        sum(
            item["event_name"] == "page.external_protection_lost"
            for item in journal.get_unpublished_outbox()
        )
        == 1
    )
    assert len(journal.list_events("external_protection_lost")) == 1
    journal.close()


@pytest.mark.unit
def test_expired_entry_authorization_latches_halted_and_pages(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    expires_at = time.time() + 60
    runtime = ProductionRuntime(
        exchange,
        journal,
        lock_path=tmp_path / "trading.lock",
        entry_authorization_expires_at=expires_at,
    )
    journal.set_mode(SystemMode.READY)

    runtime._enforce_entry_authorization(now=expires_at)
    runtime._enforce_entry_authorization(now=expires_at + 1)

    assert journal.get_mode() is SystemMode.HALTED
    events = journal.list_events()
    assert sum(row["event_name"] == "entry_authorization_expired" for row in events) == 1
    assert any(
        row["event_name"] == "page.entry_authorization_expired"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_canary_backup_rpo_continuously_latches_halted(tmp_path):
    now = time.time()
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        lock_path=tmp_path / "trading.lock",
        max_entry_backup_rpo_s=300,
    )
    journal.record_event(
        "backup_slo_sample",
        payload={
            "integrity": "ok",
            "snapshot_completed_at": now - 10,
            "offsite_readback_at": now - 5,
            "roundtrip_started_at": now - 8,
            "roundtrip_completed_at": now - 5,
            "version_id": "exact-version",
            "evidence_artifact_sha256": "a" * 64,
            "evidence_key_id": "backup-verifier-v1",
        },
    )
    journal.set_mode(SystemMode.READY)

    assert runtime._backup_entry_safe(now=now)
    runtime._enforce_backup_entry_rpo(now=now + 301)
    runtime._enforce_backup_entry_rpo(now=now + 302)

    assert journal.get_mode() is SystemMode.HALTED
    assert len(journal.list_events("entry_backup_rpo_breached")) == 1
    assert (
        sum(
            row["event_name"] == "page.entry_backup_rpo_breached"
            for row in journal.get_unpublished_outbox()
        )
        == 1
    )
    journal.close()


@pytest.mark.unit
def test_ws_disconnect_during_recovery_cannot_restore_ready(tmp_path, monkeypatch):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=50_000, bid=49_990, ask=50_010)
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.READY)

    def disconnect_during_reconcile(**_kwargs):
        ws._set_state("private", ConnectionState.BACKOFF)
        return ReconciliationResult(run_id="fixture")

    monkeypatch.setattr(runtime.reconciler, "run", disconnect_during_reconcile)
    runtime._restore_after_reconnect()

    assert journal.get_mode() is SystemMode.DEGRADED
    assert not runtime.streams.ready
    allowed, reason = runtime.risk_service.check(
        ExecutionRequest(
            inst_id="BTC-USDT",
            side="buy",
            base_qty=Decimal("0.01"),
            reserved_quote=Decimal("500"),
            stop_loss=Decimal("49000"),
        )
    )
    assert not allowed
    assert "READY" in reason
    journal.close()


@pytest.mark.unit
def test_runtime_persists_periodic_websocket_liveness_fact(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    websocket = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=websocket,
        lock_path=tmp_path / "trading.lock",
    )
    with runtime._ws_state_lock:
        runtime._ws_states = {
            channel: ConnectionState.READY for channel in ("public", "private", "business")
        }
        runtime._ws_connection_generations = {
            channel: 3 for channel in ("public", "private", "business")
        }

    runtime._record_ws_liveness_sample(baseline_safe=True)

    sample = journal.list_events("websocket_liveness_sample")[-1]["payload"]
    assert sample["states"] == {
        "public": "ready",
        "private": "ready",
        "business": "ready",
    }
    assert sample["generations"] == {
        "public": 3,
        "private": 3,
        "business": 3,
    }
    assert sample["baseline_safe"] is True
    journal.close()


@pytest.mark.unit
def test_reconnect_repeats_baseline_when_ws_generation_changes(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
        ws_ready_timeout_s=1,
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    calls = 0

    def generation_changes_once(**_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            runtime._ws_generation += 2
        return ReconciliationResult(run_id=f"fixture-{calls}")

    monkeypatch.setattr(runtime.reconciler, "run", generation_changes_once)
    runtime._restore_after_reconnect()
    assert calls == 2
    assert runtime.streams.ready
    journal.close()


@pytest.mark.unit
def test_reconnect_repeats_baseline_when_private_event_arrives(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
        ws_ready_timeout_s=1,
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    calls = 0

    def event_arrives_once(**_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            runtime.streams._on_balance([{"ccy": "BTC"}])
        return ReconciliationResult(run_id=f"event-{calls}")

    monkeypatch.setattr(runtime.reconciler, "run", event_arrives_once)
    runtime._restore_after_reconnect()
    assert calls == 2
    assert runtime.streams.ready
    journal.close()


@pytest.mark.unit
def test_periodic_reconcile_repeats_if_balance_event_changes_snapshot(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=100, bid=99, ask=101)
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.READY)
    original_pending = exchange.get_pending_orders
    triggered = False

    def balance_changes_after_old_snapshot():
        nonlocal triggered
        if not triggered:
            triggered = True
            exchange.set_holding("BTC", balance=1, available=1)
            runtime.streams._on_balance([{"ccy": "BTC"}])
        return original_pending()

    monkeypatch.setattr(exchange, "get_pending_orders", balance_changes_after_old_snapshot)
    runtime._periodic_reconcile_once()
    assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("1")
    assert runtime.streams.ready
    assert journal.get_mode() is SystemMode.READY
    healthy, _ = runtime._health()
    assert healthy
    journal.close()


@pytest.mark.unit
def test_reconcile_now_uses_same_event_sequence_fence(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_ticker("BTC-USDT", last=100, bid=99, ask=101)
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.READY)
    original_pending = exchange.get_pending_orders
    triggered = False

    def balance_changes_after_old_snapshot():
        nonlocal triggered
        if not triggered:
            triggered = True
            exchange.set_holding("BTC", balance=1, available=1)
            runtime.streams._on_balance([{"ccy": "BTC"}])
        return original_pending()

    monkeypatch.setattr(exchange, "get_pending_orders", balance_changes_after_old_snapshot)
    runtime._stop_event.clear()
    control = threading.Thread(target=runtime._control_loop)
    control.start()
    try:
        command = enqueue_and_wait(
            journal,
            "reconcile-now",
            {},
            timeout_s=2,
        )
        assert command["status"] == "completed"
        assert command["result"]["safe"]
        assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == Decimal("1")
        assert journal.get_mode() is SystemMode.READY
    finally:
        runtime._stop_event.set()
        control.join(timeout=2)
        journal.close()


@pytest.mark.unit
def test_resume_event_at_hard_release_cannot_leave_ready(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.HALTED)
    original_set_mode = journal.set_mode
    original_health = runtime._health
    event_started = threading.Event()
    event_thread = None

    def emit_balance():
        event_started.set()
        runtime.streams._on_balance([{"ccy": "BTC"}])

    def set_mode_with_event(
        mode,
        *,
        allow_hard_release=False,
        expected_hard_epoch=None,
        reason="",
    ):
        nonlocal event_thread
        if allow_hard_release:
            event_thread = threading.Thread(target=emit_balance)
            event_thread.start()
            assert event_started.wait(1)
        return original_set_mode(
            mode,
            allow_hard_release=allow_hard_release,
            expected_hard_epoch=expected_hard_epoch,
            reason=reason,
        )

    def health_after_event():
        if event_thread is not None:
            event_thread.join(timeout=1)
        return original_health()

    monkeypatch.setattr(journal, "set_mode", set_mode_with_event)
    monkeypatch.setattr(runtime, "_health", health_after_event)
    with pytest.raises(RuntimeError, match="readiness"):
        runtime._resume_entries(
            "a" * 32,
            {"actor": "operator", "risk_approver": "risk"},
        )
    assert journal.get_mode() is SystemMode.HALTED
    assert event_thread is not None and not event_thread.is_alive()
    journal.close()


@pytest.mark.unit
def test_concurrent_halt_epoch_prevents_stale_resume_release(
    tmp_path,
    monkeypatch,
):
    exchange, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.HALTED)

    def halt_during_reconcile(**_kwargs):
        # 重复 HALTED 也推进 epoch，代表一个比当前 resume 更新的人工意图。
        journal.set_mode(SystemMode.HALTED)
        return ReconciliationResult(run_id="halt-race")

    monkeypatch.setattr(runtime.reconciler, "run", halt_during_reconcile)
    with pytest.raises(RuntimeError, match="readiness"):
        runtime._resume_entries(
            "b" * 32,
            {"actor": "operator", "risk_approver": "risk"},
        )
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_startup_subscribes_then_builds_second_rest_baseline(
    tmp_path,
    monkeypatch,
):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
        ws_ready_timeout_s=1,
    )
    calls = 0
    original_run = runtime.reconciler.run

    def count_reconcile(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_run(*args, **kwargs)

    def mark_transport_ready():
        ws._states["private"] = ConnectionState.READY
        ws._states["business"] = ConnectionState.READY

    monkeypatch.setattr(runtime.reconciler, "run", count_reconcile)
    monkeypatch.setattr(runtime.streams, "start", mark_transport_ready)
    runtime.start()
    try:
        assert calls >= 2
        assert runtime.streams.ready
        assert runtime.ready
    finally:
        runtime.stop()


@pytest.mark.unit
def test_alert_delivery_failure_makes_runtime_unhealthy(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    runtime.alerts.webhook_url = "https://alerts.example"
    runtime.alerts.consecutive_failures = 3
    healthy, detail = runtime._health()
    assert not healthy
    assert detail["alert_delivery_healthy"] is False
    journal.close()


@pytest.mark.unit
def test_alert_delivery_failure_rejects_new_buy(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        runtime.alerts.webhook_url = "https://alerts.example"
        runtime.alerts.consecutive_failures = 3
        with pytest.raises(RuntimeError, match="门禁未 READY"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.01"),
                    stop_loss=Decimal("49000"),
                )
            )
    finally:
        runtime.stop()


@pytest.mark.unit
def test_halted_mode_survives_runtime_restart_and_remains_live(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.HALTED)
    runtime.start()
    try:
        assert journal.get_mode() is SystemMode.HALTED
        live, detail = runtime._liveness()
        assert live
        assert detail["mode"] == "halted"
        assert detail["runtime_instance_id"] == runtime.runtime_instance_id
        assert detail["boot_id"] == runtime.runtime_boot_id
        assert detail["reconciliation_fresh"]
        ready, _ = runtime._health()
        assert not ready
    finally:
        runtime.stop()


@pytest.mark.unit
def test_runtime_is_sole_writer_importing_signed_backup_receipt(tmp_path):
    private_key, public_key = _ed25519_pair(tmp_path, "backup")
    now = time.time()
    receipt_path = tmp_path / "last-offsite-roundtrip.json"
    receipt_path.write_text(
        json.dumps(
            sign_ed25519_payload(
                _backup_restore_evidence(now),
                private_key,
            )
        )
    )
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        expected_account_id="demo-account",
        backup_receipt_path=receipt_path,
        backup_receipt_public_key=public_key,
        backup_receipt_key_id="backup-signing-v1",
        max_entry_backup_rpo_s=300,
    )

    assert runtime._ingest_backup_receipt(now=now) is True
    assert runtime._ingest_backup_receipt(now=now) is False
    samples = journal.list_events("backup_slo_sample")
    assert len(samples) == 1
    assert len(samples[0]["payload"]["evidence_artifact_sha256"]) == 64
    assert runtime._backup_entry_safe(now=now) is True
    journal.close()


@pytest.mark.unit
def test_hard_mode_cannot_be_relaxed_by_ws_or_safe_reconcile(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.HALTED)
    runtime._on_ws_state("private", ConnectionState.BACKOFF)
    runtime._promote_ready_if_safe(True)
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_public_market_disconnect_closes_readiness_and_degrades(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    runtime.register_public_market_data(["BTC-USDT"], "1H")
    ws._states["private"] = ConnectionState.READY
    ws._states["business"] = ConnectionState.READY
    ws._states["public"] = ConnectionState.READY
    ws._last_message_at["public"] = time.time()
    runtime._on_public_market_event("ticker", "BTC-USDT", [{"last": "1"}])
    runtime._on_public_market_event("candle", "BTC-USDT", [["1"]])
    runtime.streams.mark_baseline_complete()
    journal.set_mode(SystemMode.READY)
    assert runtime.ready

    runtime._on_ws_state("public", ConnectionState.BACKOFF)
    assert journal.get_mode() is SystemMode.DEGRADED
    assert not runtime.ready
    journal.close()


@pytest.mark.unit
def test_public_market_readiness_requires_every_registered_channel(tmp_path):
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ws = OKXWebSocketClient()
    runtime = ProductionRuntime(
        exchange,
        journal,
        websocket=ws,
        lock_path=tmp_path / "trading.lock",
    )
    runtime.register_public_market_data(["BTC-USDT", "ETH-USDT"], "1H")
    ws._states["public"] = ConnectionState.READY
    for inst_id in ("BTC-USDT", "ETH-USDT"):
        runtime._on_public_market_event("ticker", inst_id, [{"last": "1"}])
    runtime._on_public_market_event("candle", "BTC-USDT", [["1"]])
    assert not runtime._public_market_ready()
    runtime._on_public_market_event("candle", "ETH-USDT", [["1"]])
    assert runtime._public_market_ready()
    journal.close()


@pytest.mark.unit
def test_runtime_refuses_mismatched_exchange_account(tmp_path):
    exchange = FakeExchange()
    exchange.set_account_identity("actual-uid")
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        expected_account_id="configured-uid",
        lock_path=tmp_path / "trading.lock",
    )
    with pytest.raises(RuntimeError, match="账户 UID"):
        runtime.start()
    assert journal.get_mode() is SystemMode.HALTED
    assert not runtime._started
    journal.close()


@pytest.mark.unit
def test_runtime_recovery_gate_allows_durable_protected_buy(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        assert runtime.ready
        intent = runtime.execution.submit(
            ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                reserved_quote=Decimal("500"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            )
        )
        assert intent.state is OrderState.FILLED
        assert journal.has_active_protection("BTC-USDT", Decimal("0.01"))
        assert exchange.orders[0].cl_ord_id
    finally:
        runtime.stop()


@pytest.mark.unit
def test_same_completed_candle_is_durable_and_idempotent(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    candle_ts = time.time() - 3600
    valid, _ = runtime.validate_candle("ma:1", "BTC-USDT", "1H", candle_ts)
    assert valid
    decision_id = runtime.persist_decision(
        strategy_instance_id="ma:1",
        strategy_name="ma",
        strategy_version="a" * 64,
        inst_id="BTC-USDT",
        candle_ts=str(candle_ts),
        signal="buy",
        requested_size_pct=Decimal("0.1"),
        reason="fixture",
    )
    assert decision_id
    stored = journal._conn.execute(
        "SELECT strategy_version FROM decisions WHERE decision_id=?",
        (decision_id,),
    ).fetchone()
    assert stored["strategy_version"] == "a" * 64
    runtime.mark_candle_processed("ma:1", "BTC-USDT", "1H", candle_ts)
    valid, reason = runtime.validate_candle("ma:1", "BTC-USDT", "1H", candle_ts)
    assert not valid and reason == "K 线已处理"
    assert (
        runtime.persist_decision(
            strategy_instance_id="ma:1",
            strategy_name="ma",
            strategy_version="a" * 64,
            inst_id="BTC-USDT",
            candle_ts=str(candle_ts),
            signal="buy",
            requested_size_pct=Decimal("0.1"),
            reason="duplicate",
        )
        is None
    )
    journal.close()


@pytest.mark.unit
def test_strategy_timeout_is_routed_to_durable_warning(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    runtime.record_strategy_warning(
        strategy_name="llm_shadow",
        strategy_version="a" * 64,
        inst_id="BTC-USDT",
        warning_kind="timeout",
        detail="fixture timeout",
    )
    rows = journal.get_unpublished_outbox()
    assert rows[-1]["event_name"] == "warning.strategy_signal_timeout"
    assert json.loads(rows[-1]["payload_json"])["strategy_version"] == "a" * 64
    journal.close()


@pytest.mark.unit
def test_candle_watermark_rejects_short_cross_window_interval(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    previous = time.time() - 7200
    runtime.mark_candle_processed(
        "ma:cadence",
        "BTC-USDT",
        "1H",
        previous,
    )
    valid, reason = runtime.validate_candle(
        "ma:cadence",
        "BTC-USDT",
        "1H",
        previous + 600,
    )
    assert not valid
    assert reason == "K 线时间不连续"
    assert journal.get_mode() is SystemMode.DEGRADED
    journal.close()


@pytest.mark.unit
def test_signal_market_window_rejects_gap_and_excess_volatility(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    candle_ts = time.time() - 3600
    valid_window = pd.DataFrame(
        {
            "ts": [candle_ts - 3600, candle_ts],
            "open": [50_000, 50_100],
            "high": [50_100, 50_200],
            "low": [49_900, 50_000],
            "close": [50_000, 50_100],
        }
    )
    valid, reason = runtime.validate_candle(
        "ma:window",
        "BTC-USDT",
        "1H",
        candle_ts,
        market_data=valid_window,
    )
    assert valid, reason

    gapped = valid_window.copy()
    gapped.loc[0, "ts"] = candle_ts - 7200
    valid, reason = runtime.validate_candle(
        "ma:gap",
        "BTC-USDT",
        "1H",
        candle_ts,
        market_data=gapped,
    )
    assert not valid and "不连续" in reason
    assert journal.get_mode() is SystemMode.DEGRADED

    wrong_cadence = valid_window.copy()
    wrong_cadence.loc[0, "ts"] = candle_ts - 600
    valid, reason = runtime.validate_candle(
        "ma:cadence",
        "BTC-USDT",
        "1H",
        candle_ts,
        market_data=wrong_cadence,
    )
    assert not valid and "不连续" in reason

    volatile = valid_window.copy()
    volatile.loc[1, ["high", "low"]] = [60_000, 40_000]
    valid, reason = runtime.validate_candle(
        "ma:volatile",
        "BTC-USDT",
        "1H",
        candle_ts,
        market_data=volatile,
    )
    assert not valid and "波动率" in reason
    journal.close()


@pytest.mark.unit
def test_risk_limits_reject_values_above_compiled_hard_caps():
    with pytest.raises(ValueError, match="编译期硬上限"):
        ProductionRiskLimits(max_order_loss_usdt=Decimal("101")).validate()
    with pytest.raises(ValueError, match="20%"):
        ProductionRiskLimits(max_candle_range_ratio=Decimal("0.21")).validate()


@pytest.mark.unit
def test_portfolio_risk_rejects_wide_spread_before_intent(tmp_path):
    limits = ProductionRiskLimits(max_spread_ratio=Decimal("0.001"))
    exchange, journal, runtime = _runtime(tmp_path, limits=limits)
    exchange.set_ticker("BTC-USDT", last=50_000, bid=49_000, ask=51_000)
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match="spread"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.01"),
                    reserved_quote=Decimal("500"),
                    stop_loss=Decimal("49000"),
                )
            )
        assert journal.recent_intent_count(0) == 0
        # 市场质量属于 REJECT_CANDIDATE，不要求人工 resume。
        assert journal.get_mode() is SystemMode.READY
    finally:
        runtime.stop()


@pytest.mark.unit
def test_existing_account_exposure_breach_halts_and_pages(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_holding("BTC", balance=2, available=2)
    exchange.set_ticker("BTC-USDT", last=100, bid=99, ask=101)
    exchange.set_ticker("ETH-USDT", last=100, bid=99, ask=101)
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("2"),
        reference_price=Decimal("100"),
        reason="fixture",
    )
    journal.set_mode(SystemMode.READY)
    service = ProductionRiskService(
        exchange,
        journal,
        ProductionRiskLimits(
            max_position_notional_usdt=Decimal("150"),
            max_total_exposure_usdt=Decimal("500"),
        ),
    )
    allowed, reason = service.check(
        ExecutionRequest(
            inst_id="ETH-USDT",
            side="buy",
            base_qty=Decimal("0.1"),
            reserved_quote=Decimal("11"),
            stop_loss=Decimal("90"),
            take_profit=Decimal("120"),
        )
    )
    assert not allowed
    assert "已经超过" in reason
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.current_position_notional_limit"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("bid", "ask"),
    [(0, 0), (50_100, 50_000)],
)
def test_pretrade_rejects_missing_or_crossed_bbo_before_intent(
    tmp_path,
    bid,
    ask,
):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=bid,
        ask=ask,
    )
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match="bid/ask"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.01"),
                    stop_loss=Decimal("49000"),
                    take_profit=Decimal("52000"),
                )
            )
        assert exchange.orders == []
    finally:
        runtime.stop()


@pytest.mark.unit
def test_pretrade_enforces_production_instrument_allowlist(tmp_path):
    limits = ProductionRiskLimits(allowed_instruments=frozenset({"BTC-USDT"}))
    exchange, journal, runtime = _runtime(tmp_path, limits=limits)
    exchange.set_ticker(
        "UNAPPROVED-USDT",
        last=1,
        bid=Decimal("0.99"),
        ask=Decimal("1.01"),
    )
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match="allowlist"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="UNAPPROVED-USDT",
                    side="buy",
                    base_qty=Decimal("1"),
                    stop_loss=Decimal("0.9"),
                    take_profit=Decimal("1.1"),
                )
            )
        assert exchange.orders == []
    finally:
        runtime.stop()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("ticker_kwargs", "message"),
    [
        (
            {
                "timestamp": 1,
                "quote_volume_24h": 1_000_000,
            },
            "行情快照",
        ),
        (
            {
                "timestamp": None,
                "quote_volume_24h": 1,
            },
            "流动性",
        ),
    ],
)
def test_pretrade_rejects_stale_or_illiquid_market(
    tmp_path,
    ticker_kwargs,
    message,
):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
        **ticker_kwargs,
    )
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match=message):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.01"),
                    stop_loss=Decimal("49000"),
                    take_profit=Decimal("52000"),
                )
            )
        assert journal.recent_intent_count(0) == 0
    finally:
        runtime.stop()


@pytest.mark.unit
def test_pretrade_rejects_take_profit_below_worst_fill(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        with pytest.raises(RuntimeError, match="有效止盈"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.01"),
                    stop_loss=Decimal("49000"),
                    take_profit=Decimal("50100"),
                )
            )
        assert journal.recent_intent_count(0) == 0
    finally:
        runtime.stop()


@pytest.mark.unit
def test_consecutive_api_and_ws_errors_latch_halted(tmp_path):
    _, journal, runtime = _runtime(
        tmp_path,
    )
    journal.set_mode(SystemMode.READY)
    runtime._observe_api_request("/fixture", "OKX:0", 0.1)
    for _ in range(runtime.max_consecutive_infrastructure_errors):
        runtime._observe_api_request("/fixture", "OKX:50011", 0.1)
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.api_error_budget_exhausted"
        for row in journal.get_unpublished_outbox()
    )
    assert any(
        row["event_name"] == "warning.api_error_rate_elevated"
        for row in journal.get_unpublished_outbox()
    )

    _, hard_epoch = journal.get_mode_state()
    journal.set_mode(
        SystemMode.READY,
        allow_hard_release=True,
        expected_hard_epoch=hard_epoch,
    )
    for _ in range(runtime.max_consecutive_infrastructure_errors):
        runtime._on_ws_state("private", ConnectionState.BACKOFF)
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.ws_error_budget_exhausted"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_api_success_only_clears_its_exact_endpoint(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)

    for _ in range(runtime.max_consecutive_infrastructure_errors):
        runtime._observe_api_request(
            "/api/v5/account/balance",
            "OKX:50011",
            0.1,
        )
        runtime._observe_api_request(
            "/api/v5/account/positions",
            "OKX:0",
            0.1,
        )

    assert journal.get_mode() is SystemMode.HALTED
    page = next(
        row
        for row in journal.get_unpublished_outbox()
        if row["event_name"] == "page.api_error_budget_exhausted"
    )
    assert json.loads(page["payload_json"])["category"] == "private_account"
    journal.close()


@pytest.mark.unit
def test_fill_slippage_is_durable_metric_and_warning(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.queue_order_outcome(
        state="filled",
        fill_size=Decimal("0.01"),
        fill_price=Decimal("51000"),
    )
    runtime.start()
    try:
        intent = runtime.execution.submit(
            ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("53000"),
            )
        )
        assert intent.submission_reference_price == Decimal("50010")
        assert journal.list_events("execution_slippage_sample")
        assert any(
            row["event_name"] == "warning.execution_slippage_exceeded"
            for row in journal.get_unpublished_outbox()
        )
        rendered = runtime.metrics.render()
        assert "execution_slippage_ratio" in rendered
        assert "protection_activation_latency_seconds_bucket" in rendered
    finally:
        runtime.stop()


@pytest.mark.unit
def test_slippage_near_limit_warns_before_hard_limit(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.queue_order_outcome(
        state="filled",
        fill_size=Decimal("0.01"),
        fill_price=Decimal("50450"),
    )
    runtime.start()
    try:
        runtime.execution.submit(
            ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("53000"),
            )
        )
        names = {row["event_name"] for row in journal.get_unpublished_outbox()}
        assert "warning.execution_slippage_near_limit" in names
        assert "warning.execution_slippage_exceeded" not in names
    finally:
        runtime.stop()


@pytest.mark.unit
def test_snapshot_and_market_data_warn_before_stale_limit(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    snapshot_id = journal.record_account_snapshot(
        total_equity_quote=Decimal("100"),
        available_quote=Decimal("100"),
        holdings=[],
        source="fixture",
    )
    sampled_at = time.time()
    with journal.transaction() as conn:
        conn.execute(
            "UPDATE account_snapshots SET captured_at=? WHERE snapshot_id=?",
            (
                sampled_at - runtime.limits.max_account_snapshot_age_s * 0.85,
                snapshot_id,
            ),
        )
    runtime._required_public_market_channels.add(("ticker", "BTC-USDT"))
    runtime._public_market_last_event_at[("ticker", "BTC-USDT")] = (
        sampled_at - runtime.max_market_data_age_s * 0.85
    )

    runtime._update_metrics()

    names = {row["event_name"] for row in journal.get_unpublished_outbox()}
    assert "warning.account_snapshot_near_stale" in names
    assert "warning.market_data_near_stale" in names
    rendered = runtime.metrics.render()
    assert "account_snapshot_max_age_seconds" in rendered
    assert "market_data_max_age_seconds" in rendered
    journal.close()


@pytest.mark.unit
def test_consecutive_database_errors_latch_halted(tmp_path, monkeypatch):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    monkeypatch.setattr(journal, "health_check", lambda: False)

    for _ in range(runtime.max_consecutive_infrastructure_errors):
        healthy, detail = runtime._liveness()
        assert not healthy
        assert detail["database_healthy"] is False

    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.database_error_budget_exhausted"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_consecutive_database_write_errors_latch_halted(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    for _ in range(runtime.max_consecutive_infrastructure_errors):
        runtime._observe_database_write(
            False,
            OSError("disk I/O error"),
        )
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.database_write_error_budget_exhausted"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unprotected_deadline_enters_emergency_and_attempts_exit(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.01"),
        reference_price=Decimal("50000"),
        reason="fixture",
    )
    calls = []
    monkeypatch.setattr(
        runtime.exit,
        "exit_position",
        lambda inst_id, reason: (
            calls.append((inst_id, reason)) or SimpleNamespace(state=OrderState.FILLED)
        ),
    )

    runtime._enforce_unprotected_deadline(now=100)
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert any(
        row["event_name"] == "page.unprotected_position_detected"
        for row in journal.get_unpublished_outbox()
    )
    runtime._enforce_unprotected_deadline(now=100 + runtime.max_unprotected_position_s)

    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    deadline = time.monotonic() + 1
    while not calls and time.monotonic() < deadline:
        time.sleep(0.01)
    assert calls == [("BTC-USDT", "unprotected position deadline")]
    assert any(
        row["event_name"] == "page.unprotected_position_deadline"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unprotected_deadline_retries_rejected_exit(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.01"),
        reference_price=Decimal("50000"),
        reason="fixture",
    )
    states = iter([OrderState.REJECTED, OrderState.FILLED])
    calls = []

    def exit_attempt(inst_id, reason):
        calls.append((inst_id, reason))
        return SimpleNamespace(state=next(states))

    monkeypatch.setattr(runtime.exit, "exit_position", exit_attempt)
    runtime._enforce_unprotected_deadline(now=100)
    deadline = 100 + runtime.max_unprotected_position_s
    runtime._enforce_unprotected_deadline(now=deadline)
    wait_deadline = time.monotonic() + 1
    while "BTC-USDT" in runtime._unprotected_deadline_reported and time.monotonic() < wait_deadline:
        time.sleep(0.01)
    assert "BTC-USDT" not in runtime._unprotected_deadline_reported
    runtime._enforce_unprotected_deadline(now=deadline + 1)
    wait_deadline = time.monotonic() + 1
    while len(calls) < 2 and time.monotonic() < wait_deadline:
        time.sleep(0.01)
    assert len(calls) == 2
    assert any(
        row["event_name"] == "page.emergency_exit_failed"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unprotected_watchdog_ignores_nontradable_dust(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    runtime._on_public_market_event(
        "ticker",
        "BTC-USDT",
        [
            {
                "last": "50000",
                "bidPx": "49990",
                "askPx": "50010",
                "ts": str(int(time.time() * 1000)),
            }
        ],
    )
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.000001"),
        reference_price=Decimal("50000"),
        reason="dust fixture",
    )
    journal.set_mode(SystemMode.READY)
    runtime._enforce_unprotected_deadline(now=100)
    assert journal.get_mode() is SystemMode.READY
    assert "BTC-USDT" not in runtime._unprotected_since
    assert not any(
        row["event_name"] == "page.unprotected_position_detected"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unprotected_watchdog_does_not_use_stale_low_mark_as_dust(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    runtime._on_public_market_event(
        "ticker",
        "BTC-USDT",
        [
            {
                "last": "100",
                "bidPx": "99",
                "askPx": "101",
                "ts": "1000",
            }
        ],
    )
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.001"),
        reference_price=Decimal("50000"),
        reason="material fixture",
    )
    journal.set_mode(SystemMode.READY)
    runtime._enforce_unprotected_deadline(now=100)
    assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
    assert "BTC-USDT" in runtime._unprotected_since
    journal.close()


@pytest.mark.unit
def test_unprotected_dust_mark_is_ws_only(tmp_path, monkeypatch):
    exchange, journal, runtime = _runtime(tmp_path)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.000001"),
        reference_price=Decimal("50000"),
        reason="dust fixture",
    )
    monkeypatch.setattr(
        exchange,
        "get_ticker",
        lambda _inst_id: (_ for _ in ()).throw(AssertionError("safety loop 禁止 REST ticker")),
    )
    monkeypatch.setattr(
        runtime.reconciler,
        "position_safely_protected",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("safety loop 禁止调用可能读取 REST 的 protection helper")
        ),
    )
    runtime._on_public_market_event(
        "ticker",
        "BTC-USDT",
        [
            {
                "last": "50000",
                "bidPx": "49990",
                "askPx": "50010",
                "ts": str(int(time.time() * 1000)),
            }
        ],
    )

    assert runtime._fresh_valid_mark_for_dust("BTC-USDT") == Decimal("50000")
    assert runtime._fresh_valid_mark_for_dust("ETH-USDT") is None
    runtime._enforce_unprotected_deadline(now=100)
    assert "BTC-USDT" not in runtime._unprotected_since
    journal.close()


@pytest.mark.unit
def test_blocked_emergency_exit_does_not_block_safety_deadline_loop(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.01"),
        reference_price=Decimal("50000"),
        reason="fixture",
    )
    exit_started = threading.Event()
    release_exit = threading.Event()
    calls = []

    def blocked_exit(inst_id, reason):
        calls.append((inst_id, reason))
        exit_started.set()
        assert release_exit.wait(2)
        return SimpleNamespace(state=OrderState.FILLED)

    monkeypatch.setattr(runtime.exit, "exit_position", blocked_exit)
    runtime._enforce_unprotected_deadline(now=100)
    started = time.monotonic()
    runtime._enforce_unprotected_deadline(
        now=100 + runtime.max_unprotected_position_s,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 0.2
    assert exit_started.wait(1)
    runtime._enforce_unprotected_deadline(
        now=101 + runtime.max_unprotected_position_s,
    )
    assert calls == [("BTC-USDT", "unprotected position deadline")]

    release_exit.set()
    worker = runtime._emergency_exit_tasks.get("BTC-USDT")
    if worker is not None:
        worker.join(timeout=1)
    journal.close()


@pytest.mark.unit
def test_pretrade_refreshes_cash_and_enforces_lot_size(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_instrument(
        InstrumentInfo(
            inst_id="BTC-USDT",
            base_ccy="BTC",
            quote_ccy="USDT",
            lot_size=0.001,
            min_size=0.001,
        )
    )
    runtime.start()
    try:
        exchange.set_balance(total=10_000, quote_avail=1)
        with pytest.raises(RuntimeError, match="可用现金"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.001"),
                    reserved_quote=Decimal("50"),
                    stop_loss=Decimal("49000"),
                )
            )
        exchange.set_balance(total=10_000, quote_avail=10_000)
        with pytest.raises(RuntimeError, match="lot size"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.0015"),
                    reserved_quote=Decimal("75"),
                    stop_loss=Decimal("49000"),
                )
            )
        snapshot = journal.latest_account_snapshot()
        assert snapshot is not None and snapshot["source"] == "pre_trade"
    finally:
        runtime.stop()


@pytest.mark.unit
def test_pretrade_rejects_invalid_or_stale_account_snapshot(
    tmp_path,
    monkeypatch,
):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        exchange.set_balance(total=100, quote_avail=101)
        with pytest.raises(RuntimeError, match="账户快照"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.001"),
                    reserved_quote=Decimal("51"),
                    stop_loss=Decimal("49000"),
                    take_profit=Decimal("52000"),
                )
            )

        exchange.set_balance(total=10_000, quote_avail=10_000)
        original = journal.latest_account_snapshot

        def stale_snapshot():
            snapshot = original()
            snapshot["captured_at"] = time.time() - 1000
            return snapshot

        monkeypatch.setattr(journal, "latest_account_snapshot", stale_snapshot)
        with pytest.raises(RuntimeError, match="账户快照过期"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.001"),
                    reserved_quote=Decimal("51"),
                    stop_loss=Decimal("49000"),
                    take_profit=Decimal("52000"),
                )
            )
    finally:
        runtime.stop()


@pytest.mark.unit
def test_daily_realized_loss_cannot_be_hidden_by_flat_equity(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        monkeypatch.setattr(
            journal,
            "realized_pnl_since",
            lambda _since: Decimal("-300"),
        )
        with pytest.raises(RuntimeError, match="已实现亏损"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.01"),
                    stop_loss=Decimal("49000"),
                    take_profit=Decimal("52000"),
                )
            )
        assert journal.get_mode() is SystemMode.HALTED
        pages = [
            row
            for row in journal.get_unpublished_outbox()
            if row["event_name"] == "page.daily_realized_loss_limit"
        ]
        assert len(pages) == 1
        runtime.risk_service.enforce_account_hard_limits()
        assert (
            len(
                [
                    row
                    for row in journal.get_unpublished_outbox()
                    if row["event_name"] == "page.daily_realized_loss_limit"
                ]
            )
            == 1
        )
    finally:
        runtime.stop()


@pytest.mark.unit
def test_account_drawdown_halts_and_pages_without_waiting_for_buy(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    monkeypatch.setattr(
        journal,
        "realized_pnl_since",
        lambda _since: Decimal("0"),
    )
    monkeypatch.setattr(
        journal,
        "account_equities_since",
        lambda _since: [Decimal("10000"), Decimal("8000")],
    )
    within_limits, reason = runtime.risk_service.enforce_account_hard_limits()
    assert not within_limits
    assert "回撤" in reason
    assert journal.get_mode() is SystemMode.HALTED
    assert any(
        row["event_name"] == "page.account_drawdown_limit"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


@pytest.mark.unit
def test_unresolved_reconciliation_pages_once_per_incident(
    tmp_path,
    monkeypatch,
):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.READY)
    monkeypatch.setattr(
        runtime.reconciler,
        "run",
        lambda **_kwargs: ReconciliationResult(
            run_id="mismatch-run",
            mismatch_count=1,
            unresolved=["balance_mismatch:BTC-USDT"],
        ),
    )
    runtime._periodic_reconcile_once()
    runtime._periodic_reconcile_once()
    pages = [
        row
        for row in journal.get_unpublished_outbox()
        if row["event_name"] == "page.reconciliation_mismatch"
    ]
    assert len(pages) == 1
    assert journal.get_mode() is SystemMode.DEGRADED
    journal.close()


@pytest.mark.unit
def test_total_exposure_rejects_stale_existing_position_mark(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_holding("ETH", balance=20, available=20)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
    )
    exchange.set_ticker(
        "ETH-USDT",
        last=1,
        bid=Decimal("0.99"),
        ask=Decimal("1.01"),
        timestamp=1,
    )
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.reconcile_position(
        "ETH-USDT",
        Decimal("20"),
        reference_price=Decimal("1"),
        reason="fixture",
    )
    journal.set_mode(SystemMode.READY)
    service = ProductionRiskService(
        exchange,
        journal,
        ProductionRiskLimits(),
    )
    request = ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.01"),
        reserved_quote=Decimal("600"),
        stop_loss=Decimal("49000"),
        take_profit=Decimal("52000"),
    )
    allowed, reason = service.check(request)
    assert not allowed and "ETH-USDT 风险价格无效" in reason

    exchange.set_ticker(
        "ETH-USDT",
        last=400,
        bid=399,
        ask=401,
    )
    allowed, reason = service.check(request)
    assert not allowed and "账户硬限制" in reason
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_pretrade_rejects_reserve_computed_from_stale_lower_ticker(
    tmp_path,
    monkeypatch,
):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    original = exchange.get_ticker
    calls = 0

    def rising_ticker(inst_id):
        nonlocal calls
        calls += 1
        if calls == 1:
            exchange.set_ticker(inst_id, last=100, bid=100, ask=100)
        else:
            exchange.set_ticker(inst_id, last=200, bid=200, ask=200)
        return original(inst_id)

    monkeypatch.setattr(exchange, "get_ticker", rising_ticker)
    try:
        with pytest.raises(RuntimeError, match="风险预留不足"):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("1"),
                    stop_loss=Decimal("150"),
                )
            )
        assert exchange.orders == []
    finally:
        runtime.stop()


@pytest.mark.unit
def test_pretrade_exposure_uses_authoritative_exchange_holdings(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_holding("BTC", balance=1, available=1)
    exchange.set_ticker("BTC-USDT", last=100)
    exchange.set_ticker("ETH-USDT", last=100)
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.READY)
    service = ProductionRiskService(
        exchange,
        journal,
        ProductionRiskLimits(
            max_position_notional_usdt=Decimal("150"),
            max_total_exposure_usdt=Decimal("150"),
        ),
    )
    allowed, reason = service.check(
        ExecutionRequest(
            inst_id="ETH-USDT",
            side="buy",
            base_qty=Decimal("1"),
            reserved_quote=Decimal("101"),
            stop_loss=Decimal("90"),
        )
    )
    assert not allowed
    assert "仓位与本地投影不一致" in reason
    assert journal.get_mode() is SystemMode.DEGRADED
    journal.close()


@pytest.mark.unit
def test_ws_disconnect_during_pretrade_never_posts_buy(
    tmp_path,
    monkeypatch,
):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    original_balance = exchange.get_balance

    def disconnect_then_balance():
        runtime._on_ws_state("private", ConnectionState.BACKOFF)
        return original_balance()

    monkeypatch.setattr(exchange, "get_balance", disconnect_then_balance)
    try:
        with pytest.raises(RuntimeError):
            runtime.execution.submit(
                ExecutionRequest(
                    inst_id="BTC-USDT",
                    side="buy",
                    base_qty=Decimal("0.01"),
                    stop_loss=Decimal("49000"),
                )
            )
        assert exchange.orders == []
        assert journal.get_mode() is SystemMode.DEGRADED
    finally:
        runtime.stop()


@pytest.mark.unit
def test_expired_exit_lease_does_not_duplicate_unknown_sell(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        runtime.execution.submit(
            ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                reserved_quote=Decimal("500"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            )
        )
        exchange.set_holding("BTC", balance=0.01, available=0.01)
        exchange.queue_order_outcome(
            state="filled",
            fill_size=0.01,
            fill_price=49_900,
            lose_response=True,
        )
        first = runtime.exit.exit_position("BTC-USDT", "fixture")
        assert first is not None and first.state is OrderState.UNKNOWN
        journal._conn.execute("UPDATE exit_leases SET expires_at=0")
        second = runtime.exit.exit_position("BTC-USDT", "retry")
        assert second is not None and second.state is OrderState.FILLED
        assert [order.side for order in exchange.orders] == ["buy", "sell"]
    finally:
        runtime.stop()


@pytest.mark.unit
def test_strategy_exit_delegates_frozen_balance_to_protection_coordinator(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        runtime.execution.submit(
            ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                reserved_quote=Decimal("500"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            )
        )
        exchange.set_holding("BTC", balance=0.01, available=0)
        original_cancel = exchange.cancel_algo_order

        def cancel_and_release(inst_id, algo_id):
            result = original_cancel(inst_id, algo_id)
            exchange.set_holding("BTC", balance=0.01, available=0.01)
            return result

        exchange.cancel_algo_order = cancel_and_release
        risk = RiskManager()
        risk.add_position(PositionInfo("BTC-USDT", size=0.01, entry_price=50_000))
        orders = OrderExecutor(
            exchange,
            "BTC-USDT",
            risk,
            production_runtime=runtime,
        )
        assert orders.sell(50_000, "strategy exit")
        assert [order.side for order in exchange.orders] == ["buy", "sell"]
    finally:
        runtime.stop()


@pytest.mark.unit
def test_order_executor_does_not_restore_position_after_emergency_exit(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        exchange.queue_algo_outcome(reject=True)
        risk = RiskManager()
        orders = OrderExecutor(
            exchange,
            "BTC-USDT",
            risk,
            production_runtime=runtime,
        )
        assert not orders.buy(
            price=50_000,
            size_coin=0.01,
            sl=49_000,
            tp=52_000,
            reason="fixture",
        )
        assert not risk.has_position("BTC-USDT")
        assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == 0
        assert [order.side for order in exchange.orders] == ["buy", "sell"]
    finally:
        runtime.stop()


@pytest.mark.unit
def test_flatten_control_runs_inside_single_writer(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    runtime.start()
    try:
        runtime.execution.submit(
            ExecutionRequest(
                inst_id="BTC-USDT",
                side="buy",
                base_qty=Decimal("0.01"),
                reserved_quote=Decimal("500"),
                stop_loss=Decimal("49000"),
                take_profit=Decimal("52000"),
            )
        )
        exchange.set_holding("BTC", balance=0.01, available=0.01)
        exchange.on_order(
            lambda order: (
                exchange.set_holding("BTC", balance=0, available=0)
                if order.side == "sell"
                else None
            )
        )
        command = enqueue_and_wait(
            journal,
            "flatten-and-cancel",
            {"instruments": ["BTC-USDT"], "actor": "test"},
            timeout_s=2,
        )
        assert command["status"] == "completed"
        assert journal.get_mode() is SystemMode.HALTED
        assert Decimal(journal.get_position("BTC-USDT")["base_qty"]) == 0
    finally:
        runtime.stop()


@pytest.mark.unit
def test_flatten_scope_never_cancels_unapproved_instrument(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.queue_order_outcome(state="live")
    btc = exchange.place_market_order("BTC-USDT", "buy", 0.01, cl_ord_id="BTCFLATTENSCOPE01")
    exchange.queue_order_outcome(state="live")
    eth = exchange.place_market_order("ETH-USDT", "buy", 0.1, cl_ord_id="ETHFLATTENSCOPE01")
    result = runtime._flatten_and_cancel(
        "c" * 32,
        {"instruments": ["BTC-USDT"], "actor": "operator"},
    )
    assert btc.ord_id in result["canceled_order_ids"]
    assert eth.ord_id not in result["canceled_order_ids"]
    assert exchange.get_order_status("ETH-USDT", ord_id=eth.ord_id).state is OrderState.LIVE
    journal.close()


@pytest.mark.unit
def test_unknown_flatten_scope_fails_without_exchange_side_effect(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.queue_order_outcome(state="live")
    eth = exchange.place_market_order("ETH-USDT", "buy", 0.1, cl_ord_id="ETHFLATTENSCOPE02")
    with pytest.raises(RuntimeError, match="不存在"):
        runtime._flatten_and_cancel(
            "d" * 32,
            {"instruments": ["BTC-USDT"], "actor": "operator"},
        )
    assert exchange.get_order_status("ETH-USDT", ord_id=eth.ord_id).state is OrderState.LIVE
    assert journal.get_mode() is SystemMode.STARTING
    journal.close()


@pytest.mark.unit
def test_flatten_all_recomputes_targets_after_baseline(tmp_path, monkeypatch):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_ticker("ETH-USDT", last=3_000)
    original_balance = exchange.get_balance
    calls = 0

    def holding_appears_during_baseline():
        nonlocal calls
        calls += 1
        if calls == 2:
            exchange.set_holding("ETH", balance=1, available=1)
        return original_balance()

    exchange.on_order(
        lambda order: (
            exchange.set_holding("ETH", balance=0, available=0)
            if order.side == "sell" and order.inst_id == "ETH-USDT"
            else None
        )
    )
    monkeypatch.setattr(
        exchange,
        "get_balance",
        holding_appears_during_baseline,
    )
    result = runtime._flatten_and_cancel(
        "e" * 32,
        {"instruments": [], "actor": "operator"},
    )
    assert result["exit_order_ids"]
    assert exchange.get_balance().holding("ETH").balance == 0
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_halted_runtime_resumes_only_after_two_person_safety_gate(tmp_path):
    exchange, journal, runtime = _runtime(tmp_path)
    exchange.set_account_identity("expected-uid")
    runtime.expected_account_id = "expected-uid"
    journal.set_mode(SystemMode.HALTED)
    runtime.start()
    try:
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"actor": "operator", "risk_approver": "risk"},
            timeout_s=2,
        )
        assert command["status"] == "completed"
        assert journal.get_mode() is SystemMode.READY
        assert runtime.ready
    finally:
        runtime.stop()


@pytest.mark.unit
def test_safety_only_ignores_shadow_and_permanently_rejects_resume(tmp_path):
    exchange = FakeExchange()
    exchange.set_balance(total=10_000, quote_avail=10_000)
    exchange.set_holding("BTC", balance=0.1, available=0.1)
    exchange.set_ticker(
        "BTC-USDT",
        last=50_000,
        bid=49_990,
        ask=50_010,
    )
    journal = SQLiteJournal(tmp_path / "trading.db")
    runtime = ProductionRuntime(
        exchange,
        journal,
        shadow_mode=True,
        safety_only=True,
        lock_path=tmp_path / "trading.lock",
        reconciliation_interval_s=0.05,
    )
    runtime.start()
    try:
        assert not runtime.shadow_mode
        assert journal.get_mode() is SystemMode.HALTED
        assert journal.has_active_protection(
            "BTC-USDT",
            Decimal("0.1"),
        )
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"actor": "operator", "risk_approver": "risk"},
            timeout_s=2,
        )
        assert command["status"] == "failed"
        assert "safety-only" in command["result"]["error"]
        assert journal.get_mode() is SystemMode.HALTED
        assert not runtime.ready
        ready, detail = runtime._health()
        assert not ready
        assert detail["safety_only"] is True
    finally:
        runtime.stop()


@pytest.mark.unit
def test_safety_only_never_downgrades_emergency_exit(tmp_path):
    exchange, journal, _ = _runtime(tmp_path)
    journal.set_mode(SystemMode.EMERGENCY_EXIT)
    runtime = ProductionRuntime(
        exchange,
        journal,
        safety_only=True,
        lock_path=tmp_path / "safety-only.lock",
        reconciliation_interval_s=0.05,
    )
    runtime.start()
    try:
        assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"actor": "operator", "risk_approver": "risk"},
            timeout_s=2,
        )
        assert command["status"] == "failed"
        assert journal.get_mode() is SystemMode.EMERGENCY_EXIT
        assert not runtime.ready
        with pytest.raises(AttributeError):
            runtime.safety_only = False
    finally:
        runtime.stop()


@pytest.mark.unit
def test_resume_failure_keeps_hard_halt_latched(tmp_path):
    _, journal, runtime = _runtime(tmp_path)
    journal.set_mode(SystemMode.HALTED)
    runtime.start()
    try:
        runtime.alerts.webhook_url = "https://alerts.example"
        runtime.alerts.consecutive_failures = 3
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"actor": "operator", "risk_approver": "risk"},
            timeout_s=2,
        )
        assert command["status"] == "failed"
        assert journal.get_mode() is SystemMode.HALTED
    finally:
        runtime.stop()


@pytest.mark.unit
def test_single_instance_lock_rejects_second_owner(tmp_path):
    first = SingleInstanceLock(tmp_path / "runtime.lock")
    second = SingleInstanceLock(tmp_path / "runtime.lock")
    first.acquire()
    try:
        with pytest.raises(RuntimeError, match="另一个交易实例"):
            second.acquire()
    finally:
        first.release()
