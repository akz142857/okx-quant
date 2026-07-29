"""Strict Demo-to-Canary transition and short-lived real-money policy."""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote, urlparse

from okx_quant.application.approval import (
    canonical_bytes,
    production_config_hash,
    verify_ed25519_artifact,
)
from okx_quant.config import ProductionSettings, load_yaml
from okx_quant.infrastructure.evidence import (
    credential_fingerprint,
    ed25519_public_key_fingerprint,
)
from okx_quant.research.demo_soak import (
    CANARY_SOURCE_PRODUCER_NAMES,
    canary_source_producer_inventory_sha256,
    validate_canary_source_producer_inventory,
    validate_strategy_identity,
)

_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
CANARY_CAPABILITY_MAX_LIFETIME_SECONDS = 300
CANARY_CAPABILITY_MAX_BYTES = 16 * 1024 * 1024
CANARY_POST_START_WS_MAX_AGE_SECONDS = 30
DEFAULT_CANARY_CAPABILITY_BUNDLE = Path(
    "/etc/okx-quant/canary-producers/capability-bundle.json"
)
DEFAULT_CANARY_CAPABILITY_PUBLIC_KEY = Path(
    "/etc/okx-quant/keys/canary-capability-public.pem"
)
DEFAULT_CANARY_IAM_PUBLIC_KEY = Path(
    "/etc/okx-quant/keys/canary-iam-public.pem"
)
DEFAULT_CANARY_WORM_READBACK_PUBLIC_KEY = Path(
    "/etc/okx-quant/keys/canary-worm-readback-public.pem"
)
DEFAULT_CANARY_DEPLOYMENT_VERIFIER_PUBLIC_KEY = Path(
    "/etc/okx-quant/keys/canary-deployment-verifier-public.pem"
)
DEFAULT_CANARY_CAPABILITY_REPLAY_STATE = Path(
    "/var/lib/okx-quant/admission/canary-capability-replay.json"
)
ALLOWED_DEPLOYMENT_DIFFERENCES = [
    "account_uid",
    "api_domain",
    "config_sha256",
    "deployment_tier",
    "environment",
    "host_image_sha256",
    "ip_allowlist_sha256",
    "key_fingerprint",
    "permissions",
    "simulated",
    "unit",
]
REQUIRED_PRE_START_CHECKS = [
    "account_uid_verified",
    "api_key_read_trade_only",
    "api_key_withdraw_disabled",
    "ip_allowlist_verified",
    "journal_identity_verified",
    "limits_match_policy",
    "release_identity_verified",
]
REQUIRED_POST_START_CHECKS = [
    "alert_challenge_received",
    "backup_exact_version_restored",
    "protected_position_or_flat",
    "rest_ws_reconciliation_safe",
    "runtime_safety_kernel_live_within_60s",
]
CANARY_PRODUCER_ADAPTERS = {
    "account_uid_verified": {"https"},
    "api_key_read_trade_only": {"https"},
    "api_key_withdraw_disabled": {"https"},
    "ip_allowlist_verified": {"https"},
    "journal_identity_verified": {"file"},
    "limits_match_policy": {"file"},
    "release_identity_verified": {"file"},
    "alert_challenge_received": {"https"},
    "backup_exact_version_restored": {"s3-version"},
    "protected_position_or_flat": {"https"},
    "rest_ws_reconciliation_safe": {"file", "https"},
    "runtime_safety_kernel_live_within_60s": {"file", "https"},
}
TARGET_CREDENTIAL_AUTHORITIES = {
    "okx_authenticated_account_api",
    "okx_api_key_admin_api",
    "okx_account_and_business_ws",
}
PRE_START_SOURCE_KEYS = {
    "version",
    "action",
    "check",
    "observed_at",
    "account_uid",
    "deployment_unit",
    "demo_soak_epoch_id",
    "release_identity_sha256",
    "release_commit",
    "deployed_source_sha256",
    "config_sha256",
    "target_deployment_identity_sha256",
    "pre_start_challenge",
    "producer_execution",
    "collection_receipt",
    "source_evidence",
    "facts",
}
SOURCE_EVIDENCE_KEYS = {
    "kind",
    "sha256",
    "bytes",
    "payload_base64",
}
_PRE_START_LOCATOR_KEYS = {
    "observed_at",
    "evidence_sha256",
    "evidence_bytes",
    "artifact_bytes_base64",
    "source_public_key_pem_base64",
}
POST_START_SOURCE_KEYS = {
    "version",
    "action",
    "check",
    "observed_at",
    "runtime_instance_id",
    "boot_id",
    "account_uid",
    "deployment_unit",
    "demo_soak_epoch_id",
    "transition_sha256",
    "policy_sha256",
    "target_deployment_identity_sha256",
    "startup_nonce",
    "expected_startup_hard_epoch",
    "producer_execution",
    "collection_receipt",
    "source_evidence",
    "facts",
}
_TARGET_KEYS = {
    "release_identity_sha256",
    "release_commit",
    "deployed_source_sha256",
    "config_sha256",
    "account_uid",
    "environment",
    "deployment_tier",
    "api_domain",
    "simulated",
    "permissions",
    "ip_allowlist_sha256",
    "unit",
    "host_image_sha256",
    "key_fingerprint",
    "allowed_instruments",
    "source_producer_inventory_sha256",
}
_TRANSITION_KEYS = {
    "version",
    "action",
    "transition_id",
    "issued_at",
    "expires_at",
    "demo_soak_epoch_id",
    "demo_ledger_head_hash",
    "release_identity",
    "strategy_identity",
    "target_deployment_identity",
    "allowed_deployment_differences",
    "required_pre_start_checks",
    "pre_start_checks",
    "pre_start_source_key_fingerprints",
    "canary_limits",
    "required_post_start_checks",
    "post_start_verifier_key_fingerprint",
    "post_start_source_key_fingerprints",
    "source_producer_inventory",
    "source_producer_inventory_sha256",
    "pre_start_challenge",
    "operator",
    "risk_approver",
}
PRODUCER_EXECUTION_KEYS = {
    "version",
    "producer_name",
    "readiness_id",
    "inventory_sha256",
    "source_key_fingerprint",
    "collector_unix_user",
    "collector_uid",
    "collector_systemd_unit",
    "collector_invocation_id",
    "collector_cgroup",
    "signer_unix_user",
    "signer_uid",
    "signer_systemd_unit",
    "signer_invocation_id",
    "signer_cgroup",
    "boot_id",
    "host_image_sha256",
    "collector_mount_namespace_id",
    "signer_mount_namespace_id",
    "iam_principal",
    "iam_sts_receipt_sha256",
    "collector_executable_sha256",
    "signer_executable_sha256",
    "parser_sha256",
    "raw_sha256",
    "raw_bytes",
    "collected_at",
    "signed_at",
    "nonce",
}
IAM_STS_RECEIPT_KEYS = {
    "version",
    "action",
    "receipt_id",
    "producer_name",
    "issued_at",
    "expires_at",
    "iam_principal",
    "sts_account_id",
    "sts_principal_arn",
    "sts_session_id",
    "sts_request",
    "sts_response",
    "collector_systemd_unit",
    "collector_invocation_id",
    "collector_cgroup",
    "collector_uid",
    "boot_id",
    "release_identity_sha256",
    "config_sha256",
    "account_uid",
    "demo_soak_epoch_id",
    "target_deployment_identity_sha256",
    "transition_sha256",
    "source_producer_inventory_sha256",
    "readiness_id",
    "nonce",
}
PRODUCER_CAPABILITY_KEYS = {
    "source_public_key_pem_base64",
    "source_key_fingerprint",
    "producer_attestation_bytes_base64",
    "producer_attestation_sha256",
    "iam_sts_receipt_bytes_base64",
    "iam_sts_receipt_sha256",
    "pre_start_source_artifact_sha256",
    "worm_readback_receipt_bytes_base64",
    "worm_readback_receipt_sha256",
    "worm_version_id",
}
PRODUCER_ATTESTATION_KEYS = {
    "version",
    "action",
    "producer_name",
    "observed_at",
    "expires_at",
    "release_identity_sha256",
    "config_sha256",
    "account_uid",
    "demo_soak_epoch_id",
    "target_deployment_identity_sha256",
    "transition_sha256",
    "source_producer_inventory_sha256",
    "readiness_id",
    "producer_execution",
    "collection_receipt",
    "capability_probe_bytes_base64",
    "capability_probe_sha256",
    "pre_start_source_artifact_sha256",
}
CAPABILITY_BUNDLE_KEYS = {
    "version",
    "action",
    "readiness_id",
    "nonce",
    "issued_at",
    "expires_at",
    "release_identity_sha256",
    "release_commit",
    "config_sha256",
    "account_uid",
    "demo_soak_epoch_id",
    "target_deployment_identity_sha256",
    "transition_sha256",
    "pre_start_challenge",
    "source_producer_inventory",
    "source_producer_inventory_sha256",
    "capability_authority_key_fingerprint",
    "iam_authority_key_fingerprint",
    "worm_readback_authority_key_fingerprint",
    "deployment_verifier_key_fingerprint",
    "deployment_verifier_artifact_bytes_base64",
    "deployment_verifier_artifact_sha256",
    "producers",
}
WORM_READBACK_RECEIPT_KEYS = {
    "version",
    "action",
    "receipt_id",
    "producer_name",
    "readiness_id",
    "demo_soak_epoch_id",
    "target_deployment_identity_sha256",
    "transition_sha256",
    "requested_at",
    "retrieved_at",
    "request_method",
    "object_uri",
    "request_uri",
    "version_id",
    "expected_kms_key_id",
    "aws_region",
    "reader_access_key_fingerprint",
    "request_header_names",
    "request_headers_sha256",
    "response_status",
    "response_headers",
    "readback_sha256",
    "readback_bytes",
    "readback_bytes_base64",
    "verifier_unix_user",
    "verifier_uid",
    "verifier_systemd_unit",
    "verifier_invocation_id",
    "verifier_cgroup",
    "host_image_sha256",
    "boot_id",
    "mount_namespace_id",
    "verifier_executable_sha256",
    "nonce",
}
DEPLOYMENT_VERIFIER_KEYS = {
    "version",
    "action",
    "verifier_id",
    "readiness_id",
    "release_identity_sha256",
    "config_sha256",
    "account_uid",
    "demo_soak_epoch_id",
    "target_deployment_identity_sha256",
    "transition_sha256",
    "source_producer_inventory_sha256",
    "verifier_unix_user",
    "verifier_uid",
    "verifier_systemd_unit",
    "verifier_invocation_id",
    "verifier_cgroup",
    "host_image_sha256",
    "boot_id",
    "mount_namespace_id",
    "systemd_version",
    "verifier_executable_sha256",
    "producer_units",
    "observed_at",
    "nonce",
}
DEPLOYMENT_UNIT_KEYS = {
    "producer_name",
    "collector_systemd_unit",
    "collector_fragment_path",
    "collector_fragment_sha256",
    "collector_exec_start_sha256",
    "collector_executable_sha256",
    "collector_user",
    "signer_systemd_unit",
    "signer_fragment_path",
    "signer_fragment_sha256",
    "signer_exec_start_sha256",
    "signer_executable_sha256",
    "signer_user",
    "parser_sha256",
    "permission_probe",
}
DEPLOYMENT_PERMISSION_PROBE_KEYS = {
    "collector_can_write_raw_directory",
    "signer_can_read_raw_artifact",
    "signer_can_write_raw_artifact",
    "signer_can_write_signed_directory",
    "capability_can_read_signed_artifact",
    "capability_can_write_signed_artifact",
    "raw_directory_mode",
    "raw_artifact_mode",
    "signed_directory_mode",
    "signed_artifact_mode",
}
COLLECTION_RECEIPT_KEYS = {
    "version",
    "action",
    "producer_name",
    "source_authority",
    "source_request_sha256",
    "collector_request",
    "adapter",
    "source_uri",
    "source_version_id",
    "request_method",
    "request_auth_timestamp",
    "actual_target_credential_fingerprint",
    "requested_at",
    "response_status",
    "response_headers",
    "received_at",
    "secondary_source_uri",
    "secondary_source_version_id",
    "secondary_response_status",
    "secondary_response_headers",
    "secondary_received_at",
    "source_device",
    "source_inode",
    "source_mode",
    "source_uid",
    "source_mount_id",
    "proc_fd_target",
    "raw_path",
    "raw_sha256",
    "raw_bytes",
    "collected_at",
    "collector_unix_user",
    "collector_uid",
    "collector_systemd_unit",
    "collector_invocation_id",
    "collector_cgroup",
    "boot_id",
    "mount_namespace_id",
}
CANARY_LIMIT_FIELDS = {
    "max_order_notional_usdt",
    "max_order_intents_per_hour",
    "max_concurrent_positions",
    "max_total_exposure_usdt",
    "max_order_loss_usdt",
    "max_daily_loss_usdt",
    "max_drawdown_ratio",
    "max_slippage_ratio",
}
_POLICY_KEYS = {
    "version",
    "action",
    "policy_id",
    "issued_at",
    "expires_at",
    "transition_sha256",
    "target_deployment_identity_sha256",
    "allowed_instruments",
    "max_order_notional_usdt",
    "max_order_intents_per_hour",
    "max_concurrent_positions",
    "max_total_exposure_usdt",
    "max_order_loss_usdt",
    "max_daily_loss_usdt",
    "max_drawdown_ratio",
    "max_slippage_ratio",
    "auto_halt",
    "auto_flatten",
    "operator",
    "risk_approver",
    "rollback_owner",
    "production_promotion",
}
_POST_START_KEYS = {
    "version",
    "action",
    "issued_at",
    "expires_at",
    "transition_sha256",
    "policy_sha256",
    "target_deployment_identity_sha256",
    "runtime_instance_id",
    "boot_id",
    "expected_startup_hard_epoch",
    "startup_nonce",
    "latch_reason",
    "checks_verifier_key_fingerprint",
    "source_key_fingerprints",
    "checks",
    "operator",
    "risk_approver",
}


def identity_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_s3(value: object) -> bool:
    parsed = urlparse(str(value))
    return parsed.scheme == "s3" and bool(parsed.netloc) and bool(parsed.path.strip("/"))


def _canonical_worm_request_uri(
    *,
    object_uri: str,
    request_origin: str,
    version_id: str,
) -> str:
    parsed_object = urlparse(object_uri)
    parsed_origin = urlparse(request_origin)
    if (
        parsed_object.scheme != "s3"
        or not parsed_object.netloc
        or not parsed_object.path.lstrip("/")
        or parsed_origin.scheme != "https"
        or not parsed_origin.netloc
        or parsed_origin.path not in {"", "/"}
        or parsed_origin.query
        or parsed_origin.fragment
        or not _nonempty(version_id)
    ):
        raise ValueError("WORM frozen locator 非法")
    key = quote(
        parsed_object.path.lstrip("/"),
        safe="/-_.~",
    )
    encoded_version = quote(version_id, safe="-_.~")
    return (
        f"{request_origin.rstrip('/')}/{key}"
        f"?versionId={encoded_version}"
    )


def canary_readiness_id(
    *,
    demo_soak_epoch_id: str,
    target_deployment_identity_sha256: str,
    source_producer_inventory_sha256: str,
) -> str:
    """Derive the challenge namespace shared by transition and producers."""
    return hashlib.sha256(
        canonical_bytes(
            {
                "domain": "okx-quant/canary-readiness/v1",
                "demo_soak_epoch_id": demo_soak_epoch_id,
                "target_deployment_identity_sha256": (
                    target_deployment_identity_sha256
                ),
                "source_producer_inventory_sha256": (
                    source_producer_inventory_sha256
                ),
            }
        )
    ).hexdigest()[:32]


def okx_ip_allowlist_sha256(value: object) -> str:
    """Hash the native OKX comma-separated IP allowlist deterministically."""
    if isinstance(value, str):
        entries = [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]
    elif isinstance(value, list):
        entries = [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]
    else:
        raise ValueError("OKX native IP allowlist 非法")
    if not entries or len(entries) != len(set(entries)):
        raise ValueError("OKX native IP allowlist 为空或重复")
    return hashlib.sha256(
        canonical_bytes(sorted(entries))
    ).hexdigest()


def _systemd_cgroup_matches(value: object, unit: str) -> bool:
    cgroup = str(value)
    return (
        cgroup.startswith("/system.slice/")
        and cgroup.endswith(f"/{unit}")
        and ".." not in cgroup.split("/")
    )


def validate_producer_execution(
    payload: object,
    *,
    producer_name: str,
    inventory: dict,
    readiness_id: str,
    raw: bytes,
    now: int,
) -> dict:
    """Validate signed per-invocation isolation and raw-byte provenance."""
    if (
        not isinstance(payload, dict)
        or set(payload) != PRODUCER_EXECUTION_KEYS
        or producer_name not in inventory
    ):
        raise ValueError("Canary producer execution schema/name 非法")
    item = inventory[producer_name]
    integer_fields = (
        "collector_uid",
        "signer_uid",
        "raw_bytes",
        "collected_at",
        "signed_at",
    )
    if (
        payload["version"] != 1
        or payload["producer_name"] != producer_name
        or payload["readiness_id"] != readiness_id
        or not re.fullmatch(r"[0-9a-f]{32}", readiness_id)
        or payload["inventory_sha256"]
        != canary_source_producer_inventory_sha256(inventory)
        or payload["source_key_fingerprint"]
        != item["source_key_fingerprint"]
        or payload["collector_unix_user"]
        != item["collector_unix_user"]
        or payload["signer_unix_user"] != item["signer_unix_user"]
        or payload["collector_systemd_unit"]
        != item["collector_systemd_unit"]
        or payload["signer_systemd_unit"]
        != item["signer_systemd_unit"]
        or payload["iam_principal"] != item["iam_principal"]
        or any(
            payload[key] != item[key]
            for key in (
                "collector_executable_sha256",
                "signer_executable_sha256",
                "parser_sha256",
            )
        )
        or any(type(payload[name]) is not int for name in integer_fields)
        or payload["collector_uid"] <= 0
        or payload["signer_uid"] <= 0
        or payload["collector_uid"] == payload["signer_uid"]
        or payload["raw_bytes"] != len(raw)
        or payload["raw_sha256"] != hashlib.sha256(raw).hexdigest()
        or payload["collected_at"] > payload["signed_at"]
        or payload["signed_at"] - payload["collected_at"] > 300
        or not now - 300 <= payload["signed_at"] <= now + 5
        or not _systemd_cgroup_matches(
            payload["collector_cgroup"],
            item["collector_systemd_unit"],
        )
        or not _systemd_cgroup_matches(
            payload["signer_cgroup"],
            item["signer_systemd_unit"],
        )
        or any(
            not re.fullmatch(r"[0-9a-f]{32}", str(payload[name]))
            for name in (
                "collector_invocation_id",
                "signer_invocation_id",
                "nonce",
            )
        )
        or payload["collector_invocation_id"]
        == payload["signer_invocation_id"]
        or not re.fullmatch(
            r"[0-9a-fA-F-]{16,64}",
            str(payload["boot_id"]),
        )
        or any(
            not re.fullmatch(
                r"mnt:\[[1-9][0-9]*\]",
                str(payload[name]),
            )
            for name in (
                "collector_mount_namespace_id",
                "signer_mount_namespace_id",
            )
        )
        or any(
            not _SHA256.fullmatch(str(payload[name]))
            for name in (
                "inventory_sha256",
                "source_key_fingerprint",
                "iam_sts_receipt_sha256",
                "collector_executable_sha256",
                "signer_executable_sha256",
                "parser_sha256",
                "raw_sha256",
                "host_image_sha256",
            )
        )
    ):
        raise ValueError(
            f"Canary producer {producer_name} execution identity/isolation 非法"
        )
    return payload


def validate_collection_receipt(
    payload: object,
    *,
    producer_name: str,
    inventory: dict,
    raw: bytes,
    target_key_fingerprint: str,
    now: int,
) -> dict:
    """Validate the signed native acquisition request and transport receipt."""
    if (
        not isinstance(payload, dict)
        or set(payload) != COLLECTION_RECEIPT_KEYS
        or producer_name not in inventory
    ):
        raise ValueError("Canary collection receipt schema/name 非法")
    item = inventory[producer_name]
    request = payload["collector_request"]
    request_keys = {
        "version",
        "producer_name",
        "adapter",
        "method",
        "source_uri",
        "source_object_uri",
        "source_version_id",
        "secondary_source_uri",
        "secondary_source_object_uri",
        "secondary_source_version_id",
        "target_credential_fingerprint",
        "auth_mode",
        "okx_auth_credentials",
        "headers_from_credentials",
        "required_response_headers",
        "secondary_required_response_headers",
        "timeout_seconds",
    }
    if (
        not isinstance(request, dict)
        or set(request) != request_keys
        or request["version"] != 1
        or request["producer_name"] != producer_name
        or request["adapter"] not in {
            "file",
            "https",
            "s3-version",
        }
        or request["adapter"]
        not in CANARY_PRODUCER_ADAPTERS[producer_name]
        or request["method"]
        != ("READ" if request["adapter"] == "file" else "GET")
        or not _nonempty(request["source_uri"])
        or not _nonempty(request["source_version_id"])
        or not isinstance(
            request["headers_from_credentials"],
            dict,
        )
        or any(
            not re.fullmatch(r"[A-Za-z0-9-]{1,64}", str(header))
            or credential != "source-authorization"
            for header, credential
            in request["headers_from_credentials"].items()
        )
        or not isinstance(
            request["required_response_headers"],
            dict,
        )
        or not isinstance(
            request["secondary_required_response_headers"],
            dict,
        )
        or type(request["timeout_seconds"]) is not int
        or not 1 <= request["timeout_seconds"] <= 30
        or request["target_credential_fingerprint"]
        != target_key_fingerprint
        or request["auth_mode"] not in {"none", "static", "okx-v5"}
        or not isinstance(request["okx_auth_credentials"], dict)
        or any(
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", str(value))
            for value in request["okx_auth_credentials"].values()
        )
        or hashlib.sha256(canonical_bytes(request)).hexdigest()
        != item["source_request_sha256"]
        or payload["source_request_sha256"]
        != item["source_request_sha256"]
        or payload["version"] != 1
        or payload["action"] != "collect-canary-native-source"
        or payload["producer_name"] != producer_name
        or payload["source_authority"] != item["source_authority"]
        or payload["adapter"] != request["adapter"]
        or payload["source_uri"] != request["source_uri"]
        or payload["source_version_id"]
        != request["source_version_id"]
        or payload["request_method"] != request["method"]
        or payload["secondary_source_uri"]
        != request["secondary_source_uri"]
        or payload["secondary_source_version_id"]
        != request["secondary_source_version_id"]
        or (
            item["source_authority"] in TARGET_CREDENTIAL_AUTHORITIES
            and (
                request["auth_mode"] != "okx-v5"
                or set(request["okx_auth_credentials"])
                != {"api_key", "secret_key", "passphrase"}
                or request["okx_auth_credentials"]
                != {
                    "api_key": "okx-api-key",
                    "secret_key": "okx-secret-key",
                    "passphrase": "okx-passphrase",
                }
                or request["headers_from_credentials"] != {}
                or payload["actual_target_credential_fingerprint"]
                != target_key_fingerprint
                or not _nonempty(payload["request_auth_timestamp"])
            )
        )
        or (
            item["source_authority"] not in TARGET_CREDENTIAL_AUTHORITIES
            and (
                request["auth_mode"] == "okx-v5"
                or request["okx_auth_credentials"] != {}
                or payload["actual_target_credential_fingerprint"] != ""
                or payload["request_auth_timestamp"] != ""
            )
        )
        or payload["raw_path"] != item["raw_source_path"]
        or payload["raw_sha256"] != hashlib.sha256(raw).hexdigest()
        or payload["raw_bytes"] != len(raw)
        or type(payload["requested_at"]) is not int
        or type(payload["received_at"]) is not int
        or type(payload["collected_at"]) is not int
        or not payload["requested_at"]
        <= payload["received_at"]
        <= payload["collected_at"]
        <= payload["requested_at"] + 30
        or not now - 300 <= payload["collected_at"] <= now + 5
        or payload["collector_unix_user"]
        != item["collector_unix_user"]
        or payload["collector_systemd_unit"]
        != item["collector_systemd_unit"]
        or type(payload["collector_uid"]) is not int
        or payload["collector_uid"] <= 0
        or not _systemd_cgroup_matches(
            payload["collector_cgroup"],
            item["collector_systemd_unit"],
        )
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(payload["collector_invocation_id"]),
        )
        or not re.fullmatch(
            r"[0-9a-fA-F-]{16,64}",
            str(payload["boot_id"]),
        )
        or not re.fullmatch(
            r"mnt:\[[1-9][0-9]*\]",
            str(payload["mount_namespace_id"]),
        )
        or not isinstance(payload["response_headers"], dict)
        or not isinstance(
            payload["secondary_response_headers"],
            dict,
        )
        or any(
            not isinstance(key, str)
            or key != key.lower()
            or not isinstance(value, str)
            for key, value in payload["response_headers"].items()
        )
        or request["required_response_headers"]
        != {
            key: payload["response_headers"].get(key)
            for key in request["required_response_headers"]
        }
    ):
        raise ValueError(
            f"Canary producer {producer_name} collection provenance 非法"
        )
    if item["source_authority"] in TARGET_CREDENTIAL_AUTHORITIES:
        try:
            auth_time = datetime.fromisoformat(
                payload["request_auth_timestamp"].replace("Z", "+00:00")
            )
        except (ValueError, AttributeError) as exc:
            raise ValueError("OKX request auth timestamp 非法") from exc
        if (
            auth_time.tzinfo is None
            or not datetime.fromtimestamp(
                payload["requested_at"] - 5,
                tz=UTC,
            )
            <= auth_time.astimezone(UTC)
            <= datetime.fromtimestamp(
                payload["received_at"] + 5,
                tz=UTC,
            )
        ):
            raise ValueError("OKX request auth timestamp 已过期或未绑定本次请求")
    if request["adapter"] == "file":
        parsed = urlparse(request["source_uri"])
        if (
            request["method"] != "READ"
            or parsed.scheme != "file"
            or parsed.netloc
            or not Path(parsed.path).is_absolute()
            or payload["response_status"] != 0
            or payload["response_headers"] != {}
            or any(
                type(payload[name]) is not int
                for name in (
                    "source_device",
                    "source_inode",
                    "source_mode",
                    "source_uid",
                )
            )
            or payload["source_device"] <= 0
            or payload["source_inode"] <= 0
            or not stat.S_ISREG(payload["source_mode"])
            or payload["source_mode"]
            & (stat.S_IWGRP | stat.S_IWOTH)
            or payload["source_uid"] != 0
            or payload["source_mount_id"]
            != f"{os.major(payload['source_device'])}:"
            f"{os.minor(payload['source_device'])}"
            or payload["proc_fd_target"] != parsed.path
        ):
            raise ValueError(
                f"Canary producer {producer_name} file device/inode/fd 非法"
            )
    else:
        if (
            request["method"] != "GET"
            or urlparse(request["source_uri"]).scheme != "https"
            or payload["response_status"] != 200
            or any(
                payload[name] not in (0, "")
                for name in (
                    "source_device",
                    "source_inode",
                    "source_mode",
                    "source_uid",
                    "source_mount_id",
                    "proc_fd_target",
                )
            )
        ):
            raise ValueError(
                f"Canary producer {producer_name} HTTPS provenance 非法"
            )
    if request["adapter"] == "s3-version":
        headers = payload["response_headers"]
        secondary_headers = payload["secondary_response_headers"]
        try:
            retain_until = datetime.fromisoformat(
                headers[
                    "x-amz-object-lock-retain-until-date"
                ].replace("Z", "+00:00")
            )
            secondary_retain_until = datetime.fromisoformat(
                secondary_headers[
                    "x-amz-object-lock-retain-until-date"
                ].replace("Z", "+00:00")
            )
        except (KeyError, ValueError, AttributeError) as exc:
            raise ValueError("S3 ObjectLock retain-until header 非法") from exc
        if (
            headers.get("x-amz-version-id")
            != request["source_version_id"]
            or headers.get("x-amz-server-side-encryption") != "aws:kms"
            or not _nonempty(
                headers.get(
                    "x-amz-server-side-encryption-aws-kms-key-id"
                )
            )
            or headers.get("x-amz-object-lock-mode")
            not in {"COMPLIANCE", "GOVERNANCE"}
            or retain_until.tzinfo is None
            or retain_until.astimezone(UTC)
            < datetime.fromtimestamp(
                payload["collected_at"],
                tz=UTC,
            )
            + timedelta(days=35)
            or producer_name != "backup_exact_version_restored"
            or not _valid_s3(request["source_object_uri"])
            or not _nonempty(request["secondary_source_uri"])
            or not _valid_s3(
                request["secondary_source_object_uri"]
            )
            or not _nonempty(request["secondary_source_version_id"])
            or payload["secondary_response_status"] != 200
            or type(payload["secondary_received_at"]) is not int
            or not payload["received_at"]
            <= payload["secondary_received_at"]
            <= payload["collected_at"]
            or request["secondary_required_response_headers"]
            != {
                key: secondary_headers.get(key)
                for key in request[
                    "secondary_required_response_headers"
                ]
            }
            or secondary_headers.get("x-amz-version-id")
            != request["secondary_source_version_id"]
            or secondary_headers.get(
                "x-amz-server-side-encryption"
            )
            != "aws:kms"
            or not _nonempty(
                secondary_headers.get(
                    "x-amz-server-side-encryption-aws-kms-key-id"
                )
            )
            or secondary_headers.get("x-amz-object-lock-mode")
            not in {"COMPLIANCE", "GOVERNANCE"}
            or secondary_retain_until.tzinfo is None
            or secondary_retain_until.astimezone(UTC)
            < datetime.fromtimestamp(
                payload["secondary_received_at"],
                tz=UTC,
            )
            + timedelta(days=35)
        ):
            raise ValueError("S3 exact-version KMS/ObjectLock/WORM receipt 非法")
        bundle, archive, _manifest_bytes, manifest = (
            _decode_backup_raw_bundle(raw)
        )
        if (
            bundle["archive_get"]["request_uri"]
            != request["source_uri"]
            or bundle["archive_get"]["version_id"]
            != request["source_version_id"]
            or bundle["archive_get"]["response_headers"]
            != payload["response_headers"]
            or bundle["manifest_get"]["request_uri"]
            != request["secondary_source_uri"]
            or bundle["manifest_get"]["version_id"]
            != request["secondary_source_version_id"]
            or bundle["manifest_get"]["response_headers"]
            != payload["secondary_response_headers"]
            or manifest["archive_object_uri"]
            != request["source_object_uri"]
            or manifest["archive_request_uri"] != request["source_uri"]
            or manifest["archive_version_id"]
            != request["source_version_id"]
            or manifest["archive_sha256"]
            != hashlib.sha256(archive).hexdigest()
            or manifest["archive_bytes"] != len(archive)
            or manifest["manifest_request_uri"]
            != request["secondary_source_uri"]
            or manifest["manifest_object_uri"]
            != request["secondary_source_object_uri"]
            or manifest["manifest_version_id"]
            != request["secondary_source_version_id"]
        ):
            raise ValueError(
                "backup archive/manifest inner exact GET 未绑定 outer receipt"
            )
    elif (
        request["secondary_source_uri"] != ""
        or request["source_object_uri"] != ""
        or request["secondary_source_object_uri"] != ""
        or request["secondary_source_version_id"] != ""
        or request["secondary_required_response_headers"] != {}
        or payload["secondary_source_uri"] != ""
        or payload["secondary_source_version_id"] != ""
        or payload["secondary_response_status"] != 0
        or payload["secondary_response_headers"] != {}
        or payload["secondary_received_at"] != 0
    ):
        raise ValueError("非 backup producer 禁止 secondary source")
    return payload


def _decode_backup_raw_bundle(
    raw: bytes,
) -> tuple[dict, bytes, bytes, dict]:
    try:
        bundle = json.loads(raw)
        if (
            not isinstance(bundle, dict)
            or set(bundle)
            != {
                "archive_get",
                "manifest_get",
                "restore_requested_at",
            }
            or type(bundle["restore_requested_at"]) is not int
        ):
            raise ValueError
        decoded = {}
        for name in ("archive_get", "manifest_get"):
            row = bundle[name]
            if (
                not isinstance(row, dict)
                or set(row)
                != {
                    "request_uri",
                    "version_id",
                    "response_headers",
                    "payload_sha256",
                    "payload_bytes",
                    "payload_base64",
                }
            ):
                raise ValueError
            payload = base64.b64decode(
                row["payload_base64"],
                validate=True,
            )
            if (
                not payload
                or row["payload_sha256"]
                != hashlib.sha256(payload).hexdigest()
                or row["payload_bytes"] != len(payload)
            ):
                raise ValueError
            decoded[name] = payload
        manifest = json.loads(decoded["manifest_get"])
    except (
        ValueError,
        TypeError,
        KeyError,
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError("backup exact-GET raw bundle 非法") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "archive_request_uri",
            "archive_object_uri",
            "archive_version_id",
            "archive_sha256",
            "archive_bytes",
            "manifest_request_uri",
            "manifest_object_uri",
            "manifest_version_id",
            "backup_completed_at",
        }
        or type(manifest["backup_completed_at"]) is not int
    ):
        raise ValueError("backup manifest native payload 非法")
    return (
        bundle,
        decoded["archive_get"],
        decoded["manifest_get"],
        manifest,
    )


def validate_execution_collection_binding(
    execution: dict,
    receipt: dict,
) -> None:
    expected = {
        "collector_unix_user": receipt["collector_unix_user"],
        "collector_uid": receipt["collector_uid"],
        "collector_systemd_unit": receipt["collector_systemd_unit"],
        "collector_invocation_id": receipt[
            "collector_invocation_id"
        ],
        "collector_cgroup": receipt["collector_cgroup"],
        "collector_mount_namespace_id": receipt[
            "mount_namespace_id"
        ],
        "boot_id": receipt["boot_id"],
        "raw_sha256": receipt["raw_sha256"],
        "raw_bytes": receipt["raw_bytes"],
        "collected_at": receipt["collected_at"],
    }
    if any(execution.get(key) != value for key, value in expected.items()):
        raise ValueError(
            "Canary producer execution 未绑定同一次 collection invocation"
        )


def _decoded_json_artifact(
    encoded: object,
    *,
    label: str,
) -> tuple[bytes, object]:
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw)
    except (
        binascii.Error,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError(f"{label} exact bytes 非法") from exc
    if not raw:
        raise ValueError(f"{label} 不能为空")
    return raw, value


def _verify_embedded_ed25519(
    artifact: object,
    public_key_bytes: bytes,
    *,
    label: str,
) -> dict:
    with tempfile.NamedTemporaryFile() as public_key_file:
        public_key_file.write(public_key_bytes)
        public_key_file.flush()
        return verify_ed25519_artifact(
            artifact,
            public_key_file.name,
            label=label,
        )


def _validate_iam_sts_receipt(
    payload: object,
    *,
    producer_name: str,
    inventory: dict,
    execution: dict,
    expected: dict,
    now: int,
) -> dict:
    item = inventory[producer_name]
    request = payload.get("sts_request") if isinstance(payload, dict) else None
    response = payload.get("sts_response") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or set(payload) != IAM_STS_RECEIPT_KEYS
        or payload["version"] != 1
        or payload["action"]
        != "attest-canary-producer-iam-session"
        or payload["producer_name"] != producer_name
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(payload["receipt_id"]),
        )
        or type(payload["issued_at"]) is not int
        or type(payload["expires_at"]) is not int
        or not 60
        <= payload["expires_at"] - payload["issued_at"]
        <= CANARY_CAPABILITY_MAX_LIFETIME_SECONDS
        or not payload["issued_at"] - 5 <= now < payload["expires_at"]
        or payload["iam_principal"] != item["iam_principal"]
        or payload["sts_principal_arn"] != item["iam_principal"]
        or not isinstance(request, dict)
        or set(request) != {"action", "requested_at"}
        or request["action"] != "GetCallerIdentity"
        or type(request["requested_at"]) is not int
        or not isinstance(response, dict)
        or set(response)
        != {
            "status",
            "received_at",
            "account",
            "arn",
            "user_id",
            "request_id",
        }
        or response["status"] != 200
        or type(response["received_at"]) is not int
        or not request["requested_at"]
        <= response["received_at"]
        <= request["requested_at"] + 30
        or response["account"] != payload["sts_account_id"]
        or response["arn"] != payload["sts_principal_arn"]
        or not _nonempty(response["user_id"])
        or not _nonempty(response["request_id"])
        or not payload["issued_at"] - 30
        <= response["received_at"]
        <= payload["issued_at"]
        or not re.fullmatch(
            r"[0-9]{12}",
            str(payload["sts_account_id"]),
        )
        or not re.fullmatch(
            r"[A-Za-z0-9+=,.@_-]{8,128}",
            str(payload["sts_session_id"]),
        )
        or payload["collector_systemd_unit"]
        != execution["collector_systemd_unit"]
        or payload["collector_invocation_id"]
        != execution["collector_invocation_id"]
        or payload["collector_cgroup"]
        != execution["collector_cgroup"]
        or payload["collector_uid"] != execution["collector_uid"]
        or payload["boot_id"] != execution["boot_id"]
        or payload["readiness_id"] != execution["readiness_id"]
        or not re.fullmatch(r"[0-9a-f]{32}", str(payload["nonce"]))
        or any(payload.get(key) != value for key, value in expected.items())
    ):
        raise ValueError(
            f"Canary producer {producer_name} IAM/STS receipt 非法"
        )
    return payload


def _secure_capability_file(path: Path, *, label: str) -> bytes:
    production_state = path.is_relative_to(
        "/var/lib/okx-quant/admission"
    )
    descriptor = os.open(
        path,
        os.O_RDONLY
        | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
        | (os.O_CLOEXEC if hasattr(os, "O_CLOEXEC") else 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > CANARY_CAPABILITY_MAX_BYTES
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or (
                (
                    path.is_relative_to("/etc/okx-quant")
                    or production_state
                )
                and before.st_uid != 0
            )
            or (
                production_state
                and stat.S_IMODE(before.st_mode) != 0o600
            )
        ):
            raise ValueError(
                f"{label} 必须是受控、有界普通文件"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"{label} 读取时被截断")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"{label} 读取时增长")
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (before.st_dev, before.st_ino, before.st_size)
            != (current.st_dev, current.st_ino, current.st_size)
        ):
            raise ValueError(f"{label} 读取时被替换")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_worm_readback_receipt(
    payload: object,
    *,
    producer_name: str,
    attestation_raw: bytes,
    expected: dict,
    worm_policy: dict,
    expected_version_id: str,
    issued_at: int,
) -> dict:
    if not isinstance(payload, dict) or set(payload) != WORM_READBACK_RECEIPT_KEYS:
        raise ValueError(f"Canary producer {producer_name} WORM receipt schema 非法")
    try:
        readback = base64.b64decode(
            payload["readback_bytes_base64"],
            validate=True,
        )
        retain_until = datetime.fromisoformat(
            payload["response_headers"][
                "x-amz-object-lock-retain-until-date"
            ].replace("Z", "+00:00")
        )
    except (
        binascii.Error,
        TypeError,
        KeyError,
        ValueError,
        AttributeError,
    ) as exc:
        raise ValueError(
            f"Canary producer {producer_name} WORM receipt bytes/retention 非法"
        ) from exc
    headers = payload["response_headers"]
    required_headers = {
        "x-amz-version-id",
        "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-aws-kms-key-id",
        "x-amz-object-lock-mode",
        "x-amz-object-lock-retain-until-date",
    }
    if (
        payload["version"] != 1
        or payload["action"] != "attest-canary-worm-exact-get"
        or payload["producer_name"] != producer_name
        or not re.fullmatch(r"[0-9a-f]{32}", str(payload["receipt_id"]))
        or not re.fullmatch(r"[0-9a-f]{32}", str(payload["nonce"]))
        or any(payload.get(key) != expected[key] for key in (
            "readiness_id",
            "demo_soak_epoch_id",
            "target_deployment_identity_sha256",
            "transition_sha256",
        ))
        or type(payload["requested_at"]) is not int
        or type(payload["retrieved_at"]) is not int
        or not issued_at - 30
        <= payload["requested_at"]
        <= payload["retrieved_at"]
        <= issued_at
        or payload["request_method"] != "GET"
        or payload["object_uri"] != worm_policy["worm_object_uri"]
        or payload["version_id"] != expected_version_id
        or payload["request_uri"]
        != _canonical_worm_request_uri(
            object_uri=worm_policy["worm_object_uri"],
            request_origin=worm_policy["worm_request_origin"],
            version_id=expected_version_id,
        )
        or payload["expected_kms_key_id"]
        != worm_policy["worm_kms_key_id"]
        or payload["aws_region"] != worm_policy["worm_aws_region"]
        or payload["reader_access_key_fingerprint"]
        != worm_policy["worm_reader_access_key_fingerprint"]
        or not isinstance(payload["request_header_names"], list)
        or payload["request_header_names"]
        != sorted(set(payload["request_header_names"]))
        or any(
            not re.fullmatch(r"[a-z0-9-]{1,64}", str(name))
            for name in payload["request_header_names"]
        )
        or not _SHA256.fullmatch(
            str(payload["request_headers_sha256"])
        )
        or payload["response_status"] != 200
        or not isinstance(headers, dict)
        or set(headers) != required_headers
        or headers["x-amz-version-id"] != payload["version_id"]
        or headers["x-amz-server-side-encryption"] != "aws:kms"
        or headers[
            "x-amz-server-side-encryption-aws-kms-key-id"
        ]
        != payload["expected_kms_key_id"]
        or headers["x-amz-object-lock-mode"] != "COMPLIANCE"
        or retain_until.tzinfo is None
        or retain_until.astimezone(UTC)
        < datetime.fromtimestamp(payload["retrieved_at"], tz=UTC)
        + timedelta(days=35)
        or payload["readback_sha256"]
        != hashlib.sha256(attestation_raw).hexdigest()
        or payload["readback_bytes"] != len(attestation_raw)
        or readback != attestation_raw
        or not _nonempty(payload["verifier_unix_user"])
        or type(payload["verifier_uid"]) is not int
        or payload["verifier_uid"] <= 0
        or not _systemd_cgroup_matches(
            payload["verifier_cgroup"],
            payload["verifier_systemd_unit"],
        )
        or not re.fullmatch(
            r"okx-quant-canary-worm-readback@[a-z0-9_.@-]+\.service",
            str(payload["verifier_systemd_unit"]),
        )
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(payload["verifier_invocation_id"]),
        )
        or not _SHA256.fullmatch(str(payload["host_image_sha256"]))
        or not re.fullmatch(
            r"[0-9a-fA-F-]{16,64}",
            str(payload["boot_id"]),
        )
        or not re.fullmatch(
            r"mnt:\[[1-9][0-9]*\]",
            str(payload["mount_namespace_id"]),
        )
        or not _SHA256.fullmatch(
            str(payload["verifier_executable_sha256"])
        )
    ):
        raise ValueError(
            f"Canary producer {producer_name} WORM exact GET receipt 非法"
        )
    return payload


def _validate_deployment_verifier(
    payload: object,
    *,
    inventory: dict,
    expected: dict,
    target: dict,
    issued_at: int,
) -> dict:
    if not isinstance(payload, dict) or set(payload) != DEPLOYMENT_VERIFIER_KEYS:
        raise ValueError("Canary deployment verifier schema 非法")
    if (
        payload["version"] != 1
        or payload["action"] != "attest-canary-deployment-units"
        or not re.fullmatch(
            r"deployment-[0-9a-f]{32}",
            str(payload["verifier_id"]),
        )
        or not re.fullmatch(r"[0-9a-f]{32}", str(payload["nonce"]))
        or any(payload.get(key) != expected[key] for key in (
            "readiness_id",
            "release_identity_sha256",
            "config_sha256",
            "account_uid",
            "demo_soak_epoch_id",
            "target_deployment_identity_sha256",
            "transition_sha256",
            "source_producer_inventory_sha256",
        ))
        or payload["host_image_sha256"] != target["host_image_sha256"]
        or type(payload["observed_at"]) is not int
        or not issued_at - 30 <= payload["observed_at"] <= issued_at
        or not _nonempty(payload["verifier_unix_user"])
        or type(payload["verifier_uid"]) is not int
        or payload["verifier_uid"] <= 0
        or payload["verifier_systemd_unit"]
        != "okx-quant-canary-deployment-verifier.service"
        or not _systemd_cgroup_matches(
            payload["verifier_cgroup"],
            payload["verifier_systemd_unit"],
        )
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(payload["verifier_invocation_id"]),
        )
        or not re.fullmatch(
            r"[0-9a-fA-F-]{16,64}",
            str(payload["boot_id"]),
        )
        or not re.fullmatch(
            r"mnt:\[[1-9][0-9]*\]",
            str(payload["mount_namespace_id"]),
        )
        or not _nonempty(payload["systemd_version"])
        or not _SHA256.fullmatch(
            str(payload["verifier_executable_sha256"])
        )
        or not isinstance(payload["producer_units"], dict)
        or set(payload["producer_units"]) != CANARY_SOURCE_PRODUCER_NAMES
    ):
        raise ValueError("Canary deployment verifier identity/freshness 非法")
    for name, unit in payload["producer_units"].items():
        item = inventory[name]
        probe = unit.get("permission_probe") if isinstance(unit, dict) else None
        if (
            not isinstance(unit, dict)
            or set(unit) != DEPLOYMENT_UNIT_KEYS
            or unit["producer_name"] != name
            or unit["collector_systemd_unit"]
            != item["collector_systemd_unit"]
            or unit["signer_systemd_unit"] != item["signer_systemd_unit"]
            or unit["collector_user"] != item["collector_unix_user"]
            or unit["signer_user"] != item["signer_unix_user"]
            or any(
                not Path(str(unit[key])).is_absolute()
                for key in (
                    "collector_fragment_path",
                    "signer_fragment_path",
                )
            )
            or any(
                not _SHA256.fullmatch(str(unit[key]))
                for key in (
                    "collector_fragment_sha256",
                    "collector_exec_start_sha256",
                    "collector_executable_sha256",
                    "signer_fragment_sha256",
                    "signer_exec_start_sha256",
                    "signer_executable_sha256",
                    "parser_sha256",
                )
            )
            or unit["collector_executable_sha256"]
            != item["collector_executable_sha256"]
            or unit["signer_executable_sha256"]
            != item["signer_executable_sha256"]
            or unit["parser_sha256"] != item["parser_sha256"]
            or not isinstance(probe, dict)
            or set(probe) != DEPLOYMENT_PERMISSION_PROBE_KEYS
            or probe
            != {
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
        ):
            raise ValueError(
                f"Canary deployment unit/permission probe {name} 非法"
            )
    return payload


def validate_canary_control_key_separation(
    fingerprints: dict[str, str],
    *,
    producer_fingerprints: set[str],
    disallowed_key_fingerprints: set[str],
) -> None:
    required = {
        "capability",
        "iam",
        "worm_readback",
        "deployment_verifier",
    }
    if (
        set(fingerprints) != required
        or any(
            not _SHA256.fullmatch(str(value))
            for value in fingerprints.values()
        )
        or len(set(fingerprints.values())) != len(required)
        or set(fingerprints.values()) & producer_fingerprints
        or set(fingerprints.values()) & disallowed_key_fingerprints
    ):
        raise ValueError(
            "Canary capability/IAM/WORM/deployment keys 必须全部分离"
        )


def validate_canary_capability_bundle(
    payload: object,
    *,
    epoch: dict,
    transition: dict,
    capability_key_fingerprint: str,
    iam_key_fingerprint: str,
    iam_public_key_bytes: bytes,
    worm_readback_key_fingerprint: str,
    worm_readback_public_key_bytes: bytes,
    deployment_verifier_key_fingerprint: str,
    deployment_verifier_public_key_bytes: bytes,
    disallowed_key_fingerprints: set[str],
    now: int,
) -> dict:
    """Validate all 12 independently signed deployment capabilities."""
    if not isinstance(payload, dict) or set(payload) != CAPABILITY_BUNDLE_KEYS:
        raise ValueError("Canary capability bundle schema 非法")
    inventory = validate_canary_source_producer_inventory(
        payload["source_producer_inventory"]
    )
    inventory_sha256 = canary_source_producer_inventory_sha256(
        inventory
    )
    target = transition["target_deployment_identity"]
    expected = {
        "release_identity_sha256": identity_sha256(
            transition["release_identity"]
        ),
        "config_sha256": target["config_sha256"],
        "account_uid": target["account_uid"],
        "demo_soak_epoch_id": epoch["soak_epoch_id"],
        "target_deployment_identity_sha256": identity_sha256(target),
        "transition_sha256": identity_sha256(transition),
        "source_producer_inventory_sha256": inventory_sha256,
        "readiness_id": canary_readiness_id(
            demo_soak_epoch_id=epoch["soak_epoch_id"],
            target_deployment_identity_sha256=identity_sha256(target),
            source_producer_inventory_sha256=inventory_sha256,
        ),
    }
    if (
        payload["version"] != 1
        or payload["action"]
        != "attest-canary-external-producer-capabilities"
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(payload["readiness_id"]),
        )
        or payload["readiness_id"] != expected["readiness_id"]
        or not re.fullmatch(r"[0-9a-f]{32}", str(payload["nonce"]))
        or type(payload["issued_at"]) is not int
        or type(payload["expires_at"]) is not int
        or not 60
        <= payload["expires_at"] - payload["issued_at"]
        <= CANARY_CAPABILITY_MAX_LIFETIME_SECONDS
        or not payload["issued_at"] - 5 <= now < payload["expires_at"]
        or payload["release_commit"]
        != transition["release_identity"]["git_commit"]
        or payload["pre_start_challenge"]
        != transition["pre_start_challenge"]
        or any(payload.get(key) != value for key, value in expected.items())
        or inventory != epoch["canary_source_producer_inventory"]
        or inventory != transition["source_producer_inventory"]
        or inventory_sha256
        != epoch["deployment_identity"][
            "canary_source_producer_inventory_sha256"
        ]
        or capability_key_fingerprint
        != payload["capability_authority_key_fingerprint"]
        or iam_key_fingerprint
        != payload["iam_authority_key_fingerprint"]
        or worm_readback_key_fingerprint
        != payload["worm_readback_authority_key_fingerprint"]
        or deployment_verifier_key_fingerprint
        != payload["deployment_verifier_key_fingerprint"]
        or not _SHA256.fullmatch(
            str(payload["deployment_verifier_artifact_sha256"])
        )
        or not isinstance(payload["producers"], dict)
        or set(payload["producers"])
        != CANARY_SOURCE_PRODUCER_NAMES
    ):
        raise ValueError(
            "Canary capability bundle identity/freshness/isolation 非法"
        )
    producer_fingerprints = {
        item["source_key_fingerprint"]
        for item in inventory.values()
    }
    validate_canary_control_key_separation(
        {
            "capability": capability_key_fingerprint,
            "iam": iam_key_fingerprint,
            "worm_readback": worm_readback_key_fingerprint,
            "deployment_verifier": deployment_verifier_key_fingerprint,
        },
        producer_fingerprints=producer_fingerprints,
        disallowed_key_fingerprints=disallowed_key_fingerprints,
    )
    deployment_raw, deployment_artifact = _decoded_json_artifact(
        payload["deployment_verifier_artifact_bytes_base64"],
        label="Canary deployment verifier",
    )
    if hashlib.sha256(deployment_raw).hexdigest() != payload[
        "deployment_verifier_artifact_sha256"
    ]:
        raise ValueError("Canary deployment verifier artifact hash 不匹配")
    deployment_verifier = _verify_embedded_ed25519(
        deployment_artifact,
        deployment_verifier_public_key_bytes,
        label="Canary independent deployment verifier",
    )
    deployment_verifier = _validate_deployment_verifier(
        deployment_verifier,
        inventory=inventory,
        expected=expected,
        target=target,
        issued_at=payload["issued_at"],
    )
    seen_receipts: set[str] = set()
    seen_sessions: set[str] = set()
    seen_nonces: set[str] = {
        payload["nonce"],
        deployment_verifier["nonce"],
    }
    seen_invocations: set[str] = {
        deployment_verifier["verifier_invocation_id"],
    }
    for name in sorted(CANARY_SOURCE_PRODUCER_NAMES):
        entry = payload["producers"][name]
        if (
            not isinstance(entry, dict)
            or set(entry) != PRODUCER_CAPABILITY_KEYS
            or entry["source_key_fingerprint"]
            != inventory[name]["source_key_fingerprint"]
            or not _SHA256.fullmatch(
                str(entry["producer_attestation_sha256"])
            )
            or not _SHA256.fullmatch(
                str(entry["iam_sts_receipt_sha256"])
            )
            or not _SHA256.fullmatch(
                str(entry["worm_readback_receipt_sha256"])
            )
            or not _nonempty(entry["worm_version_id"])
        ):
            raise ValueError(
                f"Canary producer {name} capability entry 非法"
            )
        source_key_bytes = base64.b64decode(
            entry["source_public_key_pem_base64"],
            validate=True,
        )
        with tempfile.NamedTemporaryFile() as source_key_file:
            source_key_file.write(source_key_bytes)
            source_key_file.flush()
            source_fingerprint = ed25519_public_key_fingerprint(
                source_key_file.name
            )
        if source_fingerprint != entry["source_key_fingerprint"]:
            raise ValueError(
                f"Canary producer {name} source key bytes 不匹配"
            )
        attestation_raw, attestation_artifact = (
            _decoded_json_artifact(
                entry["producer_attestation_bytes_base64"],
                label=f"Canary producer {name} attestation",
            )
        )
        if hashlib.sha256(attestation_raw).hexdigest() != entry[
            "producer_attestation_sha256"
        ]:
            raise ValueError(
                f"Canary producer {name} attestation hash 不匹配"
            )
        worm_raw, worm_artifact = _decoded_json_artifact(
            entry["worm_readback_receipt_bytes_base64"],
            label=f"Canary producer {name} WORM receipt",
        )
        if hashlib.sha256(worm_raw).hexdigest() != entry[
            "worm_readback_receipt_sha256"
        ]:
            raise ValueError(
                f"Canary producer {name} WORM receipt hash 不匹配"
            )
        worm_receipt = _verify_embedded_ed25519(
            worm_artifact,
            worm_readback_public_key_bytes,
            label=f"Canary producer {name} WORM exact GET",
        )
        worm_receipt = _validate_worm_readback_receipt(
            worm_receipt,
            producer_name=name,
            attestation_raw=attestation_raw,
            expected=expected,
            worm_policy=inventory[name],
            expected_version_id=entry["worm_version_id"],
            issued_at=payload["issued_at"],
        )
        attestation = _verify_embedded_ed25519(
            attestation_artifact,
            source_key_bytes,
            label=f"Canary producer {name} readiness",
        )
        if (
            not isinstance(attestation, dict)
            or set(attestation) != PRODUCER_ATTESTATION_KEYS
            or attestation["version"] != 1
            or attestation["action"]
            != "attest-canary-external-producer-ready"
            or attestation["producer_name"] != name
            or type(attestation["observed_at"]) is not int
            or type(attestation["expires_at"]) is not int
            or not payload["issued_at"] - 30
            <= attestation["observed_at"]
            <= payload["issued_at"]
            or attestation["expires_at"] != payload["expires_at"]
            or any(
                attestation.get(key) != value
                for key, value in expected.items()
            )
            or not _SHA256.fullmatch(
                str(attestation["capability_probe_sha256"])
            )
        ):
            raise ValueError(
                f"Canary producer {name} signed readiness 非法"
            )
        try:
            probe = base64.b64decode(
                attestation["capability_probe_bytes_base64"],
                validate=True,
            )
        except (binascii.Error, TypeError) as exc:
            raise ValueError(
                f"Canary producer {name} capability probe 非法"
            ) from exc
        if (
            not probe
            or hashlib.sha256(probe).hexdigest()
            != attestation["capability_probe_sha256"]
        ):
            raise ValueError(
                f"Canary producer {name} capability probe hash 非法"
            )
        execution = validate_producer_execution(
            attestation["producer_execution"],
            producer_name=name,
            inventory=inventory,
            readiness_id=payload["readiness_id"],
            raw=probe,
            now=now,
        )
        collection = validate_collection_receipt(
            attestation["collection_receipt"],
            producer_name=name,
            inventory=inventory,
            raw=probe,
            target_key_fingerprint=target["key_fingerprint"],
            now=now,
        )
        validate_execution_collection_binding(execution, collection)
        if (
            execution["boot_id"] != deployment_verifier["boot_id"]
            or execution["host_image_sha256"]
            != deployment_verifier["host_image_sha256"]
            or execution["collector_executable_sha256"]
            != deployment_verifier["producer_units"][name][
                "collector_executable_sha256"
            ]
            or execution["signer_executable_sha256"]
            != deployment_verifier["producer_units"][name][
                "signer_executable_sha256"
            ]
            or execution["parser_sha256"]
            != deployment_verifier["producer_units"][name]["parser_sha256"]
        ):
            raise ValueError(
                f"Canary producer {name} 未绑定 deployment verifier"
            )
        iam_raw, iam_artifact = _decoded_json_artifact(
            entry["iam_sts_receipt_bytes_base64"],
            label=f"Canary producer {name} IAM receipt",
        )
        if (
            hashlib.sha256(iam_raw).hexdigest()
            != entry["iam_sts_receipt_sha256"]
            or execution["iam_sts_receipt_sha256"]
            != entry["iam_sts_receipt_sha256"]
        ):
            raise ValueError(
                f"Canary producer {name} IAM receipt hash 不匹配"
            )
        iam = _verify_embedded_ed25519(
            iam_artifact,
            iam_public_key_bytes,
            label=f"Canary producer {name} IAM/STS",
        )
        iam = _validate_iam_sts_receipt(
            iam,
            producer_name=name,
            inventory=inventory,
            execution=execution,
            expected=expected,
            now=now,
        )
        if (
            iam["receipt_id"] in seen_receipts
            or iam["sts_session_id"] in seen_sessions
            or iam["nonce"] in seen_nonces
            or worm_receipt["nonce"] in seen_nonces
            or worm_receipt["receipt_id"] in seen_receipts
            or worm_receipt["verifier_invocation_id"]
            in seen_invocations
            or execution["nonce"] in seen_nonces
            or execution["collector_invocation_id"]
            in seen_invocations
            or execution["signer_invocation_id"] in seen_invocations
        ):
            raise ValueError(
                "Canary producer capability nonce/session/invocation 重用"
            )
        seen_receipts.update(
            {iam["receipt_id"], worm_receipt["receipt_id"]}
        )
        seen_sessions.add(iam["sts_session_id"])
        seen_nonces.update(
            {
                iam["nonce"],
                worm_receipt["nonce"],
                execution["nonce"],
            }
        )
        seen_invocations.update(
            {
                execution["collector_invocation_id"],
                execution["signer_invocation_id"],
                worm_receipt["verifier_invocation_id"],
            }
        )
        expected_pre_hash = (
            transition["pre_start_checks"][name]["evidence_sha256"]
            if name in REQUIRED_PRE_START_CHECKS
            else ""
        )
        if (
            entry["pre_start_source_artifact_sha256"]
            != expected_pre_hash
            or attestation["pre_start_source_artifact_sha256"]
            != expected_pre_hash
        ):
            raise ValueError(
                f"Canary producer {name} 未绑定实际 pre-start artifact"
            )
    return payload


def _reserve_canary_capability(
    state_path: Path,
    *,
    readiness_id: str,
    bundle_sha256: str,
    transition_sha256: str,
    expires_at: int,
) -> None:
    with _canary_capability_state_transaction(state_path):
        state = {"version": 2, "reservations": {}}
        if state_path.exists():
            raw = _secure_capability_file(
                state_path,
                label="Canary capability replay state",
            )
            state = json.loads(raw)
            if (
                not isinstance(state, dict)
                or set(state) != {"version", "reservations"}
                or state["version"] != 2
                or not isinstance(state["reservations"], dict)
            ):
                raise ValueError("Canary capability replay state 非法")
        reservation = {
            "readiness_id": readiness_id,
            "bundle_sha256": bundle_sha256,
            "transition_sha256": transition_sha256,
            "expires_at": expires_at,
            "status": "reserved",
            "approval_sha256": "",
            "consumed_at": 0,
        }
        if (
            bundle_sha256 in state["reservations"]
            or any(
                row.get("readiness_id") == readiness_id
                or row.get("transition_sha256") == transition_sha256
                for row in state["reservations"].values()
                if isinstance(row, dict)
            )
        ):
            raise ValueError("Canary capability 已被 reservation/replay")
        state["reservations"][bundle_sha256] = reservation
        _write_canary_capability_state(state_path, state)


def consume_canary_capability_reservation(
    state_path: Path,
    *,
    bundle_sha256: str,
    approval_sha256: str,
    consumed_at: int,
) -> None:
    if (
        not _SHA256.fullmatch(bundle_sha256)
        or not _SHA256.fullmatch(approval_sha256)
        or type(consumed_at) is not int
    ):
        raise ValueError("Canary consumption binding 非法")
    with _canary_capability_state_transaction(state_path):
        state = json.loads(
            _secure_capability_file(
                state_path,
                label="Canary capability replay state",
            )
        )
        reservation = (
            state.get("reservations", {}).get(bundle_sha256)
            if isinstance(state, dict)
            else None
        )
        if (
            not isinstance(state, dict)
            or set(state) != {"version", "reservations"}
            or state["version"] != 2
            or not isinstance(reservation, dict)
            or reservation.get("status") != "reserved"
            or consumed_at >= reservation.get("expires_at", 0)
        ):
            raise ValueError(
                "Canary capability 未预留、已消费或已过期"
            )
        reservation["status"] = "consumed"
        reservation["approval_sha256"] = approval_sha256
        reservation["consumed_at"] = consumed_at
        _write_canary_capability_state(state_path, state)


def _assert_canary_capability_reserved(
    state_path: Path,
    *,
    readiness_id: str,
    bundle_sha256: str,
    transition_sha256: str,
    expires_at: int,
) -> None:
    with _canary_capability_state_transaction(state_path):
        state = json.loads(
            _secure_capability_file(
                state_path,
                label="Canary capability replay state",
            )
        )
        reservation = (
            state.get("reservations", {}).get(bundle_sha256)
            if isinstance(state, dict)
            else None
        )
        if (
            not isinstance(state, dict)
            or set(state) != {"version", "reservations"}
            or state["version"] != 2
            or reservation
            != {
                "readiness_id": readiness_id,
                "bundle_sha256": bundle_sha256,
                "transition_sha256": transition_sha256,
                "expires_at": expires_at,
                "status": "reserved",
                "approval_sha256": "",
                "consumed_at": 0,
            }
        ):
            raise ValueError(
                "Canary capability 缺少 exact reserved state"
            )


@contextmanager
def _canary_capability_state_transaction(state_path: Path):
    state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = state_path.with_name(f"{state_path.name}.lock")
    if state_path.is_relative_to("/var/lib/okx-quant/admission"):
        parent = state_path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0
            or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError(
                "Canary capability replay 父目录必须 root-owned 且不可组/其他写"
            )
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT
        | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0),
        0o600,
    )
    locked = False
    try:
        info = os.fstat(descriptor)
        production_path = lock_path.is_relative_to(
            "/var/lib/okx-quant/admission"
        )
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or (production_path and info.st_uid != 0)
        ):
            raise ValueError(
                "Canary capability replay lock 必须为 root-owned 0600 普通文件"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        current = lock_path.lstat()
        if (
            current.st_dev != info.st_dev
            or current.st_ino != info.st_ino
        ):
            raise ValueError("Canary capability replay lock 被替换")
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _write_canary_capability_state(
    state_path: Path,
    state: dict,
) -> None:
    temporary = state_path.with_name(
        f".{state_path.name}.{uuid.uuid4().hex}.tmp"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0),
        0o600,
    )
    try:
        payload = (
            json.dumps(
                state,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Canary replay state write 无进展")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state_path)
    directory = os.open(state_path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def require_external_canary_producers_ready(
    *,
    epoch: dict,
    transition: dict,
    capability_bundle_path: Path,
    capability_public_key: Path,
    iam_public_key: Path,
    worm_readback_public_key: Path,
    deployment_verifier_public_key: Path,
    disallowed_key_fingerprints: set[str],
    replay_state_path: Path,
    now: int,
    reservation_mode: str = "reserve",
) -> tuple[dict, str]:
    """Verify and consume a signed, exact-target 12-producer bundle."""
    raw = _secure_capability_file(
        capability_bundle_path,
        label="Canary capability bundle",
    )
    capability_key_bytes = _secure_capability_file(
        capability_public_key,
        label="Canary capability public key",
    )
    iam_key_bytes = _secure_capability_file(
        iam_public_key,
        label="Canary IAM public key",
    )
    worm_key_bytes = _secure_capability_file(
        worm_readback_public_key,
        label="Canary WORM readback public key",
    )
    deployment_key_bytes = _secure_capability_file(
        deployment_verifier_public_key,
        label="Canary deployment verifier public key",
    )
    artifact = json.loads(raw)
    claims = _verify_embedded_ed25519(
        artifact,
        capability_key_bytes,
        label="Canary external producer capability bundle",
    )
    with tempfile.NamedTemporaryFile() as capability_key_file:
        capability_key_file.write(capability_key_bytes)
        capability_key_file.flush()
        capability_fingerprint = ed25519_public_key_fingerprint(
            capability_key_file.name
        )
    with tempfile.NamedTemporaryFile() as iam_key_file:
        iam_key_file.write(iam_key_bytes)
        iam_key_file.flush()
        iam_fingerprint = ed25519_public_key_fingerprint(
            iam_key_file.name
        )
    with tempfile.NamedTemporaryFile() as worm_key_file:
        worm_key_file.write(worm_key_bytes)
        worm_key_file.flush()
        worm_fingerprint = ed25519_public_key_fingerprint(
            worm_key_file.name
        )
    with tempfile.NamedTemporaryFile() as deployment_key_file:
        deployment_key_file.write(deployment_key_bytes)
        deployment_key_file.flush()
        deployment_fingerprint = ed25519_public_key_fingerprint(
            deployment_key_file.name
        )
    claims = validate_canary_capability_bundle(
        claims,
        epoch=epoch,
        transition=transition,
        capability_key_fingerprint=capability_fingerprint,
        iam_key_fingerprint=iam_fingerprint,
        iam_public_key_bytes=iam_key_bytes,
        worm_readback_key_fingerprint=worm_fingerprint,
        worm_readback_public_key_bytes=worm_key_bytes,
        deployment_verifier_key_fingerprint=(
            deployment_fingerprint
        ),
        deployment_verifier_public_key_bytes=deployment_key_bytes,
        disallowed_key_fingerprints=disallowed_key_fingerprints,
        now=now,
    )
    digest = hashlib.sha256(raw).hexdigest()
    reservation_arguments = {
        "readiness_id": claims["readiness_id"],
        "bundle_sha256": digest,
        "transition_sha256": claims["transition_sha256"],
        "expires_at": claims["expires_at"],
    }
    if reservation_mode == "reserve":
        _reserve_canary_capability(
            replay_state_path,
            **reservation_arguments,
        )
    elif reservation_mode == "assert-reserved":
        _assert_canary_capability_reserved(
            replay_state_path,
            **reservation_arguments,
        )
    else:
        raise ValueError("未知 Canary capability reservation mode")
    return claims, digest


def build_source_evidence(kind: str, raw: bytes) -> dict:
    """Build the strict embedded raw-source envelope used by producers."""
    if not _nonempty(kind) or not isinstance(raw, bytes) or not raw:
        raise ValueError("Canary source evidence kind/bytes 非法")
    return {
        "kind": kind,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "payload_base64": base64.b64encode(raw).decode("ascii"),
    }


def _source_evidence_bytes(
    evidence: object,
    *,
    expected_kind: str,
) -> bytes:
    if (
        not isinstance(evidence, dict)
        or set(evidence) != SOURCE_EVIDENCE_KEYS
        or evidence.get("kind") != expected_kind
        or type(evidence.get("bytes")) is not int
        or evidence["bytes"] <= 0
        or not _SHA256.fullmatch(str(evidence.get("sha256", "")))
    ):
        raise ValueError("Canary source raw evidence schema/kind 非法")
    try:
        raw = base64.b64decode(evidence["payload_base64"], validate=True)
    except (binascii.Error, TypeError) as exc:
        raise ValueError("Canary source raw evidence base64 非法") from exc
    if len(raw) != evidence["bytes"] or hashlib.sha256(raw).hexdigest() != evidence["sha256"]:
        raise ValueError("Canary source raw evidence hash/bytes 不一致")
    return raw


def _json_object(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} 不是严格 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是 JSON 对象")
    return value


def _okx_data_item(
    raw: bytes,
    label: str,
    *,
    expected_target_key_fingerprint: str | None = None,
) -> dict:
    response = _json_object(raw, label)
    data = response.get("data")
    if (
        set(response) - {"code", "msg", "data", "inTime", "outTime"}
        or str(response.get("code")) != "0"
        or not isinstance(data, list)
        or len(data) != 1
        or not isinstance(data[0], dict)
        or (
            expected_target_key_fingerprint is not None
            and (
                not isinstance(data[0].get("apiKey"), str)
                or credential_fingerprint(data[0]["apiKey"])
                != expected_target_key_fingerprint
                or not {"apiKey", "perm", "ip"}.issubset(data[0])
                or set(data[0])
                - {
                    "apiKey",
                    "perm",
                    "ip",
                    "label",
                    "subAcct",
                    "ts",
                }
            )
        )
    ):
        raise ValueError(f"{label} OKX response schema/code 非法")
    return data[0]


def canary_limits_from_settings(settings: ProductionSettings | object) -> dict:
    return {
        "max_order_notional_usdt": float(settings.max_position_notional_usdt),
        "max_order_intents_per_hour": settings.max_order_intents_per_hour,
        "max_concurrent_positions": settings.max_open_positions,
        "max_total_exposure_usdt": float(settings.max_total_exposure_usdt),
        "max_order_loss_usdt": float(settings.max_order_loss_usdt),
        "max_daily_loss_usdt": float(settings.max_daily_loss_usdt),
        "max_drawdown_ratio": float(settings.max_drawdown_ratio),
        "max_slippage_ratio": float(settings.max_slippage_ratio),
    }


_PRE_START_EVIDENCE_KINDS = {
    "account_uid_verified": "okx-account-config-response/v1",
    "api_key_read_trade_only": "okx-api-key-metadata-response/v1",
    "api_key_withdraw_disabled": "okx-api-key-metadata-response/v1",
    "ip_allowlist_verified": "okx-api-key-metadata-response/v1",
    "journal_identity_verified": "sqlite-journal-snapshot/v1",
    "limits_match_policy": "target-config-bytes/v1",
    "release_identity_verified": "release-filesystem-observation/v1",
}


def derive_pre_start_facts(
    check: str,
    evidence: object,
    *,
    target: dict,
    release_identity: dict,
) -> dict:
    """Recompute a pre-start conclusion from immutable raw bytes."""
    try:
        kind = _PRE_START_EVIDENCE_KINDS[check]
    except KeyError as exc:
        raise ValueError(f"未知 Canary pre-start check: {check}") from exc
    raw = _source_evidence_bytes(evidence, expected_kind=kind)
    if check == "account_uid_verified":
        item = _okx_data_item(
            raw,
            kind,
        )
        return {
            "actual_account_uid": str(item.get("uid", "")).strip(),
            "checked_via": "okx_authenticated_account_endpoint",
        }
    if check in {
        "api_key_read_trade_only",
        "api_key_withdraw_disabled",
        "ip_allowlist_verified",
    }:
        item = _okx_data_item(
            raw,
            kind,
            expected_target_key_fingerprint=target[
                "key_fingerprint"
            ],
        )
        permissions_value = item.get("perm")
        if isinstance(permissions_value, str):
            permissions = sorted(
                {value.strip().lower() for value in permissions_value.split(",") if value.strip()}
            )
        elif isinstance(permissions_value, list):
            permissions = sorted(
                {str(value).strip().lower() for value in permissions_value if str(value).strip()}
            )
        else:
            permissions = []
        if check == "api_key_read_trade_only":
            return {
                "actual_permissions": permissions,
                "checked_via": "okx_api_key_metadata",
            }
        if check == "api_key_withdraw_disabled":
            return {
                "withdraw_enabled": "withdraw" in permissions,
                "checked_via": "okx_api_key_metadata",
            }
        return {
            "actual_ip_allowlist_sha256": okx_ip_allowlist_sha256(
                item.get("ip")
            ),
            "checked_via": "okx_api_key_metadata",
        }
    if check == "journal_identity_verified":
        with tempfile.NamedTemporaryFile() as snapshot:
            snapshot.write(raw)
            snapshot.flush()
            try:
                connection = sqlite3.connect(
                    f"file:{snapshot.name}?mode=ro&immutable=1",
                    uri=True,
                )
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                identity = connection.execute(
                    """
                    SELECT account_id, initial_config_hash
                    FROM journal_identity WHERE singleton=1
                    """
                ).fetchone()
            except sqlite3.Error as exc:
                raise ValueError("Canary journal snapshot 无法独立验证") from exc
            finally:
                if "connection" in locals():
                    connection.close()
        return {
            "account_uid": identity[0] if identity is not None else "",
            "initial_config_sha256": (identity[1] if identity is not None else ""),
            "initialized": identity is not None,
            "integrity_check": (str(integrity[0]) if integrity is not None else ""),
        }
    if check == "limits_match_policy":
        with tempfile.NamedTemporaryFile(suffix=".yaml") as config_file:
            config_file.write(raw)
            config_file.flush()
            config = load_yaml(config_file.name)
        settings = ProductionSettings.from_config(
            config,
            require_credentials=False,
            require_external_controls=False,
        )
        if production_config_hash(settings, config) != target["config_sha256"]:
            raise ValueError("pre-start target config bytes 与 deployment hash 不一致")
        return {
            **canary_limits_from_settings(settings),
            "checked_via": "loaded_target_config",
        }
    observation = _json_object(raw, kind)
    if set(observation) != {
        "release_identity",
        "release_commit",
        "deployed_source_sha256",
    }:
        raise ValueError("release filesystem observation schema 非法")
    return {
        "release_identity_sha256": identity_sha256(observation["release_identity"]),
        "release_commit": observation["release_commit"],
        "deployed_source_sha256": observation["deployed_source_sha256"],
        "checked_via": "filesystem_exact_bytes",
    }


def pre_start_evidence_observed_at(
    check: str,
    evidence: object,
    *,
    fallback: int,
    target_key_fingerprint: str | None = None,
    collection_receipt: dict | None = None,
) -> int:
    if check not in {
        "account_uid_verified",
        "api_key_read_trade_only",
        "api_key_withdraw_disabled",
        "ip_allowlist_verified",
    }:
        return fallback
    raw = _source_evidence_bytes(
        evidence,
        expected_kind=_PRE_START_EVIDENCE_KINDS[check],
    )
    _okx_data_item(
        raw,
        _PRE_START_EVIDENCE_KINDS[check],
        expected_target_key_fingerprint=(
            target_key_fingerprint
            if check != "account_uid_verified"
            else None
        ),
    )
    if (
        not isinstance(collection_receipt, dict)
        or type(collection_receipt.get("received_at")) is not int
    ):
        raise ValueError("OKX native response 缺少 transport received_at")
    return collection_receipt["received_at"]


def _validate_pre_start_source_facts(
    check: str,
    facts: object,
    *,
    source_evidence: object,
    observed_at: int,
    target: dict,
    release_identity: dict,
    collection_receipt: dict,
    expected_limits: dict | None = None,
) -> None:
    if not isinstance(facts, dict):
        raise ValueError("Canary pre-start source facts 必须是对象")
    if (
        pre_start_evidence_observed_at(
            check,
            source_evidence,
            fallback=observed_at,
            target_key_fingerprint=target["key_fingerprint"],
            collection_receipt=collection_receipt,
        )
        != observed_at
    ):
        raise ValueError("Canary pre-start observed_at 未绑定 raw response received_at")
    derived = derive_pre_start_facts(
        check,
        source_evidence,
        target=target,
        release_identity=release_identity,
    )
    if facts != derived:
        raise ValueError("Canary pre-start facts 与固定 raw evidence 重算结果不一致")
    if check == "account_uid_verified":
        if facts != {
            "actual_account_uid": target["account_uid"],
            "checked_via": "okx_authenticated_account_endpoint",
        }:
            raise ValueError("pre-start source 未证明真实 OKX account UID")
        return
    if check == "api_key_read_trade_only":
        if facts != {
            "actual_permissions": ["read", "trade"],
            "checked_via": "okx_api_key_metadata",
        }:
            raise ValueError("pre-start source 未证明 API key 仅有 read/trade 权限")
        return
    if check == "api_key_withdraw_disabled":
        if facts != {
            "withdraw_enabled": False,
            "checked_via": "okx_api_key_metadata",
        }:
            raise ValueError("pre-start source 未证明 API key withdraw 已关闭")
        return
    if check == "ip_allowlist_verified":
        if facts != {
            "actual_ip_allowlist_sha256": target["ip_allowlist_sha256"],
            "checked_via": "okx_api_key_metadata",
        }:
            raise ValueError("pre-start source 未证明真实 IP allowlist")
        return
    if check == "journal_identity_verified":
        if facts != {
            "account_uid": target["account_uid"],
            "initial_config_sha256": target["config_sha256"],
            "initialized": True,
            "integrity_check": "ok",
        }:
            raise ValueError("pre-start source 未证明 journal identity/integrity")
        return
    if check == "release_identity_verified":
        if facts != {
            "release_identity_sha256": identity_sha256(release_identity),
            "release_commit": target["release_commit"],
            "deployed_source_sha256": target["deployed_source_sha256"],
            "checked_via": "filesystem_exact_bytes",
        }:
            raise ValueError("pre-start source 未证明 exact release identity")
        return
    if check == "limits_match_policy":
        expected_fields = {
            "max_order_notional_usdt": (5, 25),
            "max_order_intents_per_hour": (1, 6),
            "max_concurrent_positions": (1, 1),
            "max_total_exposure_usdt": (5, 100),
            "max_order_loss_usdt": (0.01, 5),
            "max_daily_loss_usdt": (0.01, 10),
            "max_drawdown_ratio": (0.0001, 0.02),
            "max_slippage_ratio": (0.0001, 0.01),
        }
        if (
            set(facts) != {*expected_fields, "checked_via"}
            or facts.get("checked_via") != "loaded_target_config"
        ):
            raise ValueError("pre-start source limits facts schema 非法")
        for name, (minimum, maximum) in expected_fields.items():
            value = facts[name]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not minimum <= float(value) <= maximum
            ):
                raise ValueError(f"pre-start source {name} 超出 Canary 硬上限")
        if (
            expected_limits is not None
            and {name: facts[name] for name in CANARY_LIMIT_FIELDS} != expected_limits
        ):
            raise ValueError("pre-start source limits 未精确匹配冻结 target policy/config")
        return
    raise ValueError(f"未知 Canary pre-start check: {check}")


def validate_pre_start_source_claims(
    source: object,
    *,
    check: str,
    target: dict,
    release_identity: dict,
    demo_soak_epoch_id: str,
    producer_inventory: dict,
    pre_start_challenge: str,
    now: int,
    expected_limits: dict | None = None,
) -> dict:
    """Validate one independently signed pre-start observation."""
    if (
        not isinstance(source, dict)
        or set(source) != PRE_START_SOURCE_KEYS
        or source["version"] != 1
        or source["action"] != "attest-canary-pre-start-source"
        or source["check"] != check
        or source["pre_start_challenge"] != pre_start_challenge
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(pre_start_challenge),
        )
        or type(source["observed_at"]) is not int
        or not now - 900 <= source["observed_at"] <= now + 5
    ):
        raise ValueError("Canary pre-start source schema/时效非法")
    expected = {
        "account_uid": target["account_uid"],
        "deployment_unit": target["unit"],
        "demo_soak_epoch_id": demo_soak_epoch_id,
        "release_identity_sha256": identity_sha256(release_identity),
        "release_commit": target["release_commit"],
        "deployed_source_sha256": target["deployed_source_sha256"],
        "config_sha256": target["config_sha256"],
        "target_deployment_identity_sha256": identity_sha256(target),
    }
    if any(source.get(key) != value for key, value in expected.items()):
        raise ValueError("Canary pre-start source 未绑定 target/release/config/account/unit/epoch")
    _validate_pre_start_source_facts(
        check,
        source["facts"],
        source_evidence=source["source_evidence"],
        observed_at=source["observed_at"],
        target=target,
        release_identity=release_identity,
        collection_receipt=source["collection_receipt"],
        expected_limits=expected_limits,
    )
    readiness_id = canary_readiness_id(
        demo_soak_epoch_id=demo_soak_epoch_id,
        target_deployment_identity_sha256=identity_sha256(target),
        source_producer_inventory_sha256=(
            canary_source_producer_inventory_sha256(
                producer_inventory
            )
        ),
    )
    validate_producer_execution(
        source["producer_execution"],
        producer_name=check,
        inventory=producer_inventory,
        readiness_id=readiness_id,
        raw=_source_evidence_bytes(
            source["source_evidence"],
            expected_kind=_PRE_START_EVIDENCE_KINDS[check],
        ),
        now=now,
    )
    collection = validate_collection_receipt(
        source["collection_receipt"],
        producer_name=check,
        inventory=producer_inventory,
        raw=_source_evidence_bytes(
            source["source_evidence"],
            expected_kind=_PRE_START_EVIDENCE_KINDS[check],
        ),
        target_key_fingerprint=target["key_fingerprint"],
        now=now,
    )
    validate_execution_collection_binding(
        source["producer_execution"],
        collection,
    )
    return source


def verify_embedded_pre_start_checks(payload: dict) -> None:
    """Reverify every signed source artifact embedded in a transition."""
    checks = payload["pre_start_checks"]
    fingerprints = payload["pre_start_source_key_fingerprints"]
    if (
        not isinstance(checks, dict)
        or set(checks) != set(REQUIRED_PRE_START_CHECKS)
        or not isinstance(fingerprints, dict)
        or set(fingerprints) != set(REQUIRED_PRE_START_CHECKS)
        or len(set(fingerprints.values())) != len(REQUIRED_PRE_START_CHECKS)
    ):
        raise ValueError("Canary pre-start evidence 集合/身份非法")
    for name in REQUIRED_PRE_START_CHECKS:
        locator = checks[name]
        if not isinstance(locator, dict) or set(locator) != _PRE_START_LOCATOR_KEYS:
            raise ValueError(f"Canary pre-start check {name} locator 非法")
        try:
            raw = base64.b64decode(
                locator["artifact_bytes_base64"],
                validate=True,
            )
            public_key = base64.b64decode(
                locator["source_public_key_pem_base64"],
                validate=True,
            )
            artifact = json.loads(raw)
        except (
            binascii.Error,
            TypeError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError(f"Canary pre-start check {name} bytes 非法") from exc
        if (
            type(locator["observed_at"]) is not int
            or type(locator["evidence_bytes"]) is not int
            or locator["evidence_bytes"] <= 0
            or not _SHA256.fullmatch(str(locator["evidence_sha256"]))
            or len(raw) != locator["evidence_bytes"]
            or hashlib.sha256(raw).hexdigest() != locator["evidence_sha256"]
            or not _SHA256.fullmatch(str(fingerprints[name]))
        ):
            raise ValueError(f"Canary pre-start check {name} hash/time 非法")
        with tempfile.NamedTemporaryFile() as public_key_file:
            public_key_file.write(public_key)
            public_key_file.flush()
            if ed25519_public_key_fingerprint(public_key_file.name) != fingerprints[name]:
                raise ValueError(f"Canary pre-start check {name} source key 指纹不匹配")
            source = verify_ed25519_artifact(
                artifact,
                public_key_file.name,
                label=f"Canary pre-start source {name}",
            )
        validate_pre_start_source_claims(
            source,
            check=name,
            target=payload["target_deployment_identity"],
            release_identity=payload["release_identity"],
            demo_soak_epoch_id=payload["demo_soak_epoch_id"],
            producer_inventory=payload["source_producer_inventory"],
            pre_start_challenge=payload["pre_start_challenge"],
            now=payload["issued_at"],
            expected_limits=payload["canary_limits"],
        )
        if source["observed_at"] != locator["observed_at"]:
            raise ValueError(f"Canary pre-start check {name} observed_at 不匹配")


_POST_START_EVIDENCE_KINDS = {
    "runtime_safety_kernel_live_within_60s": "runtime-status-response/v1",
    "alert_challenge_received": "alert-provider-receipt/v1",
    "backup_exact_version_restored": "s3-exact-version-get-restore/v1",
    "protected_position_or_flat": "okx-position-protection-snapshot/v1",
    "rest_ws_reconciliation_safe": "reconciliation-journal-row/v1",
}


def derive_post_start_facts(check: str, evidence: object) -> dict:
    """Recompute post-start facts from a fixed producer response."""
    try:
        kind = _POST_START_EVIDENCE_KINDS[check]
    except KeyError as exc:
        raise ValueError(f"未知 Canary post-start check: {check}") from exc
    raw = _source_evidence_bytes(evidence, expected_kind=kind)
    value = _json_object(raw, kind)
    if check != "runtime_safety_kernel_live_within_60s":
        if (
            set(value)
            != {
                "runtime_binding",
                "native_payload_base64",
                "native_sha256",
                "native_bytes",
            }
            or not isinstance(value["runtime_binding"], dict)
            or set(value["runtime_binding"])
            != {
                "runtime_instance_id",
                "boot_id",
                "deployment_unit",
                "startup_nonce",
                "startup_hard_epoch",
            }
            or type(value["native_bytes"]) is not int
            or value["native_bytes"] <= 0
            or not _SHA256.fullmatch(
                str(value["native_sha256"])
            )
        ):
            raise ValueError(
                f"{check} raw evidence 未内嵌完整 startup binding"
            )
        try:
            native_raw = base64.b64decode(
                value["native_payload_base64"],
                validate=True,
            )
        except (binascii.Error, TypeError) as exc:
            raise ValueError(f"{check} native payload base64 非法") from exc
        if (
            len(native_raw) != value["native_bytes"]
            or hashlib.sha256(native_raw).hexdigest()
            != value["native_sha256"]
        ):
            raise ValueError(f"{check} native payload hash/bytes 非法")
        value = _json_object(native_raw, kind)
    if check == "runtime_safety_kernel_live_within_60s":
        request_keys = {
            "unit",
            "runtime_instance_id",
            "boot_id",
            "startup_nonce",
            "startup_hard_epoch",
            "requested_at",
        }
        systemd_keys = {
            "ActiveState",
            "SubState",
            "MainPID",
            "InvocationID",
            "ControlGroup",
            "ExecMainStartTimestampMonotonic",
        }
        health_keys = {
            "live",
            "runtime_started_at",
            "runtime_instance_id",
            "boot_id",
            "startup_nonce",
            "startup_hard_epoch",
        }
        if (
            set(value) != {"request", "response"}
            or not isinstance(value["request"], dict)
            or set(value["request"]) != request_keys
            or not _nonempty(value["request"]["unit"])
            or type(value["request"]["requested_at"]) is not int
            or not isinstance(value["response"], dict)
            or set(value["response"])
            != {"observed_at", "systemd_show", "health_body"}
            or type(value["response"]["observed_at"]) is not int
            or not value["request"]["requested_at"]
            <= value["response"]["observed_at"]
            <= value["request"]["requested_at"] + 30
            or not isinstance(
                value["response"]["systemd_show"],
                dict,
            )
            or set(value["response"]["systemd_show"]) != systemd_keys
            or not isinstance(
                value["response"]["health_body"],
                dict,
            )
            or set(value["response"]["health_body"]) != health_keys
        ):
            raise ValueError("runtime status raw evidence schema 非法")
        systemd_show = value["response"]["systemd_show"]
        health = value["response"]["health_body"]
        if (
            systemd_show["ActiveState"] != "active"
            or systemd_show["SubState"] != "running"
            or type(systemd_show["MainPID"]) is not int
            or systemd_show["MainPID"] <= 0
            or not re.fullmatch(
                r"[0-9a-f]{32}",
                str(systemd_show["InvocationID"]),
            )
            or not _systemd_cgroup_matches(
                systemd_show["ControlGroup"],
                value["request"]["unit"],
            )
            or type(
                systemd_show["ExecMainStartTimestampMonotonic"]
            )
            is not int
            or systemd_show["ExecMainStartTimestampMonotonic"] <= 0
            or any(
                health[key] != value["request"][key]
                for key in (
                    "runtime_instance_id",
                    "boot_id",
                    "startup_nonce",
                    "startup_hard_epoch",
                )
            )
        ):
            raise ValueError("runtime systemd/health native identity 非法")
        return {
            "live": health["live"],
            "runtime_started_at": health["runtime_started_at"],
        }
    if check == "alert_challenge_received":
        if (
            set(value) != {"challenge", "provider_receipt"}
            or not isinstance(value["challenge"], dict)
            or set(value["challenge"])
            != {
                "challenge_id",
                "severity",
                "triggered_at",
                "runtime_instance_id",
                "startup_nonce",
            }
            or not isinstance(value["provider_receipt"], dict)
            or set(value["provider_receipt"])
            != {
                "receipt_id",
                "challenge_id",
                "severity",
                "provider_received_at",
                "provider",
                "status",
            }
            or not _nonempty(value["provider_receipt"]["receipt_id"])
            or value["provider_receipt"]["challenge_id"]
            != value["challenge"]["challenge_id"]
            or value["provider_receipt"]["severity"]
            != value["challenge"]["severity"]
            or value["provider_receipt"]["status"] != "delivered"
        ):
            raise ValueError("alert provider raw receipt schema 非法")
        return {
            "challenge_id": value["challenge"]["challenge_id"],
            "severity": value["challenge"]["severity"],
            "triggered_at": value["challenge"]["triggered_at"],
            "provider_received_at": value["provider_receipt"][
                "provider_received_at"
            ],
            "provider": value["provider_receipt"]["provider"],
        }
    if check == "protected_position_or_flat":
        response_keys = {"code", "msg", "data"}
        if (
            set(value)
            != {
                "account_config_response",
                "positions_response",
                "algo_orders_response",
                "business_ws_subscription",
                "business_ws_events",
            }
            or any(
                not isinstance(value[key], dict)
                or set(value[key]) != response_keys
                or str(value[key]["code"]) != "0"
                or not isinstance(value[key]["data"], list)
                for key in (
                    "account_config_response",
                    "positions_response",
                    "algo_orders_response",
                )
            )
            or len(value["account_config_response"]["data"]) != 1
            or not isinstance(value["business_ws_subscription"], dict)
            or set(value["business_ws_subscription"])
            != {"subscribed_at", "channels", "confirmed"}
            or type(
                value["business_ws_subscription"]["subscribed_at"]
            )
            is not int
            or value["business_ws_subscription"]["channels"]
            != ["orders-algo", "positions"]
            or value["business_ws_subscription"]["confirmed"] is not True
            or not isinstance(value["business_ws_events"], list)
        ):
            raise ValueError("OKX position/protection native responses 非法")
        account = value["account_config_response"]["data"][0]
        positions: dict[tuple[str, str], tuple[Decimal, str]] = {}
        for row in value["positions_response"]["data"]:
            if (
                not isinstance(row, dict)
                or not _nonempty(row.get("instId"))
                or not _nonempty(row.get("posId"))
                or not _nonempty(row.get("pos"))
                or row.get("posSide") not in {"long", "short", "net"}
            ):
                raise ValueError("OKX native position row 非法")
            try:
                position = Decimal(str(row["pos"]))
            except (InvalidOperation, ValueError) as exc:
                raise ValueError("OKX native position 数值非法") from exc
            if position == 0:
                continue
            side = (
                "long"
                if row["posSide"] == "long"
                or (row["posSide"] == "net" and position > 0)
                else "short"
            )
            key = (str(row["instId"]), str(row["posId"]))
            if key in positions:
                raise ValueError("OKX native position posId 重复")
            positions[key] = (abs(position), side)
        coverage = {key: Decimal("0") for key in positions}
        active_algos: dict[str, dict] = {}
        for row in value["algo_orders_response"]["data"]:
            if (
                not isinstance(row, dict)
                or not _nonempty(row.get("instId"))
                or not _nonempty(row.get("posId"))
                or not _nonempty(row.get("algoId"))
                or row.get("state")
                not in {"live", "effective", "partially_effective"}
                or row.get("ordType")
                not in {
                    "conditional",
                    "oco",
                    "trigger",
                    "move_order_stop",
                }
            ):
                continue
            key = (str(row["instId"]), str(row["posId"]))
            if key not in positions:
                continue
            try:
                size = Decimal(str(row.get("sz", "")))
                filled = Decimal(str(row.get("accFillSz", "0")))
                close_fraction = Decimal(
                    str(row.get("closeFraction", "0"))
                )
                trigger = Decimal(str(row.get("triggerPx", "")))
            except (InvalidOperation, ValueError) as exc:
                raise ValueError("OKX protection algo 数值非法") from exc
            position_size, position_side = positions[key]
            expected_side = "sell" if position_side == "long" else "buy"
            reduce_only = row.get("reduceOnly") in {True, "true", "1"}
            if (
                row.get("side") != expected_side
                or not reduce_only
                or size <= 0
                or filled < 0
                or filled > size
                or not Decimal("0") < close_fraction <= Decimal("1")
                or trigger <= 0
            ):
                continue
            effective = min(
                size - filled,
                position_size * close_fraction,
            )
            active_algos[str(row["algoId"])] = {
                "key": key,
                "state": str(row["state"]),
                "ord_type": str(row["ordType"]),
                "side": str(row["side"]),
                "reduce_only": reduce_only,
                "size": size,
                "filled": filled,
                "close_fraction": close_fraction,
                "trigger": trigger,
                "effective": max(effective, Decimal("0")),
            }
        ws_positions: dict[
            tuple[str, str],
            tuple[Decimal, str],
        ] = {}
        ws_algos: dict[str, dict] = {}
        previous_sequence: int | None = None
        subscribed_at = value["business_ws_subscription"][
            "subscribed_at"
        ]
        for event in value["business_ws_events"]:
            if (
                not isinstance(event, dict)
                or set(event)
                != {"arg", "data", "seqId", "received_at"}
                or not isinstance(event.get("arg"), dict)
                or event["arg"].get("channel")
                not in {"positions", "orders-algo"}
                or not isinstance(event.get("data"), list)
                or type(event["seqId"]) is not int
                or type(event["received_at"]) is not int
                or event["received_at"] < subscribed_at
                or (
                    previous_sequence is not None
                    and event["seqId"] <= previous_sequence
                )
            ):
                raise ValueError("OKX business WS native event 非法")
            previous_sequence = event["seqId"]
            for row in event["data"]:
                if not isinstance(row, dict):
                    raise ValueError("OKX business WS row 非法")
                if event["arg"]["channel"] == "positions":
                    if (
                        not _nonempty(row.get("instId"))
                        or not _nonempty(row.get("posId"))
                        or not _nonempty(row.get("pos"))
                        or row.get("posSide")
                        not in {"long", "short", "net"}
                    ):
                        raise ValueError("OKX WS position identity 非法")
                    try:
                        ws_position = Decimal(str(row["pos"]))
                    except (InvalidOperation, ValueError) as exc:
                        raise ValueError(
                            "OKX WS position 数值非法"
                        ) from exc
                    if ws_position == 0:
                        continue
                    ws_side = (
                        "long"
                        if row["posSide"] == "long"
                        or (
                            row["posSide"] == "net"
                            and ws_position > 0
                        )
                        else "short"
                    )
                    ws_positions[
                        (str(row["instId"]), str(row["posId"]))
                    ] = (
                        abs(ws_position),
                        ws_side,
                    )
                elif _nonempty(row.get("algoId")):
                    try:
                        ws_size = Decimal(str(row.get("sz", "")))
                        ws_filled = Decimal(
                            str(row.get("accFillSz", "0"))
                        )
                        ws_close_fraction = Decimal(
                            str(row.get("closeFraction", "0"))
                        )
                        ws_trigger = Decimal(
                            str(row.get("triggerPx", ""))
                        )
                    except (InvalidOperation, ValueError):
                        continue
                    ws_algos[str(row["algoId"])] = {
                        "key": (
                            str(row.get("instId", "")),
                            str(row.get("posId", "")),
                        ),
                        "state": str(row.get("state", "")),
                        "ord_type": str(row.get("ordType", "")),
                        "side": str(row.get("side", "")),
                        "reduce_only": row.get("reduceOnly")
                        in {True, "true", "1"},
                        "size": ws_size,
                        "filled": ws_filled,
                        "close_fraction": ws_close_fraction,
                        "trigger": ws_trigger,
                    }
        if ws_positions != positions:
            raise ValueError(
                "OKX business WS position size/side snapshot 不一致"
            )
        for algo_id, rest_algo in active_algos.items():
            ws_algo = ws_algos.get(algo_id)
            comparable = {
                key: rest_algo[key]
                for key in (
                    "key",
                    "state",
                    "ord_type",
                    "side",
                    "reduce_only",
                    "size",
                    "filled",
                    "close_fraction",
                    "trigger",
                )
            }
            if ws_algo == comparable:
                coverage[rest_algo["key"]] += rest_algo["effective"]
        non_dust = len(positions)
        active = sum(
            coverage[key] >= size
            for key, (size, _side) in positions.items()
        )
        unprotected = non_dust - active
        return {
            "account_uid": str(account.get("uid", "")),
            "position_state": (
                "flat"
                if non_dust == 0
                else "protected"
                if unprotected == 0
                else "unprotected"
            ),
            "non_dust_position_count": non_dust,
            "active_protection_count": active,
            "unprotected_position_count": unprotected,
            "checked_via": "rest_and_business_ws",
        }
    if check == "rest_ws_reconciliation_safe":
        if (
            set(value)
            != {
                "run",
                "rest_open_orders_response",
                "ws_subscription",
                "ws_order_events",
                "journal_open_orders",
            }
            or not isinstance(value["run"], dict)
            or set(value["run"])
            != {
                "reconciliation_run_id",
                "runtime_instance_id",
                "startup_nonce",
                "started_at",
                "completed_at",
                "ws_generation_before",
                "ws_generation_after",
            }
            or not isinstance(
                value["rest_open_orders_response"],
                dict,
            )
            or set(value["rest_open_orders_response"])
            != {"code", "msg", "data"}
            or str(value["rest_open_orders_response"]["code"]) != "0"
            or not isinstance(
                value["rest_open_orders_response"]["data"],
                list,
            )
            or not isinstance(value["ws_order_events"], list)
            or not isinstance(value["journal_open_orders"], list)
            or not isinstance(value["ws_subscription"], dict)
            or set(value["ws_subscription"])
            != {
                "channel",
                "confirmed",
                "subscribed_at",
                "subscription_id",
            }
            or value["ws_subscription"]["channel"] != "orders"
            or value["ws_subscription"]["confirmed"] is not True
            or type(value["ws_subscription"]["subscribed_at"]) is not int
            or not _nonempty(
                value["ws_subscription"]["subscription_id"]
            )
        ):
            raise ValueError("REST/WS/journal native reconciliation schema 非法")
        run = value["run"]
        rest_rows = value["rest_open_orders_response"]["data"]
        journal_rows = value["journal_open_orders"]
        if any(
            not isinstance(row, dict)
            or not _nonempty(row.get("ordId"))
            or not _nonempty(row.get("state"))
            for row in rest_rows
        ) or any(
            not isinstance(row, dict)
            or not _nonempty(row.get("exchange_order_id"))
            or row.get("state")
            not in {
                "SUBMITTED",
                "ACKNOWLEDGED",
                "PARTIALLY_FILLED",
                "UNKNOWN",
            }
            for row in journal_rows
        ):
            raise ValueError("REST/journal open-order native rows 非法")
        rest_ids = {str(row["ordId"]) for row in rest_rows}
        journal_ids = {
            str(row["exchange_order_id"])
            for row in journal_rows
        }
        if len(rest_ids) != len(rest_rows) or len(journal_ids) != len(
            journal_rows
        ):
            raise ValueError("REST/journal open-order identity 重复")
        def open_state(value: str) -> str:
            normalized = value.strip().lower()
            if normalized in {
                "live",
                "open",
                "new",
                "submitted",
                "acknowledged",
            }:
                return "open"
            if normalized in {
                "partially_filled",
                "partially-filled",
            }:
                return "partial"
            if normalized == "unknown":
                return "unknown"
            if normalized in {
                "canceled",
                "cancelled",
                "filled",
                "rejected",
                "mmp_canceled",
            }:
                return "terminal"
            return "invalid"

        rest_states = {
            str(row["ordId"]): open_state(str(row["state"]))
            for row in rest_rows
        }
        journal_states = {
            str(row["exchange_order_id"]): open_state(str(row["state"]))
            for row in journal_rows
        }
        ws_states: dict[str, str] = {}
        previous_sequence: int | None = None
        started = run["started_at"]
        completed = run["completed_at"]
        if (
            type(started) is not int
            or type(completed) is not int
            or completed < started
            or value["ws_subscription"]["subscribed_at"] > started
        ):
            raise ValueError("reconciliation native duration 非法")
        for event in value["ws_order_events"]:
            if (
                not isinstance(event, dict)
                or set(event)
                != {"arg", "data", "seqId", "received_at"}
                or not isinstance(event.get("arg"), dict)
                or event["arg"].get("channel") != "orders"
                or not isinstance(event.get("data"), list)
                or type(event["seqId"]) is not int
                or type(event["received_at"]) is not int
                or event["received_at"]
                < value["ws_subscription"]["subscribed_at"]
                or event["received_at"] < started
                or event["received_at"] > completed
                or (
                    previous_sequence is not None
                    and event["seqId"] <= previous_sequence
                )
            ):
                raise ValueError("private WS order native event 非法")
            previous_sequence = event["seqId"]
            for row in event["data"]:
                if (
                    not isinstance(row, dict)
                    or not _nonempty(row.get("ordId"))
                    or not _nonempty(row.get("state"))
                ):
                    raise ValueError("private WS order native row 非法")
                ws_states[str(row["ordId"])] = open_state(
                    str(row["state"])
                )
        baseline_conflicts = {
            order_id
            for order_id in rest_ids & journal_ids
            if rest_states[order_id] not in {"open", "partial"}
            or rest_states[order_id] != journal_states[order_id]
        }
        baseline_safe = (
            rest_ids == journal_ids and not baseline_conflicts
        )
        ws_conflicts = {
            order_id
            for order_id in rest_ids | journal_ids | set(ws_states)
            if order_id not in rest_states
            or order_id not in journal_states
            or order_id not in ws_states
            or rest_states.get(order_id)
            != journal_states.get(order_id)
            or rest_states.get(order_id) != ws_states.get(order_id)
            or rest_states.get(order_id) not in {"open", "partial"}
        }
        unresolved_ids = (
            rest_ids.symmetric_difference(journal_ids)
            | ((rest_ids | journal_ids) - set(ws_states))
            | baseline_conflicts
            | ws_conflicts
        )
        ws_state_safe = not unresolved_ids
        return {
            "reconciliation_run_id": run["reconciliation_run_id"],
            "rest_baseline_safe": baseline_safe,
            "ws_generation_safe": (
                run["ws_generation_before"]
                == run["ws_generation_after"]
                and ws_state_safe
            ),
            "unresolved_count": len(unresolved_ids),
            "completed_at": completed,
            "duration_seconds": completed - started,
        }
    bundle, download, _manifest_raw, manifest = (
        _decode_backup_raw_bundle(canonical_bytes(value))
    )
    download_sha256 = hashlib.sha256(download).hexdigest()
    download_bytes = len(download)
    integrity_check = "invalid"
    if download:
        with tempfile.NamedTemporaryFile() as restored:
            restored.write(download)
            restored.flush()
            try:
                connection = sqlite3.connect(
                    f"file:{restored.name}?mode=ro&immutable=1",
                    uri=True,
                )
                result = connection.execute(
                    "PRAGMA integrity_check"
                ).fetchone()
                integrity_check = (
                    str(result[0]) if result is not None else "invalid"
                )
            except sqlite3.Error:
                integrity_check = "invalid"
            finally:
                if "connection" in locals():
                    connection.close()
    exact = (
        manifest["archive_sha256"] == download_sha256
        and manifest["archive_bytes"] == download_bytes
        and bundle["archive_get"]["version_id"]
        == manifest["archive_version_id"]
        and bundle["manifest_get"]["version_id"]
        == manifest["manifest_version_id"]
    )
    return {
        "object_uri": manifest["archive_object_uri"],
        "version_id": manifest["archive_version_id"],
        "sha256": manifest["archive_sha256"],
        "bytes": manifest["archive_bytes"],
        "backup_completed_at": manifest["backup_completed_at"],
        "restored_at": bundle["restore_requested_at"],
        "exact_version_readback": exact,
        "restore_ok": exact and integrity_check == "ok",
        "integrity_check": integrity_check,
    }


def _validate_post_start_native_binding(
    check: str,
    source_evidence: object,
    *,
    runtime_instance_id: str,
    boot_id: str,
    deployment_unit: str,
    startup_nonce: str,
    expected_startup_hard_epoch: int,
) -> None:
    raw = _source_evidence_bytes(
        source_evidence,
        expected_kind=_POST_START_EVIDENCE_KINDS[check],
    )
    value = _json_object(raw, _POST_START_EVIDENCE_KINDS[check])
    expected = {
        "runtime_instance_id": runtime_instance_id,
        "startup_nonce": startup_nonce,
    }
    if check == "runtime_safety_kernel_live_within_60s":
        request = value["request"]
        expected.update(
            {
                "unit": deployment_unit,
                "boot_id": boot_id,
                "startup_hard_epoch": (
                    expected_startup_hard_epoch
                ),
            }
        )
        if any(request.get(key) != item for key, item in expected.items()):
            raise ValueError(
                "runtime native response 未绑定 startup nonce/hard epoch"
            )
    else:
        binding = value["runtime_binding"]
        complete_expected = {
            **expected,
            "boot_id": boot_id,
            "deployment_unit": deployment_unit,
            "startup_hard_epoch": expected_startup_hard_epoch,
        }
        if any(
            binding.get(key) != item
            for key, item in complete_expected.items()
        ):
            raise ValueError(
                f"{check} native evidence 未绑定 startup nonce/hard epoch"
            )


def _post_start_collected_raw(
    check: str,
    source_evidence: object,
) -> bytes:
    evidence_raw = _source_evidence_bytes(
        source_evidence,
        expected_kind=_POST_START_EVIDENCE_KINDS[check],
    )
    if check == "runtime_safety_kernel_live_within_60s":
        return evidence_raw
    wrapper = _json_object(
        evidence_raw,
        _POST_START_EVIDENCE_KINDS[check],
    )
    try:
        native = base64.b64decode(
            wrapper["native_payload_base64"],
            validate=True,
        )
    except (KeyError, binascii.Error, TypeError) as exc:
        raise ValueError("post-start native collected bytes 非法") from exc
    if (
        wrapper.get("native_bytes") != len(native)
        or wrapper.get("native_sha256")
        != hashlib.sha256(native).hexdigest()
    ):
        raise ValueError("post-start native collected hash/bytes 非法")
    return native


def _validate_post_start_source_facts(
    check: str,
    facts: object,
    *,
    source_evidence: object,
    observed_at: int,
    account_uid: str,
) -> None:
    if not isinstance(facts, dict):
        raise ValueError("Canary source facts 必须是对象")
    if facts != derive_post_start_facts(check, source_evidence):
        raise ValueError("Canary post-start facts 与固定 raw evidence 重算结果不一致")
    if check == "runtime_safety_kernel_live_within_60s":
        if (
            set(facts) != {"live", "runtime_started_at"}
            or facts["live"] is not True
            or not isinstance(facts["runtime_started_at"], (int, float))
            or not 0 <= observed_at - float(facts["runtime_started_at"]) <= 60
        ):
            raise ValueError("source 未证明 safety kernel 在 60 秒内存活")
        return
    if check == "alert_challenge_received":
        if (
            set(facts)
            != {
                "challenge_id",
                "severity",
                "triggered_at",
                "provider_received_at",
                "provider",
            }
            or not _nonempty(facts["challenge_id"])
            or facts["severity"] != "P0"
            or type(facts["triggered_at"]) is not int
            or type(facts["provider_received_at"]) is not int
            or not _nonempty(facts["provider"])
            or not facts["triggered_at"] <= facts["provider_received_at"] <= observed_at
            or facts["provider_received_at"] - facts["triggered_at"] > 60
        ):
            raise ValueError("source 未证明 P0 provider receipt ≤60 秒")
        return
    if check == "backup_exact_version_restored":
        if (
            set(facts)
            != {
                "object_uri",
                "version_id",
                "sha256",
                "bytes",
                "backup_completed_at",
                "restored_at",
                "exact_version_readback",
                "restore_ok",
                "integrity_check",
            }
            or not _valid_s3(facts["object_uri"])
            or not _SHA256.fullmatch(str(facts["sha256"]))
            or not _nonempty(facts["version_id"])
            or type(facts["bytes"]) is not int
            or facts["bytes"] <= 0
            or type(facts["backup_completed_at"]) is not int
            or type(facts["restored_at"]) is not int
            or not facts["backup_completed_at"] <= facts["restored_at"] <= observed_at
            or observed_at - facts["backup_completed_at"] > 300
            or facts["exact_version_readback"] is not True
            or facts["restore_ok"] is not True
            or facts["integrity_check"] != "ok"
        ):
            raise ValueError("source 未证明 exact-version backup 恢复/RPO")
        return
    if check == "protected_position_or_flat":
        native = _json_object(
            _post_start_collected_raw(check, source_evidence),
            "OKX position/protection native evidence",
        )
        latest_by_channel: dict[str, int] = {}
        for event in native.get("business_ws_events", []):
            if (
                isinstance(event, dict)
                and isinstance(event.get("arg"), dict)
                and event["arg"].get("channel")
                in {"positions", "orders-algo"}
                and type(event.get("received_at")) is int
            ):
                channel = event["arg"]["channel"]
                latest_by_channel[channel] = max(
                    latest_by_channel.get(channel, 0),
                    event["received_at"],
                )
        if (
            set(facts)
            != {
                "account_uid",
                "position_state",
                "non_dust_position_count",
                "active_protection_count",
                "unprotected_position_count",
                "checked_via",
            }
            or facts["account_uid"] != account_uid
            or facts["position_state"] not in {"flat", "protected"}
            or type(facts["non_dust_position_count"]) is not int
            or facts["non_dust_position_count"] < 0
            or type(facts["active_protection_count"]) is not int
            or facts["active_protection_count"] < 0
            or facts["unprotected_position_count"] != 0
            or facts["checked_via"] != "rest_and_business_ws"
            or set(latest_by_channel)
            != {"positions", "orders-algo"}
            or any(
                not observed_at - CANARY_POST_START_WS_MAX_AGE_SECONDS
                <= received_at
                <= observed_at
                for received_at in latest_by_channel.values()
            )
            or (
                facts["position_state"] == "flat"
                and (facts["non_dust_position_count"] != 0 or facts["active_protection_count"] != 0)
            )
            or (
                facts["position_state"] == "protected"
                and (
                    facts["non_dust_position_count"] <= 0
                    or facts["active_protection_count"] < facts["non_dust_position_count"]
                )
            )
        ):
            raise ValueError("source 未证明目标账户 flat 或全部仓位已保护")
        return
    if check == "rest_ws_reconciliation_safe":
        if (
            set(facts)
            != {
                "reconciliation_run_id",
                "rest_baseline_safe",
                "ws_generation_safe",
                "unresolved_count",
                "completed_at",
                "duration_seconds",
            }
            or not _nonempty(facts["reconciliation_run_id"])
            or facts["rest_baseline_safe"] is not True
            or facts["ws_generation_safe"] is not True
            or facts["unresolved_count"] != 0
            or type(facts["completed_at"]) is not int
            or facts["completed_at"] > observed_at
            or observed_at - facts["completed_at"]
            > CANARY_POST_START_WS_MAX_AGE_SECONDS
            or not isinstance(facts["duration_seconds"], (int, float))
            or not 0 <= float(facts["duration_seconds"]) <= 60
        ):
            raise ValueError("source 未证明 REST/WS reconciliation safe")
        return
    raise ValueError(f"未知 Canary post-start check: {check}")


def validate_post_start_source_claims(
    source: object,
    *,
    check: str,
    runtime_instance_id: str,
    boot_id: str,
    account_uid: str,
    deployment_unit: str,
    demo_soak_epoch_id: str,
    transition_sha256: str,
    policy_sha256: str,
    target_deployment_identity_sha256: str,
    startup_nonce: str,
    expected_startup_hard_epoch: int,
    producer_inventory: dict,
    target_key_fingerprint: str,
    now: int,
) -> dict:
    """Validate one independently signed fact against the exact Canary target."""
    if (
        not isinstance(source, dict)
        or set(source) != POST_START_SOURCE_KEYS
        or source["version"] != 1
        or source["action"] != "attest-canary-post-start-source"
        or source["check"] != check
        or type(source["observed_at"]) is not int
        or not now - 300 <= source["observed_at"] <= now + 5
    ):
        raise ValueError("Canary source evidence schema/时效非法")
    expected = {
        "runtime_instance_id": runtime_instance_id,
        "boot_id": boot_id,
        "account_uid": account_uid,
        "deployment_unit": deployment_unit,
        "demo_soak_epoch_id": demo_soak_epoch_id,
        "transition_sha256": transition_sha256,
        "policy_sha256": policy_sha256,
        "target_deployment_identity_sha256": target_deployment_identity_sha256,
        "startup_nonce": startup_nonce,
        "expected_startup_hard_epoch": expected_startup_hard_epoch,
    }
    if (
        any(source.get(key) != value for key, value in expected.items())
        or not _nonempty(account_uid)
        or not _nonempty(deployment_unit)
        or not _nonempty(demo_soak_epoch_id)
        or not re.fullmatch(r"[0-9a-f]{32}", startup_nonce)
        or type(expected_startup_hard_epoch) is not int
        or expected_startup_hard_epoch <= 0
        or any(
            not _SHA256.fullmatch(value)
            for value in (
                transition_sha256,
                policy_sha256,
                target_deployment_identity_sha256,
            )
        )
    ):
        raise ValueError("Canary source evidence 未绑定目标 deployment/account/epoch")
    _validate_post_start_source_facts(
        check,
        source["facts"],
        source_evidence=source["source_evidence"],
        observed_at=source["observed_at"],
        account_uid=account_uid,
    )
    _validate_post_start_native_binding(
        check,
        source["source_evidence"],
        runtime_instance_id=runtime_instance_id,
        boot_id=boot_id,
        deployment_unit=deployment_unit,
        startup_nonce=startup_nonce,
        expected_startup_hard_epoch=expected_startup_hard_epoch,
    )
    execution = source["producer_execution"]
    raw = _post_start_collected_raw(
        check,
        source["source_evidence"],
    )
    validate_producer_execution(
        execution,
        producer_name=check,
        inventory=producer_inventory,
        readiness_id=canary_readiness_id(
            demo_soak_epoch_id=demo_soak_epoch_id,
            target_deployment_identity_sha256=(
                target_deployment_identity_sha256
            ),
            source_producer_inventory_sha256=(
                canary_source_producer_inventory_sha256(
                    producer_inventory
                )
            ),
        ),
        raw=raw,
        now=now,
    )
    collection = validate_collection_receipt(
        source["collection_receipt"],
        producer_name=check,
        inventory=producer_inventory,
        raw=raw,
        target_key_fingerprint=target_key_fingerprint,
        now=now,
    )
    validate_execution_collection_binding(execution, collection)
    return source


def _timestamp_window(payload: dict, *, maximum_lifetime: int) -> None:
    issued = payload["issued_at"]
    expires = payload["expires_at"]
    if (
        type(issued) is not int
        or type(expires) is not int
        or not 300 <= expires - issued <= maximum_lifetime
    ):
        raise ValueError("Canary artifact 有效期非法")


def _dual_verify(
    artifact: object,
    *,
    operator_public_key: str | Path,
    risk_public_key: str | Path,
    label: str,
) -> dict:
    if not isinstance(artifact, dict) or set(artifact) != {
        "payload",
        "operator_signature",
        "risk_signature",
    }:
        raise ValueError(f"{label} 双签 envelope 非法")
    operator_fingerprint = ed25519_public_key_fingerprint(operator_public_key)
    risk_fingerprint = ed25519_public_key_fingerprint(risk_public_key)
    if operator_fingerprint == risk_fingerprint:
        raise ValueError(f"{label} operator/risk 必须使用不同公钥")
    payload = artifact["payload"]
    for signature, key, signer in (
        (artifact["operator_signature"], operator_public_key, "operator"),
        (artifact["risk_signature"], risk_public_key, "risk"),
    ):
        claims = verify_ed25519_artifact(
            {"payload": payload, "signature": signature},
            key,
            label=f"{label} {signer}",
        )
        if claims != payload:
            raise ValueError(f"{label} 双签未绑定同一 payload")
    return payload


def validate_target_deployment_identity(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != _TARGET_KEYS:
        raise ValueError("Canary target deployment identity schema 非法")
    parsed = urlparse(str(payload["api_domain"]))
    if (
        not _SHA256.fullmatch(str(payload["release_identity_sha256"]))
        or not _SHA1.fullmatch(str(payload["release_commit"]))
        or not _SHA256.fullmatch(str(payload["deployed_source_sha256"]))
        or not _SHA256.fullmatch(str(payload["config_sha256"]))
        or not _SHA256.fullmatch(str(payload["ip_allowlist_sha256"]))
        or not _SHA256.fullmatch(str(payload["host_image_sha256"]))
        or not _SHA256.fullmatch(str(payload["key_fingerprint"]))
        or not _SHA256.fullmatch(
            str(payload["source_producer_inventory_sha256"])
        )
        or payload["environment"] != "production"
        or payload["deployment_tier"] != "canary"
        or payload["simulated"] is not False
        or payload["permissions"] != ["read", "trade"]
        or payload["unit"] != "okx-quant.service"
        or parsed.scheme != "https"
        or parsed.hostname not in {"openapi.okx.com", "www.okx.com"}
        or parsed.port not in {None, 443}
        or parsed.username
        or parsed.password
        or not str(payload["account_uid"]).strip()
        or not isinstance(payload["allowed_instruments"], list)
        or payload["allowed_instruments"] != sorted(set(payload["allowed_instruments"]))
        or not payload["allowed_instruments"]
        or any(
            not re.fullmatch(r"[A-Z0-9]{2,15}-USDT", str(item))
            for item in payload["allowed_instruments"]
        )
    ):
        raise ValueError("Canary target deployment identity 非法")
    return payload


def validate_transition(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != _TRANSITION_KEYS:
        raise ValueError("Demo-to-Canary transition schema 非法")
    _timestamp_window(payload, maximum_lifetime=86400)
    release = payload["release_identity"]
    if (
        payload["version"] != 1
        or payload["action"] != "authorize-demo-to-canary-transition"
        or not re.fullmatch(
            r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{7,127}",
            str(payload["transition_id"]),
        )
        or not str(payload["demo_soak_epoch_id"]).strip()
        or not _SHA256.fullmatch(str(payload["demo_ledger_head_hash"]))
        or not isinstance(release, dict)
        or set(release)
        != {
            "git_commit",
            "git_tree_hash",
            "source_manifest_sha256",
            "dependency_lock_sha256",
            "interpreter_sha256",
        }
        or not _SHA1.fullmatch(str(release.get("git_commit", "")))
        or not _SHA1.fullmatch(str(release.get("git_tree_hash", "")))
        or any(
            not _SHA256.fullmatch(str(release.get(key, "")))
            for key in (
                "source_manifest_sha256",
                "dependency_lock_sha256",
                "interpreter_sha256",
            )
        )
        or payload["allowed_deployment_differences"] != ALLOWED_DEPLOYMENT_DIFFERENCES
        or payload["required_pre_start_checks"] != REQUIRED_PRE_START_CHECKS
        or not isinstance(payload["pre_start_source_key_fingerprints"], dict)
        or set(payload["pre_start_source_key_fingerprints"]) != set(REQUIRED_PRE_START_CHECKS)
        or any(
            not _SHA256.fullmatch(str(fingerprint))
            for fingerprint in payload["pre_start_source_key_fingerprints"].values()
        )
        or len(set(payload["pre_start_source_key_fingerprints"].values()))
        != len(REQUIRED_PRE_START_CHECKS)
        or not isinstance(payload["canary_limits"], dict)
        or set(payload["canary_limits"]) != CANARY_LIMIT_FIELDS
        or payload["required_post_start_checks"] != REQUIRED_POST_START_CHECKS
        or not _SHA256.fullmatch(str(payload["post_start_verifier_key_fingerprint"]))
        or not isinstance(
            payload["post_start_source_key_fingerprints"],
            dict,
        )
        or set(payload["post_start_source_key_fingerprints"]) != set(REQUIRED_POST_START_CHECKS)
        or any(
            not _SHA256.fullmatch(str(fingerprint))
            for fingerprint in payload["post_start_source_key_fingerprints"].values()
        )
        or len(set(payload["post_start_source_key_fingerprints"].values()))
        != len(REQUIRED_POST_START_CHECKS)
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(payload["pre_start_challenge"]),
        )
        or payload["post_start_verifier_key_fingerprint"]
        in payload["post_start_source_key_fingerprints"].values()
        or set(payload["pre_start_source_key_fingerprints"].values())
        & (
            {
                payload["post_start_verifier_key_fingerprint"],
            }
            | set(payload["post_start_source_key_fingerprints"].values())
        )
        or not str(payload["operator"]).strip()
        or not str(payload["risk_approver"]).strip()
        or payload["operator"] == payload["risk_approver"]
    ):
        raise ValueError("Demo-to-Canary transition identity/checks 非法")
    for name, maximum in {
        "max_order_notional_usdt": 25,
        "max_order_intents_per_hour": 6,
        "max_concurrent_positions": 1,
        "max_total_exposure_usdt": 100,
        "max_order_loss_usdt": 5,
        "max_daily_loss_usdt": 10,
        "max_drawdown_ratio": 0.02,
        "max_slippage_ratio": 0.01,
    }.items():
        _finite_number(
            payload["canary_limits"][name],
            f"canary_limits.{name}",
            minimum=(
                5
                if name
                in {
                    "max_order_notional_usdt",
                    "max_total_exposure_usdt",
                }
                else 0.0001
                if name in {"max_drawdown_ratio", "max_slippage_ratio"}
                else 0.01
                if name in {"max_order_loss_usdt", "max_daily_loss_usdt"}
                else 1
            ),
            maximum=maximum,
        )
    target = validate_target_deployment_identity(payload["target_deployment_identity"])
    inventory = validate_canary_source_producer_inventory(payload["source_producer_inventory"])
    inventory_fingerprints = {
        name: item["source_key_fingerprint"] for name, item in inventory.items()
    }
    inventory_sha256 = canary_source_producer_inventory_sha256(inventory)
    if inventory_fingerprints != {
        **payload["pre_start_source_key_fingerprints"],
        **payload["post_start_source_key_fingerprints"],
    }:
        raise ValueError("Transition 只接受 epoch 预注册 producer inventory/key")
    if (
        payload["source_producer_inventory_sha256"] != inventory_sha256
        or target["source_producer_inventory_sha256"] != inventory_sha256
    ):
        raise ValueError(
            "Transition target/inventory canonical hash 不一致"
        )
    try:
        validate_strategy_identity(payload["strategy_identity"])
    except ValueError as exc:
        raise ValueError("Demo-to-Canary transition strategy identity 非法") from exc
    if (
        target["release_identity_sha256"] != identity_sha256(release)
        or target["release_commit"] != release["git_commit"]
    ):
        raise ValueError("Transition target 未绑定 exact release identity")
    verify_embedded_pre_start_checks(payload)
    return payload


def verify_transition(
    artifact: object,
    *,
    operator_public_key: str | Path,
    risk_public_key: str | Path,
    now: int | None = None,
) -> dict:
    payload = validate_transition(
        _dual_verify(
            artifact,
            operator_public_key=operator_public_key,
            risk_public_key=risk_public_key,
            label="Demo-to-Canary transition",
        )
    )
    approval_fingerprints = {
        ed25519_public_key_fingerprint(operator_public_key),
        ed25519_public_key_fingerprint(risk_public_key),
    }
    evidence_fingerprints = {
        payload["post_start_verifier_key_fingerprint"],
        *payload["pre_start_source_key_fingerprints"].values(),
        *payload["post_start_source_key_fingerprints"].values(),
    }
    if approval_fingerprints & evidence_fingerprints:
        raise ValueError("Canary operator/risk 与 pre/post-start 事实身份必须隔离")
    current = int(time.time() if now is None else now)
    if not payload["issued_at"] - 30 <= current <= payload["expires_at"]:
        raise ValueError("Demo-to-Canary transition 尚未生效或已过期")
    if any(
        not current - 900 <= payload["pre_start_checks"][name]["observed_at"] <= current + 5
        for name in REQUIRED_PRE_START_CHECKS
    ):
        raise ValueError("Canary pre-start evidence 已超过 15 分钟，必须重新观测并双签")
    return payload


def _finite_number(
    value: object,
    label: str,
    *,
    minimum: float = 0,
    maximum: float,
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise ValueError(f"{label} 必须位于 [{minimum},{maximum}]")
    return float(value)


def validate_canary_policy(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != _POLICY_KEYS:
        raise ValueError("Canary policy schema 非法")
    _timestamp_window(payload, maximum_lifetime=21600)
    if (
        payload["version"] != 1
        or payload["action"] != "authorize-short-lived-canary"
        or not re.fullmatch(
            r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{7,127}",
            str(payload["policy_id"]),
        )
        or not _SHA256.fullmatch(str(payload["transition_sha256"]))
        or not _SHA256.fullmatch(str(payload["target_deployment_identity_sha256"]))
        or not isinstance(payload["allowed_instruments"], list)
        or payload["allowed_instruments"] != sorted(set(payload["allowed_instruments"]))
        or not payload["allowed_instruments"]
        or any(
            not re.fullmatch(r"[A-Z0-9]{2,15}-USDT", str(item))
            for item in payload["allowed_instruments"]
        )
        or payload["production_promotion"] != "forbidden"
        or not all(
            str(payload[key]).strip() for key in ("operator", "risk_approver", "rollback_owner")
        )
        or payload["operator"] == payload["risk_approver"]
    ):
        raise ValueError("Canary policy identity/ownership 非法")
    _finite_number(
        payload["max_order_notional_usdt"],
        "max_order_notional_usdt",
        minimum=5,
        maximum=25,
    )
    _finite_number(
        payload["max_order_intents_per_hour"],
        "max_order_intents_per_hour",
        minimum=1,
        maximum=6,
    )
    _finite_number(
        payload["max_concurrent_positions"],
        "max_concurrent_positions",
        minimum=1,
        maximum=1,
    )
    _finite_number(
        payload["max_total_exposure_usdt"],
        "max_total_exposure_usdt",
        minimum=5,
        maximum=100,
    )
    _finite_number(
        payload["max_order_loss_usdt"],
        "max_order_loss_usdt",
        minimum=0.01,
        maximum=5,
    )
    _finite_number(
        payload["max_daily_loss_usdt"],
        "max_daily_loss_usdt",
        minimum=0.01,
        maximum=10,
    )
    _finite_number(
        payload["max_drawdown_ratio"],
        "max_drawdown_ratio",
        minimum=0.0001,
        maximum=0.02,
    )
    _finite_number(
        payload["max_slippage_ratio"],
        "max_slippage_ratio",
        minimum=0.0001,
        maximum=0.01,
    )
    if payload["auto_halt"] != {
        "unknown_buy_seconds": 30,
        "infrastructure_error_count": 3,
        "backup_rpo_seconds": 300,
        "clock_offset_seconds": 1,
    } or payload["auto_flatten"] != {
        "unprotected_position_seconds": 10,
        "emergency_exit_without_approval": True,
        "ordinary_flatten_requires_dual_approval": True,
    }:
        raise ValueError("Canary auto halt/flatten policy 非法")
    return payload


def verify_canary_policy(
    artifact: object,
    *,
    operator_public_key: str | Path,
    risk_public_key: str | Path,
    now: int | None = None,
) -> dict:
    payload = validate_canary_policy(
        _dual_verify(
            artifact,
            operator_public_key=operator_public_key,
            risk_public_key=risk_public_key,
            label="Canary policy",
        )
    )
    current = int(time.time() if now is None else now)
    if not (payload["issued_at"] - 30 <= current <= payload["expires_at"] - 60):
        raise ValueError("Canary policy 尚未生效或剩余有效期不足 60 秒")
    return payload


def validate_post_start_activation(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != _POST_START_KEYS:
        raise ValueError("Canary post-start activation schema 非法")
    _timestamp_window(payload, maximum_lifetime=900)
    checks = payload["checks"]
    if (
        payload["version"] != 1
        or payload["action"] != "activate-canary-entries-after-post-start"
        or any(
            not _SHA256.fullmatch(str(payload[key]))
            for key in (
                "transition_sha256",
                "policy_sha256",
                "target_deployment_identity_sha256",
            )
        )
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(payload["runtime_instance_id"]),
        )
        or not re.fullmatch(
            r"[0-9a-fA-F-]{16,64}",
            str(payload["boot_id"]),
        )
        or type(payload["expected_startup_hard_epoch"]) is not int
        or payload["expected_startup_hard_epoch"] <= 0
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(payload["startup_nonce"]),
        )
        or payload["latch_reason"] != "canary_post_start_activation_pending"
        or not isinstance(checks, dict)
        or set(checks) != set(REQUIRED_POST_START_CHECKS)
        or not all(
            isinstance(checks[name], dict)
            and set(checks[name])
            == {
                "passed",
                "observed_at",
                "evidence_uri",
                "evidence_version_id",
                "evidence_sha256",
                "evidence_bytes",
                "artifact_bytes_base64",
            }
            and checks[name]["passed"] is True
            and type(checks[name]["observed_at"]) is int
            and _SHA256.fullmatch(str(checks[name]["evidence_sha256"]))
            and type(checks[name]["evidence_bytes"]) is int
            and checks[name]["evidence_bytes"] > 0
            and isinstance(
                checks[name]["artifact_bytes_base64"],
                str,
            )
            and urlparse(str(checks[name]["evidence_uri"])).scheme == "s3"
            and bool(urlparse(str(checks[name]["evidence_uri"])).netloc)
            and bool(str(checks[name]["evidence_version_id"]).strip())
            for name in REQUIRED_POST_START_CHECKS
        )
        or not str(payload["operator"]).strip()
        or not _SHA256.fullmatch(str(payload["checks_verifier_key_fingerprint"]))
        or not isinstance(payload["source_key_fingerprints"], dict)
        or set(payload["source_key_fingerprints"]) != set(REQUIRED_POST_START_CHECKS)
        or any(
            not _SHA256.fullmatch(str(fingerprint))
            for fingerprint in payload["source_key_fingerprints"].values()
        )
        or len(set(payload["source_key_fingerprints"].values())) != len(REQUIRED_POST_START_CHECKS)
        or payload["checks_verifier_key_fingerprint"] in payload["source_key_fingerprints"].values()
        or not str(payload["risk_approver"]).strip()
        or payload["operator"] == payload["risk_approver"]
    ):
        raise ValueError("Canary post-start activation checks/identity 非法")
    if any(
        not payload["issued_at"] - 300 <= checks[name]["observed_at"] <= payload["issued_at"] + 30
        for name in REQUIRED_POST_START_CHECKS
    ):
        raise ValueError("Canary post-start check 时间窗口非法")
    return payload


def verify_post_start_activation(
    artifact: object,
    *,
    operator_public_key: str | Path,
    risk_public_key: str | Path,
    checks_verifier_public_key: str | Path,
    source_key_fingerprints: dict[str, str],
    producer_inventory: dict,
    target_key_fingerprint: str,
    transition_sha256: str,
    policy_sha256: str,
    target_deployment_identity_sha256: str,
    account_uid: str,
    deployment_unit: str,
    demo_soak_epoch_id: str,
    runtime_instance_id: str,
    boot_id: str,
    expected_startup_hard_epoch: int,
    startup_nonce: str,
    latch_reason: str,
    now: int | None = None,
) -> dict:
    payload = validate_post_start_activation(
        _dual_verify(
            artifact,
            operator_public_key=operator_public_key,
            risk_public_key=risk_public_key,
            label="Canary post-start activation",
        )
    )
    current = int(time.time() if now is None else now)
    verifier_fingerprint = ed25519_public_key_fingerprint(checks_verifier_public_key)
    if payload["checks_verifier_key_fingerprint"] != verifier_fingerprint:
        raise ValueError("Canary activation 未绑定配置的 post-start verifier")
    if payload["source_key_fingerprints"] != source_key_fingerprints:
        raise ValueError("Canary activation source identities 未绑定 transition")
    for name in REQUIRED_POST_START_CHECKS:
        locator = payload["checks"][name]
        try:
            raw = base64.b64decode(
                locator["artifact_bytes_base64"],
                validate=True,
            )
            check_artifact = json.loads(raw)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Canary post-start check {name} bytes 非法") from exc
        if (
            len(raw) != locator["evidence_bytes"]
            or hashlib.sha256(raw).hexdigest() != locator["evidence_sha256"]
        ):
            raise ValueError(f"Canary post-start check {name} exact bytes 不匹配")
        claims = verify_ed25519_artifact(
            check_artifact,
            checks_verifier_public_key,
            label=f"Canary post-start check {name}",
        )
        if (
            not isinstance(claims, dict)
            or set(claims)
            != {
                "version",
                "action",
                "check",
                "passed",
                "observed_at",
                "runtime_instance_id",
                "boot_id",
                "account_uid",
                "deployment_unit",
                "demo_soak_epoch_id",
                "transition_sha256",
                "policy_sha256",
                "target_deployment_identity_sha256",
                "source_evidence_sha256",
                "source_key_fingerprint",
                "source_artifact_bytes_base64",
                "source_public_key_pem_base64",
            }
            or claims["version"] != 1
            or claims["action"] != "attest-canary-post-start-check"
            or claims["check"] != name
            or claims["passed"] is not True
            or claims["observed_at"] != locator["observed_at"]
            or claims["runtime_instance_id"] != runtime_instance_id
            or claims["boot_id"] != boot_id
            or claims["account_uid"] != account_uid
            or claims["deployment_unit"] != deployment_unit
            or claims["demo_soak_epoch_id"] != demo_soak_epoch_id
            or claims["transition_sha256"] != transition_sha256
            or claims["policy_sha256"] != policy_sha256
            or claims["target_deployment_identity_sha256"] != target_deployment_identity_sha256
            or not _SHA256.fullmatch(str(claims["source_evidence_sha256"]))
            or not _SHA256.fullmatch(str(claims["source_key_fingerprint"]))
            or claims["source_key_fingerprint"] != source_key_fingerprints[name]
        ):
            raise ValueError(f"Canary post-start check {name} 签名 claims 非法")
        try:
            source_raw = base64.b64decode(
                claims["source_artifact_bytes_base64"],
                validate=True,
            )
            source_public_key = base64.b64decode(
                claims["source_public_key_pem_base64"],
                validate=True,
            )
            source_artifact = json.loads(source_raw)
        except (
            binascii.Error,
            TypeError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError(f"Canary post-start source {name} embedded bytes 非法") from exc
        if hashlib.sha256(source_raw).hexdigest() != claims["source_evidence_sha256"]:
            raise ValueError(f"Canary post-start source {name} exact bytes 不匹配")
        with tempfile.NamedTemporaryFile() as source_key_file:
            source_key_file.write(source_public_key)
            source_key_file.flush()
            if (
                ed25519_public_key_fingerprint(source_key_file.name)
                != claims["source_key_fingerprint"]
            ):
                raise ValueError(f"Canary post-start source {name} key fingerprint 不匹配")
            source = verify_ed25519_artifact(
                source_artifact,
                source_key_file.name,
                label=f"Canary post-start source {name}",
            )
        validate_post_start_source_claims(
            source,
            check=name,
            runtime_instance_id=runtime_instance_id,
            boot_id=boot_id,
            account_uid=account_uid,
            deployment_unit=deployment_unit,
            demo_soak_epoch_id=demo_soak_epoch_id,
            transition_sha256=transition_sha256,
            policy_sha256=policy_sha256,
            target_deployment_identity_sha256=target_deployment_identity_sha256,
            startup_nonce=startup_nonce,
            expected_startup_hard_epoch=expected_startup_hard_epoch,
            producer_inventory=producer_inventory,
            target_key_fingerprint=target_key_fingerprint,
            now=claims["observed_at"],
        )
        if (
            source["producer_execution"]["source_key_fingerprint"]
            != claims["source_key_fingerprint"]
        ):
            raise ValueError(
                f"Canary post-start source {name} execution key 不匹配"
            )
    expected = {
        "transition_sha256": transition_sha256,
        "policy_sha256": policy_sha256,
        "target_deployment_identity_sha256": (target_deployment_identity_sha256),
        "runtime_instance_id": runtime_instance_id,
        "boot_id": boot_id,
        "expected_startup_hard_epoch": expected_startup_hard_epoch,
        "startup_nonce": startup_nonce,
        "latch_reason": latch_reason,
    }
    mismatched = [key for key, value in expected.items() if payload.get(key) != value]
    if mismatched:
        raise ValueError(f"Canary post-start activation 未绑定当前运行时: {mismatched}")
    if not payload["issued_at"] - 30 <= current < payload["expires_at"]:
        raise ValueError("Canary post-start activation 尚未生效或已过期")
    return payload


def target_identity_from_runtime(
    *,
    release_identity: dict,
    strategy_identity: dict,
    source_producer_inventory: dict,
    actual_runtime_identity: dict,
    config: dict,
    host_image_sha256: str,
    ip_allowlist_sha256: str,
    api_permissions: tuple[str, ...],
    deployment_unit: str,
    allowed_instruments: tuple[str, ...],
) -> dict:
    validate_strategy_identity(strategy_identity)
    if actual_runtime_identity.get("release_identity") != release_identity:
        raise ValueError("Canary actual runtime 未绑定 epoch exact release")
    if actual_runtime_identity.get("strategy_identity") != strategy_identity:
        raise ValueError("Canary actual runtime 未绑定 epoch strategy identity")
    okx = config.get("okx", {})
    target = {
        "release_identity_sha256": identity_sha256(release_identity),
        "release_commit": actual_runtime_identity["commit_sha"],
        "deployed_source_sha256": actual_runtime_identity["deployed_source_sha256"],
        "config_sha256": actual_runtime_identity["config_hash"],
        "account_uid": actual_runtime_identity["account_id"],
        "environment": actual_runtime_identity["environment"],
        "deployment_tier": "canary",
        "api_domain": str(okx.get("base_url", "")).rstrip("/"),
        "simulated": okx.get("simulated"),
        "permissions": list(api_permissions),
        "ip_allowlist_sha256": ip_allowlist_sha256,
        "unit": deployment_unit,
        "host_image_sha256": host_image_sha256,
        "key_fingerprint": credential_fingerprint(str(okx.get("api_key", ""))),
        "allowed_instruments": sorted(allowed_instruments),
        "source_producer_inventory_sha256": (
            canary_source_producer_inventory_sha256(
                source_producer_inventory
            )
        ),
    }
    return validate_target_deployment_identity(target)


def enforce_policy_limits(policy: dict, settings) -> None:
    comparisons = {
        "max_position_notional_usdt": (
            Decimal(str(settings.max_position_notional_usdt)),
            Decimal(str(policy["max_order_notional_usdt"])),
        ),
        "max_total_exposure_usdt": (
            Decimal(str(settings.max_total_exposure_usdt)),
            Decimal(str(policy["max_total_exposure_usdt"])),
        ),
        "max_order_loss_usdt": (
            Decimal(str(settings.max_order_loss_usdt)),
            Decimal(str(policy["max_order_loss_usdt"])),
        ),
        "max_daily_loss_usdt": (
            Decimal(str(settings.max_daily_loss_usdt)),
            Decimal(str(policy["max_daily_loss_usdt"])),
        ),
        "max_drawdown_ratio": (
            Decimal(str(settings.max_drawdown_ratio)),
            Decimal(str(policy["max_drawdown_ratio"])),
        ),
        "max_slippage_ratio": (
            Decimal(str(settings.max_slippage_ratio)),
            Decimal(str(policy["max_slippage_ratio"])),
        ),
        "max_order_intents_per_hour": (
            Decimal(str(settings.max_order_intents_per_hour)),
            Decimal(str(policy["max_order_intents_per_hour"])),
        ),
        "max_open_positions": (
            Decimal(str(settings.max_open_positions)),
            Decimal(str(policy["max_concurrent_positions"])),
        ),
    }
    exceeded = [
        name for name, (configured, approved) in comparisons.items() if configured > approved
    ]
    if exceeded:
        raise ValueError(f"Canary config 超过短效 policy: {sorted(exceeded)}")
    if (
        sorted(settings.allowed_instruments) != policy["allowed_instruments"]
        or settings.max_unprotected_position_s
        > policy["auto_flatten"]["unprotected_position_seconds"]
        or settings.max_consecutive_infrastructure_errors
        > policy["auto_halt"]["infrastructure_error_count"]
        or settings.max_clock_skew_s > policy["auto_halt"]["clock_offset_seconds"]
    ):
        raise ValueError("Canary instruments/自动停止边界与 policy 不一致")


def policy_limit_projection(policy: dict) -> dict:
    return {name: policy[name] for name in CANARY_LIMIT_FIELDS}


def validate_canary_runtime(
    *,
    settings,
    config: dict,
    actual_runtime_identity: dict,
    deployment_receipt: dict,
    now: int | None = None,
) -> tuple[dict, dict]:
    """Verify transition/policy and bind them to the exact running target."""
    import json

    if settings.environment != "production" or settings.deployment_tier != "canary":
        raise ValueError("Canary gate 只接受 production environment/canary tier")
    transition_artifact = json.loads(
        Path(settings.canary_transition_path).read_text(encoding="utf-8")
    )
    policy_artifact = json.loads(Path(settings.canary_policy_path).read_text(encoding="utf-8"))
    transition = verify_transition(
        transition_artifact,
        operator_public_key=settings.canary_operator_public_key,
        risk_public_key=settings.canary_risk_public_key,
        now=now,
    )
    policy = verify_canary_policy(
        policy_artifact,
        operator_public_key=settings.canary_operator_public_key,
        risk_public_key=settings.canary_risk_public_key,
        now=now,
    )
    verifier_fingerprints = {
        ed25519_public_key_fingerprint(settings.canary_operator_public_key),
        ed25519_public_key_fingerprint(settings.canary_risk_public_key),
        ed25519_public_key_fingerprint(settings.canary_check_verifier_public_key),
    }
    pre_start_fingerprints = set(transition["pre_start_source_key_fingerprints"].values())
    source_fingerprints = set(transition["post_start_source_key_fingerprints"].values())
    if (
        len(verifier_fingerprints) != 3
        or len(pre_start_fingerprints) != len(REQUIRED_PRE_START_CHECKS)
        or len(source_fingerprints) != len(REQUIRED_POST_START_CHECKS)
        or verifier_fingerprints & (pre_start_fingerprints | source_fingerprints)
        or pre_start_fingerprints & source_fingerprints
        or transition["post_start_verifier_key_fingerprint"]
        != ed25519_public_key_fingerprint(settings.canary_check_verifier_public_key)
    ):
        raise ValueError("Canary operator/risk/post-start verifier 身份未隔离或未绑定")
    target = transition["target_deployment_identity"]
    okx = config.get("okx", {})
    expected = {
        "release_commit": actual_runtime_identity["commit_sha"],
        "deployed_source_sha256": actual_runtime_identity["deployed_source_sha256"],
        "config_sha256": actual_runtime_identity["config_hash"],
        "account_uid": actual_runtime_identity["account_id"],
        "environment": actual_runtime_identity["environment"],
        "deployment_tier": settings.deployment_tier,
        "api_domain": str(okx.get("base_url", "")).rstrip("/"),
        "simulated": okx.get("simulated"),
        "permissions": list(settings.api_permissions),
        "ip_allowlist_sha256": settings.ip_allowlist_sha256,
        "unit": settings.deployment_unit,
        "host_image_sha256": settings.host_image_sha256,
        "key_fingerprint": credential_fingerprint(str(okx.get("api_key", ""))),
        "allowed_instruments": sorted(settings.allowed_instruments),
        "source_producer_inventory_sha256": (
            canary_source_producer_inventory_sha256(
                transition["source_producer_inventory"]
            )
        ),
    }
    mismatched = [key for key, value in expected.items() if target.get(key) != value]
    if mismatched:
        raise ValueError(f"Canary transition 未绑定实际 deployment: {sorted(mismatched)}")
    if transition["release_identity"] != actual_runtime_identity.get("release_identity"):
        raise ValueError("Canary transition 未绑定实际 exact release identity")
    if transition["strategy_identity"] != actual_runtime_identity.get("strategy_identity"):
        raise ValueError("Canary transition 未绑定实际 strategy/risk behavior")
    if (
        transition["demo_ledger_head_hash"] != deployment_receipt.get("ledger_head_hash")
        or policy["transition_sha256"] != identity_sha256(transition)
        or policy["target_deployment_identity_sha256"] != identity_sha256(target)
        or policy["allowed_instruments"] != target["allowed_instruments"]
        or policy["operator"] != transition["operator"]
        or policy["risk_approver"] != transition["risk_approver"]
        or policy_limit_projection(policy) != transition["canary_limits"]
    ):
        raise ValueError("Canary policy/transition/ledger 绑定不一致")
    enforce_policy_limits(policy, settings)
    return transition, policy
