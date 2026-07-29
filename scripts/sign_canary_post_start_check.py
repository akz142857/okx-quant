#!/usr/bin/env python3
"""Sign one runtime-bound Canary post-start check in the verifier domain."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import time
from pathlib import Path
from urllib.parse import urlparse

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.research.canary import (
    REQUIRED_POST_START_CHECKS,
    identity_sha256,
    validate_post_start_source_claims,
    verify_transition,
)

_SOURCE_KEYS = {
    "version",
    "action",
    "check",
    "observed_at",
    "runtime_instance_id",
    "boot_id",
    "facts",
}


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_s3(value: object) -> bool:
    parsed = urlparse(str(value))
    return parsed.scheme == "s3" and bool(parsed.netloc) and bool(parsed.path.strip("/"))


def _validate_facts(check: str, facts: object, *, observed_at: int) -> None:
    if not isinstance(facts, dict):
        raise ValueError("Canary source facts 必须是对象")
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
            or not _nonempty(facts["version_id"])
            or not isinstance(facts["sha256"], str)
            or len(facts["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in facts["sha256"])
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
            or not _nonempty(facts["account_uid"])
            or facts["position_state"] not in {"flat", "protected"}
            or type(facts["non_dust_position_count"]) is not int
            or facts["non_dust_position_count"] < 0
            or type(facts["active_protection_count"]) is not int
            or facts["active_protection_count"] < 0
            or facts["unprotected_position_count"] != 0
            or facts["checked_via"] != "rest_and_business_ws"
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
            raise ValueError("source 未证明账户 flat 或全部仓位已保护")
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
            or not isinstance(facts["duration_seconds"], (int, float))
            or not 0 <= float(facts["duration_seconds"]) <= 60
        ):
            raise ValueError("source 未证明 REST/WS reconciliation safe")
        return
    raise ValueError(f"未知 Canary post-start check: {check}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        required=True,
        choices=REQUIRED_POST_START_CHECKS,
    )
    parser.add_argument("--runtime-status", required=True, type=Path)
    parser.add_argument("--transition", required=True, type=Path)
    parser.add_argument(
        "--operator-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--risk-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--source-evidence",
        required=True,
        type=Path,
        help="由独立事实生产者签名的机器证据",
    )
    parser.add_argument(
        "--source-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    transition = verify_transition(
        json.loads(args.transition.read_text(encoding="utf-8")),
        operator_public_key=args.operator_public_key,
        risk_public_key=args.risk_public_key,
    )
    if args.output.exists() or args.output.is_symlink():
        raise RuntimeError("拒绝覆盖 Canary post-start check")
    key_info = args.private_key.lstat()
    if (
        not stat.S_ISREG(key_info.st_mode)
        or args.private_key.is_symlink()
        or stat.S_IMODE(key_info.st_mode) != 0o600
        or key_info.st_size <= 0
    ):
        raise RuntimeError("Canary verifier 私钥必须是 0600 普通文件")
    runtime = json.loads(args.runtime_status.read_text(encoding="utf-8"))
    if (
        not isinstance(runtime, dict)
        or runtime.get("live") is not True
        or not str(runtime.get("runtime_instance_id", "")).strip()
        or not str(runtime.get("boot_id", "")).strip()
        or not str(runtime.get("account_uid", "")).strip()
        or not str(runtime.get("deployment_unit", "")).strip()
        or not str(runtime.get("demo_soak_epoch_id", "")).strip()
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(runtime.get("canary_startup_nonce", "")),
        )
        or type(runtime.get("canary_startup_hard_epoch")) is not int
        or runtime["canary_startup_hard_epoch"] <= 0
        or any(
            not isinstance(runtime.get(key), str) or len(runtime[key]) != 64
            for key in (
                "canary_transition_sha256",
                "canary_policy_sha256",
                "canary_target_deployment_identity_sha256",
            )
        )
    ):
        raise RuntimeError("runtime status 未绑定 safety kernel/deployment/account/epoch")
    if (
        runtime["canary_transition_sha256"]
        != identity_sha256(transition)
        or runtime["canary_target_deployment_identity_sha256"]
        != identity_sha256(
            transition["target_deployment_identity"]
        )
        or runtime["account_uid"]
        != transition["target_deployment_identity"]["account_uid"]
        or runtime["deployment_unit"]
        != transition["target_deployment_identity"]["unit"]
        or runtime["demo_soak_epoch_id"]
        != transition["demo_soak_epoch_id"]
    ):
        raise RuntimeError("runtime status 未绑定已双签 transition")
    source_raw = args.source_evidence.read_bytes()
    source = verify_ed25519_artifact(
        json.loads(source_raw),
        args.source_public_key,
        label=f"Canary {args.check} source evidence",
    )
    observed_at = int(time.time())
    source = validate_post_start_source_claims(
        source,
        check=args.check,
        runtime_instance_id=runtime["runtime_instance_id"],
        boot_id=runtime["boot_id"],
        account_uid=runtime["account_uid"],
        deployment_unit=runtime["deployment_unit"],
        demo_soak_epoch_id=runtime["demo_soak_epoch_id"],
        transition_sha256=runtime["canary_transition_sha256"],
        policy_sha256=runtime["canary_policy_sha256"],
        target_deployment_identity_sha256=runtime[
            "canary_target_deployment_identity_sha256"
        ],
        startup_nonce=runtime["canary_startup_nonce"],
        expected_startup_hard_epoch=runtime[
            "canary_startup_hard_epoch"
        ],
        producer_inventory=transition[
            "source_producer_inventory"
        ],
        target_key_fingerprint=transition[
            "target_deployment_identity"
        ]["key_fingerprint"],
        now=observed_at,
    )
    verifier_fingerprint = ed25519_public_key_fingerprint(
        args.private_key,
        private_key=True,
    )
    source_fingerprint = ed25519_public_key_fingerprint(args.source_public_key)
    if verifier_fingerprint == source_fingerprint:
        raise RuntimeError("Canary check verifier 与事实生产者必须使用不同 Ed25519 身份")
    artifact = sign_ed25519_payload(
        {
            "version": 1,
            "action": "attest-canary-post-start-check",
            "check": args.check,
            "passed": True,
            "observed_at": source["observed_at"],
            "runtime_instance_id": runtime["runtime_instance_id"],
            "boot_id": runtime["boot_id"],
            "account_uid": runtime["account_uid"],
            "deployment_unit": runtime["deployment_unit"],
            "demo_soak_epoch_id": runtime["demo_soak_epoch_id"],
            "transition_sha256": runtime["canary_transition_sha256"],
            "policy_sha256": runtime["canary_policy_sha256"],
            "target_deployment_identity_sha256": runtime[
                "canary_target_deployment_identity_sha256"
            ],
            "source_evidence_sha256": hashlib.sha256(source_raw).hexdigest(),
            "source_key_fingerprint": source_fingerprint,
            "source_artifact_bytes_base64": base64.b64encode(source_raw).decode("ascii"),
            "source_public_key_pem_base64": base64.b64encode(
                args.source_public_key.read_bytes()
            ).decode("ascii"),
        },
        args.private_key,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            artifact,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
