#!/usr/bin/env python3
"""Build and dual-sign Demo-to-Canary transition and short-lived policy."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.config import ProductionSettings, load_yaml
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.infrastructure.immutable_bundle import verify_locked_object
from okx_quant.research.canary import (
    ALLOWED_DEPLOYMENT_DIFFERENCES,
    REQUIRED_POST_START_CHECKS,
    REQUIRED_PRE_START_CHECKS,
    canary_limits_from_settings,
    enforce_policy_limits,
    identity_sha256,
    target_identity_from_runtime,
    validate_canary_policy,
    validate_post_start_activation,
    validate_post_start_source_claims,
    validate_pre_start_source_claims,
    validate_transition,
    verify_canary_policy,
    verify_transition,
)
from okx_quant.research.demo_soak import (
    DemoObservationLedgerV2,
    validate_30_day_aggregate,
    verify_dual_signed_soak_epoch,
)


def _exclusive(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"拒绝覆盖 Canary artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _private_key(path: Path, label: str) -> None:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size <= 0
        or path.stat().st_mode & 0o077
    ):
        raise RuntimeError(f"{label} 必须是 owner-only 普通文件")


def _load_env(path: Path | None) -> None:
    if path is None:
        return
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        1,
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or not key.replace("_", "").isalnum() or not key[0].isalpha():
            raise ValueError(f"env 第 {line_number} 行非法")
        os.environ.setdefault(key, value.strip().strip("'\""))


def _aware_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp 必须带时区")
    return parsed


def _named_path(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name or not raw_path:
        raise argparse.ArgumentTypeError("必须使用 check=/absolute/path 格式")
    return name, Path(raw_path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    target = sub.add_parser("target-identity")
    target.add_argument("--soak-epoch", required=True, type=Path)
    target.add_argument("--epoch-monitor-public-key", required=True, type=Path)
    target.add_argument("--epoch-risk-public-key", required=True, type=Path)
    target.add_argument("--target-config", required=True, type=Path)
    target.add_argument("--target-env", type=Path)
    target.add_argument("--runtime-identity", required=True, type=Path)
    target.add_argument("--output", required=True, type=Path)
    transition = sub.add_parser("request-transition")
    transition.add_argument("--soak-epoch", required=True, type=Path)
    transition.add_argument("--epoch-monitor-public-key", required=True, type=Path)
    transition.add_argument("--epoch-risk-public-key", required=True, type=Path)
    transition.add_argument("--ledger", required=True, type=Path)
    transition.add_argument("--observation-public-key", required=True, type=Path)
    transition.add_argument(
        "--pre-start-check",
        required=True,
        action="append",
        type=_named_path,
        metavar="CHECK=PATH",
        help="每个 pre-start check 的独立 source 签名 artifact",
    )
    transition.add_argument(
        "--pre-start-source-public-key",
        required=True,
        action="append",
        type=_named_path,
        metavar="CHECK=PATH",
        help="每个 pre-start check 的独立 source 公钥",
    )
    transition.add_argument(
        "--post-start-verifier-public-key",
        required=True,
        type=Path,
    )
    transition.add_argument(
        "--post-start-source-public-key",
        required=True,
        action="append",
        type=_named_path,
        metavar="CHECK=PATH",
        help="每个 post-start check 的预绑定机器证据公钥；必须恰好提供五类检查",
    )
    transition.add_argument("--target-config", required=True, type=Path)
    transition.add_argument("--target-env", type=Path)
    transition.add_argument("--runtime-identity", required=True, type=Path)
    transition.add_argument("--operator", required=True)
    transition.add_argument("--risk-approver", required=True)
    transition.add_argument(
        "--pre-start-challenge",
        required=True,
        help="预先分发给七个 producer 的一次性 32 位 hex challenge",
    )
    transition.add_argument("--max-slippage", required=True, type=float)
    transition.add_argument("--lifetime-seconds", type=int, default=86400)
    transition.add_argument("--output", required=True, type=Path)
    policy = sub.add_parser("request-policy")
    policy.add_argument("--transition", required=True, type=Path)
    policy.add_argument("--operator-public-key", required=True, type=Path)
    policy.add_argument("--risk-public-key", required=True, type=Path)
    policy.add_argument("--target-config", required=True, type=Path)
    policy.add_argument("--target-env", type=Path)
    policy.add_argument("--rollback-owner", required=True)
    policy.add_argument("--lifetime-seconds", type=int, default=21600)
    policy.add_argument("--output", required=True, type=Path)
    activation = sub.add_parser("request-activation")
    activation.add_argument("--transition", required=True, type=Path)
    activation.add_argument("--policy", required=True, type=Path)
    activation.add_argument(
        "--operator-public-key",
        required=True,
        type=Path,
    )
    activation.add_argument(
        "--risk-public-key",
        required=True,
        type=Path,
    )
    activation.add_argument("--runtime-status", required=True, type=Path)
    activation.add_argument("--checks", required=True, type=Path)
    activation.add_argument(
        "--checks-verifier-public-key",
        required=True,
        type=Path,
    )
    activation.add_argument(
        "--minimum-retain-until",
        required=True,
        type=_aware_datetime,
    )
    activation.add_argument("--kms-key-id", required=True)
    activation.add_argument("--lifetime-seconds", type=int, default=600)
    activation.add_argument("--output", required=True, type=Path)
    sign_role = sub.add_parser("sign-role")
    sign_role.add_argument(
        "--role",
        required=True,
        choices=("operator", "risk"),
    )
    sign_role.add_argument("--request", required=True, type=Path)
    sign_role.add_argument("--private-key", required=True, type=Path)
    sign_role.add_argument("--output", required=True, type=Path)
    combine = sub.add_parser("combine-signatures")
    combine.add_argument("--request", required=True, type=Path)
    combine.add_argument("--operator-signature", required=True, type=Path)
    combine.add_argument("--risk-signature", required=True, type=Path)
    combine.add_argument("--operator-public-key", required=True, type=Path)
    combine.add_argument("--risk-public-key", required=True, type=Path)
    combine.add_argument("--output", required=True, type=Path)
    return parser


def _target_identity(args) -> tuple[dict, dict]:
    epoch = verify_dual_signed_soak_epoch(
        json.loads(args.soak_epoch.read_text(encoding="utf-8")),
        monitor_public_key=args.epoch_monitor_public_key,
        risk_public_key=args.epoch_risk_public_key,
    )
    _load_env(args.target_env)
    cfg = load_yaml(str(args.target_config))
    settings = ProductionSettings.from_config(cfg)
    if settings.deployment_tier != "canary":
        raise ValueError("target config 必须声明 deployment_tier=canary")
    runtime_identity = json.loads(args.runtime_identity.read_text(encoding="utf-8"))
    target = target_identity_from_runtime(
        release_identity=epoch["release_identity"],
        strategy_identity=epoch["strategy_identity"],
        source_producer_inventory=(
            epoch["canary_source_producer_inventory"]
        ),
        actual_runtime_identity=runtime_identity,
        config=cfg,
        host_image_sha256=settings.host_image_sha256,
        ip_allowlist_sha256=settings.ip_allowlist_sha256,
        api_permissions=settings.api_permissions,
        deployment_unit=settings.deployment_unit,
        allowed_instruments=settings.allowed_instruments,
    )
    return epoch, target


def _request_transition(args) -> dict:
    if not 300 <= args.lifetime_seconds <= 86400:
        raise ValueError("transition lifetime 必须位于 300..86400 秒")
    epoch, target = _target_identity(args)
    ledger = DemoObservationLedgerV2(
        args.ledger,
        epoch_payload=epoch,
        anchor_public_key=args.observation_public_key,
    )
    rows = ledger.load()
    clean_days = ledger.consecutive_clean_days(
        max_slippage_ratio=args.max_slippage,
        expected_git_commit=epoch["release_identity"]["git_commit"],
        expected_config_hash=epoch["deployment_identity"]["config_sha256"],
        expected_account_id=epoch["deployment_identity"]["account_uid"],
    )
    if clean_days < 30:
        raise RuntimeError("Demo-to-Canary transition 要求连续 30 个 clean day")
    validate_30_day_aggregate(ledger, clean_days=30)
    source_key_paths = dict(args.post_start_source_public_key)
    if len(source_key_paths) != len(args.post_start_source_public_key) or set(
        source_key_paths
    ) != set(REQUIRED_POST_START_CHECKS):
        raise ValueError("必须为每个 Canary post-start check 恰好绑定一个 source 公钥")
    source_key_fingerprints = {
        name: ed25519_public_key_fingerprint(path) for name, path in source_key_paths.items()
    }
    issued = int(time.time())
    if (
        len(args.pre_start_challenge) != 32
        or any(
            character not in "0123456789abcdef"
            for character in args.pre_start_challenge
        )
    ):
        raise ValueError("pre-start challenge 必须是 32 位小写 hex")
    target_config = load_yaml(str(args.target_config))
    target_settings = ProductionSettings.from_config(target_config)
    canary_limits = canary_limits_from_settings(target_settings)
    pre_start_paths = dict(args.pre_start_check)
    pre_start_key_paths = dict(args.pre_start_source_public_key)
    if (
        len(pre_start_paths) != len(args.pre_start_check)
        or len(pre_start_key_paths) != len(args.pre_start_source_public_key)
        or set(pre_start_paths) != set(REQUIRED_PRE_START_CHECKS)
        or set(pre_start_key_paths) != set(REQUIRED_PRE_START_CHECKS)
    ):
        raise ValueError(
            "必须为每个 Canary pre-start check 恰好提供一个签名 artifact 和 source 公钥"
        )
    pre_start_fingerprints = {
        name: ed25519_public_key_fingerprint(path) for name, path in pre_start_key_paths.items()
    }
    if len(set(pre_start_fingerprints.values())) != len(REQUIRED_PRE_START_CHECKS):
        raise ValueError("Canary pre-start checks 必须使用互不相同的 source 公钥")
    inventory = epoch["canary_source_producer_inventory"]
    requested_fingerprints = {
        **pre_start_fingerprints,
        **source_key_fingerprints,
    }
    if requested_fingerprints != {
        name: item["source_key_fingerprint"] for name, item in inventory.items()
    }:
        raise ValueError("Canary transition source keys 未精确匹配 epoch producer inventory")
    pre_start_checks = {}
    for name in REQUIRED_PRE_START_CHECKS:
        raw = pre_start_paths[name].read_bytes()
        source = verify_ed25519_artifact(
            json.loads(raw),
            pre_start_key_paths[name],
            label=f"Canary pre-start source {name}",
        )
        validate_pre_start_source_claims(
            source,
            check=name,
            target=target,
            release_identity=epoch["release_identity"],
            demo_soak_epoch_id=epoch["soak_epoch_id"],
            producer_inventory=inventory,
            pre_start_challenge=args.pre_start_challenge,
            now=issued,
            expected_limits=canary_limits,
        )
        pre_start_checks[name] = {
            "observed_at": source["observed_at"],
            "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "evidence_bytes": len(raw),
            "artifact_bytes_base64": base64.b64encode(raw).decode("ascii"),
            "source_public_key_pem_base64": base64.b64encode(
                pre_start_key_paths[name].read_bytes()
            ).decode("ascii"),
        }
    return validate_transition(
        {
            "version": 1,
            "action": "authorize-demo-to-canary-transition",
            "transition_id": f"transition-{uuid.uuid4().hex}",
            "issued_at": issued,
            "expires_at": issued + args.lifetime_seconds,
            "demo_soak_epoch_id": epoch["soak_epoch_id"],
            "demo_ledger_head_hash": rows[-1]["entry_hash"],
            "release_identity": epoch["release_identity"],
            "strategy_identity": epoch["strategy_identity"],
            "target_deployment_identity": target,
            "allowed_deployment_differences": ALLOWED_DEPLOYMENT_DIFFERENCES,
            "required_pre_start_checks": REQUIRED_PRE_START_CHECKS,
            "pre_start_checks": pre_start_checks,
            "pre_start_source_key_fingerprints": (pre_start_fingerprints),
            "canary_limits": canary_limits,
            "required_post_start_checks": REQUIRED_POST_START_CHECKS,
            "post_start_verifier_key_fingerprint": (
                ed25519_public_key_fingerprint(args.post_start_verifier_public_key)
            ),
            "post_start_source_key_fingerprints": source_key_fingerprints,
            "source_producer_inventory": inventory,
            "source_producer_inventory_sha256": (
                epoch["deployment_identity"][
                    "canary_source_producer_inventory_sha256"
                ]
            ),
            "pre_start_challenge": args.pre_start_challenge,
            "operator": args.operator,
            "risk_approver": args.risk_approver,
        }
    )


def _request_policy(args) -> dict:
    if not 300 <= args.lifetime_seconds <= 21600:
        raise ValueError("Canary policy lifetime 必须位于 300..21600 秒")
    artifact = json.loads(args.transition.read_text(encoding="utf-8"))
    transition = verify_transition(
        artifact,
        operator_public_key=args.operator_public_key,
        risk_public_key=args.risk_public_key,
    )
    _load_env(args.target_env)
    cfg = load_yaml(str(args.target_config))
    settings = ProductionSettings.from_config(cfg)
    issued = int(time.time())
    policy = validate_canary_policy(
        {
            "version": 1,
            "action": "authorize-short-lived-canary",
            "policy_id": f"canary-{uuid.uuid4().hex}",
            "issued_at": issued,
            "expires_at": issued + args.lifetime_seconds,
            "transition_sha256": identity_sha256(transition),
            "target_deployment_identity_sha256": identity_sha256(
                transition["target_deployment_identity"]
            ),
            "allowed_instruments": sorted(settings.allowed_instruments),
            "max_order_notional_usdt": float(settings.max_position_notional_usdt),
            "max_order_intents_per_hour": settings.max_order_intents_per_hour,
            "max_concurrent_positions": settings.max_open_positions,
            "max_total_exposure_usdt": float(settings.max_total_exposure_usdt),
            "max_order_loss_usdt": float(settings.max_order_loss_usdt),
            "max_daily_loss_usdt": float(settings.max_daily_loss_usdt),
            "max_drawdown_ratio": float(settings.max_drawdown_ratio),
            "max_slippage_ratio": float(settings.max_slippage_ratio),
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
            "operator": transition["operator"],
            "risk_approver": transition["risk_approver"],
            "rollback_owner": args.rollback_owner,
            "production_promotion": "forbidden",
        }
    )
    enforce_policy_limits(policy, settings)
    if {name: policy[name] for name in transition["canary_limits"]} != transition["canary_limits"]:
        raise ValueError("Canary policy limits 未精确匹配 transition 冻结 config")
    return policy


def _request_activation(args) -> dict:
    if not 300 <= args.lifetime_seconds <= 900:
        raise ValueError("Canary activation lifetime 必须位于 300..900 秒")
    if args.minimum_retain_until.astimezone(UTC) < (datetime.now(UTC) + timedelta(days=35)):
        raise ValueError("Canary post-start evidence 至少保留 35 天")
    transition = verify_transition(
        json.loads(args.transition.read_text(encoding="utf-8")),
        operator_public_key=args.operator_public_key,
        risk_public_key=args.risk_public_key,
    )
    policy = verify_canary_policy(
        json.loads(args.policy.read_text(encoding="utf-8")),
        operator_public_key=args.operator_public_key,
        risk_public_key=args.risk_public_key,
    )
    runtime = json.loads(args.runtime_status.read_text(encoding="utf-8"))
    checks = json.loads(args.checks.read_text(encoding="utf-8"))
    verifier_fingerprint = ed25519_public_key_fingerprint(args.checks_verifier_public_key)
    if (
        not isinstance(runtime, dict)
        or not str(runtime.get("runtime_instance_id", "")).strip()
        or not str(runtime.get("boot_id", "")).strip()
        or type(runtime.get("canary_startup_hard_epoch")) is not int
        or runtime["canary_startup_hard_epoch"] <= 0
        or not str(runtime.get("canary_startup_nonce", "")).strip()
        or runtime.get("canary_startup_latch_reason") != "canary_post_start_activation_pending"
        or runtime.get("account_uid") != transition["target_deployment_identity"]["account_uid"]
        or runtime.get("deployment_unit") != transition["target_deployment_identity"]["unit"]
        or runtime.get("demo_soak_epoch_id") != transition["demo_soak_epoch_id"]
        or runtime.get("canary_transition_sha256") != identity_sha256(transition)
        or runtime.get("canary_policy_sha256") != identity_sha256(policy)
        or runtime.get("canary_target_deployment_identity_sha256")
        != identity_sha256(transition["target_deployment_identity"])
    ):
        raise ValueError("runtime status 缺少或错绑 Canary startup/deployment identity")
    if policy["transition_sha256"] != identity_sha256(transition) or policy[
        "target_deployment_identity_sha256"
    ] != identity_sha256(transition["target_deployment_identity"]):
        raise ValueError("Canary activation 的 transition/policy 不一致")
    if transition["post_start_verifier_key_fingerprint"] != verifier_fingerprint:
        raise ValueError("Canary checks verifier key 未绑定 transition")
    verified_checks = {}
    for name in REQUIRED_POST_START_CHECKS:
        locator = checks.get(name) if isinstance(checks, dict) else None
        if not isinstance(locator, dict):
            raise ValueError(f"Canary post-start check {name} 缺失")
        payload = verify_locked_object(
            object_uri=locator["evidence_uri"],
            version_id=locator["evidence_version_id"],
            expected_sha256=locator["evidence_sha256"],
            expected_bytes=locator["evidence_bytes"],
            minimum_retain_until=args.minimum_retain_until,
            expected_kms_key_id=args.kms_key_id,
        )
        claims = verify_ed25519_artifact(
            json.loads(payload),
            args.checks_verifier_public_key,
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
            or claims["runtime_instance_id"] != runtime["runtime_instance_id"]
            or claims["boot_id"] != runtime["boot_id"]
            or claims["account_uid"] != runtime["account_uid"]
            or claims["deployment_unit"] != runtime["deployment_unit"]
            or claims["demo_soak_epoch_id"] != runtime["demo_soak_epoch_id"]
            or claims["transition_sha256"] != runtime["canary_transition_sha256"]
            or claims["policy_sha256"] != runtime["canary_policy_sha256"]
            or claims["target_deployment_identity_sha256"]
            != runtime["canary_target_deployment_identity_sha256"]
            or not isinstance(claims["source_evidence_sha256"], str)
            or len(claims["source_evidence_sha256"]) != 64
            or not isinstance(claims["source_key_fingerprint"], str)
            or len(claims["source_key_fingerprint"]) != 64
            or claims["source_key_fingerprint"]
            != transition["post_start_source_key_fingerprints"][name]
        ):
            raise ValueError(f"Canary post-start check {name} 语义/运行时绑定非法")
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
            runtime_instance_id=runtime["runtime_instance_id"],
            boot_id=runtime["boot_id"],
            account_uid=runtime["account_uid"],
            deployment_unit=runtime["deployment_unit"],
            demo_soak_epoch_id=runtime["demo_soak_epoch_id"],
            transition_sha256=runtime["canary_transition_sha256"],
            policy_sha256=runtime["canary_policy_sha256"],
            target_deployment_identity_sha256=runtime["canary_target_deployment_identity_sha256"],
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
            now=int(time.time()),
        )
        verified_checks[name] = {
            **locator,
            "artifact_bytes_base64": base64.b64encode(payload).decode("ascii"),
        }
    issued = int(time.time())
    return validate_post_start_activation(
        {
            "version": 1,
            "action": "activate-canary-entries-after-post-start",
            "issued_at": issued,
            "expires_at": issued + args.lifetime_seconds,
            "transition_sha256": identity_sha256(transition),
            "policy_sha256": identity_sha256(policy),
            "target_deployment_identity_sha256": identity_sha256(
                transition["target_deployment_identity"]
            ),
            "runtime_instance_id": runtime["runtime_instance_id"],
            "boot_id": runtime["boot_id"],
            "expected_startup_hard_epoch": runtime["canary_startup_hard_epoch"],
            "startup_nonce": runtime["canary_startup_nonce"],
            "latch_reason": runtime["canary_startup_latch_reason"],
            "checks_verifier_key_fingerprint": verifier_fingerprint,
            "source_key_fingerprints": transition["post_start_source_key_fingerprints"],
            "checks": verified_checks,
            "operator": transition["operator"],
            "risk_approver": transition["risk_approver"],
        }
    )


def _validated_request(path: Path) -> dict:
    request = json.loads(path.read_text(encoding="utf-8"))
    action = request.get("action") if isinstance(request, dict) else ""
    if action == "authorize-demo-to-canary-transition":
        return validate_transition(request)
    if action == "authorize-short-lived-canary":
        return validate_canary_policy(request)
    if action == "activate-canary-entries-after-post-start":
        return validate_post_start_activation(request)
    raise ValueError("未知 Canary artifact action")


def _sign_role(args) -> dict:
    _private_key(args.private_key, f"{args.role} private key")
    payload = _validated_request(args.request)
    signature = sign_ed25519_payload(payload, args.private_key)["signature"]
    return {
        "version": 1,
        "action": "sign-canary-request-role",
        "role": args.role,
        "request_sha256": identity_sha256(payload),
        "signature": signature,
    }


def _combine_signatures(args) -> dict:
    payload = _validated_request(args.request)
    request_sha256 = identity_sha256(payload)
    operator_fingerprint = ed25519_public_key_fingerprint(args.operator_public_key)
    risk_fingerprint = ed25519_public_key_fingerprint(args.risk_public_key)
    if operator_fingerprint == risk_fingerprint:
        raise ValueError("Canary operator/risk 必须使用不同公钥")
    signatures: dict[str, str] = {}
    for role, path, public_key in (
        ("operator", args.operator_signature, args.operator_public_key),
        ("risk", args.risk_signature, args.risk_public_key),
    ):
        partial = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(partial, dict)
            or set(partial)
            != {
                "version",
                "action",
                "role",
                "request_sha256",
                "signature",
            }
            or partial["version"] != 1
            or partial["action"] != "sign-canary-request-role"
            or partial["role"] != role
            or partial["request_sha256"] != request_sha256
        ):
            raise ValueError(f"Canary {role} 部分签名未绑定当前 request")
        claims = verify_ed25519_artifact(
            {
                "payload": payload,
                "signature": partial["signature"],
            },
            public_key,
            label=f"Canary {role} partial signature",
        )
        if claims != payload:
            raise ValueError(f"Canary {role} 部分签名 payload 不一致")
        signatures[role] = partial["signature"]
    return {
        "payload": payload,
        "operator_signature": signatures["operator"],
        "risk_signature": signatures["risk"],
    }


def _legacy_sign_disabled(_args) -> dict:
    """Refuse the former one-process dual-private-key signing path."""
    raise RuntimeError(
        "Canary 双私钥同进程签名已禁用；请在两台审批设备分别执行 "
        "sign-role，再由无私钥节点 combine-signatures"
    )


def _sign(args) -> dict:
    """Compatibility trap for callers of the removed unsafe helper."""
    return _legacy_sign_disabled(args)


def main() -> int:
    args = _parser().parse_args()
    if args.command == "target-identity":
        _epoch, result = _target_identity(args)
    elif args.command == "request-transition":
        result = _request_transition(args)
    elif args.command == "request-policy":
        result = _request_policy(args)
    elif args.command == "request-activation":
        result = _request_activation(args)
    elif args.command == "sign-role":
        result = _sign_role(args)
    else:
        result = _combine_signatures(args)
    _exclusive(args.output, result)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
