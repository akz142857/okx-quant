#!/usr/bin/env python3
"""Create a strict, unsigned request for a dual-signed Demo soak epoch."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import UTC, date, datetime
from pathlib import Path

from okx_quant.application.demo_probe import (
    formal_probe_schedule_sha256,
    validate_formal_probe_schedule,
)
from okx_quant.config import load_yaml
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    redacted_config_hash,
)
from okx_quant.ops.demo_preflight import DemoDeploymentProfile
from okx_quant.ops.slo import SLO_V2_POLICY_HASH, SLO_V2_SCHEMA
from okx_quant.ops.stage_c_deployment_identity import (
    validate_stage_c_chaos_deployment_identity,
)
from okx_quant.research.costs import canonical_manifest_hash
from okx_quant.research.demo_soak import (
    CANARY_SOURCE_PRODUCER_NAMES,
    canary_source_producer_inventory_sha256,
    identity_hash,
    risk_behavior_hash,
    validate_canary_source_producer_inventory,
    validate_soak_epoch,
)

if __package__:
    from scripts.non_live_validation import verify_evidence_artifact
else:
    from non_live_validation import verify_evidence_artifact


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _aware(value: str) -> str:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("started-at 必须带时区")
    return parsed.astimezone(UTC).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--release-root", required=True, type=Path)
    parser.add_argument("--release-evidence", type=Path)
    parser.add_argument("--soak-epoch-id", required=True)
    parser.add_argument("--started-at", required=True, type=_aware)
    parser.add_argument("--strategy", required=True)
    parser.add_argument("--bar", required=True)
    parser.add_argument("--instrument", action="append", required=True)
    parser.add_argument("--interval-seconds", required=True, type=float)
    parser.add_argument("--probe-schedule", required=True, type=Path)
    parser.add_argument("--host-image-sha256", required=True)
    parser.add_argument("--launch-sha256", required=True)
    parser.add_argument("--monitor-public-key", required=True, type=Path)
    parser.add_argument("--risk-public-key", required=True, type=Path)
    parser.add_argument("--observation-public-key", required=True, type=Path)
    parser.add_argument(
        "--journal-snapshot-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--external-monitor-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--alert-receipts-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--backup-receipts-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--canary-producer-inventory",
        required=True,
        type=Path,
        help=(
            "12 类 Canary producer 部署清单；每项含 source_public_key "
            "以及独立 collector/signer Unix/systemd/IAM/path"
        ),
    )
    parser.add_argument(
        "--stage-c-chaos-deployment-identity",
        required=True,
        type=Path,
        help=(
            "预批准且冻结的 Stage-C exact-release/instrumented 候选部署身份 JSON"
        ),
    )
    parser.add_argument("--operator", required=True)
    parser.add_argument("--risk-approver", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise RuntimeError(f"拒绝覆盖 soak epoch request: {args.output}")
    cfg = load_yaml(str(args.config))
    profile = DemoDeploymentProfile.from_config(cfg)
    release_root = args.release_root.resolve(strict=True)
    if release_root != Path(__file__).resolve().parents[1]:
        raise RuntimeError("release-root 必须是当前执行脚本所属的 exact release")
    revision = release_root / "REVISION"
    evidence_path = (
        args.release_evidence
        if args.release_evidence is not None
        else release_root / "non-live-validation.json"
    )
    release_base = verify_evidence_artifact(evidence_path, revision)
    lock = release_root / "uv.lock"
    if not lock.is_file() or lock.is_symlink():
        raise RuntimeError("release 缺少受控 uv.lock")
    interpreter = Path(sys.executable).resolve(strict=True)
    release = {
        "git_commit": release_base["git_commit"],
        "git_tree_hash": release_base["git_tree_hash"],
        "source_manifest_sha256": release_base["source_manifest_sha256"],
        "dependency_lock_sha256": _sha256_file(lock),
        "interpreter_sha256": _sha256_file(interpreter),
    }
    instruments = sorted(set(args.instrument))
    strategy_identity = {
        "strategy": args.strategy,
        "bar": args.bar,
        "instruments": instruments,
        "interval_seconds": args.interval_seconds,
        "risk_parameters_sha256": risk_behavior_hash(cfg, args.strategy),
    }
    probe_schedule = validate_formal_probe_schedule(
        json.loads(args.probe_schedule.read_text(encoding="utf-8"))
    )
    started_at = datetime.fromisoformat(args.started_at).astimezone(UTC)
    if (
        started_at.time() != datetime.min.time()
        or date.fromisoformat(probe_schedule["slots"][0]["day"]) != started_at.date()
    ):
        raise RuntimeError("soak epoch 必须在 schedule 首日 UTC 00:00:00 开始")
    if sorted({str(item["inst_id"]) for item in probe_schedule["slots"]}) != instruments:
        raise RuntimeError("formal probe schedule instruments 必须精确匹配 strategy")
    cost_model_hash = canonical_manifest_hash(profile.cost_model_manifest)
    monitor_fingerprint = ed25519_public_key_fingerprint(args.monitor_public_key)
    risk_fingerprint = ed25519_public_key_fingerprint(args.risk_public_key)
    observation_fingerprint = ed25519_public_key_fingerprint(args.observation_public_key)
    role_fingerprints = {
        monitor_fingerprint,
        risk_fingerprint,
        observation_fingerprint,
    }
    if len(role_fingerprints) != 3:
        raise RuntimeError("soak epoch monitor/risk/observation 必须使用不同公钥")
    external_source_key_fingerprints = {
        "journal_snapshot": ed25519_public_key_fingerprint(args.journal_snapshot_public_key),
        "external_monitor": ed25519_public_key_fingerprint(args.external_monitor_public_key),
        "alert_receipts": ed25519_public_key_fingerprint(args.alert_receipts_public_key),
        "backup_receipts": ed25519_public_key_fingerprint(args.backup_receipts_public_key),
    }
    raw_inventory = json.loads(args.canary_producer_inventory.read_text(encoding="utf-8"))
    if not isinstance(raw_inventory, dict) or set(raw_inventory) != CANARY_SOURCE_PRODUCER_NAMES:
        raise ValueError("Canary producer inventory 必须精确覆盖 12 类 source")
    canary_inventory = {}
    for name, item in raw_inventory.items():
        if (
            not isinstance(item, dict)
            or "source_public_key" not in item
            or "source_key_fingerprint" in item
        ):
            raise ValueError(
                f"Canary producer {name} 必须提供 source_public_key 且不得自报 fingerprint"
            )
        public_key = Path(str(item["source_public_key"]))
        canary_inventory[name] = {
            key: value for key, value in item.items() if key != "source_public_key"
        } | {"source_key_fingerprint": (ed25519_public_key_fingerprint(public_key))}
    validate_canary_source_producer_inventory(canary_inventory)
    stage_c_chaos_deployment_identity = (
        validate_stage_c_chaos_deployment_identity(
            json.loads(
                args.stage_c_chaos_deployment_identity.read_text(
                    encoding="utf-8"
                )
            )
        )
    )
    all_control_fingerprints = {
        *role_fingerprints,
        *external_source_key_fingerprints.values(),
        *{item["source_key_fingerprint"] for item in canary_inventory.values()},
    }
    if len(all_control_fingerprints) != 19:
        raise RuntimeError(
            "epoch 的 control/external 与 12 类 Canary producer 必须使用十九个不同公钥"
        )
    key_fingerprints = sorted(
        {
            profile.key_fingerprint,
            *all_control_fingerprints,
        }
    )
    deployment = {
        "release_identity_sha256": identity_hash(release),
        "config_sha256": redacted_config_hash(cfg),
        "launch_sha256": args.launch_sha256,
        "account_uid": profile.account_uid,
        "environment": "demo",
        "unit": profile.unit_name,
        "host_image_sha256": args.host_image_sha256,
        "key_fingerprints": key_fingerprints,
        "canary_source_producer_inventory_sha256": (
            canary_source_producer_inventory_sha256(canary_inventory)
        ),
    }
    payload = validate_soak_epoch(
        {
            "version": 1,
            "action": "start-demo-soak-epoch",
            "soak_epoch_id": args.soak_epoch_id,
            "issued_at": int(time.time()),
            "started_at": args.started_at,
            "release_identity": release,
            "deployment_identity": deployment,
            "strategy_identity": strategy_identity,
            "probe_policy": {
                "minimum_notional_usdt": 5,
                "maximum_notional_usdt": 10,
                "minimum_daily_probes": 1,
                "maximum_daily_probes": 1,
                "schedule": probe_schedule,
                "schedule_sha256": formal_probe_schedule_sha256(probe_schedule),
                "cost_model_hash": cost_model_hash,
            },
            "slo_schema": SLO_V2_SCHEMA,
            "slo_policy_hash": SLO_V2_POLICY_HASH,
            "monitor_key_fingerprint": monitor_fingerprint,
            "risk_key_fingerprint": risk_fingerprint,
            "observation_key_fingerprint": observation_fingerprint,
            "external_source_key_fingerprints": (external_source_key_fingerprints),
            "canary_source_producer_inventory": canary_inventory,
            "stage_c_chaos_deployment_identity": (
                stage_c_chaos_deployment_identity
            ),
            "operator": args.operator,
            "risk_approver": args.risk_approver,
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
