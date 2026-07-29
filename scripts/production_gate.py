#!/usr/bin/env python3
"""记录 demo 日证据或评估生产准入门槛。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
import time
from datetime import UTC, date, datetime
from importlib import metadata as importlib_metadata
from pathlib import Path

from okx_quant.application.approval import (
    canonical_bytes,
    production_config_hash,
    verify_ed25519_artifact,
)
from okx_quant.config import ProductionSettings, load_yaml
from okx_quant.infrastructure.evidence import ed25519_public_key_fingerprint
from okx_quant.infrastructure.immutable_bundle import (
    verify_independent_bundle_verification,
)
from okx_quant.ops.demo_chaos_evidence import (
    load_verified_stage_c_receipts,
    verify_stage_c_coverage,
)
from okx_quant.ops.empty_host_restore import (
    read_verified_empty_host_restore,
)
from okx_quant.research.admission import (
    NOT_APPLICABLE_CANARY_READINESS_SHA256,
    AdmissionApprovalVerifier,
    AdmissionGate,
    build_admission_request,
)
from okx_quant.research.demo_soak import (
    DemoObservationLedgerV2,
    canary_source_producer_inventory_sha256,
    risk_behavior_hash,
    validate_30_day_aggregate,
    verify_dual_signed_soak_epoch,
)


def _nonnegative_finite(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("必须是非负有限数")
    return value


def _slippage_ratio(raw: str) -> float:
    value = _nonnegative_finite(raw)
    if value > 1:
        raise argparse.ArgumentTypeError("滑点比例必须位于 [0, 1]")
    return value


def _aware_datetime(raw: str) -> datetime:
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "时间必须是 ISO-8601"
        ) from exc
    if value.tzinfo is None or value.utcoffset() is None:
        raise argparse.ArgumentTypeError("时间必须带时区")
    return value.astimezone(UTC)


def _add_evaluation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--max-slippage", type=_slippage_ratio, required=True)
    parser.add_argument(
        "--approved-max-stress-loss",
        type=_nonnegative_finite,
        required=True,
        help="来自风险审批而不是 evidence JSON 的固定预算",
    )
    parser.add_argument(
        "--observation-public-key",
        required=True,
        type=Path,
        help="独立 demo 监控身份的 Ed25519 公钥",
    )
    parser.add_argument("--soak-epoch", required=True, type=Path)
    parser.add_argument(
        "--epoch-monitor-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--epoch-risk-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--research-public-key",
        required=True,
        type=Path,
        help="独立研究 policy/runner attestation Ed25519 公钥",
    )
    parser.add_argument(
        "--bundle-signing-public-key",
        required=True,
        type=Path,
        help="每日 Object-Lock bundle publisher 的 Ed25519 公钥",
    )
    parser.add_argument(
        "--independent-verifier-public-key",
        required=True,
        type=Path,
        help="第二故障域 exact-version 重算身份的 Ed25519 公钥",
    )
    parser.add_argument(
        "--stage-c-raw-observer-public-key",
        required=True,
        type=Path,
        help="Stage-C 原始事件 observer 的独立 Ed25519 公钥",
    )
    parser.add_argument(
        "--stage-c-trust-manifest",
        required=True,
        type=Path,
        help=(
            "Stage-C frozen raw events 与逐场景 registrar/capability/"
            "source trust roots 的严格 manifest"
        ),
    )
    parser.add_argument(
        "--independent-verifier-attestations-dir",
        required=True,
        type=Path,
        help="按 <UTC-day>.json 保存的独立重算签名目录",
    )
    parser.add_argument(
        "--stage-c-drill-receipts-dir",
        required=True,
        type=Path,
        help="WP4/WP5 严格 drill result，按 <scenario>.json 保存",
    )
    parser.add_argument(
        "--stage-c-drill-manifests-dir",
        required=True,
        type=Path,
        help="WP4/WP5 detached signed WORM manifest 目录",
    )
    parser.add_argument(
        "--stage-c-drill-bundle-receipts-dir",
        required=True,
        type=Path,
        help="WP4/WP5 exact-version bundle receipt 目录",
    )
    parser.add_argument(
        "--stage-c-drill-independent-attestations-dir",
        required=True,
        type=Path,
        help="独立故障域 exact-version GET 签名证明目录",
    )
    parser.add_argument(
        "--stage-c-release-frozen-at",
        required=True,
        type=_aware_datetime,
        help="最终候选 freeze 的带时区 ISO-8601 时间",
    )
    parser.add_argument(
        "--empty-host-restore-evidence",
        required=True,
        type=Path,
        help="最近 31 日内的签名 empty-host 端到端恢复证据",
    )
    parser.add_argument(
        "--empty-host-restore-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--empty-host-restore-key-id",
        required=True,
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument(
        "--release-commit-file",
        required=True,
        type=Path,
    )
    parser.add_argument("--launch-manifest", type=Path)
    parser.add_argument("--strategy")
    parser.add_argument("--bar")
    parser.add_argument(
        "--instrument",
        dest="instruments",
        action="append",
    )
    parser.add_argument("--interval", type=_nonnegative_finite)


def _resolve_launch_arguments(args) -> None:
    manual = (args.strategy, args.bar, args.instruments, args.interval)
    if args.launch_manifest:
        if any(value is not None for value in manual):
            raise ValueError(
                "--launch-manifest 不能与手工 strategy/bar/instrument/interval 混用"
            )
        if __package__:
            from scripts.launch_manifest import load_launch_manifest
        else:
            from launch_manifest import load_launch_manifest
        launch = load_launch_manifest(args.launch_manifest)
        args.strategy = launch["strategy"]
        args.bar = launch["bar"]
        args.instruments = launch["instruments"]
        args.interval = float(launch["interval_seconds"])
    elif any(value is None for value in manual):
        raise ValueError(
            "必须提供 --launch-manifest，或完整手工 "
            "strategy/bar/instrument/interval"
        )


def _runtime_python_executable() -> tuple[Path, Path, bytes]:
    """Return a controlled venv launcher, resolved interpreter, and link identity."""
    executable = Path(sys.executable)
    if not executable.is_absolute() or not executable.exists():
        raise ValueError("实际 Python executable 必须是存在的绝对路径")
    executable_lstat = executable.lstat()
    resolved = executable.resolve(strict=True)
    resolved_stat = resolved.stat()
    link_identity = (
        os.readlink(executable).encode("utf-8")
        if executable.is_symlink()
        else b"<regular-file>"
    )
    if (
        not stat.S_ISREG(resolved_stat.st_mode)
        or not (resolved_stat.st_mode & stat.S_IXUSR)
        or resolved_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (
            not stat.S_ISLNK(executable_lstat.st_mode)
            and not stat.S_ISREG(executable_lstat.st_mode)
        )
    ):
        raise ValueError(
            "实际 Python executable/target 必须是不可由 group/other 写入的"
            "可执行普通文件或受控符号链接"
        )
    candidate = executable.parent
    while True:
        candidate_stat = candidate.lstat()
        if (
            stat.S_ISLNK(candidate_stat.st_mode)
            or candidate_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("实际 Python executable 目录链不安全")
        if candidate == candidate.parent:
            break
        candidate = candidate.parent
    return executable, resolved, link_identity


def _deployed_source_hash() -> str:
    """Hash release code, interpreter, lockfiles, and installed dependency bytes."""
    package_spec = importlib.util.find_spec("okx_quant")
    main_spec = importlib.util.find_spec("main")
    if (
        package_spec is None
        or package_spec.submodule_search_locations is None
        or main_spec is None
        or main_spec.origin is None
    ):
        raise ValueError("无法定位实际部署的 main/okx_quant Python 源码")
    scripts_root = Path(__file__).parent
    expected_main = scripts_root.parent / "main.py"
    if (
        Path(main_spec.origin).resolve() != expected_main.resolve()
        or not expected_main.is_file()
        or expected_main.is_symlink()
    ):
        raise ValueError("实际部署 main.py 与 production gate 不属于同一发布目录")
    package_root = Path(next(iter(package_spec.submodule_search_locations)))
    python_executable, python_target, python_link_identity = (
        _runtime_python_executable()
    )
    files = [
        (expected_main, "main.py"),
        (python_target, "runtime/python-interpreter"),
    ]
    for release_file in ("pyproject.toml", "uv.lock"):
        files.append(
            (scripts_root.parent / release_file, release_file)
        )
    files.extend(
        (path, f"scripts/{path.name}")
        for path in sorted(scripts_root.glob("*.py"))
    )
    files.extend(
        (path, path.relative_to(package_root.parent).as_posix())
        for path in sorted(package_root.rglob("*.py"))
    )
    pending = ["okx-quant"]
    visited_distributions: set[str] = set()
    while pending:
        requested_name = pending.pop()
        normalized_name = re.sub(r"[-_.]+", "-", requested_name.lower())
        if normalized_name in visited_distributions:
            continue
        try:
            distribution = importlib_metadata.distribution(requested_name)
        except importlib_metadata.PackageNotFoundError:
            continue
        visited_distributions.add(normalized_name)
        distribution_name = str(
            distribution.metadata.get("Name", requested_name)
        )
        distribution_label = re.sub(
            r"[-_.]+", "-", distribution_name.lower()
        )
        for relative in sorted(
            distribution.files or (),
            key=lambda item: str(item),
        ):
            installed = Path(distribution.locate_file(relative))
            files.append((
                installed,
                f"installed/{distribution_label}/{relative}",
            ))
        for requirement in distribution.requires or ():
            if "extra ==" in requirement:
                continue
            match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
            if match:
                pending.append(match.group(1))
    digest = hashlib.sha256()
    digest.update(
        b"runtime/python-launch-path\0"
        + hashlib.sha256(
            str(python_executable).encode("utf-8")
            + b"\0"
            + python_link_identity
        ).digest()
    )
    seen: set[str] = set()
    for path, label in files:
        if (
            label in seen
            or not path.is_file()
            or path.is_symlink()
        ):
            raise ValueError(f"部署源码缺失、重复或为符号链接: {label}")
        seen.add(label)
        content = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                content.update(chunk)
        content_hash = content.digest()
        digest.update(label.encode("utf-8") + b"\0" + content_hash)
    return digest.hexdigest()


def _redact_strategy_secrets(value):
    if isinstance(value, dict):
        return {
            key: (
                "<redacted>"
                if _is_secret_key(str(key))
                else _redact_strategy_secrets(item)
            )
            for key, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [_redact_strategy_secrets(item) for item in value]
    return value


def _is_secret_key(key: str) -> bool:
    normalized = key.lower()
    return bool(
        normalized
        in {
            "api_key",
            "secret_key",
            "passphrase",
            "password",
            "private_key",
            "credential",
            "credentials",
        }
        or normalized.endswith(
            (
                "_api_key",
                "_secret_key",
                "_passphrase",
                "_password",
                "_private_key",
                "_token",
            )
        )
    )


def _runtime_config_hash(
    settings: ProductionSettings,
    cfg: dict,
    *,
    strategy: str,
    bar: str,
    instruments: list[str],
    interval: float,
    deployed_source_sha256: str,
) -> str:
    if not strategy.strip() or not re.fullmatch(r"[0-9A-Za-z_-]{1,64}", strategy):
        raise ValueError("实际启动 strategy 非法")
    if not re.fullmatch(r"(?:[1-9][0-9]*[mH]|1D)", bar):
        raise ValueError("实际启动 bar 非法")
    if interval <= 0:
        raise ValueError("实际启动 interval 必须大于 0")
    if (
        not instruments
        or len(set(instruments)) != len(instruments)
        or any(item not in settings.allowed_instruments for item in instruments)
    ):
        raise ValueError("实际启动 instruments 必须是 allowed_instruments 的唯一非空子集")
    material = {
        "production_config_hash": production_config_hash(settings, cfg),
        # Bind every behavior-affecting config section; only secret values are
        # replaced, never whole sections or parameter names.
        "redacted_full_config": _redact_strategy_secrets(cfg),
        "live": {
            "strategy": strategy,
            "bar": bar,
            "instruments": instruments,
            "interval_seconds": interval,
        },
        "deployed_source_sha256": deployed_source_sha256,
    }
    return hashlib.sha256(canonical_bytes(material)).hexdigest()


def _actual_canary_release_identity(
    *,
    release_root: Path,
    release_commit_file: Path,
    interpreter: Path,
    evidence_verifier=None,
) -> dict:
    root = release_root.resolve(strict=True)
    if release_commit_file.resolve().parent != root:
        raise ValueError(
            "Canary REVISION 必须来自当前执行脚本所属的 exact release"
        )
    if evidence_verifier is None:
        if __package__:
            from scripts.non_live_validation import (
                verify_evidence_artifact as evidence_verifier,
            )
        else:
            from non_live_validation import (
                verify_evidence_artifact as evidence_verifier,
            )
    release_evidence = evidence_verifier(
        root / "non-live-validation.json",
        release_commit_file,
    )
    lock = root / "uv.lock"
    if not lock.is_file() or lock.is_symlink():
        raise ValueError("Canary exact release 缺少受控 uv.lock")
    if not interpreter.is_file() or interpreter.is_symlink():
        raise ValueError("Canary exact release interpreter 非法")
    return {
        "git_commit": str(release_evidence["git_commit"]).lower(),
        "git_tree_hash": str(release_evidence["git_tree_hash"]).lower(),
        "source_manifest_sha256": str(
            release_evidence["source_manifest_sha256"]
        ).lower(),
        "dependency_lock_sha256": hashlib.sha256(
            lock.read_bytes()
        ).hexdigest(),
        "interpreter_sha256": hashlib.sha256(
            interpreter.read_bytes()
        ).hexdigest(),
    }


def _actual_runtime_identity(
    *,
    config_path: Path,
    release_commit_file: Path,
    strategy: str,
    bar: str,
    instruments: list[str],
    interval: float,
) -> dict:
    if (
        not release_commit_file.is_file()
        or release_commit_file.is_symlink()
    ):
        raise ValueError("release commit file 必须是普通文件且不能是符号链接")
    commit_sha = release_commit_file.read_text(encoding="ascii").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise ValueError("release commit file 必须包含完整 40 位提交 SHA")
    cfg = load_yaml(str(config_path))
    settings = ProductionSettings.from_config(
        cfg,
        require_credentials=False,
        require_external_controls=False,
    )
    source_hash = _deployed_source_hash()
    identity = {
        "commit_sha": commit_sha,
        "config_hash": _runtime_config_hash(
            settings,
            cfg,
            strategy=strategy,
            bar=bar,
            instruments=instruments,
            interval=interval,
            deployed_source_sha256=source_hash,
        ),
        "account_id": settings.account_id,
        "environment": settings.environment,
        "deployed_source_sha256": source_hash,
        "strategy_identity": {
            "strategy": strategy,
            "bar": bar,
            "instruments": sorted(instruments),
            "interval_seconds": interval,
            "risk_parameters_sha256": risk_behavior_hash(cfg, strategy),
        },
    }
    if (
        settings.environment == "production"
        and settings.deployment_tier == "canary"
    ):
        release_root = Path(__file__).resolve().parents[1]
        _launcher, interpreter, _link_identity = (
            _runtime_python_executable()
        )
        identity["release_identity"] = _actual_canary_release_identity(
            release_root=release_root,
            release_commit_file=release_commit_file,
            interpreter=interpreter,
        )
    return identity


def _verify_stage_c_drills(
    *,
    epoch: dict,
    bundle_signing_public_key: Path | None,
    receipts_dir: Path | None,
    manifests_dir: Path | None,
    bundle_receipts_dir: Path | None,
    independent_attestations_dir: Path | None,
    raw_observer_public_key: Path | None,
    independent_verifier_public_key: Path | None,
    trust_manifest_path: Path | None,
    release_frozen_at: datetime | None,
) -> dict:
    if (
        bundle_signing_public_key is None
        or receipts_dir is None
        or manifests_dir is None
        or bundle_receipts_dir is None
        or independent_attestations_dir is None
        or raw_observer_public_key is None
        or independent_verifier_public_key is None
        or trust_manifest_path is None
        or release_frozen_at is None
    ):
        raise ValueError(
            "生产准入缺少最终冻结候选的 Stage-C WP4/WP5 证据"
        )
    receipts = load_verified_stage_c_receipts(
        receipts_dir=receipts_dir,
        manifests_dir=manifests_dir,
        bundle_receipts_dir=bundle_receipts_dir,
        bundle_signing_public_key=bundle_signing_public_key,
        independent_attestations_dir=independent_attestations_dir,
        raw_observer_public_key=raw_observer_public_key,
        independent_verifier_public_key=(
            independent_verifier_public_key
        ),
        trust_manifest_path=trust_manifest_path,
    )
    return verify_stage_c_coverage(
        receipts,
        expected_release_identity=epoch["release_identity"],
        expected_soak_epoch_id=epoch["soak_epoch_id"],
        release_frozen_at=release_frozen_at,
        epoch_started_at=datetime.fromisoformat(epoch["started_at"]),
        expected_stage_c_deployment_identity=epoch[
            "stage_c_chaos_deployment_identity"
        ],
    )


def _evaluate(
    *,
    ledger: DemoObservationLedgerV2,
    evidence_path: Path,
    max_slippage: float,
    approved_max_stress_loss: float,
    config_path: Path,
    release_commit_file: Path,
    strategy: str,
    bar: str,
    instruments: list[str],
    interval: float,
    research_public_key: Path,
    bundle_signing_public_key: Path | None = None,
    stage_c_raw_observer_public_key: Path | None = None,
    stage_c_trust_manifest: Path | None = None,
    independent_verifier_public_key: Path | None = None,
    independent_verifier_attestations_dir: Path | None = None,
    stage_c_drill_receipts_dir: Path | None = None,
    stage_c_drill_manifests_dir: Path | None = None,
    stage_c_drill_bundle_receipts_dir: Path | None = None,
    stage_c_drill_independent_attestations_dir: Path | None = None,
    stage_c_release_frozen_at: datetime | None = None,
    empty_host_restore_evidence: Path | None = None,
    empty_host_restore_public_key: Path | None = None,
    empty_host_restore_key_id: str = "",
    canary_reservation_mode: str = "reserve",
) -> tuple[dict, dict, str, str]:
    evidence_bytes = evidence_path.read_bytes()
    evidence = json.loads(evidence_bytes)
    metadata = evidence["evidence_metadata"]
    actual_identity = _actual_runtime_identity(
        config_path=config_path,
        release_commit_file=release_commit_file,
        strategy=strategy,
        bar=bar,
        instruments=instruments,
        interval=interval,
    )
    for key in ("commit_sha", "config_hash", "account_id", "environment"):
        actual = actual_identity[key]
        if str(metadata.get(key, "")).lower() != actual.lower():
            raise ValueError(
                f"准入证据 {key} 未绑定实际启动的 release/config/account"
            )
    if not isinstance(ledger, DemoObservationLedgerV2):
        raise ValueError("正式生产 Gate 只接受 DemoObservationLedger v2")
    epoch = ledger.epoch
    if epoch["release_identity"]["git_commit"].lower() != (
        actual_identity["commit_sha"].lower()
    ):
        raise ValueError("soak epoch release 与实际运行 release 不一致")
    cfg = load_yaml(str(config_path))
    settings = ProductionSettings.from_config(
        cfg,
        require_credentials=False,
        require_external_controls=False,
    )
    approved_slippage = float(metadata["approved_max_slippage_ratio"])
    if max_slippage != approved_slippage:
        raise ValueError(
            "--max-slippage 必须与 evidence_metadata."
            "approved_max_slippage_ratio 完全一致"
        )
    rows = ledger.load()
    if not rows:
        raise ValueError("生产准入缺少 demo observation ledger")
    if ledger.anchor_verifier is None:
        raise ValueError("生产准入必须配置独立观测监控公钥")
    if (
        bundle_signing_public_key is None
        or stage_c_raw_observer_public_key is None
        or independent_verifier_public_key is None
        or independent_verifier_attestations_dir is None
    ):
        raise ValueError("生产准入缺少独立 daily bundle 重算 verifier")
    observation_fingerprint = ed25519_public_key_fingerprint(
        ledger.anchor_verifier.public_key_path
    )
    if (
        epoch["observation_key_fingerprint"].lower()
        != observation_fingerprint
    ):
        raise ValueError("soak epoch 未绑定实际 observation 公钥指纹")
    bundle_signing_fingerprint = ed25519_public_key_fingerprint(
        bundle_signing_public_key
    )
    independent_verifier_fingerprint = (
        ed25519_public_key_fingerprint(independent_verifier_public_key)
    )
    raw_observer_fingerprint = ed25519_public_key_fingerprint(
        stage_c_raw_observer_public_key
    )
    if bundle_signing_fingerprint != observation_fingerprint:
        raise ValueError(
            "daily bundle signing 公钥必须是 epoch observation 身份"
        )
    protected_fingerprints = {
        epoch["monitor_key_fingerprint"].lower(),
        epoch["risk_key_fingerprint"].lower(),
        epoch["observation_key_fingerprint"].lower(),
    }
    if independent_verifier_fingerprint in protected_fingerprints:
        raise ValueError(
            "独立 bundle verifier 必须使用第四个不同 Ed25519 身份"
        )
    if (
        raw_observer_fingerprint in protected_fingerprints
        or raw_observer_fingerprint == independent_verifier_fingerprint
    ):
        raise ValueError(
            "Stage-C raw observer 必须与 bundle publisher、WORM readback "
            "verifier 及 epoch 保护身份全部不同"
        )
    if (
        not independent_verifier_attestations_dir.is_dir()
        or independent_verifier_attestations_dir.is_symlink()
    ):
        raise ValueError("独立 verifier attestation 目录不存在或不安全")
    deployment = epoch["deployment_identity"]
    release = epoch["release_identity"]
    if (
        empty_host_restore_evidence is None
        or empty_host_restore_public_key is None
        or not empty_host_restore_key_id.strip()
    ):
        raise ValueError("生产准入缺少签名 empty-host restore evidence")
    empty_host_claims, empty_host_restore_sha256 = (
        read_verified_empty_host_restore(
            empty_host_restore_evidence,
            public_key=empty_host_restore_public_key,
            expected_account_id=deployment["account_uid"],
            expected_release_identity=release["git_commit"],
            expected_config_sha256=deployment["config_sha256"],
            expected_deployment_unit=deployment["unit"],
            expected_soak_epoch_id=epoch["soak_epoch_id"],
            expected_key_id=empty_host_restore_key_id,
            now=datetime.now(UTC).timestamp(),
        )
    )
    empty_host_verifier_fingerprint = ed25519_public_key_fingerprint(
        empty_host_restore_public_key
    )
    if empty_host_verifier_fingerprint in (
        protected_fingerprints
        | {
            independent_verifier_fingerprint,
            raw_observer_fingerprint,
        }
    ):
        raise ValueError(
            "empty-host restore verifier 必须使用独立的第六个 Ed25519 身份"
        )
    stage_c_coverage = _verify_stage_c_drills(
        epoch=epoch,
        bundle_signing_public_key=bundle_signing_public_key,
        receipts_dir=stage_c_drill_receipts_dir,
        manifests_dir=stage_c_drill_manifests_dir,
        bundle_receipts_dir=stage_c_drill_bundle_receipts_dir,
        independent_attestations_dir=(
            stage_c_drill_independent_attestations_dir
        ),
        raw_observer_public_key=stage_c_raw_observer_public_key,
        independent_verifier_public_key=independent_verifier_public_key,
        trust_manifest_path=stage_c_trust_manifest,
        release_frozen_at=stage_c_release_frozen_at,
    )
    for row in rows:
        attestation_path = (
            independent_verifier_attestations_dir / f"{row['day']}.json"
        )
        if (
            not attestation_path.is_file()
            or attestation_path.is_symlink()
        ):
            raise ValueError(
                f"缺少 {row['day']} 独立 daily bundle 重算签名"
            )
        artifact = json.loads(
            attestation_path.read_text(encoding="utf-8")
        )
        claims = verify_independent_bundle_verification(
            artifact,
            verifier_public_key=independent_verifier_public_key,
            manifest_signing_public_key=bundle_signing_public_key,
            expected_manifest_uri=row["source_uri"],
            expected_manifest_version_id=row["source_version_id"],
            expected_manifest_sha256=row["source_sha256"],
            expected_day=row["day"],
            expected_identity={
                "git_commit": release["git_commit"],
                "config_sha256": deployment["config_sha256"],
                "account_uid": deployment["account_uid"],
                "environment": "demo",
                "unit": deployment["unit"],
                "soak_epoch_id": epoch["soak_epoch_id"],
                "phase": row["phase"],
            },
        )
        actual_external_fingerprints = {
            name: claims["external_verification"][name][
                "signing_key_fingerprint"
            ]
            for name in (
                "journal_snapshot",
                "external_monitor",
                "alert_receipts",
                "backup_receipts",
            )
        }
        if actual_external_fingerprints != epoch[
            "external_source_key_fingerprints"
        ]:
            raise ValueError(
                f"{row['day']} external source 公钥未绑定 soak epoch"
            )
        if claims["report_sha256"] != row["report_sha256"]:
            raise ValueError(
                f"{row['day']} 独立重算 report hash 与 ledger 不一致"
            )
    # Admission evidence v1 retains its historical raw-file fingerprint.
    monitor_fingerprint = hashlib.sha256(
        ledger.anchor_verifier.public_key_path.read_bytes()
    ).hexdigest()
    if str(metadata.get("monitor_key_fingerprint", "")).lower() != (
        monitor_fingerprint
    ):
        raise ValueError("准入证据未绑定实际 demo 监控公钥指纹")
    research_fingerprint = hashlib.sha256(
        research_public_key.read_bytes()
    ).hexdigest()
    if str(
        metadata.get("research_policy_key_fingerprint", "")
    ).lower() != research_fingerprint:
        raise ValueError("准入证据未绑定实际研究 policy 公钥指纹")
    research_policy_claims = verify_ed25519_artifact(
        evidence.get("research_policy"),
        research_public_key,
        label="研究预注册 policy",
    )
    stress_runner_claims = verify_ed25519_artifact(
        evidence.get("stress_runner_attestation"),
        research_public_key,
        label="压力 runner attestation",
    )
    ledger_head_hash = str(rows[-1]["entry_hash"])
    canary_capability_sha256 = (
        NOT_APPLICABLE_CANARY_READINESS_SHA256
    )
    if settings.deployment_tier == "canary":
        from okx_quant.research.canary import (
            DEFAULT_CANARY_CAPABILITY_BUNDLE,
            DEFAULT_CANARY_CAPABILITY_PUBLIC_KEY,
            DEFAULT_CANARY_CAPABILITY_REPLAY_STATE,
            DEFAULT_CANARY_DEPLOYMENT_VERIFIER_PUBLIC_KEY,
            DEFAULT_CANARY_IAM_PUBLIC_KEY,
            DEFAULT_CANARY_WORM_READBACK_PUBLIC_KEY,
            require_external_canary_producers_ready,
            validate_canary_runtime,
        )

        transition, _policy = validate_canary_runtime(
            settings=settings,
            config=cfg,
            actual_runtime_identity=actual_identity,
            deployment_receipt={"ledger_head_hash": ledger_head_hash},
        )
        if (
            transition["demo_soak_epoch_id"] != epoch["soak_epoch_id"]
            or transition["release_identity"] != epoch["release_identity"]
            or transition["strategy_identity"] != epoch["strategy_identity"]
            or transition["source_producer_inventory"]
            != epoch["canary_source_producer_inventory"]
            or transition["source_producer_inventory_sha256"]
            != canary_source_producer_inventory_sha256(
                epoch["canary_source_producer_inventory"]
            )
            or transition["target_deployment_identity"][
                "source_producer_inventory_sha256"
            ]
            != epoch["deployment_identity"][
                "canary_source_producer_inventory_sha256"
            ]
        ):
            raise ValueError(
                "Canary transition 未绑定当前 Demo soak epoch/release/strategy"
            )
        disallowed = {
            epoch["monitor_key_fingerprint"],
            epoch["risk_key_fingerprint"],
            epoch["observation_key_fingerprint"],
            *epoch["external_source_key_fingerprints"].values(),
            ed25519_public_key_fingerprint(
                settings.canary_operator_public_key
            ),
            ed25519_public_key_fingerprint(
                settings.canary_risk_public_key
            ),
            ed25519_public_key_fingerprint(
                settings.canary_check_verifier_public_key
            ),
        }
        capability, canary_capability_sha256 = (
            require_external_canary_producers_ready(
                epoch=epoch,
                transition=transition,
                capability_bundle_path=(
                    DEFAULT_CANARY_CAPABILITY_BUNDLE
                ),
                capability_public_key=(
                    DEFAULT_CANARY_CAPABILITY_PUBLIC_KEY
                ),
                iam_public_key=DEFAULT_CANARY_IAM_PUBLIC_KEY,
                worm_readback_public_key=(
                    DEFAULT_CANARY_WORM_READBACK_PUBLIC_KEY
                ),
                deployment_verifier_public_key=(
                    DEFAULT_CANARY_DEPLOYMENT_VERIFIER_PUBLIC_KEY
                ),
                disallowed_key_fingerprints=disallowed,
                replay_state_path=(
                    DEFAULT_CANARY_CAPABILITY_REPLAY_STATE
                ),
                now=int(time.time()),
                reservation_mode=canary_reservation_mode,
            )
        )
        if (
            capability["pre_start_challenge"]
            != transition["pre_start_challenge"]
        ):
            raise ValueError(
                "Canary capability bundle 未绑定 transition challenge"
            )
        ledger_expected_config = epoch["deployment_identity"]["config_sha256"]
        ledger_expected_account = epoch["deployment_identity"]["account_uid"]
    else:
        if (
            epoch["deployment_identity"]["config_sha256"].lower()
            != actual_identity["config_hash"].lower()
            or epoch["deployment_identity"]["account_uid"]
            != actual_identity["account_id"]
        ):
            raise ValueError(
                "full production 禁止直接迁移 Demo deployment identity"
            )
        ledger_expected_config = str(metadata["config_hash"])
        ledger_expected_account = str(metadata["account_id"])
    clean_days = ledger.consecutive_clean_days(
        max_slippage_ratio=max_slippage,
        expected_git_commit=str(metadata["commit_sha"]),
        expected_config_hash=ledger_expected_config,
        expected_account_id=ledger_expected_account,
        require_trusted_anchor=True,
    )
    _validate_clean_streak_aggregate(ledger, clean_days)
    result = AdmissionGate(
        maximum_stress_loss_usdt=approved_max_stress_loss
    ).evaluate(
        walk_forward_metrics=evidence["walk_forward_metrics"],
        portfolio_metrics=evidence["portfolio_metrics"],
        robustness=evidence["robustness"],
        stress_evidence=evidence["stress_evidence"],
        clean_demo_days=clean_days,
        demo_slippage_observations=[
            float(row["slippage_max_ratio"])
            for row in rows[-clean_days:]
            if int(row["slippage_sample_count"]) > 0
        ] if clean_days else [],
        demo_slippage_sample_count=sum(
            int(row["slippage_sample_count"])
            for row in rows[-clean_days:]
        ) if clean_days else 0,
        demo_protection_sample_count=sum(
            int(row["protection_sample_count"])
            for row in rows[-clean_days:]
        ) if clean_days else 0,
        research_policy_claims=research_policy_claims,
        stress_runner_claims=stress_runner_claims,
        engineering_checks=evidence["engineering_checks"],
        operational_checks=evidence["operational_checks"],
        evidence_metadata=metadata,
    )
    result["stage_c_drill_coverage"] = stage_c_coverage
    result["empty_host_restore"] = {
        "artifact_sha256": empty_host_restore_sha256,
        "drill_id": empty_host_claims["drill_id"],
        "completed_at": empty_host_claims["completed_at"],
        "elapsed_seconds": empty_host_claims["elapsed_seconds"],
    }
    result["canary_producer_capability"] = {
        "required": settings.deployment_tier == "canary",
        "artifact_sha256": canary_capability_sha256,
    }
    return (
        evidence,
        result,
        hashlib.sha256(evidence_bytes).hexdigest(),
        ledger_head_hash,
    )


def _validate_clean_streak_aggregate(
    ledger: DemoObservationLedgerV2,
    clean_days: int,
) -> None:
    if clean_days < 30:
        return
    # Admission remains valid after day 30.  The aggregate contract is
    # deliberately an exact 30-day sample, so always validate the newest
    # 30 rows of the already-proven contiguous clean streak.
    validate_30_day_aggregate(ledger, clean_days=30)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ledger", default="evidence/demo-observations.json"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    record = sub.add_parser("record")
    record.add_argument("--day", type=date.fromisoformat)
    record.add_argument(
        "--max-slippage",
        type=_slippage_ratio,
        required=True,
    )
    record.add_argument("--source-uri", required=True)
    record.add_argument("--source-sha256", required=True)
    record.add_argument("--source-version-id", required=True)
    record.add_argument("--slo-report", required=True, type=Path)
    record.add_argument("--anchor", required=True, type=Path)
    record.add_argument(
        "--observation-public-key",
        required=True,
        type=Path,
    )
    record.add_argument("--soak-epoch", required=True, type=Path)
    record.add_argument(
        "--epoch-monitor-public-key",
        required=True,
        type=Path,
    )
    record.add_argument(
        "--epoch-risk-public-key",
        required=True,
        type=Path,
    )
    request = sub.add_parser("request")
    _add_evaluation_arguments(request)
    request.add_argument("--output", required=True, type=Path)
    request.add_argument("--lifetime-seconds", type=int, default=3600)
    evaluate = sub.add_parser("evaluate")
    _add_evaluation_arguments(evaluate)
    evaluate.add_argument(
        "--approval",
        required=True,
        type=Path,
    )
    evaluate.add_argument(
        "--approval-public-key",
        required=True,
        type=Path,
    )
    identity = sub.add_parser("identity")
    identity.add_argument("--config", required=True, type=Path)
    identity.add_argument("--release-commit-file", required=True, type=Path)
    identity.add_argument("--launch-manifest", type=Path)
    identity.add_argument("--strategy")
    identity.add_argument("--bar")
    identity.add_argument(
        "--instrument",
        dest="instruments",
        action="append",
    )
    identity.add_argument("--interval", type=_nonnegative_finite)
    args = parser.parse_args()

    if args.command == "record":
        report_bytes = args.slo_report.read_bytes()
        report = json.loads(report_bytes)
        if args.day is not None and report.get("day") != args.day.isoformat():
            raise ValueError("--day 与 durable SLO v2 report 不一致")
        epoch_artifact = json.loads(
            args.soak_epoch.read_text(encoding="utf-8")
        )
        epoch = verify_dual_signed_soak_epoch(
            epoch_artifact,
            monitor_public_key=args.epoch_monitor_public_key,
            risk_public_key=args.epoch_risk_public_key,
        )
        ledger = DemoObservationLedgerV2(
            args.ledger,
            epoch_payload=epoch,
            anchor_public_key=args.observation_public_key,
        )
        ledger.append_report(
            report=report,
            report_bytes=report_bytes,
            source_uri=args.source_uri,
            source_sha256=args.source_sha256,
            source_version_id=args.source_version_id,
            anchor=json.loads(args.anchor.read_text(encoding="utf-8")),
            max_slippage_ratio=args.max_slippage,
        )
        print(args.ledger)
        return 0

    if args.command == "identity":
        _resolve_launch_arguments(args)
        print(json.dumps(_actual_runtime_identity(
            config_path=args.config,
            release_commit_file=args.release_commit_file,
            strategy=args.strategy,
            bar=args.bar,
            instruments=args.instruments,
            interval=args.interval,
        ), ensure_ascii=False, indent=2))
        return 0

    _resolve_launch_arguments(args)
    epoch_artifact = json.loads(
        args.soak_epoch.read_text(encoding="utf-8")
    )
    epoch = verify_dual_signed_soak_epoch(
        epoch_artifact,
        monitor_public_key=args.epoch_monitor_public_key,
        risk_public_key=args.epoch_risk_public_key,
    )
    ledger = DemoObservationLedgerV2(
        args.ledger,
        epoch_payload=epoch,
        anchor_public_key=args.observation_public_key,
    )
    evidence, result, evidence_sha256, ledger_head_hash = _evaluate(
        ledger=ledger,
        evidence_path=args.evidence,
        max_slippage=args.max_slippage,
        approved_max_stress_loss=args.approved_max_stress_loss,
        config_path=args.config,
        release_commit_file=args.release_commit_file,
        strategy=args.strategy,
        bar=args.bar,
        instruments=args.instruments,
        interval=args.interval,
        research_public_key=args.research_public_key,
        bundle_signing_public_key=args.bundle_signing_public_key,
        stage_c_raw_observer_public_key=(
            args.stage_c_raw_observer_public_key
        ),
        stage_c_trust_manifest=args.stage_c_trust_manifest,
        independent_verifier_public_key=(
            args.independent_verifier_public_key
        ),
        independent_verifier_attestations_dir=(
            args.independent_verifier_attestations_dir
        ),
        stage_c_drill_receipts_dir=args.stage_c_drill_receipts_dir,
        stage_c_drill_manifests_dir=args.stage_c_drill_manifests_dir,
        stage_c_drill_bundle_receipts_dir=(
            args.stage_c_drill_bundle_receipts_dir
        ),
        stage_c_drill_independent_attestations_dir=(
            args.stage_c_drill_independent_attestations_dir
        ),
        stage_c_release_frozen_at=args.stage_c_release_frozen_at,
        empty_host_restore_evidence=args.empty_host_restore_evidence,
        empty_host_restore_public_key=(
            args.empty_host_restore_public_key
        ),
        empty_host_restore_key_id=args.empty_host_restore_key_id,
    )
    stage_c_coverage_sha256 = hashlib.sha256(
        canonical_bytes(result["stage_c_drill_coverage"])
    ).hexdigest()
    if args.command == "request":
        if not result["admitted"]:
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 2
        request_payload = build_admission_request(
            evidence,
            evidence_sha256=evidence_sha256,
            ledger_head_hash=ledger_head_hash,
            empty_host_restore_sha256=result[
                "empty_host_restore"
            ]["artifact_sha256"],
            stage_c_coverage_sha256=stage_c_coverage_sha256,
            canary_readiness_sha256=result[
                "canary_producer_capability"
            ]["artifact_sha256"],
            approved_max_stress_loss_usdt=args.approved_max_stress_loss,
            lifetime_s=args.lifetime_seconds,
        )
        if args.output.exists():
            raise ValueError(f"拒绝覆盖既有准入请求: {args.output}")
        args.output.write_text(
            json.dumps(request_payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        args.output.chmod(0o600)
        print(args.output)
        return 0
    approval = json.loads(args.approval.read_text(encoding="utf-8"))
    AdmissionApprovalVerifier(args.approval_public_key).verify(
        approval,
        evidence=evidence,
        evidence_sha256=evidence_sha256,
        ledger_head_hash=ledger_head_hash,
        empty_host_restore_sha256=result[
            "empty_host_restore"
        ]["artifact_sha256"],
        stage_c_coverage_sha256=stage_c_coverage_sha256,
        canary_readiness_sha256=result[
            "canary_producer_capability"
        ]["artifact_sha256"],
        approved_max_stress_loss_usdt=args.approved_max_stress_loss,
    )
    result["signed_root_approval"] = True
    result["evidence_sha256"] = evidence_sha256
    result["ledger_head_hash"] = ledger_head_hash
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["admitted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
