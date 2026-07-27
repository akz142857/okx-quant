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
from datetime import date, datetime
from importlib import metadata as importlib_metadata
from pathlib import Path

from okx_quant.application.approval import (
    canonical_bytes,
    production_config_hash,
    verify_ed25519_artifact,
)
from okx_quant.config import ProductionSettings, load_yaml
from okx_quant.research.admission import (
    AdmissionApprovalVerifier,
    AdmissionGate,
    DemoObservationLedger,
    build_admission_request,
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
    parser.add_argument(
        "--research-public-key",
        required=True,
        type=Path,
        help="独立研究 policy/runner attestation Ed25519 公钥",
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


def _actual_runtime_identity(
    *,
    config_path: Path,
    release_commit_file: Path,
    strategy: str,
    bar: str,
    instruments: list[str],
    interval: float,
) -> dict[str, str]:
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
    return {
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
    }


def _evaluate(
    *,
    ledger: DemoObservationLedger,
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
    clean_days = ledger.consecutive_clean_days(
        max_slippage_ratio=max_slippage,
        expected_git_commit=str(metadata["commit_sha"]),
        expected_config_hash=str(metadata["config_hash"]),
        expected_account_id=str(metadata["account_id"]),
        require_trusted_anchor=True,
    )
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
    return (
        evidence,
        result,
        hashlib.sha256(evidence_bytes).hexdigest(),
        ledger_head_hash,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ledger", default="evidence/demo-observations.json"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    record = sub.add_parser("record")
    record.add_argument("--day", type=date.fromisoformat, default=date.today())
    record.add_argument("--mismatches", type=int, required=True)
    record.add_argument("--protection-p99", type=_nonnegative_finite, required=True)
    record.add_argument("--slippage", type=_slippage_ratio, required=True)
    record.add_argument("--git-commit", required=True)
    record.add_argument("--config-hash", required=True)
    record.add_argument("--account-id", required=True)
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
    record.add_argument(
        "--observation-started-at",
        type=datetime.fromisoformat,
        required=True,
    )
    record.add_argument(
        "--observation-ended-at",
        type=datetime.fromisoformat,
        required=True,
    )
    record.add_argument("--notes", default="")
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
        try:
            if (
                report["version"] != 1
                or report["day"] != args.day.isoformat()
                or float(
                    report["protection_activation"]["p99_seconds"]
                )
                != args.protection_p99
                or int(
                    report["reconciliation"]["unexplained_mismatches"]
                )
                != args.mismatches
                or float(report["execution_slippage"]["p99_ratio"])
                != args.slippage
            ):
                raise ValueError(
                    "record 参数与 durable SLO 日报告不一致"
                )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("durable SLO 日报告结构或数值非法") from exc
        ledger = DemoObservationLedger(
            args.ledger,
            anchor_public_key=args.observation_public_key,
        )
        ledger.append(
            day=args.day,
            unexplained_mismatches=args.mismatches,
            protection_sample_count=int(
                report["protection_activation"]["sample_count"]
            ),
            protection_p99_seconds=args.protection_p99,
            slippage_sample_count=int(
                report["execution_slippage"]["sample_count"]
            ),
            observed_slippage_ratio=args.slippage,
            slippage_max_ratio=float(
                report["execution_slippage"]["max_ratio"]
            ),
            git_commit=args.git_commit,
            config_hash=args.config_hash,
            account_id=args.account_id,
            source_uri=args.source_uri,
            source_sha256=args.source_sha256,
            source_version_id=args.source_version_id,
            slo_report_sha256=hashlib.sha256(report_bytes).hexdigest(),
            anchor=json.loads(args.anchor.read_text(encoding="utf-8")),
            observation_started_at=args.observation_started_at,
            observation_ended_at=args.observation_ended_at,
            notes=args.notes,
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
    ledger = DemoObservationLedger(
        args.ledger,
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
    )
    if args.command == "request":
        if not result["admitted"]:
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 2
        request_payload = build_admission_request(
            evidence,
            evidence_sha256=evidence_sha256,
            ledger_head_hash=ledger_head_hash,
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
        approved_max_stress_loss_usdt=args.approved_max_stress_loss,
    )
    result["signed_root_approval"] = True
    result["evidence_sha256"] = evidence_sha256
    result["ledger_head_hash"] = ledger_head_hash
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["admitted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
