#!/usr/bin/env python3
"""Run the strongest repeatable validation that does not submit real orders.

The resulting artifact is deliberately marked as non-production-admissible.
It proves deterministic code paths against the committed test model; it does
not claim that OKX, external infrastructure, elapsed time, or humans behaved
as required.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

if __package__:
    from scripts.fault_injection import _source_manifest_hash
else:
    from fault_injection import _source_manifest_hash

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")

SUITES: tuple[dict[str, Any], ...] = (
    {
        "id": "core-domain-execution",
        "description": (
            "订单状态机、单写者、幂等成交、风险预留和旧执行层兼容"
        ),
        "tests": (
            "tests/test_order_domain.py",
            "tests/test_execution_coordinator.py",
            "tests/test_order_executor.py",
            "tests/test_risk_manager.py",
        ),
    },
    {
        "id": "exchange-contract-model",
        "description": (
            "交易所适配、写请求不盲重试和 OKX demo 契约离线模型"
        ),
        "tests": (
            "tests/test_exchange.py",
            "tests/test_rest_client_config.py",
            "tests/test_rest_retry_safety.py",
            "tests/test_demo_contract.py",
            "tests/test_demo_contract_evidence.py",
            "tests/test_account_snapshot.py",
        ),
    },
    {
        "id": "persistence-recovery-streams",
        "description": (
            "SQLite journal、投影重建、联合对账、私有流重放和恢复"
        ),
        "tests": (
            "tests/test_sqlite_journal.py",
            "tests/test_reconciliation.py",
            "tests/test_private_streams.py",
            "tests/test_position_restore.py",
            "tests/test_state_store.py",
            "tests/test_demo_probe.py",
            "tests/test_demo_soak_v2.py",
        ),
    },
    {
        "id": "protection-runtime-operations",
        "description": (
            "保护单、退出竞态、生产运行时、故障、备份恢复和 SLO"
        ),
        "tests": (
            "tests/test_protection.py",
            "tests/test_production_runtime.py",
            "tests/test_operations.py",
            "tests/test_resume_approval.py",
            "tests/test_failure_injection.py",
            "tests/test_slo_report.py",
            "tests/test_production_config.py",
            "tests/test_demo_preflight.py",
            "tests/test_account_lease.py",
            "tests/test_alert_control.py",
            "tests/test_external_demo_monitor.py",
            "tests/test_monitoring_deploy.py",
            "tests/test_web_dashboard.py",
            "tests/test_empty_host_restore.py",
            "tests/test_immutable_bundle.py",
            "tests/test_demo_chaos_evidence.py",
            "tests/test_external_deployment_attestation.py",
            "tests/test_linux_deployment_preflight.py",
            "tests/test_stage_c_legacy_protocols.py",
        ),
    },
    {
        "id": "strategy-data-research",
        "description": (
            "指标、策略循环、回测、研究溯源和准入抗伪造"
        ),
        "tests": (
            "tests/test_backtest_engine.py",
            "tests/test_indicators.py",
            "tests/test_indicator_cache.py",
            "tests/test_live_trader_integration.py",
            "tests/test_review_fixes.py",
            "tests/test_research_gate.py",
            "tests/test_research_producers.py",
            "tests/test_canary_transition.py",
            "tests/test_canary_capability_security.py",
        ),
    },
    {
        "id": "stage-c-adversarial-protocol",
        "description": (
            "Stage-C 原始证据解析、显式实现清单、外部 actor、"
            "业务屏障与构建隔离"
        ),
        "tests": (
            "tests/test_stage_c_exact_release_drivers.py",
            "tests/test_stage_c_external_executors.py",
            "tests/test_stage_c_implementation_inventory.py",
            "tests/test_stage_c_barrier_harness.py",
            "tests/test_stage_c_native_recovery.py",
            "tests/test_stage_c_pipeline_barriers.py",
            "tests/test_stage_c_external_bridge.py",
        ),
    },
    {
        "id": "configuration-security-tooling",
        "description": (
            "配置边界、日志脱敏、超时和非实盘证据工具自身"
        ),
        "tests": (
            "tests/test_config_env.py",
            "tests/test_security.py",
            "tests/test_timeout.py",
            "tests/test_non_live_validation.py",
        ),
    },
)

LIMITATIONS: tuple[dict[str, str], ...] = (
    {
        "id": "real_exchange_contract",
        "not_proven": (
            "OKX 当前 API 的字段语义、拒绝码、部分成交、冻结余额及保护单行为"
        ),
        "next_stage": "使用隔离 OKX Demo 账户运行 demo_contract.py",
    },
    {
        "id": "real_latency_and_liquidity",
        "not_proven": "公网抖动、限频、排队、盘口冲击及真实滑点分布",
        "next_stage": "Demo/Shadow 连续运行并采集 durable SLO",
    },
    {
        "id": "external_operations",
        "not_proven": "真实 Page、S3 version、NTP、磁盘和空主机恢复链",
        "next_stage": "在隔离 Linux 预生产主机完成运维演练",
    },
    {
        "id": "elapsed_time",
        "not_proven": "同一提交、配置和账户连续 30 个自然日的稳定性",
        "next_stage": "生成不可回填的每日 Demo ledger",
    },
    {
        "id": "strategy_profitability",
        "not_proven": "未来收益、市场容量及制度变化下的策略有效性",
        "next_stage": "独立 OOS、Shadow A/B、压力测试及小资金 Canary",
    },
    {
        "id": "independent_human_approval",
        "not_proven": "操作人、风险审批人和回滚责任人的独立签署",
        "next_stage": "完成 RELEASE_CHECKLIST.md 的人工准入",
    },
)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _suite_tests() -> list[str]:
    return [
        test
        for suite in SUITES
        for test in suite["tests"]
    ]


def _validate_suite_inventory() -> list[str]:
    selected = _suite_tests()
    duplicates = sorted({
        item for item in selected if selected.count(item) > 1
    })
    discovered = sorted(
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in (PROJECT_ROOT / "tests").glob("test_*.py")
    )
    missing = sorted(set(discovered) - set(selected))
    extra = sorted(set(selected) - set(discovered))
    if duplicates or missing or extra:
        raise RuntimeError(
            "非实盘验证测试清单不完整: "
            f"duplicates={duplicates}, missing={missing}, extra={extra}"
        )
    return discovered


def _test_inventory_hash() -> str:
    digest = hashlib.sha256()
    for suite in SUITES:
        digest.update(str(suite["id"]).encode("utf-8") + b"\0")
        for test in suite["tests"]:
            digest.update(str(test).encode("utf-8") + b"\0")
    return digest.hexdigest()


def _git_identity() -> tuple[str, str, bool]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip().lower()
        tree_hash = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip().lower()
        clean = not subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown", "unknown", False
    return commit, tree_hash, clean


def _run_suite(suite: dict[str, Any]) -> dict[str, Any]:
    tests = list(suite["tests"])
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--tb=short",
        *tests,
    ]
    started = time.monotonic()
    process = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    duration = time.monotonic() - started
    return {
        "id": suite["id"],
        "description": suite["description"],
        "tests": tests,
        "command": command,
        "duration_seconds": round(duration, 6),
        "exit_code": process.returncode,
        "passed": process.returncode == 0,
        "stdout_sha256": _sha256_text(process.stdout),
        "stderr_sha256": _sha256_text(process.stderr),
        "stdout": process.stdout,
        "stderr": process.stderr,
    }


def build_evidence() -> dict[str, Any]:
    discovered = _validate_suite_inventory()
    commit, tree_hash, workspace_clean = _git_identity()
    started = time.time()
    suites = [_run_suite(suite) for suite in SUITES]
    completed = time.time()
    overall_passed = all(suite["passed"] for suite in suites)
    complete_inventory = sorted(_suite_tests()) == discovered
    release_candidate_eligible = bool(
        overall_passed
        and complete_inventory
        and workspace_clean
        and _SHA1.fullmatch(commit)
        and _SHA1.fullmatch(tree_hash)
    )
    return {
        "schema_version": 1,
        "evidence_type": "okx_quant_non_live_validation",
        "assurance_scope": "offline_deterministic_only",
        "production_admissible": False,
        "started_at": started,
        "completed_at": completed,
        "git_commit": commit,
        "git_tree_hash": tree_hash,
        "workspace_clean": workspace_clean,
        "source_manifest_sha256": _source_manifest_hash(),
        "test_inventory_sha256": _test_inventory_hash(),
        "complete_test_inventory": complete_inventory,
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": str(Path(sys.executable).resolve()),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "suites": suites,
        "limitations": list(LIMITATIONS),
        "overall_passed": overall_passed,
        "release_candidate_eligible": release_candidate_eligible,
    }


def _write_once(path: Path, evidence: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"拒绝覆盖既有非实盘验证证据: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(
                evidence,
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_evidence_artifact(
    evidence_path: Path,
    revision_file: Path,
) -> dict[str, Any]:
    if (
        not evidence_path.is_file()
        or evidence_path.is_symlink()
        or not revision_file.is_file()
        or revision_file.is_symlink()
    ):
        raise RuntimeError("非实盘 evidence/REVISION 必须是非符号链接普通文件")
    revision = revision_file.read_text(encoding="ascii").strip().lower()
    if not _SHA1.fullmatch(revision):
        raise RuntimeError("REVISION 必须是完整 40 位提交 SHA")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "evidence_type",
        "assurance_scope",
        "production_admissible",
        "started_at",
        "completed_at",
        "git_commit",
        "git_tree_hash",
        "workspace_clean",
        "source_manifest_sha256",
        "test_inventory_sha256",
        "complete_test_inventory",
        "suites",
        "limitations",
        "overall_passed",
        "release_candidate_eligible",
    }
    if not isinstance(evidence, dict) or not required <= set(evidence):
        raise RuntimeError("非实盘 evidence 结构不完整")
    if (
        evidence["schema_version"] != 1
        or evidence["evidence_type"] != "okx_quant_non_live_validation"
        or evidence["assurance_scope"] != "offline_deterministic_only"
        or evidence["production_admissible"] is not False
    ):
        raise RuntimeError("非实盘 evidence 类型或保证范围非法")
    if (
        evidence["workspace_clean"] is not True
        or evidence["complete_test_inventory"] is not True
        or evidence["overall_passed"] is not True
        or evidence["release_candidate_eligible"] is not True
        or str(evidence["git_commit"]).lower() != revision
        or not _SHA1.fullmatch(str(evidence["git_tree_hash"]).lower())
    ):
        raise RuntimeError("非实盘 evidence 未通过或未绑定干净发布提交")
    if evidence["source_manifest_sha256"] != _source_manifest_hash():
        raise RuntimeError("非实盘 evidence 未绑定当前源码/测试 manifest")
    if evidence["test_inventory_sha256"] != _test_inventory_hash():
        raise RuntimeError("非实盘 evidence 测试清单已变化")
    _validate_suite_inventory()
    suites = evidence["suites"]
    if not isinstance(suites, list) or len(suites) != len(SUITES):
        raise RuntimeError("非实盘 evidence suite 数量非法")
    for recorded, expected in zip(suites, SUITES, strict=True):
        if (
            not isinstance(recorded, dict)
            or recorded.get("id") != expected["id"]
            or recorded.get("tests") != list(expected["tests"])
            or recorded.get("exit_code") != 0
            or recorded.get("passed") is not True
            or not isinstance(recorded.get("stdout"), str)
            or not isinstance(recorded.get("stderr"), str)
            or recorded.get("stdout_sha256")
            != _sha256_text(recorded["stdout"])
            or recorded.get("stderr_sha256")
            != _sha256_text(recorded["stderr"])
        ):
            raise RuntimeError(
                f"非实盘 evidence suite 非法: {expected['id']}"
            )
    limitation_ids = {
        item.get("id")
        for item in evidence["limitations"]
        if isinstance(item, dict)
    }
    if limitation_ids != {item["id"] for item in LIMITATIONS}:
        raise RuntimeError("非实盘 evidence 未完整声明不可替代的外部限制")
    started = evidence["started_at"]
    completed = evidence["completed_at"]
    if (
        isinstance(started, bool)
        or isinstance(completed, bool)
        or not isinstance(started, (int, float))
        or not isinstance(completed, (int, float))
        or completed < started
    ):
        raise RuntimeError("非实盘 evidence 时间链非法")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(
        description="运行不提交真实订单的完整确定性验证并生成证据",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("non-live-validation.json"),
    )
    parser.add_argument("--verify-evidence", type=Path)
    parser.add_argument(
        "--revision-file",
        type=Path,
        default=Path("REVISION"),
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="允许开发工作树运行；报告不能作为干净发布制品证据",
    )
    args = parser.parse_args()
    if args.verify_evidence is not None:
        evidence = verify_evidence_artifact(
            args.verify_evidence,
            args.revision_file,
        )
        print(json.dumps({
            "verified": True,
            "production_admissible": False,
            "git_commit": evidence["git_commit"],
            "source_manifest_sha256": evidence[
                "source_manifest_sha256"
            ],
        }, ensure_ascii=False))
        return 0

    evidence = build_evidence()
    _write_once(args.output, evidence)
    print(json.dumps({
        "output": str(args.output),
        "overall_passed": evidence["overall_passed"],
        "workspace_clean": evidence["workspace_clean"],
        "release_candidate_eligible": evidence[
            "release_candidate_eligible"
        ],
        "production_admissible": False,
        "limitations": [
            item["id"] for item in evidence["limitations"]
        ],
    }, ensure_ascii=False))
    if not evidence["overall_passed"]:
        return 1
    if not evidence["workspace_clean"] and not args.allow_dirty:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
