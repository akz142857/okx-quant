"""量化与模拟盘生产准入证据。"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from itertools import product
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.research.costs import DynamicCostModel, canonical_manifest_hash
from okx_quant.research.cycle import compute_calendar_cycle_metrics
from okx_quant.research.provenance import (
    canonical_artifact_bytes,
    frames_from_artifact,
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
DEMO_LEDGER_VERSION = 2
NOT_APPLICABLE_CANARY_READINESS_SHA256 = hashlib.sha256(
    b"okx-quant/canary-readiness/not-applicable/v1"
).hexdigest()
_ADMISSION_KEYS = {
    "version",
    "action",
    "evidence_sha256",
    "ledger_head_hash",
    "demo_ledger_version",
    "slo_schema",
    "slo_policy_hash",
    "empty_host_restore_sha256",
    "stage_c_coverage_sha256",
    "canary_readiness_sha256",
    "commit_sha",
    "config_hash",
    "account_id",
    "environment",
    "approved_max_slippage_ratio",
    "approved_max_stress_loss_usdt",
    "monitor_key_fingerprint",
    "operator",
    "risk_approver",
    "issued_at",
    "expires_at",
}
_OBSERVATION_ANCHOR_KEYS = {
    "version",
    "action",
    "day",
    "unexplained_mismatches",
    "protection_sample_count",
    "protection_p99_seconds",
    "slippage_sample_count",
    "observed_slippage_ratio",
    "slippage_max_ratio",
    "git_commit",
    "config_hash",
    "account_id",
    "source_uri",
    "source_sha256",
    "source_version_id",
    "slo_report_sha256",
    "observation_started_at",
    "observation_ended_at",
    "monitor",
    "issued_at",
}


def _slo_v2_identity() -> tuple[str, str]:
    # Lazy import avoids the package initialization cycle
    # slo -> research.costs -> research.__init__ -> admission.
    from okx_quant.ops.slo import SLO_V2_POLICY_HASH, SLO_V2_SCHEMA

    return SLO_V2_SCHEMA, SLO_V2_POLICY_HASH


def build_admission_request(
    evidence: dict,
    *,
    evidence_sha256: str,
    ledger_head_hash: str,
    empty_host_restore_sha256: str,
    stage_c_coverage_sha256: str,
    canary_readiness_sha256: str,
    approved_max_stress_loss_usdt: float,
    lifetime_s: int = 3600,
    now: int | None = None,
) -> dict:
    """构建待独立风险审批人签名的生产准入根请求。"""
    metadata = evidence.get("evidence_metadata")
    AdmissionGate._validate_metadata(metadata)
    if not _SHA256.fullmatch(evidence_sha256):
        raise ValueError("evidence_sha256 必须是 SHA-256")
    if not _SHA256.fullmatch(ledger_head_hash):
        raise ValueError("ledger_head_hash 必须是 SHA-256")
    if not _SHA256.fullmatch(empty_host_restore_sha256):
        raise ValueError("empty_host_restore_sha256 必须是 SHA-256")
    if not _SHA256.fullmatch(stage_c_coverage_sha256):
        raise ValueError("stage_c_coverage_sha256 必须是 SHA-256")
    if not _SHA256.fullmatch(canary_readiness_sha256):
        raise ValueError("canary_readiness_sha256 必须是 SHA-256")
    if (
        isinstance(approved_max_stress_loss_usdt, bool)
        or not isinstance(approved_max_stress_loss_usdt, (int, float))
        or not math.isfinite(float(approved_max_stress_loss_usdt))
        or not 0 <= float(approved_max_stress_loss_usdt) <= 500
    ):
        raise ValueError("批准压力损失预算必须在 0..500")
    if type(lifetime_s) is not int or not 300 <= lifetime_s <= 86400:
        raise ValueError("生产准入批准有效期必须是 300..86400 秒")
    issued_at = int(time.time() if now is None else now)
    slo_schema, slo_policy_hash = _slo_v2_identity()
    return {
        "version": 2,
        "action": "admit-production",
        "evidence_sha256": evidence_sha256,
        "ledger_head_hash": ledger_head_hash,
        "empty_host_restore_sha256": empty_host_restore_sha256,
        "stage_c_coverage_sha256": stage_c_coverage_sha256,
        "canary_readiness_sha256": canary_readiness_sha256,
        "demo_ledger_version": DEMO_LEDGER_VERSION,
        "slo_schema": slo_schema,
        "slo_policy_hash": slo_policy_hash,
        "commit_sha": str(metadata["commit_sha"]).lower(),
        "config_hash": str(metadata["config_hash"]).lower(),
        "account_id": str(metadata["account_id"]),
        "environment": str(metadata["environment"]),
        "approved_max_slippage_ratio": float(
            metadata["approved_max_slippage_ratio"]
        ),
        "approved_max_stress_loss_usdt": float(
            approved_max_stress_loss_usdt
        ),
        "monitor_key_fingerprint": str(
            metadata["monitor_key_fingerprint"]
        ).lower(),
        "operator": str(metadata["operator"]),
        "risk_approver": "",
        "issued_at": issued_at,
        "expires_at": issued_at + lifetime_s,
    }


class AdmissionApprovalVerifier:
    """验证独立风险审批签名，并绑定证据、ledger head、预算和发布身份。"""

    def __init__(self, public_key_path: str | Path, *, clock=time.time):
        self.public_key_path = Path(public_key_path)
        self._clock = clock

    def verify(
        self,
        artifact: object,
        *,
        evidence: dict,
        evidence_sha256: str,
        ledger_head_hash: str,
        empty_host_restore_sha256: str,
        stage_c_coverage_sha256: str,
        canary_readiness_sha256: str,
        approved_max_stress_loss_usdt: float,
    ) -> dict:
        claims = verify_ed25519_artifact(
            artifact,
            self.public_key_path,
            label="生产准入批准",
        )
        if set(claims) != _ADMISSION_KEYS:
            raise ValueError("生产准入批准 claims 不完整或包含未知字段")
        if claims["version"] != 2 or claims["action"] != "admit-production":
            raise ValueError("生产准入批准版本或 action 非法")
        metadata = evidence["evidence_metadata"]
        slo_schema, slo_policy_hash = _slo_v2_identity()
        expected = {
            "evidence_sha256": evidence_sha256,
            "ledger_head_hash": ledger_head_hash,
            "empty_host_restore_sha256": empty_host_restore_sha256,
            "stage_c_coverage_sha256": stage_c_coverage_sha256,
            "canary_readiness_sha256": canary_readiness_sha256,
            "demo_ledger_version": DEMO_LEDGER_VERSION,
            "slo_schema": slo_schema,
            "slo_policy_hash": slo_policy_hash,
            "commit_sha": str(metadata["commit_sha"]).lower(),
            "config_hash": str(metadata["config_hash"]).lower(),
            "account_id": str(metadata["account_id"]),
            "environment": str(metadata["environment"]),
            "approved_max_slippage_ratio": float(
                metadata["approved_max_slippage_ratio"]
            ),
            "approved_max_stress_loss_usdt": float(
                approved_max_stress_loss_usdt
            ),
            "monitor_key_fingerprint": str(
                metadata["monitor_key_fingerprint"]
            ).lower(),
            "operator": str(metadata["operator"]),
        }
        for key, value in expected.items():
            if claims.get(key) != value:
                raise ValueError(f"生产准入批准未绑定当前 {key}")
        approver = claims["risk_approver"]
        if (
            not isinstance(approver, str)
            or not approver.strip()
            or approver == claims["operator"]
            or approver != metadata["risk_approver"]
        ):
            raise ValueError("生产准入批准必须由 metadata 中的独立风险审批人签署")
        issued_at = claims["issued_at"]
        expires_at = claims["expires_at"]
        if (
            type(issued_at) is not int
            or type(expires_at) is not int
            or not 300 <= expires_at - issued_at <= 86400
        ):
            raise ValueError("生产准入批准有效期非法")
        now = int(self._clock())
        if now < issued_at - 30 or now > expires_at:
            raise ValueError("生产准入批准尚未生效或已过期")
        return claims


class DemoObservationAnchorVerifier:
    """验证由独立监控身份签发的每日不可变观测锚。"""

    def __init__(self, public_key_path: str | Path):
        self.public_key_path = Path(public_key_path)

    def verify(self, row: dict) -> dict:
        anchor = row.get("anchor")
        claims = verify_ed25519_artifact(
            anchor,
            self.public_key_path,
            label="demo 日观测锚",
        )
        if set(claims) != _OBSERVATION_ANCHOR_KEYS:
            raise ValueError("demo 日观测锚 claims 不完整或包含未知字段")
        expected = {
            key: row[key]
            for key in _OBSERVATION_ANCHOR_KEYS
            if key not in {"version", "action", "monitor", "issued_at"}
        }
        if claims["version"] != 1 or claims["action"] != "anchor-demo-day":
            raise ValueError("demo 日观测锚版本或 action 非法")
        if not isinstance(claims["monitor"], str) or not claims["monitor"].strip():
            raise ValueError("demo 日观测锚 monitor 不能为空")
        for key, value in expected.items():
            if claims.get(key) != value:
                raise ValueError(f"demo 日观测锚未绑定当前 {key}")
        issued_at = claims["issued_at"]
        if type(issued_at) is not int:
            raise ValueError("demo 日观测锚 issued_at 非法")
        ended = datetime.fromisoformat(row["observation_ended_at"])
        recorded = datetime.fromisoformat(row["recorded_at"])
        issued = datetime.fromtimestamp(issued_at, tz=UTC)
        if issued < ended - timedelta(minutes=5) or issued > recorded + timedelta(minutes=5):
            raise ValueError("demo 日观测锚签发时间不在实时结算窗口")
        return claims


class DemoObservationLedger:
    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
        anchor_public_key: str | Path = "",
    ):
        self.path = Path(path)
        self._clock = clock or (lambda: datetime.now(UTC))
        self.anchor_verifier = (
            DemoObservationAnchorVerifier(anchor_public_key)
            if anchor_public_key
            else None
        )

    def append(
        self,
        *,
        day: date,
        unexplained_mismatches: int,
        protection_sample_count: int = 1,
        protection_p99_seconds: float,
        slippage_sample_count: int = 1,
        observed_slippage_ratio: float,
        slippage_max_ratio: float | None = None,
        git_commit: str,
        config_hash: str,
        account_id: str,
        source_uri: str,
        observation_started_at: datetime,
        observation_ended_at: datetime,
        source_sha256: str = "",
        source_version_id: str = "",
        slo_report_sha256: str = "",
        anchor: dict | None = None,
        notes: str = "",
    ) -> None:
        now_raw = self._clock()
        self._require_aware(now_raw, "clock")
        now = now_raw.astimezone(UTC)
        if day not in {now.date(), now.date() - timedelta(days=1)}:
            raise ValueError("demo 日证据只能实时结算当天或前一天，禁止历史回填")
        if (
            type(unexplained_mismatches) is not int
            or unexplained_mismatches < 0
        ):
            raise ValueError("unexplained_mismatches 必须是非负整数")
        for name, value in {
            "protection_sample_count": protection_sample_count,
            "slippage_sample_count": slippage_sample_count,
        }.items():
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} 必须是非负整数")
        if slippage_max_ratio is None:
            slippage_max_ratio = observed_slippage_ratio
        for name, value in {
            "protection_p99_seconds": protection_p99_seconds,
            "observed_slippage_ratio": observed_slippage_ratio,
            "slippage_max_ratio": slippage_max_ratio,
        }.items():
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} 必须是非负有限数")
        if observed_slippage_ratio > slippage_max_ratio:
            raise ValueError("slippage p99 不能大于 max")
        if not re.fullmatch(r"[0-9a-fA-F]{40}", git_commit):
            raise ValueError("git_commit 必须是完整 40 位提交 SHA")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", config_hash):
            raise ValueError("config_hash 必须是 64 位 SHA-256")
        if not account_id or not source_uri:
            raise ValueError("demo 证据必须绑定 account_id 和 source_uri")
        source = urlparse(source_uri)
        if (
            source.scheme != "s3"
            or not source.netloc
            or not source.path.strip("/")
        ):
            raise ValueError("demo source_uri 必须指向 S3 不可变证据对象")
        self._require_aware(observation_started_at, "observation_started_at")
        self._require_aware(observation_ended_at, "observation_ended_at")
        started = observation_started_at.astimezone(UTC)
        ended = observation_ended_at.astimezone(UTC)
        if ended <= started or (ended - started).total_seconds() < 20 * 3600:
            raise ValueError("每日 demo 证据必须覆盖至少 20 小时观测窗口")
        if day not in {started.date(), ended.date()}:
            raise ValueError("观测窗口与结算日期不一致")
        if ended > now + timedelta(minutes=5):
            raise ValueError("观测结束时间不能位于未来")
        rows = self.load()
        if any(row["day"] == day.isoformat() for row in rows):
            raise ValueError("demo ledger 为 append-only，禁止覆盖同一天证据")
        if rows and day <= date.fromisoformat(rows[-1]["day"]):
            raise ValueError("demo ledger 只能按日期顺序追加，禁止插入历史记录")
        previous_hash = rows[-1]["entry_hash"] if rows else "GENESIS"
        row = {
            "day": day.isoformat(),
            "unexplained_mismatches": unexplained_mismatches,
            "protection_sample_count": protection_sample_count,
            "protection_p99_seconds": protection_p99_seconds,
            "slippage_sample_count": slippage_sample_count,
            "observed_slippage_ratio": observed_slippage_ratio,
            "slippage_max_ratio": slippage_max_ratio,
            "git_commit": git_commit.lower(),
            "config_hash": config_hash.lower(),
            "account_id": account_id,
            "source_uri": source_uri,
            "source_sha256": source_sha256.lower(),
            "source_version_id": source_version_id,
            "slo_report_sha256": slo_report_sha256.lower(),
            "observation_started_at": started.isoformat(),
            "observation_ended_at": ended.isoformat(),
            "notes": notes,
            "recorded_at": now.isoformat(),
            "previous_hash": previous_hash,
            "anchor": anchor,
        }
        if anchor is not None or source_sha256 or source_version_id:
            if (
                not _SHA256.fullmatch(source_sha256.lower())
                or not _SHA256.fullmatch(slo_report_sha256.lower())
                or not source_version_id.strip()
                or anchor is None
                or self.anchor_verifier is None
            ):
                raise ValueError(
                    "可信 demo 日证据必须同时提供 source SHA/version、"
                    "anchor 和监控公钥"
                )
            self.anchor_verifier.verify(row)
        row["entry_hash"] = self._entry_hash(row)
        rows.append(row)
        rows.sort(key=lambda row: row["day"])
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(rows, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        rows = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(rows, list):
            raise ValueError("demo ledger 必须是数组")
        previous = "GENESIS"
        prior_day: date | None = None
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("demo ledger 行必须是对象")
            current = date.fromisoformat(row["day"])
            if prior_day is not None and current <= prior_day:
                raise ValueError("demo ledger 日期必须严格递增且不可重复")
            if row.get("previous_hash") != previous:
                raise ValueError("demo ledger 哈希链断裂")
            if row.get("entry_hash") != self._entry_hash(row):
                raise ValueError("demo ledger 行哈希校验失败")
            recorded_raw = datetime.fromisoformat(row["recorded_at"])
            self._require_aware(recorded_raw, "recorded_at")
            recorded = recorded_raw.astimezone(UTC)
            if current not in {
                recorded.date(),
                recorded.date() - timedelta(days=1),
            }:
                raise ValueError("demo ledger 存在历史回填记录")
            previous = row["entry_hash"]
            prior_day = current
        return rows

    @staticmethod
    def _entry_hash(row: dict) -> str:
        material = {
            key: value
            for key, value in row.items()
            if key != "entry_hash"
        }
        encoded = json.dumps(
            material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _require_aware(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{name} 必须包含时区")

    def consecutive_clean_days(
        self,
        *,
        max_protection_p99_s: float = 10,
        max_slippage_ratio: float,
        expected_git_commit: str,
        expected_config_hash: str,
        expected_account_id: str,
        as_of: date | None = None,
        require_trusted_anchor: bool = False,
    ) -> int:
        for name, value in {
            "max_protection_p99_s": max_protection_p99_s,
            "max_slippage_ratio": max_slippage_ratio,
        }.items():
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"{name} 必须是数值")
            if not math.isfinite(float(value)) or float(value) < 0:
                raise ValueError(f"{name} 必须是非负有限数")
        if not re.fullmatch(r"[0-9a-fA-F]{40}", expected_git_commit):
            raise ValueError("expected_git_commit 必须是完整 40 位提交 SHA")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_config_hash):
            raise ValueError("expected_config_hash 必须是 64 位 SHA-256")
        if not expected_account_id:
            raise ValueError("expected_account_id 不能为空")
        rows = self.load()
        if not rows:
            return 0
        as_of = as_of or date.today()
        latest = date.fromisoformat(rows[-1]["day"])
        if latest not in {as_of, as_of - timedelta(days=1)}:
            return 0
        count = 0
        expected: date | None = None
        for row in reversed(rows):
            current = date.fromisoformat(row["day"])
            if expected is not None and current != expected:
                break
            if (
                require_trusted_anchor
                and (
                    self.anchor_verifier is None
                    or not self._trusted_anchor(row)
                )
            ):
                break
            if (
                type(row["unexplained_mismatches"]) is not int
                or row["unexplained_mismatches"] != 0
                or float(row["protection_p99_seconds"]) > max_protection_p99_s
                or float(row["slippage_max_ratio"]) > max_slippage_ratio
                or str(row["git_commit"]).lower()
                != expected_git_commit.lower()
                or str(row["config_hash"]).lower()
                != expected_config_hash.lower()
                or str(row["account_id"]) != expected_account_id
            ):
                break
            count += 1
            expected = current - timedelta(days=1)
        return count

    def _trusted_anchor(self, row: dict) -> bool:
        try:
            assert self.anchor_verifier is not None
            self.anchor_verifier.verify(row)
            return True
        except (AssertionError, KeyError, TypeError, ValueError):
            return False


@dataclass(frozen=True)
class AdmissionGate:
    required_demo_days: int = 30
    maximum_stress_loss_usdt: float = 500
    minimum_oos_sharpe: float = 0
    minimum_positive_fold_ratio: float = 0.5
    required_engineering_checks: tuple[str, ...] = (
        "ci",
        "state_machine_coverage",
        "static_scan",
        "migration_restore",
        "fault_injection",
        "demo_contract",
        "response_loss",
        "partial_fill",
        "ws_recovery",
    )
    required_operational_checks: tuple[str, ...] = (
        "alerts",
        "runbook",
        "restore_rto",
        "audit_chain",
        "api_key_permissions",
        "ip_whitelist",
        "heartbeat_page",
        "kill_switch",
        "flatten_drill",
        "environment_isolation",
        "canary_approval",
        "llm_shadow_or_disabled",
    )

    def __post_init__(self) -> None:
        if type(self.required_demo_days) is not int or self.required_demo_days < 1:
            raise ValueError("required_demo_days 必须是正整数")
        for name, value in {
            "maximum_stress_loss_usdt": self.maximum_stress_loss_usdt,
            "minimum_oos_sharpe": self.minimum_oos_sharpe,
            "minimum_positive_fold_ratio": self.minimum_positive_fold_ratio,
        }.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} 必须是数值")
            if not math.isfinite(float(value)):
                raise ValueError(f"{name} 必须是有限数")
        if not 0 <= self.maximum_stress_loss_usdt <= 500:
            raise ValueError(
                "maximum_stress_loss_usdt 必须在 0..500 编译期硬上限内"
            )
        if self.minimum_oos_sharpe < 0:
            raise ValueError("minimum_oos_sharpe 不能为负")
        if not 0 <= self.minimum_positive_fold_ratio <= 1:
            raise ValueError("minimum_positive_fold_ratio 必须位于 [0, 1]")

    def evaluate(
        self,
        *,
        walk_forward_metrics: dict,
        portfolio_metrics: dict,
        robustness: dict,
        stress_evidence: dict,
        clean_demo_days: int,
        demo_slippage_observations: list[float],
        research_policy_claims: dict,
        stress_runner_claims: dict,
        demo_slippage_sample_count: int | None = None,
        demo_protection_sample_count: int | None = None,
        engineering_checks: dict[str, bool],
        operational_checks: dict[str, bool],
        evidence_metadata: dict[str, str],
    ) -> dict:
        self._validate_check_map(
            "engineering_checks",
            engineering_checks,
            self.required_engineering_checks,
        )
        self._validate_check_map(
            "operational_checks",
            operational_checks,
            self.required_operational_checks,
        )
        self._validate_metadata(evidence_metadata)
        if not isinstance(robustness, dict):
            raise ValueError("robustness 必须是对象")
        if not isinstance(stress_evidence, dict):
            raise ValueError("stress_evidence 必须是对象")
        self._validate_stress_evidence(stress_evidence)
        folds = self._strict_nonnegative_int(
            walk_forward_metrics.get("folds"), "folds"
        )
        positive = self._strict_nonnegative_int(
            walk_forward_metrics.get("positive_folds"), "positive_folds"
        )
        if positive > folds:
            raise ValueError("positive_folds 不能超过 folds")
        clean_demo_days = self._strict_nonnegative_int(
            clean_demo_days, "clean_demo_days"
        )
        oos_sharpe = self._finite_number(
            walk_forward_metrics.get("oos_sharpe_ratio"),
            "oos_sharpe_ratio",
        )
        oos_return = self._finite_number(
            walk_forward_metrics.get("oos_return_pct"),
            "oos_return_pct",
        )
        oos_observations = self._strict_nonnegative_int(
            walk_forward_metrics.get("oos_observations"),
            "oos_observations",
        )
        oos_duration_days = self._strict_nonnegative_int(
            walk_forward_metrics.get("oos_duration_days"),
            "oos_duration_days",
        )
        oos_total_trades = self._strict_nonnegative_int(
            walk_forward_metrics.get("oos_total_trades"),
            "oos_total_trades",
        )
        oos_drawdown = self._finite_number(
            walk_forward_metrics.get("oos_max_drawdown_pct"),
            "oos_max_drawdown_pct",
        )
        if oos_drawdown > 0:
            raise ValueError("oos_max_drawdown_pct 不能为正")
        portfolio_return = self._finite_number(
            portfolio_metrics.get("total_return_pct"),
            "portfolio.total_return_pct",
        )
        stress_loss_usdt = self._finite_number(
            stress_evidence.get("loss_usdt"), "stress.loss_usdt"
        )
        if stress_loss_usdt < 0:
            raise ValueError("stress_loss_usdt 不能为负")
        claimed_full_cycle = self._strict_bool(
            portfolio_metrics.get("covers_full_cycle"),
            "portfolio.covers_full_cycle",
        )
        shared_cash = self._strict_bool(
            portfolio_metrics.get("shared_cash"),
            "portfolio.shared_cash",
        )
        claimed_plateau = self._strict_bool(
            robustness.get("plateau"), "robustness.plateau"
        )
        cycle = self._recompute_cycle(portfolio_metrics)
        robustness_result = self._recompute_robustness(robustness)
        cost_manifest = self._validate_dynamic_cost_manifest(
            evidence_metadata["cost_model_manifest"]
        )
        if canonical_manifest_hash(cost_manifest) != str(
            evidence_metadata["cost_model_hash"]
        ).lower():
            raise ValueError("动态成本模型 manifest 与 cost_model_hash 不一致")
        self._validate_dataset_provenance(
            evidence_metadata["dataset_provenance"],
            walk_forward_metrics=walk_forward_metrics,
            portfolio_metrics=portfolio_metrics,
        )
        if not isinstance(demo_slippage_observations, list):
            raise ValueError("demo_slippage_observations 必须是数组")
        demo_slippage = [
            self._finite_number(value, "demo observed slippage")
            for value in demo_slippage_observations
        ]
        if any(value < 0 for value in demo_slippage):
            raise ValueError("demo observed slippage 不能为负")
        if demo_slippage_sample_count is None:
            demo_slippage_sample_count = len(demo_slippage)
        if demo_protection_sample_count is None:
            demo_protection_sample_count = self.required_demo_days
        demo_slippage_sample_count = self._strict_nonnegative_int(
            demo_slippage_sample_count,
            "demo_slippage_sample_count",
        )
        demo_protection_sample_count = self._strict_nonnegative_int(
            demo_protection_sample_count,
            "demo_protection_sample_count",
        )
        cost_slippage_limit = float(cost_manifest["maximum_slippage"])
        approved_slippage_limit = float(
            evidence_metadata["approved_max_slippage_ratio"]
        )
        approved_cost_hash = str(evidence_metadata["cost_model_hash"]).lower()
        walk_cost_hash = self._sha256(
            walk_forward_metrics.get("cost_model_hash"),
            "walk_forward.cost_model_hash",
        )
        portfolio_cost_hash = self._sha256(
            portfolio_metrics.get("cost_model_hash"),
            "portfolio.cost_model_hash",
        )
        robustness_cost_hash = self._sha256(
            robustness.get("cost_model_hash"),
            "robustness.cost_model_hash",
        )
        stress_cost_hash = self._sha256(
            stress_evidence.get("cost_model_hash"),
            "stress.cost_model_hash",
        )
        walk_family_hash = self._validate_strategy_family(
            walk_forward_metrics,
            "walk_forward",
        )
        robustness_family_hash = self._validate_strategy_family(
            robustness,
            "robustness",
        )
        walk_evaluation_hash = self._sha256(
            walk_forward_metrics.get("evaluation_manifest_hash"),
            "walk_forward.evaluation_manifest_hash",
        )
        robustness_evaluation_hash = self._sha256(
            robustness.get("evaluation_manifest_hash"),
            "robustness.evaluation_manifest_hash",
        )
        robustness_grid_hash = self._sha256(
            robustness.get("parameter_grid_hash"),
            "robustness.parameter_grid_hash",
        )
        portfolio_evaluation_hash = self._sha256(
            portfolio_metrics.get("evaluation_manifest_hash"),
            "portfolio.evaluation_manifest_hash",
        )
        if self._sha256(
            walk_forward_metrics.get("strategy_hash"),
            "walk_forward.strategy_hash",
        ) != walk_family_hash:
            raise ValueError("walk_forward strategy_hash alias 非法")
        if self._sha256(
            robustness.get("strategy_hash"),
            "robustness.strategy_hash",
        ) != robustness_family_hash:
            raise ValueError("robustness strategy_hash alias 非法")
        if self._sha256(
            portfolio_metrics.get("strategy_hash"),
            "portfolio.strategy_hash",
        ) != portfolio_evaluation_hash:
            raise ValueError("portfolio strategy_hash alias 非法")
        identity = {
            "walk_forward": {
                "cost_model_hash": walk_cost_hash,
                "dataset_hash": self._sha256(
                    walk_forward_metrics.get("dataset_hash"),
                    "walk_forward.dataset_hash",
                ),
                "strategy_hash": self._sha256(
                    walk_family_hash,
                    "walk_forward.strategy_family_hash",
                ),
                "evaluation_manifest_hash": walk_evaluation_hash,
            },
            "portfolio": {
                "cost_model_hash": portfolio_cost_hash,
                "dataset_hash": self._sha256(
                    portfolio_metrics.get("dataset_hash"),
                    "portfolio.dataset_hash",
                ),
                "strategy_hash": self._sha256(
                    portfolio_metrics.get("strategy_hash"),
                    "portfolio.strategy_hash",
                ),
                "evaluation_manifest_hash": portfolio_evaluation_hash,
            },
            "robustness": {
                "cost_model_hash": robustness_cost_hash,
                "dataset_hash": self._sha256(
                    robustness.get("dataset_hash"),
                    "robustness.dataset_hash",
                ),
                "strategy_hash": self._sha256(
                    robustness_family_hash,
                    "robustness.strategy_family_hash",
                ),
                "evaluation_manifest_hash": robustness_evaluation_hash,
                "parameter_grid_hash": robustness_grid_hash,
            },
            "stress": {
                "cost_model_hash": stress_cost_hash,
                "dataset_hash": self._sha256(
                    stress_evidence.get("dataset_hash"),
                    "stress.dataset_hash",
                ),
                "strategy_hash": self._sha256(
                    stress_evidence.get("strategy_hash"),
                    "stress.strategy_hash",
                ),
                "scenario_manifest_hash": self._sha256(
                    stress_evidence.get("scenario_manifest_hash"),
                    "stress.scenario_manifest_hash",
                ),
            },
        }
        computed_research_manifest = canonical_manifest_hash(identity)
        self._validate_research_trust_claims(
            research_policy_claims,
            stress_runner_claims,
            evidence_metadata=evidence_metadata,
            walk_family_hash=walk_family_hash,
            robustness_family_hash=robustness_family_hash,
            parameter_grid_hash=robustness_grid_hash,
            stress_evidence=stress_evidence,
            portfolio_evaluation_hash=portfolio_evaluation_hash,
        )
        checks = {
            "oos_post_cost_positive": oos_return > 0,
            "oos_sharpe_positive": (
                oos_sharpe > self.minimum_oos_sharpe
            ),
            "oos_sufficient_path": (
                oos_observations >= 2
                and oos_duration_days >= 1
                and oos_total_trades >= 1
            ),
            "cost_model_bound": (
                walk_cost_hash == approved_cost_hash
                and portfolio_cost_hash == approved_cost_hash
                and robustness_cost_hash == approved_cost_hash
                and stress_cost_hash == approved_cost_hash
            ),
            "research_manifest_bound": (
                computed_research_manifest
                == str(
                    evidence_metadata["research_manifest_hash"]
                ).lower()
            ),
            "robustness_matches_walk_forward": (
                identity["robustness"]["dataset_hash"]
                == identity["walk_forward"]["dataset_hash"]
                and identity["robustness"]["strategy_hash"]
                == identity["walk_forward"]["strategy_hash"]
            ),
            "stress_matches_portfolio": (
                identity["stress"]["dataset_hash"]
                == identity["portfolio"]["dataset_hash"]
                and identity["stress"]["strategy_hash"]
                == identity["portfolio"]["strategy_hash"]
            ),
            "positive_fold_ratio": (
                folds > 0 and positive / folds >= self.minimum_positive_fold_ratio
            ),
            "portfolio_post_cost_positive": (
                portfolio_return > 0
            ),
            "portfolio_full_cycle": (
                claimed_full_cycle
                and cycle["covers_full_cycle"]
                and self._cycle_claims_match(portfolio_metrics, cycle)
            ),
            "portfolio_shared_cash": shared_cash,
            "parameter_plateau": (
                claimed_plateau
                and robustness_result["plateau"]
                and self._robustness_claims_match(
                    robustness,
                    robustness_result,
                )
            ),
            "dynamic_cost_model": True,
            "demo_slippage_bound_to_cost_model": (
                demo_slippage_sample_count >= self.required_demo_days
                and bool(demo_slippage)
                and approved_slippage_limit == cost_slippage_limit
                and max(demo_slippage, default=math.inf)
                <= cost_slippage_limit
            ),
            "demo_protection_samples": (
                demo_protection_sample_count >= self.required_demo_days
            ),
            "stress_within_budget": (
                stress_loss_usdt <= self.maximum_stress_loss_usdt
            ),
            "demo_30_days": clean_demo_days >= self.required_demo_days,
            **{
                f"engineering.{name}": engineering_checks[name]
                for name in self.required_engineering_checks
            },
            **{
                f"operations.{name}": operational_checks[name]
                for name in self.required_operational_checks
            },
        }
        failed = [name for name, passed in checks.items() if not passed]
        return {"admitted": not failed, "checks": checks, "failed": failed}

    @classmethod
    def _recompute_cycle(cls, metrics: dict) -> dict[str, float | int | bool]:
        raw = metrics.get("cycle_daily_benchmark")
        if not isinstance(raw, list) or not raw:
            raise ValueError("portfolio.cycle_daily_benchmark 必须是非空数组")
        points: list[tuple[date, float]] = []
        for index, item in enumerate(raw):
            if not isinstance(item, dict) or set(item) != {"day", "value"}:
                raise ValueError(
                    "cycle_daily_benchmark 行必须仅含 day/value"
                )
            try:
                day = date.fromisoformat(str(item["day"]))
            except ValueError as exc:
                raise ValueError(
                    f"cycle_daily_benchmark[{index}].day 非法"
                ) from exc
            value = cls._finite_number(
                item["value"],
                f"cycle_daily_benchmark[{index}].value",
            )
            if value <= 0:
                raise ValueError("cycle_daily_benchmark value 必须大于 0")
            points.append((day, value))
        if any(
            right[0] <= left[0]
            for left, right in zip(points, points[1:], strict=False)
        ):
            raise ValueError("cycle_daily_benchmark 日期必须严格递增")
        threshold = cls._finite_number(
            metrics.get("cycle_regime_threshold"),
            "portfolio.cycle_regime_threshold",
        )
        if not 0 < threshold < 1:
            raise ValueError("cycle_regime_threshold 必须位于 (0, 1)")
        return compute_calendar_cycle_metrics(
            points,
            window_days=90,
            minimum_cycle_days=365,
            minimum_cycle_coverage=0.90,
            maximum_cycle_gap_days=7,
            regime_threshold=threshold,
        )

    @classmethod
    def _cycle_claims_match(cls, metrics: dict, computed: dict) -> bool:
        for key, expected in computed.items():
            if key == "covers_full_cycle":
                continue
            actual = metrics.get(key)
            if isinstance(expected, int):
                if type(actual) is not int or actual != expected:
                    return False
            else:
                try:
                    rendered = cls._finite_number(actual, f"portfolio.{key}")
                except ValueError:
                    return False
                if not math.isclose(
                    rendered,
                    float(expected),
                    rel_tol=1e-12,
                    abs_tol=1e-12,
                ):
                    return False
        return True

    @classmethod
    def _recompute_robustness(cls, robustness: dict) -> dict:
        grid_manifest = robustness.get("parameter_grid_manifest")
        if (
            not isinstance(grid_manifest, dict)
            or set(grid_manifest)
            != {"version", "parameters", "point_count"}
            or grid_manifest["version"] != 1
            or not isinstance(grid_manifest["parameters"], dict)
            or not grid_manifest["parameters"]
        ):
            raise ValueError("robustness.parameter_grid_manifest 结构非法")
        grid_hash = cls._sha256(
            robustness.get("parameter_grid_hash"),
            "robustness.parameter_grid_hash",
        )
        if grid_hash != canonical_manifest_hash(grid_manifest):
            raise ValueError("robustness parameter grid hash 不匹配")
        parameter_names = tuple(sorted(grid_manifest["parameters"]))
        if any(
            not isinstance(name, str) or not name
            for name in parameter_names
        ):
            raise ValueError("robustness parameter grid 名称非法")
        grid_values: dict[str, list] = {}
        for name in parameter_names:
            values = grid_manifest["parameters"][name]
            if not isinstance(values, list) or not values:
                raise ValueError("robustness parameter grid 值域非法")
            identities = [
                canonical_manifest_hash({"value": value})
                for value in values
            ]
            if len(identities) != len(set(identities)):
                raise ValueError("robustness parameter grid 含重复值")
            grid_values[name] = values
        expected_count = math.prod(
            len(grid_values[name]) for name in parameter_names
        )
        if (
            type(grid_manifest["point_count"]) is not int
            or grid_manifest["point_count"] != expected_count
        ):
            raise ValueError("robustness parameter grid point_count 非法")
        rows = robustness.get("rows")
        if (
            not isinstance(rows, list)
            or len(rows) < 3
            or len(rows) != expected_count
        ):
            raise ValueError("robustness.rows 至少需要 3 个参数点")
        names: tuple[str, ...] | None = None
        normalized: list[tuple[dict, float, float]] = []
        seen: set[str] = set()
        for index, row in enumerate(rows):
            if (
                not isinstance(row, dict)
                or set(row) != {"params", "sharpe", "return_pct"}
                or not isinstance(row["params"], dict)
                or not row["params"]
            ):
                raise ValueError(
                    f"robustness.rows[{index}] 结构非法"
                )
            current_names = tuple(sorted(row["params"]))
            if names is None:
                names = current_names
            elif names != current_names:
                raise ValueError("robustness 参数维度不一致")
            identity = json.dumps(
                row["params"],
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            if identity in seen:
                raise ValueError("robustness 参数点重复")
            seen.add(identity)
            normalized.append((
                row["params"],
                cls._finite_number(
                    row["sharpe"],
                    f"robustness.rows[{index}].sharpe",
                ),
                cls._finite_number(
                    row["return_pct"],
                    f"robustness.rows[{index}].return_pct",
                ),
            ))
        assert names is not None
        if names != parameter_names:
            raise ValueError("robustness rows 与批准参数网格维度不一致")
        expected_identities = {
            canonical_manifest_hash({
                "params": dict(
                    zip(parameter_names, values, strict=True)
                )
            })
            for values in product(
                *(grid_values[name] for name in parameter_names)
            )
        }
        actual_identities = {
            canonical_manifest_hash({"params": row[0]})
            for row in normalized
        }
        if actual_identities != expected_identities:
            raise ValueError("robustness.rows 未精确覆盖批准参数网格")
        coordinates = {
            index: tuple(
                grid_values[name].index(row[0][name]) for name in names
            )
            for index, row in enumerate(normalized)
        }
        positive = {
            index for index, row in enumerate(normalized) if row[1] > 0
        }
        largest = 0
        unseen = set(positive)
        while unseen:
            stack = [unseen.pop()]
            size = 0
            while stack:
                current = stack.pop()
                size += 1
                neighbors = {
                    candidate
                    for candidate in unseen
                    if sum(
                        abs(left - right)
                        for left, right in zip(
                            coordinates[current],
                            coordinates[candidate],
                            strict=True,
                        )
                    )
                    == 1
                }
                unseen -= neighbors
                stack.extend(neighbors)
            largest = max(largest, size)
        sharpes = [row[1] for row in normalized]
        mean = sum(sharpes) / len(sharpes)
        std = math.sqrt(
            sum((value - mean) ** 2 for value in sharpes)
            / len(sharpes)
        )
        positive_ratio = len(positive) / len(normalized)
        connected_ratio = largest / len(normalized)
        return {
            "plateau": (
                positive_ratio >= 0.6
                and connected_ratio >= 0.6
                and std <= max(abs(mean), 0.5)
            ),
            "positive_ratio": positive_ratio,
            "connected_positive_ratio": connected_ratio,
            "mean_sharpe": mean,
            "sharpe_std": std,
        }

    @classmethod
    def _robustness_claims_match(
        cls,
        robustness: dict,
        computed: dict,
    ) -> bool:
        for key, expected in computed.items():
            if key == "plateau":
                continue
            try:
                actual = cls._finite_number(
                    robustness.get(key),
                    f"robustness.{key}",
                )
            except ValueError:
                return False
            if not math.isclose(
                actual,
                float(expected),
                rel_tol=1e-12,
                abs_tol=1e-12,
            ):
                return False
        return True

    @classmethod
    def _validate_strategy_family(
        cls,
        metrics: dict,
        label: str,
    ) -> str:
        manifest = metrics.get("strategy_family_manifest")
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"version", "strategy_types"}
            or manifest["version"] != 1
            or not isinstance(manifest["strategy_types"], list)
            or not manifest["strategy_types"]
            or any(
                not isinstance(item, str) or not item.strip()
                for item in manifest["strategy_types"]
            )
            or manifest["strategy_types"]
            != sorted(set(manifest["strategy_types"]))
        ):
            raise ValueError(f"{label}.strategy_family_manifest 非法")
        rendered = cls._sha256(
            metrics.get("strategy_family_hash"),
            f"{label}.strategy_family_hash",
        )
        if rendered != canonical_manifest_hash(manifest):
            raise ValueError(f"{label}.strategy_family_hash 不匹配")
        return rendered

    @classmethod
    def _validate_research_trust_claims(
        cls,
        policy: dict,
        attestation: dict,
        *,
        evidence_metadata: dict,
        walk_family_hash: str,
        robustness_family_hash: str,
        parameter_grid_hash: str,
        stress_evidence: dict,
        portfolio_evaluation_hash: str,
    ) -> None:
        policy_keys = {
            "version",
            "action",
            "policy_id",
            "commit_sha",
            "strategy_family_hash",
            "parameter_grid_hash",
            "stress_scenario_manifest_hash",
            "dataset_sources",
            "evaluation_started_at",
            "issued_at",
        }
        if not isinstance(policy, dict) or set(policy) != policy_keys:
            raise ValueError("research policy claims 结构非法")
        if (
            policy["version"] != 1
            or policy["action"] != "pre-register-research-policy"
            or not isinstance(policy["policy_id"], str)
            or not policy["policy_id"].strip()
            or str(policy["commit_sha"]).lower()
            != str(evidence_metadata["commit_sha"]).lower()
            or cls._sha256(
                policy["strategy_family_hash"],
                "research policy strategy_family_hash",
            )
            not in {walk_family_hash, robustness_family_hash}
            or walk_family_hash != robustness_family_hash
            or cls._sha256(
                policy["parameter_grid_hash"],
                "research policy parameter_grid_hash",
            )
            != parameter_grid_hash
            or cls._sha256(
                policy["stress_scenario_manifest_hash"],
                "research policy stress_scenario_manifest_hash",
            )
            != str(stress_evidence["scenario_manifest_hash"]).lower()
        ):
            raise ValueError("research policy 未绑定当前研究身份/网格/压力场景")
        expected_sources = {
            name: {
                key: manifest[key]
                for key in (
                    "source_uri",
                    "source_version_id",
                    "source_sha256",
                )
            }
            for name, manifest in sorted(
                evidence_metadata["dataset_provenance"].items()
            )
        }
        if policy["dataset_sources"] != expected_sources:
            raise ValueError("research policy 未绑定 exact dataset locator")
        evaluation_started = datetime.fromisoformat(
            str(policy["evaluation_started_at"])
        )
        DemoObservationLedger._require_aware(
            evaluation_started,
            "research policy evaluation_started_at",
        )
        if (
            type(policy["issued_at"]) is not int
            or datetime.fromtimestamp(policy["issued_at"], tz=UTC)
            > evaluation_started.astimezone(UTC)
        ):
            raise ValueError("research policy 必须在评估开始前签发")

        attestation_keys = {
            "version",
            "action",
            "policy_id",
            "commit_sha",
            "dataset_hash",
            "cost_model_hash",
            "portfolio_evaluation_manifest_hash",
            "scenario_manifest_hash",
            "stress_evidence_sha256",
            "runner",
            "issued_at",
        }
        if (
            not isinstance(attestation, dict)
            or set(attestation) != attestation_keys
            or attestation["version"] != 1
            or attestation["action"] != "attest-stress-run"
            or attestation["policy_id"] != policy["policy_id"]
            or str(attestation["commit_sha"]).lower()
            != str(evidence_metadata["commit_sha"]).lower()
            or not isinstance(attestation["runner"], str)
            or not attestation["runner"].strip()
            or type(attestation["issued_at"]) is not int
        ):
            raise ValueError("stress runner attestation claims 结构非法")
        expected_stress = {
            "dataset_hash": str(stress_evidence["dataset_hash"]).lower(),
            "cost_model_hash": str(stress_evidence["cost_model_hash"]).lower(),
            "portfolio_evaluation_manifest_hash": (
                portfolio_evaluation_hash
            ),
            "scenario_manifest_hash": str(
                stress_evidence["scenario_manifest_hash"]
            ).lower(),
            "stress_evidence_sha256": hashlib.sha256(
                json.dumps(
                    stress_evidence,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        }
        for key, expected in expected_stress.items():
            if cls._sha256(
                attestation.get(key),
                f"stress attestation {key}",
            ) != expected:
                raise ValueError(f"stress runner attestation 未绑定 {key}")

    @classmethod
    def _validate_stress_evidence(cls, evidence: dict) -> None:
        required = {
            "loss_usdt",
            "cost_model_hash",
            "dataset_hash",
            "strategy_hash",
            "scenario_manifest",
            "scenario_manifest_hash",
            "initial_capital",
            "scenarios",
        }
        if set(evidence) != required:
            raise ValueError("stress_evidence 字段不完整或含未知字段")
        initial = cls._finite_number(
            evidence["initial_capital"],
            "stress.initial_capital",
        )
        if initial <= 0:
            raise ValueError("stress.initial_capital 必须大于 0")
        manifest = evidence["scenario_manifest"]
        rows = evidence["scenarios"]
        if (
            not isinstance(manifest, list)
            or not manifest
            or not isinstance(rows, list)
            or len(rows) != len(manifest)
        ):
            raise ValueError("stress scenario manifest/rows 非法")
        if cls._sha256(
            evidence["scenario_manifest_hash"],
            "stress.scenario_manifest_hash",
        ) != canonical_manifest_hash(manifest):
            raise ValueError("stress scenario manifest hash 不匹配")
        names: set[str] = set()
        losses: list[float] = []
        has_required_severe_scenario = False
        scenario_keys = {
            "name",
            "gap_ratio",
            "volume_multiplier",
            "volatility_multiplier",
        }
        row_keys = {
            "name",
            "scenario",
            "scenario_hash",
            "final_capital",
            "loss_usdt",
            "stressed_dataset_hash",
        }
        for index, (scenario, row) in enumerate(
            zip(manifest, rows, strict=True)
        ):
            if (
                not isinstance(scenario, dict)
                or set(scenario) != scenario_keys
                or not isinstance(row, dict)
                or set(row) != row_keys
                or row["scenario"] != scenario
                or row["name"] != scenario["name"]
            ):
                raise ValueError(f"stress scenario[{index}] 结构非法")
            name = scenario["name"]
            if (
                not isinstance(name, str)
                or not name.strip()
                or name in names
            ):
                raise ValueError("stress scenario name 非法")
            names.add(name)
            gap = cls._finite_number(
                scenario["gap_ratio"],
                f"stress scenario[{index}].gap_ratio",
            )
            volume = cls._finite_number(
                scenario["volume_multiplier"],
                f"stress scenario[{index}].volume_multiplier",
            )
            volatility = cls._finite_number(
                scenario["volatility_multiplier"],
                f"stress scenario[{index}].volatility_multiplier",
            )
            if not 0 <= gap < 1 or volume <= 0 or volatility <= 0:
                raise ValueError("stress scenario 参数越界")
            has_required_severe_scenario = (
                has_required_severe_scenario
                or (
                    gap >= 0.10
                    and volume <= 0.25
                    and volatility >= 3
                )
            )
            if cls._sha256(
                row["scenario_hash"],
                f"stress scenario[{index}].scenario_hash",
            ) != canonical_manifest_hash(scenario):
                raise ValueError("stress scenario row hash 不匹配")
            final = cls._finite_number(
                row["final_capital"],
                f"stress scenario[{index}].final_capital",
            )
            loss = cls._finite_number(
                row["loss_usdt"],
                f"stress scenario[{index}].loss_usdt",
            )
            if final < 0 or loss < 0 or not math.isclose(
                loss,
                max(initial - final, 0),
                rel_tol=1e-12,
                abs_tol=1e-9,
            ):
                raise ValueError("stress scenario loss 无法由资本重算")
            cls._sha256(
                row["stressed_dataset_hash"],
                f"stress scenario[{index}].stressed_dataset_hash",
            )
            losses.append(loss)
        if not has_required_severe_scenario:
            raise ValueError(
                "stress evidence 缺少生产硬下限场景："
                "gap>=10%、volume<=25%、volatility>=3x"
            )
        top_loss = cls._finite_number(
            evidence["loss_usdt"],
            "stress.loss_usdt",
        )
        if not math.isclose(
            top_loss,
            max(losses),
            rel_tol=1e-12,
            abs_tol=1e-9,
        ):
            raise ValueError("stress.loss_usdt 不是场景最大损失")

    @classmethod
    def _validate_dynamic_cost_manifest(cls, manifest: object) -> dict:
        required = {
            "model",
            "fee_rate",
            "minimum_slippage",
            "range_fraction",
            "impact_coefficient",
            "maximum_slippage",
            "stress_multiplier",
        }
        if not isinstance(manifest, dict) or set(manifest) != required:
            raise ValueError("cost_model_manifest 字段不完整或含未知字段")
        if (
            manifest["model"]
            != "okx_quant.research.costs.DynamicCostModel"
        ):
            raise ValueError("生产准入只接受 DynamicCostModel")
        kwargs = {
            key: cls._finite_number(
                manifest[key],
                f"cost_model_manifest.{key}",
            )
            for key in required - {"model"}
        }
        model = DynamicCostModel(**kwargs)
        normalized = model.manifest()
        if normalized != manifest:
            raise ValueError(
                "动态成本 manifest 未使用模型自身的规范表示"
            )
        if model.maximum_slippage > 0.05:
            raise ValueError("动态成本 maximum_slippage 超过生产硬上限")
        return normalized

    @classmethod
    def _validate_dataset_provenance(
        cls,
        manifests: object,
        *,
        walk_forward_metrics: dict,
        portfolio_metrics: dict,
    ) -> None:
        if (
            not isinstance(manifests, dict)
            or set(manifests) != {"walk_forward", "portfolio"}
        ):
            raise ValueError("dataset_provenance 必须包含 walk_forward/portfolio")
        expected_hashes = {
            "walk_forward": walk_forward_metrics.get("dataset_hash"),
            "portfolio": portfolio_metrics.get("dataset_hash"),
        }
        required = {
            "version",
            "kind",
            "provider",
            "source_uri",
            "source_version_id",
            "source_sha256",
            "source_artifact",
            "dataset_hash",
            "retrieved_at",
            "start_at",
            "end_at",
            "instruments",
            "bar",
            "rows",
        }
        for name, manifest in manifests.items():
            if not isinstance(manifest, dict) or set(manifest) != required:
                raise ValueError(f"dataset_provenance.{name} 结构非法")
            if manifest["version"] != 2 or manifest["kind"] != name:
                raise ValueError(f"dataset_provenance.{name}.version 非法")
            for key in ("provider", "bar"):
                if not isinstance(manifest[key], str) or not manifest[key].strip():
                    raise ValueError(
                        f"dataset_provenance.{name}.{key} 不能为空"
                    )
            source = urlparse(str(manifest["source_uri"]))
            if (
                source.scheme != "s3"
                or not source.netloc
                or not source.path.strip("/")
                or not isinstance(manifest["source_version_id"], str)
                or not manifest["source_version_id"].strip()
            ):
                raise ValueError(
                    f"dataset_provenance.{name} 必须绑定版本化 S3 对象"
                )
            source_hash = cls._sha256(
                manifest["source_sha256"],
                f"dataset_provenance.{name}.source_sha256",
            )
            artifact = manifest["source_artifact"]
            if hashlib.sha256(
                canonical_artifact_bytes(artifact)
            ).hexdigest() != source_hash:
                raise ValueError(
                    f"dataset_provenance.{name} source bytes hash 不匹配"
                )
            frames = frames_from_artifact(artifact)
            if (
                artifact["kind"] != name
                or artifact["provider"] != manifest["provider"]
                or artifact["bar"] != manifest["bar"]
            ):
                raise ValueError(
                    f"dataset_provenance.{name} artifact identity 不匹配"
                )
            component_hashes = {
                inst_id: canonical_manifest_hash(payload)
                for inst_id, payload in sorted(
                    artifact["datasets"].items()
                )
            }
            computed_dataset_hash = (
                next(iter(component_hashes.values()))
                if name == "walk_forward"
                and len(component_hashes) == 1
                else canonical_manifest_hash(component_hashes)
            )
            dataset_hash = cls._sha256(
                manifest["dataset_hash"],
                f"dataset_provenance.{name}.dataset_hash",
            )
            if (
                dataset_hash != computed_dataset_hash
                or dataset_hash != str(expected_hashes[name]).lower()
            ):
                raise ValueError(
                    f"dataset_provenance.{name} 未绑定 source/research dataset_hash"
                )
            parsed_times = {}
            for key in ("retrieved_at", "start_at", "end_at"):
                parsed = datetime.fromisoformat(str(manifest[key]))
                DemoObservationLedger._require_aware(
                    parsed,
                    f"dataset_provenance.{name}.{key}",
                )
                parsed_times[key] = parsed.astimezone(UTC)
            if not (
                parsed_times["start_at"] < parsed_times["end_at"]
                <= parsed_times["retrieved_at"]
                <= datetime.now(UTC) + timedelta(minutes=5)
            ):
                raise ValueError(
                    f"dataset_provenance.{name} 时间范围非法"
                )
            if (
                not isinstance(manifest["instruments"], list)
                or not manifest["instruments"]
                or any(
                    not isinstance(item, str) or not item
                    for item in manifest["instruments"]
                )
                or len(set(manifest["instruments"]))
                != len(manifest["instruments"])
            ):
                raise ValueError(
                    f"dataset_provenance.{name}.instruments 非法"
                )
            if type(manifest["rows"]) is not int or manifest["rows"] < 1:
                raise ValueError(f"dataset_provenance.{name}.rows 非法")
            source_timestamps = pd.concat(
                [frame["ts"] for frame in frames.values()],
                ignore_index=True,
            )
            if (
                manifest["instruments"] != sorted(frames)
                or manifest["rows"]
                != sum(len(frame) for frame in frames.values())
            ):
                raise ValueError(
                    f"dataset_provenance.{name} rows/time/instruments 不匹配"
                )
            actual_start = (
                source_timestamps.min().to_pydatetime().astimezone(UTC)
            )
            actual_end = (
                source_timestamps.max().to_pydatetime().astimezone(UTC)
            )
            if (
                parsed_times["start_at"] != actual_start
                or parsed_times["end_at"] != actual_end
            ):
                raise ValueError(
                    f"dataset_provenance.{name} 时间范围未绑定 source"
                )
            if name == "portfolio":
                cls._validate_cycle_against_source(
                    portfolio_metrics,
                    frames,
                )

    @classmethod
    def _validate_cycle_against_source(
        cls,
        portfolio_metrics: dict,
        frames: dict[str, pd.DataFrame],
    ) -> None:
        weights = portfolio_metrics.get("cycle_benchmark_weights")
        if (
            not isinstance(weights, dict)
            or set(weights) != set(frames)
        ):
            raise ValueError("portfolio cycle benchmark weights 未绑定数据集")
        normalized_weights = {}
        for inst_id, value in weights.items():
            rendered = cls._finite_number(
                value,
                f"portfolio.cycle_benchmark_weights.{inst_id}",
            )
            if rendered < 0:
                raise ValueError("portfolio cycle benchmark weight 不能为负")
            normalized_weights[inst_id] = rendered
        if not math.isclose(
            sum(normalized_weights.values()),
            1.0,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            raise ValueError("portfolio cycle benchmark weights 必须归一化")
        components = []
        for inst_id, frame in sorted(frames.items()):
            indexed = frame.set_index("ts")
            daily = indexed["close"].astype(float).resample("1D").last()
            components.append(
                daily / daily.iloc[0] * normalized_weights[inst_id]
            )
        benchmark = pd.concat(components, axis=1, join="inner").sum(
            axis=1,
            min_count=len(components),
        ).dropna()
        expected = [
            {
                "day": timestamp.date().isoformat(),
                "value": float(value),
            }
            for timestamp, value in benchmark.items()
        ]
        claimed = portfolio_metrics.get("cycle_daily_benchmark")
        if (
            not isinstance(claimed, list)
            or len(claimed) != len(expected)
        ):
            raise ValueError("portfolio cycle benchmark 未绑定 source")
        for actual, source in zip(claimed, expected, strict=True):
            if (
                not isinstance(actual, dict)
                or set(actual) != {"day", "value"}
                or actual["day"] != source["day"]
                or not math.isclose(
                    cls._finite_number(
                        actual["value"],
                        "portfolio.cycle_daily_benchmark.value",
                    ),
                    source["value"],
                    rel_tol=1e-12,
                    abs_tol=1e-12,
                )
            ):
                raise ValueError("portfolio cycle benchmark 未绑定 source")

    @staticmethod
    def _strict_bool(value, name: str) -> bool:
        if type(value) is not bool:
            raise ValueError(f"{name} 必须是 JSON 原生布尔值")
        return value

    @staticmethod
    def _strict_nonnegative_int(value, name: str) -> int:
        if type(value) is not int or value < 0:
            raise ValueError(f"{name} 必须是非负整数")
        return value

    @staticmethod
    def _finite_number(value, name: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} 必须是数值")
        rendered = float(value)
        if not math.isfinite(rendered):
            raise ValueError(f"{name} 必须是有限数")
        return rendered

    @staticmethod
    def _sha256(value, name: str) -> str:
        rendered = str(value)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", rendered):
            raise ValueError(f"{name} 必须是 SHA-256")
        return rendered.lower()

    @classmethod
    def _validate_check_map(
        cls,
        name: str,
        values: dict,
        required: tuple[str, ...],
    ) -> None:
        if not isinstance(values, dict):
            raise ValueError(f"{name} 必须是对象")
        if set(values) != set(required):
            missing = sorted(set(required) - set(values))
            unknown = sorted(set(values) - set(required))
            raise ValueError(
                f"{name} 证据键不完整: missing={missing}, unknown={unknown}"
            )
        for key in required:
            cls._strict_bool(values[key], f"{name}.{key}")

    @staticmethod
    def _validate_metadata(metadata: dict[str, object]) -> None:
        required = {
            "commit_sha",
            "config_hash",
            "cost_model_hash",
            "cost_model_manifest",
            "dataset_provenance",
            "research_manifest_hash",
            "approved_max_slippage_ratio",
            "monitor_key_fingerprint",
            "research_policy_key_fingerprint",
            "account_id",
            "environment",
            "evidence_uri",
            "generated_at",
            "expires_at",
            "operator",
            "risk_approver",
        }
        if not isinstance(metadata, dict) or set(metadata) != required:
            raise ValueError("evidence_metadata 字段不完整或含未知字段")
        if not re.fullmatch(r"[0-9a-fA-F]{40}", str(metadata["commit_sha"])):
            raise ValueError("evidence_metadata.commit_sha 必须是完整 SHA")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", str(metadata["config_hash"])):
            raise ValueError("evidence_metadata.config_hash 必须是 SHA-256")
        if not re.fullmatch(
            r"[0-9a-fA-F]{64}", str(metadata["cost_model_hash"])
        ):
            raise ValueError("evidence_metadata.cost_model_hash 必须是 SHA-256")
        if not re.fullmatch(
            r"[0-9a-fA-F]{64}", str(metadata["research_manifest_hash"])
        ):
            raise ValueError(
                "evidence_metadata.research_manifest_hash 必须是 SHA-256"
            )
        if not re.fullmatch(
            r"[0-9a-fA-F]{64}",
            str(metadata["monitor_key_fingerprint"]),
        ):
            raise ValueError(
                "evidence_metadata.monitor_key_fingerprint 必须是 SHA-256"
            )
        if not re.fullmatch(
            r"[0-9a-fA-F]{64}",
            str(metadata["research_policy_key_fingerprint"]),
        ):
            raise ValueError(
                "evidence_metadata.research_policy_key_fingerprint "
                "必须是 SHA-256"
            )
        cost_manifest = AdmissionGate._validate_dynamic_cost_manifest(
            metadata["cost_model_manifest"]
        )
        if canonical_manifest_hash(cost_manifest) != str(
            metadata["cost_model_hash"]
        ).lower():
            raise ValueError(
                "evidence_metadata.cost_model_manifest/hash 不一致"
            )
        approved_slippage = metadata["approved_max_slippage_ratio"]
        if (
            isinstance(approved_slippage, bool)
            or not isinstance(approved_slippage, (int, float))
            or not math.isfinite(float(approved_slippage))
            or not 0 <= float(approved_slippage) <= 0.05
        ):
            raise ValueError(
                "evidence_metadata.approved_max_slippage_ratio "
                "必须是 [0, 0.05] 内有限数"
            )
        for key in {
            "account_id",
            "environment",
            "evidence_uri",
            "operator",
            "risk_approver",
        }:
            if not isinstance(metadata[key], str) or not metadata[key].strip():
                raise ValueError(f"evidence_metadata.{key} 不能为空")
        if metadata["environment"] not in {"canary", "production"}:
            raise ValueError("最终准入证据必须绑定 canary/production 环境")
        if metadata["operator"].strip() == metadata["risk_approver"].strip():
            raise ValueError("生产准入必须由不同 operator 和 risk approver 签署")
        evidence_uri = urlparse(metadata["evidence_uri"])
        if (
            evidence_uri.scheme != "s3"
            or not evidence_uri.netloc
            or not evidence_uri.path.strip("/")
        ):
            raise ValueError("evidence_uri 必须指向 S3 不可变证据对象")
        if (
            str(metadata["commit_sha"]) == "0" * 40
            or any(
                str(metadata[key]) == "0" * 64
                for key in (
                    "config_hash",
                    "cost_model_hash",
                    "research_manifest_hash",
                    "monitor_key_fingerprint",
                    "research_policy_key_fingerprint",
                )
            )
        ):
            raise ValueError("生产准入禁止 placeholder/全零身份哈希")
        generated_raw = datetime.fromisoformat(metadata["generated_at"])
        expires_raw = datetime.fromisoformat(metadata["expires_at"])
        DemoObservationLedger._require_aware(
            generated_raw, "evidence_metadata.generated_at"
        )
        DemoObservationLedger._require_aware(
            expires_raw, "evidence_metadata.expires_at"
        )
        generated = generated_raw.astimezone(UTC)
        expires = expires_raw.astimezone(UTC)
        now = datetime.now(UTC)
        if generated > now + timedelta(minutes=5):
            raise ValueError("准入证据生成时间位于未来")
        if expires <= now or expires - generated > timedelta(days=7):
            raise ValueError("准入证据已过期或有效期超过 7 天")
