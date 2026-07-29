"""正式 Demo soak epoch、双签身份与 append-only v2 ledger。"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)
from okx_quant.application.demo_probe import (
    formal_probe_schedule_sha256,
    validate_formal_probe_schedule,
)
from okx_quant.infrastructure.evidence import ed25519_public_key_fingerprint
from okx_quant.ops.slo import (
    SLO_V2_POLICY,
    SLO_V2_POLICY_HASH,
    SLO_V2_SCHEMA,
    evaluate_slo_v2_day,
    validate_slo_v2_report,
)
from okx_quant.ops.stage_c_deployment_identity import (
    validate_stage_c_chaos_deployment_identity,
)

_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
CANARY_SOURCE_PRODUCER_NAMES = {
    "account_uid_verified",
    "api_key_read_trade_only",
    "api_key_withdraw_disabled",
    "ip_allowlist_verified",
    "journal_identity_verified",
    "limits_match_policy",
    "release_identity_verified",
    "alert_challenge_received",
    "backup_exact_version_restored",
    "protected_position_or_flat",
    "rest_ws_reconciliation_safe",
    "runtime_safety_kernel_live_within_60s",
}
_CANARY_PRODUCER_KEYS = {
    "source_key_fingerprint",
    "collector_unix_user",
    "signer_unix_user",
    "collector_systemd_unit",
    "signer_systemd_unit",
    "iam_principal",
    "source_authority",
    "source_request_sha256",
    "collector_executable_sha256",
    "signer_executable_sha256",
    "parser_sha256",
    "worm_object_uri",
    "worm_request_origin",
    "worm_kms_key_id",
    "worm_aws_region",
    "worm_reader_access_key_fingerprint",
    "raw_source_path",
    "artifact_output_path",
}
_CANARY_SOURCE_AUTHORITIES = {
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

SOAK_EPOCH_KEYS = {
    "version",
    "action",
    "soak_epoch_id",
    "issued_at",
    "started_at",
    "release_identity",
    "deployment_identity",
    "stage_c_chaos_deployment_identity",
    "strategy_identity",
    "probe_policy",
    "slo_schema",
    "slo_policy_hash",
    "monitor_key_fingerprint",
    "risk_key_fingerprint",
    "observation_key_fingerprint",
    "external_source_key_fingerprints",
    "canary_source_producer_inventory",
    "operator",
    "risk_approver",
}

ANCHOR_V2_KEYS = {
    "version",
    "action",
    "day",
    "soak_epoch_id",
    "phase",
    "status",
    "reason_codes",
    "previous_hash",
    "report_sha256",
    "source_uri",
    "source_version_id",
    "source_sha256",
    "hard_metrics",
    "monitor",
    "issued_at",
}

ROW_KEYS = {
    "version",
    "day",
    "soak_epoch_id",
    "phase",
    "status",
    "reason_codes",
    "release_identity_sha256",
    "deployment_identity_sha256",
    "report_sha256",
    "source_uri",
    "source_version_id",
    "source_sha256",
    "observation_started_at",
    "observation_ended_at",
    "protection_sample_count",
    "protection_p95_seconds",
    "protection_p99_seconds",
    "protection_max_seconds",
    "slippage_sample_count",
    "slippage_p95_ratio",
    "slippage_p99_ratio",
    "slippage_max_ratio",
    "probe_attempt_count",
    "probe_done_count",
    "protection_lifecycle_count",
    "unexplained_mismatches",
    "hard_metrics",
    "previous_hash",
    "recorded_at",
    "anchor",
    "entry_hash",
}


def identity_hash(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def risk_behavior_hash(config: dict, strategy: str) -> str:
    """Bind behavior shared by Demo/Canary, excluding deployment-only limits."""
    strategies = config.get("strategies", {})
    strategy_config = strategies.get(strategy, {}) if isinstance(strategies, dict) else {}
    return identity_hash(
        {
            "risk": config.get("risk", {}),
            "strategy": strategy_config,
        }
    )


def validate_strategy_identity(payload: object) -> dict:
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "strategy",
            "bar",
            "instruments",
            "interval_seconds",
            "risk_parameters_sha256",
        }
        or not str(payload["strategy"]).strip()
        or not str(payload["bar"]).strip()
        or not isinstance(payload["instruments"], list)
        or not payload["instruments"]
        or payload["instruments"] != sorted(set(payload["instruments"]))
        or isinstance(payload["interval_seconds"], bool)
        or not isinstance(payload["interval_seconds"], (int, float))
        or not 0 < float(payload["interval_seconds"]) <= 86400
        or not _SHA256.fullmatch(str(payload["risk_parameters_sha256"]))
    ):
        raise ValueError("strategy_identity 非法")
    return payload


def validate_canary_source_producer_inventory(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != CANARY_SOURCE_PRODUCER_NAMES:
        raise ValueError("Canary producer inventory 必须精确覆盖 12 类 source")
    fingerprints: set[str] = set()
    unix_users: set[str] = set()
    units: set[str] = set()
    iam_principals: set[str] = set()
    raw_paths: set[str] = set()
    output_paths: set[str] = set()
    worm_object_uris: set[str] = set()
    for name, producer in payload.items():
        if (
            not isinstance(producer, dict)
            or set(producer) != _CANARY_PRODUCER_KEYS
            or not _SHA256.fullmatch(str(producer["source_key_fingerprint"]))
            or not _SHA256.fullmatch(
                str(producer["source_request_sha256"])
            )
            or any(
                not _SHA256.fullmatch(str(producer[key]))
                for key in (
                    "collector_executable_sha256",
                    "signer_executable_sha256",
                    "parser_sha256",
                )
            )
            or producer["source_authority"] != _CANARY_SOURCE_AUTHORITIES[name]
        ):
            raise ValueError(f"Canary producer {name} schema/authority 非法")
        collector_user = str(producer["collector_unix_user"])
        signer_user = str(producer["signer_unix_user"])
        collector_unit = str(producer["collector_systemd_unit"])
        signer_unit = str(producer["signer_systemd_unit"])
        iam_principal = str(producer["iam_principal"])
        raw_path = Path(str(producer["raw_source_path"]))
        output_path = Path(str(producer["artifact_output_path"]))
        worm_object = urlparse(str(producer["worm_object_uri"]))
        worm_origin = urlparse(str(producer["worm_request_origin"]))
        worm_bucket = worm_object.netloc
        if (
            not re.fullmatch(r"[a-z_][a-z0-9_-]{2,31}", collector_user)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{2,31}", signer_user)
            or collector_user == signer_user
            or not re.fullmatch(
                r"okx-quant-canary-[a-z0-9_.@-]+\.service",
                collector_unit,
            )
            or not re.fullmatch(
                r"okx-quant-canary-[a-z0-9_.@-]+\.service",
                signer_unit,
            )
            or collector_unit == signer_unit
            or not iam_principal.strip()
            or iam_principal.startswith("CHANGE_ME")
            or not raw_path.is_absolute()
            or not raw_path.is_relative_to("/var/lib/okx-quant-canary-sources/raw")
            or not output_path.is_absolute()
            or not output_path.is_relative_to("/var/lib/okx-quant-canary-sources/signed")
            or ".." in raw_path.parts
            or ".." in output_path.parts
            or worm_object.scheme != "s3"
            or not re.fullmatch(
                r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",
                worm_bucket,
            )
            or not worm_object.path.lstrip("/")
            or worm_object.params
            or worm_object.query
            or worm_object.fragment
            or worm_origin.scheme != "https"
            or worm_origin.username is not None
            or worm_origin.password is not None
            or worm_origin.port is not None
            or worm_origin.path not in {"", "/"}
            or worm_origin.query
            or worm_origin.fragment
            or not re.fullmatch(
                rf"{re.escape(worm_bucket)}\.s3\."
                rf"{re.escape(str(producer['worm_aws_region']))}"
                r"\.amazonaws\.com",
                str(worm_origin.hostname),
            )
            or not re.fullmatch(
                r"[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*",
                str(producer["worm_aws_region"]),
            )
            or not re.fullmatch(
                rf"arn:aws:kms:{re.escape(str(producer['worm_aws_region']))}:"
                r"[0-9]{12}:"
                r"(?:key|alias)/[A-Za-z0-9/_+=,.@:-]{1,256}",
                str(producer["worm_kms_key_id"]),
            )
            or not _SHA256.fullmatch(
                str(producer["worm_reader_access_key_fingerprint"])
            )
        ):
            raise ValueError(f"Canary producer {name} Unix/systemd/IAM/path 隔离非法")
        fingerprint = producer["source_key_fingerprint"]
        if (
            fingerprint in fingerprints
            or collector_user in unix_users
            or signer_user in unix_users
            or collector_unit in units
            or signer_unit in units
            or iam_principal in iam_principals
            or str(raw_path) in raw_paths
            or str(output_path) in output_paths
            or producer["worm_object_uri"] in worm_object_uris
        ):
            raise ValueError("Canary 12 类 producers 必须使用独立 key/user/unit/IAM/path")
        fingerprints.add(fingerprint)
        unix_users.update({collector_user, signer_user})
        units.update({collector_unit, signer_unit})
        iam_principals.add(iam_principal)
        raw_paths.add(str(raw_path))
        output_paths.add(str(output_path))
        worm_object_uris.add(producer["worm_object_uri"])
    return payload


def canary_source_producer_inventory_sha256(payload: object) -> str:
    """Return the canonical identity of the complete 12-producer inventory."""
    inventory = validate_canary_source_producer_inventory(payload)
    return hashlib.sha256(canonical_bytes(inventory)).hexdigest()


def validate_soak_epoch(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != SOAK_EPOCH_KEYS:
        raise ValueError("soak epoch schema 不完整或含未知字段")
    if (
        payload["version"] != 1
        or payload["action"] != "start-demo-soak-epoch"
        or not re.fullmatch(
            r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{7,127}",
            str(payload["soak_epoch_id"]),
        )
        or payload["slo_schema"] != SLO_V2_SCHEMA
        or payload["slo_policy_hash"] != SLO_V2_POLICY_HASH
    ):
        raise ValueError("soak epoch version/id/SLO policy 非法")
    started = datetime.fromisoformat(str(payload["started_at"]))
    if (
        started.tzinfo is None
        or started.utcoffset() is None
        or type(payload["issued_at"]) is not int
        or payload["issued_at"] <= 0
    ):
        raise ValueError("soak epoch started_at 必须带时区")
    release = payload["release_identity"]
    if (
        not isinstance(release, dict)
        or set(release)
        != {
            "git_commit",
            "git_tree_hash",
            "source_manifest_sha256",
            "dependency_lock_sha256",
            "interpreter_sha256",
        }
        or not _SHA1.fullmatch(str(release["git_commit"]))
        or not _SHA1.fullmatch(str(release["git_tree_hash"]))
        or any(
            not _SHA256.fullmatch(str(release[key]))
            for key in (
                "source_manifest_sha256",
                "dependency_lock_sha256",
                "interpreter_sha256",
            )
        )
    ):
        raise ValueError("soak epoch release_identity 非法")
    deployment = payload["deployment_identity"]
    if (
        not isinstance(deployment, dict)
        or set(deployment)
        != {
            "release_identity_sha256",
            "config_sha256",
            "launch_sha256",
            "account_uid",
            "environment",
            "unit",
            "host_image_sha256",
            "key_fingerprints",
            "canary_source_producer_inventory_sha256",
        }
        or deployment["release_identity_sha256"] != identity_hash(release)
        or deployment["environment"] != "demo"
        or not str(deployment["account_uid"]).strip()
        or not str(deployment["unit"]).strip()
        or not isinstance(deployment["key_fingerprints"], list)
        or not deployment["key_fingerprints"]
        or any(
            not _SHA256.fullmatch(str(deployment[key]))
            for key in (
                "release_identity_sha256",
                "config_sha256",
                "launch_sha256",
                "host_image_sha256",
                "canary_source_producer_inventory_sha256",
            )
        )
        or any(not _SHA256.fullmatch(str(item)) for item in deployment["key_fingerprints"])
    ):
        raise ValueError("soak epoch deployment_identity 非法")
    stage_c_identity = validate_stage_c_chaos_deployment_identity(
        payload["stage_c_chaos_deployment_identity"]
    )
    if (
        stage_c_identity["host_image_sha256"]
        != deployment["host_image_sha256"]
        or stage_c_identity["exact_release"]["account_uid"]
        != deployment["account_uid"]
    ):
        raise ValueError("soak epoch Stage-C candidate 未绑定主部署")
    try:
        validate_strategy_identity(payload["strategy_identity"])
    except ValueError as exc:
        raise ValueError("soak epoch strategy_identity 非法") from exc
    probe = payload["probe_policy"]
    if (
        not isinstance(probe, dict)
        or set(probe)
        != {
            "minimum_notional_usdt",
            "maximum_notional_usdt",
            "minimum_daily_probes",
            "maximum_daily_probes",
            "schedule",
            "schedule_sha256",
            "cost_model_hash",
        }
        or not 5
        <= float(probe["minimum_notional_usdt"])
        <= float(probe["maximum_notional_usdt"])
        <= 10
        or probe["minimum_daily_probes"] != 1
        or probe["maximum_daily_probes"] != 1
        or not _SHA256.fullmatch(str(probe["schedule_sha256"]))
        or not _SHA256.fullmatch(str(probe["cost_model_hash"]))
    ):
        raise ValueError("soak epoch probe_policy 非法")
    try:
        schedule = validate_formal_probe_schedule(probe["schedule"])
    except ValueError as exc:
        raise ValueError("soak epoch formal probe schedule 非法") from exc
    started_utc = started.astimezone(UTC)
    schedule_created = datetime.fromisoformat(str(schedule["created_at"])).astimezone(UTC)
    issued_at = datetime.fromtimestamp(payload["issued_at"], UTC)
    scheduled_instruments = sorted({str(item["inst_id"]) for item in schedule["slots"]})
    first_schedule_day = date.fromisoformat(schedule["slots"][0]["day"])
    if (
        formal_probe_schedule_sha256(schedule) != probe["schedule_sha256"]
        or scheduled_instruments != payload["strategy_identity"]["instruments"]
        or schedule_created >= issued_at
        or issued_at >= started_utc
        or started_utc.time() != datetime.min.time()
        or first_schedule_day != started_utc.date()
    ):
        raise ValueError(
            "soak epoch schedule hash/instruments/pre-registration/start day 未精确绑定"
        )
    role_fingerprints = [
        payload[key]
        for key in (
            "monitor_key_fingerprint",
            "risk_key_fingerprint",
            "observation_key_fingerprint",
        )
    ]
    for key in (
        "monitor_key_fingerprint",
        "risk_key_fingerprint",
        "observation_key_fingerprint",
    ):
        if not _SHA256.fullmatch(str(payload[key])):
            raise ValueError(f"soak epoch {key} 非法")
    if len(set(role_fingerprints)) != len(role_fingerprints):
        raise ValueError("soak epoch monitor/risk/observation 必须使用不同公钥")
    external = payload["external_source_key_fingerprints"]
    expected_external_names = {
        "journal_snapshot",
        "external_monitor",
        "alert_receipts",
        "backup_receipts",
    }
    if (
        not isinstance(external, dict)
        or set(external) != expected_external_names
        or any(not _SHA256.fullmatch(str(value)) for value in external.values())
        or len(set(external.values())) != len(expected_external_names)
        or set(external.values()) & set(role_fingerprints)
    ):
        raise ValueError("soak epoch 四类 external source 必须预注册互异独立公钥")
    inventory = validate_canary_source_producer_inventory(
        payload["canary_source_producer_inventory"]
    )
    if (
        deployment["canary_source_producer_inventory_sha256"]
        != canary_source_producer_inventory_sha256(inventory)
    ):
        raise ValueError(
            "soak epoch deployment identity 未绑定完整 Canary producer inventory"
        )
    producer_fingerprints = {item["source_key_fingerprint"] for item in inventory.values()}
    if producer_fingerprints & (set(role_fingerprints) | set(external.values())):
        raise ValueError("Canary producer keys 必须与 epoch control/external keys 隔离")
    registered_fingerprints = (
        set(role_fingerprints) | set(external.values()) | producer_fingerprints
    )
    if not registered_fingerprints.issubset(set(deployment["key_fingerprints"])):
        raise ValueError("soak epoch deployment identity 未包含全部预注册 producer/control keys")
    if (
        not str(payload["operator"]).strip()
        or not str(payload["risk_approver"]).strip()
        or payload["operator"] == payload["risk_approver"]
    ):
        raise ValueError("soak epoch 必须由独立 operator/risk approver 确认")
    return payload


def verify_dual_signed_soak_epoch(
    artifact: object,
    *,
    monitor_public_key: str | Path,
    risk_public_key: str | Path,
) -> dict:
    if not isinstance(artifact, dict) or set(artifact) != {
        "payload",
        "monitor_signature",
        "risk_signature",
    }:
        raise ValueError("soak epoch 双签 envelope 非法")
    payload = validate_soak_epoch(artifact["payload"])
    actual_monitor_fingerprint = ed25519_public_key_fingerprint(monitor_public_key)
    actual_risk_fingerprint = ed25519_public_key_fingerprint(risk_public_key)
    if (
        actual_monitor_fingerprint != payload["monitor_key_fingerprint"]
        or actual_risk_fingerprint != payload["risk_key_fingerprint"]
    ):
        raise ValueError("soak epoch signer 公钥指纹与 payload 不一致")
    if actual_monitor_fingerprint == actual_risk_fingerprint:
        raise ValueError("soak epoch monitor/risk 必须使用不同公钥")
    monitor_claims = verify_ed25519_artifact(
        {
            "payload": payload,
            "signature": artifact["monitor_signature"],
        },
        monitor_public_key,
        label="soak epoch monitor signature",
    )
    risk_claims = verify_ed25519_artifact(
        {
            "payload": payload,
            "signature": artifact["risk_signature"],
        },
        risk_public_key,
        label="soak epoch risk signature",
    )
    if monitor_claims != payload or risk_claims != payload:
        raise ValueError("soak epoch signatures 未绑定同一 payload")
    return payload


def hard_metrics_from_report(report: dict) -> dict:
    return {
        "window": report["window"],
        "websocket": report["websocket"],
        "reconciliation": report["reconciliation"],
        "runtime": report["runtime"],
        "alerts": report["alerts"],
        "backups": report["backups"],
        "resources": report["resources"],
        "clock": report["clock"],
        "probes": report["probes"],
        "protection": report["protection"],
        "execution_slippage": report["execution_slippage"],
        "integrity": report["integrity"],
    }


class DemoObservationAnchorV2Verifier:
    def __init__(self, public_key_path: str | Path):
        self.public_key_path = Path(public_key_path)

    def verify(self, row: dict) -> dict:
        claims = verify_ed25519_artifact(
            row.get("anchor"),
            self.public_key_path,
            label="demo observation v2 anchor",
        )
        if not isinstance(claims, dict) or set(claims) != ANCHOR_V2_KEYS:
            raise ValueError("demo observation v2 anchor schema 非法")
        expected = {
            "day": row["day"],
            "soak_epoch_id": row["soak_epoch_id"],
            "phase": row["phase"],
            "status": row["status"],
            "reason_codes": row["reason_codes"],
            "previous_hash": row["previous_hash"],
            "report_sha256": row["report_sha256"],
            "source_uri": row["source_uri"],
            "source_version_id": row["source_version_id"],
            "source_sha256": row["source_sha256"],
        }
        if claims["version"] != 2 or claims["action"] != "anchor-demo-day-v2":
            raise ValueError("demo observation anchor 版本/action 非法")
        for key, value in expected.items():
            if claims.get(key) != value:
                raise ValueError(f"demo observation anchor 未绑定 {key}")
        if claims["hard_metrics"] != row.get("hard_metrics"):
            raise ValueError("demo observation anchor hard metrics 不匹配")
        if not str(claims["monitor"]).strip() or type(claims["issued_at"]) is not int:
            raise ValueError("demo observation anchor monitor/time 非法")
        return claims


class DemoObservationLedgerV2:
    """严格 v2 ledger；v1、burn-in 混入和坏日删除均不能形成 clean streak。"""

    def __init__(
        self,
        path: str | Path,
        *,
        epoch_payload: dict,
        anchor_public_key: str | Path,
        clock=None,
    ):
        self.path = Path(path)
        self.epoch = validate_soak_epoch(epoch_payload)
        self.anchor_verifier = DemoObservationAnchorV2Verifier(anchor_public_key)
        if (
            ed25519_public_key_fingerprint(anchor_public_key)
            != self.epoch["observation_key_fingerprint"]
        ):
            raise ValueError("demo ledger observation 公钥与 soak epoch 指纹不一致")
        self._clock = clock or (lambda: datetime.now(UTC))

    @staticmethod
    def _entry_hash(row: dict) -> str:
        material = {key: value for key, value in row.items() if key != "entry_hash"}
        return identity_hash(material)

    def _epoch_started_at(self) -> datetime:
        return datetime.fromisoformat(self.epoch["started_at"]).astimezone(UTC)

    def _require_full_day_after_epoch(
        self,
        day_value: date,
        *,
        observed_started_at: object | None = None,
        observed_ended_at: object | None = None,
    ) -> None:
        day_started = datetime.combine(
            day_value,
            datetime.min.time(),
            tzinfo=UTC,
        )
        day_ended = day_started + timedelta(days=1)
        if observed_started_at is not None or observed_ended_at is not None:
            try:
                parsed_start = datetime.fromisoformat(str(observed_started_at))
                parsed_end = datetime.fromisoformat(str(observed_ended_at))
            except (TypeError, ValueError) as exc:
                raise ValueError("demo ledger v2 observation window 非法") from exc
            if (
                parsed_start.tzinfo is None
                or parsed_start.utcoffset() is None
                or parsed_end.tzinfo is None
                or parsed_end.utcoffset() is None
            ):
                raise ValueError("demo ledger v2 observation window 必须带时区")
            observed_start = parsed_start.astimezone(UTC)
            observed_end = parsed_end.astimezone(UTC)
            if observed_start != day_started or observed_end != day_ended:
                raise ValueError("demo ledger v2 observation 必须覆盖完整 UTC day")
        if day_started < self._epoch_started_at():
            raise ValueError("demo ledger v2 只接受 started_at 不早于 epoch 的完整 UTC day")

    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != {"version", "soak_epoch_sha256", "rows"}
            or value["version"] != 2
            or value["soak_epoch_sha256"] != identity_hash(self.epoch)
            or not isinstance(value["rows"], list)
        ):
            raise ValueError("demo ledger v2 root schema/epoch 非法")
        previous = "GENESIS"
        previous_day: date | None = None
        for row in value["rows"]:
            if not isinstance(row, dict) or set(row) != ROW_KEYS:
                raise ValueError("demo ledger v2 row schema 非法")
            current = date.fromisoformat(row["day"])
            self._require_full_day_after_epoch(
                current,
                observed_started_at=row["observation_started_at"],
                observed_ended_at=row["observation_ended_at"],
            )
            if previous_day is not None and current <= previous_day:
                raise ValueError("demo ledger v2 日期必须严格递增")
            if row["previous_hash"] != previous:
                raise ValueError("demo ledger v2 hash chain 断裂")
            if row["entry_hash"] != self._entry_hash(row):
                raise ValueError("demo ledger v2 row hash 非法")
            if row["soak_epoch_id"] != self.epoch["soak_epoch_id"]:
                raise ValueError("demo ledger v2 epoch 串线")
            self.anchor_verifier.verify(row)
            previous = row["entry_hash"]
            previous_day = current
        return value["rows"]

    def append_report(
        self,
        *,
        report: dict,
        report_bytes: bytes,
        source_uri: str,
        source_version_id: str,
        source_sha256: str,
        anchor: dict,
        max_slippage_ratio: float,
    ) -> dict:
        validate_slo_v2_report(report)
        if json.loads(report_bytes) != report:
            raise ValueError("report_bytes 与已验证 SLO report 不一致")
        if report["soak_epoch_id"] != self.epoch["soak_epoch_id"]:
            raise ValueError("SLO report soak_epoch_id 与 ledger 不匹配")
        parsed = urlparse(source_uri)
        if (
            parsed.scheme != "s3"
            or not parsed.netloc
            or not parsed.path.strip("/")
            or not source_version_id.strip()
            or not _SHA256.fullmatch(source_sha256)
        ):
            raise ValueError("ledger source 必须绑定 S3 exact version 和 SHA-256")
        now = self._clock().astimezone(UTC)
        observed_day = date.fromisoformat(report["day"])
        self._require_full_day_after_epoch(
            observed_day,
            observed_started_at=report["window"]["started_at"],
            observed_ended_at=report["window"]["ended_at"],
        )
        observation_ended = datetime.fromisoformat(report["window"]["ended_at"]).astimezone(UTC)
        if observed_day not in {
            now.date(),
            now.date() - timedelta(days=1),
        } or observation_ended > now + timedelta(minutes=5):
            raise ValueError("ledger v2 禁止历史回填")
        rows = self.load()
        if rows and observed_day <= date.fromisoformat(rows[-1]["day"]):
            raise ValueError("ledger v2 禁止覆盖或插入历史日期")
        status, reason_codes = evaluate_slo_v2_day(
            report,
            max_slippage_ratio=max_slippage_ratio,
        )
        previous_hash = rows[-1]["entry_hash"] if rows else "GENESIS"
        hard_metrics = hard_metrics_from_report(report)
        row = {
            "version": 2,
            "day": report["day"],
            "soak_epoch_id": report["soak_epoch_id"],
            "phase": report["phase"],
            "status": status,
            "reason_codes": reason_codes,
            "release_identity_sha256": identity_hash(self.epoch["release_identity"]),
            "deployment_identity_sha256": identity_hash(self.epoch["deployment_identity"]),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "source_uri": source_uri,
            "source_version_id": source_version_id,
            "source_sha256": source_sha256,
            "observation_started_at": report["window"]["started_at"],
            "observation_ended_at": report["window"]["ended_at"],
            "protection_sample_count": report["protection"]["success_count"],
            "protection_p95_seconds": report["protection"]["p95_seconds"],
            "protection_p99_seconds": report["protection"]["p99_seconds"],
            "protection_max_seconds": report["protection"]["max_seconds"],
            "slippage_sample_count": report["execution_slippage"]["sample_count"],
            "slippage_p95_ratio": report["execution_slippage"]["p95_ratio"],
            "slippage_p99_ratio": report["execution_slippage"]["p99_ratio"],
            "slippage_max_ratio": report["execution_slippage"]["max_ratio"],
            "probe_attempt_count": report["probes"]["attempt_count"],
            "probe_done_count": report["probes"]["done_count"],
            "protection_lifecycle_count": report["protection"]["independent_probe_count"],
            "unexplained_mismatches": report["reconciliation"]["unresolved_count"],
            "hard_metrics": hard_metrics,
            "previous_hash": previous_hash,
            "recorded_at": now.isoformat(),
            "anchor": anchor,
            "entry_hash": "",
        }
        claims = self.anchor_verifier.verify(row)
        if claims["hard_metrics"] != hard_metrics:
            raise ValueError("anchor hard metrics 与 report 不一致")
        row["entry_hash"] = self._entry_hash(row)
        rows.append(row)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "version": 2,
                    "soak_epoch_sha256": identity_hash(self.epoch),
                    "rows": rows,
                },
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)
        return row

    def consecutive_clean_days(
        self,
        *,
        max_slippage_ratio: float,
        expected_git_commit: str,
        expected_config_hash: str,
        expected_account_id: str,
        as_of: date | None = None,
        require_trusted_anchor: bool = True,
        **_ignored,
    ) -> int:
        if (
            self.epoch["release_identity"]["git_commit"].lower() != expected_git_commit.lower()
            or self.epoch["deployment_identity"]["config_sha256"].lower()
            != expected_config_hash.lower()
            or self.epoch["deployment_identity"]["account_uid"] != expected_account_id
        ):
            return 0
        rows = self.load()
        if not rows:
            return 0
        as_of = as_of or datetime.now(UTC).date()
        if date.fromisoformat(rows[-1]["day"]) not in {
            as_of,
            as_of - timedelta(days=1),
        }:
            return 0
        count = 0
        expected_day: date | None = None
        for row in reversed(rows):
            current = date.fromisoformat(row["day"])
            day_started = datetime.combine(
                current,
                datetime.min.time(),
                tzinfo=UTC,
            )
            if day_started < self._epoch_started_at():
                break
            if expected_day is not None and current != expected_day:
                break
            if (
                row["phase"] != "soak"
                or row["status"] != "clean"
                or row["reason_codes"]
                or row["slippage_max_ratio"] > max_slippage_ratio
                or row["protection_p95_seconds"] > 3
                or row["protection_max_seconds"] > 10
                or row["probe_done_count"] != 1
                or row["unexplained_mismatches"] != 0
                or len(row["hard_metrics"]["probes"]["formal_probe_ids"]) != 1
                or row["hard_metrics"]["probes"]["formal_probe_ids"]
                != row["hard_metrics"]["probes"]["done_probe_ids"]
                or row["hard_metrics"]["probes"]["done_probe_ids"]
                != row["hard_metrics"]["execution_slippage"]["residual_cluster_ids"]
                or row["hard_metrics"]["probes"]["schedule_sha256"]
                != self.epoch["probe_policy"]["schedule_sha256"]
                or row["hard_metrics"]["execution_slippage"]["model_paired_count"]
                != row["slippage_sample_count"]
                or row["hard_metrics"]["execution_slippage"]["cost_model_hash"]
                != self.epoch["probe_policy"]["cost_model_hash"]
            ):
                break
            # Signature was checked on append; production_gate record also
            # revalidates the immutable report hard metrics.
            if require_trusted_anchor and row["anchor"] is None:
                break
            count += 1
            expected_day = current - timedelta(days=1)
        return count

    def aggregate_clean_samples(self, clean_days: int) -> dict:
        rows = self.load()
        selected = rows[-clean_days:] if clean_days else []
        return {
            "probe_count": sum(row["probe_done_count"] for row in selected),
            "protection_lifecycle_count": sum(
                row["protection_lifecycle_count"] for row in selected
            ),
            "slippage_sample_count": sum(row["slippage_sample_count"] for row in selected),
            "protection_sample_count": sum(row["protection_sample_count"] for row in selected),
            "done_probe_ids": [
                probe_id
                for row in selected
                for probe_id in row["hard_metrics"]["probes"]["done_probe_ids"]
            ],
            "residual_cluster_ids": [
                probe_id
                for row in selected
                for probe_id in row["hard_metrics"]["execution_slippage"]["residual_cluster_ids"]
            ],
        }


def validate_30_day_aggregate(
    ledger: DemoObservationLedgerV2,
    *,
    clean_days: int,
) -> None:
    required_days = int(SLO_V2_POLICY["aggregate_required_clean_days"])
    required_clusters = int(SLO_V2_POLICY["aggregate_required_residual_clusters"])
    if clean_days != required_days:
        raise ValueError(f"30 日 Demo 样本不足: clean_days={clean_days}!={required_days}")
    aggregate = ledger.aggregate_clean_samples(clean_days)
    exact = {
        "probe_count": required_days,
        "protection_lifecycle_count": required_days,
    }
    missing = [
        f"{key}={aggregate[key]}!={expected}"
        for key, expected in exact.items()
        if aggregate[key] != expected
    ]
    if aggregate["slippage_sample_count"] < 60:
        missing.append(f"slippage_sample_count={aggregate['slippage_sample_count']}<60")
    rows = ledger.load()
    selected = rows[-clean_days:] if clean_days else []
    if len(selected) != required_days:
        missing.append(f"clean row count={len(selected)}!={required_days}")
    selected_days = [
        date.fromisoformat(str(row["day"])) for row in selected if isinstance(row.get("day"), str)
    ]
    if len(selected_days) != required_days or any(
        right - left != timedelta(days=1)
        for left, right in zip(
            selected_days,
            selected_days[1:],
            strict=False,
        )
    ):
        missing.append("clean rows 不是精确连续 30 UTC 日")
    slippage = [row["hard_metrics"]["execution_slippage"] for row in selected]
    paired_count = sum(int(item["model_paired_count"]) for item in slippage)
    cluster_count = sum(int(item["residual_cluster_count"]) for item in slippage)
    residual_sum = sum(float(item["cluster_residual_sum_ratio"]) for item in slippage)
    residual_squares = sum(float(item["cluster_residual_sum_squares_ratio"]) for item in slippage)
    if paired_count != aggregate["slippage_sample_count"]:
        missing.append(
            f"realized-model 配对样本不完整: {paired_count}!={aggregate['slippage_sample_count']}"
        )
    daily_lineage_valid = all(
        len(row["hard_metrics"]["probes"]["formal_probe_ids"]) == 1
        and row["hard_metrics"]["probes"]["formal_probe_ids"]
        == row["hard_metrics"]["probes"]["done_probe_ids"]
        == row["hard_metrics"]["execution_slippage"]["residual_cluster_ids"]
        for row in selected
    )
    done_probe_ids = aggregate["done_probe_ids"]
    residual_cluster_ids = aggregate["residual_cluster_ids"]
    if (
        not daily_lineage_valid
        or len(done_probe_ids) != required_days
        or len(set(done_probe_ids)) != required_days
        or residual_cluster_ids != done_probe_ids
    ):
        missing.append(
            "formal DONE probe 与 residual cluster lineage 必须每日一一对应且 30 日全局唯一"
        )
    if cluster_count != required_clusters:
        missing.append(
            "realized-model 独立 probe cluster 必须精确为 "
            f"{required_clusters}: {cluster_count}!={required_clusters}"
        )
    elif daily_lineage_valid and len(set(done_probe_ids)) == required_days:
        mean = residual_sum / cluster_count
        variance = max(
            (residual_squares - residual_sum * residual_sum / cluster_count) / (cluster_count - 1),
            0,
        )
        # Conservative pre-registered one-sided Student-t critical value
        # for df=29 (the minimum accepted 30 independent probe clusters).
        upper_95 = mean + 1.6991270265334972 * (variance / cluster_count) ** 0.5
        if not math.isfinite(upper_95) or upper_95 > 0:
            missing.append(f"realized-model slippage 单侧 95% 上界未通过: {upper_95}")
    if missing:
        raise ValueError("30 日 Demo 样本不足: " + ", ".join(missing))
