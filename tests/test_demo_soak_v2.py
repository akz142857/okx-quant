"""SLO v2 epoch/ledger 的身份、阶段和哈希链测试。"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest

from okx_quant.application.demo_probe import formal_probe_schedule_sha256
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.ops.slo import (
    SLO_V2_POLICY_HASH,
    SLO_V2_SCHEMA,
    evaluate_slo_v2_day,
)
from okx_quant.research.demo_soak import (
    ROW_KEYS,
    DemoObservationLedgerV2,
    canary_source_producer_inventory_sha256,
    hard_metrics_from_report,
    identity_hash,
    validate_30_day_aggregate,
    validate_soak_epoch,
    verify_dual_signed_soak_epoch,
)
from scripts import sign_soak_epoch
from scripts.slo_report import build_report

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


def _canary_inventory() -> dict:
    return {
        name: {
            "source_key_fingerprint": hashlib.sha256(f"canary-source-{name}".encode()).hexdigest(),
            "collector_unix_user": f"canaryc{index:02d}",
            "signer_unix_user": f"canarys{index:02d}",
            "collector_systemd_unit": (f"okx-quant-canary-c{index:02d}.service"),
            "signer_systemd_unit": (f"okx-quant-canary-s{index:02d}.service"),
            "iam_principal": f"canary-source-{index:02d}",
            "source_authority": _CANARY_AUTHORITIES[name],
            "source_request_sha256": hashlib.sha256(
                f"collector-request:{name}".encode()
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
            "raw_source_path": (f"/var/lib/okx-quant-canary-sources/raw/{index:02d}.evidence"),
            "artifact_output_path": (f"/var/lib/okx-quant-canary-sources/signed/{index:02d}.json"),
        }
        for index, name in enumerate(sorted(_CANARY_AUTHORITIES))
    }


def _keypair(tmp_path, name: str):
    private = tmp_path / f"{name}-private.pem"
    public = tmp_path / f"{name}-public.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(private),
        ],
        check=True,
        capture_output=True,
    )
    private.chmod(0o600)
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private),
            "-pubout",
            "-out",
            str(public),
        ],
        check=True,
        capture_output=True,
    )
    return private, public


def _formal_schedule(started_at: str) -> dict:
    first_day = datetime.fromisoformat(started_at).astimezone(UTC).date()
    cells = [
        (time_bin, spread, volatility)
        for _cycle in range(2)
        for time_bin in range(4)
        for spread in ((0.0, 3.0), (3.0, 10.0))
        for volatility in ((0.0, 15.0), (15.0, 80.0))
    ]
    cells.remove((0, (0.0, 3.0), (0.0, 15.0)))
    cells.remove((1, (3.0, 10.0), (15.0, 80.0)))
    slots = []
    for index in range(30):
        day = first_day + timedelta(days=index)
        time_bin, spread, volatility = cells[index]
        started = datetime.combine(
            day,
            datetime.min.time(),
            tzinfo=UTC,
        ) + timedelta(hours=time_bin * 6)
        slots.append(
            {
                "day": day.isoformat(),
                "slot": 1,
                "inst_id": "BTC-USDT",
                "direction": "buy_then_exit",
                "window_start": started.isoformat(),
                "window_end": (started + timedelta(hours=4)).isoformat(),
                "spread_min_bps": spread[0],
                "spread_max_bps": spread[1],
                "volatility_min_bps": volatility[0],
                "volatility_max_bps": volatility[1],
            }
        )
    return {
        "version": 2,
        "action": "precommit-demo-probe-schedule",
        "schedule_id": "formal-test-schedule",
        "created_at": (
            datetime.combine(
                first_day,
                datetime.min.time(),
                tzinfo=UTC,
            )
            - timedelta(days=1)
        ).isoformat(),
        "slots": slots,
    }


def _epoch(
    *,
    started_at: str = "2020-01-01T00:00:00+00:00",
) -> dict:
    release = {
        "git_commit": "1" * 40,
        "git_tree_hash": "2" * 40,
        "source_manifest_sha256": "3" * 64,
        "dependency_lock_sha256": "4" * 64,
        "interpreter_sha256": "5" * 64,
    }
    schedule = _formal_schedule(started_at)
    inventory = _canary_inventory()
    registered_keys = {
        "c" * 64,
        "e" * 64,
        "d" * 64,
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "4" * 64,
        *{item["source_key_fingerprint"] for item in inventory.values()},
    }

    return {
        "version": 1,
        "action": "start-demo-soak-epoch",
        "soak_epoch_id": "epoch-2026-07-28",
        "issued_at": int(datetime.fromisoformat(started_at).timestamp()) - 3600,
        "started_at": started_at,
        "release_identity": release,
        "deployment_identity": {
            "release_identity_sha256": identity_hash(release),
            "config_sha256": "6" * 64,
            "launch_sha256": "7" * 64,
            "account_uid": "demo-account",
            "environment": "demo",
            "unit": "okx-quant-demo-active.service",
            "host_image_sha256": "8" * 64,
            "key_fingerprints": sorted(
                {
                    "9" * 64,
                    *registered_keys,
                }
            ),
            "canary_source_producer_inventory_sha256": (
                canary_source_producer_inventory_sha256(inventory)
            ),
        },
        "stage_c_chaos_deployment_identity": {
            "version": 1,
            "exact_release": {
                "account_uid": "demo-account",
                "config_sha256": "6" * 64,
                "unit": "okx-quant-demo-active.service",
                "artifact_sha256": "a" * 64,
            },
            "instrumented": {
                "account_uid": "demo-chaos-instrumented",
                "config_sha256": "b" * 64,
                "unit": "okx-quant-demo-chaos-instrumented.service",
                "artifact_sha256": "c" * 64,
            },
            "host_image_sha256": "8" * 64,
            "network_namespace_sha256": "d" * 64,
            "cgroup_policy_sha256": "e" * 64,
            "observer_api_key_fingerprint": "9" * 64,
            "source_key_fingerprints": ["1" * 64, "2" * 64, "3" * 64],
            "safety_behavior_sha256": "4" * 64,
            "build_provenance_sha256": "5" * 64,
        },
        "strategy_identity": {
            "strategy": "validation_probe",
            "bar": "1m",
            "instruments": ["BTC-USDT"],
            "interval_seconds": 60,
            "risk_parameters_sha256": "a" * 64,
        },
        "probe_policy": {
            "minimum_notional_usdt": 5,
            "maximum_notional_usdt": 10,
            "minimum_daily_probes": 1,
            "maximum_daily_probes": 1,
            "schedule": schedule,
            "schedule_sha256": formal_probe_schedule_sha256(schedule),
            "cost_model_hash": "f" * 64,
        },
        "slo_schema": SLO_V2_SCHEMA,
        "slo_policy_hash": SLO_V2_POLICY_HASH,
        "monitor_key_fingerprint": "c" * 64,
        "risk_key_fingerprint": "e" * 64,
        "observation_key_fingerprint": "d" * 64,
        "external_source_key_fingerprints": {
            "journal_snapshot": "1" * 64,
            "external_monitor": "2" * 64,
            "alert_receipts": "3" * 64,
            "backup_receipts": "4" * 64,
        },
        "canary_source_producer_inventory": inventory,
        "operator": "operator-a",
        "risk_approver": "risk-b",
    }


def _sync_epoch_registered_keys(epoch: dict) -> dict:
    registered = {
        epoch["monitor_key_fingerprint"],
        epoch["risk_key_fingerprint"],
        epoch["observation_key_fingerprint"],
        *epoch["external_source_key_fingerprints"].values(),
        *{
            item["source_key_fingerprint"]
            for item in epoch["canary_source_producer_inventory"].values()
        },
    }
    return {
        **epoch,
        "deployment_identity": {
            **epoch["deployment_identity"],
            "key_fingerprints": sorted(
                {
                    *epoch["deployment_identity"]["key_fingerprints"],
                    *registered,
                }
            ),
            "canary_source_producer_inventory_sha256": (
                canary_source_producer_inventory_sha256(
                    epoch["canary_source_producer_inventory"]
                )
            ),
        },
    }


def _clean_report(tmp_path, day):
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.close()
    report = build_report(
        tmp_path / "trading.db",
        day,
        soak_epoch_id=_epoch()["soak_epoch_id"],
        phase="soak",
    )
    report["window"].update(
        {
            "sample_count": 288,
            "actual_observable_seconds": 86400,
            "unobservable_seconds": 0,
            "max_evidence_gap_seconds": 300,
        }
    )
    resource_values = {
        "rss_bytes": 100_000_000,
        "fd_count": 100,
        "threads": 10,
        "pids_current": 10,
        "db_bytes": 10_000_000,
        "wal_bytes": 1_000_000,
        "disk_free_bytes": 10_000_000_000,
        "disk_free_inodes": 100_000,
        "memory_high_bytes": 524_288_000,
        "memory_max_bytes": 629_145_600,
        "limit_nofile": 4096,
        "tasks_max": 128,
        "max_database_bytes": 2_147_483_648,
        "max_wal_bytes": 268_435_456,
        "wal_checkpoint_age_seconds": 30,
        "max_wal_checkpoint_age_seconds": 300,
        "wal_checkpoint_busy": 0,
        "wal_checkpoint_log_frames": 0,
        "wal_checkpointed_frames": 0,
        "wal_checkpoint_backlog_frames": 0,
        "wal_checkpoint_page_size_bytes": 4096,
        "wal_checkpoint_backlog_bytes": 0,
        "max_database_growth_bytes_per_day": 268_435_456,
        "min_free_bytes": 5_368_709_120,
        "min_free_inodes": 10_000,
        "oom_kill_count": 0,
        "cpu_nr_throttled": 0,
        "cpu_throttled_usec": 0,
    }
    report["resources"].update(
        {
            "sample_count": 288,
            "identity_mismatch_count": 0,
            "warning_sample_count": 0,
            "breach_sample_count": 0,
        }
    )
    for field, value in resource_values.items():
        report["resources"][field] = {
            "first": value,
            "last": value,
            "min": value,
            "max": value,
            "growth": 0,
        }
    for metrics in report["websocket"]["channels"].values():
        metrics.update(
            {
                "transition_count": 2,
                "state_sample_count": 1440,
                "max_state_sample_gap_seconds": 60,
                "generation_count": 1,
                "ready_seconds": 86400,
                "unavailable_seconds": 0,
                "availability_ratio": 1,
                "disconnect_count": 0,
                "max_disconnect_seconds": 0,
            }
        )
    report["reconciliation"].update(
        {
            "expected_count": 2880,
            "attempt_count": 2880,
            "success_count": 2880,
            "failure_count": 0,
            "success_ratio": 1,
            "maximum_completion_gap_seconds": 30,
            "auto_repaired_count": 0,
            "unresolved_count": 0,
        }
    )
    report["runtime"].update(
        {
            "startup_count": 1,
            "startup_max_seconds": 30,
            "readiness_transition_count": 1,
            "ready_transition_count": 1,
            "hard_transition_count": 0,
            "max_previous_mode_duration_seconds": 30,
            "readiness_ready_seconds": 86400,
            "readiness_nonready_seconds": 0,
            "readiness_ratio": 1,
            "readiness_max_nonready_seconds": 0,
            "heartbeat_sample_count": 1440,
            "heartbeat_max_gap_seconds": 60,
            "unhealthy_heartbeat_count": 0,
            "shadow_intent_count": 0,
            "shadow_write_audit_sample_count": 0,
            "shadow_write_attempt_event_count": 0,
            "shadow_write_attempt_count": 0,
            "shadow_write_counter_mismatch_count": 0,
        }
    )
    report["backups"].update(
        {
            "sample_count": 720,
            "failure_count": 0,
            "local_max_recovery_point_age_seconds": 120,
            "offsite_max_recovery_point_age_seconds": 240,
            "component_restore_sample_count": 720,
            "component_restore_max_seconds": 30,
        }
    )
    report["clock"].update(
        {
            "sample_count": 1440,
            "max_absolute_offset_seconds": 0.1,
        }
    )
    report["alerts"].update(
        {
            "sample_count": 1,
            "incident_count": 0,
            "synthetic_challenge_count": 1,
            "synthetic_provider_received_count": 1,
            "attempt_count": 1,
            "ingestion_accepted_count": 1,
            "p0_provider_received_max_seconds": 0,
            "p1_provider_received_max_seconds": 5,
            "provider_failure_count": 0,
            "dlq_count": 0,
            "human_ack_count": 0,
            "escalation_count": 0,
            "unacknowledged_p0_count": 0,
        }
    )
    report["probes"].update(
        {
            "attempt_count": 1,
            "done_count": 1,
            "failed_count": 0,
            "unknown_count": 0,
            "manual_review_count": 0,
            "duplicate_buy_count": 0,
            "fully_correlated_count": 1,
            "schedule_sample_count": 1,
            "schedule_compliant_count": 1,
            "schedule_violation_count": 0,
            "schedule_sha256": _epoch()["probe_policy"]["schedule_sha256"],
            "formal_probe_ids": ["a" * 32],
            "done_probe_ids": ["a" * 32],
        }
    )
    report["protection"].update(
        {
            "attempt_count": 1,
            "success_count": 1,
            "failure_count": 0,
            "independent_probe_count": 1,
            "p50_seconds": 1,
            "p95_seconds": 1,
            "p99_seconds": 1,
            "max_seconds": 1,
            "p99_is_gate": False,
        }
    )
    report["execution_slippage"].update(
        {
            "attempt_count": 2,
            "sample_count": 2,
            "independent_probe_count": 1,
            "p95_ratio": 0.001,
            "p99_ratio": 0.001,
            "max_ratio": 0.001,
            "model_paired_count": 2,
            "expected_model_ratio": 0.001,
            "cost_model_hash": "f" * 64,
            "residual_sum_ratio": 0,
            "residual_sum_squares_ratio": 0,
            "residual_upper_95_ratio": 0,
            "residual_cluster_count": 1,
            "residual_cluster_ids": ["a" * 32],
            "cluster_residual_sum_ratio": 0,
            "cluster_residual_sum_squares_ratio": 0,
            "cluster_residual_upper_95_ratio": 0,
        }
    )
    report["integrity"] = {
        "valid": True,
        "invalid_event_count": 0,
        "reason_codes": [],
    }
    return report


def test_30_day_gate_uses_paired_slippage_one_sided_upper_bound():
    class Ledger:
        @staticmethod
        def aggregate_clean_samples(_clean_days):
            return {
                "probe_count": 30,
                "protection_lifecycle_count": 30,
                "slippage_sample_count": 60,
                "protection_sample_count": 30,
                "done_probe_ids": [f"{index:032x}" for index in range(30)],
                "residual_cluster_ids": [f"{index:032x}" for index in range(30)],
            }

        @staticmethod
        def load():
            return [
                {
                    "day": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=index))
                    .date()
                    .isoformat(),
                    "hard_metrics": {
                        "probes": {
                            "formal_probe_ids": [f"{index:032x}"],
                            "done_probe_ids": [f"{index:032x}"],
                        },
                        "execution_slippage": {
                            "model_paired_count": 2,
                            "residual_cluster_count": 1,
                            "residual_cluster_ids": [f"{index:032x}"],
                            "cluster_residual_sum_ratio": -0.001,
                            "cluster_residual_sum_squares_ratio": 0.000001,
                        },
                    },
                }
                for index in range(30)
            ]

    validate_30_day_aggregate(Ledger(), clean_days=30)
    rows = Ledger.load()
    for row in rows:
        row["hard_metrics"]["execution_slippage"]["cluster_residual_sum_ratio"] = 0.001

    class BiasedLedger(Ledger):
        @staticmethod
        def load():
            return rows

    with pytest.raises(ValueError, match="单侧 95% 上界"):
        validate_30_day_aggregate(BiasedLedger(), clean_days=30)


def test_30_day_gate_rejects_extra_or_cross_day_duplicate_clusters():
    def rows():
        return [
            {
                "day": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=index))
                .date()
                .isoformat(),
                "probe_done_count": 1,
                "protection_lifecycle_count": 1,
                "slippage_sample_count": 2,
                "protection_sample_count": 1,
                "hard_metrics": {
                    "probes": {
                        "formal_probe_ids": [f"{index:032x}"],
                        "done_probe_ids": [f"{index:032x}"],
                    },
                    "execution_slippage": {
                        "model_paired_count": 2,
                        "residual_cluster_count": 1,
                        "residual_cluster_ids": [f"{index:032x}"],
                        "cluster_residual_sum_ratio": -0.001,
                        "cluster_residual_sum_squares_ratio": 0.000001,
                    },
                },
            }
            for index in range(30)
        ]

    class Ledger:
        def __init__(self, values):
            self.values = values

        def load(self):
            return self.values

        def aggregate_clean_samples(self, _clean_days):
            return {
                "probe_count": sum(row["probe_done_count"] for row in self.values),
                "protection_lifecycle_count": sum(
                    row["protection_lifecycle_count"] for row in self.values
                ),
                "slippage_sample_count": sum(row["slippage_sample_count"] for row in self.values),
                "protection_sample_count": sum(
                    row["protection_sample_count"] for row in self.values
                ),
                "done_probe_ids": [
                    probe_id
                    for row in self.values
                    for probe_id in row["hard_metrics"]["probes"]["done_probe_ids"]
                ],
                "residual_cluster_ids": [
                    probe_id
                    for row in self.values
                    for probe_id in row["hard_metrics"]["execution_slippage"][
                        "residual_cluster_ids"
                    ]
                ],
            }

    extra = rows()
    extra_id = "f" * 32
    extra[0]["hard_metrics"]["execution_slippage"].update(
        {
            "residual_cluster_count": 2,
            "residual_cluster_ids": ["0" * 32, extra_id],
        }
    )
    with pytest.raises(ValueError, match="精确为 30"):
        validate_30_day_aggregate(Ledger(extra), clean_days=30)

    duplicated = rows()
    duplicated[-1]["hard_metrics"]["probes"].update(
        {
            "formal_probe_ids": ["0" * 32],
            "done_probe_ids": ["0" * 32],
        }
    )
    duplicated[-1]["hard_metrics"]["execution_slippage"]["residual_cluster_ids"] = ["0" * 32]
    with pytest.raises(ValueError, match="全局唯一"):
        validate_30_day_aggregate(Ledger(duplicated), clean_days=30)


def test_soak_epoch_requires_two_valid_signatures(tmp_path):
    monitor_private, monitor_public = _keypair(tmp_path, "monitor")
    risk_private, risk_public = _keypair(tmp_path, "risk")
    payload = _sync_epoch_registered_keys(
        {
            **_epoch(),
            "monitor_key_fingerprint": ed25519_public_key_fingerprint(monitor_public),
            "risk_key_fingerprint": ed25519_public_key_fingerprint(risk_public),
        }
    )
    artifact = {
        "payload": payload,
        "monitor_signature": sign_ed25519_payload(
            payload,
            monitor_private,
        )["signature"],
        "risk_signature": sign_ed25519_payload(
            payload,
            risk_private,
        )["signature"],
    }
    assert (
        verify_dual_signed_soak_epoch(
            artifact,
            monitor_public_key=monitor_public,
            risk_public_key=risk_public,
        )
        == payload
    )
    artifact["risk_signature"] = artifact["monitor_signature"]
    with pytest.raises(ValueError, match="签名"):
        verify_dual_signed_soak_epoch(
            artifact,
            monitor_public_key=monitor_public,
            risk_public_key=risk_public,
        )


def test_soak_epoch_freezes_one_probe_per_day_and_external_keys():
    duplicate_external = _epoch()
    duplicate_external["external_source_key_fingerprints"] = {
        **duplicate_external["external_source_key_fingerprints"],
        "journal_snapshot": duplicate_external["monitor_key_fingerprint"],
    }
    with pytest.raises(ValueError, match="external source"):
        validate_soak_epoch(duplicate_external)

    changed_inventory = _epoch()
    changed_inventory["canary_source_producer_inventory"][
        "account_uid_verified"
    ]["iam_principal"] = "changed-independent-principal"
    with pytest.raises(ValueError, match="deployment identity"):
        validate_soak_epoch(changed_inventory)

    two_slots = _epoch()
    two_slots["probe_policy"] = {
        **two_slots["probe_policy"],
        "maximum_daily_probes": 2,
    }
    with pytest.raises(ValueError, match="probe_policy"):
        validate_soak_epoch(two_slots)

    late_schedule = _epoch()
    issued_at = datetime.fromtimestamp(
        late_schedule["issued_at"],
        UTC,
    )
    late_schedule["probe_policy"]["schedule"]["created_at"] = (
        issued_at + timedelta(minutes=30)
    ).isoformat()
    late_schedule["probe_policy"]["schedule_sha256"] = formal_probe_schedule_sha256(
        late_schedule["probe_policy"]["schedule"]
    )
    with pytest.raises(ValueError, match="pre-registration"):
        validate_soak_epoch(late_schedule)


def test_soak_epoch_sign_rejects_copied_monitor_risk_key(
    tmp_path,
    monkeypatch,
):
    monitor_private, monitor_public = _keypair(tmp_path, "monitor")
    _risk_private, risk_public = _keypair(tmp_path, "risk")
    copied = tmp_path / "copied-monitor-private.pem"
    copied.write_bytes(monitor_private.read_bytes())
    copied.chmod(0o600)
    now = datetime.now(UTC)
    started_at = datetime.combine(
        (now + timedelta(days=1)).date(),
        datetime.min.time(),
        tzinfo=UTC,
    )
    payload = _sync_epoch_registered_keys(
        {
            **_epoch(started_at=started_at.isoformat()),
            "issued_at": int(now.timestamp()),
            "monitor_key_fingerprint": ed25519_public_key_fingerprint(monitor_public),
            "risk_key_fingerprint": ed25519_public_key_fingerprint(risk_public),
        }
    )
    request = tmp_path / "request.json"
    request.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sign_soak_epoch.py",
            "--request",
            str(request),
            "--monitor-private-key",
            str(monitor_private),
            "--risk-private-key",
            str(copied),
            "--output",
            str(tmp_path / "signed.json"),
        ],
    )
    with pytest.raises(SystemExit, match="同一公钥"):
        sign_soak_epoch.main()


def test_v2_ledger_keeps_invalid_day_and_rejects_tampered_anchor(tmp_path):
    observation_private, observation_public = _keypair(
        tmp_path,
        "observation",
    )
    now = datetime.now(UTC)
    day = (now - timedelta(days=1)).date()
    report = _clean_report(tmp_path, day)
    assert {
        "runtime",
        "resources",
        "clock",
    } <= hard_metrics_from_report(report).keys()
    status, reasons = evaluate_slo_v2_day(
        report,
        max_slippage_ratio=0.01,
    )
    assert (status, reasons) == ("clean", [])
    report_bytes = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
    claims = {
        "version": 2,
        "action": "anchor-demo-day-v2",
        "day": report["day"],
        "soak_epoch_id": report["soak_epoch_id"],
        "phase": "soak",
        "status": "clean",
        "reason_codes": [],
        "previous_hash": "GENESIS",
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "source_uri": "s3://audit/day.bundle",
        "source_version_id": "exact-version",
        "source_sha256": "e" * 64,
        "hard_metrics": hard_metrics_from_report(report),
        "monitor": "independent-monitor",
        "issued_at": int(now.timestamp()),
    }
    anchor = sign_ed25519_payload(claims, observation_private)
    epoch = _sync_epoch_registered_keys(
        {
            **_epoch(),
            "observation_key_fingerprint": ed25519_public_key_fingerprint(observation_public),
        }
    )
    ledger = DemoObservationLedgerV2(
        tmp_path / "ledger.json",
        epoch_payload=epoch,
        anchor_public_key=observation_public,
        clock=lambda: now,
    )
    row = ledger.append_report(
        report=report,
        report_bytes=report_bytes,
        source_uri=claims["source_uri"],
        source_version_id=claims["source_version_id"],
        source_sha256=claims["source_sha256"],
        anchor=anchor,
        max_slippage_ratio=0.01,
    )
    assert row["status"] == "clean"
    assert (
        ledger.consecutive_clean_days(
            max_slippage_ratio=0.01,
            expected_git_commit="1" * 40,
            expected_config_hash="6" * 64,
            expected_account_id="demo-account",
            as_of=now.date(),
        )
        == 1
    )

    root = json.loads(ledger.path.read_text())
    root["rows"][0]["status"] = "invalid"
    root["rows"][0]["entry_hash"] = ledger._entry_hash(root["rows"][0])
    ledger.path.write_text(json.dumps(root))
    with pytest.raises(ValueError, match="anchor"):
        ledger.load()


def test_burn_in_report_never_counts_as_clean(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    report = _clean_report(tmp_path, day)
    report["phase"] = "burn-in"
    assert (
        evaluate_slo_v2_day(
            report,
            max_slippage_ratio=0.01,
        )[0]
        == "burn-in"
    )


def test_formal_soak_rejects_hard_or_long_nonready_runtime(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    report = _clean_report(tmp_path, day)
    report["runtime"].update(
        {
            "hard_transition_count": 1,
            "readiness_ready_seconds": 100,
            "readiness_nonready_seconds": 86300,
            "readiness_ratio": 100 / 86400,
            "readiness_max_nonready_seconds": 86300,
        }
    )

    status, reasons = evaluate_slo_v2_day(
        report,
        max_slippage_ratio=0.01,
    )

    assert status == "invalid"
    assert {
        "RUNTIME_HARD_TRANSITION",
        "RUNTIME_READINESS_AVAILABILITY",
        "RUNTIME_READINESS_MAX_NONREADY",
    } <= set(reasons)


def test_formal_soak_rejects_more_than_one_completed_probe(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    report = _clean_report(tmp_path, day)
    report["probes"].update(
        {
            "attempt_count": 2,
            "done_count": 2,
            "fully_correlated_count": 2,
            "schedule_sample_count": 2,
            "schedule_compliant_count": 2,
            "formal_probe_ids": ["a" * 32, "b" * 32],
            "done_probe_ids": ["a" * 32, "b" * 32],
        }
    )
    report["execution_slippage"].update(
        {
            "independent_probe_count": 2,
            "residual_cluster_count": 2,
            "residual_cluster_ids": ["a" * 32, "b" * 32],
        }
    )

    status, reasons = evaluate_slo_v2_day(
        report,
        max_slippage_ratio=0.01,
    )

    assert status == "invalid"
    assert "PROBE_DAILY_COUNT" in reasons


def test_ledger_requires_full_utc_day_started_after_epoch(
    tmp_path,
    monkeypatch,
):
    _observation_private, observation_public = _keypair(
        tmp_path,
        "observation",
    )
    with pytest.raises(ValueError, match="start day"):
        validate_soak_epoch(_epoch(started_at="2026-07-28T12:00:00+00:00"))

    epoch = _sync_epoch_registered_keys(
        {
            **_epoch(started_at="2026-07-29T00:00:00+00:00"),
            "observation_key_fingerprint": ed25519_public_key_fingerprint(observation_public),
        }
    )
    ledger = DemoObservationLedgerV2(
        tmp_path / "ledger.json",
        epoch_payload=epoch,
        anchor_public_key=observation_public,
        clock=lambda: datetime(2026, 7, 29, 0, 10, tzinfo=UTC),
    )
    report = _clean_report(tmp_path, datetime(2026, 7, 28).date())
    report_bytes = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
    with pytest.raises(ValueError, match="完整 UTC day"):
        ledger.append_report(
            report=report,
            report_bytes=report_bytes,
            source_uri="s3://audit/day.bundle",
            source_version_id="exact-version",
            source_sha256="f" * 64,
            anchor={},
            max_slippage_ratio=0.01,
        )

    invalid_row = {key: None for key in ROW_KEYS}
    invalid_row["day"] = "2026-07-28"
    ledger.path.write_text(
        json.dumps(
            {
                "version": 2,
                "soak_epoch_sha256": identity_hash(epoch),
                "rows": [invalid_row],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="完整 UTC day"):
        ledger.load()

    monkeypatch.setattr(
        ledger,
        "load",
        lambda: [{"day": "2026-07-28"}],
    )
    assert (
        ledger.consecutive_clean_days(
            max_slippage_ratio=0.01,
            expected_git_commit="1" * 40,
            expected_config_hash="6" * 64,
            expected_account_id="demo-account",
            as_of=datetime(2026, 7, 29).date(),
        )
        == 0
    )
