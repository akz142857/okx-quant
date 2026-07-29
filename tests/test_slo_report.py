"""Durable 运行 SLO 报告测试。"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pandas as pd
import pytest

from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.ops.slo import evaluate_slo_v2_day, validate_slo_v2_report
from okx_quant.ops.slo_facts import (
    export_slo_v2_facts,
    report_from_slo_v2_facts,
)
from okx_quant.research.costs import DynamicCostModel
from scripts.slo_report import build_report


@pytest.mark.unit
def test_slo_report_computes_quantiles_from_durable_events(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    for latency in (0.5, 1.0, 2.0, 9.0):
        journal.record_event(
            "protection_activation_slo_sample",
            payload={"latency_seconds": latency},
        )
    journal.record_event(
        "startup_reconciliation_slo_sample",
        payload={"duration_seconds": 12.0},
    )
    journal.record_event(
        "websocket_subscription_ready",
        payload={
            "channel": "public",
            "generation": 1,
            "connect_subscribe_latency_seconds": 0.25,
        },
    )
    journal.record_event(
        "runtime_readiness_transition",
        payload={
            "old_mode": "starting",
            "new_mode": "ready",
            "reason": "startup_complete",
            "previous_mode_duration_seconds": 12.0,
        },
    )
    journal.record_event(
        "runtime_heartbeat_sample",
        payload={
            "healthy": True,
            "mode": "ready",
            "pid": 123,
            "boot_id": "boot-1",
            "runtime_instance_id": "runtime-1",
            "account_uid": "test-account",
            "deployment_unit": "test.service",
            "soak_epoch_id": "burn-in-unassigned",
            "shadow_mode": False,
            "shadow_write_attempt_count": 0,
        },
    )
    journal.record_event(
        "shadow_order_intent",
        payload={
            "inst_id": "BTC-USDT",
            "side": "buy",
            "requested_base_qty": "0.001",
            "source": "strategy",
            "probe_id": "",
        },
    )
    journal.record_event(
        "execution_slippage_sample",
        payload={"adverse_slippage_ratio": 0.001},
    )
    journal.close()

    report = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
    )
    protection = report["protection"]
    assert protection["attempt_count"] == 4
    assert protection["p95_seconds"] == 9.0
    assert protection["p99_seconds"] == 9.0
    assert protection["max_seconds"] == 9.0
    assert report["runtime"]["startup_max_seconds"] == 12.0
    assert report["runtime"]["readiness_transition_count"] == 1
    assert report["runtime"]["ready_transition_count"] == 1
    assert report["runtime"]["heartbeat_sample_count"] == 1
    assert report["runtime"]["shadow_intent_count"] == 1
    assert report["runtime"]["shadow_write_audit_sample_count"] == 0
    assert report["runtime"]["shadow_write_attempt_event_count"] == 0
    assert report["runtime"]["shadow_write_attempt_count"] == 0
    assert report["runtime"]["shadow_write_counter_mismatch_count"] == 0
    assert report["websocket"]["subscription_ready_by_channel"]["public"][
        "max_seconds"
    ] == 0.25
    assert report["execution_slippage"]["p99_ratio"] == 0.001
    assert report["reconciliation"]["unresolved_count"] == 0
    assert report["version"] == 2


@pytest.mark.unit
def test_slo_report_marks_low_activity_day_without_fabricating_samples(
    tmp_path,
):
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.close()
    report = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
    )
    assert report["protection"]["attempt_count"] == 0
    assert report["execution_slippage"]["sample_count"] == 0
    assert report["integrity"]["valid"] is False
    assert "NO_RESOURCE_OBSERVABILITY_SAMPLES" in report["integrity"][
        "reason_codes"
    ]


@pytest.mark.unit
def test_shadow_slo_requires_zero_durable_transport_write_attempts(
    tmp_path,
):
    journal = SQLiteJournal(tmp_path / "shadow.db")
    journal.record_event(
        "runtime_heartbeat_sample",
        payload={
            "healthy": True,
            "mode": "halted",
            "pid": 123,
            "boot_id": "boot-shadow",
            "runtime_instance_id": "runtime-shadow",
            "account_uid": "shadow-account",
            "deployment_unit": "okx-quant-demo-shadow.service",
            "soak_epoch_id": "shadow-epoch",
            "shadow_mode": True,
            "shadow_write_attempt_count": 1,
        },
    )
    journal.record_event(
        "shadow_write_endpoint_attempt",
        severity="critical",
        payload={
            "method": "POST",
            "endpoint": "/api/v5/trade/order",
            "attempt_count": 1,
            "account_uid": "shadow-account",
            "deployment_unit": "okx-quant-demo-shadow.service",
            "soak_epoch_id": "shadow-epoch",
            "runtime_instance_id": "runtime-shadow",
            "boot_id": "boot-shadow",
        },
    )
    journal.close()
    report = build_report(
        tmp_path / "shadow.db",
        datetime.now(UTC).date(),
        soak_epoch_id="shadow-epoch",
        phase="shadow",
    )
    assert report["runtime"]["shadow_write_audit_sample_count"] == 1
    assert report["runtime"]["shadow_write_attempt_event_count"] == 1
    assert report["runtime"]["shadow_write_attempt_count"] == 1
    assert report["runtime"]["shadow_write_counter_mismatch_count"] == 0
    _status, reasons = evaluate_slo_v2_day(
        report,
        max_slippage_ratio=0.01,
    )
    assert "SHADOW_WRITE_ENDPOINT_ATTEMPT" in reasons


@pytest.mark.unit
def test_ws_ready_generation_requires_exact_subscription_fact(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    journal = SQLiteJournal(tmp_path / "ws-subscription.db")
    with journal.transaction() as connection:
        states = (
            ("disconnected", "connecting", 1, started + 10),
            ("connecting", "subscribing", 1, started + 11),
            ("subscribing", "ready", 1, started + 12),
        )
        for old_state, new_state, generation, observed_at in states:
            connection.execute(
                """
                INSERT INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?, 'websocket_state_transition', 'info', 'public', ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    json.dumps({
                        "channel": "public",
                        "old_state": old_state,
                        "new_state": new_state,
                        "generation": generation,
                    }),
                    observed_at,
                ),
            )
    journal.close()

    report = build_report(tmp_path / "ws-subscription.db", day)

    assert "WS_SUBSCRIPTION_ASSOCIATION:public" in report[
        "integrity"
    ]["reason_codes"]


@pytest.mark.unit
def test_ws_generation_cannot_jump_without_prior_epoch(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    journal = SQLiteJournal(tmp_path / "ws-generation.db")
    with journal.transaction() as connection:
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'websocket_state_transition', 'info', 'public', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "channel": "public",
                    "old_state": "disconnected",
                    "new_state": "connecting",
                    "generation": 2,
                }),
                started + 10,
            ),
        )
    journal.close()

    report = build_report(tmp_path / "ws-generation.db", day)

    assert any(
        reason.startswith("INVALID_WS_EVENT:public:")
        for reason in report["integrity"]["reason_codes"]
    )


@pytest.mark.unit
def test_ws_liveness_cannot_claim_a_future_generation(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    journal = SQLiteJournal(tmp_path / "ws-liveness-generation.db")
    with journal.transaction() as connection:
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'websocket_state_transition', 'info', 'public', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "channel": "public",
                    "old_state": "subscribing",
                    "new_state": "ready",
                    "generation": 1,
                }),
                started - 1,
            ),
        )
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'websocket_liveness_sample', 'info', '', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "states": {
                        "public": "ready",
                        "private": "ready",
                        "business": "ready",
                    },
                    "generations": {
                        "public": 2,
                        "private": 1,
                        "business": 1,
                    },
                    "baseline_safe": True,
                }),
                started + 30,
            ),
        )
    journal.close()

    report = build_report(tmp_path / "ws-liveness-generation.db", day)

    assert any(
        reason.startswith("INVALID_WS_EVENT:public:")
        for reason in report["integrity"]["reason_codes"]
    )


@pytest.mark.unit
def test_ws_disconnect_requires_one_correlated_recovery(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    journal = SQLiteJournal(tmp_path / "ws-recovery.db")
    rows = (
        ("subscribing", "ready", 1, started - 1),
        ("ready", "disconnected", 1, started + 10),
        ("disconnected", "connecting", 2, started + 20),
        ("connecting", "ready", 2, started + 30),
    )
    with journal.transaction() as connection:
        for old_state, new_state, generation, observed_at in rows:
            connection.execute(
                """
                INSERT INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?, 'websocket_state_transition', 'info', 'public', ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    json.dumps({
                        "channel": "public",
                        "old_state": old_state,
                        "new_state": new_state,
                        "generation": generation,
                    }),
                    observed_at,
                ),
            )
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'websocket_subscription_ready', 'info', 'public', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "channel": "public",
                    "generation": 2,
                    "connect_subscribe_latency_seconds": 10,
                }),
                started + 30,
            ),
        )
    journal.close()

    report = build_report(tmp_path / "ws-recovery.db", day)

    assert "WS_RECOVERY_ASSOCIATION:public" in report[
        "integrity"
    ]["reason_codes"]


@pytest.mark.unit
def test_heartbeat_identity_and_mode_must_match_readiness_chain(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    journal = SQLiteJournal(tmp_path / "heartbeat-readiness.db")
    with journal.transaction() as connection:
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'runtime_readiness_transition', 'info', '', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "old_mode": "starting",
                    "new_mode": "ready",
                    "reason": "startup_complete",
                    "previous_mode_duration_seconds": 1,
                }),
                started - 1,
            ),
        )
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'runtime_heartbeat_sample', 'info', '', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "healthy": True,
                    "mode": "halted",
                    "pid": 123,
                    "boot_id": "boot-1",
                    "runtime_instance_id": "runtime-1",
                    "account_uid": "account-1",
                    "deployment_unit": "test.service",
                    "soak_epoch_id": "epoch-1",
                    "shadow_mode": False,
                    "shadow_write_attempt_count": 0,
                }),
                started + 30,
            ),
        )
    journal.close()

    report = build_report(
        tmp_path / "heartbeat-readiness.db",
        day,
        soak_epoch_id="epoch-1",
    )

    assert "RUNTIME_HEARTBEAT_READINESS_MISMATCH" in report[
        "integrity"
    ]["reason_codes"]


@pytest.mark.unit
def test_slo_report_reads_runtime_adverse_slippage_field(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.record_event(
        "execution_slippage_sample",
        payload={"adverse_slippage_ratio": "0.05"},
    )
    journal.close()
    report = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
    )
    assert report["execution_slippage"]["sample_count"] == 1
    assert report["execution_slippage"]["attempt_count"] == 1
    assert report["execution_slippage"]["p95_ratio"] == 0.05
    assert report["execution_slippage"]["p99_ratio"] == 0.05
    assert report["execution_slippage"]["max_ratio"] == 0.05


@pytest.mark.unit
def test_slo_recomputes_dynamic_cost_output_and_rejects_tamper(tmp_path):
    model = DynamicCostModel(maximum_slippage=0.01)
    inputs = {
        "side": "buy",
        "notional": 5.0,
        "close": 50000.0,
        "high": 50100.0,
        "low": 49900.0,
        "vol": 10.0,
        "vol_ccy": 500000.0,
    }
    _fee, expected = model(
        "buy",
        pd.Series({
            key: inputs[key]
            for key in ("close", "high", "low", "vol", "vol_ccy")
        }),
        inputs["notional"],
    )
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.record_event(
        "execution_slippage_sample",
        payload={
            "adverse_slippage_ratio": expected - 0.0001,
            "expected_model_slippage_ratio": expected,
            "cost_model_hash": model.manifest_hash(),
            "cost_model_manifest": model.manifest(),
            "cost_model_inputs": inputs,
            "source": "demo_validation_probe",
            "side": "buy",
            "probe_id": "a" * 32,
        },
    )
    journal.close()
    report = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
    )
    assert (
        report["execution_slippage"]["cost_model_hash"]
        == model.manifest_hash()
    )
    assert (
        report["execution_slippage"]["residual_cluster_count"] == 1
    )

    journal = SQLiteJournal(tmp_path / "trading.db", must_exist=True)
    with journal.transaction() as connection:
        row = connection.execute(
            """
            SELECT event_id, payload_json FROM system_events
            WHERE event_name='execution_slippage_sample'
            """
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["expected_model_slippage_ratio"] = expected + 0.001
        connection.execute(
            "UPDATE system_events SET payload_json=? WHERE event_id=?",
            (json.dumps(payload), row["event_id"]),
        )
    journal.close()
    tampered = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
    )
    assert "SLIPPAGE_MODEL_RECOMPUTATION_FAILED" in tampered[
        "integrity"
    ]["reason_codes"]


@pytest.mark.unit
def test_soak_rejects_hashless_cost_samples_from_cluster_ucb(tmp_path):
    model = DynamicCostModel(maximum_slippage=0.01)
    inputs = {
        "side": "buy",
        "notional": 5.0,
        "close": 50000.0,
        "high": 50100.0,
        "low": 49900.0,
        "vol": 10.0,
        "vol_ccy": 500000.0,
    }
    _fee, expected = model(
        "buy",
        pd.Series({
            key: inputs[key]
            for key in ("close", "high", "low", "vol", "vol_ccy")
        }),
        inputs["notional"],
    )
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.record_event(
        "execution_slippage_sample",
        payload={
            "adverse_slippage_ratio": expected,
            "expected_model_slippage_ratio": expected,
            "cost_model_hash": model.manifest_hash(),
            "cost_model_manifest": model.manifest(),
            "cost_model_inputs": inputs,
            "source": "demo_validation_probe",
            "side": "buy",
            "probe_id": "a" * 32,
        },
    )
    journal.record_event(
        "execution_slippage_sample",
        payload={
            "adverse_slippage_ratio": 0.01,
            "expected_model_slippage_ratio": 1.0,
            "probe_id": "b" * 32,
        },
    )
    journal.close()

    report = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
        soak_epoch_id="formal-soak",
        phase="soak",
    )

    assert report["execution_slippage"]["model_paired_count"] == 1
    assert (
        "SLIPPAGE_DYNAMIC_MODEL_PROVENANCE_MISSING"
        in report["integrity"]["reason_codes"]
    )
    assert (
        "SLIPPAGE_MODEL_PAIRING_INCOMPLETE"
        in report["integrity"]["reason_codes"]
    )


@pytest.mark.unit
def test_soak_rejects_residual_cluster_outside_done_formal_probe_lineage(
    tmp_path,
):
    model = DynamicCostModel(maximum_slippage=0.01)
    journal = SQLiteJournal(tmp_path / "trading.db")
    done_probe_id = "a" * 32
    extra_probe_id = "b" * 32
    journal.create_probe_run(
        probe_id=done_probe_id,
        account_uid="demo-account",
        utc_day=datetime.now(UTC).date().isoformat(),
        slot=1,
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        buy_cl_ord_id=f"pb{done_probe_id[:30]}",
        algo_cl_ord_id=f"pa{done_probe_id[:30]}",
        baseline_base_balance=Decimal("0"),
    )
    with journal.transaction() as connection:
        connection.execute(
            "UPDATE probe_runs SET state='DONE' WHERE probe_id=?",
            (done_probe_id,),
        )
    journal.record_event(
        "probe_schedule_sample",
        payload={
            "schedule_sha256": "c" * 64,
            "probe_id": done_probe_id,
            "compliant": True,
        },
    )
    for probe_id in (done_probe_id, extra_probe_id):
        inputs = {
            "side": "buy",
            "notional": 5.0,
            "close": 50000.0,
            "high": 50100.0,
            "low": 49900.0,
            "vol": 10.0,
            "vol_ccy": 500000.0,
        }
        _fee, expected = model(
            "buy",
            pd.Series({
                key: inputs[key]
                for key in ("close", "high", "low", "vol", "vol_ccy")
            }),
            inputs["notional"],
        )
        journal.record_event(
            "execution_slippage_sample",
            payload={
                "adverse_slippage_ratio": expected,
                "expected_model_slippage_ratio": expected,
                "cost_model_hash": model.manifest_hash(),
                "cost_model_manifest": model.manifest(),
                "cost_model_inputs": inputs,
                "source": "demo_validation_probe",
                "side": "buy",
                "probe_id": probe_id,
            },
        )
    journal.close()

    report = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
        soak_epoch_id="formal-soak",
        phase="soak",
    )

    assert report["probes"]["formal_probe_ids"] == [done_probe_id]
    assert report["probes"]["done_probe_ids"] == [done_probe_id]
    assert report["execution_slippage"]["residual_cluster_ids"] == [
        done_probe_id,
        extra_probe_id,
    ]
    assert "PROBE_RESIDUAL_LINEAGE_INVALID" in report["integrity"][
        "reason_codes"
    ]


@pytest.mark.unit
def test_slo_v2_rejects_v1_unknown_fields_and_zero_sample_success(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.close()
    report = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
    )
    with pytest.raises(ValueError, match="version"):
        validate_slo_v2_report({**report, "version": 1})
    with pytest.raises(ValueError, match="未知字段"):
        validate_slo_v2_report({**report, "manual_override": True})
    report["integrity"] = {
        "valid": True,
        "invalid_event_count": 0,
        "reason_codes": [],
    }
    with pytest.raises(ValueError, match="零预期采样"):
        validate_slo_v2_report(report)


@pytest.mark.unit
def test_backup_rpo_is_max_age_between_exact_restore_points(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    journal = SQLiteJournal(tmp_path / "trading.db")
    timestamps = [started - 60, *range(int(started) + 180, int(started) + 86400, 240)]
    with journal.transaction() as connection:
        for timestamp in timestamps:
            payload = {
                "integrity": "ok",
                "snapshot_completed_at": timestamp - 10,
                "offsite_readback_at": timestamp - 5,
                "roundtrip_started_at": timestamp - 8,
                "roundtrip_completed_at": timestamp - 5,
                "version_id": f"version-{timestamp}",
                "evidence_artifact_sha256": "a" * 64,
                "evidence_key_id": "backup-verifier-v1",
            }
            connection.execute(
                """
                INSERT INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?, 'backup_slo_sample', 'info', '', ?, ?)
                """,
                (uuid.uuid4().hex, json.dumps(payload), timestamp),
            )
    journal.close()
    report = build_report(tmp_path / "trading.db", day)
    assert report["backups"]["local_max_recovery_point_age_seconds"] <= 250
    assert report["backups"]["offsite_max_recovery_point_age_seconds"] <= 250
    assert report["backups"]["component_restore_sample_count"] > 0
    assert report["backups"]["component_restore_max_seconds"] == 3

    journal = SQLiteJournal(tmp_path / "trading.db", must_exist=True)
    with journal.transaction() as connection:
        connection.execute(
            "DELETE FROM system_events WHERE created_at=?",
            (float(int(started) + 420),),
        )
    journal.close()
    report = build_report(tmp_path / "trading.db", day)
    assert report["backups"]["local_max_recovery_point_age_seconds"] > 300
    assert report["backups"]["offsite_max_recovery_point_age_seconds"] > 300


@pytest.mark.unit
def test_raw_facts_keep_old_midnight_backup_boundary(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    database = tmp_path / "trading.db"
    journal = SQLiteJournal(database)
    timestamps = [
        started - 600,
        *range(int(started) + 60, int(started) + 86400, 240),
    ]
    with journal.transaction() as connection:
        for timestamp in timestamps:
            connection.execute(
                """
                INSERT INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?, 'backup_slo_sample', 'info', '', ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    json.dumps({
                        "integrity": "ok",
                        "snapshot_completed_at": timestamp - 10,
                        "offsite_readback_at": timestamp,
                        "roundtrip_started_at": timestamp - 5,
                        "roundtrip_completed_at": timestamp,
                        "version_id": f"version-{timestamp}",
                        "evidence_artifact_sha256": "a" * 64,
                        "evidence_key_id": "backup-verifier-v1",
                    }),
                    timestamp,
                ),
            )
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'backup_slo_sample', 'info', '', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "integrity": "ok",
                    "snapshot_completed_at": started - 1,
                    "offsite_readback_at": started - 1,
                    "roundtrip_started_at": started - 1,
                    "roundtrip_completed_at": started - 1,
                    "version_id": "forged-near-midnight",
                    "evidence_artifact_sha256": "forged",
                    "evidence_key_id": "backup-verifier-v1",
                }),
                started - 1,
            ),
        )
    journal.close()

    facts = export_slo_v2_facts(database, day)
    prior_backup_rows = [
        row
        for row in facts["tables"]["system_events"]
        if (
            row["event_name"] == "backup_slo_sample"
            and row["created_at"] < started
        )
    ]
    assert len(prior_backup_rows) == 1
    assert "forged-near-midnight" not in prior_backup_rows[0][
        "payload_json"
    ]
    rebuilt = report_from_slo_v2_facts(
        facts,
        soak_epoch_id="epoch-fixture",
        phase="burn-in",
    )
    direct = build_report(
        database,
        day,
        soak_epoch_id="epoch-fixture",
        phase="burn-in",
    )

    assert rebuilt == direct
    assert (
        rebuilt["backups"]["local_max_recovery_point_age_seconds"]
        > 300
    )
    assert (
        rebuilt["backups"]["offsite_max_recovery_point_age_seconds"]
        > 300
    )


@pytest.mark.unit
def test_stable_websocket_day_uses_periodic_liveness_not_fake_transitions(
    tmp_path,
):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    journal = SQLiteJournal(tmp_path / "trading.db")
    with journal.transaction() as connection:
        for channel in ("public", "private", "business"):
            connection.execute(
                """
                INSERT INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?, 'websocket_state_transition', 'info', ?, ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    channel,
                    json.dumps({
                        "channel": channel,
                        "old_state": "subscribing",
                        "new_state": "ready",
                        "generation": 1,
                    }),
                    started - 1,
                ),
            )
        for timestamp in range(
            int(started) + 30,
            int(started) + 86400,
            60,
        ):
            connection.execute(
                """
                INSERT INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?, 'websocket_liveness_sample', 'info', '', ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    json.dumps({
                        "states": {
                            "public": "ready",
                            "private": "ready",
                            "business": "ready",
                        },
                        "generations": {
                            "public": 1,
                            "private": 1,
                            "business": 1,
                        },
                        "baseline_safe": True,
                    }),
                    timestamp,
                ),
            )
    journal.close()

    report = build_report(tmp_path / "trading.db", day)

    for metrics in report["websocket"]["channels"].values():
        assert metrics["transition_count"] == 0
        assert metrics["state_sample_count"] == 1440
        assert metrics["ready_seconds"] == 86400
    assert "NO_WS_STATE_EVIDENCE" not in report["integrity"]["reason_codes"]


@pytest.mark.unit
def test_synthetic_alert_challenge_requires_signed_provider_provenance(
    tmp_path,
):
    journal = SQLiteJournal(tmp_path / "trading.db")
    event_id = journal.enqueue_outbox_once(
        "synthetic-alert:test-account:today",
        "warning.synthetic_alert_delivery_challenge",
        {"requires_signed_provider_receipt": True},
    )
    now = datetime.now(UTC).timestamp()
    journal.record_alert_attempt(
        event_id,
        started_at=now,
        completed_at=now + 0.1,
        http_status=202,
        ingestion_accepted=True,
    )
    journal.record_alert_provider_received(
        event_id,
        provider_received_at=now + 0.2,
        provider_event_id="provider-event",
        artifact_sha256="a" * 64,
    )
    journal.close()

    report = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
    )

    assert report["alerts"]["incident_count"] == 0
    assert report["alerts"]["synthetic_challenge_count"] == 1
    assert report["alerts"]["synthetic_provider_received_count"] == 1
    assert "NO_SYNTHETIC_ALERT_CHALLENGE" not in report[
        "integrity"
    ]["reason_codes"]


@pytest.mark.unit
def test_canonical_raw_facts_recompute_the_same_report(tmp_path):
    database = tmp_path / "trading.db"
    journal = SQLiteJournal(database)
    journal.record_event(
        "clock_quality_sample",
        payload={"okx_midpoint_offset_seconds": 0.25},
    )
    journal.record_event(
        "execution_slippage_sample",
        payload={"adverse_slippage_ratio": 0.001},
    )
    journal.close()
    day = datetime.now(UTC).date()

    facts = export_slo_v2_facts(database, day)
    rebuilt = report_from_slo_v2_facts(
        facts,
        soak_epoch_id="epoch-fixture",
        phase="burn-in",
    )
    direct = build_report(
        database,
        day,
        soak_epoch_id="epoch-fixture",
        phase="burn-in",
    )

    assert rebuilt == direct
    clock_row = next(
        row
        for row in facts["tables"]["system_events"]
        if row["event_name"] == "clock_quality_sample"
    )
    clock_row["payload_json"] = json.dumps({
        "okx_midpoint_offset_seconds": 10,
    })
    changed = report_from_slo_v2_facts(
        facts,
        soak_epoch_id="epoch-fixture",
        phase="burn-in",
    )
    assert changed != direct


@pytest.mark.unit
def test_raw_facts_keep_readiness_midnight_boundary(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    database = tmp_path / "readiness-boundary.db"
    journal = SQLiteJournal(database)
    with journal.transaction() as connection:
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'runtime_readiness_transition', 'info', '', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "old_mode": "starting",
                    "new_mode": "ready",
                    "reason": "startup_complete",
                    "previous_mode_duration_seconds": 1,
                }),
                started - 1,
            ),
        )
    journal.close()

    facts = export_slo_v2_facts(database, day)
    rebuilt = report_from_slo_v2_facts(
        facts,
        soak_epoch_id="epoch-fixture",
        phase="burn-in",
    )

    assert any(
        row["event_name"] == "runtime_readiness_transition"
        and row["created_at"] < started
        for row in facts["tables"]["system_events"]
    )
    assert rebuilt["runtime"]["readiness_ready_seconds"] == 86400


@pytest.mark.unit
def test_ws_recovery_crossing_midnight_uses_original_incident_start(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    database = tmp_path / "ws-midnight-recovery.db"
    journal = SQLiteJournal(database)
    transitions = (
        ("subscribing", "ready", 1, started - 200),
        ("ready", "disconnected", 1, started - 120),
        ("disconnected", "connecting", 2, started - 10),
        ("connecting", "ready", 2, started + 10),
    )
    with journal.transaction() as connection:
        for old_state, new_state, generation, observed_at in transitions:
            connection.execute(
                """
                INSERT INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?, 'websocket_state_transition', 'info', 'public', ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    json.dumps({
                        "channel": "public",
                        "old_state": old_state,
                        "new_state": new_state,
                        "generation": generation,
                    }),
                    observed_at,
                ),
            )
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'websocket_subscription_ready', 'info', 'public', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "channel": "public",
                    "generation": 2,
                    "connect_subscribe_latency_seconds": 20,
                }),
                started + 10,
            ),
        )
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'websocket_recovery_completed', 'info', 'public', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "channel": "public",
                    "generation": 2,
                    "disconnect_duration_seconds": 140,
                    "rest_baseline_duration_seconds": 10,
                    "safe": True,
                }),
                started + 20,
            ),
        )
    journal.close()

    direct = build_report(
        database,
        day,
        soak_epoch_id="epoch-fixture",
    )
    facts = export_slo_v2_facts(database, day)
    rebuilt = report_from_slo_v2_facts(
        facts,
        soak_epoch_id="epoch-fixture",
        phase="burn-in",
    )

    assert "WS_RECOVERY_DURATION_MISMATCH:public" not in direct[
        "integrity"
    ]["reason_codes"]
    assert rebuilt == direct
    assert any(
        row["event_name"] == "websocket_state_transition"
        and json.loads(row["payload_json"]).get("new_state")
        == "disconnected"
        and row["created_at"] == started - 120
        for row in facts["tables"]["system_events"]
    )


@pytest.mark.unit
def test_first_heartbeat_cannot_self_attest_readiness_boundary(tmp_path):
    day = (datetime.now(UTC) - timedelta(days=1)).date()
    started = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=UTC,
    ).timestamp()
    journal = SQLiteJournal(tmp_path / "heartbeat-only-boundary.db")
    with journal.transaction() as connection:
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'runtime_heartbeat_sample', 'info', '', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "healthy": True,
                    "mode": "ready",
                    "pid": 123,
                    "boot_id": "boot-1",
                    "runtime_instance_id": "runtime-1",
                    "account_uid": "account-1",
                    "deployment_unit": "test.service",
                    "soak_epoch_id": "epoch-1",
                    "shadow_mode": False,
                    "shadow_write_attempt_count": 0,
                }),
                started + 30,
            ),
        )
    journal.close()

    report = build_report(
        tmp_path / "heartbeat-only-boundary.db",
        day,
        soak_epoch_id="epoch-1",
    )

    assert "RUNTIME_READINESS_BOUNDARY_UNKNOWN" in report[
        "integrity"
    ]["reason_codes"]
    assert "RUNTIME_HEARTBEAT_READINESS_MISMATCH" in report[
        "integrity"
    ]["reason_codes"]
    assert report["runtime"]["readiness_ready_seconds"] == 0
