"""Durable 运行 SLO 报告测试。"""

from datetime import UTC, datetime

import pytest

from okx_quant.infrastructure.db import SQLiteJournal
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
        "execution_slippage_sample",
        payload={"adverse_slippage_ratio": 0.001},
    )
    journal.close()

    report = build_report(
        tmp_path / "trading.db",
        datetime.now(UTC).date(),
    )
    protection = report["protection_activation"]
    assert protection["sample_count"] == 4
    assert protection["p95_seconds"] == 9.0
    assert protection["p99_seconds"] == 9.0
    assert protection["p99_within_10_seconds"] is True
    assert (
        report["startup_reconciliation"]["all_within_60_seconds"]
        is True
    )
    assert report["execution_slippage"]["p99_ratio"] == 0.001
    assert report["reconciliation"]["unexplained_mismatches"] == 0


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
    assert report["protection_activation"]["sample_count"] == 0
    assert report["execution_slippage"]["sample_count"] == 0


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
    assert report["execution_slippage"] == {
        "sample_count": 1,
        "p99_ratio": 0.05,
        "max_ratio": 0.05,
    }
