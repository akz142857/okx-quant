"""Read-only Web Dashboard contracts."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.request
from decimal import Decimal

import pytest

from okx_quant.domain.orders import SystemMode
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.web_dashboard import DashboardReadModel
from okx_quant.web_dashboard.server import DashboardServer
from scripts.dashboard_preview import _seed_preview


@pytest.fixture
def dashboard_database(tmp_path):
    path = tmp_path / "trading.db"
    journal = SQLiteJournal(path)
    journal.initialize_identity(
        account_id="demo-account-sensitive",
        initial_config_hash="a" * 64,
        actor="fixture",
    )
    assert journal.set_mode(
        SystemMode.READY,
        allow_hard_release=True,
        expected_hard_epoch=1,
        reason="dashboard_fixture_ready",
    )
    journal.record_account_snapshot(
        total_equity_quote=Decimal("5001.25"),
        available_quote=Decimal("4980.50"),
        holdings=[{"ccy": "USDT", "balance": "5001.25"}],
        source="fixture",
    )
    journal.reconcile_position(
        "DOGE-USDT",
        Decimal("10"),
        available_qty=Decimal("9.99"),
        reference_price=Decimal("0.07"),
        reason="fixture",
    )
    journal.record_event(
        "dashboard_fixture_event",
        severity="warning",
        payload={
            "detail": "safe",
            "api_key": "must-not-leak",
            "account_id": "must-not-leak",
        },
    )
    with journal.transaction() as connection:
        connection.execute(
            """
            INSERT INTO order_intents(
                intent_id, cl_ord_id, inst_id, side,
                requested_base_qty, state, source,
                created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                "intent-1",
                "client-order-1",
                "DOGE-USDT",
                "buy",
                "10",
                "filled",
                "strategy",
                1,
                2,
            ),
        )
    journal.close()
    return path


@pytest.mark.unit
def test_read_model_projects_overview_and_redacts_events(dashboard_database):
    model = DashboardReadModel(dashboard_database)

    overview = model.overview()
    positions = model.positions()
    orders = model.orders()
    events = model.events()

    assert overview["mode"] == "ready"
    assert overview["account"]["equity"] == pytest.approx(5001.25)
    assert overview["account_fingerprint"]
    assert "demo-account-sensitive" not in json.dumps(overview)
    assert positions[0]["instrument"] == "DOGE-USDT"
    assert positions[0]["quantity"] == pytest.approx(10)
    assert orders[0]["intent_id"] == "intent-1"
    fixture_event = next(
        event for event in events if event["name"] == "dashboard_fixture_event"
    )
    assert fixture_event["payload"]["detail"] == "safe"
    assert fixture_event["payload"]["api_key"] == "[REDACTED]"
    assert fixture_event["payload"]["account_id"] == "[REDACTED]"


@pytest.mark.unit
def test_read_model_never_opens_database_for_write(dashboard_database):
    model = DashboardReadModel(dashboard_database)

    with (
        model._connection() as connection,
        pytest.raises(sqlite3.OperationalError),
    ):
        connection.execute(
            "INSERT INTO system_state(key, value, updated_at) VALUES('x','y',0)"
        )


@pytest.mark.unit
def test_dashboard_server_is_local_read_only_and_secured(dashboard_database):
    model = DashboardReadModel(dashboard_database)
    server = DashboardServer(model, port=0)
    server.start()
    base = f"http://127.0.0.1:{server.port}"
    try:
        with urllib.request.urlopen(f"{base}/healthz", timeout=2) as response:
            health = json.load(response)
            assert health["ok"] is True
            assert health["access"] == "read-only"
            assert response.headers["X-Frame-Options"] == "DENY"
            assert "frame-ancestors 'none'" in response.headers[
                "Content-Security-Policy"
            ]

        with urllib.request.urlopen(
            f"{base}/api/v1/overview",
            timeout=2,
        ) as response:
            assert json.load(response)["mode"] == "ready"

        with urllib.request.urlopen(f"{base}/", timeout=2) as response:
            body = response.read().decode()
            assert "OKX Quant · Mission Control" in body

        request = urllib.request.Request(
            f"{base}/api/v1/orders",
            method="POST",
            data=b"{}",
        )
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(request, timeout=2)
        assert rejected.value.code == 405
    finally:
        server.stop()


@pytest.mark.unit
def test_dashboard_rejects_non_loopback_binding(dashboard_database):
    with pytest.raises(ValueError, match="回环地址"):
        DashboardServer(
            DashboardReadModel(dashboard_database),
            host="0.0.0.0",
        )


@pytest.mark.unit
def test_dashboard_rejects_symlink_database(dashboard_database, tmp_path):
    link = tmp_path / "linked.db"
    link.symlink_to(dashboard_database)

    with pytest.raises(ValueError, match="符号链接"):
        DashboardReadModel(link)


@pytest.mark.unit
def test_synthetic_preview_populates_every_dashboard_section(tmp_path):
    journal = SQLiteJournal(tmp_path / "preview.db")
    _seed_preview(journal, now=1_800_000_000)
    journal.close()

    model = DashboardReadModel(tmp_path / "preview.db")
    overview = model.overview()

    assert overview["data_class"] == "synthetic_preview"
    assert overview["mode"] == "ready"
    assert overview["account"]["equity"] > 5000
    assert len(overview["equity_series"]) == 48
    assert len(model.positions()) == 2
    assert len(model.orders()) == 5
    assert len(model.events()) >= 5
