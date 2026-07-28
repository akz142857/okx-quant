"""生产监控、备份与外部 watchdog 契约测试。"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

from okx_quant.cli.operations import halt_entries
from okx_quant.domain.orders import OrderIntent, OrderState, SystemMode
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.infrastructure.logging import JsonFormatter, SecretRedactionFilter
from okx_quant.infrastructure.metrics import MetricRegistry, MetricsServer
from okx_quant.infrastructure.operations import BackupService, HeartbeatService
from okx_quant.ops.watchdog import inspect
from scripts import cold_restore
from scripts import test_api as api_diagnostic
from scripts.cold_restore import install_verified_database
from scripts.offsite_restore_check import _version_id


def _backup_signing_keys(tmp_path: Path) -> tuple[Path, Path]:
    private_key = tmp_path / "backup-private.pem"
    public_key = tmp_path / "backup-public.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "Ed25519",
            "-out",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    private_key.chmod(0o600)
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )
    return private_key, public_key


@pytest.mark.unit
def test_online_backup_can_be_opened_readonly_and_restored(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.record_event("fixture")
    service = BackupService(journal, tmp_path / "backups")
    backup = service.backup_once()
    probe = sqlite3.connect(f"file:{backup}?mode=ro", uri=True)
    try:
        assert probe.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert probe.execute(
            "SELECT COUNT(*) FROM system_events"
        ).fetchone()[0] >= 1
    finally:
        probe.close()
        journal.close()


@pytest.mark.unit
def test_healthz_reports_liveness_while_readyz_reports_readiness():
    server = MetricsServer(
        MetricRegistry(),
        host="127.0.0.1",
        port=0,
        health=lambda: (False, {"ready": False}),
        liveness=lambda: (True, {"live": True}),
    )
    server.start()
    try:
        assert server._server is not None
        port = server._server.server_address[1]
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/healthz",
            timeout=2,
        ) as response:
            assert response.status == 200
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/readyz",
                timeout=2,
            )
        assert rejected.value.code == 503
    finally:
        server.stop()


@pytest.mark.unit
def test_online_backup_retention_is_tiered(tmp_path, monkeypatch):
    journal = SQLiteJournal(tmp_path / "trading.db")
    service = BackupService(journal, tmp_path / "backups")
    service.backup_dir.mkdir()
    now = 1_800_000_000.0
    monkeypatch.setattr(time, "time", lambda: now)
    fixtures = [
        ("recent-a", 60),
        ("recent-b", 300),
        ("hour-a", 2 * 86400 + 600),
        ("hour-b", 2 * 86400 + 900),
        ("day-a", 10 * 86400 + 600),
        ("day-b", 10 * 86400 + 900),
        ("expired", 31 * 86400),
    ]
    for name, age in fixtures:
        path = service.backup_dir / f"trading-{name}.db"
        path.touch()
        os.utime(path, (now - age, now - age))
    service._prune()
    remaining = {path.stem for path in service.backup_dir.glob("*.db")}
    assert {"trading-recent-a", "trading-recent-b"} <= remaining
    assert len({name for name in remaining if "hour-" in name}) == 1
    assert len({name for name in remaining if "day-" in name}) == 1
    assert "trading-expired" not in remaining
    journal.close()


@pytest.mark.unit
def test_encrypted_daily_archive_passes_isolated_restore_drill(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.initialize_identity(
        account_id="demo-account",
        initial_config_hash="a" * 64,
        actor="fixture",
    )
    journal.record_event("fixture")
    project = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment["OKX_QUANT_BACKUP_PASSPHRASE"] = "test-only-passphrase"
    private_key, public_key = _backup_signing_keys(tmp_path)
    archive = subprocess.run(
        [
            sys.executable,
            str(project / "scripts/daily_archive.py"),
            "--database",
            str(journal.path),
            "--output-dir",
            str(tmp_path / "daily"),
            "--expected-account-id",
            "demo-account",
            "--manifest-private-key",
            str(private_key),
            "--manifest-public-key",
            str(public_key),
            "--signing-key-id",
            "test-signing-v1",
            "--encryption-key-id",
            "test-encryption-v1",
            "--min-free-bytes",
            "0",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.strip()
    assert Path(archive + ".manifest.json").exists()
    evidence = tmp_path / "restore.json"
    subprocess.run(
        [
            sys.executable,
            str(project / "scripts/restore_drill.py"),
            archive,
            "--expected-account-id",
            "demo-account",
            "--manifest-public-key",
            str(public_key),
            "--expected-signing-key-id",
            "test-signing-v1",
            "--expected-encryption-key-id",
            "test-encryption-v1",
            "--output",
            str(evidence),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    result = json.loads(evidence.read_text())
    assert result["ok"]
    assert result["checksum_verified"]
    assert result["schema_version"] == 9
    assert result["account_id"] == "demo-account"
    assert result["elapsed_seconds"] <= result["max_rto_seconds"]
    journal.close()


@pytest.mark.unit
def test_restore_drill_rejects_plaintext_and_wrong_account(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.initialize_identity(
        account_id="demo-account",
        initial_config_hash="a" * 64,
        actor="fixture",
    )
    project = Path(__file__).resolve().parents[1]
    private_key, public_key = _backup_signing_keys(tmp_path)
    plaintext = subprocess.run(
        [
            sys.executable,
            str(project / "scripts/restore_drill.py"),
            str(journal.path),
            "--expected-account-id",
            "demo-account",
            "--manifest-public-key",
            str(public_key),
            "--expected-signing-key-id",
            "test-signing-v1",
            "--expected-encryption-key-id",
            "test-encryption-v1",
        ],
        capture_output=True,
        text=True,
    )
    assert plaintext.returncode != 0
    assert "加密" in plaintext.stderr

    environment = dict(os.environ)
    environment["OKX_QUANT_BACKUP_PASSPHRASE"] = "test-only-passphrase"
    archive = subprocess.run(
        [
            sys.executable,
            str(project / "scripts/daily_archive.py"),
            "--database",
            str(journal.path),
            "--output-dir",
            str(tmp_path / "daily"),
            "--expected-account-id",
            "demo-account",
            "--manifest-private-key",
            str(private_key),
            "--manifest-public-key",
            str(public_key),
            "--signing-key-id",
            "test-signing-v1",
            "--encryption-key-id",
            "test-encryption-v1",
            "--min-free-bytes",
            "0",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.strip()
    wrong = subprocess.run(
        [
            sys.executable,
            str(project / "scripts/restore_drill.py"),
            archive,
            "--expected-account-id",
            "other-account",
            "--manifest-public-key",
            str(public_key),
            "--expected-signing-key-id",
            "test-signing-v1",
            "--expected-encryption-key-id",
            "test-encryption-v1",
        ],
        capture_output=True,
        text=True,
        env=environment,
    )
    assert wrong.returncode != 0
    assert "manifest 账户" in wrong.stderr
    journal.close()


@pytest.mark.unit
def test_cold_restore_atomically_installs_and_latches_maintenance(tmp_path):
    source = SQLiteJournal(tmp_path / "source.db")
    source.initialize_identity(
        account_id="demo-account",
        initial_config_hash="a" * 64,
        actor="fixture",
    )
    _, hard_epoch = source.get_mode_state()
    source.set_mode(
        SystemMode.READY,
        allow_hard_release=True,
        expected_hard_epoch=hard_epoch,
    )
    candidate = tmp_path / "candidate.db"
    source.backup(candidate)
    source.close()
    target = tmp_path / "installed" / "trading.db"
    result = install_verified_database(
        candidate,
        target,
        actor="restore-operator",
        source=tmp_path / "archive.db.enc",
        replace_existing=False,
        confirmation="",
        expected_account_id="demo-account",
        expected_schema_version=9,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    assert result["installed"]
    assert result["mode"] == "maintenance"
    assert target.stat().st_mode & 0o777 == 0o640
    assert result["owner_uid"] == os.getuid()
    assert result["owner_gid"] == os.getgid()
    assert result["mode_bits"] == "0640"
    assert not candidate.exists()

    replacement = tmp_path / "replacement.db"
    shutil.copy2(target, replacement)
    with pytest.raises(RuntimeError, match="精确确认词"):
        install_verified_database(
            replacement,
            target,
            actor="restore-operator",
            source=tmp_path / "archive.db.enc",
            replace_existing=False,
            confirmation="",
            expected_account_id="demo-account",
            expected_schema_version=9,
        )


@pytest.mark.unit
def test_cold_restore_switch_failure_keeps_canonical_target(tmp_path, monkeypatch):
    source = SQLiteJournal(tmp_path / "source.db")
    source.initialize_identity(
        account_id="demo-account",
        initial_config_hash="a" * 64,
        actor="fixture",
    )
    target = tmp_path / "installed" / "trading.db"
    candidate = tmp_path / "candidate.db"
    source.backup(target)
    source.record_event("candidate-is-newer")
    source.backup(candidate)
    source.close()
    original_target = target.read_bytes()

    replace_calls = []

    def fail_atomic_switch(source_path, destination_path):
        replace_calls.append((Path(source_path), Path(destination_path)))
        raise OSError("injected atomic switch failure")

    monkeypatch.setattr(cold_restore.os, "replace", fail_atomic_switch)
    with pytest.raises(OSError, match="injected atomic switch failure"):
        install_verified_database(
            candidate,
            target,
            actor="restore-operator",
            source=tmp_path / "archive.db.enc",
            replace_existing=True,
            confirmation=(
                f"REPLACE {target.absolute()} WITH ACCOUNT demo-account"
            ),
            expected_account_id="demo-account",
            expected_schema_version=9,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )

    assert replace_calls == [(candidate, target.absolute())]
    assert target.read_bytes() == original_target
    assert candidate.exists()
    preserved = list(
        target.parent.glob("trading.db.pre-cold-restore-*")
    )
    assert len(preserved) == 1
    assert preserved[0].read_bytes() == original_target


@pytest.mark.unit
def test_cold_restore_checkpoints_old_wal_before_atomic_switch(tmp_path):
    old = SQLiteJournal(tmp_path / "old.db")
    old.initialize_identity(
        account_id="demo-account",
        initial_config_hash="a" * 64,
        actor="fixture",
    )
    target = tmp_path / "production" / "trading.db"
    old.backup(target)
    old.close()
    subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import os,sqlite3,sys;"
                "c=sqlite3.connect(sys.argv[1]);"
                "c.execute('PRAGMA journal_mode=WAL');"
                "c.execute('CREATE TABLE legacy_marker(value TEXT)');"
                "c.execute(\"INSERT INTO legacy_marker VALUES('committed')\");"
                "c.commit();"
                "os._exit(0)"
            ),
            str(target),
        ],
        check=True,
    )
    assert Path(f"{target}-wal").exists()

    restored = SQLiteJournal(tmp_path / "restored.db")
    restored.initialize_identity(
        account_id="demo-account",
        initial_config_hash="b" * 64,
        actor="fixture",
    )
    candidate = tmp_path / "candidate.db"
    restored.backup(candidate)
    restored.close()

    result = install_verified_database(
        candidate,
        target,
        actor="restore-operator",
        source=tmp_path / "archive.db.enc",
        replace_existing=True,
        confirmation=(
            f"REPLACE {target.absolute()} WITH ACCOUNT demo-account"
        ),
        expected_account_id="demo-account",
        expected_schema_version=9,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )

    installed = sqlite3.connect(target)
    previous = sqlite3.connect(result["replaced_backup"])
    try:
        assert installed.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='table' AND name='legacy_marker'"
        ).fetchone()[0] == 0
        assert previous.execute(
            "SELECT value FROM legacy_marker"
        ).fetchone()[0] == "committed"
    finally:
        installed.close()
        previous.close()


@pytest.mark.unit
def test_cold_restore_cli_wires_owner_only_to_install(tmp_path, monkeypatch):
    archive = tmp_path / "archive.db.enc"
    output = tmp_path / "cold-restore.json"
    target = tmp_path / "production" / "trading.db"
    captured = {}
    monkeypatch.setattr(cold_restore, "_assert_trader_stopped", lambda: None)
    monkeypatch.setattr(
        cold_restore.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1234),
    )
    monkeypatch.setattr(
        cold_restore.grp,
        "getgrnam",
        lambda _name: SimpleNamespace(gr_gid=2345),
    )
    monkeypatch.setattr(
        cold_restore,
        "verify_manifest",
        lambda *_args: {
            "account_id": "demo-account",
            "schema_version": 9,
            "signing_key_id": "signing-v1",
            "encryption_key_id": "encryption-v1",
            "sha256": "a" * 64,
        },
    )

    def fake_decrypt(_archive, candidate, _passphrase_env):
        candidate.write_bytes(b"candidate")

    def fake_verify(
        _candidate,
        *,
        expected_account_id,
        expected_schema_version,
    ):
        assert expected_account_id == "demo-account"
        assert expected_schema_version == 9
        return {"database_ok": True}

    def fake_install(candidate, installed_target, **kwargs):
        captured.update(kwargs)
        assert candidate.read_bytes() == b"candidate"
        assert installed_target == target
        return {"installed": True}

    monkeypatch.setattr(cold_restore, "decrypt", fake_decrypt)
    monkeypatch.setattr(cold_restore, "verify", fake_verify)
    monkeypatch.setattr(cold_restore, "install_verified_database", fake_install)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cold_restore.py",
            str(archive),
            "--target",
            str(target),
            "--expected-account-id",
            "demo-account",
            "--manifest-public-key",
            str(tmp_path / "manifest-public.pem"),
            "--expected-signing-key-id",
            "signing-v1",
            "--expected-encryption-key-id",
            "encryption-v1",
            "--actor",
            "operator",
            "--output",
            str(output),
        ],
    )

    assert cold_restore.main() == 0
    assert captured["owner_uid"] == 1234
    assert captured["owner_gid"] == 2345
    assert json.loads(output.read_text(encoding="utf-8"))["installed"]


@pytest.mark.unit
def test_api_diagnostic_refuses_all_live_trade_writes():
    client = SimpleNamespace(simulated=False)
    assert not api_diagnostic.test_trade(
        client,
        "BTC-USDT",
        100,
    )
    with pytest.raises(RuntimeError, match="禁止实盘写"):
        api_diagnostic._test_trade_live(
            client,
            "BTC-USDT",
        )


@pytest.mark.unit
def test_api_diagnostic_rejects_incomplete_demo_credentials(capsys):
    client = SimpleNamespace(
        api_key="demo-key",
        secret_key="",
        passphrase="",
        simulated=True,
        base_url="https://openapi.okx.com",
    )
    assert api_diagnostic.test_auth(client) == (False, 0.0)
    output = capsys.readouterr().out
    assert "OKX_SECRET_KEY" in output
    assert "OKX_PASSPHRASE" in output
    assert "demo-key" not in output


@pytest.mark.unit
def test_external_watchdog_pages_on_stale_heartbeat_with_position(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.01"),
        available_qty=Decimal("0.01"),
        reason="fixture",
    )
    heartbeat = tmp_path / "heartbeat"
    heartbeat.write_text(json.dumps({
        "pid": 123,
        "timestamp": time.time() - 120,
    }))
    report = inspect(heartbeat, journal.path, stale_after_s=20)
    assert not report["ok"]
    assert report["unsafe_positions"][0]["inst_id"] == "BTC-USDT"
    journal.close()


@pytest.mark.unit
def test_halt_entries_latches_mode_before_runtime_ack(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    result = halt_entries(journal, actor="fixture", timeout_s=0)
    assert result["status"] == "pending"
    assert journal.get_mode() is SystemMode.HALTED
    journal.close()


@pytest.mark.unit
def test_external_watchdog_pages_on_stale_heartbeat_with_pending_buy(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    intent = journal.create_order_intent(OrderIntent(
        intent_id="pending-buy",
        cl_ord_id="QPENDINGBUY01",
        inst_id="BTC-USDT",
        side="buy",
        requested_base_qty=Decimal("0.01"),
        reserved_quote=Decimal("500"),
    ))
    journal.update_intent(intent, OrderState.SUBMITTING)
    report = inspect(
        tmp_path / "missing-heartbeat",
        journal.path,
        stale_after_s=20,
    )
    assert not report["ok"]
    assert report["stale_with_pending_risk"]
    assert report["nonterminal_orders"][0]["intent_id"] == "pending-buy"
    journal.close()


@pytest.mark.unit
@pytest.mark.parametrize("offset", [-120, 86400])
def test_external_watchdog_rejects_stale_or_future_heartbeat_when_flat(
    tmp_path, offset
):
    journal = SQLiteJournal(tmp_path / "trading.db")
    heartbeat = tmp_path / "heartbeat"
    heartbeat.write_text(json.dumps({
        "pid": 123,
        "timestamp": time.time() + offset,
    }))
    report = inspect(heartbeat, journal.path, stale_after_s=20)
    assert not report["ok"]
    assert not report["heartbeat_fresh"]
    journal.close()


@pytest.mark.unit
def test_heartbeat_is_atomic_and_watchdog_accepts_safe_state(tmp_path):
    journal = SQLiteJournal(tmp_path / "trading.db")
    heartbeat = tmp_path / "heartbeat"
    service = HeartbeatService(heartbeat, interval_s=0.01)
    service.start()
    deadline = time.monotonic() + 1
    while not heartbeat.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    service.stop()
    assert inspect(heartbeat, journal.path, stale_after_s=20)["ok"]
    assert not heartbeat.with_suffix(".tmp").exists()
    journal.close()


@pytest.mark.unit
def test_external_watchdog_reports_database_corruption_instead_of_crashing(
    tmp_path,
):
    database = tmp_path / "broken.db"
    database.write_text("not sqlite", encoding="utf-8")
    report = inspect(tmp_path / "missing-heartbeat", database, stale_after_s=20)
    assert not report["ok"]
    assert "DatabaseError" in report["database_error"]


@pytest.mark.unit
def test_external_watchdog_pages_directly_on_database_volume_exhaustion(
    tmp_path,
    monkeypatch,
):
    journal = SQLiteJournal(tmp_path / "trading.db")
    heartbeat = tmp_path / "heartbeat"
    heartbeat.write_text(json.dumps({
        "pid": 123,
        "timestamp": time.time(),
        "healthy": True,
    }))
    monkeypatch.setattr(
        "okx_quant.ops.watchdog.shutil.disk_usage",
        lambda _path: SimpleNamespace(
            total=1000,
            used=999,
            free=1,
        ),
    )
    monkeypatch.setattr(
        "okx_quant.ops.watchdog.os.statvfs",
        lambda _path: SimpleNamespace(
            f_files=1000,
            f_favail=1,
        ),
    )
    report = inspect(
        heartbeat,
        journal.path,
        stale_after_s=20,
        min_free_bytes=10,
        min_free_ratio=0.05,
        min_free_inode_ratio=0.05,
    )
    assert not report["ok"]
    assert report["disk_unsafe"]
    assert report["database_volume_free_bytes"] == 1
    journal.close()


@pytest.mark.unit
def test_offsite_restore_requires_and_uses_an_immutable_s3_version(monkeypatch):
    observed = {}

    def fake_run(argv, **_kwargs):
        observed["argv"] = argv
        return SimpleNamespace(stdout='{"VersionId":"version-123"}')

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _version_id("backup-bucket", "prefix/archive.enc") == "version-123"
    assert observed["argv"][0:3] == ["aws", "s3api", "head-object"]
    assert observed["argv"][observed["argv"].index("--bucket") + 1] == (
        "backup-bucket"
    )


@pytest.mark.unit
def test_post_start_verifier_checks_backup_before_restart_and_has_fail_safe():
    script = (
        Path(__file__).resolve().parents[1] / "scripts/verify_deploy.sh"
    ).read_text(encoding="utf-8")
    assert "trap post_start_fail_safe ERR" in script
    assert (
        '[[ "${status_mode}" =~ ^(halted|emergency_exit|maintenance)$ ]]'
        in script
    )
    assert "verified hard-safe protection kernel remains live" in script
    assert "page_service_failure.py" in script
    assert "stopping unverifiable trader fail closed" in script
    assert script.index(
        "systemctl start okx-quant-daily-backup.service"
    ) < script.index('systemctl restart "${SERVICE_NAME}"')


@pytest.mark.unit
def test_json_logging_redacts_secrets_and_keeps_context():
    record = logging.LogRecord(
        "fixture", logging.INFO, __file__, 1, "key=secret-value", (), None
    )
    record.intent_id = "intent-1"
    record.payload = {"nested": "secret-value"}
    redactor = SecretRedactionFilter(["secret-value"])
    assert redactor.filter(record)
    payload = json.loads(JsonFormatter().format(record))
    assert "secret-value" not in payload["message"]
    assert payload["payload"]["nested"] == "[REDACTED]"
    assert payload["intent_id"] == "intent-1"
    assert {
        "cl_ord_id",
        "ord_id",
        "algo_id",
        "inst_id",
        "system_mode",
        "state_from",
        "state_to",
        "exchange_code",
        "latency_ms",
        "correlation_id",
    } <= payload.keys()


@pytest.mark.unit
def test_prometheus_registry_renders_core_labels():
    registry = MetricRegistry()
    registry.inc(
        "okx_api_requests_total",
        endpoint="/api/v5/trade/order",
        code="0",
    )
    registry.set("system_mode", 1, mode="ready")
    registry.set("account_snapshot_age_seconds", float("inf"))
    rendered = registry.render()
    assert '# TYPE okx_api_requests_total counter' in rendered
    assert 'endpoint="/api/v5/trade/order"' in rendered
    assert 'system_mode{mode="ready"} 1' in rendered
    assert "account_snapshot_age_seconds +Inf" in rendered


@pytest.mark.unit
def test_prometheus_registry_renders_histogram():
    registry = MetricRegistry()
    registry.observe(
        "protection_activation_latency_seconds",
        1.5,
        buckets=(1, 3, 10),
        inst="BTC-USDT",
    )
    rendered = registry.render()
    assert (
        "# TYPE protection_activation_latency_seconds histogram"
        in rendered
    )
    assert (
        'protection_activation_latency_seconds_bucket'
        '{inst="BTC-USDT",le="1"} 0.0'
        in rendered
    )
    assert (
        'protection_activation_latency_seconds_bucket'
        '{inst="BTC-USDT",le="3"} 1.0'
        in rendered
    )
    assert (
        'protection_activation_latency_seconds_count'
        '{inst="BTC-USDT"} 1.0'
        in rendered
    )
