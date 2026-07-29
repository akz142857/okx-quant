import json
import subprocess
import sys
import time

import pytest

from okx_quant.application.approval import verify_ed25519_artifact
from scripts import external_demo_monitor


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def _keys(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)],
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


def _signal_args() -> list[str]:
    result = []
    for name in ("host", "service", "provider", "evidence-close", "backup"):
        result.extend(
            ["--signal-url", f"{name}=http://127.0.0.1/signals/{name}"]
        )
    return result


def _signal_response(url, release, config):
    name = url.rsplit("/", 1)[-1]
    return _Response(200, {
        "ok": True,
        "signal": name,
        "observed_at": time.time(),
        "deadman_id": f"{name}-deadman",
        "target": "demo-active",
        "release_identity": release,
        "config_identity": config,
        "account_uid": "demo-account",
        "deployment_unit": "okx-quant-demo-active.service",
        "soak_epoch_id": "epoch-0001",
    })


def test_external_monitor_signs_healthy_identity_bound_observation(
    tmp_path,
    monkeypatch,
):
    release = "a" * 40
    config = "b" * 64

    def fake_get(url, **_kwargs):
        if url.endswith("/healthz"):
            return _Response(200, {
                "live": True,
                "release_identity": release,
                "config_identity": config,
                "account_uid": "demo-account",
                "deployment_unit": "okx-quant-demo-active.service",
                "soak_epoch_id": "epoch-0001",
            })
        if url.endswith("/readyz"):
            return _Response(200, {
                "ready": True,
                "release_identity": release,
                "config_identity": config,
                "account_uid": "demo-account",
                "deployment_unit": "okx-quant-demo-active.service",
                "soak_epoch_id": "epoch-0001",
            })
        if "/signals/" in url:
            return _signal_response(url, release, config)
        return _Response(200, {
            "code": "0",
            "data": [{"ts": str(int(time.time() * 1000))}],
        })

    monkeypatch.setattr(external_demo_monitor.requests, "get", fake_get)
    private, public = _keys(tmp_path)
    output = tmp_path / "observation.json"
    monkeypatch.setattr(sys, "argv", [
        "external_demo_monitor.py",
        "--target",
        "demo-active",
        "--health-url",
        "http://127.0.0.1/healthz",
        "--ready-url",
        "http://127.0.0.1/readyz",
        "--allow-loopback-http",
        *_signal_args(),
        "--expected-release",
        release,
        "--expected-config",
        config,
        "--expected-account-uid",
        "demo-account",
        "--expected-unit",
        "okx-quant-demo-active.service",
        "--soak-epoch-id",
        "epoch-0001",
        "--private-key",
        str(private),
        "--signing-key-id",
        "external-v1",
        "--output",
        str(output),
    ])
    assert external_demo_monitor.main() == 0
    artifact = json.loads(output.read_text())
    claims = verify_ed25519_artifact(
        artifact,
        public,
        label="external monitor fixture",
    )
    assert claims["ok"]
    assert claims["failures"] == []
    assert claims["expected_release"] == release
    assert claims["expected_account_uid"] == "demo-account"
    assert claims["expected_unit"] == "okx-quant-demo-active.service"
    assert claims["soak_epoch_id"] == "epoch-0001"
    for endpoint in claims["endpoints"].values():
        assert endpoint["account_uid"] == "demo-account"
        assert (
            endpoint["deployment_unit"]
            == "okx-quant-demo-active.service"
        )
        assert endpoint["soak_epoch_id"] == "epoch-0001"
    assert set(claims["signals"]) == {
        "host",
        "service",
        "provider",
        "evidence-close",
        "backup",
    }
    assert all(row["ok"] for row in claims["signals"].values())


def test_external_monitor_fails_closed_when_response_identity_is_missing(
    tmp_path,
    monkeypatch,
):
    release = "a" * 40
    config = "b" * 64

    def fake_get(url, **_kwargs):
        if url.endswith("/healthz"):
            return _Response(200, {
                "live": True,
                "release_identity": release,
                "config_identity": config,
                "account_uid": "demo-account",
                "deployment_unit": "okx-quant-demo-active.service",
            })
        if url.endswith("/readyz"):
            return _Response(200, {
                "ready": True,
                "release_identity": release,
                "config_identity": config,
                "account_uid": "wrong-account",
                "deployment_unit": "okx-quant-demo-shadow.service",
                "soak_epoch_id": "wrong-epoch",
            })
        if "/signals/" in url:
            return _signal_response(url, release, config)
        return _Response(200, {
            "code": "0",
            "data": [{"ts": str(int(time.time() * 1000))}],
        })

    monkeypatch.setattr(external_demo_monitor.requests, "get", fake_get)
    monkeypatch.setattr(
        external_demo_monitor.requests,
        "post",
        lambda *_args, **_kwargs: _Response(202, {}),
    )
    private, public = _keys(tmp_path)
    output = tmp_path / "rejected-observation.json"
    monkeypatch.setattr(sys, "argv", [
        "external_demo_monitor.py",
        "--target",
        "demo-active",
        "--health-url",
        "http://127.0.0.1/healthz",
        "--ready-url",
        "http://127.0.0.1/readyz",
        "--allow-loopback-http",
        *_signal_args(),
        "--expected-release",
        release,
        "--expected-config",
        config,
        "--expected-account-uid",
        "demo-account",
        "--expected-unit",
        "okx-quant-demo-active.service",
        "--soak-epoch-id",
        "epoch-0001",
        "--private-key",
        str(private),
        "--signing-key-id",
        "external-v1",
        "--primary-page-url",
        "https://primary.example.test/page",
        "--independent-page-url",
        "https://independent.example.test/page",
        "--output",
        str(output),
    ])

    assert external_demo_monitor.main() == 2
    claims = verify_ed25519_artifact(
        json.loads(output.read_text()),
        public,
        label="external monitor rejected fixture",
    )
    assert not claims["ok"]
    assert claims["failures"] == [
        "HEALTH_SOAK_EPOCH_ID_MISMATCH",
        "READY_ACCOUNT_UID_MISMATCH",
        "READY_DEPLOYMENT_UNIT_MISMATCH",
        "READY_SOAK_EPOCH_ID_MISMATCH",
    ]
    assert claims["endpoints"]["health"]["soak_epoch_id"] == ""
    assert claims["endpoints"]["ready"]["account_uid"] == "wrong-account"
    assert all(row["ingestion_accepted"] for row in claims["deliveries"])


def test_external_monitor_unit_creates_private_state_and_identity():
    project = external_demo_monitor.Path(__file__).resolve().parents[1]
    unit = (
        project
        / "deploy/external-monitor/"
        "okx-quant-demo-external-monitor@.service"
    ).read_text(encoding="utf-8")
    sysusers = (
        project
        / "deploy/sysusers/okx-quant-external-monitor.conf"
    ).read_text(encoding="utf-8")

    assert "User=okxquant-external-monitor" in unit
    assert "Group=okxquant-external-monitor" in unit
    assert "StateDirectory=okx-quant-external-monitor/%i" in unit
    assert "StateDirectoryMode=0700" in unit
    assert (
        "ReadWritePaths=/var/lib/okx-quant-external-monitor/%i"
        in unit
    )
    assert (
        "--incident-state "
        "/var/lib/okx-quant-external-monitor/%i/incidents.json"
        in unit
    )
    for signal in (
        "host",
        "service",
        "provider",
        "evidence-close",
        "backup",
    ):
        assert f"--signal-url {signal}=" in unit
    assert (
        'u okxquant-external-monitor - "OKX Quant External Monitor" '
        "/nonexistent"
    ) in sysusers


def test_external_monitor_incident_id_is_stable_until_recovery(tmp_path):
    state_path = tmp_path / "incidents.json"
    state = external_demo_monitor._load_incident_state(state_path)
    identity = {
        "target": "demo-active",
        "release": "a" * 40,
        "config": "b" * 64,
        "account_uid": "demo-account",
        "unit": "okx-quant-demo-active.service",
        "soak_epoch_id": "epoch-0001",
    }

    state, first_event_id, should_deliver = (
        external_demo_monitor._advance_incident(
            state,
            identity=identity,
            failures=["READY_UNHEALTHY"],
        )
    )
    assert should_deliver
    assert state["generation"] == 1
    external_demo_monitor._save_incident_state(state_path, state)
    assert state_path.stat().st_mode & 0o777 == 0o600

    loaded = external_demo_monitor._load_incident_state(state_path)
    loaded, retry_event_id, should_deliver = (
        external_demo_monitor._advance_incident(
            loaded,
            identity=identity,
            failures=["HEALTH_UNHEALTHY", "READY_UNHEALTHY"],
        )
    )
    assert should_deliver
    assert retry_event_id == first_event_id
    delivered = {**loaded, "delivered": True}
    delivered, sustained_event_id, should_deliver = (
        external_demo_monitor._advance_incident(
            delivered,
            identity=identity,
            failures=["READY_UNHEALTHY"],
        )
    )
    assert sustained_event_id == first_event_id
    assert not should_deliver

    recovered, _healthy_event_id, should_deliver = (
        external_demo_monitor._advance_incident(
            delivered,
            identity=identity,
            failures=[],
        )
    )
    assert not recovered["active"]
    assert not should_deliver
    recurrent, recurrent_event_id, should_deliver = (
        external_demo_monitor._advance_incident(
            recovered,
            identity=identity,
            failures=["READY_UNHEALTHY"],
        )
    )
    assert recurrent["generation"] == 2
    assert recurrent_event_id != first_event_id
    assert should_deliver


def test_external_monitor_incident_state_handles_partial_writes(
    tmp_path,
    monkeypatch,
):
    state_path = tmp_path / "incidents.json"
    state = external_demo_monitor._load_incident_state(state_path)
    state = {**state, "generation": 3}
    real_write = external_demo_monitor.os.write

    def partial_write(descriptor, payload):
        return real_write(descriptor, payload[:7])

    monkeypatch.setattr(
        external_demo_monitor.os,
        "write",
        partial_write,
    )
    external_demo_monitor._save_incident_state(state_path, state)

    assert json.loads(state_path.read_text(encoding="utf-8")) == state


def test_external_monitor_fails_closed_on_stale_backup_deadman(
    tmp_path,
    monkeypatch,
):
    release = "a" * 40
    config = "b" * 64

    def fake_get(url, **_kwargs):
        if url.endswith("/healthz"):
            return _Response(200, {
                "live": True,
                "release_identity": release,
                "config_identity": config,
                "account_uid": "demo-account",
                "deployment_unit": "okx-quant-demo-active.service",
                "soak_epoch_id": "epoch-0001",
            })
        if url.endswith("/readyz"):
            return _Response(200, {
                "ready": True,
                "release_identity": release,
                "config_identity": config,
                "account_uid": "demo-account",
                "deployment_unit": "okx-quant-demo-active.service",
                "soak_epoch_id": "epoch-0001",
            })
        if "/signals/" in url:
            response = _signal_response(url, release, config)
            if url.endswith("/backup"):
                response._payload["observed_at"] = time.time() - 301
            return response
        return _Response(200, {
            "code": "0",
            "data": [{"ts": str(int(time.time() * 1000))}],
        })

    monkeypatch.setattr(external_demo_monitor.requests, "get", fake_get)
    monkeypatch.setattr(
        external_demo_monitor.requests,
        "post",
        lambda *_args, **_kwargs: _Response(202, {}),
    )
    private, public = _keys(tmp_path)
    output = tmp_path / "stale-backup.json"
    monkeypatch.setattr(sys, "argv", [
        "external_demo_monitor.py",
        "--target",
        "demo-active",
        "--health-url",
        "http://127.0.0.1/healthz",
        "--ready-url",
        "http://127.0.0.1/readyz",
        "--allow-loopback-http",
        *_signal_args(),
        "--expected-release",
        release,
        "--expected-config",
        config,
        "--expected-account-uid",
        "demo-account",
        "--expected-unit",
        "okx-quant-demo-active.service",
        "--soak-epoch-id",
        "epoch-0001",
        "--private-key",
        str(private),
        "--signing-key-id",
        "external-v1",
        "--primary-page-url",
        "https://primary.example.test/page",
        "--independent-page-url",
        "https://independent.example.test/page",
        "--output",
        str(output),
    ])
    assert external_demo_monitor.main() == 2
    claims = verify_ed25519_artifact(
        json.loads(output.read_text()),
        public,
        label="external monitor stale backup fixture",
    )
    assert claims["failures"] == ["BACKUP_DEADMAN_MISSING_OR_STALE"]


def test_external_monitor_rejects_non_https_remote_url():
    with pytest.raises(ValueError, match="HTTPS"):
        external_demo_monitor._https_url("http://example.com/healthz")
