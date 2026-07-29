"""Crash/restart tests for the genuine Stage-C test-only boundaries."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import signal
import subprocess
import threading
import time
import types
from contextlib import suppress
from decimal import Decimal
from pathlib import Path

import pytest
import requests

from okx_quant.application.approval import canonical_bytes
from okx_quant.application.demo_probe import DemoProbeSaga
from okx_quant.application.execution import (
    ExecutionCoordinator,
    ExecutionRequest,
)
from okx_quant.application.protection import (
    ExitCoordinator,
    ProtectionManager,
)
from okx_quant.domain.orders import OrderState, SystemMode
from okx_quant.exchange import InstrumentInfo
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.infrastructure.okx.streams import map_order_event
from okx_quant.ops.stage_c_build_provenance import (
    instrument_stage_c_member,
)
from okx_quant.ops.stage_c_native_collectors import NativeAcquisition
from stage_c_test_harness import recovery
from stage_c_test_harness.barriers import (
    BarrierHook,
    BarrierStateStore,
)
from stage_c_test_harness.cli import _load_trader_account_binding
from stage_c_test_harness.pipeline import (
    PIPELINE_PROOF_SCHEMA,
    activate_pipeline_barrier,
    build_pipeline_runtime,
    load_pipeline_proof,
)
from stage_c_test_harness.tls_ack_proxy import (
    TLSAckHoldingProxyController,
    TLSDemoPassthroughController,
    build_tls_ack_holding_server,
)

_INVOCATION_ID = "11111111-1111-1111-1111-111111111111"


def test_trader_account_binding_performs_authenticated_transport_get(
    monkeypatch,
):
    from okx_quant.client.rest import OKXRestClient

    calls = []

    class Session:
        def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            response = requests.Response()
            response.status_code = 200
            response._content = json.dumps({
                "code": "0",
                "msg": "",
                "data": [{
                    "uid": "demo-account",
                    "perm": "read_only,trade",
                }],
            }).encode()
            return response

        def close(self):
            return None

    session = Session()
    monkeypatch.setattr(
        OKXRestClient,
        "_make_session",
        lambda _self: session,
    )
    account, permissions, fingerprint = _load_trader_account_binding(
        {
            "api_key": "stage-c-key",
            "secret_key": "secret",
            "passphrase": "passphrase",
            "timeout": 1,
        },
        expected_account_uid="demo-account",
    )

    assert account["uid"] == "demo-account"
    assert permissions == ("read", "trade")
    assert fingerprint == hashlib.sha256(b"stage-c-key").hexdigest()
    assert len(calls) == 1
    method, url, kwargs = calls[0]
    assert method == "GET"
    assert url == "https://openapi.okx.com/api/v5/account/config"
    assert kwargs["headers"]["OK-ACCESS-KEY"] == "stage-c-key"
    assert kwargs["headers"]["x-simulated-trading"] == "1"


def _challenge(scenario: str) -> dict:
    return {
        "scenario": scenario,
        "challenge_id": "a" * 32,
        "barrier_nonce": "b" * 32,
        "identity": {
            "artifact_sha256": "c" * 64,
            "artifact_build_id": "test-only:pipeline-e2e",
            "test_hooks_present": True,
        },
    }


def _exchange() -> FakeExchange:
    exchange = FakeExchange()
    exchange.set_account_identity("demo-account")
    exchange.set_balance(total=5000, quote_avail=5000)
    exchange.set_ticker(
        "BTC-USDT",
        last=50000,
        bid=49990,
        ask=50010,
    )
    exchange.set_fill_price(50000)
    exchange.set_instrument(InstrumentInfo(
        inst_id="BTC-USDT",
        base_ccy="BTC",
        quote_ccy="USDT",
        lot_size=Decimal("0.00001"),
        min_size=Decimal("0.00001"),
        tick_size=Decimal("0.1"),
    ))
    return exchange


def _saga(database: Path, saga_class=DemoProbeSaga):
    exchange = _exchange()
    journal = SQLiteJournal(database)
    execution = ExecutionCoordinator(exchange, journal)
    protection = ProtectionManager(exchange, journal)
    protection.attach_to(execution)
    saga = saga_class(
        exchange,
        journal,
        execution,
        protection,
        ExitCoordinator(exchange, journal, execution, protection),
        environment="demo",
        shadow_mode=False,
        account_uid="demo-account",
        allowed_instruments=("BTC-USDT",),
    )
    return exchange, journal, saga


def _instrumented_class(relative: str, class_name: str):
    root = Path(__file__).resolve().parents[1]
    raw = (root / relative).read_bytes()
    transformed = instrument_stage_c_member(relative, raw)
    module = types.ModuleType(f"stage_c_e2e_{class_name}")
    module.__file__ = str(root / relative)
    exec(compile(transformed, module.__file__, "exec"), module.__dict__)
    return module.__dict__[class_name]


def _run_buy_boundary(
    database: str,
    probe_id: str,
    state_database: str,
    marker: str,
    proof: str,
) -> None:
    saga_class = _instrumented_class(
        "okx_quant/application/demo_probe.py",
        "DemoProbeSaga",
    )
    _exchange_value, journal, saga = _saga(Path(database), saga_class)
    challenge = _challenge("barrier-buy-intent-before-post")
    activate_pipeline_barrier(build_pipeline_runtime(
        challenge=challenge,
        state_database=Path(state_database),
        marker_output=Path(marker),
        proof_output=Path(proof),
        systemd_invocation_id=_INVOCATION_ID,
    ))
    saga.advance(probe_id, owner="crashed-worker", lease_ttl_s=1)
    journal.close()


def _run_fill_boundary(
    database: str,
    raw_event: dict,
    state_database: str,
    marker: str,
    proof: str,
) -> None:
    service_class = _instrumented_class(
        "okx_quant/infrastructure/okx/streams.py",
        "PrivateStreamService",
    )
    exchange = _exchange()
    journal = SQLiteJournal(Path(database))
    coordinator = ExecutionCoordinator(exchange, journal)
    service = object.__new__(service_class)
    service.coordinator = coordinator
    service.journal = journal
    service._generations = {"private": 1, "business": 1}
    service._event_sequence = 1
    service._event_lock = threading.RLock()
    challenge = _challenge("barrier-fill-before-projection")
    activate_pipeline_barrier(build_pipeline_runtime(
        challenge=challenge,
        state_database=Path(state_database),
        marker_output=Path(marker),
        proof_output=Path(proof),
        systemd_invocation_id=_INVOCATION_ID,
    ))
    service._project_orders([raw_event])
    journal.close()


def _wait_for(path: Path, process, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        if not process.is_alive():
            raise AssertionError(f"barrier process exited: {process.exitcode}")
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path}")


def _kill(process) -> None:
    os.kill(process.pid, signal.SIGKILL)
    process.join(5)
    assert process.exitcode == -signal.SIGKILL


def test_buy_submitting_commit_crash_restarts_without_first_post(tmp_path):
    database = tmp_path / "buy.sqlite3"
    exchange, journal, saga = _saga(database)
    journal.set_mode(SystemMode.READY)
    row = saga.prepare(
        inst_id="BTC-USDT",
        nominal_usdt=Decimal("5"),
        slot=1,
        probe_id="d" * 32,
    )
    journal.close()
    marker = tmp_path / "buy-marker.json"
    proof = tmp_path / "buy-proof.json"
    process = multiprocessing.get_context("fork").Process(
        target=_run_buy_boundary,
        args=(
            str(database),
            row["probe_id"],
            str(tmp_path / "buy-marker.sqlite3"),
            str(marker),
            str(proof),
        ),
    )
    process.start()
    _wait_for(marker, process)
    _kill(process)

    marker_value = json.loads(marker.read_bytes())
    proof_value = load_pipeline_proof(proof, marker=marker_value)
    assert proof_value["facts"]["intent_state"] == "BUY_SUBMITTING"
    assert proof_value["facts"]["order_intent_count"] == 0
    assert proof_value["facts"]["socket_write_count"] == 0

    time.sleep(1.05)
    recovered_exchange, recovered_journal, recovered = _saga(database)
    result = recovered.reclaim_once(owner="restart-reclaimer")[0]
    assert result["state"] == "REJECTED"
    assert recovered_exchange.orders == []
    assert recovered_journal.find_intent(
        cl_ord_id=row["buy_cl_ord_id"]
    ) is None
    recovered_journal.close()


def test_fill_observation_crash_restarts_with_one_projection_and_protection(
    tmp_path,
):
    database = tmp_path / "fill.sqlite3"
    exchange = _exchange()
    journal = SQLiteJournal(database)
    journal.set_mode(SystemMode.READY)
    coordinator = ExecutionCoordinator(exchange, journal)
    exchange.queue_order_outcome(state="live")
    intent = coordinator.submit(ExecutionRequest(
        inst_id="BTC-USDT",
        side="buy",
        base_qty=Decimal("0.001"),
        stop_loss=Decimal("49000"),
        take_profit=Decimal("52000"),
    ))
    assert intent.state is OrderState.LIVE
    journal.close()
    raw_event = {
        "instId": "BTC-USDT",
        "side": "buy",
        "ordId": intent.exchange_ord_id,
        "clOrdId": intent.cl_ord_id,
        "state": "filled",
        "sz": "0.001",
        "accFillSz": "0.001",
        "avgPx": "50000",
        "fee": "-0.000001",
        "feeCcy": "BTC",
        "tradeId": "trade-stage-c-fill",
        "uTime": str(int(time.time() * 1000)),
    }
    marker = tmp_path / "fill-marker.json"
    proof = tmp_path / "fill-proof.json"
    process = multiprocessing.get_context("fork").Process(
        target=_run_fill_boundary,
        args=(
            str(database),
            raw_event,
            str(tmp_path / "fill-marker.sqlite3"),
            str(marker),
            str(proof),
        ),
    )
    process.start()
    _wait_for(marker, process)
    _kill(process)

    marker_value = json.loads(marker.read_bytes())
    proof_value = load_pipeline_proof(proof, marker=marker_value)
    assert proof_value["facts"]["projection_apply_count"] == 0
    check = SQLiteJournal(database)
    assert check.get_position("BTC-USDT") is None
    check.close()

    recovered_exchange = _exchange()
    recovered_journal = SQLiteJournal(database)
    recovered = ExecutionCoordinator(
        recovered_exchange,
        recovered_journal,
    )
    protection = ProtectionManager(recovered_exchange, recovered_journal)
    protection.attach_to(recovered)
    update = map_order_event(raw_event)
    first, delta = recovered.process_exchange_update(update)
    second, duplicate_delta = recovered.process_exchange_update(update)
    assert first.state is OrderState.FILLED
    assert second.state is OrderState.FILLED
    assert delta == Decimal("0.001")
    assert duplicate_delta == 0
    position = recovered_journal.get_position("BTC-USDT")
    assert Decimal(position["base_qty"]) == Decimal("0.000999")
    assert recovered_journal.has_active_protection(
        "BTC-USDT",
        Decimal("0.00099"),
    )
    recovered_journal.close()


def test_recovery_producer_acquires_native_sqlite_systemd_and_okx(
    tmp_path,
    monkeypatch,
):
    database = tmp_path / "recovery.sqlite3"
    journal = SQLiteJournal(database)
    journal.set_mode(SystemMode.HALTED)
    journal.close()
    challenge = _challenge("barrier-buy-intent-before-post")
    proof = {
        "schema": PIPELINE_PROOF_SCHEMA,
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "barrier_nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "boundary": "buy-intent-before-post",
        "pid": os.getpid(),
        "facts": {
            "probe_id": "d" * 32,
            "cl_ord_id": "probeRecovery1",
        },
    }
    proof_path = tmp_path / "recovery-proof.json"
    proof_path.write_bytes(canonical_bytes(proof) + b"\n")
    marker = {
        "schema": "okx-quant.stage-c-barrier-marker/v2",
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "barrier": "buy-intent-before-post",
        "pid": os.getpid(),
        "systemd_invocation_id": _INVOCATION_ID,
        "reached_at": "2026-07-28T00:00:00+00:00",
        "monotonic_ns": 1,
        "boundary_proof_sha256": hashlib.sha256(
            canonical_bytes(proof)
        ).hexdigest(),
        "marker_sha256": "0" * 64,
    }
    marker_path = tmp_path / "recovery-marker.json"
    marker_path.write_bytes(canonical_bytes(marker) + b"\n")
    observed_headers = []

    def collect_http(**kwargs):
        observed_headers.append(kwargs["headers"])
        return NativeAcquisition(
            source="okx_collector",
            operation=f"{kwargs['method']} {kwargs['url']}",
            request_bytes=b"native-okx-request",
            response_bytes=b'HTTP/1.1 200\r\n\r\n{"code":"0","data":[]}',
            returncode=0,
        )

    monkeypatch.setattr(recovery, "collect_http_native", collect_http)
    monkeypatch.setattr(
        recovery,
        "collect_systemd_native",
        lambda **_kwargs: NativeAcquisition(
            source="systemd_collector",
            operation="show-runtime",
            request_bytes=b"systemd request",
            response_bytes=b"MainPID=123\n",
            returncode=0,
        ),
    )
    bundle = recovery.collect_native_recovery_bundle(
        challenge=challenge,
        marker_path=marker_path,
        proof_path=proof_path,
        database=database,
        runtime_unit="okx-quant-stage-c-test-only.service",
        api_key="demo-key",
        secret_key="demo-secret",
        passphrase="demo-passphrase",
    )
    assert bundle["schema"] == recovery.NATIVE_RECOVERY_SCHEMA
    assert bundle["systemd"]["source"] == "systemd_collector"
    assert len(bundle["sqlite_snapshot"]) == 10
    assert len(bundle["okx_demo_https"]) == 6
    assert len(bundle["okx_stability_https"]) == 6
    assert bundle["journal_readiness_artifact"] is None
    assert all(
        headers["x-simulated-trading"] == "1"
        for headers in observed_headers
    )


class _UpstreamResponse:
    status_code = 200
    headers = {"content-type": "application/json"}
    content = b'{"code":"0","data":[{"ordId":"upstream-1"}]}'


class _UpstreamSession:
    calls: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return _UpstreamResponse()


class _PassthroughSession(_UpstreamSession):
    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return _UpstreamResponse()


def test_recovery_passthrough_is_demo_only_and_never_holds_ack():
    controller = TLSDemoPassthroughController(
        session_factory=_PassthroughSession,
    )
    _PassthroughSession.calls.clear()
    status, _headers, body = controller.forward(
        method="GET",
        target="/api/v5/account/balance?ccy=USDT",
        headers=[("x-simulated-trading", "1")],
        body=b"",
    )
    assert status == 200
    assert body == _UpstreamResponse.content
    assert len(_PassthroughSession.calls) == 1
    with pytest.raises(ValueError, match="非法"):
        controller.forward(
            method="POST",
            target="/api/v5/asset/withdrawal",
            headers=[("x-simulated-trading", "1")],
            body=b"{}",
        )
    with pytest.raises(ValueError, match="非法"):
        controller.forward(
            method="GET",
            target="/api/v5/account/balance",
            headers=[],
            body=b"",
        )


def test_tls_proxy_rejects_live_or_ambiguous_requests_before_upstream(
    tmp_path,
):
    challenge = _challenge("barrier-post-before-ack")
    hook = BarrierHook(
        challenge=challenge,
        state_store=BarrierStateStore(tmp_path / "negative.sqlite3"),
        marker_output=tmp_path / "negative-marker.json",
        systemd_invocation_id=_INVOCATION_ID,
        pid=os.getpid(),
    )
    controller = TLSAckHoldingProxyController(
        challenge=challenge,
        hook=hook,
        proof_output=tmp_path / "negative-proof.json",
        upstream_base_url="https://openapi.okx.com",
        target_pid=os.getpid(),
        session_factory=_UpstreamSession,
        wait_for_kill=lambda: None,
    )
    _UpstreamSession.calls.clear()
    valid_body = (
        b'{"instId":"BTC-USDT","tdMode":"cash","side":"buy",'
        b'"ordType":"market","sz":"0.0001","tgtCcy":"base_ccy",'
        b'"clOrdId":"stagecProxyBuy1"}'
    )
    with pytest.raises(ValueError, match="模拟盘"):
        controller.receive_and_hold(
            path="/api/v5/trade/order",
            headers=[("Content-Length", str(len(valid_body)))],
            body=valid_body,
        )
    duplicate = valid_body[:-1] + b',"side":"buy"}'
    with pytest.raises(ValueError, match="重复"):
        controller.receive_and_hold(
            path="/api/v5/trade/order",
            headers=[
                ("Content-Length", str(len(duplicate))),
                ("x-simulated-trading", "1"),
            ],
            body=duplicate,
        )
    with pytest.raises(ValueError, match="未绑定"):
        TLSAckHoldingProxyController(
            challenge=challenge,
            hook=hook,
            proof_output=tmp_path / "insecure-proof.json",
            upstream_base_url="https://openapi.okx.com",
            target_pid=os.getpid(),
            verify_upstream=False,
        )
    assert _UpstreamSession.calls == []
    assert not (tmp_path / "negative-proof.json").exists()


def _tls_client(connection, certificate: str) -> None:
    url = connection.recv()
    with suppress(requests.RequestException):
        requests.post(
            url,
            json={
                "instId": "BTC-USDT",
                "tdMode": "cash",
                "side": "buy",
                "ordType": "market",
                "sz": "0.0001",
                "tgtCcy": "base_ccy",
                "clOrdId": "stagecProxyBuy1",
            },
            headers={"x-simulated-trading": "1"},
            verify=certificate,
            timeout=30,
        )


@pytest.mark.skipif(
    not Path("/usr/bin/openssl").exists()
    and not Path("/opt/homebrew/bin/openssl").exists(),
    reason="openssl required for local TLS certificate",
)
def test_isolated_tls_proxy_receives_full_post_and_withholds_ack(tmp_path):
    openssl = (
        Path("/usr/bin/openssl")
        if Path("/usr/bin/openssl").exists()
        else Path("/opt/homebrew/bin/openssl")
    )
    certificate = tmp_path / "tls-cert.pem"
    private_key = tmp_path / "tls-key.pem"
    subprocess.run(
        [
            str(openssl),
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    parent, child = multiprocessing.get_context("fork").Pipe()
    client = multiprocessing.get_context("fork").Process(
        target=_tls_client,
        args=(child, str(certificate)),
    )
    client.start()
    challenge = _challenge("barrier-post-before-ack")
    marker = tmp_path / "proxy-marker.json"
    proof = tmp_path / "proxy-proof.json"
    hook = BarrierHook(
        challenge=challenge,
        state_store=BarrierStateStore(tmp_path / "proxy-marker.sqlite3"),
        marker_output=marker,
        systemd_invocation_id=_INVOCATION_ID,
        pid=client.pid,
    )
    release = threading.Event()
    controller = TLSAckHoldingProxyController(
        challenge=challenge,
        hook=hook,
        proof_output=proof,
        upstream_base_url="https://openapi.okx.com",
        target_pid=client.pid,
        session_factory=_UpstreamSession,
        wait_for_kill=lambda: release.wait(10),
    )
    _UpstreamSession.calls.clear()
    try:
        server = build_tls_ack_holding_server(
            host="127.0.0.1",
            port=0,
            certificate=certificate,
            private_key=private_key,
            controller=controller,
        )
    except PermissionError:
        _kill(client)
        pytest.skip("sandbox forbids loopback socket bind")
    server_thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    server_thread.start()
    parent.send(f"https://127.0.0.1:{server.server_port}/api/v5/trade/order")
    _wait_for(marker, client)
    assert client.is_alive()
    _kill(client)
    marker_value = json.loads(marker.read_bytes())
    proof_value = load_pipeline_proof(proof, marker=marker_value)
    facts = proof_value["facts"]
    assert facts["request_fully_received"] is True
    assert facts["upstream_ack_observed_by_proxy"] is True
    assert facts["ack_delivery_started_to_trader"] is False
    assert len(_UpstreamSession.calls) == 1
    release.set()
    server.shutdown()
    server.server_close()
