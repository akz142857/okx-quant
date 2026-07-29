from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from okx_quant.infrastructure.evidence import ed25519_public_key_fingerprint
from okx_quant.ops import stage_c_chaos_protocol as protocol
from okx_quant.ops.stage_c_exact_release_drivers import (
    EXACT_RELEASE_SCENARIOS,
    SCENARIO_ACTION_ALLOWLIST,
    TimedNativeAcquisition,
    action_allowed,
    attach_live_acquisition_attestation,
    build_live_acquisition_envelope,
    build_live_signed_native_event,
    derive_live_native_facts,
    verify_live_acquisition_attestation,
)
from okx_quant.ops.stage_c_external_executors import stable_client_order_id
from okx_quant.ops.stage_c_native_collectors import (
    NativeAcquisition,
    collect_sqlite_snapshot_native,
)


def _workload() -> dict:
    return {
        "host_id": "stage-c-host-1",
        "boot_id": "12345678-1234-4234-9234-123456789abc",
        "systemd_invocation_id": (
            "abcdefab-cdef-4abc-8def-abcdefabcdef"
        ),
        "pid": 4321,
        "uid": 2101,
        "cgroup": "/system.slice/okx-stage-c-driver.service",
        "executable_sha256": "1" * 64,
        "parser_manifest_sha256": protocol.PARSER_MANIFEST_SHA256,
        "iam_principal_arn": (
            "arn:aws:sts::123456789012:"
            "assumed-role/stage-c-driver/session-1"
        ),
        "iam_account_id": "123456789012",
        "iam_session_id": "session-1",
    }


def _key_pair(tmp_path, name: str):
    private = tmp_path / f"{name}-private.pem"
    public = tmp_path / f"{name}-public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", private],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", private, "-pubout", "-out", public],
        check=True,
        capture_output=True,
    )
    return private, public


def _challenge(now: datetime) -> dict:
    return {
        "challenge_id": "d" * 32,
        "not_before": int((now - timedelta(seconds=5)).timestamp()),
        "expires_at": int((now + timedelta(seconds=30)).timestamp()),
        "identity": {"account_uid": "1234567890123456"},
        "okx_observer_bindings": {
            "observer_api_key_fingerprint": "a" * 64,
            "tls_certificate_sha256": "b" * 64,
            "tls_spki_sha256": "c" * 64,
        },
        "driver_contract_sha256": "2" * 64,
        "capability_attestation_sha256": "3" * 64,
        "workloads": {"fault_driver": _workload()},
    }


def _timed(
    acquisition: NativeAcquisition,
    now: datetime,
) -> TimedNativeAcquisition:
    return TimedNativeAcquisition(
        acquisition=acquisition,
        requested_at=(now - timedelta(milliseconds=20)).isoformat(),
        response_completed_at=(
            now - timedelta(milliseconds=10)
        ).isoformat(),
        requested_monotonic_ns=1_000_000_000,
        response_completed_monotonic_ns=1_010_000_000,
    )


def _systemd_acquisition(*, pid: int = 4321) -> NativeAcquisition:
    return NativeAcquisition(
        source="systemd_collector",
        operation="show-runtime",
        request_bytes=(
            b'{"action":"show-runtime",'
            b'"unit":"okx-stage-c-driver.service"}'
        ),
        response_bytes=(
            "Id=okx-stage-c-driver.service\n"
            "ActiveState=active\n"
            "SubState=running\n"
            "InvocationID=abcdefabcdef4abc8defabcdefabcdef\n"
            f"MainPID={pid}\n"
            "ControlGroup=/system.slice/okx-stage-c-driver.service\n"
            "ExecMainStartTimestampMonotonic=1000000\n"
        ).encode(),
        returncode=0,
    )


def _replace_descriptor_payload(descriptor: dict, raw: bytes) -> None:
    descriptor["payload_base64"] = base64.b64encode(raw).decode()
    descriptor["bytes"] = len(raw)
    descriptor["sha256"] = hashlib.sha256(raw).hexdigest()


def _http_acquisition(
    *,
    operation: str,
    target: str,
    data: list[dict],
    host: str = "openapi.okx.com",
    api_key_fingerprint: str = "a" * 64,
) -> NativeAcquisition:
    request = (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Stage-C-API-Key-Fingerprint: {api_key_fingerprint}\r\n"
        "X-Simulated-Trading: 1\r\n"
        "\r\n"
    ).encode()
    response_headers = {
        "ok-trace-id": "trace-1",
        "x-stage-c-peer-address": "203.0.113.10",
        "x-stage-c-peer-port": "443",
        "x-stage-c-tls-version": "TLSv1.3",
        "x-stage-c-tls-cipher": "TLS_AES_256_GCM_SHA384",
        "x-stage-c-peer-cert-sha256": "b" * 64,
        "x-stage-c-peer-spki-sha256": "c" * 64,
    }
    body = json.dumps(
        {"code": "0", "msg": "", "data": data},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    response = (
        "HTTP/1.1 200\r\n"
        + "".join(
            f"{key}: {value}\r\n"
            for key, value in response_headers.items()
        )
        + "\r\n"
    ).encode() + body
    return NativeAcquisition(
        source="okx_collector",
        operation=operation,
        request_bytes=request,
        response_bytes=response,
        returncode=0,
    )


def test_exact_release_inventory_is_parser_ready_but_not_implemented():
    assert set(SCENARIO_ACTION_ALLOWLIST) == set(EXACT_RELEASE_SCENARIOS)
    assert len(EXACT_RELEASE_SCENARIOS) == 10
    assert protocol.implemented_stage_c_scenarios() == frozenset()
    assert "facts" not in inspect.signature(
        build_live_acquisition_envelope
    ).parameters
    assert "facts" not in inspect.signature(
        build_live_signed_native_event
    ).parameters


def test_action_allowlist_is_exact_without_prefix_or_argv_fallback():
    assert action_allowed(
        "oco-active-process-death",
        "systemd-sigkill",
    )
    assert not action_allowed(
        "oco-active-process-death",
        "systemd-sigkill --kill-whom=all",
    )
    assert not action_allowed(
        "oco-active-process-death",
        "systemd-restart",
    )
    assert not action_allowed("unknown", "systemd-sigkill")


def test_live_systemd_parser_binds_pid_invocation_and_freshness():
    now = datetime.now(UTC)
    envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="run.completed",
        acquisitions=[_timed(_systemd_acquisition(), now)],
    )
    result = derive_live_native_facts(
        envelope,
        scenario="external-fill",
        kind="run.completed",
        challenge=_challenge(now),
        workload=_workload(),
        observed_at=now.isoformat(),
    )
    assert result == {"outcome": "completed"}

    wrong_pid = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="run.completed",
        acquisitions=[
            _timed(_systemd_acquisition(pid=9999), now),
        ],
    )
    with pytest.raises(ValueError, match="frozen workload"):
        derive_live_native_facts(
            wrong_pid,
            scenario="external-fill",
            kind="run.completed",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )

    stale = copy.deepcopy(envelope)
    stale["requested_at"] = (
        now - timedelta(minutes=5)
    ).isoformat()
    stale["response_completed_at"] = (
        now - timedelta(minutes=5) + timedelta(milliseconds=10)
    ).isoformat()
    with pytest.raises(ValueError, match="freshness"):
        derive_live_native_facts(
            stale,
            scenario="external-fill",
            kind="run.completed",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_live_envelope_rejects_wrong_source_and_operation():
    now = datetime.now(UTC)
    wrong_source = NativeAcquisition(
        source="journal_collector",
        operation="show-runtime",
        request_bytes=b"request",
        response_bytes=b"response",
        returncode=0,
    )
    with pytest.raises(ValueError, match="source"):
        build_live_acquisition_envelope(
            scenario="external-fill",
            kind="run.completed",
            acquisitions=[_timed(wrong_source, now)],
        )

    envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="run.completed",
        acquisitions=[_timed(_systemd_acquisition(), now)],
    )
    envelope["acquisitions"][0]["operation"] = "show-after-kill"
    with pytest.raises(ValueError, match="allow-list"):
        derive_live_native_facts(
            envelope,
            scenario="external-fill",
            kind="run.completed",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_live_acquisition_attestation_separates_acquirer_and_signer(
    tmp_path,
):
    now = datetime.now(UTC)
    private, public = _key_pair(tmp_path, "systemd-acquirer")
    wrong_private, wrong_public = _key_pair(tmp_path, "wrong-acquirer")
    acquirer_workload = {
        **_workload(),
        "pid": 5321,
        "uid": 2201,
        "systemd_invocation_id": (
            "12345678-1234-4234-9234-123456789abc"
        ),
        "cgroup": (
            "/system.slice/okx-stage-c-systemd-acquirer.service"
        ),
        "iam_session_id": "systemd-acquirer-session",
    }
    challenge = _challenge(now) | {
        "source_key_fingerprints": {
            "systemd_collector_acquirer": (
                ed25519_public_key_fingerprint(public)
            )
        },
        "workloads": {
            "fault_driver": _workload(),
            "systemd_collector_acquirer": acquirer_workload,
        },
    }
    envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="run.completed",
        acquisitions=[_timed(_systemd_acquisition(), now)],
    )
    attested = attach_live_acquisition_attestation(
        scenario="external-fill",
        kind="run.completed",
        challenge=challenge,
        envelope=envelope,
        acquirer_private_key=private,
    )
    assert verify_live_acquisition_attestation(
        scenario="external-fill",
        kind="run.completed",
        challenge=challenge,
        envelope=attested,
        acquirer_public_key=public,
    ) == envelope

    tampered = copy.deepcopy(attested)
    tampered["response_completed_at"] = (
        now + timedelta(milliseconds=1)
    ).isoformat()
    with pytest.raises(ValueError, match="bytes/workload"):
        verify_live_acquisition_attestation(
            scenario="external-fill",
            kind="run.completed",
            challenge=challenge,
            envelope=tampered,
            acquirer_public_key=public,
        )
    with pytest.raises(ValueError, match="公钥|signature|签名"):
        verify_live_acquisition_attestation(
            scenario="external-fill",
            kind="run.completed",
            challenge=challenge,
            envelope=attested,
            acquirer_public_key=wrong_public,
        )
    with pytest.raises(ValueError, match="private key"):
        attach_live_acquisition_attestation(
            scenario="external-fill",
            kind="run.completed",
            challenge=challenge,
            envelope=envelope,
            acquirer_private_key=wrong_private,
        )


def test_sqlite_snapshot_rows_are_recomputed_from_raw_database(tmp_path):
    database = tmp_path / "journal.sqlite"
    connection = sqlite3.connect(database)
    connection.executescript(
        "CREATE TABLE probe_runs("
        "probe_id TEXT, duplicate_buy_count INTEGER);"
        "CREATE TABLE order_intents("
        "intent_id TEXT, decision_id TEXT, side TEXT,"
        "exchange_ord_id TEXT);"
    )
    connection.commit()
    connection.close()
    database.chmod(0o600)
    acquisitions = collect_sqlite_snapshot_native(
        database=database,
        query_requests=(("duplicate-buy-audit", ()),),
    )
    now = datetime.now(UTC)
    envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="journal.duplicate_buy_audit",
        acquisitions=[
            _timed(
                acquisitions[("duplicate-buy-audit", ())],
                now,
            )
        ],
    )
    assert derive_live_native_facts(
        envelope,
        scenario="external-fill",
        kind="journal.duplicate_buy_audit",
        challenge=_challenge(now),
        workload=_workload(),
        observed_at=now.isoformat(),
    ) == {"count": 0, "intent_ids": []}

    forged = copy.deepcopy(envelope)
    descriptor = forged["acquisitions"][0]["response"]
    response = json.loads(
        base64.b64decode(descriptor["payload_base64"])
    )
    response["results"][0]["rows"] = [["forged-intent"]]
    response_raw = json.dumps(
        response,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    _replace_descriptor_payload(descriptor, response_raw)
    request_descriptor = forged["acquisitions"][0]["request"]
    request = json.loads(
        base64.b64decode(request_descriptor["payload_base64"])
    )
    request["snapshot_response_sha256"] = hashlib.sha256(
        response_raw
    ).hexdigest()
    request_raw = json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    _replace_descriptor_payload(request_descriptor, request_raw)
    with pytest.raises(ValueError, match="无法从 snapshot bytes 重算"):
        derive_live_native_facts(
            forged,
            scenario="external-fill",
            kind="journal.duplicate_buy_audit",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_protection_ownership_is_derived_from_unique_journal_join(tmp_path):
    database = tmp_path / "ownership.sqlite"
    connection = sqlite3.connect(database)
    connection.executescript(
        "CREATE TABLE order_intents("
        "intent_id TEXT PRIMARY KEY, cl_ord_id TEXT, exchange_ord_id TEXT, "
        "inst_id TEXT, side TEXT);"
        "CREATE TABLE protective_orders("
        "protection_id TEXT PRIMARY KEY, parent_intent_id TEXT, "
        "algo_cl_ord_id TEXT, exchange_algo_id TEXT, protected_qty TEXT, "
        "state TEXT, updated_at REAL);"
    )
    connection.execute(
        "INSERT INTO order_intents VALUES(?,?,?,?,?)",
        ("intent-1", "owned-cl", "owned-order", "BTC-USDT", "buy"),
    )
    connection.execute(
        "INSERT INTO protective_orders VALUES(?,?,?,?,?,?,?)",
        (
            "protection-1",
            "intent-1",
            "owned-algo-client",
            "owned-algo",
            "0.01",
            "active",
            123.0,
        ),
    )
    connection.commit()
    connection.close()
    database.chmod(0o600)
    locator = ("owned-cl", "owned-algo-client", "owned-algo")
    acquisitions = collect_sqlite_snapshot_native(
        database=database,
        query_requests=(("stage-c-protection-ownership", locator),),
    )
    now = datetime.now(UTC)
    envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="journal.protection_ownership",
        acquisitions=[
            _timed(
                acquisitions[("stage-c-protection-ownership", locator)],
                now,
            )
        ],
    )
    result = derive_live_native_facts(
        envelope,
        scenario="external-fill",
        kind="journal.protection_ownership",
        challenge=_challenge(now),
        workload=_workload(),
        observed_at=now.isoformat(),
    )
    assert result["parent_ord_id"] == "owned-order"
    assert result["parent_cl_ord_id"] == "owned-cl"
    assert result["algo_id"] == "owned-algo"
    assert result["algo_cl_ord_id"] == "owned-algo-client"
    assert len(result["snapshot_sha256"]) == 64

    connection = sqlite3.connect(database)
    connection.execute(
        "INSERT INTO protective_orders VALUES(?,?,?,?,?,?,?)",
        (
            "protection-duplicate",
            "intent-1",
            "owned-algo-client",
            "owned-algo",
            "0.01",
            "active",
            124.0,
        ),
    )
    connection.commit()
    connection.close()
    duplicate = collect_sqlite_snapshot_native(
        database=database,
        query_requests=(("stage-c-protection-ownership", locator),),
    )
    duplicate_envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="journal.protection_ownership",
        acquisitions=[
            _timed(
                duplicate[("stage-c-protection-ownership", locator)],
                now,
            )
        ],
    )
    with pytest.raises(ValueError, match="恰好一行"):
        derive_live_native_facts(
            duplicate_envelope,
            scenario="external-fill",
            kind="journal.protection_ownership",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_raw_descriptor_tamper_is_rejected_before_adapter():
    now = datetime.now(UTC)
    envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="run.completed",
        acquisitions=[_timed(_systemd_acquisition(), now)],
    )
    descriptor = envelope["acquisitions"][0]["response"]
    raw = bytearray(base64.b64decode(descriptor["payload_base64"]))
    raw[-2] ^= 1
    descriptor["payload_base64"] = base64.b64encode(raw).decode()
    with pytest.raises(ValueError, match="bytes/hash"):
        derive_live_native_facts(
            envelope,
            scenario="external-fill",
            kind="run.completed",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_okx_adapter_rejects_wrong_host_path_and_account_uid():
    now = datetime.now(UTC)
    pending = _http_acquisition(
        operation="pending-orders",
        target=(
            "/api/v5/trade/orders-pending?instId=BTC-USDT"
            "&instType=SPOT"
        ),
        data=[],
    )
    account = _http_acquisition(
        operation="account-config",
        target="/api/v5/account/config",
        data=[{"uid": "1234567890123456"}],
    )
    envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="exchange.pending_orders",
        acquisitions=[_timed(pending, now), _timed(account, now)],
    )
    assert derive_live_native_facts(
        envelope,
        scenario="external-fill",
        kind="exchange.pending_orders",
        challenge=_challenge(now),
        workload=_workload(),
        observed_at=now.isoformat(),
    ) == {"order_ids": []}

    wrong_host = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="exchange.pending_orders",
        acquisitions=[
            _timed(
                _http_acquisition(
                    operation="pending-orders",
                    target=(
                        "/api/v5/trade/orders-pending?instId=BTC-USDT"
                        "&instType=SPOT"
                    ),
                    data=[],
                    host="attacker.example",
                ),
                now,
            ),
            _timed(account, now),
        ],
    )
    with pytest.raises(ValueError, match="TLS peer"):
        derive_live_native_facts(
            wrong_host,
            scenario="external-fill",
            kind="exchange.pending_orders",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )

    wrong_path = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="exchange.pending_orders",
        acquisitions=[
            _timed(
                _http_acquisition(
                    operation="pending-orders",
                    target="/api/v5/account/balance",
                    data=[],
                ),
                now,
            ),
            _timed(account, now),
        ],
    )
    with pytest.raises(ValueError, match="request 未精确绑定"):
        derive_live_native_facts(
            wrong_path,
            scenario="external-fill",
            kind="exchange.pending_orders",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )

    wrong_account = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="exchange.pending_orders",
        acquisitions=[
            _timed(pending, now),
            _timed(
                _http_acquisition(
                    operation="account-config",
                    target="/api/v5/account/config",
                    data=[{"uid": "9999999999999999"}],
                ),
                now,
            ),
        ],
    )
    with pytest.raises(ValueError, match="account UID"):
        derive_live_native_facts(
            wrong_account,
            scenario="external-fill",
            kind="exchange.pending_orders",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_external_fill_filters_foreign_page_rows_by_exact_order_locator():
    now = datetime.now(UTC)
    challenge = _challenge(now)
    cl_ord_id = stable_client_order_id(
        scenario="external-fill",
        challenge_id=challenge["challenge_id"],
        purpose="fault",
    )
    order = _http_acquisition(
        operation="order",
        target=(
            "/api/v5/trade/order?clOrdId="
            f"{cl_ord_id}&instId=BTC-USDT"
        ),
        data=[{
            "ordId": "owned-order",
            "clOrdId": cl_ord_id,
            "instId": "BTC-USDT",
            "side": "buy",
            "state": "filled",
            "accFillSz": "0.01001",
            "fee": "-0.00001",
            "feeCcy": "BTC",
        }],
    )
    fills = _http_acquisition(
        operation="fills-history",
        target=(
            "/api/v5/trade/fills-history?instId=BTC-USDT"
            "&instType=SPOT&limit=100&ordId=owned-order"
        ),
        data=[
            {
                "ordId": "foreign-order",
                "clOrdId": "foreign",
                "instId": "BTC-USDT",
                "tradeId": "foreign-trade",
                "side": "buy",
                "fillSz": "9",
            },
            {
                "ordId": "owned-order",
                "clOrdId": cl_ord_id,
                "instId": "BTC-USDT",
                "tradeId": "owned-trade",
                "side": "buy",
                "fillSz": "0.006",
            },
            {
                "ordId": "owned-order",
                "clOrdId": cl_ord_id,
                "instId": "BTC-USDT",
                "tradeId": "owned-trade-2",
                "side": "buy",
                "fillSz": "0.00401",
            },
        ],
    )
    account = _http_acquisition(
        operation="account-config",
        target="/api/v5/account/config",
        data=[{"uid": "1234567890123456"}],
    )
    envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="exchange.fill.external",
        acquisitions=[
            _timed(order, now),
            _timed(fills, now),
            _timed(account, now),
        ],
    )
    assert derive_live_native_facts(
        envelope,
        scenario="external-fill",
        kind="exchange.fill.external",
        challenge=challenge,
        workload=_workload(),
        observed_at=now.isoformat(),
        ) == {
            "ord_id": "owned-order",
            "cl_ord_id": cl_ord_id,
            "inst_id": "BTC-USDT",
        "trade_ids": ["owned-trade", "owned-trade-2"],
        "side": "buy",
        "qty": "0.01000",
        "origin": "external",
    }

    wrong_locator = copy.deepcopy(envelope)
    request_descriptor = wrong_locator["acquisitions"][1]["request"]
    raw = base64.b64decode(request_descriptor["payload_base64"])
    raw = raw.replace(b"ordId=owned-order", b"ordId=foreign-order")
    _replace_descriptor_payload(request_descriptor, raw)
    with pytest.raises(ValueError, match="query locator"):
        derive_live_native_facts(
            wrong_locator,
            scenario="external-fill",
            kind="exchange.fill.external",
            challenge=challenge,
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_external_pending_requires_exact_stable_clordid_not_prefix_only():
    now = datetime.now(UTC)
    challenge = _challenge(now)
    expected = stable_client_order_id(
        scenario="external-pending-buy",
        challenge_id=challenge["challenge_id"],
        purpose="fault",
    )
    prefix_collision = expected[:-1] + ("0" if expected[-1] != "0" else "1")
    order = _http_acquisition(
        operation="order",
        target=(
            "/api/v5/trade/order?clOrdId="
            f"{prefix_collision}&instId=BTC-USDT"
        ),
        data=[{
            "ordId": "foreign-order",
            "clOrdId": prefix_collision,
            "instId": "BTC-USDT",
            "side": "buy",
            "state": "live",
        }],
    )
    account = _http_acquisition(
        operation="account-config",
        target="/api/v5/account/config",
        data=[{"uid": "1234567890123456"}],
    )
    envelope = build_live_acquisition_envelope(
        scenario="external-pending-buy",
        kind="exchange.order.external_pending",
        acquisitions=[_timed(order, now), _timed(account, now)],
    )
    with pytest.raises(ValueError, match="exact challenge clOrdId"):
        derive_live_native_facts(
            envelope,
            scenario="external-pending-buy",
            kind="exchange.order.external_pending",
            challenge=challenge,
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_external_protection_filters_algo_page_and_binds_owned_order():
    now = datetime.now(UTC)
    challenge = _challenge(now)
    cl_ord_id = stable_client_order_id(
        scenario="external-fill",
        challenge_id=challenge["challenge_id"],
        purpose="fault",
    )
    algos = _http_acquisition(
        operation="algo-order",
        target="/api/v5/trade/order-algo?algoClOrdId=ownedclient",
        data=[
            {
                "algoId": "foreign-algo",
                "algoClOrdId": "foreignclient",
                "instId": "BTC-USDT",
                "state": "live",
                "sz": "9",
            },
            {
                "algoId": "owned-algo",
                "algoClOrdId": "ownedclient",
                "instId": "BTC-USDT",
                "state": "live",
                "sz": "0.01",
                "ordType": "oco",
                "side": "sell",
                "tdMode": "cash",
            },
        ],
    )
    order = _http_acquisition(
        operation="order",
        target=(
            "/api/v5/trade/order?clOrdId="
            f"{cl_ord_id}&instId=BTC-USDT"
        ),
        data=[{
            "ordId": "owned-order",
            "clOrdId": cl_ord_id,
            "instId": "BTC-USDT",
            "accFillSz": "0.010009",
            "fee": "-0.000009",
            "feeCcy": "BTC",
        }],
    )
    instrument = _http_acquisition(
        operation="instrument",
        target=(
            "/api/v5/public/instruments?instId=BTC-USDT"
            "&instType=SPOT"
        ),
        data=[{"instId": "BTC-USDT", "lotSz": "0.00001"}],
    )
    account = _http_acquisition(
        operation="account-config",
        target="/api/v5/account/config",
        data=[{"uid": "1234567890123456"}],
    )
    envelope = build_live_acquisition_envelope(
        scenario="external-fill",
        kind="exchange.protection.active",
        acquisitions=[
            _timed(algos, now),
            _timed(order, now),
            _timed(instrument, now),
            _timed(account, now),
        ],
    )
    assert derive_live_native_facts(
        envelope,
        scenario="external-fill",
        kind="exchange.protection.active",
        challenge=challenge,
        workload=_workload(),
        observed_at=now.isoformat(),
        ) == {
            "algo_id": "owned-algo",
            "algo_cl_ord_id": "ownedclient",
            "inst_id": "BTC-USDT",
        "position_qty": "0.010000",
        "protected_qty": "0.01",
        "lot_size": "0.00001",
        "state": "live",
    }

    mixed_key = copy.deepcopy(envelope)
    descriptor = mixed_key["acquisitions"][-1]["request"]
    raw = base64.b64decode(descriptor["payload_base64"])
    raw = raw.replace(("a" * 64).encode(), ("d" * 64).encode())
    _replace_descriptor_payload(descriptor, raw)
    with pytest.raises(ValueError, match="API key|精确绑定"):
        derive_live_native_facts(
            mixed_key,
            scenario="external-fill",
            kind="exchange.protection.active",
            challenge=challenge,
            workload=_workload(),
            observed_at=now.isoformat(),
        )

    wrong_registered_key = copy.deepcopy(challenge)
    wrong_registered_key["okx_observer_bindings"][
        "observer_api_key_fingerprint"
    ] = "d" * 64
    with pytest.raises(ValueError, match="精确绑定"):
        derive_live_native_facts(
            envelope,
            scenario="external-fill",
            kind="exchange.protection.active",
            challenge=wrong_registered_key,
            workload=_workload(),
            observed_at=now.isoformat(),
        )

    wrong_registered_tls = copy.deepcopy(challenge)
    wrong_registered_tls["okx_observer_bindings"][
        "tls_certificate_sha256"
    ] = "d" * 64
    with pytest.raises(ValueError, match="精确绑定"):
        derive_live_native_facts(
            envelope,
            scenario="external-fill",
            kind="exchange.protection.active",
            challenge=wrong_registered_tls,
            workload=_workload(),
            observed_at=now.isoformat(),
        )

    wrong_contract = copy.deepcopy(envelope)
    descriptor = wrong_contract["acquisitions"][0]["response"]
    raw = base64.b64decode(descriptor["payload_base64"])
    raw = raw.replace(b'"side":"sell"', b'"side":"buy"')
    _replace_descriptor_payload(descriptor, raw)
    with pytest.raises(ValueError, match="challenge order"):
        derive_live_native_facts(
            wrong_contract,
            scenario="external-fill",
            kind="exchange.protection.active",
            challenge=challenge,
            workload=_workload(),
            observed_at=now.isoformat(),
        )

    foreign_link = copy.deepcopy(envelope)
    descriptor = foreign_link["acquisitions"][0]["response"]
    raw = base64.b64decode(descriptor["payload_base64"])
    raw = raw.replace(
        b'"algoClOrdId":"ownedclient"',
        b'"algoClOrdId":"otherclient"',
    )
    _replace_descriptor_payload(descriptor, raw)
    with pytest.raises(ValueError, match="要求恰好一行"):
        derive_live_native_facts(
            foreign_link,
            scenario="external-fill",
            kind="exchange.protection.active",
            challenge=challenge,
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_frozen_balance_projects_only_challenge_owned_locked_slice():
    now = datetime.now(UTC)
    challenge = _challenge(now)
    cl_ord_id = stable_client_order_id(
        scenario="frozen-balance",
        challenge_id=challenge["challenge_id"],
        purpose="fault",
    )
    balance = _http_acquisition(
        operation="balance",
        target="/api/v5/account/balance?ccy=BTC",
        data=[{
            "details": [
                {
                    "ccy": "ETH",
                    "eq": "8",
                    "availBal": "0",
                    "frozenBal": "8",
                },
                {
                    "ccy": "BTC",
                    "eq": "2",
                    "availBal": "1.90",
                    "frozenBal": "0.10",
                },
            ],
        }],
    )
    order = _http_acquisition(
        operation="order",
        target=(
            "/api/v5/trade/order?clOrdId="
            f"{cl_ord_id}&instId=BTC-USDT"
        ),
        data=[{
            "ordId": "owned-lock",
            "clOrdId": cl_ord_id,
            "instId": "BTC-USDT",
            "side": "sell",
            "state": "live",
            "sz": "0.05",
            "accFillSz": "0",
        }],
    )
    account = _http_acquisition(
        operation="account-config",
        target="/api/v5/account/config",
        data=[{"uid": "1234567890123456"}],
    )
    envelope = build_live_acquisition_envelope(
        scenario="frozen-balance",
        kind="exchange.balance.frozen",
        acquisitions=[
            _timed(balance, now),
            _timed(order, now),
            _timed(account, now),
        ],
    )
    assert derive_live_native_facts(
        envelope,
        scenario="frozen-balance",
        kind="exchange.balance.frozen",
        challenge=challenge,
        workload=_workload(),
        observed_at=now.isoformat(),
    ) == {
        "inst_id": "BTC-USDT",
        "ccy": "BTC",
        "total": "0.05",
        "available": "0",
        "locking_order_ids": ["owned-lock"],
    }


def test_cross_role_clordid_and_unknown_write_are_fail_closed():
    assert SCENARIO_ACTION_ALLOWLIST["clordid-conflict"]
    assert SCENARIO_ACTION_ALLOWLIST["rest-5xx-429-unknown"]
    # Their core contracts do not yet expose a separately signed journal
    # conflict event or a trader-internal same-fd TLS write-trace source.
    assert (
        protocol._expected_source(
            "clordid-conflict",
            "exchange.clordid_conflict",
        )
        == "okx_collector"
    )
    assert (
        protocol._expected_source(
            "rest-5xx-429-unknown",
            "proxy.ambiguous_write",
        )
        == "fault_controller"
    )

    now = datetime.now(UTC)
    trace = NativeAcquisition(
        source="fault_controller",
        operation="tls-socket-write-trace",
        request_bytes=b'{"fd":7,"action":"trace"}',
        response_bytes=b'{"write_completed":true}',
        returncode=0,
    )
    unknown = build_live_acquisition_envelope(
        scenario="rest-5xx-429-unknown",
        kind="proxy.ambiguous_write",
        acquisitions=[_timed(trace, now)],
    )
    with pytest.raises(ValueError, match="trader_http_collector"):
        derive_live_native_facts(
            unknown,
            scenario="rest-5xx-429-unknown",
            kind="proxy.ambiguous_write",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )

    cl_ord_id = f"SC{'d' * 16}001"
    order = _http_acquisition(
        operation="order",
        target=(
            "/api/v5/trade/order?instId=BTC-USDT"
            f"&clOrdId={cl_ord_id}"
        ),
        data=[{
            "ordId": "order-external-1",
            "clOrdId": cl_ord_id,
        }],
    )
    account = _http_acquisition(
        operation="account-config",
        target="/api/v5/account/config",
        data=[{"uid": "1234567890123456"}],
    )
    conflict = build_live_acquisition_envelope(
        scenario="clordid-conflict",
        kind="exchange.clordid_conflict",
        acquisitions=[_timed(order, now), _timed(account, now)],
    )
    with pytest.raises(ValueError, match="独立 journal signer"):
        derive_live_native_facts(
            conflict,
            scenario="clordid-conflict",
            kind="exchange.clordid_conflict",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )


def test_restore_summary_and_single_systemd_receipt_are_fail_closed():
    now = datetime.now(UTC)
    restore = NativeAcquisition(
        source="restore_verifier",
        operation="restore-exact-version",
        request_bytes=b'{"object_uri":"s3://bucket/archive"}',
        response_bytes=b'{"integrity_result":"ok"}',
        returncode=0,
    )
    envelope = build_live_acquisition_envelope(
        scenario="backup-db-corruption",
        kind="backup.exact_version_restored",
        acquisitions=[_timed(restore, now)],
    )
    with pytest.raises(ValueError, match="双对象 exact-version"):
        derive_live_native_facts(
            envelope,
            scenario="backup-db-corruption",
            kind="backup.exact_version_restored",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )

    control = NativeAcquisition(
        source="systemd_collector",
        operation="systemd-sigkill",
        request_bytes=(
            b'{"action":"systemd-sigkill",'
            b'"unit":"okx-stage-c-driver.service"}'
        ),
        response_bytes=b'{"returncode":0}',
        returncode=0,
    )
    incomplete = build_live_acquisition_envelope(
        scenario="oco-active-process-death",
        kind="systemd.process_killed",
        acquisitions=[_timed(control, now)],
    )
    with pytest.raises(ValueError, match="allow-list"):
        derive_live_native_facts(
            incomplete,
            scenario="oco-active-process-death",
            kind="systemd.process_killed",
            challenge=_challenge(now),
            workload=_workload(),
            observed_at=now.isoformat(),
        )
