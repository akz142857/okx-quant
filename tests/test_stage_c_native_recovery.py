"""End-to-end native-byte tests for the Stage-C barrier recovery adapter."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import urllib.parse
from datetime import UTC, datetime, timedelta

import pytest

from okx_quant.application.approval import canonical_bytes
from okx_quant.domain.orders import SystemMode
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.ops.stage_c_chaos_protocol import _opaque_bytes_descriptor
from okx_quant.ops.stage_c_native_collectors import NativeAcquisition
from stage_c_test_harness import barriers, recovery
from stage_c_test_harness.pipeline import PIPELINE_PROOF_SCHEMA

_REACHED_AT = datetime(2026, 7, 28, 12, tzinfo=UTC)


def _key_pair(tmp_path, name):
    private = tmp_path / f"{name}-private.pem"
    public = tmp_path / f"{name}-public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", private],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            private,
            "-pubout",
            "-out",
            public,
        ],
        check=True,
        capture_output=True,
    )
    return private, public


def _challenge(scenario):
    unit = "okx-quant-stage-c-test-only-driver@barrier.service"
    return {
        "scenario": scenario,
        "challenge_id": "a" * 32,
        "barrier_nonce": "b" * 32,
        "identity": {
            "artifact_sha256": "c" * 64,
            "artifact_build_id": "test-only:stage-c",
            "account_uid": "demo-account-1",
            "test_hooks_present": True,
            "unit": unit,
        },
        "barrier_recovery_bindings": {
            "observer_api_key_fingerprint": "4" * 64,
            "tls_certificate_sha256": (
                "5" * 64 if scenario == "barrier-post-before-ack" else None
            ),
            "tls_spki_sha256": (
                "6" * 64 if scenario == "barrier-post-before-ack" else None
            ),
        },
        "workloads": {
            "fault_driver": {
                "pid": 4321,
                "systemd_invocation_id": (
                    "11111111-1111-1111-1111-111111111111"
                ),
                "boot_id": "22222222-2222-2222-2222-222222222222",
                "cgroup": f"/system.slice/{unit}",
            }
        },
    }


def _signed_chain(tmp_path, challenge, *, marker_sha256, proof_sha256):
    reached_private, reached_public = _key_pair(tmp_path, "reached")
    kill_private, kill_public = _key_pair(tmp_path, "kill")
    reached = sign_ed25519_payload(
        {
            "version": 2,
            "action": barriers.REACHED_ACTION,
            "challenge_id": challenge["challenge_id"],
            "scenario": challenge["scenario"],
            "barrier": barriers.BARRIER_SCENARIOS[challenge["scenario"]],
            "nonce": challenge["barrier_nonce"],
            "artifact_sha256": challenge["identity"]["artifact_sha256"],
            "pid": 4321,
            "systemd_invocation_id": challenge["workloads"][
                "fault_driver"
            ]["systemd_invocation_id"],
            "observed_at": _REACHED_AT.isoformat(),
            "marker_sha256": marker_sha256,
            "boundary_proof_sha256": proof_sha256,
        },
        reached_private,
    )
    kill_at = _REACHED_AT + timedelta(seconds=1)
    killed = sign_ed25519_payload(
        {
            "version": 2,
            "action": barriers.KILL_ACTION,
            "challenge_id": challenge["challenge_id"],
            "scenario": challenge["scenario"],
            "barrier": barriers.BARRIER_SCENARIOS[challenge["scenario"]],
            "nonce": challenge["barrier_nonce"],
            "artifact_sha256": challenge["identity"]["artifact_sha256"],
            "old_pid": 4321,
            "reached_artifact_sha256": hashlib.sha256(
                canonical_bytes(reached)
            ).hexdigest(),
            "kill_command": _opaque_bytes_descriptor(
                b'{"signal":"SIGKILL"}'
            ),
            "kill_response": _opaque_bytes_descriptor(b"\n"),
            "inactive_systemd_show": _opaque_bytes_descriptor(
                b"MainPID=0\n"
                b"InvocationID=11111111-1111-1111-1111-111111111111\n"
                b"ActiveState=failed\nSubState=failed\n"
            ),
            "old_process_inactive": True,
            "observed_at": kill_at.isoformat(),
        },
        kill_private,
    )
    return reached, reached_public, killed, kill_public


def _attach_independent_sources(
    tmp_path,
    challenge,
    native,
    *,
    reached_artifact,
    kill_artifact,
):
    frames = {
        "journal_collector": native["sqlite_snapshot"],
        "okx_collector": native["okx_demo_https"],
        "systemd_collector": [native["systemd"]],
    }
    private_keys = {}
    public_keys = {}
    challenge.setdefault("source_key_fingerprints", {})
    for index, source in enumerate(sorted(frames), start=10):
        private, public = _key_pair(tmp_path, source)
        private_keys[source] = private
        public_keys[source] = public
        challenge["source_key_fingerprints"][source] = (
            ed25519_public_key_fingerprint(public)
        )
        challenge["workloads"][source] = {
            "pid": 4000 + index,
            "uid": 5000 + index,
            "cgroup": f"/system.slice/{source}.service",
            "systemd_invocation_id": f"{index:08x}-1111-1111-1111-111111111111",
            "executable_sha256": f"{index:x}".rjust(64, "0"),
        }

    marker_sha256 = json.loads(
        __import__("base64").b64decode(native["marker"]["payload_base64"])
    )["marker_sha256"]

    def payload_for(source, *, started_at, collected_at):
        payload = {
            "schema": "okx-quant.stage-c-recovery-source/v1",
            "source": source,
            "scenario": challenge["scenario"],
            "challenge_id": challenge["challenge_id"],
            "boundary_proof_sha256": native["boundary_proof_sha256"],
            "marker_sha256": marker_sha256,
            "recovery_started_at": started_at,
            "collected_at": collected_at,
            "frames": frames[source],
        }
        if source == "journal_collector":
            payload["snapshot_response"] = frames[source][0]["response"]
            payload["frames"] = [
                {key: value for key, value in frame.items() if key != "response"}
                for frame in frames[source]
            ]
        elif source == "okx_collector":
            payload["api_key_fingerprint"] = "4" * 64
            payload["stability_frames"] = native["okx_stability_https"]
        return payload

    def sign_source(source, payload, *, phase="final", predecessors=None):
        predecessors = predecessors or {}
        return sign_ed25519_payload(
            {
                "version": 2,
                "action": recovery.RECOVERY_SOURCE_ACTION,
                "scenario": challenge["scenario"],
                "challenge_id": challenge["challenge_id"],
                "source": source,
                "workload_binding_sha256": hashlib.sha256(
                    canonical_bytes(challenge["workloads"][source])
                ).hexdigest(),
                "artifact_sha256": challenge["identity"]["artifact_sha256"],
                "reached_artifact_sha256": hashlib.sha256(
                    canonical_bytes(reached_artifact)
                ).hexdigest(),
                "kill_artifact_sha256": hashlib.sha256(
                    canonical_bytes(kill_artifact)
                ).hexdigest(),
                "marker_sha256": payload["marker_sha256"],
                "boundary_proof_sha256": payload[
                    "boundary_proof_sha256"
                ],
                "phase": phase,
                "predecessor_artifact_sha256s": {
                    name: hashlib.sha256(canonical_bytes(artifact)).hexdigest()
                    for name, artifact in sorted(predecessors.items())
                },
                "payload": _opaque_bytes_descriptor(canonical_bytes(payload)),
                "collected_at": payload["collected_at"],
            },
            private_keys[source],
        )

    readiness_at = native["recovery_started_at"]
    journal_readiness_payload = payload_for(
        "journal_collector",
        started_at=readiness_at,
        collected_at=readiness_at,
    )
    journal_readiness_artifact = sign_source(
        "journal_collector",
        journal_readiness_payload,
        phase="readiness",
    )
    okx_started_at = native["okx_stability_https"][0]["requested_at"]
    okx_collected_at = native["okx_demo_https"][-1]["completed_at"]
    okx_payload = payload_for(
        "okx_collector",
        started_at=okx_started_at,
        collected_at=okx_collected_at,
    )
    okx_payload["journal_readiness_sha256"] = hashlib.sha256(
        canonical_bytes(journal_readiness_artifact)
    ).hexdigest()
    okx_predecessors = {"journal_readiness": journal_readiness_artifact}
    okx_artifact = sign_source(
        "okx_collector",
        okx_payload,
        predecessors=okx_predecessors,
    )
    final_predecessors = {
        **okx_predecessors,
        "okx_final": okx_artifact,
    }
    final_started_at = okx_collected_at
    artifacts = {
        "journal_collector": sign_source(
            "journal_collector",
            payload_for(
                "journal_collector",
                started_at=final_started_at,
                collected_at=native["collected_at"],
            ),
            predecessors=final_predecessors,
        ),
        "okx_collector": okx_artifact,
        "systemd_collector": sign_source(
            "systemd_collector",
            payload_for(
                "systemd_collector",
                started_at=final_started_at,
                collected_at=native["collected_at"],
            ),
            predecessors=final_predecessors,
        ),
    }
    # The assembled v3 bundle starts at the first signed OKX pass; the
    # earlier journal-readiness cut is carried as its predecessor artifact.
    native["recovery_started_at"] = okx_started_at
    native["journal_readiness_artifact"] = journal_readiness_artifact
    native["source_artifacts"] = artifacts
    return public_keys


def _seed_database(path, scenario):
    journal = SQLiteJournal(path)
    journal.set_mode(SystemMode.HALTED)
    now = _REACHED_AT.timestamp() + 10
    with journal.transaction() as connection:
        if scenario == "barrier-buy-intent-before-post":
            connection.execute(
                """
                INSERT INTO probe_runs(
                    probe_id, account_uid, utc_day, slot, inst_id,
                    nominal_usdt, state, buy_cl_ord_id, algo_cl_ord_id,
                    created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "d" * 32,
                    "demo-account-1",
                    "2026-07-28",
                    1,
                    "BTC-USDT",
                    "5.1",
                    "REJECTED",
                    "cl-before",
                    "algo-before",
                    now,
                    now,
                ),
            )
        else:
            cl_ord_id = "cl-post" if scenario.endswith("ack") else "cl-fill"
            ord_id = "ord-post" if scenario.endswith("ack") else "ord-fill"
            quantity = "0.01" if scenario.endswith("ack") else "0.010"
            connection.execute(
                """
                INSERT INTO order_intents(
                    intent_id, cl_ord_id, inst_id, side,
                    requested_base_qty, state, exchange_ord_id,
                    exchange_state, acc_fill_qty, fee, fee_ccy,
                    source, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    f"intent-{scenario}",
                    cl_ord_id,
                    "BTC-USDT",
                    "buy",
                    quantity,
                    "filled",
                    ord_id,
                    "filled",
                    quantity,
                    "-0.001" if scenario.endswith("projection") else "0",
                    "BTC",
                    "demo_validation_probe",
                    now,
                    now,
                ),
            )
            net_qty = "0.009" if scenario.endswith("projection") else "0.01"
            connection.execute(
                """
                INSERT INTO positions(
                    inst_id, base_qty, available_qty, avg_entry_px,
                    protection_status, updated_at
                ) VALUES(?,?,?,?,?,?)
                """,
                ("BTC-USDT", net_qty, net_qty, "63000", "active", now),
            )
            connection.execute(
                """
                INSERT INTO protective_orders(
                    protection_id, inst_id, kind, protected_qty,
                    trigger_px, state, algo_cl_ord_id, exchange_algo_id,
                    parent_intent_id, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    f"protection-{scenario}",
                    "BTC-USDT",
                    "oco",
                    net_qty,
                    "62000",
                    "active",
                    f"algo-cl-{scenario}",
                    f"algo-{scenario}",
                    f"intent-{scenario}",
                    now,
                    now,
                ),
            )
            if scenario.endswith("projection"):
                connection.execute(
                    """
                    INSERT INTO fills(
                        fill_id, intent_id, exchange_ord_id, inst_id,
                        side, fill_qty, fill_px, fee, fee_ccy, trade_id,
                        idempotency_key, created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        "fill-1",
                        f"intent-{scenario}",
                        ord_id,
                        "BTC-USDT",
                        "buy",
                        quantity,
                        "63000",
                        "-0.001",
                        "BTC",
                        "trade-fill",
                        "trade:trade-fill",
                        now,
                    ),
                )
    run_id = journal.start_reconciliation()
    journal.finish_reconciliation(
        run_id,
        status="ok",
        mismatch_count=0,
        repaired_count=0,
        details={"unresolved": [], "details": []},
    )
    with journal.transaction() as connection:
        reconciliation = connection.execute(
            "SELECT completed_at FROM reconciliation_runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?,?,?,?,?,?)
            """,
            (
                f"checkpoint-{scenario}",
                "stage_c_recovery_evidence_ready",
                "info",
                "a" * 32,
                json.dumps({
                    "challenge_id": "a" * 32,
                    "scenario": scenario,
                    "evidence_hold": True,
                    "pid": 5432,
                    "systemd_invocation_id": (
                        "33333333-3333-3333-3333-333333333333"
                    ),
                    "reconciliation_run_id": run_id,
                    "reconciliation_completed_at": reconciliation[
                        "completed_at"
                    ],
                }),
                _REACHED_AT.timestamp() + 20,
            ),
        )
    journal.close()
    path.chmod(0o600)


def _proof(scenario, challenge):
    common = {
        "schema": PIPELINE_PROOF_SCHEMA,
        "scenario": scenario,
        "challenge_id": challenge["challenge_id"],
        "barrier_nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "boundary": barriers.BARRIER_SCENARIOS[scenario],
        "pid": 4321,
    }
    if scenario == "barrier-buy-intent-before-post":
        facts = {
            "probe_id": "d" * 32,
            "cl_ord_id": "cl-before",
            "intent_state": "BUY_SUBMITTING",
            "intent_tx_committed": True,
            "order_intent_count": 0,
            "socket_write_count": 0,
            "sqlite_queries": [],
        }
    elif scenario == "barrier-post-before-ack":
        request = {
            "instId": "BTC-USDT",
            "clOrdId": "cl-post",
            "side": "buy",
            "ordType": "market",
            "sz": "0.01",
        }
        body = canonical_bytes(request)
        facts = {
            "cl_ord_id": "cl-post",
            "request_sha256": "1" * 64,
            "request_body": _opaque_bytes_descriptor(body),
            "bytes_received": len(body),
            "request_fully_received": True,
            "write_completed_at": (
                _REACHED_AT - timedelta(seconds=2)
            ).isoformat(),
            "order_params_sha256": hashlib.sha256(body).hexdigest(),
            "upstream_status": 200,
            "upstream_headers_sha256": "2" * 64,
            "upstream_response": _opaque_bytes_descriptor(b'{}'),
            "upstream_ack_observed_by_proxy": True,
            "ack_delivery_started_to_trader": False,
        }
    else:
        raw_event = canonical_bytes({
            "ordId": "ord-fill",
            "tradeId": "trade-fill",
            "uTime": str(
                int((_REACHED_AT - timedelta(seconds=2)).timestamp() * 1000)
            ),
        })
        facts = {
            "ord_id": "ord-fill",
            "trade_id": "trade-fill",
            "qty": "0.010",
            "fee": "-0.001",
            "fee_ccy": "BTC",
            "base_ccy": "BTC",
            "projection_apply_count": 0,
            "projection_rows_before": [],
            "raw_exchange_event": _opaque_bytes_descriptor(raw_event),
        }
    return {**common, "facts": facts}


def _http_acquisition(path, params, rows, *, code="0"):
    query = urllib.parse.urlencode(params)
    target = f"{path}?{query}" if query else path
    request = (
        f"GET {target} HTTP/1.1\r\n"
        "Host: openapi.okx.com\r\n"
        f"X-Stage-C-API-Key-Fingerprint: {'4' * 64}\r\n"
        "x-simulated-trading: 1\r\n\r\n"
    ).encode()
    response = (
        "HTTP/1.1 200\r\n"
        "ok-trace-id: stage-c-test\r\n"
        "x-stage-c-peer-address: 1.2.3.4\r\n"
        "x-stage-c-peer-port: 443\r\n"
        "x-stage-c-tls-version: TLSv1.3\r\n"
        "x-stage-c-tls-cipher: TLS_AES_256_GCM_SHA384\r\n"
        f"x-stage-c-peer-cert-sha256: {'5' * 64}\r\n"
        f"x-stage-c-peer-spki-sha256: {'6' * 64}\r\n\r\n"
    ).encode() + canonical_bytes({"code": code, "data": rows})
    return NativeAcquisition(
        source="okx_collector",
        operation=f"GET {target}",
        request_bytes=request,
        response_bytes=response,
        returncode=0,
    )


def _install_native_collectors(monkeypatch, challenge, scenario):
    order = {
        "instId": "BTC-USDT",
        "clOrdId": "cl-post" if scenario.endswith("ack") else "cl-fill",
        "ordId": "ord-post" if scenario.endswith("ack") else "ord-fill",
        "side": "buy",
        "ordType": "market",
        "sz": "0.01" if scenario.endswith("ack") else "0.010",
        "state": "filled",
        "tradeId": "trade-post" if scenario.endswith("ack") else "trade-fill",
    }
    has_position = scenario != "barrier-buy-intent-before-post"
    algo = {
        "algoId": f"algo-{scenario}",
        "instId": "BTC-USDT",
        "state": "live",
        "side": "sell",
        "sz": "0.009" if scenario.endswith("projection") else "0.01",
        "tdMode": "cash",
    }

    def okx_get(*, path, params, **_kwargs):
        if path == "/api/v5/account/config":
            return _http_acquisition(
                path,
                params,
                [{"uid": "demo-account-1", "perm": "read"}],
            )
        if path == "/api/v5/trade/orders-pending":
            return _http_acquisition(path, params, [])
        if path == "/api/v5/trade/orders-algo-pending":
            return _http_acquisition(path, params, [algo] if has_position else [])
        if path == "/api/v5/account/balance":
            return _http_acquisition(
                path,
                params,
                [{"details": [{"ccy": "USDT", "eq": "100"}]}],
            )
        if path == "/api/v5/trade/order":
            if scenario == "barrier-buy-intent-before-post":
                return _http_acquisition(path, params, [], code="51603")
            return _http_acquisition(path, params, [order])
        if path == "/api/v5/trade/fills-history":
            return _http_acquisition(
                path,
                params,
                [order] if has_position else [],
            )
        raise AssertionError(path)

    monkeypatch.setattr(recovery, "_okx_get", okx_get)
    monkeypatch.setattr(
        recovery,
        "collect_systemd_native",
        lambda **_kwargs: NativeAcquisition(
            source="systemd_collector",
            operation="show-after-restart",
            request_bytes=b'{"action":"show-after-restart"}',
            response_bytes=(
                f"Id={challenge['identity']['unit']}\n"
                "ActiveState=active\nSubState=running\n"
                "InvocationID=33333333-3333-3333-3333-333333333333\n"
                "MainPID=5432\n"
                f"ControlGroup={challenge['workloads']['fault_driver']['cgroup']}\n"
                "ExecMainStartTimestampMonotonic=123\n"
            ).encode(),
            returncode=0,
        ),
    )


@pytest.mark.parametrize("scenario", sorted(barriers.BARRIER_SCENARIOS))
def test_native_recovery_projects_and_validates_core_contract(
    tmp_path,
    monkeypatch,
    scenario,
):
    challenge = _challenge(scenario)
    database = tmp_path / "recovery.sqlite3"
    _seed_database(database, scenario)
    proof = _proof(scenario, challenge)
    proof_path = tmp_path / "proof.json"
    proof_path.write_bytes(canonical_bytes(proof) + b"\n")
    marker = {
        "schema": "okx-quant.stage-c-barrier-marker/v2",
        "scenario": scenario,
        "challenge_id": challenge["challenge_id"],
        "nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "barrier": barriers.BARRIER_SCENARIOS[scenario],
        "pid": 4321,
        "systemd_invocation_id": challenge["workloads"]["fault_driver"][
            "systemd_invocation_id"
        ],
        "reached_at": _REACHED_AT.isoformat(),
        "monotonic_ns": 1,
        "boundary_proof_sha256": hashlib.sha256(
            canonical_bytes(proof)
        ).hexdigest(),
    }
    marker["marker_sha256"] = hashlib.sha256(
        canonical_bytes(marker)
    ).hexdigest()
    marker_path = tmp_path / "marker.json"
    marker_path.write_bytes(canonical_bytes(marker) + b"\n")
    reached, reached_public, killed, kill_public = _signed_chain(
        tmp_path,
        challenge,
        marker_sha256=marker["marker_sha256"],
        proof_sha256=marker["boundary_proof_sha256"],
    )
    _install_native_collectors(monkeypatch, challenge, scenario)
    native = recovery.collect_native_recovery_bundle(
        challenge=challenge,
        marker_path=marker_path,
        proof_path=proof_path,
        database=database,
        runtime_unit=challenge["identity"]["unit"],
        api_key="demo-key",
        secret_key="demo-secret",
        passphrase="demo-passphrase",
    )
    source_public_keys = _attach_independent_sources(
        tmp_path,
        challenge,
        native,
        reached_artifact=reached,
        kill_artifact=killed,
    )
    core = recovery.project_native_recovery_bundle(
        native,
        challenge=challenge,
        reached_artifact=reached,
        reached_public_key=reached_public,
        kill_artifact=killed,
        kill_public_key=kill_public,
        source_public_keys=source_public_keys,
    )
    facts = barriers.validate_recovery_bundle(
        core,
        challenge=challenge,
        reached_artifact=reached,
        reached_public_key=reached_public,
        kill_artifact=killed,
        kill_public_key=kill_public,
    )
    assert facts["runtime.recovery_started"]["new_pid"] == 5432

    wrong_observer = copy.deepcopy(challenge)
    wrong_observer["barrier_recovery_bindings"][
        "observer_api_key_fingerprint"
    ] = "9" * 64
    with pytest.raises(ValueError, match="readiness chain"):
        recovery.project_native_recovery_bundle(
            native,
            challenge=wrong_observer,
            reached_artifact=reached,
            reached_public_key=reached_public,
            kill_artifact=killed,
            kill_public_key=kill_public,
            source_public_keys=source_public_keys,
        )

    if scenario == "barrier-post-before-ack":
        wrong_tls = copy.deepcopy(challenge)
        wrong_tls["barrier_recovery_bindings"][
            "tls_certificate_sha256"
        ] = "9" * 64
        with pytest.raises(ValueError, match="HTTP status/schema"):
            recovery.project_native_recovery_bundle(
                native,
                challenge=wrong_tls,
                reached_artifact=reached,
                reached_public_key=reached_public,
                kill_artifact=killed,
                kill_public_key=kill_public,
                source_public_keys=source_public_keys,
            )

    tampered_readiness = copy.deepcopy(native)
    tampered_readiness["journal_readiness_artifact"]["payload"][
        "collected_at"
    ] = (_REACHED_AT - timedelta(seconds=1)).isoformat()
    with pytest.raises(ValueError, match="签名"):
        recovery.project_native_recovery_bundle(
            tampered_readiness,
            challenge=challenge,
            reached_artifact=reached,
            reached_public_key=reached_public,
            kill_artifact=killed,
            kill_public_key=kill_public,
            source_public_keys=source_public_keys,
        )

    reversed_cut = copy.deepcopy(native)
    reversed_cut["recovery_started_at"] = (
        _REACHED_AT - timedelta(seconds=1)
    ).isoformat()
    with pytest.raises(ValueError, match="signatures/frames|challenge/kill"):
        recovery.project_native_recovery_bundle(
            reversed_cut,
            challenge=challenge,
            reached_artifact=reached,
            reached_public_key=reached_public,
            kill_artifact=killed,
            kill_public_key=kill_public,
            source_public_keys=source_public_keys,
        )

    tampered = copy.deepcopy(native)
    frame = tampered["sqlite_snapshot"][0]
    decoded = json.loads(
        __import__("base64").b64decode(frame["response"]["payload_base64"])
    )
    decoded["results"][0]["rows"] = [["forged"]]
    frame["response"] = _opaque_bytes_descriptor(canonical_bytes(decoded))
    with pytest.raises(ValueError, match="snapshot|rows|重算|signatures/frames"):
        recovery.project_native_recovery_bundle(
            tampered,
            challenge=challenge,
            reached_artifact=reached,
            reached_public_key=reached_public,
            kill_artifact=killed,
            kill_public_key=kill_public,
            source_public_keys=source_public_keys,
        )
