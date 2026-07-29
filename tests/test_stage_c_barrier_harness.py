"""Security and contract tests for the Stage-C PARSER_READY scaffold."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.ops import demo_chaos_evidence, stage_c_chaos_protocol
from okx_quant.ops import stage_c_build_provenance as provenance
from scripts import build_stage_c_barrier_artifact
from stage_c_test_harness import barriers


def _key_pair(tmp_path, name):
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
    private.chmod(0o600)
    return private, public


def _dependency_lock() -> bytes:
    wheels = [{
        "name": "requests",
        "version": "2.32.0",
        "filename": "requests-2.32.0-py3-none-any.whl",
        "sha256": "1" * 64,
    }]
    return canonical_bytes({
        "schema": provenance.DEPENDENCY_LOCK_SCHEMA,
        "lock_sha256": hashlib.sha256(
            canonical_bytes(wheels)
        ).hexdigest(),
        "wheels": wheels,
    })


def _build_bundle(repo_root):
    dependency_lock = _dependency_lock()
    lock_sha = json.loads(dependency_lock)["lock_sha256"]
    build_receipt = canonical_bytes({
        "schema": provenance.BUILD_RECEIPT_SCHEMA,
        "git_commit": "a" * 40,
        "git_tree_hash": "b" * 40,
        "builder_image_digest": f"sha256:{'2' * 64}",
        "dependency_lock_sha256": lock_sha,
        "build_command": [
            "python",
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
        ],
        "source_date_epoch": 1_785_240_000,
    })
    exact = provenance.exact_release_wheel({
        "main.py": b"def main():\n    return 0\n",
        "okx_quant/__init__.py": b"",
        "okx_quant/config.py": b"PRODUCTION = True\n",
        "okx_quant/application/demo_probe.py": (
            repo_root / "okx_quant/application/demo_probe.py"
        ).read_bytes(),
        "okx_quant/infrastructure/okx/streams.py": (
            repo_root / "okx_quant/infrastructure/okx/streams.py"
        ).read_bytes(),
        provenance.BUILD_RECEIPT_PATH: build_receipt,
        provenance.DEPENDENCY_LOCK_PATH: dependency_lock,
    })
    with zipfile.ZipFile(BytesIO(exact)) as archive:
        exact_files = {
            row.filename: archive.read(row)
            for row in archive.infolist()
            if not row.is_dir()
        }
    instrumented_files = dict(exact_files)
    for name in provenance.INSTRUMENTED_TRANSFORM_MEMBERS:
        instrumented_files[name] = provenance.instrument_stage_c_member(
            name,
            exact_files[name],
        )
    instrumented_files["__main__.py"] = provenance.INSTRUMENTED_MAIN
    for name in (
        "stage_c_test_harness/__init__.py",
        "stage_c_test_harness/barriers.py",
        "stage_c_test_harness/cli.py",
        "stage_c_test_harness/native_events.py",
        "stage_c_test_harness/pipeline.py",
        "stage_c_test_harness/recovery.py",
        "stage_c_test_harness/tls_ack_proxy.py",
    ):
        instrumented_files[name] = (repo_root / name).read_bytes()
    instrumented = provenance.deterministic_zip(instrumented_files)
    exact_manifest, exact_sbom = provenance.build_manifest_bytes(
        exact,
        artifact_class=provenance.EXACT_ARTIFACT_CLASS,
        artifact_build_id="exact-release:test",
        entrypoint="main.py",
        hook_module=None,
    )
    instrumented_manifest, instrumented_sbom = (
        provenance.build_manifest_bytes(
            instrumented,
            artifact_class=provenance.INSTRUMENTED_ARTIFACT_CLASS,
            artifact_build_id="test-only:stage-c",
            entrypoint=provenance.INSTRUMENTED_ENTRYPOINT,
            hook_module=provenance.INSTRUMENTED_HOOK_MODULE,
            shared_production_files=exact_files,
        )
    )
    manifest = json.loads(instrumented_manifest)
    identity = {
        "git_commit": "a" * 40,
        "git_tree_hash": "b" * 40,
        "source_manifest_sha256": manifest["source_manifest_sha256"],
        "artifact_sha256": hashlib.sha256(instrumented).hexdigest(),
        "artifact_build_id": "test-only:stage-c",
        "test_hooks_present": True,
    }
    return {
        "instrumented": instrumented,
        "instrumented_manifest": instrumented_manifest,
        "instrumented_sbom": instrumented_sbom,
        "exact": exact,
        "exact_manifest": exact_manifest,
        "exact_sbom": exact_sbom,
        "identity": identity,
        "exact_files": exact_files,
    }


def _verify_bundle(bundle):
    return provenance.verify_build_provenance(
        instrumented_archive=bundle["instrumented"],
        instrumented_manifest=bundle["instrumented_manifest"],
        instrumented_sbom=bundle["instrumented_sbom"],
        exact_release_archive=bundle["exact"],
        exact_release_manifest=bundle["exact_manifest"],
        exact_release_sbom=bundle["exact_sbom"],
        identity=bundle["identity"],
        executable_sha256=bundle["identity"]["artifact_sha256"],
    )


def _challenge(scenario):
    return {
        "scenario": scenario,
        "challenge_id": "a" * 32,
        "barrier_nonce": "b" * 32,
        "identity": {
            "artifact_sha256": "c" * 64,
            "artifact_build_id": "test-only:stage-c",
            "test_hooks_present": True,
            "unit": "okx-quant-stage-c-test-only-harness.service",
        },
        "workloads": {
            "fault_driver": {
                "pid": 4321,
                "systemd_invocation_id": (
                    "11111111-1111-1111-1111-111111111111"
                ),
                "boot_id": "22222222-2222-2222-2222-222222222222",
            }
        },
    }


def _dynamodb_runner():
    item = None

    def run(argv, **_kwargs):
        nonlocal item
        if "put-item" in argv:
            item = json.loads(argv[argv.index("--item") + 1])
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=json.dumps({
                    "ConsumedCapacity": {
                        "TableName": "stage-c-barrier-phases"
                    }
                }).encode(),
                stderr=b"",
            )
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps({"Item": item}).encode(),
            stderr=b"",
        )

    return run


def _phase_receipt(tmp_path, challenge, phase, name):
    private, public = _key_pair(tmp_path, name)
    artifact = barriers.consume_barrier_phase_globally(
        challenge=challenge,
        phase=phase,
        private_key=private,
        backend={
            "kind": "dynamodb-conditional-put-v1",
            "table_name": "stage-c-barrier-phases",
            "region": "ap-east-1",
            "account_id": "123456789012",
        },
        command_runner=_dynamodb_runner(),
        consumed_at=1_785_240_000,
    )
    return artifact, private, public


def _signed_chain(tmp_path, challenge):
    reached_private, reached_public = _key_pair(tmp_path, "reached")
    kill_private, kill_public = _key_pair(tmp_path, "kill")
    reached_at = datetime(2026, 7, 28, 12, tzinfo=UTC)
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
            "observed_at": reached_at.isoformat(),
            "marker_sha256": "9" * 64,
            "boundary_proof_sha256": "8" * 64,
        },
        reached_private,
    )
    inactive = (
        b"MainPID=0\n"
        b"InvocationID=11111111-1111-1111-1111-111111111111\n"
        b"ActiveState=failed\n"
        b"SubState=failed\n"
    )
    kill_at = reached_at + timedelta(seconds=1)
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
            "kill_command": stage_c_chaos_protocol._opaque_bytes_descriptor(
                b'{"signal":"SIGKILL"}'
            ),
            "kill_response": (
                stage_c_chaos_protocol._opaque_bytes_descriptor(b"\n")
            ),
            "inactive_systemd_show": (
                stage_c_chaos_protocol._opaque_bytes_descriptor(inactive)
            ),
            "old_process_inactive": True,
            "observed_at": kill_at.isoformat(),
        },
        kill_private,
    )
    return reached, reached_public, killed, kill_public, kill_at


def _query(operation, kill_at, rows, snapshot_id="okx-cut-1"):
    return {
        "operation": operation,
        "requested_at": (kill_at + timedelta(seconds=1)).isoformat(),
        "completed_at": (kill_at + timedelta(seconds=2)).isoformat(),
        "request": stage_c_chaos_protocol._opaque_bytes_descriptor(
            f"GET {operation}".encode()
        ),
        "response": stage_c_chaos_protocol._opaque_bytes_descriptor(
            json.dumps(rows).encode()
        ),
        "rows": rows,
        "snapshot_id": snapshot_id,
    }


def _common(recovery_at):
    return {
        "snapshot_id": "post-recovery-cut-1",
        "snapshot_sha256": "d" * 64,
        "collected_at": (recovery_at + timedelta(seconds=5)).isoformat(),
        "journal_integrity": "ok",
        "duplicate_buy_count": 0,
        "positions": [],
        "pending_orders": [],
        "pending_algos": [],
        "balances": {"USDT": "100"},
        "runtime_mode": "ready",
        "reconciliation": {"unresolved": []},
    }


def _bundle(scenario, challenge, kill_at, reached_artifact):
    recovery_at = kill_at + timedelta(seconds=3)
    base = {
        "schema": barriers.RECOVERY_SCHEMA,
        "scenario": scenario,
        "challenge_id": challenge["challenge_id"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "old_pid": 4321,
        "new_pid": 5432,
        "new_systemd_invocation_id": (
            "33333333-3333-3333-3333-333333333333"
        ),
        "recovery_started_at": recovery_at.isoformat(),
        "recovery_snapshot_sha256": "e" * 64,
        "marker_sha256": "9" * 64,
        "boundary_proof_sha256": "8" * 64,
        "reached_artifact_sha256": hashlib.sha256(
            canonical_bytes(reached_artifact)
        ).hexdigest(),
        "final_common": _common(recovery_at),
    }
    if scenario == "barrier-buy-intent-before-post":
        base["before"] = {
            "cl_ord_id": "cl-before",
            "intent_state": "BUY_SUBMITTING",
            "intent_tx_committed": True,
            "socket_write_count": 0,
        }
        base["after"] = {
            "pending_query": _query("pending", kill_at, []),
            "history_query": _query("history", kill_at, []),
            "fills_query": _query("fills", kill_at, []),
            "buy_post_count": 0,
            "intent_state": "REJECTED",
            "reservation_outcome": {
                "state": "never_created",
                "reservation_id": None,
                "released_at": None,
            },
        }
    elif scenario == "barrier-post-before-ack":
        params = "f" * 64
        base["before"] = {
            "cl_ord_id": "cl-post",
            "intent_tx_committed": True,
            "tls_write": {
                "request_sha256": "1" * 64,
                "bytes_written": 128,
                "write_completed_at": (
                    kill_at - timedelta(seconds=2)
                ).isoformat(),
                "ack_bytes_observed": False,
            },
            "ack_persisted": False,
            "order_params_sha256": params,
        }
        order = {
            "cl_ord_id": "cl-post",
            "ord_id": "ord-post",
            "state": "filled",
            "order_params_sha256": params,
        }
        base["after"] = {
            "pending_query": _query("pending", kill_at, []),
            "history_query": _query("history", kill_at, [order]),
            "fills_query": _query("fills", kill_at, []),
            "buy_post_count": 1,
            "resolved_order": order,
            "duplicate_buy_count": 0,
            "net_position_qty": "0.01",
            "protection": {
                "state": "active",
                "reduce_only": True,
                "covered_qty": "0.01",
                "algo_id": "algo-post",
                "emergency_exit_ord_id": None,
            },
        }
    else:
        base["before"] = {
            "fill": {
                "ord_id": "ord-fill",
                "trade_id": "trade-fill",
                "qty": "0.010",
                "fee": "-0.001",
                "fee_ccy": "BTC",
                "base_ccy": "BTC",
                "observed_at": (
                    kill_at - timedelta(seconds=2)
                ).isoformat(),
                "raw": stage_c_chaos_protocol._opaque_bytes_descriptor(
                    b'{"tradeId":"trade-fill"}'
                ),
            },
            "projection_apply_count": 0,
            "projection_snapshot_sha256": "2" * 64,
        }
        base["after"] = {
            "fill_apply_count": 1,
            "net_position_qty": "0.009",
            "position_snapshot_sha256": "3" * 64,
            "protection": {
                "state": "active",
                "reduce_only": True,
                "covered_qty": "0.009",
                "algo_id": "algo-fill",
                "emergency_exit_ord_id": None,
            },
        }
    return base


def test_build_provenance_recomputes_shared_production_and_delta(tmp_path):
    bundle = _build_bundle(Path(__file__).resolve().parents[1])
    result = _verify_bundle(bundle)
    assert result["production_hook_absent"] is True
    assert result["source_manifest_sha256"] == (
        bundle["identity"]["source_manifest_sha256"]
    )

    with zipfile.ZipFile(BytesIO(bundle["instrumented"])) as archive:
        files = {
            row.filename: archive.read(row)
            for row in archive.infolist()
            if not row.is_dir()
        }
    files["okx_quant/config.py"] = b"PRODUCTION = False\n"
    forged = copy.deepcopy(bundle)
    forged["instrumented"] = provenance.deterministic_zip(files)
    forged["identity"]["artifact_sha256"] = hashlib.sha256(
        forged["instrumented"]
    ).hexdigest()
    forged["instrumented_manifest"], forged["instrumented_sbom"] = (
        provenance.build_manifest_bytes(
            forged["instrumented"],
            artifact_class=provenance.INSTRUMENTED_ARTIFACT_CLASS,
            artifact_build_id="test-only:stage-c",
            entrypoint=provenance.INSTRUMENTED_ENTRYPOINT,
            hook_module=provenance.INSTRUMENTED_HOOK_MODULE,
            shared_production_files=bundle["exact_files"],
        )
    )
    with pytest.raises(ValueError, match="超出固定 transform"):
        _verify_bundle(forged)


def test_build_provenance_rejects_dummy_exact_hook_and_record_tamper(tmp_path):
    bundle = _build_bundle(Path(__file__).resolve().parents[1])
    dummy = copy.deepcopy(bundle)
    dummy_exact = provenance.exact_release_wheel({
        "main.py": b"def main(): return 0\n",
        "okx_quant/__init__.py": b"",
        "okx_quant/config.py": b"PRODUCTION=True\n",
        provenance.BUILD_RECEIPT_PATH: (
            bundle["exact_files"][provenance.BUILD_RECEIPT_PATH]
        ),
        provenance.DEPENDENCY_LOCK_PATH: (
            bundle["exact_files"][provenance.DEPENDENCY_LOCK_PATH]
        ),
    })
    dummy["exact"] = dummy_exact
    dummy["exact_manifest"], dummy["exact_sbom"] = (
        provenance.build_manifest_bytes(
            dummy_exact,
            artifact_class=provenance.EXACT_ARTIFACT_CLASS,
            artifact_build_id="exact-release:test",
            entrypoint="main.py",
            hook_module=None,
        )
    )
    with pytest.raises(ValueError, match="生产入口"):
        _verify_bundle(dummy)

    with zipfile.ZipFile(BytesIO(bundle["exact"])) as archive:
        exact_files = {
            row.filename: archive.read(row)
            for row in archive.infolist()
            if not row.is_dir()
        }
    record = next(name for name in exact_files if name.endswith("/RECORD"))
    exact_files[record] += b"main.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1\n"
    tampered = copy.deepcopy(bundle)
    tampered["exact"] = provenance.deterministic_zip(exact_files)
    with pytest.raises(ValueError, match="RECORD"):
        _verify_bundle(tampered)

    hook_files = dict(bundle["exact_files"])
    hook_files["okx_quant/config.py"] = (
        b"from stage_c_test_harness import BarrierStore\n"
    )
    hooked = provenance.exact_release_wheel({
        key: value
        for key, value in hook_files.items()
        if not key.endswith("/RECORD")
    })
    hooked_bundle = copy.deepcopy(bundle)
    hooked_bundle["exact"] = hooked
    hooked_bundle["exact_manifest"], hooked_bundle["exact_sbom"] = (
        provenance.build_manifest_bytes(
            hooked,
            artifact_class=provenance.EXACT_ARTIFACT_CLASS,
            artifact_build_id="exact-release:test",
            entrypoint="main.py",
            hook_module=None,
        )
    )
    with pytest.raises(ValueError, match="import test harness"):
        _verify_bundle(hooked_bundle)


def test_isolated_build_cli_emits_recomputable_artifacts(
    tmp_path,
    monkeypatch,
):
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_bytes(_dependency_lock())
    outputs = {
        "exact": tmp_path / "exact.whl",
        "instrumented": tmp_path / "instrumented.pyz",
        "exact_manifest": tmp_path / "exact-manifest.json",
        "instrumented_manifest": tmp_path / "instrumented-manifest.json",
        "exact_sbom": tmp_path / "exact-sbom.json",
        "instrumented_sbom": tmp_path / "instrumented-sbom.json",
        "identity": tmp_path / "identity.json",
    }
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "build_stage_c_barrier_artifact.py",
            "--source-root",
            str(Path(__file__).resolve().parents[1]),
            "--git-commit",
            "a" * 40,
            "--git-tree-hash",
            "b" * 40,
            "--builder-image-digest",
            f"sha256:{'2' * 64}",
            "--source-date-epoch",
            "1785240000",
            "--dependency-lock",
            str(dependency_lock),
            "--artifact-build-id",
            "test-only:stage-c-build-test",
            "--exact-output",
            str(outputs["exact"]),
            "--instrumented-output",
            str(outputs["instrumented"]),
            "--exact-manifest-output",
            str(outputs["exact_manifest"]),
            "--instrumented-manifest-output",
            str(outputs["instrumented_manifest"]),
            "--exact-sbom-output",
            str(outputs["exact_sbom"]),
            "--instrumented-sbom-output",
            str(outputs["instrumented_sbom"]),
            "--identity-output",
            str(outputs["identity"]),
        ],
    )
    assert build_stage_c_barrier_artifact.main() == 0
    identity = json.loads(outputs["identity"].read_text())
    result = provenance.verify_build_provenance(
        instrumented_archive=outputs["instrumented"].read_bytes(),
        instrumented_manifest=outputs[
            "instrumented_manifest"
        ].read_bytes(),
        instrumented_sbom=outputs["instrumented_sbom"].read_bytes(),
        exact_release_archive=outputs["exact"].read_bytes(),
        exact_release_manifest=outputs["exact_manifest"].read_bytes(),
        exact_release_sbom=outputs["exact_sbom"].read_bytes(),
        identity=identity,
        executable_sha256=identity["artifact_sha256"],
    )
    assert result["production_hook_absent"] is True
    assert outputs["instrumented"].stat().st_mode & 0o777 == 0o750
    capability = tmp_path / "barrier-capability.json"
    execution = subprocess.run(
        [
            sys.executable,
            str(outputs["instrumented"]),
            "self-check",
            "--scenario",
            "barrier-buy-intent-before-post",
            "--output",
            str(capability),
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert execution.returncode == 2, execution.stderr.decode()
    assert json.loads(capability.read_text())["status"] == "EXTERNAL OPEN"


@pytest.mark.parametrize("phase", ["reached", "kill"])
def test_barrier_phase_consumption_is_conditional_and_bound(
    tmp_path,
    phase,
):
    challenge = _challenge("barrier-post-before-ack")
    artifact, _private, public = _phase_receipt(
        tmp_path,
        challenge,
        phase,
        f"consumer-{phase}",
    )
    claims = barriers.verify_phase_consumption(
        artifact,
        public_key=public,
        challenge=challenge,
        phase=phase,
    )
    assert claims["phase_key"] == barriers.barrier_phase_key(
        scenario=challenge["scenario"],
        challenge_id=challenge["challenge_id"],
        nonce=challenge["barrier_nonce"],
        artifact_sha256=challenge["identity"]["artifact_sha256"],
        phase=phase,
    )
    replay_private, _ = _key_pair(tmp_path, f"replay-{phase}")

    def replay(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            255,
            stdout=b"",
            stderr=b"ConditionalCheckFailedException",
        )

    with pytest.raises(ValueError, match="已消费"):
        barriers.consume_barrier_phase_globally(
            challenge=challenge,
            phase=phase,
            private_key=replay_private,
            backend={
                "kind": "dynamodb-conditional-put-v1",
                "table_name": "stage-c-barrier-phases",
                "region": "ap-east-1",
                "account_id": "123456789012",
            },
            command_runner=replay,
        )


def test_marker_is_one_shot_and_cannot_target_another_boundary(tmp_path):
    challenge = _challenge("barrier-buy-intent-before-post")
    store = barriers.BarrierStateStore(tmp_path / "markers.sqlite3")
    hook = barriers.BarrierHook(
        challenge=challenge,
        state_store=store,
        marker_output=tmp_path / "marker.json",
        systemd_invocation_id=challenge["workloads"][
            "fault_driver"
        ]["systemd_invocation_id"],
        pid=4321,
    )
    with pytest.raises(ValueError, match="boundary"):
        hook.reach(
            "post-before-ack",
            boundary_proof_sha256="1" * 64,
        )
    marker = hook.reach(
        "buy-intent-before-post",
        boundary_proof_sha256="1" * 64,
    )
    assert marker["nonce"] == challenge["barrier_nonce"]
    with pytest.raises(ValueError, match="已使用"):
        store.record_reached({
            key: marker[key]
            for key in marker
            if key != "marker_sha256"
        })


def test_independent_attestor_and_systemd_kill_capture_inactive_raw(tmp_path):
    challenge = _challenge("barrier-post-before-ack")
    reached_consumption, _reached_consumer_private, reached_consumer_public = (
        _phase_receipt(
            tmp_path,
            challenge,
            "reached",
            "reached-consumer",
        )
    )
    kill_consumption, _kill_consumer_private, kill_consumer_public = (
        _phase_receipt(
            tmp_path,
            challenge,
            "kill",
            "kill-consumer",
        )
    )
    attestor_private, attestor_public = _key_pair(tmp_path, "attestor")
    kill_private, kill_public = _key_pair(tmp_path, "kill-controller")
    challenge["barrier_attestor_key_fingerprint"] = (
        ed25519_public_key_fingerprint(attestor_public)
    )
    challenge["kill_controller_key_fingerprint"] = (
        ed25519_public_key_fingerprint(kill_public)
    )
    boundary_proof = {
        "schema": "okx-quant.stage-c-pipeline-boundary-proof/v1",
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "barrier_nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "boundary": "post-before-ack",
        "pid": 4321,
        "facts": {},
    }
    marker_without_hash = {
        "schema": barriers.MARKER_SCHEMA,
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "barrier": "post-before-ack",
        "pid": 4321,
        "systemd_invocation_id": challenge["workloads"][
            "fault_driver"
        ]["systemd_invocation_id"],
        "reached_at": datetime.now(UTC).isoformat(),
        "monotonic_ns": 10,
        "boundary_proof_sha256": hashlib.sha256(
            canonical_bytes(boundary_proof)
        ).hexdigest(),
    }
    marker = {
        **marker_without_hash,
        "marker_sha256": hashlib.sha256(
            canonical_bytes(marker_without_hash)
        ).hexdigest(),
    }
    reached = barriers.attest_barrier_reached(
        marker=marker,
        boundary_proof=boundary_proof,
        challenge=challenge,
        phase_consumption=reached_consumption,
        phase_consumer_public_key=reached_consumer_public,
        private_key=attestor_private,
    )
    calls = []

    def run(argv, **_kwargs):
        calls.append(argv)
        if "kill" in argv:
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=b"",
                stderr=b"",
            )
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=(
                b"MainPID=0\n"
                b"InvocationID=11111111-1111-1111-1111-111111111111\n"
                b"ActiveState=failed\n"
                b"SubState=failed\n"
            ),
            stderr=b"",
        )

    killed = barriers.execute_systemd_kill(
        challenge=challenge,
        reached_artifact=reached,
        reached_public_key=attestor_public,
        reached_consumption=reached_consumption,
        reached_consumer_public_key=reached_consumer_public,
        kill_consumption=kill_consumption,
        kill_consumer_public_key=kill_consumer_public,
        private_key=kill_private,
        unit=challenge["identity"]["unit"],
        command_runner=run,
    )
    claims = verify_ed25519_artifact(
        killed,
        kill_public,
        label="kill controller",
    )
    assert claims["old_process_inactive"] is True
    assert "--signal=SIGKILL" in calls[0]
    raw = stage_c_chaos_protocol._decode_opaque_bytes(
        claims["inactive_systemd_show"],
        "inactive raw",
    )
    assert b"MainPID=0" in raw


@pytest.mark.parametrize(
    "scenario",
    sorted(barriers.BARRIER_SCENARIOS),
)
def test_recovery_contracts_project_parser_facts(tmp_path, scenario):
    challenge = _challenge(scenario)
    reached, reached_public, killed, kill_public, kill_at = (
        _signed_chain(tmp_path, challenge)
    )
    result = barriers.validate_recovery_bundle(
        _bundle(scenario, challenge, kill_at, reached),
        challenge=challenge,
        reached_artifact=reached,
        reached_public_key=reached_public,
        kill_artifact=killed,
        kill_public_key=kill_public,
    )
    assert result["runtime.recovery_started"]["new_pid"] == 5432
    if scenario == "barrier-buy-intent-before-post":
        assert result[
            "journal.intent_rejected_no_exchange_order"
        ] == {
            "cl_ord_id": "cl-before",
            "state": "REJECTED",
            "buy_post_count": 0,
        }
    elif scenario == "barrier-post-before-ack":
        assert result[
            "journal.clordid_resolved_without_duplicate"
        ]["duplicate_buy_count"] == 0
    else:
        assert result[
            "journal.fill_projection_recovered"
        ]["protection_state"] == "active"


def test_recovery_rejects_old_okx_snapshot_second_post_and_undercoverage(
    tmp_path,
):
    scenario = "barrier-buy-intent-before-post"
    challenge = _challenge(scenario)
    reached, reached_public, killed, kill_public, kill_at = (
        _signed_chain(tmp_path, challenge)
    )
    stale = _bundle(scenario, challenge, kill_at, reached)
    stale["after"]["pending_query"]["completed_at"] = (
        kill_at - timedelta(seconds=1)
    ).isoformat()
    with pytest.raises(ValueError, match="时间"):
        barriers.validate_recovery_bundle(
            stale,
            challenge=challenge,
            reached_artifact=reached,
            reached_public_key=reached_public,
            kill_artifact=killed,
            kill_public_key=kill_public,
        )

    scenario = "barrier-post-before-ack"
    challenge = _challenge(scenario)
    reached, reached_public, killed, kill_public, kill_at = (
        _signed_chain(tmp_path, challenge)
    )
    second = _bundle(scenario, challenge, kill_at, reached)
    second["after"]["buy_post_count"] = 2
    with pytest.raises(ValueError, match="exactly-one"):
        barriers.validate_recovery_bundle(
            second,
            challenge=challenge,
            reached_artifact=reached,
            reached_public_key=reached_public,
            kill_artifact=killed,
            kill_public_key=kill_public,
        )

    scenario = "barrier-fill-before-projection"
    challenge = _challenge(scenario)
    reached, reached_public, killed, kill_public, kill_at = (
        _signed_chain(tmp_path, challenge)
    )
    uncovered = _bundle(scenario, challenge, kill_at, reached)
    uncovered["after"]["protection"]["covered_qty"] = "0.0001"
    with pytest.raises(ValueError, match="未覆盖净仓"):
        barriers.validate_recovery_bundle(
            uncovered,
            challenge=challenge,
            reached_artifact=reached,
            reached_public_key=reached_public,
            kill_artifact=killed,
            kill_public_key=kill_public,
        )


def test_scaffold_is_permanently_open_and_cannot_enter_inventory(tmp_path):
    assert stage_c_chaos_protocol.implemented_stage_c_scenarios() == frozenset()
    for scenario in barriers.BARRIER_SCENARIOS:
        report = barriers.barrier_capability_self_check(
            scenario=scenario,
        )
        assert report["status"] == "EXTERNAL OPEN"
        assert report["protocol_ready"] is True
        assert report["standalone_boundary_executor"] is False
        assert report["production_receipt_admissible"] is False
        assert report["missing_requirements"]
        with pytest.raises(RuntimeError, match="PARSER_READY"):
            barriers.require_barrier_production_capability(
                scenario=scenario,
            )
        assert scenario in demo_chaos_evidence.EXTERNAL_OPEN_SCENARIOS

    output = tmp_path / "self-check.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "stage_c_test_harness.cli",
            "self-check",
            "--scenario",
            "barrier-post-before-ack",
            "--output",
            str(output),
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert json.loads(output.read_text())["production_receipt_admissible"] is False


def test_v2_scaffold_attestation_is_not_core_v1_evidence(tmp_path):
    private, public = _key_pair(tmp_path, "incompatible")
    challenge = _challenge("barrier-post-before-ack")
    artifact = sign_ed25519_payload(
        {
            "version": 2,
            "action": barriers.REACHED_ACTION,
            "challenge_id": challenge["challenge_id"],
        },
        private,
    )
    with pytest.raises(ValueError, match="claims"):
        stage_c_chaos_protocol._verify_role_attestation(
            artifact,
            public,
            action="attest-stage-c-barrier-reached-v1",
            challenge=challenge,
            extra={},
            label="v2 scaffold",
        )


def test_test_only_units_and_manifest_are_isolated_from_production():
    root = Path(__file__).resolve().parents[1]
    isolated = root / "deploy/stage-c-barriers"
    manifest = json.loads(
        (isolated / "instrumented-artifact-manifest.json.example").read_text()
    )
    assert manifest["production_eligible"] is False
    assert manifest["production_receipt_admissible"] is False
    assert "PARSER_READY" in manifest["capability_status"]
    for unit in (isolated / "systemd").glob("*.service"):
        text = unit.read_text()
        assert "TEST-ONLY" in text
        assert "PARSER_READY" in text
        assert "EnvironmentFile=" not in text
        assert "/etc/okx-quant/config" not in text
        assert "NoNewPrivileges=yes" in text or "User=root" in text
        assert "ProtectSystem=strict" in text
        assert (
            "ConditionPathExists="
            "/opt/okx-quant-stage-c-test-only/instrumented.pyz"
            in text
        )
        assert "ConditionPathIsExecutable=" not in text
        assert (
            "ConditionFileIsExecutable="
            "/opt/okx-quant-stage-c-test-only/venv/bin/python"
            in text
        )
        assert (
            "ExecStart=/opt/okx-quant-stage-c-test-only/venv/bin/python "
            "/opt/okx-quant-stage-c-test-only/instrumented.pyz"
            in text
        )
        assert (
            "LoadCredential=scenario:"
            "/etc/okx-quant-stage-c-test-only/%i/scenario"
            in text
        )
        assert "--scenario-file %d/scenario" in text
        assert "--scenario %i" not in text
    for unit in (root / "deploy/systemd").glob("okx-quant*.service"):
        assert "stage-c-test-only" not in unit.read_text().lower()


def test_cli_uses_run_scoped_scenario_credential_and_rejects_symlink(
    tmp_path,
):
    root = Path(__file__).resolve().parents[1]
    scenario = tmp_path / "scenario"
    scenario.write_text("barrier-post-before-ack\n")
    output = tmp_path / "self-check.json"
    command = [
        sys.executable,
        "-m",
        "stage_c_test_harness.cli",
        "self-check",
        "--scenario-file",
        str(scenario),
        "--output",
        str(output),
    ]
    result = subprocess.run(command, cwd=root, capture_output=True, check=False)
    assert result.returncode == 2
    assert json.loads(output.read_text())["scenario"] == (
        "barrier-post-before-ack"
    )

    output.unlink()
    link = tmp_path / "scenario-link"
    link.symlink_to(scenario)
    command[5] = str(link)
    rejected = subprocess.run(
        command,
        cwd=root,
        capture_output=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert not output.exists()


def test_cli_has_no_passthrough_and_unknown_activation_fails(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "stage_c_test_harness.cli",
            "--stage-c-barrier",
            "post-before-ack",
        ],
        cwd=root,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert b"unrecognized arguments" in result.stderr or b"invalid choice" in result.stderr
