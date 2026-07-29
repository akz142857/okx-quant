"""WP4/WP5 matrix schema, coverage gate, and fault proxy safety tests."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from io import BytesIO
from pathlib import Path

import pytest

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)
from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.infrastructure.immutable_bundle import (
    build_bundle_manifest,
    build_bundle_receipt,
    sign_bundle_manifest,
)
from okx_quant.ops import demo_chaos_evidence as chaos_evidence
from okx_quant.ops import stage_c_build_provenance, stage_c_native_collectors
from okx_quant.ops import stage_c_chaos_protocol as stage_c_protocol
from okx_quant.ops.demo_chaos_evidence import (
    DRILL_SCENARIOS,
    DrillArtifactClass,
    expected_transitions_for,
    load_verified_stage_c_receipts,
    scenario_names,
    validate_drill_receipt,
    verify_stage_c_coverage,
)
from okx_quant.ops.stage_c_deployment_identity import (
    stage_c_chaos_deployment_identity_sha256,
)
from scripts import (
    build_stage_c_trust_manifest,
    demo_chaos_matrix,
    production_gate,
    stage_c_chaos_producer,
    verify_demo_chaos_coverage,
)
from scripts import ws_channel_fault_proxy as fault_proxy
from stage_c_test_harness import pipeline as stage_c_pipeline

_RELEASE = {
    "git_commit": "a" * 40,
    "git_tree_hash": "b" * 40,
    "source_manifest_sha256": "c" * 64,
}
_EPOCH = "stage-c-epoch-2026-07"


def _stage_c_candidate_identity(
    *,
    exact_artifact_sha256: str = "c" * 64,
    instrumented_artifact_sha256: str = "d" * 64,
) -> dict:
    return {
        "version": 1,
        "exact_release": {
            "account_uid": "demo-chaos-account",
            "config_sha256": "e" * 64,
            "unit": "okx-quant-demo-chaos.service",
            "artifact_sha256": exact_artifact_sha256,
        },
        "instrumented": {
            "account_uid": "test-harness-account",
            "config_sha256": "e" * 64,
            "unit": "okx-quant-instrumented-test.service",
            "artifact_sha256": instrumented_artifact_sha256,
        },
        "host_image_sha256": "4" * 64,
        "network_namespace_sha256": "5" * 64,
        "cgroup_policy_sha256": "6" * 64,
        "observer_api_key_fingerprint": "f" * 64,
        "source_key_fingerprints": ["1" * 64, "2" * 64, "3" * 64],
        "safety_behavior_sha256": "7" * 64,
        "build_provenance_sha256": "8" * 64,
    }


@lru_cache(maxsize=1)
def _barrier_build_bundle() -> dict:
    repository_root = Path(__file__).resolve().parents[1]
    wheels = [{
        "name": "requests",
        "version": "2.32.0",
        "filename": "requests-2.32.0-py3-none-any.whl",
        "sha256": "9" * 64,
    }]
    dependency_lock = canonical_bytes({
        "schema": stage_c_build_provenance.DEPENDENCY_LOCK_SCHEMA,
        "lock_sha256": hashlib.sha256(
            canonical_bytes(wheels)
        ).hexdigest(),
        "wheels": wheels,
    })
    build_receipt = canonical_bytes({
        "schema": stage_c_build_provenance.BUILD_RECEIPT_SCHEMA,
        "git_commit": _RELEASE["git_commit"],
        "git_tree_hash": _RELEASE["git_tree_hash"],
        "builder_image_digest": f"sha256:{'8' * 64}",
        "dependency_lock_sha256": json.loads(dependency_lock)[
            "lock_sha256"
        ],
        "build_command": [
            "python",
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
        ],
        "source_date_epoch": 1_785_240_000,
    })
    exact_sources = {
        "main.py": b"def main():\n    return 0\n",
        "okx_quant/__init__.py": b'"""fixture production package."""\n',
        "okx_quant/config.py": b"PRODUCTION = True\n",
        "okx_quant/application/demo_probe.py": (
            repository_root
            / "okx_quant/application/demo_probe.py"
        ).read_bytes(),
        "okx_quant/infrastructure/okx/streams.py": (
            repository_root
            / "okx_quant/infrastructure/okx/streams.py"
        ).read_bytes(),
        stage_c_build_provenance.BUILD_RECEIPT_PATH: build_receipt,
        stage_c_build_provenance.DEPENDENCY_LOCK_PATH: dependency_lock,
    }
    exact = stage_c_build_provenance.exact_release_wheel(exact_sources)
    with zipfile.ZipFile(BytesIO(exact)) as archive:
        exact_files = {
            info.filename: archive.read(info)
            for info in archive.infolist()
            if not info.is_dir()
        }
    instrumented_files = dict(exact_files)
    for name in stage_c_build_provenance.INSTRUMENTED_TRANSFORM_MEMBERS:
        instrumented_files[name] = (
            stage_c_build_provenance.instrument_stage_c_member(
                name,
                exact_files[name],
            )
        )
    instrumented_files["__main__.py"] = (
        stage_c_build_provenance.INSTRUMENTED_MAIN
    )
    for name in (
        stage_c_build_provenance.INSTRUMENTED_ONLY_MEMBERS
        - {"__main__.py"}
    ):
        instrumented_files[name] = (repository_root / name).read_bytes()
    instrumented = stage_c_build_provenance.deterministic_zip(
        instrumented_files
    )
    exact_manifest, exact_sbom = (
        stage_c_build_provenance.build_manifest_bytes(
            exact,
            artifact_class=stage_c_build_provenance.EXACT_ARTIFACT_CLASS,
            artifact_build_id="exact-release:fixture",
            entrypoint="main.py",
            hook_module=None,
        )
    )
    instrumented_manifest, instrumented_sbom = (
        stage_c_build_provenance.build_manifest_bytes(
            instrumented,
            artifact_class=(
                stage_c_build_provenance.INSTRUMENTED_ARTIFACT_CLASS
            ),
            artifact_build_id="test-only:stage-c-barrier",
            entrypoint=(
                stage_c_build_provenance.INSTRUMENTED_ENTRYPOINT
            ),
            hook_module=(
                stage_c_build_provenance.INSTRUMENTED_HOOK_MODULE
            ),
            shared_production_files=exact_files,
        )
    )
    instrumented_claims = json.loads(instrumented_manifest)
    return {
        "instrumented": instrumented,
        "instrumented_manifest": instrumented_manifest,
        "instrumented_sbom": instrumented_sbom,
        "exact": exact,
        "exact_manifest": exact_manifest,
        "exact_sbom": exact_sbom,
        "artifact_sha256": hashlib.sha256(instrumented).hexdigest(),
        "source_manifest_sha256": instrumented_claims[
            "source_manifest_sha256"
        ],
        "sbom_sha256": hashlib.sha256(instrumented_sbom).hexdigest(),
        "hook_sha256": hashlib.sha256(
            instrumented_files[
                stage_c_build_provenance.INSTRUMENTED_HOOK_MODULE
            ]
        ).hexdigest(),
    }


def _receipt(
    scenario: str,
    *,
    started: datetime,
    passed: bool = True,
) -> dict:
    spec = chaos_evidence.SCENARIO_BY_NAME[scenario]
    exact = (
        spec.artifact_class
        is DrillArtifactClass.EXACT_RELEASE_BLACK_BOX
    )
    completed = started + timedelta(seconds=20)
    expected = expected_transitions_for(scenario)
    errors = [] if passed else ["external drill not executed"]
    receipt = {
        "version": 2,
        "action": "attest-demo-chaos-drill-v2",
        "scenario": scenario,
        "work_package": spec.work_package,
        "artifact_class": spec.artifact_class.value,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "identity": {
            **_RELEASE,
            "artifact_sha256": (
                _RELEASE["source_manifest_sha256"] if exact else "d" * 64
            ),
            "artifact_build_id": (
                "exact-release:fixture"
                if exact
                else "test-only:barrier-fixture"
            ),
            "config_sha256": "e" * 64,
            "account_uid": (
                "demo-chaos-account" if exact else "test-harness-account"
            ),
            "environment": "demo",
            "unit": (
                "okx-quant-demo-chaos.service"
                if exact
                else "okx-quant-instrumented-test.service"
            ),
            "soak_epoch_id": _EPOCH,
            "stage_c_chaos_deployment_identity_sha256": (
                stage_c_chaos_deployment_identity_sha256(
                    _stage_c_candidate_identity()
                )
            ),
            "workspace_clean": True,
            "test_hooks_present": not exact,
        },
        "execution": {
            "run_id": "f" * 32,
            "executor": (
                "scripts/demo_chaos_matrix.py"
                if exact
                else "instrumented-barrier-harness"
            ),
            "host_id": "isolated-linux-host",
            "fault_mechanism": scenario,
            "evidence_origin": (
                "real_demo_black_box"
                if exact
                else "instrumented_harness"
            ),
            "adapter": (
                "independent_raw_observation"
                if scenario
                in chaos_evidence.INDEPENDENT_OBSERVATION_SCENARIOS
                else (
                    "automated_control"
                    if exact
                    else "instrumented_barrier_protocol"
                )
            ),
            "raw_observation": None,
        },
        "expected_transitions": expected,
        "actual_transitions": (
            [
                {
                    "transition_id": item["transition_id"],
                    "from_state": item["from_state"],
                    "to_state": item["to_state"],
                    "observed_at": (
                        started + timedelta(seconds=index + 1)
                    ).isoformat(),
                    "evidence_ids": [f"event-{index}"],
                }
                for index, item in enumerate(expected)
            ]
            if passed
            else []
        ),
        "reconciliation": {
            "required": True,
            "run_ids": ["reconciliation-1"] if passed else [],
            "mismatch_count": 1 if passed else 0,
            "repaired_count": 1 if passed else 0,
            "unresolved": [] if passed else ["not_executed"],
        },
        "page_receipt": {
            "required": True,
            "event_id": "page-event-1" if passed else "",
            "event_name": (
                (
                    "page.ws_error_budget_exhausted"
                    if scenario.startswith("ws-")
                    else "page.external_watchdog"
                )
                if (
                    passed
                    and scenario
                    in chaos_evidence.AUTOMATED_EXACT_RELEASE_SCENARIOS
                )
                else ("page.independent_chaos_fault" if passed else "")
            ),
            "fault_correlation": scenario if passed else "",
            "provider_event_id": "provider-event-1" if passed else "",
            "provider_artifact_sha256": "7" * 64 if passed else "",
            "provider_received_at": (
                started.timestamp() + 2 if passed else None
            ),
            "human_ack_at": (
                started.timestamp() + 3 if passed else None
            ),
        },
        "postcondition": {
            "journal_integrity": "ok" if passed else "unknown",
            "mode": "ready" if passed else "",
            "duplicate_buy_count": 0,
            "uncovered_instruments": [],
            "pending_order_count": 0,
            "pending_algo_count": 0,
            "local_nonzero_position_count": 0,
            "balances": {"USDT": "100"},
            "residual_risk": [] if passed else ["not_executed"],
            "startup_reconciliation_seconds": (
                10 if spec.startup_ready_max_seconds is not None else None
            ),
        },
        "errors": errors,
        "passed": passed,
    }
    if scenario in chaos_evidence.RAW_RECOMPUTED_SCENARIOS:
        receipt["execution"]["raw_observation"] = {
            "payload": {
                "version": 2,
                "action": "attest-stage-c-derived-raw-evidence-v2",
                "scenario": scenario,
                "challenge_id": receipt["execution"]["run_id"],
                "consumption_receipt_sha256": "4" * 64,
                "observer_id": "independent-chaos-observer",
                "observer_key_fingerprint": "9" * 64,
                "source": {
                    "collector": "isolated-fault-orchestrator",
                    "object_uri": (
                        f"s3://evidence/raw-observations/{scenario}.jsonl"
                    ),
                    "version_id": f"{scenario}-raw-version-1",
                    "sha256": "8" * 64,
                    "bytes": 1024,
                },
                "raw_event_protocol": (
                    "okx-quant.stage-c-native-event/v1"
                ),
                "driver_contract_sha256": "6" * 64,
                "parser_manifest_sha256": "5" * 64,
                "identity": receipt["identity"],
                "workloads": {
                    "systemd_collector": {
                        "host_id": "isolated-linux-host",
                    },
                },
                "started_at": receipt["started_at"],
                "completed_at": receipt["completed_at"],
                "fault_mechanism": receipt["execution"][
                    "fault_mechanism"
                ],
                "actual_transitions": receipt["actual_transitions"],
                "reconciliation": receipt["reconciliation"],
                "page_receipt": receipt["page_receipt"],
                "postcondition": receipt["postcondition"],
                "errors": receipt["errors"],
                "passed": receipt["passed"],
            },
            "signature": base64.b64encode(bytes(64)).decode("ascii"),
        }
    return receipt


def _full_matrix(started: datetime) -> list[dict]:
    return [_receipt(spec.name, started=started) for spec in DRILL_SCENARIOS]


def _key_pair(tmp_path, name="bundle"):
    private_key = tmp_path / f"{name}-private.pem"
    public_key = tmp_path / f"{name}-public.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
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


def _protocol_identity(scenario: str) -> dict:
    barrier = scenario in chaos_evidence.INSTRUMENTED_BARRIER_SCENARIOS
    build = _barrier_build_bundle() if barrier else None
    candidate = _stage_c_candidate_identity(
        instrumented_artifact_sha256=(
            build["artifact_sha256"] if build is not None else "d" * 64
        ),
    )
    if barrier:
        candidate["instrumented"]["account_uid"] = "barrier-harness-account"
    return {
        **{
            **_RELEASE,
            "source_manifest_sha256": (
                build["source_manifest_sha256"]
                if build is not None
                else _RELEASE["source_manifest_sha256"]
            ),
        },
        "artifact_sha256": (
            build["artifact_sha256"] if build is not None else "c" * 64
        ),
        "artifact_build_id": (
            "test-only:stage-c-barrier"
            if barrier
            else "exact-release:stage-c-native"
        ),
        "config_sha256": "e" * 64,
        "account_uid": (
            "barrier-harness-account" if barrier else "demo-chaos-account"
        ),
        "environment": "demo",
        "unit": (
            "okx-quant-instrumented-test.service"
            if barrier
            else "okx-quant-demo-chaos.service"
        ),
        "soak_epoch_id": _EPOCH,
        "stage_c_chaos_deployment_identity_sha256": (
            stage_c_chaos_deployment_identity_sha256(candidate)
        ),
        "workspace_clean": True,
        "test_hooks_present": barrier,
    }


def _protocol_workload(role: str, index: int) -> dict:
    return {
        "host_id": f"stage-c-{role}-host",
        "boot_id": f"00000000-0000-0000-0000-{index + 1:012d}",
        "systemd_invocation_id": (
            f"10000000-0000-0000-0000-{index + 1:012d}"
        ),
        "pid": 2000 + index,
        "uid": 3000 + index,
        "cgroup": f"/system.slice/stage-c-{role}.service",
        "executable_sha256": f"{index + 1:064x}",
        "parser_manifest_sha256": (
            stage_c_protocol.PARSER_MANIFEST_SHA256
        ),
        "iam_principal_arn": (
            "arn:aws:sts::123456789012:"
            f"assumed-role/stage-c-{role}/session-{index}"
        ),
        "iam_account_id": "123456789012",
        "iam_session_id": f"stage-c-session-{index}",
    }


def _protocol_native_attestation(workload: dict) -> dict:
    unit = workload["cgroup"].removeprefix("/system.slice/")
    executable = f"/opt/okx-quant-stage-c/{unit}"
    return {
        "systemd_show": stage_c_protocol._opaque_bytes_descriptor(
            (
                f"Id={unit}\n"
                f"InvocationID={workload['systemd_invocation_id']}\n"
                f"MainPID={workload['pid']}\n"
                f"ControlGroup={workload['cgroup']}\n"
            ).encode()
        ),
        "proc_status": stage_c_protocol._opaque_bytes_descriptor(
            (
                "Name:\tstage-c\n"
                f"Pid:\t{workload['pid']}\n"
                f"Uid:\t{workload['uid']}\t{workload['uid']}\t"
                f"{workload['uid']}\t{workload['uid']}\n"
            ).encode()
        ),
        "proc_cgroup": stage_c_protocol._opaque_bytes_descriptor(
            f"0::{workload['cgroup']}\n".encode()
        ),
        "proc_exe": stage_c_protocol._opaque_bytes_descriptor(
            f"{executable}\n".encode()
        ),
        "boot_id": stage_c_protocol._opaque_bytes_descriptor(
            f"{workload['boot_id']}\n".encode()
        ),
        "machine_id": stage_c_protocol._opaque_bytes_descriptor(
            f"{workload['host_id']}\n".encode()
        ),
        "executable_sha256sum": (
            stage_c_protocol._opaque_bytes_descriptor(
                (
                    f"{workload['executable_sha256']}  {executable}\n"
                ).encode()
            )
        ),
        "sts_get_caller_identity": (
            stage_c_protocol._opaque_bytes_descriptor(
                json.dumps(
                    {
                        "UserId": workload["iam_session_id"],
                        "Account": workload["iam_account_id"],
                        "Arn": workload["iam_principal_arn"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            )
        ),
    }


def _scenario_native_facts(
    scenario: str,
    kind: str,
    *,
    challenge: dict,
    observed_at: str,
    source_private_keys: dict,
    reached_artifact: dict | None = None,
) -> dict:
    if kind == "exchange.order.partial":
        return {
            "ord_id": "ord-1",
            "cl_ord_id": "cl-1",
            "acc_fill_qty": "0.01",
            "state": "partially_filled",
        }
    if kind == "gateway.disconnected":
        return {"channel": "private", "generation": 3}
    if kind == "exchange.order.cumulative_fill":
        return {
            "ord_id": "ord-1",
            "acc_fill_qty": "0.02",
            "trade_ids": ["trade-1", "trade-2"],
        }
    if kind == "gateway.rest_baseline.completed":
        return {
            "channel": (
                "private"
                if scenario == "ws-partial-fill-recovery"
                else "business"
            ),
            "generation": (
                4 if scenario == "ws-partial-fill-recovery" else 9
            ),
            "safe": True,
        }
    if kind == "exchange.protection.active":
        if scenario == "external-fill":
            return {
                "algo_id": "algo-1",
                "algo_cl_ord_id": "algo-client-1",
                "inst_id": "BTC-USDT",
                "position_qty": "0.010009",
                "protected_qty": "0.01",
                "lot_size": "0.00001",
                "state": "live",
            }
        return {
            "algo_id": "algo-1",
            "ord_id": "ord-1",
            "protected_qty": (
                "0.02"
                if scenario == "ws-partial-fill-recovery"
                else "0.01"
            ),
            "state": "live",
        }
    if kind == "exchange.order.external_pending":
        return {
            "ord_id": "ord-ext",
            "cl_ord_id": "cl-ext",
            "side": "buy",
            "state": "live",
            "origin": "external",
        }
    if kind == "runtime.entry_frozen":
        return {"mode": "halted", "new_buy_count": 0}
    if kind == "exchange.fill.external":
        return {
            "ord_id": "ord-1",
            "cl_ord_id": "cl-1",
            "inst_id": "BTC-USDT",
            "trade_ids": ["trade-ext-1", "trade-ext-2"],
            "side": "buy",
            "qty": "0.010009",
            "origin": "external",
        }
    if kind == "exchange.protection.canceled":
        return {
            "algo_id": "algo-1",
            "algo_cl_ord_id": "algo-client-1",
            "inst_id": "BTC-USDT",
            "observed_order_id": "ord-1",
            "observed_cl_ord_id": "cl-1",
            "state": "canceled",
            "origin": "external",
        }
    if kind == "journal.protection_ownership":
        return {
            "parent_intent_id": "intent-1",
            "parent_cl_ord_id": "cl-1",
            "parent_ord_id": "ord-1",
            "inst_id": "BTC-USDT",
            "algo_cl_ord_id": "algo-client-1",
            "algo_id": "algo-1",
            "protected_qty": "0.01",
            "state": "active",
            "updated_at": 1_785_240_000,
            "snapshot_sha256": "9" * 64,
        }
    if kind == "runtime.emergency_exit":
        return {"mode": "emergency_exit", "algo_id": "algo-1"}
    if kind == "exchange.balance.frozen":
        return {
            "inst_id": "BTC-USDT",
            "ccy": "BTC",
            "total": "0.01",
            "available": "0",
            "locking_order_ids": ["ord-lock"],
        }
    if kind == "journal.position_preserved":
        return {"inst_id": "BTC-USDT", "base_qty": "0.01"}
    if kind == "exchange.clordid_conflict":
        return {
            "cl_ord_id": "cl-conflict",
            "local_intent_id": "intent-local",
            "exchange_ord_id": "ord-external",
        }
    if kind == "runtime.manual_review":
        return {
            "mode": "manual_review",
            "retry_count": 0,
            "cl_ord_id": "cl-conflict",
        }
    if kind == "proxy.ambiguous_write":
        return {
            "method": "POST",
            "status_code": 503,
            "request_id": "request-1",
            "bytes_sent": True,
            "response_ambiguous": True,
        }
    if kind == "journal.intent_unknown":
        return {
            "cl_ord_id": "cl-unknown",
            "state": "unknown",
            "retry_count": 0,
        }
    if kind == "journal.intent_resolved":
        return {
            "cl_ord_id": "cl-unknown",
            "state": "filled",
            "duplicate_buy_count": 0,
        }
    if kind == "exchange.protection.before_process_death":
        return {"algo_id": "algo-oco", "state": "live"}
    if (
        kind == "systemd.process_killed"
        and scenario not in chaos_evidence.INSTRUMENTED_BARRIER_SCENARIOS
    ):
        workload = challenge["workloads"]["fault_driver"]
        return {
            "old_pid": workload["pid"],
            "signal": "SIGKILL",
            "systemd_invocation_id": workload[
                "systemd_invocation_id"
            ],
        }
    if kind == "exchange.protection.after_process_death":
        return {
            "algo_id": "algo-oco",
            "state": "live",
            "verified_by": "okx_rest",
        }
    if kind == "runtime.restart_reconciled":
        old_pid = challenge["workloads"]["fault_driver"]["pid"]
        return {
            "old_pid": old_pid,
            "new_pid": old_pid + 100,
            "mode": "ready",
            "run_id": "reconcile-restart",
        }
    if kind == "gateway.fault_control.blocked":
        return {
            "channel": "business",
            "state": "blocked",
            "control_inode": 12345,
        }
    if kind == "systemd.restart_requested":
        workload = challenge["workloads"]["fault_driver"]
        return {
            "old_pid": workload["pid"],
            "systemd_invocation_id": workload[
                "systemd_invocation_id"
            ],
        }
    if kind == "runtime.not_ready":
        return {
            "ready": False,
            "mode": "starting",
            "pid": challenge["workloads"]["fault_driver"]["pid"]
            + 100,
        }
    if kind == "journal.corruption_detected":
        return {
            "database_sha256": "1" * 64,
            "integrity_result": "database disk image is malformed",
        }
    if kind == "runtime.halted":
        return {"mode": "halted", "reason": "database_corrupt"}
    if kind == "backup.exact_version_restored":
        return {
            "object_uri": "s3://evidence/backup.db.enc",
            "version_id": "backup-version-1",
            "sha256": "2" * 64,
            "bytes": 4096,
            "kms_key_id": "kms-stage-c",
            "retain_until": "2027-07-28T00:00:00+00:00",
            "restored_database_sha256": "3" * 64,
            "integrity_result": "ok",
        }
    if kind == "runtime.ready_after_restore":
        return {"mode": "ready", "database_sha256": "3" * 64}
    if kind == "build.instrumented_provenance":
        identity = challenge["identity"]
        build = _barrier_build_bundle()
        return {
            "source_manifest_sha256": identity[
                "source_manifest_sha256"
            ],
            "artifact_sha256": identity["artifact_sha256"],
            "artifact_build_id": identity["artifact_build_id"],
            "sbom_sha256": build["sbom_sha256"],
            "hook_sha256": build["hook_sha256"],
            "test_hooks_present": True,
            "production_env_enableable": False,
            "instrumented_artifact": (
                stage_c_protocol._opaque_bytes_descriptor(
                    build["instrumented"]
                )
            ),
            "instrumented_manifest": (
                stage_c_protocol._opaque_bytes_descriptor(
                    build["instrumented_manifest"]
                )
            ),
            "instrumented_sbom": (
                stage_c_protocol._opaque_bytes_descriptor(
                    build["instrumented_sbom"]
                )
            ),
            "exact_release_artifact": (
                stage_c_protocol._opaque_bytes_descriptor(build["exact"])
            ),
            "exact_release_manifest": (
                stage_c_protocol._opaque_bytes_descriptor(
                    build["exact_manifest"]
                )
            ),
            "exact_release_sbom": (
                stage_c_protocol._opaque_bytes_descriptor(
                    build["exact_sbom"]
                )
            ),
        }
    if kind == "barrier.armed":
        return {
            "barrier": stage_c_protocol.SCENARIO_PROTOCOLS[
                scenario
            ].barrier_name,
            "nonce": challenge["barrier_nonce"],
            "hook_sha256": _barrier_build_bundle()["hook_sha256"],
        }
    if kind == "journal.intent_persisted":
        return {
            "cl_ord_id": "cl-barrier",
            "state": "BUY_SUBMITTING",
            "db_committed": True,
        }
    if kind == "barrier.reached":
        barrier = stage_c_protocol.SCENARIO_PROTOCOLS[
            scenario
        ].barrier_name
        artifact = sign_ed25519_payload(
            {
                "version": 2,
                "action": "attest-stage-c-barrier-reached-v2",
                "challenge_id": challenge["challenge_id"],
                "scenario": scenario,
                "barrier": barrier,
                "nonce": challenge["barrier_nonce"],
                "artifact_sha256": challenge["identity"]["artifact_sha256"],
                "pid": challenge["workloads"]["fault_driver"]["pid"],
                "systemd_invocation_id": challenge["workloads"][
                    "fault_driver"
                ]["systemd_invocation_id"],
                "observed_at": observed_at,
                "monotonic_ns": 123456789,
                "marker_sha256": "1" * 64,
                "boundary_proof_sha256": "2" * 64,
                "phase_consumption_sha256": "3" * 64,
            },
            source_private_keys["barrier_attestor"],
        )
        return {"attestation": artifact}
    if (
        kind == "systemd.process_killed"
        and scenario in chaos_evidence.INSTRUMENTED_BARRIER_SCENARIOS
    ):
        barrier = stage_c_protocol.SCENARIO_PROTOCOLS[
            scenario
        ].barrier_name
        artifact = sign_ed25519_payload(
            {
                "version": 2,
                "action": "attest-stage-c-process-kill-v2",
                "challenge_id": challenge["challenge_id"],
                "scenario": scenario,
                "barrier": barrier,
                "nonce": challenge["barrier_nonce"],
                "artifact_sha256": challenge["identity"]["artifact_sha256"],
                "old_pid": challenge["workloads"]["fault_driver"]["pid"],
                "signal": "SIGKILL",
                "reached_artifact_sha256": hashlib.sha256(
                    canonical_bytes(reached_artifact)
                ).hexdigest(),
                "reached_consumption_sha256": "4" * 64,
                "kill_consumption_sha256": "5" * 64,
                "kill_command": stage_c_protocol._opaque_bytes_descriptor(
                    b'{"signal":"SIGKILL"}'
                ),
                "kill_response": stage_c_protocol._opaque_bytes_descriptor(
                    b"\n"
                ),
                "inactive_systemd_show": (
                    stage_c_protocol._opaque_bytes_descriptor(
                        b"MainPID=0\nActiveState=failed\nSubState=failed\n"
                    )
                ),
                "old_process_inactive": True,
                "observed_at": observed_at,
            },
            source_private_keys["kill_controller"],
        )
        return {"attestation": artifact}
    if kind == "runtime.recovery_started":
        old_pid = challenge["workloads"]["fault_driver"]["pid"]
        return {
            "old_pid": old_pid,
            "new_pid": old_pid + 100,
            "boot_id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "systemd_invocation_id": (
                "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
            ),
            "snapshot_sha256": "a" * 64,
        }
    if kind == "exchange.order.absent":
        return {
            "cl_ord_id": "cl-barrier",
            "lookup_sources": ["pending", "history", "fills"],
        }
    if kind == "journal.intent_rejected_no_exchange_order":
        return {
            "cl_ord_id": "cl-barrier",
            "state": "REJECTED",
            "buy_post_count": 0,
        }
    if kind == "http.order_post_written":
        return {
            "cl_ord_id": "cl-barrier",
            "request_sha256": "6" * 64,
            "socket_write_completed": True,
        }
    if kind == "exchange.order.by_clordid":
        return {
            "cl_ord_id": "cl-barrier",
            "ord_id": "ord-barrier",
            "state": "filled",
        }
    if kind == "journal.clordid_resolved_without_duplicate":
        return {
            "cl_ord_id": "cl-barrier",
            "ord_id": "ord-barrier",
            "duplicate_buy_count": 0,
        }
    if kind == "exchange.fill.observed":
        return {
            "ord_id": "ord-barrier",
            "trade_id": "trade-barrier",
            "qty": "0.01",
        }
    if kind == "journal.projection_absent":
        return {"ord_id": "ord-barrier", "fill_apply_count": 0}
    if kind == "journal.fill_projection_recovered":
        return {
            "ord_id": "ord-barrier",
            "trade_id": "trade-barrier",
            "fill_apply_count": 1,
            "protection_state": "active",
        }
    raise AssertionError(f"missing fixture facts for {scenario}/{kind}")


def _build_protocol_receipt(tmp_path, scenario: str) -> tuple[dict, dict]:
    now = 1_785_240_000
    identity = _protocol_identity(scenario)
    roles = stage_c_protocol.required_source_roles(scenario)
    source_key_pairs = {
        role: _key_pair(tmp_path, f"{scenario}-{role}")
        for role in sorted(roles)
    }
    source_private = {
        role: pair[0] for role, pair in source_key_pairs.items()
    }
    source_public = {
        role: pair[1] for role, pair in source_key_pairs.items()
    }
    workloads = {
        role: _protocol_workload(role, index)
        for index, role in enumerate(sorted(roles))
    }
    workloads["fault_driver"]["cgroup"] = (
        f"/system.slice/{identity['unit']}"
    )
    if scenario in chaos_evidence.INSTRUMENTED_BARRIER_SCENARIOS:
        workloads["fault_driver"]["executable_sha256"] = (
            hashlib.sha256(b"stage-c-python-interpreter").hexdigest()
        )
    native_attestations = {
        role: _protocol_native_attestation(workload)
        for role, workload in workloads.items()
    }
    capability_private, capability_public = _key_pair(
        tmp_path,
        f"{scenario}-capability-authority",
    )
    registrar_private, registrar_public = _key_pair(
        tmp_path,
        f"{scenario}-registrar",
    )
    capability = stage_c_protocol.build_stage_c_capability_attestation(
        scenario=scenario,
        identity=identity,
        native_attestations=native_attestations,
        source_public_keys=source_public,
        authority_private_key=capability_private,
        now=now,
    )
    recovery_bindings = None
    okx_observer_bindings = None
    if scenario in chaos_evidence.INSTRUMENTED_BARRIER_SCENARIOS:
        recovery_bindings = {
            "observer_api_key_fingerprint": "f" * 64,
            "tls_certificate_sha256": (
                "7" * 64 if scenario == "barrier-post-before-ack" else None
            ),
            "tls_spki_sha256": (
                "8" * 64 if scenario == "barrier-post-before-ack" else None
            ),
        }
    else:
        okx_observer_bindings = {
            "observer_api_key_fingerprint": "f" * 64,
            "tls_certificate_sha256": "7" * 64,
            "tls_spki_sha256": "8" * 64,
        }
    challenge_artifact = stage_c_protocol.issue_stage_c_challenge(
        scenario=scenario,
        capability_attestation=capability,
        capability_authority_public_key=capability_public,
        registrar_private_key=registrar_private,
        consumption_backend={
            "kind": "dynamodb-conditional-put-v1",
            "table_name": "stage-c-consumption",
            "region": "us-east-1",
            "account_id": "123456789012",
        },
        okx_observer_bindings=okx_observer_bindings,
        barrier_recovery_bindings=recovery_bindings,
        now=now,
    )
    challenge = challenge_artifact["payload"]
    consumption_item = stage_c_protocol._consumption_item(
        challenge_artifact,
        challenge,
    )
    consumption_receipt = (
        stage_c_protocol.build_stage_c_consumption_receipt(
            challenge_artifact=challenge_artifact,
            registrar_public_key=registrar_public,
            consumer_private_key=source_private["challenge_consumer"],
            conditional_put_response=json.dumps({
                "ConsumedCapacity": {
                    "TableName": "stage-c-consumption",
                }
            }).encode(),
            consistent_read_response=json.dumps({
                "Item": consumption_item,
            }).encode(),
            consumed_at=now,
        )
    )
    events = [{
        "schema": stage_c_protocol.RAW_EVENT_SCHEMA,
        "scenario": scenario,
        "challenge_id": challenge["challenge_id"],
        "seq": 0,
        "observed_at": datetime.fromtimestamp(now, UTC).isoformat(),
        "monotonic_ns": 1_000_000_000,
        "source": "registrar",
        "kind": "challenge.accepted",
        "payload": {
            "artifact": challenge_artifact,
            "consumption_receipt": consumption_receipt,
        },
    }]
    event_kinds = [
        "driver.invoked",
        "clock.sample",
        *stage_c_protocol.SCENARIO_PROTOCOLS[scenario].required_events,
        "reconciliation.completed",
        "page.provider_receipt",
        "journal.integrity",
        "journal.duplicate_buy_audit",
        "journal.positions",
        "exchange.pending_orders",
        "exchange.pending_algos",
        "exchange.balances",
        "runtime.mode",
    ]
    if scenario in {
        "oco-active-process-death",
        "restart-while-ws-down",
    } and "startup.reconciliation" not in event_kinds:
        event_kinds.append("startup.reconciliation")
    event_kinds.append("run.completed")
    barrier_reached_artifact = None
    for seq, kind in enumerate(event_kinds, start=1):
        observed_at = (
            datetime.fromtimestamp(now, UTC)
            + timedelta(milliseconds=100 * seq)
        ).isoformat()
        if kind == "driver.invoked":
            facts = {
                "driver_id": stage_c_protocol.SCENARIO_PROTOCOLS[
                    scenario
                ].driver_id,
                "workload": workloads["fault_driver"],
                "driver_contract_sha256": challenge[
                    "driver_contract_sha256"
                ],
                "capability_attestation": capability,
            }
        elif kind == "clock.sample":
            facts = {"ntp_synchronized": True, "max_error_ms": 10}
        elif kind == "reconciliation.completed":
            facts = {
                "run_id": "reconciliation-1",
                "status": "ok",
                "mismatch_count": 1,
                "repaired_count": 1,
                "unresolved": [],
            }
        elif kind == "page.provider_receipt":
            provider_receipt = sign_ed25519_payload(
                {
                    "version": 1,
                    "action": "attest-stage-c-provider-receipt-v1",
                    "challenge_id": challenge["challenge_id"],
                    "event_id": "page-event-1",
                    "event_name": "page.stage_c_fault",
                    "fault_correlation": scenario,
                    "provider_event_id": "provider-event-1",
                    "provider_received_at": observed_at,
                    "human_ack_at": None,
                },
                source_private["provider_receipt_authority"],
            )
            facts = {"artifact": provider_receipt}
        elif kind == "journal.integrity":
            facts = {"result": "ok", "database_sha256": "7" * 64}
        elif kind == "journal.duplicate_buy_audit":
            facts = {"count": 0, "intent_ids": []}
        elif kind == "journal.positions":
            facts = {"positions": []}
        elif kind == "exchange.pending_orders":
            facts = {"order_ids": []}
        elif kind == "exchange.pending_algos":
            facts = {"algo_ids": []}
        elif kind == "exchange.balances":
            facts = {"balances": {"USDT": "100"}}
        elif kind == "runtime.mode":
            facts = {"mode": "ready"}
        elif kind == "startup.reconciliation":
            facts = {"seconds": 10}
        elif kind == "run.completed":
            facts = {"outcome": "completed"}
        else:
            facts = _scenario_native_facts(
                scenario,
                kind,
                challenge=challenge,
                observed_at=observed_at,
                source_private_keys=source_private,
                reached_artifact=barrier_reached_artifact,
            )
            if kind == "barrier.reached":
                barrier_reached_artifact = facts["attestation"]
        source = stage_c_protocol._expected_source(scenario, kind)
        native_request = (
            stage_c_protocol.build_fixture_native_request_evidence(
                source=source,
                kind=kind,
                observed_at=observed_at,
                workload=workloads[source],
                request_id=f"{scenario}:{kind}:{seq}",
            )
        )
        events.append(stage_c_protocol.build_fixture_signed_native_event(
            scenario=scenario,
            challenge_id=challenge["challenge_id"],
            seq=seq,
            observed_at=observed_at,
            monotonic_ns=1_000_000_000 + seq * 100_000_000,
            source=source,
            kind=kind,
            facts=facts,
            workload=workloads[source],
            source_private_key=source_private[source],
            native_request=native_request,
        ))
    raw_bytes = b"".join(canonical_bytes(event) + b"\n" for event in events)
    derived = stage_c_protocol.derive_stage_c_raw_observation(
        raw_bytes,
        scenario=scenario,
        registrar_public_key=registrar_public,
        capability_authority_public_key=capability_public,
        provider_public_key=source_public["provider_receipt_authority"],
        raw_observer_public_key=source_public["parser_signer"],
        source_public_keys=source_public,
        barrier_attestor_public_key=source_public.get(
            "barrier_attestor"
        ),
        kill_controller_public_key=source_public.get("kill_controller"),
    )
    observation = stage_c_protocol.build_stage_c_raw_observation_artifact(
        derived,
        source={
            "collector": "stage-c-native-jsonl-collector/v1",
            "object_uri": f"s3://evidence/raw/{scenario}.jsonl",
            "version_id": f"{scenario}-version-1",
            "sha256": derived["raw_sha256"],
            "bytes": derived["raw_bytes"],
        },
        observer_id="stage-c-parser",
        observer_private_key=source_private["parser_signer"],
    )
    receipt = stage_c_protocol.build_stage_c_drill_receipt(
        derived,
        raw_observation_artifact=observation,
    )
    context = {
        "raw_bytes": raw_bytes,
        "events": events,
        "events_by_kind": {
            event["kind"]: event for event in events
        },
        "challenge": challenge_artifact,
        "capability": capability,
        "identity": identity,
        "registrar_public": registrar_public,
        "registrar_private": registrar_private,
        "capability_public": capability_public,
        "capability_private": capability_private,
        "source_public": source_public,
        "source_private": source_private,
        "workloads": workloads,
        "native_attestations": native_attestations,
    }
    return receipt, context


def test_pipeline_activation_binds_distinct_fault_driver_workload(tmp_path):
    scenario = "barrier-buy-intent-before-post"
    _receipt, context = _build_protocol_receipt(tmp_path, scenario)
    build = _barrier_build_bundle()
    archive = tmp_path / "instrumented.pyz"
    archive.write_bytes(build["instrumented"])
    interpreter = tmp_path / "python"
    interpreter.write_bytes(b"stage-c-python-interpreter")
    challenge_artifact = context["challenge"]
    request = {
        "schema": stage_c_pipeline.PIPELINE_ACTIVATION_REQUEST_SCHEMA,
        "scenario": scenario,
        "challenge_artifact": challenge_artifact,
        "consumption_receipt": context["events"][0]["payload"][
            "consumption_receipt"
        ],
    }
    driver = context["workloads"]["fault_driver"]
    argv = stage_c_pipeline.fixed_pipeline_main_argv(
        config=(tmp_path / "config.yaml").resolve(),
        env_file=(tmp_path / "environment").resolve(),
        inst_id="BTC-USDT",
    )
    challenge, activation = stage_c_pipeline.verify_pipeline_activation(
        request,
        scenario=scenario,
        registrar_public_key=context["registrar_public"],
        challenge_consumer_public_key=context["source_public"][
            "challenge_consumer"
        ],
        fault_driver_private_key=context["source_private"]["fault_driver"],
        config_sha256=context["identity"]["config_sha256"],
        account_uid=context["identity"]["account_uid"],
        api_key_fingerprint="f" * 64,
        api_permissions=("read", "trade"),
        main_argv=argv,
        archive_path=archive,
        interpreter_path=interpreter,
        actual_pid=driver["pid"],
        actual_uid=driver["uid"],
        actual_cgroup=driver["cgroup"],
        actual_invocation_id=driver["systemd_invocation_id"],
        activated_at=1_785_240_000,
    )
    claims = verify_ed25519_artifact(
        activation,
        context["source_public"]["fault_driver"],
        label="fault driver activation",
    )
    assert challenge == challenge_artifact["payload"]
    assert claims["pid"] == driver["pid"]
    assert claims["instrumented_artifact_sha256"] == build[
        "artifact_sha256"
    ]
    assert claims["main_argv"] == argv

    killed = sign_ed25519_payload(
        {
            "version": 2,
            "action": "attest-stage-c-process-kill-v2",
            "challenge_id": challenge["challenge_id"],
            "scenario": scenario,
            "barrier": "buy-intent-before-post",
            "nonce": challenge["barrier_nonce"],
            "artifact_sha256": challenge["identity"]["artifact_sha256"],
            "old_pid": driver["pid"],
            "reached_artifact_sha256": "9" * 64,
            "kill_command": stage_c_protocol._opaque_bytes_descriptor(
                b'{"signal":"SIGKILL"}'
            ),
            "kill_response": stage_c_protocol._opaque_bytes_descriptor(b"\n"),
            "inactive_systemd_show": (
                stage_c_protocol._opaque_bytes_descriptor(
                    (
                        f"MainPID=0\nInvocationID={driver['systemd_invocation_id']}\n"
                        "ActiveState=failed\nSubState=failed\n"
                    ).encode()
                )
            ),
            "old_process_inactive": True,
            "observed_at": datetime.fromtimestamp(
                1_785_240_001,
                UTC,
            ).isoformat(),
        },
        context["source_private"]["kill_controller"],
    )
    _recovery_challenge, recovery_activation = (
        stage_c_pipeline.verify_pipeline_recovery_activation(
            request,
            scenario=scenario,
            registrar_public_key=context["registrar_public"],
            challenge_consumer_public_key=context["source_public"][
                "challenge_consumer"
            ],
            kill_artifact=killed,
            kill_public_key=context["source_public"]["kill_controller"],
            fault_driver_private_key=context["source_private"][
                "fault_driver"
            ],
            config_sha256=context["identity"]["config_sha256"],
            account_uid=context["identity"]["account_uid"],
            api_key_fingerprint="f" * 64,
            api_permissions=("read", "trade"),
            main_argv=argv,
            archive_path=archive,
            interpreter_path=interpreter,
            actual_pid=driver["pid"] + 1000,
            actual_uid=driver["uid"],
            actual_cgroup=driver["cgroup"],
            actual_invocation_id=(
                "99999999-9999-9999-9999-999999999999"
            ),
            activated_at=1_785_240_002,
        )
    )
    recovery_claims = verify_ed25519_artifact(
        recovery_activation,
        context["source_public"]["fault_driver"],
        label="fault driver recovery activation",
    )
    assert recovery_claims["old_pid"] == driver["pid"]
    assert recovery_claims["new_pid"] == driver["pid"] + 1000

    collector = context["workloads"]["systemd_collector"]
    with pytest.raises(ValueError, match="fault driver"):
        stage_c_pipeline.verify_pipeline_activation(
            request,
            scenario=scenario,
            registrar_public_key=context["registrar_public"],
            challenge_consumer_public_key=context["source_public"][
                "challenge_consumer"
            ],
            fault_driver_private_key=context["source_private"][
                "fault_driver"
            ],
            config_sha256=context["identity"]["config_sha256"],
            account_uid=context["identity"]["account_uid"],
            api_key_fingerprint="f" * 64,
            api_permissions=("read", "trade"),
            main_argv=argv,
            archive_path=archive,
            interpreter_path=interpreter,
            actual_pid=collector["pid"],
            actual_uid=collector["uid"],
            actual_cgroup=collector["cgroup"],
            actual_invocation_id=collector["systemd_invocation_id"],
            activated_at=1_785_240_000,
        )


def _protocol_raw_bytes(events: list[dict]) -> bytes:
    return b"".join(canonical_bytes(event) + b"\n" for event in events)


def test_stage_c_raw_jsonl_rejects_duplicate_or_noncanonical_event_keys(
    tmp_path,
):
    """The final parser must consume one fixed JSONL representation."""
    scenario = "external-fill"
    _receipt, context = _build_protocol_receipt(tmp_path, scenario)
    first = json.loads(context["raw_bytes"].splitlines()[0])
    # Duplicate top-level keys must not be interpreted with JSON's
    # last-key-wins behaviour.
    duplicate = (
        b'{"challenge_id":"' + first["challenge_id"].encode()
        + b'","challenge_id":"' + first["challenge_id"].encode()
        + b'","kind":"challenge.accepted","monotonic_ns":0,'
        b'"observed_at":"' + first["observed_at"].encode()
        + b'","payload":{},"schema":"' + first["schema"].encode()
        + b'","scenario":"' + scenario.encode()
        + b'","seq":0,"source":"registrar"}'
    )
    with pytest.raises(ValueError, match="JSON 非法"):
        stage_c_protocol._parse_events(duplicate, scenario)
    # Whitespace/order changes are also rejected even when the decoded object
    # has the expected fields; only canonical_bytes(event) is accepted.
    noncanonical = json.dumps(first, sort_keys=True).encode()
    assert noncanonical != canonical_bytes(first)
    with pytest.raises(ValueError, match="canonical JSONL"):
        stage_c_protocol._parse_events(noncanonical, scenario)


def _derive_protocol_context(
    context: dict,
    *,
    scenario: str,
    raw_bytes: bytes,
    require_live_exact_release: bool = False,
) -> dict:
    return stage_c_protocol.derive_stage_c_raw_observation(
        raw_bytes,
        scenario=scenario,
        registrar_public_key=context["registrar_public"],
        capability_authority_public_key=context["capability_public"],
        provider_public_key=context["source_public"]["provider"],
        raw_observer_public_key=context["source_public"][
            "parser_signer"
        ],
        source_public_keys=context["source_public"],
        barrier_attestor_public_key=context["source_public"].get(
            "barrier_attestor"
        ),
        kill_controller_public_key=context["source_public"].get(
            "kill_controller"
        ),
        require_live_exact_release=require_live_exact_release,
    )


def test_stage_c_production_parser_rejects_resigned_canonical_facts(
    tmp_path,
):
    scenario = "external-fill"
    _receipt, context = _build_protocol_receipt(tmp_path, scenario)
    # Every event is correctly signed by its challenge-bound source key, but
    # this stream carries fixture canonical facts rather than live request /
    # response acquisitions.  Production recomputation must reject it.
    with pytest.raises(ValueError, match="canonical facts"):
        _derive_protocol_context(
            context,
            scenario=scenario,
            raw_bytes=context["raw_bytes"],
            require_live_exact_release=True,
        )


def test_stage_c_production_barrier_parser_also_requires_live_bytes(tmp_path):
    scenario = "barrier-buy-intent-before-post"
    _receipt, context = _build_protocol_receipt(tmp_path, scenario)
    with pytest.raises(ValueError, match="live acquisition bytes"):
        _derive_protocol_context(
            context,
            scenario=scenario,
            raw_bytes=context["raw_bytes"],
            require_live_exact_release=True,
        )


def _resign_protocol_event(
    context: dict,
    *,
    scenario: str,
    event: dict,
    facts: dict,
) -> dict:
    source = event["source"]
    native_request = stage_c_protocol._decode_native_bytes(
        event["payload"]["artifact"]["payload"]["native_request"],
        "fixture native request",
    )
    return stage_c_protocol.build_fixture_signed_native_event(
        scenario=scenario,
        challenge_id=event["challenge_id"],
        seq=event["seq"],
        observed_at=event["observed_at"],
        monotonic_ns=event["monotonic_ns"],
        source=source,
        kind=event["kind"],
        facts=facts,
        workload=context["workloads"][source],
        source_private_key=context["source_private"][source],
        native_request=native_request,
    )


@pytest.mark.parametrize(
    "scenario",
    sorted(stage_c_protocol.SCENARIO_PROTOCOLS),
)
def test_stage_c_native_protocol_derives_all_registered_scenarios(
    tmp_path,
    scenario,
):
    receipt, context = _build_protocol_receipt(tmp_path, scenario)

    validated = validate_drill_receipt(receipt)
    assert validated["scenario"] == scenario
    assert validated["passed"] is True
    raw_sha256 = hashlib.sha256(context["raw_bytes"]).hexdigest()
    assert all(
        transition["evidence_ids"]
        == [
            f"raw-sha256:{raw_sha256}:seq:"
            f"{context['events_by_kind'][event_kind]['seq']}"
        ]
        for transition, (_transition_id, event_kind) in zip(
            validated["actual_transitions"],
            stage_c_protocol.SCENARIO_PROTOCOLS[
                scenario
            ].transition_events,
            strict=True,
        )
    )


def test_production_loader_locally_recomputes_raw_with_all_trust_roots(
    tmp_path,
):
    scenario = "external-fill"
    receipt, context = _build_protocol_receipt(tmp_path, scenario)
    raw_path = tmp_path / f"{scenario}.jsonl"
    raw_path.write_bytes(context["raw_bytes"])

    with pytest.raises(ValueError, match="canonical facts"):
        chaos_evidence.locally_recompute_stage_c_receipt(
            receipt,
            raw_events_path=raw_path,
            registrar_public_key=context["registrar_public"],
            capability_authority_public_key=context["capability_public"],
            raw_observer_public_key=context["source_public"][
                "parser_signer"
            ],
            source_public_keys=context["source_public"],
        )
    raw_path.write_bytes(context["raw_bytes"] + b" ")
    with pytest.raises(ValueError, match="WORM raw locator"):
        chaos_evidence.locally_recompute_stage_c_receipt(
            receipt,
            raw_events_path=raw_path,
            registrar_public_key=context["registrar_public"],
            capability_authority_public_key=context["capability_public"],
            raw_observer_public_key=context["source_public"][
                "parser_signer"
            ],
            source_public_keys=context["source_public"],
        )


def test_stage_c_challenge_is_single_use_expiring_and_scenario_bound(
    tmp_path,
):
    _receipt_value, context = _build_protocol_receipt(
        tmp_path,
        "external-fill",
    )
    challenge = context["challenge"]["payload"]
    registry = tmp_path / "challenge-registry.sqlite3"

    consumed = stage_c_protocol.consume_stage_c_challenge(
        registry=registry,
        challenge_artifact=context["challenge"],
        registrar_public_key=context["registrar_public"],
        scenario="external-fill",
        now=challenge["not_before"],
    )
    assert consumed["challenge_id"] == challenge["challenge_id"]
    with pytest.raises(ValueError, match="已消费"):
        stage_c_protocol.consume_stage_c_challenge(
            registry=registry,
            challenge_artifact=context["challenge"],
            registrar_public_key=context["registrar_public"],
            scenario="external-fill",
            now=challenge["not_before"],
        )
    with pytest.raises(ValueError, match="过期"):
        stage_c_protocol.verify_stage_c_challenge(
            context["challenge"],
            registrar_public_key=context["registrar_public"],
            scenario="external-fill",
            now=challenge["expires_at"] + 1,
            enforce_current_window=True,
        )
    with pytest.raises(ValueError):
        stage_c_protocol.verify_stage_c_challenge(
            context["challenge"],
            registrar_public_key=context["registrar_public"],
            scenario="frozen-balance",
            now=challenge["not_before"],
            enforce_current_window=True,
        )


def test_stage_c_global_consumption_uses_conditional_put_and_consistent_read(
    tmp_path,
):
    scenario = "external-fill"
    _receipt_value, context = _build_protocol_receipt(tmp_path, scenario)
    challenge = context["challenge"]["payload"]
    item = stage_c_protocol._consumption_item(
        context["challenge"],
        challenge,
    )
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if "put-item" in argv:
            payload = {
                "ConsumedCapacity": {
                    "TableName": challenge["consumption_backend"][
                        "table_name"
                    ],
                }
            }
        else:
            payload = {"Item": item}
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps(payload).encode(),
            stderr=b"",
        )

    artifact = stage_c_protocol.consume_stage_c_challenge_globally(
        challenge_artifact=context["challenge"],
        registrar_public_key=context["registrar_public"],
        consumer_private_key=context["source_private"][
            "challenge_consumer"
        ],
        now=challenge["not_before"],
        command_runner=run,
    )
    assert "attribute_not_exists(challenge_id)" in calls[0][0]
    assert "--consistent-read" in calls[1][0]
    assert stage_c_protocol.verify_stage_c_consumption_receipt(
        artifact,
        challenge_artifact=context["challenge"],
        registrar_public_key=context["registrar_public"],
        consumer_public_key=context["source_public"][
            "challenge_consumer"
        ],
    )["item"] == item

    def replay(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            255,
            stdout=b"",
            stderr=b"ConditionalCheckFailedException",
        )

    with pytest.raises(ValueError, match="conditional consumption"):
        stage_c_protocol.consume_stage_c_challenge_globally(
            challenge_artifact=context["challenge"],
            registrar_public_key=context["registrar_public"],
            consumer_private_key=context["source_private"][
                "challenge_consumer"
            ],
            now=challenge["not_before"],
            command_runner=replay,
        )


def test_stage_c_rejects_reused_source_key_and_workload_domains(tmp_path):
    scenario = "external-fill"
    _receipt_value, context = _build_protocol_receipt(tmp_path, scenario)
    roles = sorted(stage_c_protocol.required_source_roles(scenario))
    reused_keys = dict(context["source_public"])
    reused_keys[roles[1]] = reused_keys[roles[0]]
    with pytest.raises(ValueError, match="完全分钥"):
        stage_c_protocol.build_stage_c_capability_attestation(
            scenario=scenario,
            identity=context["identity"],
            native_attestations=context["native_attestations"],
            source_public_keys=reused_keys,
            authority_private_key=context["capability_private"],
            now=context["challenge"]["payload"]["issued_at"],
        )
    reused_attestations = copy.deepcopy(context["native_attestations"])
    reused_attestations[roles[1]] = reused_attestations[roles[0]]
    with pytest.raises(ValueError, match="不同 UID"):
        stage_c_protocol.build_stage_c_capability_attestation(
            scenario=scenario,
            identity=context["identity"],
            native_attestations=reused_attestations,
            source_public_keys=context["source_public"],
            authority_private_key=context["capability_private"],
            now=context["challenge"]["payload"]["issued_at"],
        )
    tampered_native = copy.deepcopy(context["native_attestations"])
    systemd_raw = (
        stage_c_protocol._decode_opaque_bytes(
            tampered_native[roles[0]]["systemd_show"],
            "fixture systemd show",
        )
        .replace(
            f"MainPID={context['workloads'][roles[0]]['pid']}".encode(),
            b"MainPID=999999",
        )
    )
    tampered_native[roles[0]]["systemd_show"] = (
        stage_c_protocol._opaque_bytes_descriptor(systemd_raw)
    )
    with pytest.raises(ValueError, match="systemd show 与 /proc"):
        stage_c_protocol.build_stage_c_capability_attestation(
            scenario=scenario,
            identity=context["identity"],
            native_attestations=tampered_native,
            source_public_keys=context["source_public"],
            authority_private_key=context["capability_private"],
            now=context["challenge"]["payload"]["issued_at"],
        )


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("tamper", "签名"),
        ("missing", "envelope"),
        ("time-forgery", "时间伪造"),
        ("summary-bypass", "envelope"),
    ],
)
def test_stage_c_rejects_raw_tamper_missing_time_and_summary_bypass(
    tmp_path,
    mutation,
    error,
):
    scenario = "external-fill"
    _receipt_value, context = _build_protocol_receipt(tmp_path, scenario)
    events = copy.deepcopy(context["events"])
    if mutation == "tamper":
        target = next(
            event
            for event in events
            if event["kind"] == "exchange.fill.external"
        )
        descriptor = target["payload"]["artifact"]["payload"][
            "native_response"
        ]
        descriptor["sha256"] = "0" * 64
    elif mutation == "missing":
        events.pop(2)
    elif mutation == "time-forgery":
        target = events[-1]
        target["observed_at"] = (
            datetime.fromisoformat(target["observed_at"])
            + timedelta(seconds=10)
        ).isoformat()
    else:
        target = events[1]
        target["kind"] = "summary"
    with pytest.raises(ValueError, match=error):
        _derive_protocol_context(
            context,
            scenario=scenario,
            raw_bytes=_protocol_raw_bytes(events),
        )


def test_stage_c_rejects_provider_summary_even_when_outer_source_resigns(
    tmp_path,
):
    scenario = "external-fill"
    _receipt_value, context = _build_protocol_receipt(tmp_path, scenario)
    events = copy.deepcopy(context["events"])
    index = next(
        index
        for index, event in enumerate(events)
        if event["kind"] == "page.provider_receipt"
    )
    original = events[index]
    facts = stage_c_protocol._decode_native_bytes(
        original["payload"]["artifact"]["payload"]["native_response"],
        "fixture provider response",
    )
    facts["artifact"]["payload"]["event_id"] = "forged-summary-event"
    events[index] = _resign_protocol_event(
        context,
        scenario=scenario,
        event=original,
        facts=facts,
    )
    with pytest.raises(ValueError, match="签名"):
        _derive_protocol_context(
            context,
            scenario=scenario,
            raw_bytes=_protocol_raw_bytes(events),
        )


def test_stage_c_rejects_production_enableable_barrier_hook(tmp_path):
    scenario = "barrier-post-before-ack"
    _receipt_value, context = _build_protocol_receipt(tmp_path, scenario)
    events = copy.deepcopy(context["events"])
    index = next(
        index
        for index, event in enumerate(events)
        if event["kind"] == "build.instrumented_provenance"
    )
    original = events[index]
    facts = stage_c_protocol._decode_native_bytes(
        original["payload"]["artifact"]["payload"]["native_response"],
        "fixture build response",
    )
    facts["production_env_enableable"] = True
    events[index] = _resign_protocol_event(
        context,
        scenario=scenario,
        event=original,
        facts=facts,
    )
    with pytest.raises(ValueError, match="provenance"):
        _derive_protocol_context(
            context,
            scenario=scenario,
            raw_bytes=_protocol_raw_bytes(events),
        )


def test_stage_c_capability_inventory_is_checked_dynamically(monkeypatch):
    monkeypatch.setattr(
        chaos_evidence,
        "implemented_stage_c_scenarios",
        lambda: frozenset(),
    )
    scenario = chaos_evidence.SCENARIO_BY_NAME["external-fill"]

    with pytest.raises(ValueError, match="EXTERNAL OPEN"):
        chaos_evidence.require_stage_c_production_capabilities((scenario,))


def test_legacy_repository_producer_is_not_production_capability():
    scenario = chaos_evidence.SCENARIO_BY_NAME["ws-public"]
    item = chaos_evidence.stage_c_capability_inventory((scenario,))[0]

    assert item["status"] == "EXTERNAL OPEN"
    assert item["capability_layer"] == "REPOSITORY_PRODUCER"
    assert item["repository_producer"] is True
    assert item["executor_shipped"] is False
    with pytest.raises(ValueError, match="EXTERNAL OPEN"):
        chaos_evidence.require_stage_c_production_capabilities((scenario,))


def test_stage_c_inventory_does_not_accept_executor_as_deployment_attestation(
    monkeypatch,
):
    scenario = "barrier-buy-intent-before-post"
    monkeypatch.setattr(
        chaos_evidence,
        "implemented_stage_c_scenarios",
        lambda: frozenset({scenario}),
    )
    item = chaos_evidence.stage_c_capability_inventory((
        chaos_evidence.SCENARIO_BY_NAME[scenario],
    ))[0]
    assert item["capability_layer"] == "EXECUTOR_SHIPPED"
    assert item["executor_shipped"] is True
    assert item["deployment_attested"] is False
    assert item["status"] == "EXTERNAL OPEN"


def test_stage_c_production_loader_rejects_canonical_barrier_trust_config(
    tmp_path,
    monkeypatch,
):
    scenario = "barrier-buy-intent-before-post"
    receipt, context = _build_protocol_receipt(tmp_path, scenario)
    raw_dir = tmp_path / "raw-events"
    raw_dir.mkdir()
    raw_path = raw_dir / f"{scenario}.jsonl"
    raw_path.write_bytes(context["raw_bytes"])

    def key_ref(path):
        return {
            "path": str(path.resolve()),
            "fingerprint_sha256": (
                chaos_evidence.ed25519_public_key_fingerprint(path)
            ),
        }

    entry = {
        "trust_state": "TRUST_CONFIGURED",
        "driver_contract_sha256": hashlib.sha256(
            canonical_bytes(
                stage_c_protocol.driver_contract_document(scenario)
            )
        ).hexdigest(),
        "raw_events_file": raw_path.name,
        "raw_events_sha256": hashlib.sha256(
            context["raw_bytes"]
        ).hexdigest(),
        "raw_events_bytes": len(context["raw_bytes"]),
        "registrar_public_key": key_ref(context["registrar_public"]),
        "capability_authority_public_key": key_ref(
            context["capability_public"]
        ),
        "source_public_keys": {
            role: key_ref(path)
            for role, path in context["source_public"].items()
        },
    }
    trust_payload = {
        "version": 1,
        "action": "configure-stage-c-production-trust-v1",
        "parser_manifest_sha256": (
            stage_c_protocol.PARSER_MANIFEST_SHA256
        ),
        "raw_events_dir": str(raw_dir.resolve()),
        "scenarios": {scenario: entry},
    }
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps(trust_payload), encoding="utf-8")
    monkeypatch.setattr(
        chaos_evidence,
        "RAW_RECOMPUTED_SCENARIOS",
        frozenset({scenario}),
    )
    monkeypatch.setattr(
        chaos_evidence,
        "DRILL_SCENARIOS",
        (chaos_evidence.SCENARIO_BY_NAME[scenario],),
    )
    monkeypatch.setattr(
        chaos_evidence,
        "implemented_stage_c_scenarios",
        lambda: frozenset({scenario}),
    )

    injected = copy.deepcopy(trust_payload)
    injected["scenarios"][scenario]["trust_state"] = (
        "DEPLOYMENT_ATTESTED"
    )
    trust_path.write_text(json.dumps(injected), encoding="utf-8")
    with pytest.raises(ValueError, match="schema/state"):
        chaos_evidence.load_stage_c_production_trust_manifest(trust_path)
    trust_path.write_text(json.dumps(trust_payload), encoding="utf-8")

    receipts_dir = tmp_path / "receipts"
    manifests_dir = tmp_path / "manifests"
    bundle_receipts_dir = tmp_path / "bundle-receipts"
    independent_dir = tmp_path / "independent"
    for directory in (
        receipts_dir,
        manifests_dir,
        bundle_receipts_dir,
        independent_dir,
    ):
        directory.mkdir()
    (receipts_dir / f"{scenario}.json").write_text(
        json.dumps(receipt),
        encoding="utf-8",
    )
    _publisher_private, publisher_public = _key_pair(
        tmp_path,
        "barrier-publisher",
    )
    _verifier_private, verifier_public = _key_pair(
        tmp_path,
        "barrier-readback",
    )
    with pytest.raises(ValueError, match="完全分钥"):
        load_verified_stage_c_receipts(
            receipts_dir=receipts_dir,
            manifests_dir=manifests_dir,
            bundle_receipts_dir=bundle_receipts_dir,
            bundle_signing_public_key=context["registrar_public"],
            independent_attestations_dir=independent_dir,
            raw_observer_public_key=context["source_public"][
                "parser_signer"
            ],
            independent_verifier_public_key=verifier_public,
            trust_manifest_path=trust_path,
        )
    with pytest.raises(
        ValueError,
        match="production Stage-C barrier",
    ):
        load_verified_stage_c_receipts(
            receipts_dir=receipts_dir,
            manifests_dir=manifests_dir,
            bundle_receipts_dir=bundle_receipts_dir,
            bundle_signing_public_key=publisher_public,
            independent_attestations_dir=independent_dir,
            raw_observer_public_key=context["source_public"][
                "parser_signer"
            ],
            independent_verifier_public_key=verifier_public,
            trust_manifest_path=trust_path,
        )


def test_stage_c_trust_manifest_builder_computes_exact_roles_and_refuses_overwrite(
    tmp_path,
    monkeypatch,
):
    scenario = "external-fill"
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    (raw_dir / f"{scenario}.jsonl").write_bytes(b'{"native":"raw"}\n')
    key_root = tmp_path / "keys"
    scenario_root = key_root / scenario
    sources_root = scenario_root / "sources"
    sources_root.mkdir(parents=True)
    global_root = key_root / "global"
    global_root.mkdir()
    _key_pair(global_root, "parser-signer")
    _key_pair(scenario_root, "registrar")
    _key_pair(scenario_root, "capability-authority")
    for role in sorted(stage_c_protocol.required_source_roles(scenario)):
        if role == "parser_signer":
            continue
        _key_pair(sources_root, role)
    selected = frozenset({scenario})
    monkeypatch.setattr(
        build_stage_c_trust_manifest,
        "RAW_RECOMPUTED_SCENARIOS",
        selected,
    )
    monkeypatch.setattr(
        chaos_evidence,
        "RAW_RECOMPUTED_SCENARIOS",
        selected,
    )
    value = build_stage_c_trust_manifest.build_manifest(
        raw_events_dir=raw_dir.resolve(),
        key_root=key_root.resolve(),
    )
    entry = value["scenarios"][scenario]
    assert entry["trust_state"] == "TRUST_CONFIGURED"
    assert set(entry["source_public_keys"]) == set(
        stage_c_protocol.required_source_roles(scenario)
    )
    output = tmp_path / "trust.json"
    build_stage_c_trust_manifest.write_manifest(output.resolve(), value)
    trust = chaos_evidence.load_stage_c_production_trust_manifest(
        output.resolve()
    )
    assert trust.raw_events_dir == raw_dir.resolve()
    duplicate = tmp_path / "duplicate-trust.json"
    duplicate.write_text(
        json.dumps(value).replace(
            '{"version": 1,',
            '{"version": 1, "version": 1,',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="重复字段"):
        chaos_evidence.load_stage_c_production_trust_manifest(
            duplicate.resolve()
        )
    with pytest.raises(FileExistsError):
        build_stage_c_trust_manifest.write_manifest(
            output.resolve(),
            value,
        )


def test_stage_c_production_entrypoints_require_production_evidence_mode():
    producer_source = (
        Path(stage_c_chaos_producer.__file__)
        .read_text(encoding="utf-8")
    )
    verifier_source = (
        Path(verify_demo_chaos_coverage.__file__)
        .read_text(encoding="utf-8")
    )
    assert "require_production_evidence=True" in producer_source
    assert "require_live_exact_release=True" not in producer_source
    assert "require_production_evidence=True" in verifier_source
    assert "require_live_exact_release=True" not in verifier_source


def test_stage_c_producer_contract_cli_is_systemd_callable(
    tmp_path,
    monkeypatch,
):
    output = tmp_path / "contract.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "stage_c_chaos_producer.py",
            "contract",
            "--scenario",
            "external-fill",
            "--output",
            str(output),
        ],
    )

    assert stage_c_chaos_producer.main() == 0
    assert json.loads(output.read_text()) == (
        stage_c_protocol.driver_contract_document("external-fill")
    )
    assert output.stat().st_mode & 0o777 == 0o644


def test_stage_c_live_capability_collector_derives_from_os_and_sts_bytes(
    tmp_path,
    monkeypatch,
):
    proc_root = tmp_path / "proc"
    proc_dir = proc_root / "4321"
    proc_dir.mkdir(parents=True)
    executable = tmp_path / "collector"
    executable.write_bytes(b"stage-c-collector")
    (proc_dir / "exe").symlink_to(executable)
    (proc_dir / "status").write_text(
        "Name:\tcollector\nPid:\t4321\n"
        "Uid:\t3301\t3301\t3301\t3301\n",
        encoding="utf-8",
    )
    (proc_dir / "cgroup").write_text(
        "0::/system.slice/stage-c-source.service\n",
        encoding="utf-8",
    )
    boot_id = tmp_path / "boot_id"
    boot_id.write_text(
        "00000000-0000-0000-0000-000000000001\n",
        encoding="ascii",
    )
    machine_id = tmp_path / "machine-id"
    machine_id.write_text("stage-c-host-1\n", encoding="ascii")
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()

    def run(argv, **_kwargs):
        if "show" in argv:
            stdout = (
                b"Id=stage-c-source.service\n"
                b"InvocationID=10000000-0000-0000-0000-000000000001\n"
                b"MainPID=4321\n"
                b"ControlGroup=/system.slice/stage-c-source.service\n"
            )
        elif "get-caller-identity" in argv:
            stdout = json.dumps({
                "UserId": "stage-c-session",
                "Account": "123456789012",
                "Arn": (
                    "arn:aws:sts::123456789012:"
                    "assumed-role/stage-c-source/session"
                ),
            }).encode()
        else:
            stdout = f"{executable_sha}  {executable}\n".encode()
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=stdout,
            stderr=b"",
        )

    monkeypatch.setattr(stage_c_native_collectors, "_run_native", run)
    native = (
        stage_c_native_collectors.collect_native_workload_attestation(
            unit="stage-c-source.service",
            proc_root=proc_root,
            boot_id_path=boot_id,
            machine_id_path=machine_id,
        )
    )
    workload = stage_c_protocol.derive_workload_from_native_attestation(
        native
    )
    assert workload["pid"] == 4321
    assert workload["uid"] == 3301
    assert workload["executable_sha256"] == executable_sha
    assert workload["iam_account_id"] == "123456789012"


def test_stage_c_native_sqlite_and_fault_executor_are_allowlisted(
    tmp_path,
    monkeypatch,
):
    database = tmp_path / "journal.db"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE system_state(key TEXT PRIMARY KEY, value TEXT)"
    )
    connection.execute(
        "INSERT INTO system_state VALUES('mode', 'ready')"
    )
    connection.commit()
    connection.close()

    acquisition = stage_c_native_collectors.collect_sqlite_native(
        database=database,
        query_name="system-mode",
    )
    assert acquisition.source == "journal_collector"
    assert json.loads(acquisition.response_bytes)["rows"] == [
        ["mode", "ready"]
    ]
    with pytest.raises(ValueError, match="allow-list"):
        stage_c_native_collectors.collect_sqlite_native(
            database=database,
            query_name="DROP TABLE system_state",
        )

    observed = {}

    def run(argv, **_kwargs):
        observed["argv"] = argv
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=b"",
            stderr=b"",
        )

    monkeypatch.setattr(stage_c_native_collectors, "_run_native", run)
    result = stage_c_native_collectors.execute_controlled_fault(
        action="systemd-sigkill",
        unit="okx-quant-instrumented-test.service",
    )
    assert "--signal=SIGKILL" in observed["argv"]
    assert result.returncode == 0
    with pytest.raises(ValueError, match="allow-list"):
        stage_c_native_collectors.execute_controlled_fault(
            action="shell",
            unit="okx-quant.service",
        )


def test_stable_catalog_covers_all_wp4_wp5_acceptance_classes():
    assert len(DRILL_SCENARIOS) == 18
    assert {
        spec.work_package for spec in DRILL_SCENARIOS
    } == {"WP4", "WP5"}
    assert len(
        scenario_names(DrillArtifactClass.EXACT_RELEASE_BLACK_BOX)
    ) == 15
    assert set(
        scenario_names(DrillArtifactClass.EXACT_RELEASE_BLACK_BOX)
    ) == (
        chaos_evidence.AUTOMATED_EXACT_RELEASE_SCENARIOS
        | chaos_evidence.INDEPENDENT_OBSERVATION_SCENARIOS
    )
    assert len(chaos_evidence.INDEPENDENT_OBSERVATION_SCENARIOS) == 10
    assert len(chaos_evidence.RAW_EXTERNAL_OPEN_SCENARIOS) == 13
    assert len(chaos_evidence.EXTERNAL_OPEN_SCENARIOS) == 18
    inventory = chaos_evidence.stage_c_capability_inventory()
    assert sum(
        item["status"] == "EXTERNAL OPEN" for item in inventory
    ) == 18
    assert sum(item["repository_producer"] for item in inventory) == 5
    assert scenario_names(
        DrillArtifactClass.INSTRUMENTED_TEST_ONLY
    ) == (
        "barrier-buy-intent-before-post",
        "barrier-post-before-ack",
        "barrier-fill-before-projection",
    )


def test_receipt_rejects_exact_release_masquerading_as_test_only():
    started = datetime(2026, 7, 28, 12, tzinfo=UTC)
    receipt = _receipt("restart-sigkill", started=started)
    receipt["identity"]["artifact_sha256"] = "d" * 64
    receipt["identity"]["artifact_build_id"] = "test-only:forged"
    receipt["identity"]["test_hooks_present"] = True

    with pytest.raises(ValueError, match="exact-release"):
        validate_drill_receipt(receipt)


def test_receipt_enforces_transition_and_page_deadlines():
    started = datetime(2026, 7, 28, 12, tzinfo=UTC)
    receipt = _receipt("ws-public", started=started)
    receipt["actual_transitions"][0]["observed_at"] = (
        started + timedelta(seconds=21)
    ).isoformat()
    receipt["actual_transitions"][1]["observed_at"] = (
        started + timedelta(seconds=22)
    ).isoformat()
    receipt["completed_at"] = (
        started + timedelta(seconds=30)
    ).isoformat()
    with pytest.raises(ValueError, match="transition deadline"):
        validate_drill_receipt(receipt)

    receipt = _receipt("ws-public", started=started)
    receipt["completed_at"] = (
        started + timedelta(seconds=90)
    ).isoformat()
    receipt["page_receipt"]["provider_received_at"] = (
        started.timestamp() + 61
    )
    receipt["page_receipt"]["human_ack_at"] = (
        started.timestamp() + 62
    )
    with pytest.raises(ValueError, match="不超过 60"):
        validate_drill_receipt(receipt)

    receipt = _receipt("ws-public", started=started)
    receipt["page_receipt"]["event_name"] = "page.unrelated_incident"
    with pytest.raises(ValueError, match="预期故障告警"):
        validate_drill_receipt(receipt)


def test_coverage_requires_full_final_freeze_matrix_and_distinct_artifacts():
    frozen = datetime(2026, 7, 28, 12, tzinfo=UTC)
    receipts = _full_matrix(frozen + timedelta(minutes=1))

    coverage = verify_stage_c_coverage(
        receipts,
        expected_release_identity=_RELEASE,
        expected_soak_epoch_id=_EPOCH,
        release_frozen_at=frozen,
        epoch_started_at=frozen + timedelta(minutes=5),
        expected_stage_c_deployment_identity=(
            _stage_c_candidate_identity()
        ),
    )

    assert coverage["scenario_count"] == len(DRILL_SCENARIOS)
    assert len(coverage["receipt_sha256"]) == len(DRILL_SCENARIOS)
    with pytest.raises(ValueError, match="完整矩阵"):
        verify_stage_c_coverage(
            receipts[:-1],
            expected_release_identity=_RELEASE,
            expected_soak_epoch_id=_EPOCH,
            release_frozen_at=frozen,
            epoch_started_at=frozen + timedelta(minutes=5),
            expected_stage_c_deployment_identity=(
                _stage_c_candidate_identity()
            ),
        )
    receipts = _full_matrix(frozen - timedelta(seconds=1))
    with pytest.raises(ValueError, match="早于最终"):
        verify_stage_c_coverage(
            receipts,
            expected_release_identity=_RELEASE,
            expected_soak_epoch_id=_EPOCH,
            release_frozen_at=frozen,
            epoch_started_at=frozen + timedelta(minutes=5),
            expected_stage_c_deployment_identity=(
                _stage_c_candidate_identity()
            ),
        )

    late = _full_matrix(frozen + timedelta(minutes=1))
    late[0]["completed_at"] = (frozen + timedelta(minutes=6)).isoformat()
    with pytest.raises(ValueError, match="deployment/timing"):
        verify_stage_c_coverage(
            late,
            expected_release_identity=_RELEASE,
            expected_soak_epoch_id=_EPOCH,
            release_frozen_at=frozen,
            epoch_started_at=frozen + timedelta(minutes=5),
            expected_stage_c_deployment_identity=(
                _stage_c_candidate_identity()
            ),
        )

    wrong_candidate = _full_matrix(frozen + timedelta(minutes=1))
    wrong_candidate[0]["identity"][
        "stage_c_chaos_deployment_identity_sha256"
    ] = "0" * 64
    with pytest.raises(ValueError, match="release/epoch"):
        verify_stage_c_coverage(
            wrong_candidate,
            expected_release_identity=_RELEASE,
            expected_soak_epoch_id=_EPOCH,
            release_frozen_at=frozen,
            epoch_started_at=frozen + timedelta(minutes=5),
            expected_stage_c_deployment_identity=(
                _stage_c_candidate_identity()
            ),
        )


def test_signed_worm_manifest_must_bind_exact_drill_result(
    tmp_path,
    monkeypatch,
):
    started = datetime(2026, 7, 28, 12, tzinfo=UTC)
    spec = DRILL_SCENARIOS[0]
    receipt = _receipt(spec.name, started=started)
    result_bytes = json.dumps(receipt, sort_keys=True).encode()
    receipts_dir = tmp_path / "receipts"
    manifests_dir = tmp_path / "manifests"
    bundle_receipts_dir = tmp_path / "bundle-receipts"
    independent_attestations_dir = tmp_path / "independent"
    for directory in (
        receipts_dir,
        manifests_dir,
        bundle_receipts_dir,
        independent_attestations_dir,
    ):
        directory.mkdir()
    (receipts_dir / f"{spec.name}.json").write_bytes(result_bytes)
    private_key, public_key = _key_pair(tmp_path)
    bundle_identity = {
        "git_commit": receipt["identity"]["git_commit"],
        "config_sha256": receipt["identity"]["config_sha256"],
        "account_uid": receipt["identity"]["account_uid"],
        "environment": "demo",
        "unit": receipt["identity"]["unit"],
        "soak_epoch_id": receipt["identity"]["soak_epoch_id"],
        "phase": "chaos",
    }
    manifest = build_bundle_manifest(
        bundle_id="1" * 32,
        kind="chaos",
        identity=bundle_identity,
        components={
            "drill-result": (
                result_bytes,
                "s3://evidence/bundle-1/drill-result.json",
                "result-version-1",
            )
        },
        retain_until=started + timedelta(days=365),
        signing_key_id="chaos-evidence-v1",
        created_at=started,
    )
    artifact = sign_bundle_manifest(manifest, private_key)
    manifest_bytes = json.dumps(artifact, sort_keys=True).encode()
    (manifests_dir / f"{spec.name}.json").write_bytes(manifest_bytes)
    bundle_receipt = build_bundle_receipt(
        manifest_uri="s3://evidence/bundle-1/manifest.json",
        manifest_version_id="manifest-version-1",
        manifest_bytes=manifest_bytes,
        verified_at=started + timedelta(seconds=30),
    )
    (bundle_receipts_dir / f"{spec.name}.json").write_text(
        json.dumps(bundle_receipt),
        encoding="utf-8",
    )
    verifier_private, verifier_public = _key_pair(tmp_path, "verifier")
    _observer_private, observer_public = _key_pair(tmp_path, "observer")
    independent_claims = (
        chaos_evidence.build_independent_drill_readback_claims(
            scenario=spec.name,
            manifest_uri=bundle_receipt["manifest_uri"],
            manifest_version_id=bundle_receipt[
                "manifest_version_id"
            ],
            manifest_bytes=manifest_bytes,
            manifest_signing_public_key=public_key,
            verifier_key_id="independent-verifier-v1",
            verifier_private_key=verifier_private,
            result_uri=manifest["components"]["drill-result"][
                "object_uri"
            ],
            result_version_id=manifest["components"]["drill-result"][
                "version_id"
            ],
            result_bytes=result_bytes,
            verified_at=started + timedelta(seconds=40),
        )
    )
    (independent_attestations_dir / f"{spec.name}.json").write_text(
        json.dumps(
            sign_ed25519_payload(
                independent_claims,
                verifier_private,
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        chaos_evidence,
        "DRILL_SCENARIOS",
        (spec,),
    )

    with pytest.raises(ValueError, match="三个不同"):
        load_verified_stage_c_receipts(
            receipts_dir=receipts_dir,
            manifests_dir=manifests_dir,
            bundle_receipts_dir=bundle_receipts_dir,
            bundle_signing_public_key=public_key,
            independent_attestations_dir=independent_attestations_dir,
            raw_observer_public_key=verifier_public,
            independent_verifier_public_key=verifier_public,
        )
    with pytest.raises(ValueError, match="EXTERNAL OPEN"):
        load_verified_stage_c_receipts(
            receipts_dir=receipts_dir,
            manifests_dir=manifests_dir,
            bundle_receipts_dir=bundle_receipts_dir,
            bundle_signing_public_key=public_key,
            independent_attestations_dir=independent_attestations_dir,
            raw_observer_public_key=observer_public,
            independent_verifier_public_key=verifier_public,
        )
    # Exercise the downstream WORM binding independently of the production
    # capability gate; this bypass exists only inside the unit test process.
    monkeypatch.setattr(
        chaos_evidence,
        "require_stage_c_production_capabilities",
        lambda _scenarios: None,
    )
    assert load_verified_stage_c_receipts(
        receipts_dir=receipts_dir,
        manifests_dir=manifests_dir,
        bundle_receipts_dir=bundle_receipts_dir,
        bundle_signing_public_key=public_key,
        independent_attestations_dir=independent_attestations_dir,
        raw_observer_public_key=observer_public,
        independent_verifier_public_key=verifier_public,
    ) == [receipt]
    (receipts_dir / f"{spec.name}.json").write_text(
        json.dumps({**receipt, "passed": False}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_verified_stage_c_receipts(
            receipts_dir=receipts_dir,
            manifests_dir=manifests_dir,
            bundle_receipts_dir=bundle_receipts_dir,
            bundle_signing_public_key=public_key,
            independent_attestations_dir=independent_attestations_dir,
            raw_observer_public_key=observer_public,
            independent_verifier_public_key=verifier_public,
        )


def test_independent_verifier_gets_exact_manifest_and_component_versions(
    tmp_path,
    monkeypatch,
):
    scenario = "external-fill"
    receipt, context = _build_protocol_receipt(tmp_path, scenario)
    started = datetime.fromisoformat(receipt["started_at"])
    result_bytes = json.dumps(receipt, sort_keys=True).encode()
    publisher_private, publisher_public = _key_pair(tmp_path, "publisher")
    verifier_private, _verifier_public = _key_pair(tmp_path, "verifier")
    manifest = build_bundle_manifest(
        bundle_id="2" * 32,
        kind="chaos",
        identity={
            "git_commit": receipt["identity"]["git_commit"],
            "config_sha256": receipt["identity"]["config_sha256"],
            "account_uid": receipt["identity"]["account_uid"],
            "environment": "demo",
            "unit": receipt["identity"]["unit"],
            "soak_epoch_id": receipt["identity"]["soak_epoch_id"],
            "phase": "chaos",
        },
        components={
            "drill-result": (
                result_bytes,
                "s3://evidence/bundle-2/drill-result.json",
                "result-version-2",
            )
        },
        retain_until=started + timedelta(days=365),
        signing_key_id="publisher-v1",
        created_at=started,
    )
    artifact = sign_bundle_manifest(manifest, publisher_private)
    manifest_path = tmp_path / "manifest.json"
    manifest_bytes = json.dumps(artifact, sort_keys=True).encode()
    manifest_path.write_bytes(manifest_bytes)
    observed = {"locked": []}

    def verify_manifest(**kwargs):
        observed["locked"].append(kwargs)
        if kwargs["version_id"] == f"{scenario}-version-1":
            return context["raw_bytes"]
        return manifest_bytes

    def verify_components(artifact_arg, **kwargs):
        observed["components"] = (artifact_arg, kwargs)
        return {"drill-result": result_bytes}

    monkeypatch.setattr(
        verify_demo_chaos_coverage,
        "verify_locked_object",
        verify_manifest,
    )
    monkeypatch.setattr(
        verify_demo_chaos_coverage,
        "verify_bundle_artifact",
        verify_components,
    )
    output = tmp_path / "independent.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_demo_chaos_coverage.py",
            "--scenario",
            scenario,
            "--manifest",
            str(manifest_path),
            "--manifest-uri",
            "s3://evidence/bundle-2/manifest.json",
            "--manifest-version-id",
            "manifest-version-2",
            "--bundle-signing-public-key",
            str(publisher_public),
            "--independent-verifier-private-key",
            str(verifier_private),
            "--independent-verifier-key-id",
            "verifier-v1",
            "--minimum-retain-until",
            (started + timedelta(days=30)).isoformat(),
            "--kms-key-id",
            "kms-key-1",
            "--registrar-public-key",
            str(context["registrar_public"]),
            "--capability-authority-public-key",
            str(context["capability_public"]),
            "--raw-observer-public-key",
            str(context["source_public"]["parser_signer"]),
            *[
                item
                for role, path in sorted(
                    context["source_public"].items()
                )
                for item in (
                    "--source-public-key",
                    f"{role}={path}",
                )
            ],
            "--output",
            str(output),
        ],
    )

    with pytest.raises(ValueError, match="canonical facts"):
        verify_demo_chaos_coverage.main()
    assert {
        item["version_id"] for item in observed["locked"]
    } == {
        "manifest-version-2",
        f"{scenario}-version-1",
    }
    assert observed["locked"][0]["object_uri"].endswith(
        "/manifest.json"
    )
    assert observed["components"][1]["expected_identity"] == (
        manifest["identity"]
    )
    assert not output.exists()

    def reject_raw_source(**kwargs):
        if kwargs["version_id"] == f"{scenario}-version-1":
            raise RuntimeError("raw source exact-version hash mismatch")
        return manifest_bytes

    monkeypatch.setattr(
        verify_demo_chaos_coverage,
        "verify_locked_object",
        reject_raw_source,
    )
    rejected_output = tmp_path / "rejected-independent.json"
    sys.argv[-1] = str(rejected_output)
    with pytest.raises(RuntimeError, match="raw source exact-version"):
        verify_demo_chaos_coverage.main()
    assert not rejected_output.exists()


def test_production_gate_stage_c_hook_is_fail_closed(tmp_path, monkeypatch):
    epoch = {
        "soak_epoch_id": _EPOCH,
        "release_identity": _RELEASE,
        "started_at": "2026-07-29T00:00:00+00:00",
        "stage_c_chaos_deployment_identity": (
            _stage_c_candidate_identity()
        ),
    }
    with pytest.raises(ValueError, match="Stage-C"):
        production_gate._verify_stage_c_drills(
            epoch=epoch,
            bundle_signing_public_key=None,
            receipts_dir=None,
            manifests_dir=None,
            bundle_receipts_dir=None,
            independent_attestations_dir=None,
            raw_observer_public_key=None,
            independent_verifier_public_key=None,
            trust_manifest_path=None,
            release_frozen_at=None,
        )
    observed = {}

    def load(**kwargs):
        observed["load"] = kwargs
        return ["verified-receipts"]

    def verify(receipts, **kwargs):
        observed["verify"] = (receipts, kwargs)
        return {"scenario_count": len(DRILL_SCENARIOS)}

    monkeypatch.setattr(
        production_gate,
        "load_verified_stage_c_receipts",
        load,
    )
    monkeypatch.setattr(
        production_gate,
        "verify_stage_c_coverage",
        verify,
    )
    frozen = datetime(2026, 7, 28, 12, tzinfo=UTC)
    result = production_gate._verify_stage_c_drills(
        epoch=epoch,
        bundle_signing_public_key=tmp_path / "bundle.pem",
        receipts_dir=tmp_path / "receipts",
        manifests_dir=tmp_path / "manifests",
        bundle_receipts_dir=tmp_path / "bundle-receipts",
        independent_attestations_dir=tmp_path / "independent",
        raw_observer_public_key=tmp_path / "observer.pem",
        independent_verifier_public_key=tmp_path / "verifier.pem",
        trust_manifest_path=tmp_path / "trust.json",
        release_frozen_at=frozen,
    )
    assert result["scenario_count"] == len(DRILL_SCENARIOS)
    assert observed["load"]["raw_observer_public_key"] == (
        tmp_path / "observer.pem"
    )
    assert observed["load"]["trust_manifest_path"] == (
        tmp_path / "trust.json"
    )
    assert observed["verify"][1]["release_frozen_at"] == frozen


def test_exact_release_runner_rejects_instrumented_scenario(
    monkeypatch,
):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "demo_chaos_matrix.py",
            "--config",
            "unused.yaml",
            "--scenario",
            "barrier-post-before-ack",
            "--confirm",
            demo_chaos_matrix.CONFIRMATION,
            "--soak-epoch-id",
            _EPOCH,
            "--output",
            "unused-result.json",
            "--identity-output",
            "unused-identity.json",
            "--manifest-output",
            "unused-manifest.json",
            "--bundle-receipt-output",
            "unused-bundle-receipt.json",
            "--s3-prefix",
            "s3://unused",
            "--retain-until",
            "2027-07-28T00:00:00+00:00",
            "--kms-key-id",
            "unused",
            "--bundle-private-key",
            "unused.pem",
            "--signing-key-id",
            "unused",
        ],
    )
    with pytest.raises(SystemExit, match="test-only"):
        demo_chaos_matrix.main()


def test_exact_release_runner_machine_blocks_missing_raw_observation(
    monkeypatch,
):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "demo_chaos_matrix.py",
            "--config",
            "unused.yaml",
            "--scenario",
            "external-fill",
            "--confirm",
            demo_chaos_matrix.CONFIRMATION,
            "--soak-epoch-id",
            _EPOCH,
            "--output",
            "unused-result.json",
            "--identity-output",
            "unused-identity.json",
            "--manifest-output",
            "unused-manifest.json",
            "--bundle-receipt-output",
            "unused-bundle-receipt.json",
            "--s3-prefix",
            "s3://unused",
            "--retain-until",
            "2027-07-28T00:00:00+00:00",
            "--kms-key-id",
            "unused",
            "--bundle-private-key",
            "unused.pem",
            "--signing-key-id",
            "unused",
        ],
    )
    with pytest.raises(SystemExit, match="禁止本机手填"):
        demo_chaos_matrix.main()


def test_independent_raw_observation_requires_distinct_valid_signature(
    tmp_path,
):
    receipt = _receipt(
        "external-fill",
        started=datetime(2026, 7, 28, 12, tzinfo=UTC),
    )
    observer_private, observer_public = _key_pair(tmp_path, "observer")
    publisher_private, publisher_public = _key_pair(tmp_path, "publisher")
    claims = receipt["execution"]["raw_observation"]["payload"]
    claims["observer_key_fingerprint"] = (
        chaos_evidence.ed25519_public_key_fingerprint(observer_public)
    )
    receipt["execution"]["raw_observation"] = sign_ed25519_payload(
        claims,
        observer_private,
    )

    assert chaos_evidence.verify_independent_raw_observation_artifact(
        receipt["execution"]["raw_observation"],
        receipt=receipt,
        observer_public_key=observer_public,
        publisher_key=publisher_public,
    ) == claims
    assert claims["source"]["object_uri"].startswith("s3://")
    with pytest.raises(ValueError, match="EXTERNAL OPEN"):
        chaos_evidence.require_stage_c_production_capabilities((
            chaos_evidence.SCENARIO_BY_NAME["external-fill"],
        ))
    _verifier_private, verifier_public = _key_pair(
        tmp_path,
        "readback-verifier",
    )
    receipts_dir = tmp_path / "receipts"
    manifests_dir = tmp_path / "manifests"
    bundle_receipts_dir = tmp_path / "bundle-receipts"
    attestations_dir = tmp_path / "attestations"
    for directory in (
        receipts_dir,
        manifests_dir,
        bundle_receipts_dir,
        attestations_dir,
    ):
        directory.mkdir()
    (receipts_dir / "external-fill.json").write_text(
        json.dumps(receipt),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_verified_stage_c_receipts(
            receipts_dir=receipts_dir,
            manifests_dir=manifests_dir,
            bundle_receipts_dir=bundle_receipts_dir,
            bundle_signing_public_key=publisher_public,
            independent_attestations_dir=attestations_dir,
            raw_observer_public_key=observer_public,
            independent_verifier_public_key=verifier_public,
        )
    with pytest.raises(ValueError, match="独立于 publisher"):
        chaos_evidence.verify_independent_raw_observation_artifact(
            receipt["execution"]["raw_observation"],
            receipt=receipt,
            observer_public_key=observer_public,
            publisher_key=observer_private,
            publisher_key_is_private=True,
        )
    assert publisher_private.is_file()


def test_fault_proxy_control_uses_nofollow_owner_and_mode(tmp_path):
    control = tmp_path / "public.state"
    control.write_text("open\n", encoding="ascii")
    control.chmod(0o600)
    assert fault_proxy.read_control(
        control,
        expected_owner_uid=os.getuid(),
    ) == "open"

    control.chmod(0o666)
    with pytest.raises(RuntimeError, match="不可被非 owner"):
        fault_proxy.read_control(
            control,
            expected_owner_uid=os.getuid(),
        )
    control.chmod(0o600)
    link = tmp_path / "link.state"
    link.symlink_to(control)
    with pytest.raises(RuntimeError, match="安全打开"):
        fault_proxy.read_control(
            link,
            expected_owner_uid=os.getuid(),
        )
    control.write_text("invalid\n", encoding="ascii")
    with pytest.raises(RuntimeError, match="open/blocked"):
        fault_proxy.read_control(
            control,
            expected_owner_uid=os.getuid(),
        )


def test_fault_proxy_upstream_connect_is_bounded(monkeypatch):
    async def never_connect(*_args, **_kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(
        fault_proxy.asyncio,
        "open_connection",
        never_connect,
    )
    with pytest.raises(TimeoutError, match="未在"):
        asyncio.run(
            fault_proxy._open_upstream(
                "127.0.0.1",
                9,
                timeout=0.1,
            )
        )
    with pytest.raises(ValueError, match="0.1..30"):
        asyncio.run(
            fault_proxy._open_upstream(
                "127.0.0.1",
                9,
                timeout=31,
            )
        )
