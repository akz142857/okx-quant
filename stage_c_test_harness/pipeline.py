"""Real pipeline-boundary hooks for the isolated Stage-C test artifact.

This module is absent from the exact-release wheel.  The instrumented build
replaces exactly two reviewed source members with verifier-recomputed
transforms that call :func:`reach_pipeline_boundary`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from okx_quant.application.approval import (
    canonical_bytes,
    production_config_hash,
    verify_ed25519_artifact,
)
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.ops.stage_c_chaos_protocol import (
    _decode_opaque_bytes,
    _opaque_bytes_descriptor,
    verify_stage_c_challenge,
    verify_stage_c_consumption_receipt,
)
from stage_c_test_harness.barriers import (
    BARRIER_SCENARIOS,
    BarrierHook,
    BarrierStateStore,
    _atomic_new,
)

PIPELINE_PROOF_SCHEMA = "okx-quant.stage-c-pipeline-boundary-proof/v1"
PIPELINE_ACTIVATION_REQUEST_SCHEMA = (
    "okx-quant.stage-c-pipeline-activation-request/v1"
)
PIPELINE_ACTIVATION_ACTION = "attest-stage-c-fault-driver-activation-v1"
PIPELINE_RECOVERY_ACTION = "attest-stage-c-fault-driver-recovery-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ID128 = re.compile(
    r"(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})"
)
_INSTRUMENT = re.compile(r"[A-Z0-9]{2,20}-USDT")


def _stable_bytes(
    path: Path,
    *,
    label: str,
    maximum: int = 16 * 1024 * 1024,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} 无法安全打开") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError(f"{label} 必须是非空普通文件")
        raw = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise ValueError(f"{label} 读取期间发生变化")
        return raw
    finally:
        os.close(descriptor)


def load_pipeline_activation_request(path: Path) -> dict:
    try:
        value = json.loads(
            _stable_bytes(
                path,
                label="Stage-C pipeline activation request",
                maximum=2 * 1024 * 1024,
            )
        )
    except json.JSONDecodeError as exc:
        raise ValueError("Stage-C pipeline activation request JSON 非法") from exc
    if (
        not isinstance(value, dict)
        or set(value)
        != {"schema", "scenario", "challenge_artifact", "consumption_receipt"}
        or value["schema"] != PIPELINE_ACTIVATION_REQUEST_SCHEMA
        or value["scenario"] not in BARRIER_SCENARIOS
        or not isinstance(value["challenge_artifact"], dict)
        or not isinstance(value["consumption_receipt"], dict)
    ):
        raise ValueError("Stage-C pipeline activation request schema 非法")
    return value


def wait_for_pipeline_activation(
    path: Path,
    *,
    timeout_seconds: int,
) -> dict:
    if not 1 <= timeout_seconds <= 900:
        raise ValueError("Stage-C activation wait 必须在 1..900 秒")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_symlink():
            raise ValueError("Stage-C activation request 禁止符号链接")
        if path.is_file():
            return load_pipeline_activation_request(path)
        time.sleep(0.05)
    raise TimeoutError("等待 Stage-C signed activation request 超时")


def _normalize_id128(value: str, *, label: str) -> str:
    lowered = str(value).lower()
    if not _ID128.fullmatch(lowered):
        raise ValueError(f"{label} 非法")
    return lowered.replace("-", "")


def read_self_cgroup(path: Path = Path("/proc/self/cgroup")) -> str:
    raw = _stable_bytes(path, label="Stage-C self cgroup", maximum=64 * 1024)
    try:
        lines = raw.decode().splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("Stage-C self cgroup 非 UTF-8") from exc
    matches = [line.removeprefix("0::") for line in lines if line.startswith("0::")]
    if len(matches) != 1 or not matches[0].startswith("/system.slice/"):
        raise ValueError("Stage-C fault driver 必须位于 systemd cgroup v2 unit")
    return matches[0]


def fixed_pipeline_main_argv(
    *,
    config: Path,
    env_file: Path,
    inst_id: str,
) -> list[str]:
    if (
        not config.is_absolute()
        or not env_file.is_absolute()
        or not _INSTRUMENT.fullmatch(inst_id)
    ):
        raise ValueError("Stage-C fixed main argv 配置/交易对非法")
    return [
        "okx-quant",
        "--config",
        str(config),
        "--env-file",
        str(env_file),
        "live",
        "--inst",
        inst_id,
        "--strategy",
        "validation_probe",
        "--bar",
        "1m",
        "--interval",
        "5",
        "--no-dashboard",
        "--yes",
    ]


def stage_c_application_preflight(
    args: object,
    cfg: dict,
    settings: object,
    *,
    challenge: dict,
    activation: dict,
    process_argv: list[str],
) -> dict:
    """Authorize ``main`` only with the signed test-only process receipt.

    The ordinary Demo preflight is intentionally bound to the normal Demo
    service and cannot describe this challenge-specific unit.  This guard is
    present only in the instrumented archive and rechecks the registrar-bound
    process, config, account and fixed validation-probe argv immediately
    before ``main`` constructs an OKX client.
    """
    action = activation.get("action")
    recovery = action == PIPELINE_RECOVERY_ACTION
    expected_pid = activation.get("new_pid" if recovery else "pid")
    expected_invocation = activation.get(
        "new_systemd_invocation_id" if recovery else "systemd_invocation_id"
    )
    identity = challenge.get("identity", {})
    driver = challenge.get("workloads", {}).get("fault_driver", {})
    expected_argv = activation.get("main_argv")
    actual_cgroup = read_self_cgroup()
    if (
        action not in {PIPELINE_ACTIVATION_ACTION, PIPELINE_RECOVERY_ACTION}
        or activation.get("challenge_id") != challenge.get("challenge_id")
        or activation.get("scenario") != challenge.get("scenario")
        or expected_pid != os.getpid()
        or activation.get("uid") != os.getuid()
        or activation.get("config_sha256")
        != production_config_hash(settings, cfg)
        or activation.get("cgroup", driver.get("cgroup")) != actual_cgroup
        or _normalize_id128(
            str(expected_invocation),
            label="Stage-C receipt InvocationID",
        )
        != _normalize_id128(
            os.environ.get("INVOCATION_ID", ""),
            label="Stage-C live InvocationID",
        )
        or process_argv != expected_argv
        or getattr(args, "command", None) != "live"
        or getattr(args, "strategy", None) != "validation_probe"
        or getattr(args, "bar", None) != "1m"
        or getattr(args, "interval", None) != 5
        or getattr(args, "no_dashboard", None) is not True
        or getattr(args, "yes", None) is not True
        or [
            item.strip()
            for item in str(getattr(args, "inst", "")).split(",")
            if item.strip()
        ]
        != [expected_argv[7]]
        or getattr(settings, "environment", None) != "demo"
        or getattr(settings, "shadow_mode", None) is not False
        or getattr(settings, "account_id", None) != identity.get("account_uid")
        or activation.get("account_uid") != identity.get("account_uid")
        or activation.get("api_permissions") != ["read", "trade"]
        or activation.get("tls_certificate_sha256")
        != challenge.get("barrier_recovery_bindings", {}).get(
            "tls_certificate_sha256"
        )
        or activation.get("tls_spki_sha256")
        != challenge.get("barrier_recovery_bindings", {}).get(
            "tls_spki_sha256"
        )
        or activation.get("api_key_fingerprint")
        != hashlib.sha256(
            str(cfg.get("okx", {}).get("api_key", "")).encode()
        ).hexdigest()
        or cfg.get("okx", {}).get("simulated") is not True
        or identity.get("test_hooks_present") is not True
        or not str(identity.get("artifact_build_id", "")).startswith(
            "test-only:"
        )
    ):
        raise RuntimeError(
            "Stage-C instrumented process receipt/config/runtime binding 非法"
        )
    return activation


def verify_pipeline_activation(
    request: dict,
    *,
    scenario: str,
    registrar_public_key: Path,
    challenge_consumer_public_key: Path,
    fault_driver_private_key: Path,
    config_sha256: str,
    account_uid: str,
    api_key_fingerprint: str,
    api_permissions: tuple[str, ...],
    main_argv: list[str],
    archive_path: Path,
    interpreter_path: Path,
    actual_pid: int,
    actual_uid: int,
    actual_cgroup: str,
    actual_invocation_id: str,
    tls_certificate_sha256: str | None = None,
    tls_spki_sha256: str | None = None,
    activated_at: int | None = None,
    include_claims: bool = False,
) -> tuple[dict, dict] | tuple[dict, dict, dict]:
    """Verify one consumed challenge against the actual waiting process."""
    if (
        not isinstance(request, dict)
        or request.get("schema") != PIPELINE_ACTIVATION_REQUEST_SCHEMA
        or request.get("scenario") != scenario
        or scenario not in BARRIER_SCENARIOS
        or not _SHA256.fullmatch(config_sha256)
        or not _SHA256.fullmatch(api_key_fingerprint)
        or api_permissions != ("read", "trade")
        or type(actual_pid) is not int
        or actual_pid <= 1
        or type(actual_uid) is not int
        or actual_uid <= 0
    ):
        raise ValueError("Stage-C pipeline activation 基础字段非法")
    now = int(datetime.now(UTC).timestamp()) if activated_at is None else activated_at
    challenge_artifact = request["challenge_artifact"]
    challenge = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=registrar_public_key,
        scenario=scenario,
        now=now,
        enforce_current_window=True,
    )
    verify_stage_c_consumption_receipt(
        request["consumption_receipt"],
        challenge_artifact=challenge_artifact,
        registrar_public_key=registrar_public_key,
        consumer_public_key=challenge_consumer_public_key,
    )
    _validate_tls_binding(
        scenario=scenario,
        challenge=challenge,
        tls_certificate_sha256=tls_certificate_sha256,
        tls_spki_sha256=tls_spki_sha256,
    )
    driver = challenge["workloads"]["fault_driver"]
    identity = challenge["identity"]
    archive_sha256 = hashlib.sha256(
        _stable_bytes(archive_path, label="Stage-C instrumented archive")
    ).hexdigest()
    interpreter_sha256 = hashlib.sha256(
        _stable_bytes(interpreter_path, label="Stage-C Python interpreter")
    ).hexdigest()
    normalized_invocation = _normalize_id128(
        actual_invocation_id,
        label="Stage-C actual INVOCATION_ID",
    )
    expected_invocation = _normalize_id128(
        driver["systemd_invocation_id"],
        label="Stage-C challenge InvocationID",
    )
    expected_unit = actual_cgroup.removeprefix("/system.slice/")
    driver_key_fingerprint = ed25519_public_key_fingerprint(
        fault_driver_private_key,
        private_key=True,
    )
    if (
        identity["environment"] != "demo"
        or identity["test_hooks_present"] is not True
        or not identity["artifact_build_id"].startswith("test-only:")
        or identity["artifact_sha256"] != archive_sha256
        or identity["config_sha256"] != config_sha256
        or identity["account_uid"] != account_uid
        or identity["unit"] != expected_unit
        or driver["pid"] != actual_pid
        or driver["uid"] != actual_uid
        or driver["cgroup"] != actual_cgroup
        or expected_invocation != normalized_invocation
        or driver["executable_sha256"] != interpreter_sha256
        or challenge["source_key_fingerprints"]["fault_driver"]
        != driver_key_fingerprint
        or main_argv[0] != "okx-quant"
        or main_argv[1:]
        != fixed_pipeline_main_argv(
            config=Path(main_argv[2]),
            env_file=Path(main_argv[4]),
            inst_id=main_argv[7],
        )[1:]
    ):
        raise ValueError("Stage-C activation 未绑定实际 fault driver/build/config")
    claims = {
        "version": 1,
        "action": PIPELINE_ACTIVATION_ACTION,
        "scenario": scenario,
        "challenge_id": challenge["challenge_id"],
        "challenge_sha256": hashlib.sha256(
            canonical_bytes(challenge_artifact)
        ).hexdigest(),
        "consumption_receipt_sha256": hashlib.sha256(
            canonical_bytes(request["consumption_receipt"])
        ).hexdigest(),
        "pid": actual_pid,
        "uid": actual_uid,
        "cgroup": actual_cgroup,
        "systemd_invocation_id": driver["systemd_invocation_id"],
        "unit": identity["unit"],
        "instrumented_artifact_sha256": archive_sha256,
        "interpreter_sha256": interpreter_sha256,
        "config_sha256": config_sha256,
        "account_uid": account_uid,
        "api_key_fingerprint": api_key_fingerprint,
        "api_permissions": list(api_permissions),
        "tls_certificate_sha256": tls_certificate_sha256,
        "tls_spki_sha256": tls_spki_sha256,
        "main_argv": main_argv,
        "activated_at": now,
    }
    artifact = sign_ed25519_payload(claims, fault_driver_private_key)
    if include_claims:
        return challenge, artifact, claims
    return challenge, artifact


def verify_pipeline_recovery_activation(
    request: dict,
    *,
    scenario: str,
    registrar_public_key: Path,
    challenge_consumer_public_key: Path,
    kill_artifact: dict,
    kill_public_key: Path,
    fault_driver_private_key: Path,
    config_sha256: str,
    account_uid: str,
    api_key_fingerprint: str,
    api_permissions: tuple[str, ...],
    main_argv: list[str],
    archive_path: Path,
    interpreter_path: Path,
    actual_pid: int,
    actual_uid: int,
    actual_cgroup: str,
    actual_invocation_id: str,
    tls_certificate_sha256: str | None = None,
    tls_spki_sha256: str | None = None,
    activated_at: int | None = None,
    include_claims: bool = False,
) -> tuple[dict, dict] | tuple[dict, dict, dict]:
    """Authorize only the new invocation proven after the signed SIGKILL."""
    now = int(datetime.now(UTC).timestamp()) if activated_at is None else activated_at
    if (
        not isinstance(request, dict)
        or request.get("schema") != PIPELINE_ACTIVATION_REQUEST_SCHEMA
        or request.get("scenario") != scenario
        or not _SHA256.fullmatch(config_sha256)
        or not _SHA256.fullmatch(api_key_fingerprint)
        or api_permissions != ("read", "trade")
        or type(actual_pid) is not int
        or actual_pid <= 1
        or type(actual_uid) is not int
        or actual_uid <= 0
    ):
        raise ValueError("Stage-C pipeline recovery activation 基础字段非法")
    challenge_artifact = request["challenge_artifact"]
    challenge = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=registrar_public_key,
        scenario=scenario,
        now=now,
        enforce_current_window=True,
    )
    verify_stage_c_consumption_receipt(
        request["consumption_receipt"],
        challenge_artifact=challenge_artifact,
        registrar_public_key=registrar_public_key,
        consumer_public_key=challenge_consumer_public_key,
    )
    _validate_tls_binding(
        scenario=scenario,
        challenge=challenge,
        tls_certificate_sha256=tls_certificate_sha256,
        tls_spki_sha256=tls_spki_sha256,
    )
    killed = verify_ed25519_artifact(
        kill_artifact,
        kill_public_key,
        label="Stage-C recovery kill artifact",
    )
    driver = challenge["workloads"]["fault_driver"]
    identity = challenge["identity"]
    try:
        inactive = dict(
            line.split("=", 1)
            for line in _decode_opaque_bytes(
                killed["inactive_systemd_show"],
                "Stage-C inactive systemd show",
            ).decode().splitlines()
            if "=" in line
        )
    except (KeyError, UnicodeDecodeError) as exc:
        raise ValueError("Stage-C recovery kill raw chain 非法") from exc
    archive_sha256 = hashlib.sha256(
        _stable_bytes(archive_path, label="Stage-C instrumented archive")
    ).hexdigest()
    interpreter_sha256 = hashlib.sha256(
        _stable_bytes(interpreter_path, label="Stage-C Python interpreter")
    ).hexdigest()
    normalized_invocation = _normalize_id128(
        actual_invocation_id,
        label="Stage-C recovery INVOCATION_ID",
    )
    old_invocation = _normalize_id128(
        driver["systemd_invocation_id"],
        label="Stage-C old INVOCATION_ID",
    )
    expected_unit = actual_cgroup.removeprefix("/system.slice/")
    if (
        killed.get("action") != "attest-stage-c-process-kill-v2"
        or killed.get("challenge_id") != challenge["challenge_id"]
        or killed.get("scenario") != scenario
        or killed.get("nonce") != challenge["barrier_nonce"]
        or killed.get("artifact_sha256") != identity["artifact_sha256"]
        or killed.get("old_pid") != driver["pid"]
        or killed.get("old_process_inactive") is not True
        or inactive.get("ActiveState") == "active"
        or int(inactive.get("MainPID", driver["pid"])) == driver["pid"]
        or actual_pid == driver["pid"]
        or normalized_invocation == old_invocation
        or actual_uid != driver["uid"]
        or actual_cgroup != driver["cgroup"]
        or identity["unit"] != expected_unit
        or identity["artifact_sha256"] != archive_sha256
        or identity["config_sha256"] != config_sha256
        or identity["account_uid"] != account_uid
        or driver["executable_sha256"] != interpreter_sha256
        or challenge["source_key_fingerprints"]["fault_driver"]
        != ed25519_public_key_fingerprint(
            fault_driver_private_key,
            private_key=True,
        )
        or challenge["kill_controller_key_fingerprint"]
        != ed25519_public_key_fingerprint(kill_public_key)
        or main_argv[0] != "okx-quant"
        or main_argv[1:]
        != fixed_pipeline_main_argv(
            config=Path(main_argv[2]),
            env_file=Path(main_argv[4]),
            inst_id=main_argv[7],
        )[1:]
    ):
        raise ValueError("Stage-C recovery invocation/build/kill 未闭合")
    claims = {
        "version": 1,
        "action": PIPELINE_RECOVERY_ACTION,
        "scenario": scenario,
        "challenge_id": challenge["challenge_id"],
        "kill_artifact_sha256": hashlib.sha256(
            canonical_bytes(kill_artifact)
        ).hexdigest(),
        "old_pid": driver["pid"],
        "new_pid": actual_pid,
        "uid": actual_uid,
        "old_systemd_invocation_id": driver["systemd_invocation_id"],
        "new_systemd_invocation_id": actual_invocation_id,
        "cgroup": actual_cgroup,
        "instrumented_artifact_sha256": archive_sha256,
        "interpreter_sha256": interpreter_sha256,
        "config_sha256": config_sha256,
        "account_uid": account_uid,
        "api_key_fingerprint": api_key_fingerprint,
        "api_permissions": list(api_permissions),
        "tls_certificate_sha256": tls_certificate_sha256,
        "tls_spki_sha256": tls_spki_sha256,
        "main_argv": main_argv,
        "activated_at": now,
    }
    artifact = sign_ed25519_payload(claims, fault_driver_private_key)
    if include_claims:
        return challenge, artifact, claims
    return challenge, artifact


def _read_rows(
    database: Path,
    statements: tuple[tuple[str, tuple[object, ...]], ...],
) -> list[dict]:
    if not database.is_file() or database.is_symlink():
        raise RuntimeError("Stage-C pipeline journal 不是安全普通文件")
    connection = sqlite3.connect(
        f"{database.resolve().as_uri()}?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    try:
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Stage-C pipeline journal integrity_check 失败")
        result = []
        for sql, parameters in statements:
            rows = connection.execute(sql, parameters).fetchall()
            result.append({
                "sql_sha256": hashlib.sha256(sql.encode()).hexdigest(),
                "parameters": [str(value) for value in parameters],
                "columns": list(rows[0].keys()) if rows else [],
                "rows": [list(row) for row in rows],
            })
        return result
    finally:
        connection.close()


def _buy_intent_proof(*, journal, probe_row: dict) -> dict:
    probe_id = str(probe_row.get("probe_id", ""))
    cl_ord_id = str(probe_row.get("buy_cl_ord_id", ""))
    if (
        len(probe_id) != 32
        or not cl_ord_id
        or probe_row.get("state") != "BUY_SUBMITTING"
    ):
        raise RuntimeError("BUY_SUBMITTING boundary 缺少 durable probe identity")
    queries = _read_rows(
        Path(journal.path),
        (
            (
                "SELECT probe_id, state, buy_cl_ord_id, buy_intent_id, "
                "version FROM probe_runs WHERE probe_id=?",
                (probe_id,),
            ),
            (
                "SELECT intent_id, cl_ord_id, state FROM order_intents "
                "WHERE probe_id=? OR cl_ord_id=? ORDER BY intent_id",
                (probe_id, cl_ord_id),
            ),
        ),
    )
    probe_rows = queries[0]["rows"]
    intent_rows = queries[1]["rows"]
    if (
        len(probe_rows) != 1
        or probe_rows[0][0] != probe_id
        or probe_rows[0][1] != "BUY_SUBMITTING"
        or probe_rows[0][2] != cl_ord_id
        or probe_rows[0][3] is not None
        or intent_rows
    ):
        raise RuntimeError(
            "BUY_SUBMITTING 未证明已提交且第一笔 POST 尚未进入执行层"
        )
    return {
        "probe_id": probe_id,
        "cl_ord_id": cl_ord_id,
        "intent_state": "BUY_SUBMITTING",
        "intent_tx_committed": True,
        "order_intent_count": 0,
        "socket_write_count": 0,
        "sqlite_queries": queries,
    }


def _fill_proof(*, journal, exchange_order, raw_event: dict) -> dict | None:
    quantity = Decimal(str(exchange_order.acc_fill_qty))
    if quantity <= 0:
        return None
    trade_id = str(exchange_order.trade_id)
    order_id = str(exchange_order.ord_id)
    if not trade_id or not order_id or not isinstance(raw_event, dict):
        raise RuntimeError("fill boundary 缺少 ordId/tradeId/raw event")
    queries = _read_rows(
        Path(journal.path),
        (
            (
                "SELECT fill_id, trade_id, exchange_ord_id, fill_qty "
                "FROM fills WHERE trade_id=? OR exchange_ord_id=? "
                "ORDER BY fill_id",
                (trade_id, order_id),
            ),
            (
                "SELECT inst_id, base_qty, version FROM positions "
                "WHERE inst_id=?",
                (str(exchange_order.inst_id),),
            ),
        ),
    )
    if queries[0]["rows"]:
        raise RuntimeError("fill-before-projection boundary 已存在本地 fill")
    raw = canonical_bytes(raw_event)
    return {
        "ord_id": order_id,
        "trade_id": trade_id,
        "qty": str(quantity),
        "fee": str(exchange_order.fee),
        "fee_ccy": str(exchange_order.fee_ccy),
        "base_ccy": str(exchange_order.inst_id).split("-")[0],
        "projection_apply_count": 0,
        "projection_rows_before": queries,
        "raw_exchange_event": _opaque_bytes_descriptor(raw),
    }


@dataclass
class PipelineBarrierRuntime:
    """One armed, one-shot barrier tied to a registrar challenge."""

    challenge: dict
    hook: BarrierHook
    proof_output: Path
    wait_for_kill: Callable[[], None] = BarrierHook.wait_for_systemd_kill

    def __post_init__(self) -> None:
        scenario = self.challenge.get("scenario")
        if (
            scenario not in BARRIER_SCENARIOS
            or self.hook.challenge != self.challenge
            or self.proof_output.exists()
            or self.proof_output.is_symlink()
        ):
            raise ValueError("Stage-C pipeline runtime 未绑定新鲜 challenge")
        self._lock = threading.Lock()
        self._reached = False

    @property
    def expected_boundary(self) -> str:
        return BARRIER_SCENARIOS[self.challenge["scenario"]]

    def reach(self, boundary: str, **values: object) -> None:
        if boundary != self.expected_boundary:
            return
        with self._lock:
            if self._reached:
                raise RuntimeError("Stage-C pipeline barrier 已到达")
            if boundary == "buy-intent-before-post":
                facts = _buy_intent_proof(
                    journal=values.get("journal"),
                    probe_row=values.get("probe_row"),
                )
            elif boundary == "fill-before-projection":
                facts = _fill_proof(
                    journal=values.get("journal"),
                    exchange_order=values.get("exchange_order"),
                    raw_event=values.get("raw_event"),
                )
                if facts is None:
                    return
            else:
                raise RuntimeError(
                    "post-before-ack 必须由隔离 TLS proxy 到达"
                )
            proof = {
                "schema": PIPELINE_PROOF_SCHEMA,
                "scenario": self.challenge["scenario"],
                "challenge_id": self.challenge["challenge_id"],
                "barrier_nonce": self.challenge["barrier_nonce"],
                "artifact_sha256": self.challenge["identity"][
                    "artifact_sha256"
                ],
                "boundary": boundary,
                "pid": os.getpid(),
                "facts": facts,
            }
            proof_sha256 = hashlib.sha256(
                canonical_bytes(proof)
            ).hexdigest()
            _atomic_new(self.proof_output, proof, mode=0o640)
            self.hook.reach(
                boundary,
                boundary_proof_sha256=proof_sha256,
            )
            self._reached = True
        self.wait_for_kill()
        raise RuntimeError("Stage-C kill waiter 非法返回")


_ACTIVE_LOCK = threading.Lock()
_ACTIVE_RUNTIME: PipelineBarrierRuntime | None = None


def activate_pipeline_barrier(runtime: PipelineBarrierRuntime) -> None:
    """Arm one process-local test barrier; there is no env/config loader."""
    if not isinstance(runtime, PipelineBarrierRuntime):
        raise TypeError("Stage-C pipeline runtime 类型非法")
    global _ACTIVE_RUNTIME
    with _ACTIVE_LOCK:
        if _ACTIVE_RUNTIME is not None:
            raise RuntimeError("Stage-C pipeline barrier 已激活")
        _ACTIVE_RUNTIME = runtime


def deactivate_pipeline_barrier_for_test() -> None:
    """Test cleanup only; the instrumented systemd process is kill-only."""
    global _ACTIVE_RUNTIME
    with _ACTIVE_LOCK:
        _ACTIVE_RUNTIME = None


def reach_pipeline_boundary(boundary: str, **values: object) -> None:
    with _ACTIVE_LOCK:
        runtime = _ACTIVE_RUNTIME
    if runtime is None:
        raise RuntimeError(
            "instrumented Stage-C artifact 未通过 signed challenge 激活"
        )
    runtime.reach(boundary, **values)


def build_pipeline_runtime(
    *,
    challenge: dict,
    state_database: Path,
    marker_output: Path,
    proof_output: Path,
    systemd_invocation_id: str,
    pid: int | None = None,
    wait_for_kill: Callable[[], None] = BarrierHook.wait_for_systemd_kill,
) -> PipelineBarrierRuntime:
    """Construct the runtime only from already verified challenge claims."""
    return PipelineBarrierRuntime(
        challenge=challenge,
        hook=BarrierHook(
            challenge=challenge,
            state_store=BarrierStateStore(state_database),
            marker_output=marker_output,
            systemd_invocation_id=systemd_invocation_id,
            pid=pid,
        ),
        proof_output=proof_output,
        wait_for_kill=wait_for_kill,
    )


def load_pipeline_proof(path: Path, *, marker: dict) -> dict:
    """Read and bind the immutable sidecar to the reached marker."""
    if not path.is_file() or path.is_symlink():
        raise ValueError("Stage-C pipeline proof 不是普通文件")
    value = json.loads(path.read_bytes())
    if (
        not isinstance(value, dict)
        or value.get("schema") != PIPELINE_PROOF_SCHEMA
        or hashlib.sha256(canonical_bytes(value)).hexdigest()
        != marker.get("boundary_proof_sha256")
        or value.get("scenario") != marker.get("scenario")
        or value.get("challenge_id") != marker.get("challenge_id")
        or value.get("barrier_nonce") != marker.get("nonce")
        or value.get("artifact_sha256") != marker.get("artifact_sha256")
        or value.get("boundary") != marker.get("barrier")
        or value.get("pid") != marker.get("pid")
    ):
        raise ValueError("Stage-C pipeline proof 未绑定 reached marker")
    return value
def tls_certificate_identity(certificate: Path) -> dict[str, str]:
    """Derive the exact leaf and SPKI hashes trusted by the local TLS client."""
    raw = _stable_bytes(
        certificate,
        label="Stage-C TLS certificate",
        maximum=256 * 1024,
    )
    der = subprocess.run(
        ["/usr/bin/openssl", "x509", "-outform", "DER"],
        input=raw,
        capture_output=True,
        check=False,
        timeout=5,
    )
    public = subprocess.run(
        ["/usr/bin/openssl", "x509", "-pubkey", "-noout"],
        input=raw,
        capture_output=True,
        check=False,
        timeout=5,
    )
    spki = subprocess.run(
        ["/usr/bin/openssl", "pkey", "-pubin", "-outform", "DER"],
        input=public.stdout,
        capture_output=True,
        check=False,
        timeout=5,
    )
    if (
        der.returncode != 0
        or not der.stdout
        or public.returncode != 0
        or not public.stdout
        or spki.returncode != 0
        or not spki.stdout
    ):
        raise ValueError("Stage-C TLS certificate/SPKI 无法解析")
    return {
        "tls_certificate_sha256": hashlib.sha256(der.stdout).hexdigest(),
        "tls_spki_sha256": hashlib.sha256(spki.stdout).hexdigest(),
    }


def _validate_tls_binding(
    *,
    scenario: str,
    challenge: dict,
    tls_certificate_sha256: str | None,
    tls_spki_sha256: str | None,
) -> None:
    expected = challenge.get("barrier_recovery_bindings", {})
    actual = {
        "tls_certificate_sha256": tls_certificate_sha256,
        "tls_spki_sha256": tls_spki_sha256,
    }
    if scenario == "barrier-post-before-ack":
        if (
            not all(_SHA256.fullmatch(str(value)) for value in actual.values())
            or any(expected.get(key) != value for key, value in actual.items())
        ):
            raise ValueError("Stage-C recovery TLS certificate/SPKI 未绑定 challenge")
    elif any(value is not None for value in actual.values()):
        raise ValueError("非 TLS barrier 禁止 recovery TLS identity")
