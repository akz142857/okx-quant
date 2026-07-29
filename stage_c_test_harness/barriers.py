"""Test-only deterministic barriers and fail-closed recovery contracts.

No production configuration or environment variable can construct a hook.
The only constructor accepts a registrar-signed, globally consumed Stage-C
challenge and a recomputed instrumented build identity.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.ops.stage_c_chaos_protocol import (
    _decode_opaque_bytes,
    _opaque_bytes_descriptor,
)

BARRIER_SCENARIOS = {
    "barrier-buy-intent-before-post": "buy-intent-before-post",
    "barrier-post-before-ack": "post-before-ack",
    "barrier-fill-before-projection": "fill-before-projection",
}
PHASE_CONSUMPTION_ACTION = "attest-stage-c-barrier-phase-consumption-v1"
REACHED_ACTION = "attest-stage-c-barrier-reached-v2"
KILL_ACTION = "attest-stage-c-process-kill-v2"
MARKER_SCHEMA = "okx-quant.stage-c-barrier-marker/v2"
RECOVERY_SCHEMA = "okx-quant.stage-c-barrier-recovery/v1"
EXTERNAL_CAPABILITY_REQUIREMENTS = (
    "final_epoch_exact_release_digest_binding",
    "independent_build_signer_attestation",
    "independent_worm_exact_version_readback",
    "production_unit_hook_absence_and_sandbox_attestation",
    "production_black_box_barrier_activation_rejection",
    "role_local_uid_unit_sts_key_attestations",
    "reached_global_conditional_consumption",
    "kill_global_conditional_consumption",
    "systemd_old_inactive_new_invocation_raw_chain",
    "scenario_specific_live_okx_tls_sqlite_collectors",
    "post_recovery_single_snapshot_common_facts",
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[0-9a-f]{32}")
_UUID = re.compile(
    r"(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})"
)


def _strict(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} schema 非法")
    return value


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _decimal(value: object, label: str, *, positive: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"{label} 非法")
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"{label} 非法") from exc
    if not parsed.is_finite() or (positive and parsed <= 0):
        raise ValueError(f"{label} 非法")
    return parsed


def _iso(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} 非法")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} 非法") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} 缺少时区")
    return parsed.astimezone(UTC)


def _atomic_new(path: Path, value: object, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    payload = canonical_bytes(value) + b"\n"
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _safe_json(path: Path, *, label: str, maximum: int = 2 * 1024 * 1024) -> dict:
    if (
        not path.is_file()
        or path.is_symlink()
        or not 0 < path.stat().st_size <= maximum
    ):
        raise ValueError(f"{label} 不是安全普通文件")
    try:
        value = json.loads(path.read_bytes())
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} JSON 非法") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是 object")
    return value


def barrier_phase_key(
    *,
    scenario: str,
    challenge_id: str,
    nonce: str,
    artifact_sha256: str,
    phase: str,
) -> str:
    if (
        scenario not in BARRIER_SCENARIOS
        or not _RUN_ID.fullmatch(challenge_id)
        or not _RUN_ID.fullmatch(nonce)
        or not _SHA256.fullmatch(artifact_sha256)
        or phase not in {"reached", "kill"}
    ):
        raise ValueError("barrier phase key fields 非法")
    return hashlib.sha256(canonical_bytes({
        "scenario": scenario,
        "challenge_id": challenge_id,
        "nonce": nonce,
        "artifact_sha256": artifact_sha256,
        "phase": phase,
    })).hexdigest()


def consume_barrier_phase_globally(
    *,
    challenge: dict,
    phase: str,
    private_key: Path,
    backend: dict,
    aws_executable: Path = Path("/usr/bin/aws"),
    command_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    consumed_at: int | None = None,
) -> dict:
    """Consume reached/kill once with DynamoDB conditional put + strong read."""
    _strict(
        backend,
        {"kind", "table_name", "region", "account_id"},
        "barrier phase backend",
    )
    if (
        backend["kind"] != "dynamodb-conditional-put-v1"
        or not str(backend["table_name"]).strip()
        or not str(backend["region"]).strip()
        or not re.fullmatch(r"[0-9]{12}", str(backend["account_id"]))
    ):
        raise ValueError("barrier phase backend 非法")
    phase_key = barrier_phase_key(
        scenario=challenge["scenario"],
        challenge_id=challenge["challenge_id"],
        nonce=challenge["barrier_nonce"],
        artifact_sha256=challenge["identity"]["artifact_sha256"],
        phase=phase,
    )
    now = int(datetime.now(UTC).timestamp()) if consumed_at is None else consumed_at
    item = {
        "phase_key": {"S": phase_key},
        "scenario": {"S": challenge["scenario"]},
        "challenge_id": {"S": challenge["challenge_id"]},
        "nonce": {"S": challenge["barrier_nonce"]},
        "artifact_sha256": {
            "S": challenge["identity"]["artifact_sha256"],
        },
        "phase": {"S": phase},
        "consumed_at": {"N": str(now)},
    }
    common = [
        str(aws_executable),
        "dynamodb",
    ]
    put = command_runner(
        [
            *common,
            "put-item",
            "--table-name",
            backend["table_name"],
            "--region",
            backend["region"],
            "--item",
            json.dumps(item, sort_keys=True, separators=(",", ":")),
            "--condition-expression",
            "attribute_not_exists(phase_key)",
            "--return-consumed-capacity",
            "TOTAL",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        capture_output=True,
        check=False,
        timeout=15,
    )
    if put.returncode != 0:
        raise ValueError("barrier phase 已消费或 conditional put 失败")
    get = command_runner(
        [
            *common,
            "get-item",
            "--table-name",
            backend["table_name"],
            "--region",
            backend["region"],
            "--key",
            json.dumps(
                {"phase_key": {"S": phase_key}},
                sort_keys=True,
                separators=(",", ":"),
            ),
            "--consistent-read",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        capture_output=True,
        check=False,
        timeout=15,
    )
    if get.returncode != 0:
        raise ValueError("barrier phase consistent read 失败")
    try:
        put_value = json.loads(put.stdout)
        get_value = json.loads(get.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("barrier phase DynamoDB response 非法") from exc
    if (
        not isinstance(put_value, dict)
        or put_value.get("ConsumedCapacity", {}).get("TableName")
        != backend["table_name"]
        or not isinstance(get_value, dict)
        or get_value.get("Item") != item
    ):
        raise ValueError("barrier phase conditional write/readback 不一致")
    claims = {
        "version": 1,
        "action": PHASE_CONSUMPTION_ACTION,
        "phase_key": phase_key,
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "phase": phase,
        "backend": backend,
        "item": item,
        "conditional_put_response_sha256": hashlib.sha256(
            put.stdout
        ).hexdigest(),
        "consistent_read_response_sha256": hashlib.sha256(
            get.stdout
        ).hexdigest(),
        "consumed_at": now,
    }
    return sign_ed25519_payload(claims, private_key)


def verify_phase_consumption(
    artifact: object,
    *,
    public_key: Path,
    challenge: dict,
    phase: str,
) -> dict:
    claims = verify_ed25519_artifact(
        artifact,
        public_key,
        label=f"Stage-C barrier {phase} consumption",
    )
    expected_key = barrier_phase_key(
        scenario=challenge["scenario"],
        challenge_id=challenge["challenge_id"],
        nonce=challenge["barrier_nonce"],
        artifact_sha256=challenge["identity"]["artifact_sha256"],
        phase=phase,
    )
    if (
        claims.get("version") != 1
        or claims.get("action") != PHASE_CONSUMPTION_ACTION
        or claims.get("phase_key") != expected_key
        or claims.get("scenario") != challenge["scenario"]
        or claims.get("challenge_id") != challenge["challenge_id"]
        or claims.get("nonce") != challenge["barrier_nonce"]
        or claims.get("artifact_sha256")
        != challenge["identity"]["artifact_sha256"]
        or claims.get("phase") != phase
    ):
        raise ValueError("barrier phase consumption 未绑定 challenge")
    return claims


class BarrierStateStore:
    """Local durable marker store; authorization remains external DynamoDB."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS barrier_markers(
                    phase_key TEXT PRIMARY KEY,
                    scenario TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    barrier TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    systemd_invocation_id TEXT NOT NULL,
                    reached_at TEXT NOT NULL,
                    monotonic_ns INTEGER NOT NULL,
                    boundary_proof_sha256 TEXT NOT NULL,
                    marker_sha256 TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def record_reached(self, marker: dict) -> dict:
        _strict(
            marker,
            {
                "schema",
                "scenario",
                "challenge_id",
                "nonce",
                "artifact_sha256",
                "barrier",
                "pid",
                "systemd_invocation_id",
                "reached_at",
                "monotonic_ns",
                "boundary_proof_sha256",
            },
            "barrier marker",
        )
        if not _SHA256.fullmatch(str(marker["boundary_proof_sha256"])):
            raise ValueError("barrier boundary proof digest 非法")
        phase_key = barrier_phase_key(
            scenario=marker["scenario"],
            challenge_id=marker["challenge_id"],
            nonce=marker["nonce"],
            artifact_sha256=marker["artifact_sha256"],
            phase="reached",
        )
        marker_sha = _sha(marker)
        connection = sqlite3.connect(self.path)
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO barrier_markers VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        phase_key,
                        marker["scenario"],
                        marker["challenge_id"],
                        marker["nonce"],
                        marker["artifact_sha256"],
                        marker["barrier"],
                        marker["pid"],
                        marker["systemd_invocation_id"],
                        marker["reached_at"],
                        marker["monotonic_ns"],
                        marker["boundary_proof_sha256"],
                        marker_sha,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("barrier marker nonce/reached 已使用") from exc
        finally:
            connection.close()
        return {**marker, "marker_sha256": marker_sha}

    def get(self, phase_key: str) -> dict:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT * FROM barrier_markers WHERE phase_key=?",
                (phase_key,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ValueError("barrier reached marker 不存在")
        return dict(row)


class BarrierHook:
    """One exact boundary hook for the isolated instrumented artifact."""

    def __init__(
        self,
        *,
        challenge: dict,
        state_store: BarrierStateStore,
        marker_output: Path,
        systemd_invocation_id: str,
        pid: int | None = None,
    ):
        scenario = challenge.get("scenario")
        if (
            scenario not in BARRIER_SCENARIOS
            or challenge.get("barrier_nonce") is None
            or challenge.get("identity", {}).get("test_hooks_present")
            is not True
            or not str(
                challenge.get("identity", {}).get("artifact_build_id", "")
            ).startswith("test-only:")
            or not _UUID.fullmatch(systemd_invocation_id.lower())
        ):
            raise ValueError("拒绝为非 test-only signed challenge 构造 barrier")
        self.challenge = challenge
        self.state_store = state_store
        self.marker_output = marker_output
        self.systemd_invocation_id = systemd_invocation_id.lower()
        self.pid = os.getpid() if pid is None else pid
        if self.pid <= 1:
            raise ValueError("barrier pid 非法")

    def reach(
        self,
        boundary: str,
        *,
        boundary_proof_sha256: str,
    ) -> dict:
        expected = BARRIER_SCENARIOS[self.challenge["scenario"]]
        if (
            boundary != expected
            or not _SHA256.fullmatch(boundary_proof_sha256)
        ):
            raise ValueError("barrier boundary 与 challenge 不匹配")
        marker = {
            "schema": MARKER_SCHEMA,
            "scenario": self.challenge["scenario"],
            "challenge_id": self.challenge["challenge_id"],
            "nonce": self.challenge["barrier_nonce"],
            "artifact_sha256": self.challenge["identity"][
                "artifact_sha256"
            ],
            "barrier": boundary,
            "pid": self.pid,
            "systemd_invocation_id": self.systemd_invocation_id,
            "reached_at": datetime.now(UTC).isoformat(),
            "monotonic_ns": time.monotonic_ns(),
            "boundary_proof_sha256": boundary_proof_sha256,
        }
        recorded = self.state_store.record_reached(marker)
        # The marker is immutable but must be readable by the independently
        # sandboxed attestor/recovery UIDs.  The deployment gives those UIDs a
        # shared read-only evidence group; 0640 keeps it non-public while the
        # O_EXCL write still prevents replacement.
        _atomic_new(self.marker_output, recorded, mode=0o640)
        return recorded

    @staticmethod
    def wait_for_systemd_kill() -> None:
        while True:
            time.sleep(60)


def attest_barrier_reached(
    *,
    marker: dict,
    boundary_proof: dict,
    challenge: dict,
    phase_consumption: dict,
    phase_consumer_public_key: Path,
    private_key: Path,
) -> dict:
    _strict(
        marker,
        {
            "schema",
            "scenario",
            "challenge_id",
            "nonce",
            "artifact_sha256",
            "barrier",
            "pid",
            "systemd_invocation_id",
            "reached_at",
            "monotonic_ns",
            "boundary_proof_sha256",
            "marker_sha256",
        },
        "barrier reached marker",
    )
    if not isinstance(boundary_proof, dict):
        raise ValueError("barrier boundary proof 非对象")
    proof_sha256 = _sha(boundary_proof)
    if (
        marker["boundary_proof_sha256"] != proof_sha256
        or boundary_proof.get("scenario") != challenge["scenario"]
        or boundary_proof.get("challenge_id") != challenge["challenge_id"]
        or boundary_proof.get("barrier_nonce") != challenge["barrier_nonce"]
        or boundary_proof.get("artifact_sha256")
        != challenge["identity"]["artifact_sha256"]
        or boundary_proof.get("boundary")
        != BARRIER_SCENARIOS[challenge["scenario"]]
        or boundary_proof.get("pid")
        != challenge["workloads"]["fault_driver"]["pid"]
    ):
        raise ValueError("barrier boundary proof 未绑定 marker/challenge")
    verify_phase_consumption(
        phase_consumption,
        public_key=phase_consumer_public_key,
        challenge=challenge,
        phase="reached",
    )
    expected = {
        "schema": MARKER_SCHEMA,
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "barrier": BARRIER_SCENARIOS[challenge["scenario"]],
        "pid": challenge["workloads"]["fault_driver"]["pid"],
        "systemd_invocation_id": challenge["workloads"][
            "fault_driver"
        ]["systemd_invocation_id"],
        "reached_at": marker["reached_at"],
        "monotonic_ns": marker["monotonic_ns"],
        "boundary_proof_sha256": marker["boundary_proof_sha256"],
    }
    if (
        {key: marker[key] for key in expected} != expected
        or marker["marker_sha256"] != _sha(expected)
    ):
        raise ValueError("barrier marker 未绑定 challenge/workload")
    return sign_ed25519_payload(
        {
            "version": 2,
            "action": REACHED_ACTION,
            "challenge_id": challenge["challenge_id"],
            "scenario": challenge["scenario"],
            "barrier": BARRIER_SCENARIOS[challenge["scenario"]],
            "nonce": challenge["barrier_nonce"],
            "artifact_sha256": challenge["identity"]["artifact_sha256"],
            "pid": marker["pid"],
            "systemd_invocation_id": marker["systemd_invocation_id"],
            "observed_at": marker["reached_at"],
            "monotonic_ns": marker["monotonic_ns"],
            "marker_sha256": marker["marker_sha256"],
            "boundary_proof_sha256": marker[
                "boundary_proof_sha256"
            ],
            "phase_consumption_sha256": _sha(phase_consumption),
        },
        private_key,
    )


def execute_systemd_kill(
    *,
    challenge: dict,
    reached_artifact: dict,
    reached_public_key: Path,
    reached_consumption: dict,
    reached_consumer_public_key: Path,
    kill_consumption: dict,
    kill_consumer_public_key: Path,
    private_key: Path,
    unit: str,
    systemctl_executable: Path = Path("/usr/bin/systemctl"),
    command_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict:
    """Verify reached, SIGKILL the exact unit, and prove old PID inactive."""
    if (
        ed25519_public_key_fingerprint(reached_public_key)
        != challenge["barrier_attestor_key_fingerprint"]
        or ed25519_public_key_fingerprint(private_key, private_key=True)
        != challenge["kill_controller_key_fingerprint"]
    ):
        raise ValueError("kill controller role key 未绑定 challenge")
    if (
        unit != challenge["identity"]["unit"]
        or "/" in unit
        or not unit.endswith(".service")
    ):
        raise ValueError("kill controller unit 未绑定 challenge")
    reached = verify_ed25519_artifact(
        reached_artifact,
        reached_public_key,
        label="barrier reached",
    )
    verify_phase_consumption(
        reached_consumption,
        public_key=reached_consumer_public_key,
        challenge=challenge,
        phase="reached",
    )
    verify_phase_consumption(
        kill_consumption,
        public_key=kill_consumer_public_key,
        challenge=challenge,
        phase="kill",
    )
    old_pid = challenge["workloads"]["fault_driver"]["pid"]
    if (
        reached.get("action") != REACHED_ACTION
        or reached.get("challenge_id") != challenge["challenge_id"]
        or reached.get("scenario") != challenge["scenario"]
        or reached.get("barrier") != BARRIER_SCENARIOS[challenge["scenario"]]
        or reached.get("nonce") != challenge["barrier_nonce"]
        or reached.get("artifact_sha256")
        != challenge["identity"]["artifact_sha256"]
        or reached.get("pid") != old_pid
        or reached.get("systemd_invocation_id")
        != challenge["workloads"]["fault_driver"]["systemd_invocation_id"]
        or not _SHA256.fullmatch(str(reached.get("marker_sha256", "")))
        or not _SHA256.fullmatch(
            str(reached.get("boundary_proof_sha256", ""))
        )
        or reached.get("phase_consumption_sha256")
        != _sha(reached_consumption)
    ):
        raise ValueError("kill controller reached artifact 非法")
    kill = command_runner(
        [
            str(systemctl_executable),
            "kill",
            "--signal=SIGKILL",
            "--kill-whom=main",
            unit,
        ],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if kill.returncode != 0:
        raise RuntimeError("systemd SIGKILL 失败")
    deadline = time.monotonic() + 5
    show = None
    while time.monotonic() < deadline:
        candidate = command_runner(
            [
                str(systemctl_executable),
                "show",
                unit,
                "--property=MainPID,InvocationID,ActiveState,SubState",
                "--no-pager",
            ],
            capture_output=True,
            check=False,
            timeout=10,
        )
        candidate_values = {}
        if candidate.returncode == 0 and candidate.stdout:
            for line in candidate.stdout.decode().splitlines():
                key, separator, value = line.partition("=")
                if separator:
                    candidate_values[key] = value
        if (
            set(candidate_values)
            == {"MainPID", "InvocationID", "ActiveState", "SubState"}
            and int(candidate_values["MainPID"]) != old_pid
            and candidate_values["ActiveState"] != "active"
        ):
            show = candidate
            break
        time.sleep(0.05)
    if show is None:
        raise RuntimeError("systemd 未在 deadline 证明 old PID inactive")
    killed_at = datetime.now(UTC).isoformat()
    return sign_ed25519_payload(
        {
            "version": 2,
            "action": KILL_ACTION,
            "challenge_id": challenge["challenge_id"],
            "scenario": challenge["scenario"],
            "barrier": BARRIER_SCENARIOS[challenge["scenario"]],
            "nonce": challenge["barrier_nonce"],
            "artifact_sha256": challenge["identity"]["artifact_sha256"],
            "old_pid": old_pid,
            "signal": "SIGKILL",
            "reached_artifact_sha256": _sha(reached_artifact),
            "reached_consumption_sha256": _sha(reached_consumption),
            "kill_consumption_sha256": _sha(kill_consumption),
            "kill_command": _opaque_bytes_descriptor(
                canonical_bytes({
                    "unit": unit,
                    "signal": "SIGKILL",
                    "kill_whom": "main",
                })
            ),
            "kill_response": _opaque_bytes_descriptor(
                kill.stdout or b"\n"
            ),
            "inactive_systemd_show": _opaque_bytes_descriptor(show.stdout),
            "old_process_inactive": True,
            "observed_at": killed_at,
        },
        private_key,
    )


def _native_query(
    value: object,
    *,
    operation: str,
    after: datetime,
) -> dict:
    query = _strict(
        value,
        {
            "operation",
            "requested_at",
            "completed_at",
            "request",
            "response",
            "rows",
            "snapshot_id",
        },
        f"{operation} native query",
    )
    if (
        query["operation"] != operation
        or _iso(query["completed_at"], f"{operation} completed_at") <= after
        or _iso(query["requested_at"], f"{operation} requested_at") > _iso(
            query["completed_at"],
            f"{operation} completed_at",
        )
        or not isinstance(query["rows"], list)
        or not str(query["snapshot_id"]).strip()
    ):
        raise ValueError(f"{operation} native query 时间/schema 非法")
    _decode_opaque_bytes(query["request"], f"{operation} request raw")
    _decode_opaque_bytes(query["response"], f"{operation} response raw")
    return query


def _validate_final_cut(bundle: dict, *, recovery_at: datetime) -> None:
    final = _strict(
        bundle["final_common"],
        {
            "snapshot_id",
            "snapshot_sha256",
            "collected_at",
            "journal_integrity",
            "duplicate_buy_count",
            "positions",
            "pending_orders",
            "pending_algos",
            "balances",
            "runtime_mode",
            "reconciliation",
        },
        "barrier final common facts",
    )
    if (
        not str(final["snapshot_id"]).strip()
        or not _SHA256.fullmatch(str(final["snapshot_sha256"]))
        or _iso(final["collected_at"], "final common collected_at")
        <= recovery_at
        or final["journal_integrity"] != "ok"
        or final["duplicate_buy_count"] != 0
        or not isinstance(final["positions"], list)
        or not isinstance(final["pending_orders"], list)
        or not isinstance(final["pending_algos"], list)
        or not isinstance(final["balances"], dict)
        or final["runtime_mode"]
        not in {"ready", "halted", "emergency_exit", "manual_review"}
        or not isinstance(final["reconciliation"], dict)
        or final["reconciliation"].get("unresolved") != []
    ):
        raise ValueError("barrier final common facts 非同一新鲜 snapshot cut")
    for key in (
        "positions",
        "pending_orders",
        "pending_algos",
        "balances",
        "reconciliation",
    ):
        value = final[key]
        if (
            isinstance(value, dict)
            and "snapshot_id" in value
            and value["snapshot_id"] != final["snapshot_id"]
        ):
            raise ValueError("barrier final facts snapshot 串线")


def _validate_protection(value: object, *, net_qty: Decimal) -> str:
    protection = _strict(
        value,
        {
            "state",
            "reduce_only",
            "covered_qty",
            "algo_id",
            "emergency_exit_ord_id",
        },
        "barrier protection",
    )
    if protection["state"] == "active":
        if (
            protection["reduce_only"] is not True
            or _decimal(
                protection["covered_qty"],
                "covered qty",
                positive=True,
            )
            < net_qty
            or not str(protection["algo_id"]).strip()
            or protection["emergency_exit_ord_id"] is not None
        ):
            raise ValueError("fill recovery reduceOnly protection 未覆盖净仓")
        return "active"
    if (
        protection["state"] != "emergency_exit"
        or protection["reduce_only"] is not True
        or _decimal(protection["covered_qty"], "emergency covered qty")
        != net_qty
        or protection["algo_id"] is not None
        or not str(protection["emergency_exit_ord_id"]).strip()
    ):
        raise ValueError("fill recovery emergency exit 非法")
    return "emergency_exit"


def validate_recovery_bundle(
    bundle: object,
    *,
    challenge: dict,
    reached_artifact: dict,
    reached_public_key: Path,
    kill_artifact: dict,
    kill_public_key: Path,
) -> dict:
    """Validate native business facts and return parser fact projections."""
    bundle = _strict(
        bundle,
        {
            "schema",
            "scenario",
            "challenge_id",
            "artifact_sha256",
            "old_pid",
            "new_pid",
            "new_systemd_invocation_id",
            "recovery_started_at",
            "recovery_snapshot_sha256",
            "marker_sha256",
            "boundary_proof_sha256",
            "reached_artifact_sha256",
            "before",
            "after",
            "final_common",
        },
        "barrier recovery bundle",
    )
    reached = verify_ed25519_artifact(
        reached_artifact,
        reached_public_key,
        label="barrier reached",
    )
    killed = verify_ed25519_artifact(
        kill_artifact,
        kill_public_key,
        label="barrier kill",
    )
    scenario = challenge["scenario"]
    old_pid = challenge["workloads"]["fault_driver"]["pid"]
    old_invocation = challenge["workloads"]["fault_driver"][
        "systemd_invocation_id"
    ]
    recovery_at = _iso(
        bundle["recovery_started_at"],
        "recovery started_at",
    )
    kill_at = _iso(killed.get("observed_at"), "kill observed_at")
    try:
        inactive_raw = _decode_opaque_bytes(
            killed["inactive_systemd_show"],
            "kill inactive systemd show",
        ).decode()
        inactive_values = dict(
            line.split("=", 1)
            for line in inactive_raw.splitlines()
            if "=" in line
        )
        _decode_opaque_bytes(
            killed["kill_command"],
            "kill command raw",
        )
        _decode_opaque_bytes(
            killed["kill_response"],
            "kill response raw",
        )
    except (KeyError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("kill artifact 缺少 systemd raw chain") from exc
    if (
        bundle["schema"] != RECOVERY_SCHEMA
        or bundle["scenario"] != scenario
        or bundle["challenge_id"] != challenge["challenge_id"]
        or bundle["artifact_sha256"]
        != challenge["identity"]["artifact_sha256"]
        or bundle["old_pid"] != old_pid
        or type(bundle["new_pid"]) is not int
        or bundle["new_pid"] <= 1
        or bundle["new_pid"] == old_pid
        or not _UUID.fullmatch(
            str(bundle["new_systemd_invocation_id"]).lower()
        )
        or bundle["new_systemd_invocation_id"] == old_invocation
        or not _SHA256.fullmatch(
            str(bundle["recovery_snapshot_sha256"])
        )
        or not _SHA256.fullmatch(str(bundle["marker_sha256"]))
        or not _SHA256.fullmatch(str(bundle["boundary_proof_sha256"]))
        or not _SHA256.fullmatch(str(bundle["reached_artifact_sha256"]))
        or bundle["marker_sha256"] != reached.get("marker_sha256")
        or bundle["boundary_proof_sha256"]
        != reached.get("boundary_proof_sha256")
        or bundle["reached_artifact_sha256"]
        != _sha(reached_artifact)
        or reached.get("action") != REACHED_ACTION
        or reached.get("challenge_id") != challenge["challenge_id"]
        or reached.get("scenario") != scenario
        or reached.get("nonce") != challenge["barrier_nonce"]
        or reached.get("artifact_sha256")
        != challenge["identity"]["artifact_sha256"]
        or reached.get("pid") != old_pid
        or reached.get("systemd_invocation_id") != old_invocation
        or killed.get("action") != KILL_ACTION
        or killed.get("challenge_id") != challenge["challenge_id"]
        or killed.get("scenario") != scenario
        or killed.get("nonce") != challenge["barrier_nonce"]
        or killed.get("artifact_sha256")
        != challenge["identity"]["artifact_sha256"]
        or killed.get("old_pid") != old_pid
        or killed.get("old_process_inactive") is not True
        or int(inactive_values.get("MainPID", old_pid)) == old_pid
        or inactive_values.get("ActiveState") == "active"
        or killed.get("reached_artifact_sha256") != _sha(reached_artifact)
        or not (
            _iso(reached.get("observed_at"), "reached observed_at")
            < kill_at
            < recovery_at
        )
    ):
        raise ValueError("barrier reached<kill<inactive<new invocation 不闭合")

    before = bundle["before"]
    after = bundle["after"]
    projected: dict[str, dict] = {
        "runtime.recovery_started": {
            "old_pid": old_pid,
            "new_pid": bundle["new_pid"],
            "boot_id": challenge["workloads"]["fault_driver"][
                "boot_id"
            ],
            "systemd_invocation_id": bundle[
                "new_systemd_invocation_id"
            ],
            "snapshot_sha256": bundle["recovery_snapshot_sha256"],
        }
    }
    if scenario == "barrier-buy-intent-before-post":
        before = _strict(
            before,
            {
                "cl_ord_id",
                "intent_state",
                "intent_tx_committed",
                "socket_write_count",
            },
            "before-post pre-kill",
        )
        after = _strict(
            after,
            {
                "pending_query",
                "history_query",
                "fills_query",
                "buy_post_count",
                "intent_state",
                "reservation_outcome",
            },
            "before-post recovery",
        )
        queries = [
            _native_query(after[f"{name}_query"], operation=name, after=kill_at)
            for name in ("pending", "history", "fills")
        ]
        reservation = _strict(
            after["reservation_outcome"],
            {"state", "reservation_id", "released_at"},
            "before-post reservation outcome",
        )
        reservation_ok = (
            reservation == {
                "state": "never_created",
                "reservation_id": None,
                "released_at": None,
            }
            or (
                reservation["state"] == "released"
                and bool(str(reservation["reservation_id"]))
                and _iso(
                    reservation["released_at"],
                    "reservation released_at",
                )
                > kill_at
            )
        )
        if (
            before["intent_state"] != "BUY_SUBMITTING"
            or before["intent_tx_committed"] is not True
            or before["socket_write_count"] != 0
            or any(query["rows"] for query in queries)
            or len({query["snapshot_id"] for query in queries}) != 1
            or after["buy_post_count"] != 0
            or after["intent_state"] != "REJECTED"
            or not reservation_ok
        ):
            raise ValueError("before-post 无单/REJECTED/release 合同失败")
        cl_ord_id = str(before["cl_ord_id"])
        projected.update({
            "journal.intent_persisted": {
                "cl_ord_id": cl_ord_id,
                "state": "BUY_SUBMITTING",
                "db_committed": True,
            },
            "exchange.order.absent": {
                "cl_ord_id": cl_ord_id,
                "lookup_sources": ["pending", "history", "fills"],
            },
            "journal.intent_rejected_no_exchange_order": {
                "cl_ord_id": cl_ord_id,
                "state": "REJECTED",
                "buy_post_count": 0,
            },
        })
    elif scenario == "barrier-post-before-ack":
        before = _strict(
            before,
            {
                "cl_ord_id",
                "intent_tx_committed",
                "tls_write",
                "ack_persisted",
                "order_params_sha256",
            },
            "post-before-ack pre-kill",
        )
        after = _strict(
            after,
            {
                "pending_query",
                "history_query",
                "fills_query",
                "buy_post_count",
                "resolved_order",
                "duplicate_buy_count",
                "net_position_qty",
                "protection",
            },
            "post-before-ack recovery",
        )
        tls = _strict(
            before["tls_write"],
            {
                "request_sha256",
                "bytes_written",
                "write_completed_at",
                "ack_bytes_observed",
            },
            "TLS write receipt",
        )
        queries = [
            _native_query(after[f"{name}_query"], operation=name, after=kill_at)
            for name in ("pending", "history", "fills")
        ]
        resolved = _strict(
            after["resolved_order"],
            {
                "cl_ord_id",
                "ord_id",
                "state",
                "order_params_sha256",
            },
            "clOrdId resolved order",
        )
        matches = [
            row
            for query in queries
            for row in query["rows"]
            if isinstance(row, dict)
            and row.get("cl_ord_id") == before["cl_ord_id"]
        ]
        matching_order_ids = {
            str(row.get("ord_id", "")) for row in matches
            if str(row.get("ord_id", ""))
        }
        if (
            before["intent_tx_committed"] is not True
            or before["ack_persisted"] is not False
            or tls["bytes_written"] <= 0
            or tls["ack_bytes_observed"] is not False
            or not _SHA256.fullmatch(str(tls["request_sha256"]))
            or _iso(tls["write_completed_at"], "TLS write completed")
            >= _iso(reached["observed_at"], "barrier reached")
            or after["buy_post_count"] != 1
            or after["duplicate_buy_count"] != 0
            or len(matching_order_ids) != 1
            or resolved["ord_id"] not in matching_order_ids
            or resolved["cl_ord_id"] != before["cl_ord_id"]
            or resolved["order_params_sha256"]
            != before["order_params_sha256"]
            or not str(resolved["ord_id"]).strip()
        ):
            raise ValueError("post-before-ack exactly-one/ACK-negative 合同失败")
        net_qty = _decimal(after["net_position_qty"], "net position")
        protection_state = None
        if net_qty > 0:
            protection_state = _validate_protection(
                after["protection"],
                net_qty=net_qty,
            )
        elif after["protection"] is not None:
            raise ValueError("零仓位不得伪造保护")
        projected.update({
            "http.order_post_written": {
                "cl_ord_id": before["cl_ord_id"],
                "request_sha256": tls["request_sha256"],
                "socket_write_completed": True,
            },
            "exchange.order.by_clordid": {
                "cl_ord_id": before["cl_ord_id"],
                "ord_id": resolved["ord_id"],
                "state": resolved["state"],
            },
            "journal.clordid_resolved_without_duplicate": {
                "cl_ord_id": before["cl_ord_id"],
                "ord_id": resolved["ord_id"],
                "duplicate_buy_count": 0,
            },
        })
        if protection_state is not None:
            projected["post_ack_protection_state"] = {
                "state": protection_state,
            }
    else:
        before = _strict(
            before,
            {
                "fill",
                "projection_apply_count",
                "projection_snapshot_sha256",
            },
            "fill-before-projection pre-kill",
        )
        after = _strict(
            after,
            {
                "fill_apply_count",
                "net_position_qty",
                "position_snapshot_sha256",
                "protection",
            },
            "fill-before-projection recovery",
        )
        fill = _strict(
            before["fill"],
            {
                "ord_id",
                "trade_id",
                "qty",
                "fee",
                "fee_ccy",
                "base_ccy",
                "observed_at",
                "raw",
            },
            "durable fill observation",
        )
        qty = _decimal(fill["qty"], "fill qty", positive=True)
        fee = _decimal(fill["fee"], "fill fee")
        _decode_opaque_bytes(fill["raw"], "fill raw bytes")
        net_qty = qty + fee if fill["fee_ccy"] == fill["base_ccy"] else qty
        if (
            not str(fill["trade_id"]).strip()
            or not str(fill["ord_id"]).strip()
            or _iso(fill["observed_at"], "fill observed_at")
            >= _iso(reached["observed_at"], "barrier reached")
            or before["projection_apply_count"] != 0
            or not _SHA256.fullmatch(
                str(before["projection_snapshot_sha256"])
            )
            or after["fill_apply_count"] != 1
            or _decimal(after["net_position_qty"], "net position")
            != net_qty
            or not _SHA256.fullmatch(
                str(after["position_snapshot_sha256"])
            )
        ):
            raise ValueError("fill unique/apply-once/fee-net 合同失败")
        protection_state = _validate_protection(
            after["protection"],
            net_qty=net_qty,
        )
        projected.update({
            "exchange.fill.observed": {
                "ord_id": fill["ord_id"],
                "trade_id": fill["trade_id"],
                "qty": str(qty),
            },
            "journal.projection_absent": {
                "ord_id": fill["ord_id"],
                "fill_apply_count": 0,
            },
            "journal.fill_projection_recovered": {
                "ord_id": fill["ord_id"],
                "trade_id": fill["trade_id"],
                "fill_apply_count": 1,
                "protection_state": protection_state,
            },
        })
    _validate_final_cut(bundle, recovery_at=recovery_at)
    return projected


def load_marker(path: Path) -> dict:
    return _safe_json(path, label="barrier marker")


def barrier_capability_self_check(
    *,
    scenario: str,
) -> dict:
    """Report parser readiness; this scaffold can never self-promote."""
    if scenario not in BARRIER_SCENARIOS:
        raise ValueError("未知 Stage-C barrier scenario")
    return {
        "schema": "okx-quant.stage-c-barrier-capability/v1",
        "scenario": scenario,
        "status": "EXTERNAL OPEN",
        "protocol_ready": True,
        "standalone_boundary_executor": False,
        "production_receipt_admissible": False,
        "missing_requirements": list(EXTERNAL_CAPABILITY_REQUIREMENTS),
    }


def require_barrier_production_capability(
    *,
    scenario: str,
) -> dict:
    report = barrier_capability_self_check(scenario=scenario)
    raise RuntimeError(
        "Stage-C barrier PARSER_READY scaffold / EXTERNAL OPEN: "
        + ",".join(report["missing_requirements"])
    )
