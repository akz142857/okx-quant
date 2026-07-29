"""Live OS/cloud collectors and allow-listed Stage-C control executor.

This module intentionally does not accept precomputed workload/fact objects.
It acquires bytes from systemd, procfs, SQLite, AWS STS, HTTP, or a narrowly
allow-listed fault control operation.  Scenario inventory remains OPEN until a
scenario-specific driver composes these primitives and is independently
reviewed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import requests

from okx_quant.infrastructure.evidence import credential_fingerprint
from okx_quant.ops.stage_c_chaos_protocol import (
    _opaque_bytes_descriptor,
)

_SYSTEMD_PROPERTIES = "Id,InvocationID,MainPID,ControlGroup"
_SQLITE_QUERIES = {
    "integrity": "PRAGMA integrity_check",
    "system-mode": (
        "SELECT key, value FROM system_state WHERE key='mode' "
        "ORDER BY key"
    ),
    "pending-intents": (
        "SELECT intent_id, cl_ord_id, state FROM order_intents "
        "WHERE state NOT IN ('filled','rejected','canceled') "
        "ORDER BY intent_id"
    ),
    "reconciliations": (
        "SELECT run_id, status, mismatch_count, repaired_count, "
        "details_json, started_at, completed_at "
        "FROM reconciliation_runs ORDER BY started_at DESC, run_id DESC "
        "LIMIT 1"
    ),
    "duplicate-buy-audit": (
        "SELECT 'decision:' || decision_id AS intent_id "
        "FROM order_intents WHERE side='buy' AND decision_id IS NOT NULL "
        "AND decision_id!='' AND exchange_ord_id!='' "
        "GROUP BY decision_id HAVING COUNT(DISTINCT exchange_ord_id) > 1 "
        "UNION ALL "
        "SELECT 'probe:' || probe_id AS intent_id FROM probe_runs "
        "WHERE duplicate_buy_count > 0 ORDER BY intent_id"
    ),
    "positions": (
        "SELECT p.inst_id, p.base_qty, p.protection_status, "
        "COALESCE(("
        " SELECT po.state FROM protective_orders po "
        " WHERE po.inst_id=p.inst_id "
        " ORDER BY po.updated_at DESC, po.protection_id DESC LIMIT 1"
        "), '') AS latest_protection_state "
        "FROM positions p ORDER BY p.inst_id"
    ),
    "stage-c-system-event": (
        "SELECT event_id, event_name, severity, correlation_id, "
        "payload_json, created_at FROM system_events "
        "WHERE event_name=? AND correlation_id=? "
        "ORDER BY created_at DESC, event_id DESC LIMIT 1"
    ),
    "stage-c-control-command": (
        "SELECT command_id, command_type, payload_json, status, "
        "result_json, created_at, started_at, completed_at "
        "FROM control_commands WHERE command_id=? LIMIT 1"
    ),
    "stage-c-intent-by-clordid": (
        "SELECT intent_id, cl_ord_id, inst_id, side, state, "
        "exchange_ord_id, exchange_state, acc_fill_qty, source, "
        "last_error_code, last_error_message, created_at, updated_at "
        "FROM order_intents WHERE cl_ord_id=? LIMIT 1"
    ),
    "stage-c-probe-by-id": (
        "SELECT probe_id, state, buy_cl_ord_id, buy_intent_id, "
        "duplicate_buy_count, version, updated_at "
        "FROM probe_runs WHERE probe_id=? LIMIT 1"
    ),
    "stage-c-fill-by-trade": (
        "SELECT fill_id, intent_id, exchange_ord_id, inst_id, side, "
        "fill_qty, fill_px, fee, fee_ccy, trade_id, idempotency_key, "
        "created_at FROM fills WHERE trade_id=? OR exchange_ord_id=? "
        "ORDER BY created_at, fill_id"
    ),
    "stage-c-protection-by-algo": (
        "SELECT protection_id, inst_id, protected_qty, state, "
        "exchange_algo_id, parent_intent_id, last_error, updated_at "
        "FROM protective_orders WHERE exchange_algo_id=? LIMIT 1"
    ),
    "stage-c-active-protection-by-inst": (
        "SELECT po.protection_id, po.inst_id, po.protected_qty, po.state, "
        "po.exchange_algo_id, po.parent_intent_id, po.last_error, "
        "po.updated_at, oi.cl_ord_id AS parent_cl_ord_id, "
        "oi.exchange_ord_id AS parent_exchange_ord_id, "
        "oi.inst_id AS parent_inst_id, oi.side AS parent_side "
        "FROM protective_orders po JOIN order_intents oi "
        "ON oi.intent_id=po.parent_intent_id WHERE po.inst_id=? "
        "ORDER BY po.updated_at DESC, po.protection_id DESC LIMIT 1"
    ),
    "stage-c-risk-by-probe": (
        "SELECT rr.reservation_id, rr.intent_id, rr.inst_id, "
        "rr.reserved_quote, rr.reserved_slot, rr.released_at "
        "FROM risk_reservations rr JOIN order_intents oi "
        "ON oi.intent_id=rr.intent_id WHERE oi.probe_id=? "
        "ORDER BY rr.reservation_id"
    ),
    "stage-c-recovery-checkpoint": (
        "SELECT event_id, event_name, correlation_id, payload_json, created_at "
        "FROM system_events WHERE event_name="
        "'stage_c_recovery_evidence_ready' AND correlation_id=? "
        "ORDER BY created_at DESC, event_id DESC LIMIT 1"
    ),
    "stage-c-protection-ownership": (
        "SELECT po.protection_id, po.parent_intent_id, "
        "oi.cl_ord_id AS parent_cl_ord_id, "
        "oi.exchange_ord_id AS parent_exchange_ord_id, "
        "oi.inst_id, oi.side AS parent_side, po.algo_cl_ord_id, "
        "po.exchange_algo_id, po.protected_qty, po.state, po.updated_at "
        "FROM protective_orders po JOIN order_intents oi "
        "ON oi.intent_id=po.parent_intent_id "
        "WHERE oi.cl_ord_id=? AND po.algo_cl_ord_id=? "
        "AND po.exchange_algo_id=? "
        "ORDER BY po.updated_at DESC, po.protection_id DESC"
    ),
}
_SQLITE_PARAMETER_COUNTS = {
    "integrity": 0,
    "system-mode": 0,
    "pending-intents": 0,
    "reconciliations": 0,
    "duplicate-buy-audit": 0,
    "positions": 0,
    "stage-c-system-event": 2,
    "stage-c-control-command": 1,
    "stage-c-intent-by-clordid": 1,
    "stage-c-probe-by-id": 1,
    "stage-c-fill-by-trade": 2,
    "stage-c-protection-by-algo": 1,
    "stage-c-active-protection-by-inst": 1,
    "stage-c-risk-by-probe": 1,
    "stage-c-recovery-checkpoint": 1,
    "stage-c-protection-ownership": 3,
}

_SYSTEMD_ACTIONS = frozenset({
    "show-runtime",
    "show-after-restart",
    "show-after-kill",
})
_SYSTEMD_SHOW_PROPERTIES = (
    "Id,ActiveState,SubState,InvocationID,MainPID,ControlGroup,"
    "ExecMainStartTimestampMonotonic"
)

OKX_V5_OPERATION_ALLOWLIST = {
    "account-config": ("GET", "/api/v5/account/config"),
    "pending-orders": ("GET", "/api/v5/trade/orders-pending"),
    "pending-algos": ("GET", "/api/v5/trade/orders-algo-pending"),
    "order": ("GET", "/api/v5/trade/order"),
    "fills-history": ("GET", "/api/v5/trade/fills-history"),
    "algo-history": ("GET", "/api/v5/trade/orders-algo-history"),
    "balance": ("GET", "/api/v5/account/balance"),
    "place-order": ("POST", "/api/v5/trade/order"),
    "cancel-order": ("POST", "/api/v5/trade/cancel-order"),
    "cancel-algo": ("POST", "/api/v5/trade/cancel-algos"),
}
_OKX_BASE_URLS = frozenset({
    "https://www.okx.com",
    "https://openapi.okx.com",
})
_OKX_QUERY_KEYS = {
    "account-config": frozenset(),
    "pending-orders": frozenset({"instType", "instId"}),
    "pending-algos": frozenset({"ordType", "instId", "algoId"}),
    "order": frozenset({"instId", "ordId", "clOrdId"}),
    "fills-history": frozenset({
        "instType",
        "instId",
        "ordId",
        "limit",
    }),
    "algo-history": frozenset({
        "ordType",
        "state",
        "instId",
        "algoId",
    }),
    "balance": frozenset({"ccy"}),
}
_OKX_POST_KEYS = {
    "place-order": frozenset({
        "instId",
        "tdMode",
        "clOrdId",
        "side",
        "ordType",
        "sz",
        "px",
        "tgtCcy",
    }),
    "cancel-order": frozenset({"instId", "ordId", "clOrdId"}),
    "cancel-algo": frozenset({"instId", "algoId"}),
}


@dataclass(frozen=True)
class NativeAcquisition:
    source: str
    operation: str
    request_bytes: bytes
    response_bytes: bytes
    returncode: int


def assert_current_process_matches_workload(workload: object) -> None:
    """Fail unless this Linux process is the challenge-attested workload."""
    if not isinstance(workload, dict):
        raise ValueError("Stage-C current workload schema 非法")
    invocation = os.environ.get("INVOCATION_ID", "").replace("-", "").lower()
    expected_invocation = str(
        workload.get("systemd_invocation_id", "")
    ).replace("-", "").lower()
    try:
        cgroup = next(
            value
            for line in Path("/proc/self/cgroup").read_text().splitlines()
            for prefix, separator, value in (line.partition("::"),)
            if separator and prefix == "0"
        )
        executable = Path("/proc/self/exe").resolve(strict=True)
        digest = hashlib.sha256()
        with executable.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except (OSError, StopIteration) as exc:
        raise ValueError(
            "Stage-C workload 只能在 attested Linux systemd/cgroup v2 执行"
        ) from exc
    if (
        workload.get("pid") != os.getpid()
        or workload.get("uid") != os.getuid()
        or workload.get("cgroup") != cgroup
        or expected_invocation != invocation
        or workload.get("executable_sha256") != digest.hexdigest()
    ):
        raise ValueError("Stage-C current process 未绑定 challenge workload")


def _run_native(
    argv: list[str],
    *,
    timeout: float,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _required_success(
    result: subprocess.CompletedProcess,
    *,
    label: str,
) -> bytes:
    if result.returncode != 0 or not result.stdout:
        raise RuntimeError(
            f"{label} failed rc={result.returncode}; "
            f"stderr_sha256={hashlib.sha256(result.stderr).hexdigest()}"
        )
    return result.stdout


def collect_native_workload_attestation(
    *,
    unit: str,
    systemctl_executable: Path = Path("/usr/bin/systemctl"),
    aws_executable: Path = Path("/usr/bin/aws"),
    sha256sum_executable: Path = Path("/usr/bin/sha256sum"),
    proc_root: Path = Path("/proc"),
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
    machine_id_path: Path = Path("/etc/machine-id"),
) -> dict:
    """Acquire systemd/procfs/executable/STS bytes for one source role."""
    if (
        not unit.endswith(".service")
        or "/" in unit
        or unit.startswith(".")
    ):
        raise ValueError("Stage-C collector unit 非法")
    systemd = _run_native(
        [
            str(systemctl_executable),
            "show",
            unit,
            f"--property={_SYSTEMD_PROPERTIES}",
            "--no-pager",
        ],
        timeout=5,
    )
    systemd_raw = _required_success(systemd, label="systemctl show")
    values = {}
    for raw_line in systemd_raw.decode("utf-8").splitlines():
        key, separator, value = raw_line.partition("=")
        if separator:
            values[key] = value
    if set(values) != set(_SYSTEMD_PROPERTIES.split(",")):
        raise RuntimeError("systemctl show 未返回完整 Stage-C properties")
    try:
        pid = int(values["MainPID"])
    except ValueError as exc:
        raise RuntimeError("systemctl MainPID 非整数") from exc
    if pid <= 1:
        raise RuntimeError("systemctl MainPID 非运行进程")
    proc_dir = proc_root / str(pid)
    status_raw = (proc_dir / "status").read_bytes()
    cgroup_raw = (proc_dir / "cgroup").read_bytes()
    executable = Path(os.readlink(proc_dir / "exe"))
    executable_path_raw = (str(executable) + "\n").encode()
    executable_hash = _run_native(
        [str(sha256sum_executable), "--", str(executable)],
        timeout=30,
    )
    executable_hash_raw = _required_success(
        executable_hash,
        label="sha256sum /proc exe",
    )
    sts = _run_native(
        [
            str(aws_executable),
            "sts",
            "get-caller-identity",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        timeout=10,
    )
    sts_raw = _required_success(sts, label="aws sts get-caller-identity")
    return {
        "systemd_show": _opaque_bytes_descriptor(systemd_raw),
        "proc_status": _opaque_bytes_descriptor(status_raw),
        "proc_cgroup": _opaque_bytes_descriptor(cgroup_raw),
        "proc_exe": _opaque_bytes_descriptor(executable_path_raw),
        "boot_id": _opaque_bytes_descriptor(boot_id_path.read_bytes()),
        "machine_id": _opaque_bytes_descriptor(machine_id_path.read_bytes()),
        "executable_sha256sum": _opaque_bytes_descriptor(
            executable_hash_raw
        ),
        "sts_get_caller_identity": _opaque_bytes_descriptor(sts_raw),
    }


def collect_sqlite_native(
    *,
    database: Path,
    query_name: str,
    parameters: tuple[str, ...] = (),
) -> NativeAcquisition:
    """Run one fixed read-only query and retain exact request/row bytes."""
    sql = _SQLITE_QUERIES.get(query_name)
    if sql is None:
        raise ValueError("Stage-C SQLite query 不在 allow-list")
    expected_parameters = _SQLITE_PARAMETER_COUNTS[query_name]
    if (
        len(parameters) != expected_parameters
        or any(
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 1024
            or "\x00" in value
            for value in parameters
        )
    ):
        raise ValueError("Stage-C SQLite query 参数不符合 allow-list")
    if not database.is_file() or database.is_symlink():
        raise ValueError("Stage-C SQLite database 不是安全普通文件")
    request = json.dumps(
        {
            "database": str(database.resolve()),
            "database_sha256": hashlib.sha256(
                database.read_bytes()
            ).hexdigest(),
            "query_name": query_name,
            "query_sha256": hashlib.sha256(sql.encode()).hexdigest(),
            "parameters": list(parameters),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    connection = sqlite3.connect(
        f"{database.resolve().as_uri()}?mode=ro&immutable=1",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(sql, parameters).fetchall()
        response = json.dumps(
            {
                "columns": (
                    list(rows[0].keys()) if rows else []
                ),
                "rows": [list(row) for row in rows],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    finally:
        connection.close()
    return NativeAcquisition(
        source="journal_collector",
        operation=query_name,
        request_bytes=request,
        response_bytes=response,
        returncode=0,
    )


def collect_sqlite_snapshot_native(
    *,
    database: Path,
    query_requests: tuple[tuple[str, tuple[str, ...]], ...],
) -> dict[tuple[str, tuple[str, ...]], NativeAcquisition]:
    """Run all requested allow-listed queries against one backup-API cut.

    The exact backup file, live inode/owner/mode, WAL hash, SQLite
    schema/data/user versions, and every result set are sealed together.
    Reusing the returned acquisitions for the final Stage-C common facts proves
    they came from one reconciliation/postcondition cut.
    """
    if (
        not query_requests
        or len(query_requests) > 64
        or len(set(query_requests)) != len(query_requests)
    ):
        raise ValueError("Stage-C SQLite snapshot query inventory 非法")
    info = database.lstat()
    if (
        database.is_symlink()
        or not database.is_file()
        or info.st_mode & 0o022
        or info.st_size <= 0
    ):
        raise ValueError("Stage-C SQLite live database 权限/类型不安全")
    for query_name, parameters in query_requests:
        if query_name not in _SQLITE_QUERIES:
            raise ValueError("Stage-C SQLite snapshot query 不在 allow-list")
        if (
            len(parameters) != _SQLITE_PARAMETER_COUNTS[query_name]
            or any(
                not isinstance(value, str)
                or not value
                or len(value.encode()) > 1024
                or "\x00" in value
                for value in parameters
            )
        ):
            raise ValueError("Stage-C SQLite snapshot query 参数非法")
    descriptor = os.open(database, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened_info = os.fstat(descriptor)
        if (
            opened_info.st_dev != info.st_dev
            or opened_info.st_ino != info.st_ino
            or opened_info.st_uid != info.st_uid
            or opened_info.st_gid != info.st_gid
            or opened_info.st_mode != info.st_mode
        ):
            raise RuntimeError("Stage-C SQLite database 在打开期间替换")
        wal_path = Path(f"{database}-wal")
        wal_raw = b""
        if wal_path.exists():
            wal_info = wal_path.lstat()
            if (
                wal_path.is_symlink()
                or not wal_path.is_file()
                or wal_info.st_mode & 0o022
            ):
                raise ValueError("Stage-C SQLite WAL 权限/类型不安全")
            wal_raw = wal_path.read_bytes()
        with tempfile.TemporaryDirectory(
            prefix="okx-stage-c-snapshot-"
        ) as directory:
            snapshot_path = Path(directory) / "snapshot.sqlite"
            source = sqlite3.connect(
                f"{database.resolve().as_uri()}?mode=ro",
                uri=True,
            )
            source_metadata = {
                "schema_version": source.execute(
                    "PRAGMA schema_version"
                ).fetchone()[0],
                "data_version": source.execute(
                    "PRAGMA data_version"
                ).fetchone()[0],
                "user_version": source.execute(
                    "PRAGMA user_version"
                ).fetchone()[0],
                "journal_mode": source.execute(
                    "PRAGMA journal_mode"
                ).fetchone()[0],
            }
            after_open = database.lstat()
            if (
                after_open.st_dev != opened_info.st_dev
                or after_open.st_ino != opened_info.st_ino
                or after_open.st_uid != opened_info.st_uid
                or after_open.st_gid != opened_info.st_gid
            ):
                source.close()
                raise RuntimeError(
                    "Stage-C SQLite database 在 connect 期间替换"
                )
            destination = sqlite3.connect(snapshot_path)
            try:
                source.backup(destination)
                destination.commit()
            finally:
                destination.close()
                source.close()
            final_info = database.lstat()
            if (
                final_info.st_dev != opened_info.st_dev
                or final_info.st_ino != opened_info.st_ino
            ):
                raise RuntimeError(
                    "Stage-C SQLite database 在 backup 期间替换"
                )
            snapshot_raw = snapshot_path.read_bytes()
            if not 0 < len(snapshot_raw) <= 4 * 1024 * 1024:
                raise ValueError(
                    "Stage-C inline SQLite snapshot 必须为 1..4MiB；"
                    "更大数据库必须使用 independent exact-version object"
                )
            snapshot = sqlite3.connect(
                f"{snapshot_path.as_uri()}?mode=ro&immutable=1",
                uri=True,
            )
            snapshot.row_factory = sqlite3.Row
            try:
                metadata = {
                    **source_metadata,
                    "quick_check": snapshot.execute(
                        "PRAGMA quick_check"
                    ).fetchone()[0],
                }
                results = []
                for query_name, parameters in query_requests:
                    rows = snapshot.execute(
                        _SQLITE_QUERIES[query_name],
                        parameters,
                    ).fetchall()
                    results.append({
                        "query_name": query_name,
                        "parameters": list(parameters),
                        "query_sha256": hashlib.sha256(
                            _SQLITE_QUERIES[query_name].encode()
                        ).hexdigest(),
                        "columns": (
                            list(rows[0].keys()) if rows else []
                        ),
                        "rows": [list(row) for row in rows],
                    })
            finally:
                snapshot.close()
    finally:
        os.close(descriptor)
    snapshot_sha256 = hashlib.sha256(snapshot_raw).hexdigest()
    cut = {
        "schema": "okx-quant.stage-c-sqlite-snapshot/v1",
        "live_database": {
            "path": str(database.resolve()),
            "device": info.st_dev,
            "inode": info.st_ino,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": info.st_mode & 0o7777,
            "bytes": info.st_size,
            "database_sha256_at_open": hashlib.sha256(
                database.read_bytes()
            ).hexdigest(),
            "wal_sha256": (
                hashlib.sha256(wal_raw).hexdigest() if wal_raw else None
            ),
            "wal_bytes": len(wal_raw),
        },
        "snapshot": {
            **metadata,
            "database_sha256": snapshot_sha256,
            "bytes": len(snapshot_raw),
            "database_bytes": _opaque_bytes_descriptor(snapshot_raw),
        },
        "results": results,
    }
    response_bytes = json.dumps(
        cut,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    acquisitions: dict[
        tuple[str, tuple[str, ...]],
        NativeAcquisition,
    ] = {}
    for query_name, parameters in query_requests:
        request_bytes = json.dumps(
            {
                "schema": "okx-quant.stage-c-sqlite-snapshot-request/v1",
                "query_name": query_name,
                "parameters": list(parameters),
                "snapshot_sha256": snapshot_sha256,
                "snapshot_response_sha256": hashlib.sha256(
                    response_bytes
                ).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        acquisitions[(query_name, parameters)] = NativeAcquisition(
            source="journal_collector",
            operation=f"snapshot:{query_name}",
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            returncode=0,
        )
    return acquisitions


def collect_systemd_native(
    *,
    action: str,
    unit: str,
    systemctl_executable: Path = Path("/usr/bin/systemctl"),
) -> NativeAcquisition:
    """Acquire a fixed systemd runtime snapshot without accepting argv."""
    if (
        action not in _SYSTEMD_ACTIONS
        or not unit.endswith(".service")
        or "/" in unit
        or unit.startswith(".")
    ):
        raise ValueError("Stage-C systemd snapshot action/unit 不在 allow-list")
    argv = [
        str(systemctl_executable),
        "show",
        unit,
        f"--property={_SYSTEMD_SHOW_PROPERTIES}",
        "--no-pager",
    ]
    result = _run_native(argv, timeout=10)
    response = _required_success(result, label="systemctl show runtime")
    return NativeAcquisition(
        source="systemd_collector",
        operation=action,
        request_bytes=json.dumps(
            {
                "action": action,
                "unit": unit,
                "properties": _SYSTEMD_SHOW_PROPERTIES.split(","),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        response_bytes=response,
        returncode=result.returncode,
    )


def collect_clock_native(
    *,
    chronyc_executable: Path = Path("/usr/bin/chronyc"),
) -> NativeAcquisition:
    """Acquire machine-readable chrony tracking output."""
    result = _run_native(
        [str(chronyc_executable), "-c", "tracking"],
        timeout=5,
    )
    response = _required_success(result, label="chronyc tracking")
    return NativeAcquisition(
        source="clock_collector",
        operation="chrony-tracking",
        request_bytes=b'{"action":"chrony-tracking","format":"csv"}',
        response_bytes=response,
        returncode=result.returncode,
    )


def collect_http_native(
    *,
    source: str,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    timeout: float = 10,
) -> NativeAcquisition:
    """Perform one HTTPS request and retain exact request/response bodies."""
    if source not in {"okx_collector", "provider", "restore_verifier"}:
        raise ValueError("Stage-C HTTP source 非法")
    parsed_url = urllib.parse.urlsplit(url)
    if (
        method not in {"GET", "POST"}
        or parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.fragment
    ):
        raise ValueError("Stage-C HTTP method/url 非法")
    prepared = requests.Request(
        method,
        url,
        headers=headers,
        data=body,
    ).prepare()
    host_header = parsed_url.hostname
    if parsed_url.port is not None:
        host_header = f"{host_header}:{parsed_url.port}"
    prepared.headers.setdefault("Host", host_header)
    recorded_headers: dict[str, str] = {}
    for key, value in prepared.headers.items():
        lowered = key.lower()
        if lowered in {
            "authorization",
            "ok-access-sign",
            "ok-access-passphrase",
        }:
            continue
        if lowered == "ok-access-key":
            recorded_headers[
                "X-Stage-C-API-Key-Fingerprint"
            ] = credential_fingerprint(str(value))
            continue
        recorded_headers[str(key)] = str(value)
    request_bytes = (
        f"{prepared.method} {prepared.path_url} HTTP/1.1\r\n"
        + "".join(
            f"{key}: {value}\r\n"
            for key, value in sorted(recorded_headers.items())
        )
        + "\r\n"
    ).encode() + (prepared.body or b"")
    with requests.Session() as session:
        response = session.send(prepared, timeout=timeout, stream=True)
        connection = getattr(response.raw, "_connection", None)
        socket = getattr(connection, "sock", None)
        if socket is None:
            response.close()
            raise RuntimeError("Stage-C HTTPS collector 无法取得 TLS socket")
        certificate_der = socket.getpeercert(binary_form=True)
        peer = socket.getpeername()
        tls_version = socket.version()
        cipher = socket.cipher()
        if (
            not certificate_der
            or not isinstance(peer, tuple)
            or not peer
            or not tls_version
            or not cipher
        ):
            response.close()
            raise RuntimeError("Stage-C HTTPS TLS peer evidence 不完整")
        x509_result = subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-inform",
                "DER",
                "-pubkey",
                "-noout",
            ],
            input=certificate_der,
            capture_output=True,
            check=False,
            timeout=5,
        )
        if x509_result.returncode != 0 or not x509_result.stdout:
            response.close()
            raise RuntimeError("Stage-C HTTPS peer SPKI 提取失败")
        spki_result = subprocess.run(
            [
                "/usr/bin/openssl",
                "pkey",
                "-pubin",
                "-outform",
                "DER",
            ],
            input=x509_result.stdout,
            capture_output=True,
            check=False,
            timeout=5,
        )
        if spki_result.returncode != 0 or not spki_result.stdout:
            response.close()
            raise RuntimeError("Stage-C HTTPS peer SPKI 编码失败")
        content = response.content
        response_headers = {
            str(key).lower(): str(value)
            for key, value in response.headers.items()
        }
        response_headers.update({
            "x-stage-c-peer-address": str(peer[0]),
            "x-stage-c-peer-port": str(peer[1]),
            "x-stage-c-tls-version": str(tls_version),
            "x-stage-c-tls-cipher": str(cipher[0]),
            "x-stage-c-peer-cert-sha256": hashlib.sha256(
                certificate_der
            ).hexdigest(),
            "x-stage-c-peer-spki-sha256": hashlib.sha256(
                spki_result.stdout
            ).hexdigest(),
        })
        response.close()
    response_bytes = (
        f"HTTP/1.1 {response.status_code}\r\n"
        + "".join(
            f"{key}: {value}\r\n"
            for key, value in sorted(response_headers.items())
        )
        + "\r\n"
    ).encode() + content
    return NativeAcquisition(
        source=source,
        operation=f"{method} {prepared.path_url}",
        request_bytes=request_bytes,
        response_bytes=response_bytes,
        returncode=0,
    )


def execute_controlled_fault(
    *,
    action: str,
    unit: str | None = None,
    control_file: Path | None = None,
    systemctl_executable: Path = Path("/usr/bin/systemctl"),
) -> NativeAcquisition:
    """Execute only reviewed systemd/proxy controls; never arbitrary argv."""
    if action in {"systemd-restart", "systemd-sigkill"}:
        if unit is None or not unit.endswith(".service") or "/" in unit:
            raise ValueError("Stage-C systemd fault unit 非法")
        argv = (
            [str(systemctl_executable), "restart", unit]
            if action == "systemd-restart"
            else [
                str(systemctl_executable),
                "kill",
                "--signal=SIGKILL",
                "--kill-whom=main",
                unit,
            ]
        )
        result = _run_native(argv, timeout=30)
        request = json.dumps(
            {"action": action, "unit": unit},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        response = json.dumps(
            {
                "returncode": result.returncode,
                "stdout_base64": _opaque_bytes_descriptor(
                    result.stdout or b"\n"
                ),
                "stderr_base64": _opaque_bytes_descriptor(
                    result.stderr or b"\n"
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if result.returncode != 0:
            raise RuntimeError(f"Stage-C controlled fault failed: {action}")
        return NativeAcquisition(
            source="systemd_collector",
            operation=action,
            request_bytes=request,
            response_bytes=response,
            returncode=result.returncode,
        )
    if action in {"proxy-block", "proxy-unblock"}:
        if (
            control_file is None
            or not control_file.is_file()
            or control_file.is_symlink()
            or control_file.stat().st_uid != os.getuid()
            or control_file.stat().st_mode & 0o077
        ):
            raise ValueError("Stage-C proxy control file 不安全")
        before = control_file.read_bytes()
        before_info = control_file.stat()
        target = b"blocked\n" if action == "proxy-block" else b"open\n"
        descriptor = os.open(
            control_file,
            os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
        )
        try:
            os.write(descriptor, target)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        after = control_file.read_bytes()
        if after != target:
            raise RuntimeError("Stage-C proxy control readback 不一致")
        after_info = control_file.stat()
        invocation_id = os.environ.get("INVOCATION_ID", "").lower()
        if not re.fullmatch(r"[0-9a-f]{32}", invocation_id):
            raise RuntimeError(
                "Stage-C proxy controller 缺少 systemd INVOCATION_ID"
            )
        channel = control_file.stem
        if channel not in {"public", "private", "business"}:
            raise ValueError("Stage-C proxy control channel 非法")
        return NativeAcquisition(
            source="fault_controller",
            operation=action,
            request_bytes=json.dumps(
                {
                    "action": action,
                    "channel": channel,
                    "control_inode": before_info.st_ino,
                    "before_sha256": hashlib.sha256(before).hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
            response_bytes=json.dumps(
                {
                    "action": action,
                    "channel": channel,
                    "state": after.decode().strip(),
                    "control_inode": after_info.st_ino,
                    "generation": after_info.st_mtime_ns,
                    "actor_invocation_id": invocation_id,
                    "readback_verified": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
            returncode=0,
        )
    raise ValueError("Stage-C fault action 不在 allow-list")
