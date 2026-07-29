"""Native post-restart acquisition for Stage-C barrier recovery."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)
from okx_quant.infrastructure.evidence import (
    credential_fingerprint,
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.ops.demo_preflight import normalize_okx_permissions
from okx_quant.ops.stage_c_chaos_protocol import (
    _decode_opaque_bytes,
    _opaque_bytes_descriptor,
)
from okx_quant.ops.stage_c_exact_release_drivers import (
    _OKX_PATH_BY_OPERATION,
    _parse_http,
    _sqlite_rows,
    _validate_tls_frame,
)
from okx_quant.ops.stage_c_exact_release_drivers import (
    _systemd_values as _strict_systemd_values,
)
from okx_quant.ops.stage_c_native_collectors import (
    NativeAcquisition,
    collect_http_native,
    collect_sqlite_snapshot_native,
    collect_systemd_native,
)
from stage_c_test_harness.barriers import REACHED_ACTION
from stage_c_test_harness.pipeline import (
    _normalize_id128,
    _stable_bytes,
    load_pipeline_proof,
    read_self_cgroup,
)

NATIVE_RECOVERY_SCHEMA = "okx-quant.stage-c-native-barrier-recovery/v3"
RECOVERY_SOURCE_ACTION = "attest-stage-c-recovery-source-v2"
RECOVERY_SOURCE_ROLES = frozenset({
    "journal_collector",
    "okx_collector",
    "systemd_collector",
})
_OKX_BASE_URLS = {
    "https://openapi.okx.com",
    "https://www.okx.com",
}


def sign_recovery_source_payload(
    *,
    source: str,
    payload: dict,
    challenge: dict,
    private_key: Path,
    collected_at: str,
    reached_artifact: dict,
    kill_artifact: dict,
    phase: str = "final",
    predecessor_artifacts: dict[str, dict] | None = None,
) -> dict:
    """Seal one native source from the exact challenge-bound workload.

    This function is invoked inside three different fixed-surface systemd
    units.  It verifies the live PID/UID/cgroup/InvocationID/interpreter and
    role key before signing; a coordinator never receives a source private
    key or acquisition privilege.
    """
    if (
        source not in RECOVERY_SOURCE_ROLES
        or not isinstance(payload, dict)
        or phase not in {"readiness", "final"}
        or (phase == "readiness" and source != "journal_collector")
    ):
        raise ValueError("Stage-C recovery source/payload 非法")
    predecessors = predecessor_artifacts or {}
    if not isinstance(predecessors, dict) or any(
        not isinstance(name, str) or not isinstance(value, dict)
        for name, value in predecessors.items()
    ):
        raise ValueError("Stage-C recovery source predecessor artifacts 非法")
    workload = challenge.get("workloads", {}).get(source)
    fingerprints = challenge.get("source_key_fingerprints", {})
    if not isinstance(workload, dict):
        raise ValueError("Stage-C recovery source workload 缺失")
    actual_invocation = os.environ.get("INVOCATION_ID", "")
    executable_sha256 = hashlib.sha256(
        _stable_bytes(
            Path("/proc/self/exe").resolve(strict=True),
            label="Stage-C recovery source interpreter",
        )
    ).hexdigest()
    archive_arg = Path(sys.argv[0])
    if archive_arg.is_symlink():
        raise ValueError("Stage-C recovery source archive 禁止符号链接")
    archive_sha256 = hashlib.sha256(
        _stable_bytes(
            archive_arg.resolve(strict=True),
            label="Stage-C recovery source instrumented archive",
        )
    ).hexdigest()
    if (
        workload.get("pid") != os.getpid()
        or workload.get("uid") != os.getuid()
        or workload.get("cgroup") != read_self_cgroup()
        or _normalize_id128(
            str(workload.get("systemd_invocation_id", "")),
            label="Stage-C source challenge InvocationID",
        )
        != _normalize_id128(
            actual_invocation,
            label="Stage-C source live InvocationID",
        )
        or workload.get("executable_sha256") != executable_sha256
        or challenge.get("identity", {}).get("artifact_sha256")
        != archive_sha256
        or fingerprints.get(source)
        != ed25519_public_key_fingerprint(private_key, private_key=True)
    ):
        raise ValueError("Stage-C recovery source live workload/key 串线")
    raw = canonical_bytes(payload)
    return sign_ed25519_payload(
        {
            "version": 2,
            "action": RECOVERY_SOURCE_ACTION,
            "scenario": challenge["scenario"],
            "challenge_id": challenge["challenge_id"],
            "source": source,
            "workload_binding_sha256": hashlib.sha256(
                canonical_bytes(workload)
            ).hexdigest(),
            "artifact_sha256": archive_sha256,
            "reached_artifact_sha256": hashlib.sha256(
                canonical_bytes(reached_artifact)
            ).hexdigest(),
            "kill_artifact_sha256": hashlib.sha256(
                canonical_bytes(kill_artifact)
            ).hexdigest(),
            "marker_sha256": payload.get("marker_sha256"),
            "boundary_proof_sha256": payload.get(
                "boundary_proof_sha256"
            ),
            "phase": phase,
            "predecessor_artifact_sha256s": {
                name: hashlib.sha256(canonical_bytes(value)).hexdigest()
                for name, value in sorted(predecessors.items())
            },
            "payload": _opaque_bytes_descriptor(raw),
            "collected_at": collected_at,
        },
        private_key,
    )


def verify_recovery_source_artifact(
    artifact: dict,
    *,
    source: str,
    challenge: dict,
    public_key: Path,
    reached_artifact: dict,
    kill_artifact: dict,
    expected_phase: str = "final",
    predecessor_artifacts: dict[str, dict] | None = None,
    include_claims: bool = False,
) -> dict:
    if (
        source not in RECOVERY_SOURCE_ROLES
        or challenge.get("source_key_fingerprints", {}).get(source)
        != ed25519_public_key_fingerprint(public_key)
    ):
        raise ValueError("Stage-C recovery source public key 未绑定 challenge")
    claims = verify_ed25519_artifact(
        artifact,
        public_key,
        label=f"Stage-C {source} recovery source",
    )
    expected = {
        "version",
        "action",
        "scenario",
        "challenge_id",
        "source",
        "workload_binding_sha256",
        "artifact_sha256",
        "reached_artifact_sha256",
        "kill_artifact_sha256",
        "marker_sha256",
        "boundary_proof_sha256",
        "phase",
        "predecessor_artifact_sha256s",
        "payload",
        "collected_at",
    }
    workload = challenge["workloads"][source]
    if (
        not isinstance(claims, dict)
        or set(claims) != expected
        or claims["version"] != 2
        or claims["action"] != RECOVERY_SOURCE_ACTION
        or claims["scenario"] != challenge["scenario"]
        or claims["challenge_id"] != challenge["challenge_id"]
        or claims["source"] != source
        or claims["workload_binding_sha256"]
        != hashlib.sha256(canonical_bytes(workload)).hexdigest()
        or claims["artifact_sha256"]
        != challenge["identity"]["artifact_sha256"]
        or claims["reached_artifact_sha256"]
        != hashlib.sha256(canonical_bytes(reached_artifact)).hexdigest()
        or claims["kill_artifact_sha256"]
        != hashlib.sha256(canonical_bytes(kill_artifact)).hexdigest()
        or claims["phase"] != expected_phase
        or claims["predecessor_artifact_sha256s"]
        != {
            name: hashlib.sha256(canonical_bytes(value)).hexdigest()
            for name, value in sorted((predecessor_artifacts or {}).items())
        }
        or not re.fullmatch(r"[0-9a-f]{64}", str(claims["marker_sha256"]))
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(claims["boundary_proof_sha256"]),
        )
    ):
        raise ValueError("Stage-C recovery source signature/workload 非法")
    _iso(claims["collected_at"], label=f"{source} collected_at")
    try:
        payload = json.loads(
            _decode_opaque_bytes(
                claims["payload"],
                f"Stage-C {source} payload",
            )
        )
    except json.JSONDecodeError as exc:
        raise ValueError("Stage-C recovery source payload JSON 非法") from exc
    if (
        not isinstance(payload, dict)
        or canonical_bytes(payload) != _decode_opaque_bytes(
            claims["payload"],
            f"Stage-C {source} payload",
        )
        or payload.get("marker_sha256") != claims["marker_sha256"]
        or payload.get("boundary_proof_sha256")
        != claims["boundary_proof_sha256"]
    ):
        raise ValueError("Stage-C recovery source payload 非 canonical JSON")
    if include_claims:
        return {"payload": payload, "claims": claims}
    return payload


def _frame(
    acquisition: NativeAcquisition,
    *,
    label: str,
    requested_at: datetime,
    completed_at: datetime,
) -> dict:
    if not isinstance(acquisition, NativeAcquisition):
        raise TypeError("Stage-C recovery collector 未返回 native acquisition")
    return {
        "label": label,
        "source": acquisition.source,
        "operation": acquisition.operation,
        "request": _opaque_bytes_descriptor(acquisition.request_bytes),
        "response": _opaque_bytes_descriptor(acquisition.response_bytes),
        "returncode": acquisition.returncode,
        "requested_at": requested_at.isoformat(),
        "completed_at": completed_at.isoformat(),
    }


def _okx_get(
    *,
    base_url: str,
    path: str,
    params: dict[str, str],
    api_key: str,
    secret_key: str,
    passphrase: str,
) -> NativeAcquisition:
    if (
        base_url not in _OKX_BASE_URLS
        or not path.startswith("/api/v5/")
        or not api_key
        or not secret_key
        or not passphrase
    ):
        raise ValueError("Stage-C recovery OKX endpoint/credentials 非法")
    query = urllib.parse.urlencode(params)
    path_url = f"{path}?{query}" if query else path
    timestamp = (
        datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )
    signature = base64.b64encode(
        hmac.new(
            secret_key.encode(),
            f"{timestamp}GET{path_url}".encode(),
            hashlib.sha256,
        ).digest()
    ).decode()
    return collect_http_native(
        source="okx_collector",
        method="GET",
        url=base_url + path_url,
        headers={
            "OK-ACCESS-KEY": api_key,
            "OK-ACCESS-SIGN": signature,
            "OK-ACCESS-TIMESTAMP": timestamp,
            "OK-ACCESS-PASSPHRASE": passphrase,
            "x-simulated-trading": "1",
        },
    )


def _recovery_target(marker_path: Path, proof_path: Path) -> tuple[dict, dict]:
    if (
        not marker_path.is_file()
        or marker_path.is_symlink()
        or not proof_path.is_file()
        or proof_path.is_symlink()
    ):
        raise ValueError("Stage-C recovery marker/proof 非安全普通文件")
    marker = json.loads(marker_path.read_bytes())
    proof = load_pipeline_proof(proof_path, marker=marker)
    return marker, proof


def _recovery_query_requests(proof: dict) -> list[tuple[str, tuple[str, ...]]]:
    facts = proof["facts"]
    cl_ord_id = str(facts.get("cl_ord_id", ""))
    order_id = str(facts.get("ord_id", ""))
    trade_id = str(facts.get("trade_id", ""))
    probe_id = str(facts.get("probe_id", ""))
    requests: list[tuple[str, tuple[str, ...]]] = [
        ("integrity", ()),
        ("system-mode", ()),
        ("reconciliations", ()),
        ("duplicate-buy-audit", ()),
        ("positions", ()),
        ("stage-c-active-protection-by-inst", ("BTC-USDT",)),
        ("stage-c-recovery-checkpoint", (str(proof["challenge_id"]),)),
    ]
    if cl_ord_id:
        requests.append(("stage-c-intent-by-clordid", (cl_ord_id,)))
    if probe_id:
        requests.extend((
            ("stage-c-probe-by-id", (probe_id,)),
            ("stage-c-risk-by-probe", (probe_id,)),
        ))
    if trade_id and order_id:
        requests.append(("stage-c-fill-by-trade", (trade_id, order_id)))
    return requests


def _wait_recovery_checkpoint(
    *,
    challenge: dict,
    proof: dict,
    database: Path,
    required_after: datetime,
) -> dict:
    """Wait for a runtime-authored checkpoint bound to this restart generation."""
    deadline = time.monotonic() + 120
    facts = proof["facts"]
    old_pid = int(challenge["workloads"]["fault_driver"]["pid"])
    old_invocation = _normalize_id128(
        str(challenge["workloads"]["fault_driver"]["systemd_invocation_id"]),
        label="Stage-C old InvocationID",
    )
    while time.monotonic() < deadline:
        connection = None
        try:
            connection = sqlite3.connect(
                f"{database.resolve().as_uri()}?mode=ro",
                uri=True,
            )
            connection.row_factory = sqlite3.Row
            reconciliation = connection.execute(
                "SELECT run_id, status, completed_at FROM reconciliation_runs "
                "ORDER BY started_at DESC, run_id DESC LIMIT 1"
            ).fetchone()
            checkpoint_row = connection.execute(
                "SELECT event_id, payload_json, created_at FROM system_events "
                "WHERE event_name='stage_c_recovery_evidence_ready' "
                "AND correlation_id=? ORDER BY created_at DESC, event_id DESC "
                "LIMIT 1",
                (challenge["challenge_id"],),
            ).fetchone()
            scenario_ready = False
            if challenge["scenario"] == "barrier-buy-intent-before-post":
                row = connection.execute(
                    "SELECT state FROM probe_runs WHERE probe_id=?",
                    (str(facts.get("probe_id", "")),),
                ).fetchone()
                scenario_ready = row is not None and row["state"] == "REJECTED"
            elif challenge["scenario"] == "barrier-post-before-ack":
                row = connection.execute(
                    "SELECT state FROM order_intents WHERE cl_ord_id=?",
                    (str(facts.get("cl_ord_id", "")),),
                ).fetchone()
                scenario_ready = row is not None and row["state"] not in {
                    "BUY_SUBMITTING",
                    "UNKNOWN",
                }
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS n FROM fills WHERE trade_id=? "
                    "AND exchange_ord_id=?",
                    (
                        str(facts.get("trade_id", "")),
                        str(facts.get("ord_id", "")),
                    ),
                ).fetchone()
                protection = connection.execute(
                    "SELECT state FROM protective_orders WHERE inst_id=? "
                    "ORDER BY updated_at DESC LIMIT 1",
                    ("BTC-USDT",),
                ).fetchone()
                scenario_ready = (
                    row is not None
                    and row["n"] == 1
                    and protection is not None
                    and protection["state"] == "active"
                )
            checkpoint = (
                json.loads(str(checkpoint_row["payload_json"]))
                if checkpoint_row is not None
                else None
            )
            completed = (
                datetime.fromtimestamp(float(reconciliation["completed_at"]), UTC)
                if reconciliation is not None
                and reconciliation["completed_at"] is not None
                else None
            )
            checkpoint_created = (
                datetime.fromtimestamp(float(checkpoint_row["created_at"]), UTC)
                if checkpoint_row is not None
                else None
            )
            if isinstance(checkpoint, dict):
                new_invocation = _normalize_id128(
                    str(checkpoint.get("systemd_invocation_id", "")),
                    label="Stage-C recovery checkpoint InvocationID",
                )
                checkpoint_completed = datetime.fromtimestamp(
                    float(checkpoint.get("reconciliation_completed_at")), UTC
                )
                checkpoint_pid = int(checkpoint.get("pid", 0))
            else:
                new_invocation = ""
                checkpoint_completed = None
                checkpoint_pid = 0
            if (
                reconciliation is not None
                and reconciliation["status"] == "ok"
                and completed is not None
                and completed > required_after.astimezone(UTC)
                and checkpoint_created is not None
                and checkpoint_created > required_after.astimezone(UTC)
                and checkpoint is not None
                and checkpoint.get("challenge_id") == challenge["challenge_id"]
                and checkpoint.get("scenario") == challenge["scenario"]
                and checkpoint.get("evidence_hold") is True
                and checkpoint.get("reconciliation_run_id")
                == reconciliation["run_id"]
                and checkpoint_completed == completed
                and checkpoint_pid > 1
                and checkpoint_pid != old_pid
                and new_invocation != old_invocation
                and scenario_ready
            ):
                return checkpoint
        except (
            OSError,
            sqlite3.Error,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            pass
        finally:
            if connection is not None:
                connection.close()
        time.sleep(0.2)
    raise TimeoutError("Stage-C journal recovery 未达到 challenge-bound checkpoint")


def collect_journal_recovery_payload(
    *,
    challenge: dict,
    marker_path: Path,
    proof_path: Path,
    database: Path,
    required_after: datetime | None = None,
) -> dict:
    marker, proof = _recovery_target(marker_path, proof_path)
    started = datetime.now(UTC)
    if required_after is not None:
        _wait_recovery_checkpoint(
            challenge=challenge,
            proof=proof,
            database=database,
            required_after=required_after,
        )
    requests = _recovery_query_requests(proof)
    requested_at = datetime.now(UTC)
    cut = collect_sqlite_snapshot_native(
        database=database,
        query_requests=tuple(requests),
    )
    completed_at = datetime.now(UTC)
    frames = [
        _frame(
            cut[request],
            label=request[0],
            requested_at=requested_at,
            completed_at=completed_at,
        )
        for request in requests
    ]
    if not frames or any(frame["response"] != frames[0]["response"] for frame in frames):
        raise ValueError("Stage-C journal source 未返回唯一 SQLite snapshot cut")
    snapshot_response = frames[0]["response"]
    return {
        "schema": "okx-quant.stage-c-recovery-source/v1",
        "source": "journal_collector",
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "boundary_proof_sha256": marker["boundary_proof_sha256"],
        "marker_sha256": marker["marker_sha256"],
        "recovery_started_at": started.isoformat(),
        "collected_at": completed_at.isoformat(),
        # Store the (potentially large) SQLite backup cut once.  Individual
        # query frames carry only their exact request/timing metadata and are
        # deterministically rehydrated by the assembler/projector.
        "snapshot_response": snapshot_response,
        "frames": [
            {key: value for key, value in frame.items() if key != "response"}
            for frame in frames
        ],
    }


def collect_okx_recovery_payload(
    *,
    challenge: dict,
    marker_path: Path,
    proof_path: Path,
    api_key: str,
    secret_key: str,
    passphrase: str,
    journal_readiness_sha256: str,
    okx_base_url: str = "https://openapi.okx.com",
) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", journal_readiness_sha256):
        raise ValueError("Stage-C OKX recovery journal readiness hash 非法")
    marker, proof = _recovery_target(marker_path, proof_path)
    observer_fingerprint = credential_fingerprint(api_key)
    if (
        challenge.get("barrier_recovery_bindings", {}).get(
            "observer_api_key_fingerprint"
        )
        != observer_fingerprint
    ):
        raise ValueError("Stage-C OKX observer API key 未预绑定 challenge")
    started = datetime.now(UTC)
    facts = proof["facts"]
    cl_ord_id = str(facts.get("cl_ord_id", ""))
    order_id = str(facts.get("ord_id", ""))
    requests: list[tuple[str, str, dict[str, str]]] = [
        ("account-config", "/api/v5/account/config", {}),
        (
            "pending-orders",
            "/api/v5/trade/orders-pending",
            {"instType": "SPOT", "instId": "BTC-USDT"},
        ),
        (
            "pending-algos",
            "/api/v5/trade/orders-algo-pending",
            {"ordType": "oco", "instId": "BTC-USDT"},
        ),
        ("balance", "/api/v5/account/balance", {"ccy": "BTC,USDT"}),
    ]
    if cl_ord_id or order_id:
        order_params = {"instId": "BTC-USDT"}
        order_params["ordId" if order_id else "clOrdId"] = order_id or cl_ord_id
        requests.append(("order", "/api/v5/trade/order", order_params))
        fill_params = {
            "instType": "SPOT",
            "instId": "BTC-USDT",
            "limit": "100",
        }
        if order_id:
            fill_params["ordId"] = order_id
        requests.append((
            "fills-history",
            "/api/v5/trade/fills-history",
            fill_params,
        ))
    passes: list[list[dict]] = []
    for pass_index in range(2):
        frames: list[dict] = []
        for label, path, params in requests:
            requested_at = datetime.now(UTC)
            acquisition = _okx_get(
                base_url=okx_base_url,
                path=path,
                params=params,
                api_key=api_key,
                secret_key=secret_key,
                passphrase=passphrase,
            )
            frames.append(_frame(
                acquisition,
                label=label,
                requested_at=requested_at,
                completed_at=datetime.now(UTC),
            ))
        passes.append(frames)
        if pass_index == 0:
            time.sleep(0.2)
    if _okx_semantic_projection(passes[0]) != _okx_semantic_projection(passes[1]):
        raise ValueError("Stage-C OKX double-read 在两次完整读取间不稳定")
    collected = datetime.now(UTC)
    return {
        "schema": "okx-quant.stage-c-recovery-source/v1",
        "source": "okx_collector",
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "boundary_proof_sha256": marker["boundary_proof_sha256"],
        "marker_sha256": marker["marker_sha256"],
        "journal_readiness_sha256": journal_readiness_sha256,
        "api_key_fingerprint": observer_fingerprint,
        "recovery_started_at": started.isoformat(),
        "collected_at": collected.isoformat(),
        "stability_frames": passes[0],
        "frames": passes[1],
    }


_OKX_STABLE_FIELDS = {
    "account-config": ("uid", "perm"),
    "pending-orders": (
        "ordId", "clOrdId", "instId", "state", "side", "sz", "accFillSz",
    ),
    "pending-algos": (
        "algoId", "algoClOrdId", "instId", "state", "side", "sz", "ordType",
    ),
    "order": (
        "ordId", "clOrdId", "instId", "state", "side", "ordType", "sz",
        "accFillSz", "avgPx", "fee", "feeCcy",
    ),
    "fills-history": (
        "tradeId", "ordId", "clOrdId", "instId", "side", "fillSz", "fillPx",
        "fee", "feeCcy",
    ),
}


def _okx_semantic_projection(frames: list[dict]) -> dict[str, list[dict]]:
    """Ignore valuation clocks while requiring all recovery semantics stable."""
    projection: dict[str, list[dict]] = {}
    for frame in frames:
        label = str(frame.get("label", ""))
        status, _headers, document = _parse_http(
            _decode_opaque_bytes(frame.get("response"), f"{label} response"),
            f"recovery-stability/{label}",
        )
        if status != 200 or not isinstance(document, dict):
            raise ValueError("Stage-C OKX stability response schema 非法")
        if document.get("code") == "51603" and label == "order":
            rows: list[dict] = []
        else:
            rows = document.get("data")
            if document.get("code") != "0" or not isinstance(rows, list) or any(
                not isinstance(row, dict) for row in rows
            ):
                raise ValueError("Stage-C OKX stability API response 非法")
        if label == "balance":
            details = []
            for account in rows:
                account_details = account.get("details", [])
                if not isinstance(account_details, list):
                    raise ValueError("Stage-C OKX balance details 非法")
                for item in account_details:
                    if isinstance(item, dict) and item.get("ccy") in {"BTC", "USDT"}:
                        details.append({
                            key: str(item.get(key, ""))
                            for key in ("ccy", "cashBal", "availBal", "frozenBal")
                        })
            projection[label] = sorted(details, key=lambda item: item["ccy"])
        else:
            fields = _OKX_STABLE_FIELDS.get(label)
            if fields is None:
                raise ValueError("Stage-C OKX stability operation 非法")
            projection[label] = sorted(
                ({key: str(row.get(key, "")) for key in fields} for row in rows),
                key=lambda item: canonical_bytes(item),
            )
    return projection


def collect_systemd_recovery_payload(
    *,
    challenge: dict,
    marker_path: Path,
    proof_path: Path,
    runtime_unit: str,
    required_after: datetime | None = None,
) -> dict:
    marker, _proof = _recovery_target(marker_path, proof_path)
    started = datetime.now(UTC)
    deadline = time.monotonic() + 120
    frame = None
    while time.monotonic() < deadline:
        requested_at = datetime.now(UTC)
        candidate = _frame(
            collect_systemd_native(
                action="show-after-restart",
                unit=runtime_unit,
            ),
            label="show-after-restart",
            requested_at=requested_at,
            completed_at=datetime.now(UTC),
        )
        try:
            values = _strict_systemd_values(
                {
                    "response_raw": _decode_opaque_bytes(
                        candidate["response"],
                        "Stage-C systemd source response",
                    )
                },
                "Stage-C systemd source readiness",
            )
            ready = (
                values["ActiveState"] == "active"
                and values["SubState"] in {"running", "start-post"}
                and int(values["MainPID"])
                != challenge["workloads"]["fault_driver"]["pid"]
                and values["InvocationID"].replace("-", "").lower()
                != str(challenge["workloads"]["fault_driver"][
                    "systemd_invocation_id"
                ]).replace("-", "").lower()
                and (
                    required_after is None
                    or datetime.fromisoformat(candidate["completed_at"])
                    > required_after
                )
            )
        except (KeyError, ValueError):
            ready = False
        if ready:
            frame = candidate
            break
        time.sleep(0.2)
    if frame is None:
        raise TimeoutError("Stage-C systemd recovery 未在 deadline 达到新 invocation")
    collected = datetime.now(UTC)
    return {
        "schema": "okx-quant.stage-c-recovery-source/v1",
        "source": "systemd_collector",
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "boundary_proof_sha256": marker["boundary_proof_sha256"],
        "marker_sha256": marker["marker_sha256"],
        "recovery_started_at": started.isoformat(),
        "collected_at": collected.isoformat(),
        "frames": [frame],
    }


def assemble_native_recovery_bundle(
    *,
    challenge: dict,
    marker_path: Path,
    proof_path: Path,
    source_artifacts: dict[str, dict],
    journal_readiness_artifact: dict,
    source_public_keys: dict[str, Path],
    reached_artifact: dict,
    kill_artifact: dict,
) -> dict:
    """Assemble only independently signed source artifacts."""
    if (
        set(source_artifacts) != RECOVERY_SOURCE_ROLES
        or set(source_public_keys) != RECOVERY_SOURCE_ROLES
    ):
        raise ValueError("Stage-C recovery 独立 source artifacts/keys 不完整")
    marker, _proof = _recovery_target(marker_path, proof_path)
    readiness_payload = verify_recovery_source_artifact(
        journal_readiness_artifact,
        source="journal_collector",
        challenge=challenge,
        public_key=source_public_keys["journal_collector"],
        reached_artifact=reached_artifact,
        kill_artifact=kill_artifact,
        expected_phase="readiness",
    )
    okx_payload = verify_recovery_source_artifact(
        source_artifacts["okx_collector"],
        source="okx_collector",
        challenge=challenge,
        public_key=source_public_keys["okx_collector"],
        reached_artifact=reached_artifact,
        kill_artifact=kill_artifact,
        predecessor_artifacts={"journal_readiness": journal_readiness_artifact},
    )
    final_predecessors = {
        "journal_readiness": journal_readiness_artifact,
        "okx_final": source_artifacts["okx_collector"],
    }
    payloads = {
        "journal_collector": verify_recovery_source_artifact(
            source_artifacts["journal_collector"],
            source="journal_collector",
            challenge=challenge,
            public_key=source_public_keys["journal_collector"],
            reached_artifact=reached_artifact,
            kill_artifact=kill_artifact,
            predecessor_artifacts=final_predecessors,
        ),
        "okx_collector": okx_payload,
        "systemd_collector": verify_recovery_source_artifact(
            source_artifacts["systemd_collector"],
            source="systemd_collector",
            challenge=challenge,
            public_key=source_public_keys["systemd_collector"],
            reached_artifact=reached_artifact,
            kill_artifact=kill_artifact,
            predecessor_artifacts=final_predecessors,
        ),
    }
    expected_keys = {
        "schema",
        "source",
        "scenario",
        "challenge_id",
        "boundary_proof_sha256",
        "marker_sha256",
        "recovery_started_at",
        "collected_at",
        "frames",
    }
    for source, payload in payloads.items():
        source_expected = set(expected_keys)
        if source == "journal_collector":
            source_expected.add("snapshot_response")
        elif source == "okx_collector":
            source_expected.update({
                "journal_readiness_sha256",
                "api_key_fingerprint",
                "stability_frames",
            })
        if (
            set(payload) != source_expected
            or payload["schema"] != "okx-quant.stage-c-recovery-source/v1"
            or payload["source"] != source
            or payload["scenario"] != challenge["scenario"]
            or payload["challenge_id"] != challenge["challenge_id"]
            or payload["boundary_proof_sha256"]
            != marker["boundary_proof_sha256"]
            or payload["marker_sha256"] != marker["marker_sha256"]
            or not isinstance(payload["frames"], list)
            or not payload["frames"]
        ):
            raise ValueError("Stage-C recovery source payload 串线")
    journal_artifact_sha256 = hashlib.sha256(
        canonical_bytes(journal_readiness_artifact)
    ).hexdigest()
    if (
        payloads["okx_collector"]["journal_readiness_sha256"]
        != journal_artifact_sha256
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(payloads["okx_collector"]["api_key_fingerprint"]),
        )
        or _iso(
            readiness_payload["collected_at"],
            label="journal readiness collected_at",
        )
        > _iso(
            payloads["okx_collector"]["recovery_started_at"],
            label="OKX recovery started_at",
        )
    ):
        raise ValueError("Stage-C OKX recovery 未绑定 journal readiness cut")
    started = min(
        _iso(payload["recovery_started_at"], label=f"{source} started")
        for source, payload in payloads.items()
    )
    collected = max(
        _iso(payload["collected_at"], label=f"{source} collected")
        for source, payload in payloads.items()
    )
    journal_frames = [
        {**frame, "response": payloads["journal_collector"]["snapshot_response"]}
        for frame in payloads["journal_collector"]["frames"]
    ]
    return {
        "schema": NATIVE_RECOVERY_SCHEMA,
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "barrier_nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "boundary_proof_sha256": marker["boundary_proof_sha256"],
        "recovery_started_at": started.isoformat(),
        "collected_at": collected.isoformat(),
        "marker": _opaque_bytes_descriptor(marker_path.read_bytes()),
        "boundary_proof": _opaque_bytes_descriptor(proof_path.read_bytes()),
        "systemd": payloads["systemd_collector"]["frames"][0],
        "sqlite_snapshot": journal_frames,
        "okx_demo_https": payloads["okx_collector"]["frames"],
        "okx_stability_https": payloads["okx_collector"]["stability_frames"],
        "journal_readiness_artifact": journal_readiness_artifact,
        "source_artifacts": source_artifacts,
    }


def collect_native_recovery_bundle(
    *,
    challenge: dict,
    marker_path: Path,
    proof_path: Path,
    database: Path,
    runtime_unit: str,
    api_key: str,
    secret_key: str,
    passphrase: str,
    okx_base_url: str = "https://openapi.okx.com",
) -> dict:
    """Acquire facts directly from systemd, one SQLite cut, and OKX demo."""
    if (
        challenge.get("scenario")
        not in {
            "barrier-buy-intent-before-post",
            "barrier-post-before-ack",
            "barrier-fill-before-projection",
        }
        or not marker_path.is_file()
        or marker_path.is_symlink()
    ):
        raise ValueError("Stage-C recovery challenge/marker 非法")
    marker = json.loads(marker_path.read_bytes())
    proof = load_pipeline_proof(proof_path, marker=marker)
    recovery_started_at = datetime.now(UTC)
    facts = proof["facts"]
    cl_ord_id = str(facts.get("cl_ord_id", ""))
    order_id = str(facts.get("ord_id", ""))
    trade_id = str(facts.get("trade_id", ""))
    probe_id = str(facts.get("probe_id", ""))
    query_requests: list[tuple[str, tuple[str, ...]]] = [
        ("integrity", ()),
        ("system-mode", ()),
        ("reconciliations", ()),
        ("duplicate-buy-audit", ()),
        ("positions", ()),
        ("stage-c-active-protection-by-inst", ("BTC-USDT",)),
        ("stage-c-recovery-checkpoint", (str(proof["challenge_id"]),)),
    ]
    if cl_ord_id:
        query_requests.append(("stage-c-intent-by-clordid", (cl_ord_id,)))
    if probe_id:
        query_requests.append(("stage-c-probe-by-id", (probe_id,)))
        query_requests.append(("stage-c-risk-by-probe", (probe_id,)))
    if trade_id and order_id:
        query_requests.append(
            ("stage-c-fill-by-trade", (trade_id, order_id))
        )
    sqlite_requested_at = datetime.now(UTC)
    sqlite_cut = collect_sqlite_snapshot_native(
        database=database,
        query_requests=tuple(query_requests),
    )
    sqlite_completed_at = datetime.now(UTC)
    sqlite_frames = [
        _frame(
            sqlite_cut[request],
            label=request[0],
            requested_at=sqlite_requested_at,
            completed_at=sqlite_completed_at,
        )
        for request in query_requests
    ]
    okx_requests: list[tuple[str, str, dict[str, str]]] = [
        ("account-config", "/api/v5/account/config", {}),
        (
            "pending-orders",
            "/api/v5/trade/orders-pending",
            {"instType": "SPOT", "instId": "BTC-USDT"},
        ),
        (
            "pending-algos",
            "/api/v5/trade/orders-algo-pending",
            {"ordType": "oco", "instId": "BTC-USDT"},
        ),
        (
            "balance",
            "/api/v5/account/balance",
            {"ccy": "BTC,USDT"},
        ),
    ]
    if cl_ord_id or order_id:
        order_parameters = {"instId": "BTC-USDT"}
        if order_id:
            order_parameters["ordId"] = order_id
        else:
            order_parameters["clOrdId"] = cl_ord_id
        okx_requests.append(
            ("order", "/api/v5/trade/order", order_parameters)
        )
    if cl_ord_id or order_id:
        fill_parameters = {
            "instType": "SPOT",
            "instId": "BTC-USDT",
            "limit": "100",
        }
        if order_id:
            fill_parameters["ordId"] = order_id
        okx_requests.append(
            (
                "fills-history",
                "/api/v5/trade/fills-history",
                fill_parameters,
            )
        )
    okx_passes: list[list[dict]] = []
    for _pass_index in range(2):
        okx_frames = []
        for label, path, params in okx_requests:
            requested_at = datetime.now(UTC)
            acquisition = _okx_get(
                base_url=okx_base_url,
                path=path,
                params=params,
                api_key=api_key,
                secret_key=secret_key,
                passphrase=passphrase,
            )
            okx_frames.append(_frame(
                acquisition,
                label=label,
                requested_at=requested_at,
                completed_at=datetime.now(UTC),
            ))
        okx_passes.append(okx_frames)
    if _okx_semantic_projection(okx_passes[0]) != _okx_semantic_projection(
        okx_passes[1]
    ):
        raise ValueError("Stage-C compatibility OKX double-read 不稳定")
    systemd_requested_at = datetime.now(UTC)
    systemd_acquisition = collect_systemd_native(
        action="show-after-restart",
        unit=runtime_unit,
    )
    systemd_frame = _frame(
        systemd_acquisition,
        label="show-after-restart",
        requested_at=systemd_requested_at,
        completed_at=datetime.now(UTC),
    )
    return {
        "schema": NATIVE_RECOVERY_SCHEMA,
        "scenario": challenge["scenario"],
        "challenge_id": challenge["challenge_id"],
        "barrier_nonce": challenge["barrier_nonce"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "boundary_proof_sha256": marker["boundary_proof_sha256"],
        "recovery_started_at": recovery_started_at.isoformat(),
        "collected_at": datetime.now(UTC).isoformat(),
        "marker": _opaque_bytes_descriptor(marker_path.read_bytes()),
        "boundary_proof": _opaque_bytes_descriptor(proof_path.read_bytes()),
        "systemd": systemd_frame,
        "sqlite_snapshot": sqlite_frames,
        "okx_demo_https": okx_passes[1],
        "okx_stability_https": okx_passes[0],
        "journal_readiness_artifact": None,
        # This compatibility acquisition helper is used by local tests only.
        # Production projection rejects it until independently signed source
        # artifacts are attached by assemble_native_recovery_bundle().
        "source_artifacts": {},
    }


def _iso(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} 非 ISO-8601")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} 非法") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} 缺少时区")
    return parsed.astimezone(UTC)


def _native_frame(value: object, *, label: str) -> tuple[dict, bytes, bytes]:
    expected = {
        "label",
        "source",
        "operation",
        "request",
        "response",
        "returncode",
        "requested_at",
        "completed_at",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["label"] != label
        or value["returncode"] != 0
        or _iso(value["requested_at"], label=f"{label} requested_at")
        > _iso(value["completed_at"], label=f"{label} completed_at")
    ):
        raise ValueError(f"{label} native frame 非法")
    return (
        value,
        _decode_opaque_bytes(value["request"], f"{label} request"),
        _decode_opaque_bytes(value["response"], f"{label} response"),
    )


def _row_objects(result: dict, *, label: str) -> list[dict]:
    columns = result.get("columns")
    rows = result.get("rows")
    if (
        not isinstance(columns, list)
        or not all(isinstance(item, str) and item for item in columns)
        or len(set(columns)) != len(columns)
        or not isinstance(rows, list)
        or any(not isinstance(row, list) or len(row) != len(columns) for row in rows)
    ):
        raise ValueError(f"{label} SQLite rows 非法")
    return [dict(zip(columns, row, strict=True)) for row in rows]


def _sqlite_snapshot(
    frames: object,
    *,
    after: datetime,
) -> tuple[dict[str, list[dict]], str, dict[str, dict]]:
    if not isinstance(frames, list) or not frames:
        raise ValueError("Stage-C recovery SQLite frames 缺失")
    parsed: dict[str, tuple[dict, bytes, bytes]] = {}
    response_raw: bytes | None = None
    for raw_frame in frames:
        if not isinstance(raw_frame, dict) or not isinstance(raw_frame.get("label"), str):
            raise ValueError("Stage-C recovery SQLite frame label 非法")
        label = raw_frame["label"]
        if label in parsed:
            raise ValueError("Stage-C recovery SQLite frame 重复")
        frame, request_raw, current_response = _native_frame(
            raw_frame,
            label=label,
        )
        if (
            frame["source"] != "journal_collector"
            or not str(frame["operation"]).startswith("snapshot:")
            or _iso(frame["completed_at"], label=f"{label} completed_at") <= after
        ):
            raise ValueError("Stage-C recovery SQLite source/time 非法")
        if response_raw is None:
            response_raw = current_response
        elif current_response != response_raw:
            raise ValueError("Stage-C recovery SQLite frames 非同一 snapshot")
        parsed_frame = {
            "request_raw": request_raw,
            "response_raw": current_response,
        }
        # Deserialize the embedded database snapshot and rerun the fixed SQL.
        # The JSON result array alone is not evidence.
        _sqlite_rows(parsed_frame, f"recovery/{label}")
        parsed[label] = (frame, request_raw, current_response)
    try:
        cut = json.loads(response_raw or b"")
    except json.JSONDecodeError as exc:
        raise ValueError("Stage-C recovery SQLite cut JSON 非法") from exc
    if (
        not isinstance(cut, dict)
        or cut.get("schema") != "okx-quant.stage-c-sqlite-snapshot/v1"
        or not isinstance(cut.get("snapshot"), dict)
        or not isinstance(cut.get("results"), list)
        or cut["snapshot"].get("quick_check") != "ok"
    ):
        raise ValueError("Stage-C recovery SQLite cut schema/integrity 非法")
    snapshot_sha256 = str(cut["snapshot"].get("database_sha256", ""))
    if len(snapshot_sha256) != 64:
        raise ValueError("Stage-C recovery SQLite snapshot hash 非法")
    results: dict[tuple[str, tuple[str, ...]], dict] = {}
    for result in cut["results"]:
        if not isinstance(result, dict):
            raise ValueError("Stage-C recovery SQLite result 非法")
        key = (
            str(result.get("query_name", "")),
            tuple(str(item) for item in result.get("parameters", [])),
        )
        if key in results:
            raise ValueError("Stage-C recovery SQLite result 重复")
        results[key] = result
    rows_by_label: dict[str, list[dict]] = {}
    frames_by_label: dict[str, dict] = {}
    for label, (frame, request_raw, _response) in parsed.items():
        try:
            request = json.loads(request_raw)
        except json.JSONDecodeError as exc:
            raise ValueError("Stage-C recovery SQLite request JSON 非法") from exc
        if (
            not isinstance(request, dict)
            or request.get("schema")
            != "okx-quant.stage-c-sqlite-snapshot-request/v1"
            or request.get("query_name") != label
            or request.get("snapshot_sha256") != snapshot_sha256
        ):
            raise ValueError("Stage-C recovery SQLite request 未绑定 snapshot")
        key = (label, tuple(str(item) for item in request.get("parameters", [])))
        result = results.get(key)
        if result is None:
            raise ValueError("Stage-C recovery SQLite result 缺失")
        rows_by_label[label] = _row_objects(result, label=label)
        frames_by_label[label] = frame
    return rows_by_label, snapshot_sha256, frames_by_label


def _http_rows(
    frame: dict,
    *,
    label: str,
    after: datetime,
    expected_query: dict[str, str],
    expected_api_key_fingerprint: str,
    expected_tls_certificate_sha256: str | None = None,
    expected_tls_spki_sha256: str | None = None,
) -> list[dict]:
    parsed, request_raw, response_raw = _native_frame(frame, label=label)
    raw_frame = {
        "request_raw": request_raw,
        "response_raw": response_raw,
    }
    expected = _OKX_PATH_BY_OPERATION.get(label)
    if expected is None:
        raise ValueError(f"{label} OKX operation 未注册")
    method, target, request_headers, body = _validate_tls_frame(
        raw_frame,
        label=f"recovery/{label}",
        allowed_hosts=frozenset({"openapi.okx.com", "www.okx.com"}),
        require_request_id=True,
    )
    parsed_target = urllib.parse.urlsplit(target)
    query = (
        urllib.parse.parse_qs(
            parsed_target.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
        if parsed_target.query
        else {}
    )
    if (
        parsed["source"] != "okx_collector"
        or _iso(parsed["completed_at"], label=f"{label} completed_at") <= after
        or parsed["operation"] != f"GET {target}"
        or method != "GET"
        or body
        or parsed_target.path != expected[0]
        or set(query) != set(expected_query)
        or set(query) > expected[1]
        or any(len(values) != 1 or not values[0] for values in query.values())
        or {key: values[0] for key, values in query.items()}
        != expected_query
        or request_headers.get("x-simulated-trading") != "1"
        or request_headers.get("x-stage-c-api-key-fingerprint", "")
        != expected_api_key_fingerprint
    ):
        raise ValueError(f"{label} OKX Demo frame source/time/header 非法")
    status, response_headers, document = _parse_http(
        response_raw,
        f"recovery/{label}",
    )
    if (
        status != 200
        or not isinstance(document, dict)
        or (
            expected_tls_certificate_sha256 is not None
            and response_headers.get("x-stage-c-peer-cert-sha256")
            != expected_tls_certificate_sha256
        )
        or (
            expected_tls_spki_sha256 is not None
            and response_headers.get("x-stage-c-peer-spki-sha256")
            != expected_tls_spki_sha256
        )
    ):
        raise ValueError(f"{label} OKX HTTP status/schema 非法")
    if document.get("code") == "51603" and label == "order":
        return []
    rows = document.get("data")
    if document.get("code") != "0" or not isinstance(rows, list) or any(
        not isinstance(row, dict) for row in rows
    ):
        raise ValueError(f"{label} OKX API response 非法")
    return rows


def _core_query(
    frame: dict,
    *,
    operation: str,
    rows: list[dict],
    snapshot_id: str,
) -> dict:
    return {
        "operation": operation,
        "requested_at": frame["requested_at"],
        "completed_at": frame["completed_at"],
        "request": frame["request"],
        "response": frame["response"],
        "rows": rows,
        "snapshot_id": snapshot_id,
    }


def _systemd_values(frame: object, *, after: datetime) -> tuple[dict, dict]:
    parsed, _request, response = _native_frame(
        frame,
        label="show-after-restart",
    )
    if (
        parsed["source"] != "systemd_collector"
        or parsed["operation"] != "show-after-restart"
        or _iso(parsed["completed_at"], label="systemd completed_at") <= after
    ):
        raise ValueError("Stage-C recovery systemd source/time 非法")
    try:
        values = _strict_systemd_values(
            {"response_raw": response},
            "recovery/show-after-restart",
        )
        pid = int(values["MainPID"])
    except (UnicodeDecodeError, KeyError, ValueError) as exc:
        raise ValueError("Stage-C recovery systemd response 非法") from exc
    if (
        pid <= 1
        or values.get("ActiveState") != "active"
        or values.get("SubState") not in {"running", "start-post"}
        or not values.get("InvocationID")
        or not values.get("ControlGroup", "").startswith("/system.slice/")
    ):
        raise ValueError("Stage-C recovery new systemd invocation 未 READY")
    return values, parsed


def _reconciliation(rows: list[dict], *, after: datetime) -> dict:
    if len(rows) != 1:
        return {"unresolved": ["missing_unique_reconciliation"]}
    row = rows[0]
    try:
        details = json.loads(str(row.get("details_json", "")))
    except json.JSONDecodeError:
        return {"unresolved": ["invalid_reconciliation_details"]}
    unresolved = details.get("unresolved") if isinstance(details, dict) else None
    if (
        row.get("status") != "ok"
        or row.get("completed_at") is None
        or datetime.fromtimestamp(
            float(row["completed_at"]),
            UTC,
        ) <= after
        or not isinstance(unresolved, list)
    ):
        return {"unresolved": ["invalid_reconciliation_unresolved"]}
    return {
        "run_id": row.get("run_id"),
        "status": row.get("status"),
        "unresolved": unresolved,
    }


def _core_order_rows(rows: list[dict], *, fills: bool = False) -> list[dict]:
    result = []
    for row in rows:
        projected = {
            "ord_id": str(row.get("ordId", "")),
            "state": str(row.get("state", "")),
        }
        if fills:
            projected["trade_id"] = str(row.get("tradeId", ""))
        else:
            projected["cl_ord_id"] = str(row.get("clOrdId", ""))
        result.append(projected)
    return result


def _protection(
    rows: list[dict],
    *,
    pending_algos: list[dict],
    net_qty: Decimal,
    inst_id: str,
    order_id: str,
    cl_ord_id: str,
) -> dict | None:
    if net_qty <= 0:
        return None
    if len(rows) != 1:
        raise ValueError("Stage-C recovery 非零仓位缺少唯一 local protection")
    row = rows[0]
    algo_id = str(row.get("exchange_algo_id", ""))
    matches = [
        item
        for item in pending_algos
        if str(item.get("algoId", "")) == algo_id
        and str(item.get("state", "")).lower() in {"live", "effective"}
        and str(item.get("instId", "")) == inst_id
        and str(item.get("side", "")).lower() == "sell"
        and str(item.get("tdMode", "")).lower() == "cash"
    ]
    covered = Decimal(str(row.get("protected_qty", "0")))
    remote_qty = (
        Decimal(str(matches[0].get("sz", "0"))) if len(matches) == 1
        else Decimal(0)
    )
    cash_sell_reduces_spot = len(matches) == 1 and remote_qty == covered
    if (
        str(row.get("state", "")).lower() != "active"
        or str(row.get("inst_id", "")) != inst_id
        or str(row.get("parent_inst_id", "")) != inst_id
        or str(row.get("parent_side", "")).lower() != "buy"
        or (cl_ord_id and str(row.get("parent_cl_ord_id", "")) != cl_ord_id)
        or (order_id and str(row.get("parent_exchange_ord_id", "")) != order_id)
        or not algo_id
        or len(matches) != 1
        or covered < net_qty
        or remote_qty < net_qty
        or cash_sell_reduces_spot is not True
    ):
        raise ValueError("Stage-C recovery protection 未由 local+OKX 同时证明")
    return {
        "state": "active",
        "reduce_only": cash_sell_reduces_spot,
        "covered_qty": str(min(covered, remote_qty)),
        "algo_id": algo_id,
        "emergency_exit_ord_id": None,
    }


def project_native_recovery_bundle(
    native_bundle: object,
    *,
    challenge: dict,
    reached_artifact: dict,
    reached_public_key: Path,
    kill_artifact: dict,
    kill_public_key: Path,
    source_public_keys: dict[str, Path],
) -> dict:
    """Recompute the core recovery schema solely from captured native bytes."""
    expected_keys = {
        "schema",
        "scenario",
        "challenge_id",
        "barrier_nonce",
        "artifact_sha256",
        "boundary_proof_sha256",
        "recovery_started_at",
        "collected_at",
        "marker",
        "boundary_proof",
        "systemd",
        "sqlite_snapshot",
        "okx_demo_https",
        "okx_stability_https",
        "journal_readiness_artifact",
        "source_artifacts",
    }
    if not isinstance(native_bundle, dict) or set(native_bundle) != expected_keys:
        raise ValueError("Stage-C native recovery bundle schema 非法")
    source_artifacts = native_bundle["source_artifacts"]
    if (
        not isinstance(source_artifacts, dict)
        or set(source_artifacts) != RECOVERY_SOURCE_ROLES
        or set(source_public_keys) != RECOVERY_SOURCE_ROLES
    ):
        raise ValueError("Stage-C native recovery 缺少独立 source signatures")
    journal_readiness_artifact = native_bundle["journal_readiness_artifact"]
    journal_readiness = verify_recovery_source_artifact(
        journal_readiness_artifact,
        source="journal_collector",
        challenge=challenge,
        public_key=source_public_keys["journal_collector"],
        reached_artifact=reached_artifact,
        kill_artifact=kill_artifact,
        expected_phase="readiness",
    )
    okx_predecessors = {"journal_readiness": journal_readiness_artifact}
    okx_source = verify_recovery_source_artifact(
        source_artifacts["okx_collector"],
        source="okx_collector",
        challenge=challenge,
        public_key=source_public_keys["okx_collector"],
        reached_artifact=reached_artifact,
        kill_artifact=kill_artifact,
        predecessor_artifacts=okx_predecessors,
    )
    final_predecessors = {
        **okx_predecessors,
        "okx_final": source_artifacts["okx_collector"],
    }
    source_payloads = {
        "journal_collector": verify_recovery_source_artifact(
            source_artifacts["journal_collector"],
            source="journal_collector",
            challenge=challenge,
            public_key=source_public_keys["journal_collector"],
            reached_artifact=reached_artifact,
            kill_artifact=kill_artifact,
            predecessor_artifacts=final_predecessors,
        ),
        "okx_collector": okx_source,
        "systemd_collector": verify_recovery_source_artifact(
            source_artifacts["systemd_collector"],
            source="systemd_collector",
            challenge=challenge,
            public_key=source_public_keys["systemd_collector"],
            reached_artifact=reached_artifact,
            kill_artifact=kill_artifact,
            predecessor_artifacts=final_predecessors,
        ),
    }
    journal_source = source_payloads["journal_collector"]
    expected_observer_fingerprint = str(
        okx_source.get("api_key_fingerprint", "")
    )
    if (
        okx_source.get("journal_readiness_sha256")
        != hashlib.sha256(
            canonical_bytes(journal_readiness_artifact)
        ).hexdigest()
        or not re.fullmatch(
            r"[0-9a-f]{64}", expected_observer_fingerprint
        )
        or expected_observer_fingerprint
        != challenge.get("barrier_recovery_bindings", {}).get(
            "observer_api_key_fingerprint"
        )
        or _iso(
            journal_readiness.get("collected_at"),
            label="journal readiness collected_at",
        )
        > _iso(
            okx_source.get("recovery_started_at"),
            label="OKX recovery started_at",
        )
    ):
        raise ValueError("Stage-C recovery cross-source readiness chain 非法")
    signed_journal_frames = [
        {**frame, "response": journal_source.get("snapshot_response")}
        for frame in journal_source.get("frames", [])
    ]
    if (
        signed_journal_frames != native_bundle["sqlite_snapshot"]
        or source_payloads["okx_collector"].get("frames")
        != native_bundle["okx_demo_https"]
        or source_payloads["okx_collector"].get("stability_frames")
        != native_bundle["okx_stability_https"]
        or source_payloads["systemd_collector"].get("frames")
        != [native_bundle["systemd"]]
        or any(
            payload.get("boundary_proof_sha256")
            != native_bundle["boundary_proof_sha256"]
            for payload in source_payloads.values()
        )
        or min(
            _iso(payload.get("recovery_started_at"), label=f"{source} started")
            for source, payload in source_payloads.items()
        )
        != _iso(
            native_bundle["recovery_started_at"],
            label="native recovery started_at",
        )
        or max(
            _iso(payload.get("collected_at"), label=f"{source} collected")
            for source, payload in source_payloads.items()
        )
        != _iso(native_bundle["collected_at"], label="native collected_at")
    ):
        raise ValueError("Stage-C native recovery source signatures/frames 串线")
    reached = verify_ed25519_artifact(
        reached_artifact,
        reached_public_key,
        label="Stage-C recovery reached artifact",
    )
    killed = verify_ed25519_artifact(
        kill_artifact,
        kill_public_key,
        label="Stage-C recovery kill artifact",
    )
    kill_at = _iso(killed.get("observed_at"), label="kill observed_at")
    recovery_at = _iso(
        native_bundle["recovery_started_at"],
        label="native recovery started_at",
    )
    if (
        native_bundle["schema"] != NATIVE_RECOVERY_SCHEMA
        or native_bundle["scenario"] != challenge["scenario"]
        or native_bundle["challenge_id"] != challenge["challenge_id"]
        or native_bundle["barrier_nonce"] != challenge["barrier_nonce"]
        or native_bundle["artifact_sha256"]
        != challenge["identity"]["artifact_sha256"]
        or recovery_at <= kill_at
    ):
        raise ValueError("Stage-C native recovery 未绑定 challenge/kill")
    readiness_collected_at = _iso(
        journal_readiness.get("collected_at"),
        label="journal readiness collected_at",
    )
    okx_started_at = _iso(
        okx_source.get("recovery_started_at"),
        label="OKX recovery started_at",
    )
    okx_collected_at = _iso(
        okx_source.get("collected_at"),
        label="OKX recovery collected_at",
    )
    if (
        readiness_collected_at <= kill_at
        or okx_started_at < readiness_collected_at
        or _iso(
            journal_source.get("recovery_started_at"),
            label="journal final started_at",
        ) < okx_collected_at
        or _iso(
            source_payloads["systemd_collector"].get("recovery_started_at"),
            label="systemd final started_at",
        ) < okx_collected_at
    ):
        raise ValueError("Stage-C recovery 未满足 ready <= OKX <= final")
    try:
        marker_raw = _decode_opaque_bytes(native_bundle["marker"], "marker")
        proof_raw = _decode_opaque_bytes(
            native_bundle["boundary_proof"],
            "boundary proof",
        )
        marker = json.loads(marker_raw)
        proof = json.loads(proof_raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Stage-C recovery marker/proof JSON 非法") from exc
    if not isinstance(marker, dict):
        raise ValueError("Stage-C recovery marker 非对象")
    marker_without_hash = {
        key: value for key, value in marker.items() if key != "marker_sha256"
    }
    marker_sha256 = hashlib.sha256(
        canonical_bytes(marker_without_hash)
    ).hexdigest()
    proof_sha256 = hashlib.sha256(canonical_bytes(proof)).hexdigest()
    if (
        not isinstance(proof, dict)
        or marker.get("marker_sha256") != marker_sha256
        or marker.get("boundary_proof_sha256") != proof_sha256
        or native_bundle["boundary_proof_sha256"] != proof_sha256
        or reached.get("action") != REACHED_ACTION
        or reached.get("challenge_id") != challenge["challenge_id"]
        or reached.get("scenario") != challenge["scenario"]
        or reached.get("nonce") != challenge["barrier_nonce"]
        or reached.get("artifact_sha256")
        != challenge["identity"]["artifact_sha256"]
        or reached.get("pid")
        != challenge["workloads"]["fault_driver"]["pid"]
        or reached.get("systemd_invocation_id")
        != challenge["workloads"]["fault_driver"][
            "systemd_invocation_id"
        ]
        or reached.get("marker_sha256") != marker_sha256
        or reached.get("boundary_proof_sha256") != proof_sha256
        or killed.get("reached_artifact_sha256")
        != hashlib.sha256(canonical_bytes(reached_artifact)).hexdigest()
        or proof.get("scenario") != challenge["scenario"]
        or proof.get("challenge_id") != challenge["challenge_id"]
        or proof.get("artifact_sha256")
        != challenge["identity"]["artifact_sha256"]
        or proof.get("pid") != challenge["workloads"]["fault_driver"]["pid"]
    ):
        raise ValueError("Stage-C recovery marker/proof 未绑定 challenge")
    systemd, systemd_frame = _systemd_values(
        native_bundle["systemd"],
        after=kill_at,
    )
    new_pid = int(systemd["MainPID"])
    old_pid = challenge["workloads"]["fault_driver"]["pid"]
    if (
        new_pid == old_pid
        or systemd["Id"] != challenge["identity"]["unit"]
        or systemd["ControlGroup"]
        != challenge["workloads"]["fault_driver"]["cgroup"]
    ):
        raise ValueError("Stage-C recovery systemd target 串线")
    sqlite_rows, sqlite_sha256, sqlite_frames = _sqlite_snapshot(
        native_bundle["sqlite_snapshot"],
        after=kill_at,
    )
    readiness_frames = [
        {**frame, "response": journal_readiness.get("snapshot_response")}
        for frame in journal_readiness.get("frames", [])
    ]
    readiness_rows, _readiness_sha256, _readiness_frames = _sqlite_snapshot(
        readiness_frames,
        after=kill_at,
    )
    immutable_labels = {
        "system-mode",
        "duplicate-buy-audit",
        "positions",
        "stage-c-active-protection-by-inst",
        "stage-c-intent-by-clordid",
        "stage-c-probe-by-id",
        "stage-c-risk-by-probe",
        "stage-c-fill-by-trade",
        "stage-c-recovery-checkpoint",
    }
    if any(
        readiness_rows.get(label, []) != sqlite_rows.get(label, [])
        for label in immutable_labels
    ):
        raise ValueError("Stage-C journal readiness 到 final cut 存在中间 mutation")
    checkpoint_rows = sqlite_rows.get("stage-c-recovery-checkpoint", [])
    reconciliation_rows = sqlite_rows.get("reconciliations", [])
    if len(checkpoint_rows) != 1 or len(reconciliation_rows) != 1:
        raise ValueError("Stage-C recovery checkpoint/reconciliation 非唯一")
    try:
        checkpoint = json.loads(str(checkpoint_rows[0]["payload_json"]))
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Stage-C recovery checkpoint payload 非法") from exc
    if (
        not isinstance(checkpoint, dict)
        or checkpoint.get("challenge_id") != challenge["challenge_id"]
        or checkpoint.get("scenario") != challenge["scenario"]
        or checkpoint.get("evidence_hold") is not True
        or int(checkpoint.get("pid", 0)) != new_pid
        or _normalize_id128(
            str(checkpoint.get("systemd_invocation_id", "")),
            label="checkpoint InvocationID",
        )
        != _normalize_id128(systemd["InvocationID"], label="systemd InvocationID")
        or checkpoint.get("reconciliation_run_id")
        != reconciliation_rows[0].get("run_id")
        or datetime.fromtimestamp(
            float(checkpoint_rows[0].get("created_at", 0)), UTC
        ) <= kill_at
        or float(checkpoint.get("reconciliation_completed_at", -1))
        != float(reconciliation_rows[0].get("completed_at", -2))
    ):
        raise ValueError("Stage-C recovery checkpoint 未绑定 final systemd/reconciliation")
    facts = proof.get("facts")
    if not isinstance(facts, dict):
        raise ValueError("Stage-C recovery boundary facts 非法")
    cl_ord_id = str(facts.get("cl_ord_id", ""))
    order_id = str(facts.get("ord_id", ""))
    trade_id = str(facts.get("trade_id", ""))
    expected_queries: dict[str, dict[str, str]] = {
        "account-config": {},
        "pending-orders": {"instType": "SPOT", "instId": "BTC-USDT"},
        "pending-algos": {"ordType": "oco", "instId": "BTC-USDT"},
        "balance": {"ccy": "BTC,USDT"},
    }
    if cl_ord_id or order_id:
        expected_queries["order"] = {"instId": "BTC-USDT"}
        expected_queries["order"]["ordId" if order_id else "clOrdId"] = (
            order_id or cl_ord_id
        )
        expected_queries["fills-history"] = {
            "instType": "SPOT",
            "instId": "BTC-USDT",
            "limit": "100",
        }
        if order_id:
            expected_queries["fills-history"]["ordId"] = order_id
    okx_frames = native_bundle["okx_demo_https"]
    stability_frames = native_bundle["okx_stability_https"]
    recovery_bindings = challenge.get("barrier_recovery_bindings", {})
    expected_tls_certificate_sha256 = (
        recovery_bindings.get("tls_certificate_sha256")
        if challenge["scenario"] == "barrier-post-before-ack"
        else None
    )
    expected_tls_spki_sha256 = (
        recovery_bindings.get("tls_spki_sha256")
        if challenge["scenario"] == "barrier-post-before-ack"
        else None
    )
    if not isinstance(okx_frames, list) or not isinstance(stability_frames, list):
        raise ValueError("Stage-C recovery OKX frames 非法")
    okx_by_label: dict[str, dict] = {}
    okx_rows: dict[str, list[dict]] = {}
    for frame in okx_frames:
        if not isinstance(frame, dict) or not isinstance(frame.get("label"), str):
            raise ValueError("Stage-C recovery OKX frame label 非法")
        label = frame["label"]
        if label in okx_by_label:
            raise ValueError("Stage-C recovery OKX frame 重复")
        okx_by_label[label] = frame
        if label not in expected_queries:
            raise ValueError("Stage-C recovery OKX frame 超出精确查询计划")
        okx_rows[label] = _http_rows(
            frame,
            label=label,
            after=readiness_collected_at,
            expected_query=expected_queries[label],
            expected_api_key_fingerprint=expected_observer_fingerprint,
            expected_tls_certificate_sha256=(
                expected_tls_certificate_sha256
            ),
            expected_tls_spki_sha256=expected_tls_spki_sha256,
        )
    required_okx = set(expected_queries)
    if required_okx != set(okx_by_label):
        raise ValueError("Stage-C recovery OKX common frames 缺失")
    stability_by_label: dict[str, dict] = {}
    stability_rows: dict[str, list[dict]] = {}
    for frame in stability_frames:
        if not isinstance(frame, dict) or not isinstance(frame.get("label"), str):
            raise ValueError("Stage-C recovery OKX stability frame label 非法")
        label = frame["label"]
        if label in stability_by_label or label not in expected_queries:
            raise ValueError("Stage-C recovery OKX stability frame 重复/超出计划")
        stability_by_label[label] = frame
        stability_rows[label] = _http_rows(
            frame,
            label=label,
            after=readiness_collected_at,
            expected_query=expected_queries[label],
            expected_api_key_fingerprint=expected_observer_fingerprint,
            expected_tls_certificate_sha256=(
                expected_tls_certificate_sha256
            ),
            expected_tls_spki_sha256=expected_tls_spki_sha256,
        )
    if (
        required_okx != set(stability_by_label)
        or _okx_semantic_projection(stability_frames)
        != _okx_semantic_projection(okx_frames)
        or any(
            _iso(frame["requested_at"], label="OKX requested_at")
            < readiness_collected_at
            or _iso(frame["completed_at"], label="OKX completed_at")
            > okx_collected_at
            for frame in stability_frames + okx_frames
        )
    ):
        raise ValueError("Stage-C recovery OKX stable double-read/cut 非法")
    account_rows = okx_rows["account-config"]
    if (
        len(account_rows) != 1
        or str(account_rows[0].get("uid", ""))
        != challenge["identity"]["account_uid"]
        or normalize_okx_permissions(account_rows[0].get("perm"))
        != frozenset({"read"})
    ):
        raise ValueError("Stage-C recovery OKX account UID 串线")
    pending_matches = [
        row for row in okx_rows["pending-orders"]
        if str(row.get("clOrdId", "")) == cl_ord_id
        or (order_id and str(row.get("ordId", "")) == order_id)
    ]
    order_matches = [
        row for row in okx_rows.get("order", [])
        if str(row.get("clOrdId", "")) == cl_ord_id
        or (order_id and str(row.get("ordId", "")) == order_id)
    ]
    fill_matches = [
        row for row in okx_rows.get("fills-history", [])
        if str(row.get("clOrdId", "")) == cl_ord_id
        or (order_id and str(row.get("ordId", "")) == order_id)
    ]
    sequence_sha = hashlib.sha256(
        canonical_bytes(native_bundle["okx_demo_https"])
    ).hexdigest()
    sequence_id = f"okx-recovery-sequence:{sequence_sha[:24]}"
    empty_frame = next(iter(okx_by_label.values()))
    pending_query = _core_query(
        okx_by_label["pending-orders"],
        operation="pending",
        rows=_core_order_rows(pending_matches),
        snapshot_id=sequence_id,
    )
    history_query = _core_query(
        okx_by_label.get("order", empty_frame),
        operation="history",
        rows=_core_order_rows(order_matches),
        snapshot_id=sequence_id,
    )
    fills_query = _core_query(
        okx_by_label.get("fills-history", empty_frame),
        operation="fills",
        rows=_core_order_rows(fill_matches, fills=True),
        snapshot_id=sequence_id,
    )
    duplicate_count = len(sqlite_rows.get("duplicate-buy-audit", []))
    position_rows = sqlite_rows.get("positions", [])
    position = next(
        (row for row in position_rows if row.get("inst_id") == "BTC-USDT"),
        None,
    )
    net_qty = Decimal(str(position.get("base_qty", "0"))) if position else Decimal(0)
    resolved_order_id = order_id
    if not resolved_order_id and len(order_matches) == 1:
        resolved_order_id = str(order_matches[0].get("ordId", ""))
    protection = _protection(
        sqlite_rows.get("stage-c-active-protection-by-inst", []),
        pending_algos=okx_rows["pending-algos"],
        net_qty=net_qty,
        inst_id="BTC-USDT",
        order_id=resolved_order_id,
        cl_ord_id=cl_ord_id,
    )
    scenario = challenge["scenario"]
    if scenario == "barrier-buy-intent-before-post":
        probe_rows = sqlite_rows.get("stage-c-probe-by-id", [])
        risk_rows = sqlite_rows.get("stage-c-risk-by-probe", [])
        if len(probe_rows) != 1:
            raise ValueError("before-post recovery 缺少唯一 probe")
        risk_rows = sqlite_rows.get("stage-c-risk-by-probe", [])
        if not risk_rows:
            reservation_outcome = {
                "state": "never_created",
                "reservation_id": None,
                "released_at": None,
            }
        elif len(risk_rows) == 1 and risk_rows[0].get("released_at") is not None:
            released_at = datetime.fromtimestamp(
                float(risk_rows[0]["released_at"]),
                UTC,
            )
            if released_at <= kill_at:
                raise ValueError("before-post reservation 非 recovery 后释放")
            reservation_outcome = {
                "state": "released",
                "reservation_id": str(risk_rows[0].get("reservation_id", "")),
                "released_at": released_at.isoformat(),
            }
        else:
            raise ValueError("before-post reservation 状态不唯一或未释放")
        after = {
            "pending_query": pending_query,
            "history_query": history_query,
            "fills_query": fills_query,
            "buy_post_count": len({
                str(row.get("ordId", ""))
                for row in pending_matches + order_matches + fill_matches
                if str(row.get("ordId", ""))
            }),
            "intent_state": str(probe_rows[0].get("state", "")),
            "reservation_outcome": reservation_outcome,
        }
        before = {
            "cl_ord_id": cl_ord_id,
            "intent_state": facts.get("intent_state"),
            "intent_tx_committed": facts.get("intent_tx_committed"),
            "socket_write_count": facts.get("socket_write_count"),
        }
    elif scenario == "barrier-post-before-ack":
        request_body = json.loads(
            _decode_opaque_bytes(facts["request_body"], "POST request body")
        )
        if not order_matches:
            raise ValueError("post-before-ack recovery 未按 clOrdId 找回订单")
        resolved = order_matches[0]
        if any(
            str(resolved.get(key, "")) != str(request_body.get(payload_key, ""))
            for key, payload_key in (
                ("instId", "instId"),
                ("clOrdId", "clOrdId"),
                ("side", "side"),
                ("ordType", "ordType"),
                ("sz", "sz"),
            )
        ):
            raise ValueError("post-before-ack OKX order 与原始 POST 参数不一致")
        unique_orders = {
            str(row.get("ordId", ""))
            for row in pending_matches + order_matches + fill_matches
            if str(row.get("ordId", ""))
        }
        before = {
            "cl_ord_id": cl_ord_id,
            "intent_tx_committed": True,
            "tls_write": {
                "request_sha256": facts["request_sha256"],
                "bytes_written": facts["bytes_received"],
                "write_completed_at": facts["write_completed_at"],
                "ack_bytes_observed": facts["ack_delivery_started_to_trader"],
            },
            "ack_persisted": False,
            "order_params_sha256": facts["order_params_sha256"],
        }
        after = {
            "pending_query": pending_query,
            "history_query": history_query,
            "fills_query": fills_query,
            "buy_post_count": len(unique_orders),
            "resolved_order": {
                "cl_ord_id": cl_ord_id,
                "ord_id": str(resolved.get("ordId", "")),
                "state": str(resolved.get("state", "")),
                "order_params_sha256": hashlib.sha256(
                    canonical_bytes(request_body)
                ).hexdigest(),
            },
            "duplicate_buy_count": duplicate_count,
            "net_position_qty": str(net_qty),
            "protection": protection,
        }
    else:
        raw_event = json.loads(
            _decode_opaque_bytes(facts["raw_exchange_event"], "fill raw event")
        )
        observed_ms = int(str(raw_event["uTime"]))
        fill_rows = sqlite_rows.get("stage-c-fill-by-trade", [])
        before = {
            "fill": {
                "ord_id": order_id,
                "trade_id": trade_id,
                "qty": str(facts["qty"]),
                "fee": str(facts["fee"]),
                "fee_ccy": str(facts["fee_ccy"]),
                "base_ccy": str(facts["base_ccy"]),
                "observed_at": datetime.fromtimestamp(
                    observed_ms / 1000,
                    UTC,
                ).isoformat(),
                "raw": facts["raw_exchange_event"],
            },
            "projection_apply_count": facts["projection_apply_count"],
            "projection_snapshot_sha256": hashlib.sha256(
                canonical_bytes(facts["projection_rows_before"])
            ).hexdigest(),
        }
        after = {
            "fill_apply_count": len([
                row for row in fill_rows
                if str(row.get("trade_id", "")) == trade_id
                and str(row.get("exchange_ord_id", "")) == order_id
            ]),
            "net_position_qty": str(net_qty),
            "position_snapshot_sha256": hashlib.sha256(
                canonical_bytes(position_rows)
            ).hexdigest(),
            "protection": protection,
        }
    balances: dict[str, str] = {}
    for account in okx_rows["balance"]:
        for detail in account.get("details", []):
            if isinstance(detail, dict) and str(detail.get("ccy", "")):
                balances[str(detail["ccy"])] = str(
                    detail.get("eq", detail.get("cashBal", "0"))
                )
    mode_rows = sqlite_rows.get("system-mode", [])
    runtime_mode = (
        str(mode_rows[0].get("value", "")) if len(mode_rows) == 1 else ""
    )
    collected_at = _iso(native_bundle["collected_at"], label="collected_at")
    if collected_at <= recovery_at:
        raise ValueError("Stage-C recovery final cut 不晚于恢复启动")
    final_common = {
        "snapshot_id": f"sqlite:{sqlite_sha256}",
        "snapshot_sha256": sqlite_sha256,
        "collected_at": collected_at.isoformat(),
        "journal_integrity": (
            str(sqlite_rows.get("integrity", [{}])[0].get("integrity_check", ""))
            if len(sqlite_rows.get("integrity", [])) == 1
            else ""
        ),
        "duplicate_buy_count": duplicate_count,
        "positions": position_rows,
        "pending_orders": okx_rows["pending-orders"],
        "pending_algos": okx_rows["pending-algos"],
        "balances": balances,
        "runtime_mode": runtime_mode,
        "reconciliation": _reconciliation(
            sqlite_rows.get("reconciliations", []),
            after=kill_at,
        ),
    }
    recovery_snapshot_sha256 = hashlib.sha256(
        canonical_bytes(native_bundle)
    ).hexdigest()
    return {
        "schema": "okx-quant.stage-c-barrier-recovery/v1",
        "scenario": scenario,
        "challenge_id": challenge["challenge_id"],
        "artifact_sha256": challenge["identity"]["artifact_sha256"],
        "old_pid": old_pid,
        "new_pid": new_pid,
        "new_systemd_invocation_id": systemd["InvocationID"],
        "recovery_started_at": recovery_at.isoformat(),
        "recovery_snapshot_sha256": recovery_snapshot_sha256,
        "marker_sha256": marker_sha256,
        "boundary_proof_sha256": proof_sha256,
        "reached_artifact_sha256": hashlib.sha256(
            canonical_bytes(reached_artifact)
        ).hexdigest(),
        "before": before,
        "after": after,
        "final_common": final_common,
    }
