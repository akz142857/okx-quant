#!/usr/bin/env python3
"""Acquire and acquirer-attest raw bytes for one Stage-C external role.

The actor report is used only for fixed locators.  This process recomputes the
allow-listed plan, performs native HTTPS/SQLite acquisition, and attests each
envelope with the acquirer key.  A different service/user/key must verify that
proof and sign the final native events.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import make_client
from okx_quant.config import load_yaml
from okx_quant.ops.stage_c_chaos_protocol import (
    acquisition_role_for_source,
    verify_stage_c_challenge,
)
from okx_quant.ops.stage_c_exact_release_drivers import (
    TimedNativeAcquisition,
    attach_live_acquisition_attestation,
    build_live_acquisition_envelope,
)
from okx_quant.ops.stage_c_external_bridge import RAW_COLLECTION_SCHEMA
from okx_quant.ops.stage_c_external_executors import (
    REPORT_SCHEMA,
    ExternalScenarioReport,
    validate_prepared_report_for_source,
)
from okx_quant.ops.stage_c_native_collectors import (
    NativeAcquisition,
    assert_current_process_matches_workload,
    collect_http_native,
    collect_sqlite_snapshot_native,
)

_OKX_GET = {
    "account-config": ("/api/v5/account/config", {}),
    "pending-orders": (
        "/api/v5/trade/orders-pending",
        {"instType": "SPOT"},
    ),
    "pending-algos": (
        "/api/v5/trade/orders-algo-pending",
        {"ordType": "oco"},
    ),
    "fills-history": (
        "/api/v5/trade/fills-history",
        {"instType": "SPOT", "limit": "100"},
    ),
    "order": ("/api/v5/trade/order", {}),
    "algo-history": (
        "/api/v5/trade/orders-algo-history",
        {"ordType": "oco", "state": "canceled"},
    ),
    "algo-order": ("/api/v5/trade/order-algo", {}),
    "balance": ("/api/v5/account/balance", {}),
    "instrument": (
        "/api/v5/public/instruments",
        {"instType": "SPOT"},
    ),
}
_JOURNAL_QUERY_BY_OPERATION = {
    "snapshot:stage-c-system-event": "stage-c-system-event",
    "snapshot:reconciliations": "reconciliations",
    "snapshot:integrity": "integrity",
    "snapshot:duplicate-buy-audit": "duplicate-buy-audit",
    "snapshot:positions": "positions",
    "snapshot:system-mode": "system-mode",
    "snapshot:stage-c-protection-ownership": (
        "stage-c-protection-ownership"
    ),
}


def _json(path: Path, *, label: str) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= 8 * 1024 * 1024
        ):
            raise ValueError(f"{label} 必须是安全普通 JSON 文件")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"{label} 读取发生短读")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"{label} 读取期间增长")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError(f"{label} 读取期间替换/修改")
    finally:
        os.close(descriptor)

    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label} JSON key 重复: {key}")
            value[key] = item
        return value

    value = json.loads(
        b"".join(chunks),
        object_pairs_hook=reject_duplicates,
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是 JSON object")
    return value


def _exclusive_json(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"拒绝覆盖 Stage-C raw collection: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        raw = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode()
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o640,
            dir_fd=parent,
        )
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Stage-C raw collection 短写")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


def _report(value: dict) -> ExternalScenarioReport:
    if value.get("schema") != REPORT_SCHEMA:
        raise ValueError("Stage-C actor report schema 非法")
    if set(value) != set(ExternalScenarioReport.__dataclass_fields__):
        raise ValueError("Stage-C actor report fields 非法")
    report = ExternalScenarioReport(**value)
    validate_prepared_report_for_source(report)
    return report


def _timed(callable_, /, *args, **kwargs) -> TimedNativeAcquisition:
    requested = datetime.now(UTC)
    requested_monotonic = time.monotonic_ns()
    acquisition = callable_(*args, **kwargs)
    completed = datetime.now(UTC)
    completed_monotonic = time.monotonic_ns()
    return TimedNativeAcquisition(
        acquisition=acquisition,
        requested_at=requested.isoformat(),
        response_completed_at=completed.isoformat(),
        requested_monotonic_ns=requested_monotonic,
        response_completed_monotonic_ns=completed_monotonic,
    )


def _okx_acquisition(
    *,
    client,
    operation: str,
    parameters: dict,
) -> NativeAcquisition:
    try:
        path, fixed = _OKX_GET[operation]
    except KeyError as exc:
        raise ValueError("Stage-C OKX operation 不在 fixed GET allow-list") from exc
    params = dict(fixed)
    if operation in {"pending-orders", "pending-algos", "fills-history"}:
        params["instId"] = str(parameters["inst_id"])
        if operation == "pending-algos" and parameters.get("algo_id"):
            params["algoId"] = str(parameters["algo_id"])
        if operation == "fills-history":
            params["ordId"] = str(parameters["ord_id"])
    elif operation == "order":
        params.update({
            "instId": str(parameters["inst_id"]),
            "clOrdId": str(parameters["cl_ord_id"]),
        })
    elif operation == "algo-history":
        params.update({
            "instId": str(parameters["inst_id"]),
            "algoId": str(parameters["algo_id"]),
        })
    elif operation == "algo-order":
        params["algoClOrdId"] = str(parameters["algo_cl_ord_id"])
    elif operation == "balance":
        params["ccy"] = str(parameters["ccy"])
    elif operation == "instrument":
        params["instId"] = str(parameters["inst_id"])
    query = urllib.parse.urlencode(sorted(params.items()))
    target = f"{path}?{query}" if query else path
    headers = client._auth_headers("GET", target)  # noqa: SLF001
    headers["x-simulated-trading"] = "1"
    acquired = collect_http_native(
        source="okx_collector",
        method="GET",
        url=f"{client.base_url}{target}",
        headers=headers,
        timeout=min(float(client.timeout), 15),
    )
    return NativeAcquisition(
        source=acquired.source,
        operation=operation,
        request_bytes=acquired.request_bytes,
        response_bytes=acquired.response_bytes,
        returncode=acquired.returncode,
    )


def _resolved_order_id(
    acquisition: NativeAcquisition,
    *,
    inst_id: str,
    cl_ord_id: str,
) -> str:
    """Resolve the fill locator from the exact clOrdId order response."""
    try:
        _headers, body = acquisition.response_bytes.split(b"\r\n\r\n", 1)
        document = json.loads(body)
        if not isinstance(document, dict):
            raise ValueError("OKX response 必须是 object")
        rows = document["data"]
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Stage-C order locator HTTP response 非法") from exc
    matching = [
        row
        for row in rows
        if isinstance(row, dict)
        and str(row.get("instId", "")) == inst_id
        and str(row.get("clOrdId", "")).upper() == cl_ord_id.upper()
        and str(row.get("ordId", "")).strip()
    ] if isinstance(rows, list) else []
    if document.get("code") != "0" or len(matching) != 1:
        raise ValueError("Stage-C order locator 未唯一绑定 instId/clOrdId")
    return str(matching[0]["ordId"])


def _okx_request_acquisitions(*, client, request) -> list[TimedNativeAcquisition]:
    """Collect a fixed request, resolving fills by the exact owned order."""
    collected: list[TimedNativeAcquisition] = []
    parameters = dict(request.parameters)
    for operation in request.operations:
        if operation == "fills-history" and "ord_id" not in parameters:
            raise ValueError("fills-history 缺少 challenge-owned ordId locator")
        timed = _timed(
            _okx_acquisition,
            client=client,
            operation=operation,
            parameters=parameters,
        )
        collected.append(timed)
        if operation == "order":
            parameters["ord_id"] = _resolved_order_id(
                timed.acquisition,
                inst_id=str(parameters["inst_id"]),
                cl_ord_id=str(parameters["cl_ord_id"]),
            )
    return collected


def _journal_snapshot(
    *,
    report: ExternalScenarioReport,
    requests: tuple,
    database: Path,
) -> dict[tuple[str, tuple[str, ...]], NativeAcquisition]:
    query_requests = []
    for request in requests:
        operation = request.operations[0]
        query_name = _JOURNAL_QUERY_BY_OPERATION.get(operation)
        if query_name is None or len(request.operations) != 1:
            raise ValueError("Stage-C journal source plan operation 非法")
        if query_name == "stage-c-system-event":
            parameters = (
                str(request.parameters["event_name"]),
                report.challenge_id,
            )
        elif query_name == "stage-c-protection-ownership":
            parameters = (
                str(request.parameters["parent_cl_ord_id"]),
                str(request.parameters["algo_cl_ord_id"]),
                str(request.parameters["algo_id"]),
            )
        else:
            parameters = ()
        query_requests.append((query_name, parameters))
    return collect_sqlite_snapshot_native(
        database=database,
        query_requests=tuple(query_requests),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--role",
        required=True,
        choices=("okx_collector", "journal_collector"),
    )
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--challenge", required=True, type=Path)
    parser.add_argument(
        "--registrar-public-key",
        required=True,
        type=Path,
    )
    parser.add_argument("--acquirer-private-key", required=True, type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--input-wait-seconds", type=float, default=0)
    parser.add_argument("--start-after", type=Path)
    args = parser.parse_args()

    if not 0 <= args.input_wait_seconds <= 600:
        raise ValueError("Stage-C source input wait 必须位于 0..600 秒")
    deadline = time.monotonic() + args.input_wait_seconds
    while not all(
        path.is_file() and not path.is_symlink()
        for path in (args.report, args.challenge)
    ):
        if time.monotonic() >= deadline:
            raise TimeoutError("Stage-C source challenge/report 未就绪")
        time.sleep(0.1)
    while (
        args.start_after is not None
        and not (
            args.start_after.is_file()
            and not args.start_after.is_symlink()
        )
    ):
        if time.monotonic() >= deadline:
            raise TimeoutError("Stage-C source driver-ready marker 未就绪")
        time.sleep(0.1)

    report = _report(_json(args.report, label="Stage-C actor report"))
    challenge = verify_stage_c_challenge(
        _json(args.challenge, label="Stage-C registrar challenge"),
        registrar_public_key=args.registrar_public_key,
        scenario=report.scenario,
        now=None,
        enforce_current_window=True,
    )
    if (
        challenge["challenge_id"] != report.challenge_id
        or challenge["identity"]["account_uid"] != report.account_uid
    ):
        raise ValueError("Stage-C source report 未绑定 verified challenge")
    acquisition_role = acquisition_role_for_source(args.role)
    assert_current_process_matches_workload(
        challenge["workloads"][acquisition_role]
    )
    requests = tuple(
        request
        for request in validate_prepared_report_for_source(report)
        if request.source_role == args.role
    )
    envelopes = []
    if args.role == "okx_collector":
        if args.config is None or args.journal is not None:
            raise ValueError("OKX source 必须且只能提供 --config")
        cfg = load_yaml(str(args.config))
        okx = cfg.get("okx", {})
        if (
            not isinstance(okx, dict)
            or okx.get("simulated") is not True
            or not all(
                str(okx.get(name, "")).strip()
                for name in ("api_key", "secret_key", "passphrase")
            )
        ):
            raise ValueError("OKX source 要求独立 Demo read credentials")
        client = make_client(cfg)
        for request in requests:
            acquisitions = _okx_request_acquisitions(
                client=client,
                request=request,
            )
            envelope = build_live_acquisition_envelope(
                scenario=report.scenario,
                kind=request.kind,
                acquisitions=acquisitions,
            )
            envelopes.append({
                "kind": request.kind,
                "envelope": attach_live_acquisition_attestation(
                    scenario=report.scenario,
                    kind=request.kind,
                    challenge=challenge,
                    envelope=envelope,
                    acquirer_private_key=args.acquirer_private_key,
                ),
            })
    else:
        if args.journal is None or args.config is not None:
            raise ValueError("journal source 必须且只能提供 --journal")
        snapshot = _journal_snapshot(
            report=report,
            requests=requests,
            database=args.journal,
        )
        for request in requests:
            query_name = _JOURNAL_QUERY_BY_OPERATION[
                request.operations[0]
            ]
            if query_name == "stage-c-system-event":
                parameters = (
                    str(request.parameters["event_name"]),
                    report.challenge_id,
                )
            elif query_name == "stage-c-protection-ownership":
                parameters = (
                    str(request.parameters["parent_cl_ord_id"]),
                    str(request.parameters["algo_cl_ord_id"]),
                    str(request.parameters["algo_id"]),
                )
            else:
                parameters = ()
            acquisition = snapshot[(query_name, parameters)]
            requested = datetime.now(UTC)
            requested_monotonic = time.monotonic_ns()
            completed = datetime.now(UTC)
            completed_monotonic = time.monotonic_ns()
            envelope = build_live_acquisition_envelope(
                scenario=report.scenario,
                kind=request.kind,
                acquisitions=[
                    TimedNativeAcquisition(
                        acquisition=acquisition,
                        requested_at=requested.isoformat(),
                        response_completed_at=completed.isoformat(),
                        requested_monotonic_ns=requested_monotonic,
                        response_completed_monotonic_ns=(
                            completed_monotonic
                        ),
                    )
                ],
            )
            envelopes.append({
                "kind": request.kind,
                "envelope": attach_live_acquisition_attestation(
                    scenario=report.scenario,
                    kind=request.kind,
                    challenge=challenge,
                    envelope=envelope,
                    acquirer_private_key=args.acquirer_private_key,
                ),
            })
    _exclusive_json(
        args.output,
        {
            "schema": RAW_COLLECTION_SCHEMA,
            "scenario": report.scenario,
            "challenge_id": report.challenge_id,
            "account_uid": report.account_uid,
            "source_role": args.role,
            "collector_workload_role": acquisition_role,
            "contains_acquirer_attestations": True,
            "contains_signed_events": False,
            "facts_supplied_by_actor": False,
            "envelopes": envelopes,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
