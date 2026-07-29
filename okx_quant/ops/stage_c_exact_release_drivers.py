"""Exact-release Stage-C black-box drivers and raw-byte parsers.

Production events created here never contain caller supplied ``facts``.  Each
event signs one or more native acquisition frames (HTTPS, SQLite, systemd,
chrony, or an allow-listed fault controller).  The admission parser verifies
the source signature and deterministically derives the event facts again from
the signed request/response bytes.

The ten recipes are executable capabilities.  A recipe run is still external
evidence: it must execute against the frozen demo deployment and its resulting
JSONL must survive the independent Stage-C/WORM verification chain.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import sqlite3
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_DOWN, Decimal, InvalidOperation
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
    NATIVE_EVENT_ACTION,
    PARSER_MANIFEST_SHA256,
    RAW_EVENT_SCHEMA,
    SCENARIO_PROTOCOLS,
    _expected_source,
    _native_bytes_descriptor,
    _opaque_bytes_descriptor,
    acquisition_role_for_source,
    validate_workload_attestation,
)
from okx_quant.ops.stage_c_external_executors import stable_client_order_id
from okx_quant.ops.stage_c_native_collectors import (
    _SQLITE_QUERIES,
    NativeAcquisition,
)

LIVE_ACQUISITION_SCHEMA = "okx-quant.stage-c-live-acquisition/v1"
LIVE_ACQUISITION_ATTESTATION_ACTION = (
    "attest-stage-c-live-acquisition-v1"
)
_LIVE_ACQUISITION_ATTESTATION_KEYS = {
    "version",
    "action",
    "scenario",
    "challenge_id",
    "kind",
    "source",
    "acquisition_role",
    "workload_binding_sha256",
    "envelope_sha256",
}
EXACT_RELEASE_SCENARIOS = frozenset(
    scenario
    for scenario, spec in SCENARIO_PROTOCOLS.items()
    if spec.artifact_class == "exact_release_black_box"
)

# These are action identifiers, not arbitrary commands.  The live environment
# has one implementation per identifier and never accepts argv/SQL/URLs from
# the challenge or the caller.
SCENARIO_ACTION_ALLOWLIST: dict[str, tuple[str, ...]] = {
    "ws-partial-fill-recovery": (
        "okx-place-partial-fill-order",
        "proxy-block-private",
        "proxy-unblock-private",
    ),
    "external-pending-buy": (
        "okx-place-external-limit-buy",
        "runtime-reconcile-now",
        "okx-cancel-created-order",
    ),
    "external-fill": (
        "okx-place-external-market-buy",
        "runtime-reconcile-now",
    ),
    "external-protection-cancel": (
        "okx-cancel-live-protection",
        "runtime-reconcile-now",
    ),
    "frozen-balance": (
        "okx-place-locking-limit-order",
        "runtime-reconcile-now",
        "okx-cancel-created-order",
    ),
    "clordid-conflict": (
        "okx-place-reserved-clordid-order",
        "runtime-demo-probe-with-reserved-clordid",
        "runtime-reconcile-now",
        "okx-cancel-created-order",
    ),
    "rest-5xx-429-unknown": (
        "rest-proxy-arm-ambiguous-write",
        "runtime-demo-probe",
        "rest-proxy-disarm",
        "runtime-reconcile-now",
    ),
    "oco-active-process-death": (
        "systemd-sigkill",
    ),
    "restart-while-ws-down": (
        "proxy-block-business",
        "systemd-restart",
        "proxy-unblock-business",
    ),
    "backup-db-corruption": (
        "offline-copy-corrupt-database",
        "systemd-start-corrupt-copy",
        "restore-exact-version-to-copy",
        "systemd-restart-restored-copy",
    ),
}

if set(SCENARIO_ACTION_ALLOWLIST) != set(EXACT_RELEASE_SCENARIOS):
    raise RuntimeError("Stage-C exact-release action inventory 不完整")

_LIVE_ENVELOPE_KEYS = {
    "schema",
    "scenario",
    "kind",
    "requested_at",
    "response_completed_at",
    "requested_monotonic_ns",
    "response_completed_monotonic_ns",
    "acquisitions",
    "bindings",
}
_FRAME_KEYS = {
    "primitive",
    "source",
    "operation",
    "request",
    "response",
    "returncode",
}
_SYSTEMD_FIELDS = {
    "Id",
    "ActiveState",
    "SubState",
    "InvocationID",
    "MainPID",
    "ControlGroup",
    "ExecMainStartTimestampMonotonic",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SOURCE_PRIMITIVE = {
    "systemd_collector": "systemd-dbus",
    "clock_collector": "chrony-process",
    "journal_collector": "sqlite-backup-api",
    "provider": "https-tls",
    "okx_collector": "https-tls",
    "fault_controller": "allowlisted-control-file",
    "restore_verifier": "https-tls-exact-version",
}

_COMMON_OPERATION_ALLOWLIST = {
    "driver.invoked": ("show-runtime",),
    "clock.sample": ("chrony-tracking",),
    "reconciliation.completed": ("snapshot:reconciliations",),
    "page.provider_receipt": ("provider-receipt",),
    "journal.integrity": ("snapshot:integrity",),
    "journal.duplicate_buy_audit": (
        "snapshot:duplicate-buy-audit",
    ),
    "journal.positions": ("snapshot:positions",),
    "journal.protection_ownership": (
        "snapshot:stage-c-protection-ownership",
    ),
    "exchange.pending_orders": (
        "pending-orders",
        "account-config",
    ),
    "exchange.pending_algos": (
        "pending-algos",
        "account-config",
    ),
    "exchange.balances": ("balance", "account-config"),
    "runtime.mode": ("snapshot:system-mode",),
    "startup.reconciliation": ("snapshot:reconciliations",),
    "run.completed": ("show-runtime",),
}
_SCENARIO_OPERATION_ALLOWLIST = {
    "ws-partial-fill-recovery": {
        "exchange.order.partial": ("order", "account-config"),
        "gateway.disconnected": ("proxy-block",),
        "exchange.order.cumulative_fill": (
            "order",
            "fills-history",
            "account-config",
        ),
        "gateway.rest_baseline.completed": (
            "snapshot:stage-c-system-event",
        ),
        "exchange.protection.active": (
            "pending-algos",
            "account-config",
        ),
    },
    "external-pending-buy": {
        "exchange.order.external_pending": (
            "order",
            "account-config",
        ),
        "runtime.entry_frozen": ("snapshot:stage-c-system-event",),
    },
    "external-fill": {
        "exchange.fill.external": (
            "order",
            "fills-history",
            "account-config",
        ),
        "exchange.protection.active": (
            "algo-order",
            "order",
            "instrument",
            "account-config",
        ),
    },
    "external-protection-cancel": {
        "exchange.protection.canceled": (
            "algo-order",
            "order",
            "account-config",
        ),
        "runtime.emergency_exit": (
            "snapshot:stage-c-system-event",
        ),
    },
    "frozen-balance": {
        "exchange.balance.frozen": (
            "balance",
            "order",
            "account-config",
        ),
        "journal.position_preserved": (
            "snapshot:stage-c-system-event",
        ),
    },
    "clordid-conflict": {
        "exchange.clordid_conflict": ("order", "account-config"),
        "runtime.manual_review": ("snapshot:stage-c-system-event",),
    },
    "rest-5xx-429-unknown": {
        "proxy.ambiguous_write": ("tls-socket-write-trace",),
        "journal.intent_unknown": ("snapshot:stage-c-system-event",),
        "journal.intent_resolved": ("snapshot:stage-c-system-event",),
    },
    "oco-active-process-death": {
        "exchange.protection.before_process_death": (
            "pending-algos",
            "account-config",
        ),
        "systemd.process_killed": (
            "systemd-sigkill",
            "show-after-kill",
        ),
        "exchange.protection.after_process_death": (
            "pending-algos",
            "account-config",
        ),
        "runtime.restart_reconciled": (
            "snapshot:stage-c-system-event",
        ),
    },
    "restart-while-ws-down": {
        "gateway.fault_control.blocked": ("proxy-block",),
        "systemd.restart_requested": (
            "systemd-restart",
            "show-after-restart",
        ),
        "runtime.not_ready": ("snapshot:stage-c-system-event",),
        "gateway.rest_baseline.completed": (
            "snapshot:stage-c-system-event",
        ),
    },
    "backup-db-corruption": {
        "journal.corruption_detected": (
            "snapshot:stage-c-system-event",
        ),
        "runtime.halted": ("snapshot:stage-c-system-event",),
        "backup.exact_version_restored": (
            "restore-exact-version",
        ),
        "runtime.ready_after_restore": (
            "snapshot:stage-c-system-event",
        ),
    },
}


@dataclass(frozen=True)
class TimedNativeAcquisition:
    """One native acquisition plus wall-clock timing measured by the driver."""

    acquisition: NativeAcquisition
    requested_at: str
    response_completed_at: str
    requested_monotonic_ns: int
    response_completed_monotonic_ns: int


def capture_native_acquisition(callable_, /, *args, **kwargs) -> TimedNativeAcquisition:
    """Time one collector invocation without permitting precomputed bytes."""
    requested = datetime.now(UTC)
    requested_monotonic = time.monotonic_ns()
    acquisition = callable_(*args, **kwargs)
    completed = datetime.now(UTC)
    completed_monotonic = time.monotonic_ns()
    if not isinstance(acquisition, NativeAcquisition):
        raise TypeError("Stage-C collector 未返回 NativeAcquisition")
    return TimedNativeAcquisition(
        acquisition=acquisition,
        requested_at=requested.isoformat(),
        response_completed_at=completed.isoformat(),
        requested_monotonic_ns=requested_monotonic,
        response_completed_monotonic_ns=completed_monotonic,
    )


def _iso(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是带时区 ISO-8601")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} 非法") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} 必须带时区")
    return parsed.astimezone(UTC)


def _decode_opaque(value: object, label: str) -> bytes:
    if not isinstance(value, dict) or set(value) != {
        "encoding",
        "sha256",
        "bytes",
        "payload_base64",
    }:
        raise ValueError(f"{label} raw descriptor schema 非法")
    if (
        value["encoding"] != "base64"
        or not _SHA256.fullmatch(str(value["sha256"]))
        or type(value["bytes"]) is not int
        or not 0 < value["bytes"] <= 16 * 1024 * 1024
        or not isinstance(value["payload_base64"], str)
    ):
        raise ValueError(f"{label} raw descriptor 非法")
    try:
        raw = base64.b64decode(value["payload_base64"], validate=True)
    except ValueError as exc:
        raise ValueError(f"{label} base64 非法") from exc
    if (
        len(raw) != value["bytes"]
        or hashlib.sha256(raw).hexdigest() != value["sha256"]
    ):
        raise ValueError(f"{label} raw bytes/hash 不一致")
    return raw


def build_live_acquisition_envelope(
    *,
    scenario: str,
    kind: str,
    acquisitions: list[TimedNativeAcquisition],
    bindings: dict | None = None,
) -> dict:
    """Freeze native bytes and timings; no derived fact field is accepted."""
    if (
        scenario not in EXACT_RELEASE_SCENARIOS
        or not acquisitions
        or len(acquisitions) > 4
        or kind == "challenge.accepted"
    ):
        raise ValueError("Stage-C live acquisition scenario/kind 非法")
    expected_source = _expected_source(scenario, kind)
    requested = min(
        _iso(item.requested_at, "acquisition requested_at")
        for item in acquisitions
    )
    completed = max(
        _iso(item.response_completed_at, "acquisition completed_at")
        for item in acquisitions
    )
    requested_monotonic = min(
        item.requested_monotonic_ns for item in acquisitions
    )
    completed_monotonic = max(
        item.response_completed_monotonic_ns for item in acquisitions
    )
    if (
        requested > completed
        or (completed - requested).total_seconds() > 30
        or type(requested_monotonic) is not int
        or type(completed_monotonic) is not int
        or requested_monotonic < 0
        or completed_monotonic <= requested_monotonic
    ):
        raise ValueError("Stage-C live acquisition 时间窗非法")
    frames = []
    for item in acquisitions:
        acquisition = item.acquisition
        if (
            acquisition.source != expected_source
            or acquisition.returncode != 0
            or not acquisition.operation
            or not acquisition.request_bytes
            or not acquisition.response_bytes
        ):
            raise ValueError("Stage-C live acquisition source/结果非法")
        frame_requested = _iso(item.requested_at, "frame requested_at")
        frame_completed = _iso(
            item.response_completed_at,
            "frame response_completed_at",
        )
        if (
            frame_requested > frame_completed
            or frame_requested < requested
            or frame_completed > completed
            or type(item.requested_monotonic_ns) is not int
            or type(item.response_completed_monotonic_ns) is not int
            or item.requested_monotonic_ns < requested_monotonic
            or item.response_completed_monotonic_ns > completed_monotonic
            or item.response_completed_monotonic_ns
            <= item.requested_monotonic_ns
        ):
            raise ValueError("Stage-C live acquisition frame 时间非法")
        frames.append({
            "primitive": _SOURCE_PRIMITIVE[acquisition.source],
            "source": acquisition.source,
            "operation": acquisition.operation,
            "request": _opaque_bytes_descriptor(acquisition.request_bytes),
            "response": _opaque_bytes_descriptor(acquisition.response_bytes),
            "returncode": acquisition.returncode,
        })
    return {
        "schema": LIVE_ACQUISITION_SCHEMA,
        "scenario": scenario,
        "kind": kind,
        "requested_at": requested.isoformat(),
        "response_completed_at": completed.isoformat(),
        "requested_monotonic_ns": requested_monotonic,
        "response_completed_monotonic_ns": completed_monotonic,
        "acquisitions": frames,
        "bindings": dict(bindings or {}),
    }


def is_live_acquisition_envelope(value: object) -> bool:
    return isinstance(value, dict) and value.get("schema") == (
        LIVE_ACQUISITION_SCHEMA
    )


def _parse_http(raw: bytes, label: str) -> tuple[int, dict[str, str], object]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator or len(raw) > 16 * 1024 * 1024:
        raise ValueError(f"{label} HTTP response framing 非法")
    try:
        lines = head.decode("iso-8859-1").split("\r\n")
        status_parts = lines[0].split(" ", 2)
        status = int(status_parts[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            key, colon, value = line.partition(":")
            if not colon or key.lower() in headers:
                raise ValueError
            headers[key.lower()] = value.strip()
        document = json.loads(body)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, IndexError) as exc:
        raise ValueError(f"{label} HTTP/JSON response 非法") from exc
    if not 100 <= status <= 599:
        raise ValueError(f"{label} HTTP status 非法")
    return status, headers, document


def _parse_http_request(
    raw: bytes,
    label: str,
) -> tuple[str, str, dict[str, str], bytes]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError(f"{label} HTTP request framing 非法")
    lines = head.split(b"\r\n")
    line = lines[0]
    try:
        method, target, protocol = line.decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{label} HTTP request line 非法") from exc
    if method not in {"GET", "POST"} or protocol != "HTTP/1.1":
        raise ValueError(f"{label} HTTP request method/protocol 非法")
    parsed = urllib.parse.urlsplit(target)
    if not parsed.path.startswith("/"):
        raise ValueError(f"{label} HTTP request target 非法")
    headers: dict[str, str] = {}
    try:
        for raw_header in lines[1:]:
            key, separator, value = raw_header.decode(
                "iso-8859-1"
            ).partition(":")
            lowered = key.lower()
            if not separator or not lowered or lowered in headers:
                raise ValueError
            headers[lowered] = value.strip()
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{label} HTTP request headers 非法") from exc
    return method, target, headers, body


def _okx_rows(frame: dict, label: str) -> list[dict]:
    status, _headers, document = _parse_http(
        frame["response_raw"],
        label,
    )
    if (
        status != 200
        or not isinstance(document, dict)
        or str(document.get("code")) != "0"
        or not isinstance(document.get("data"), list)
        or any(not isinstance(row, dict) for row in document["data"])
    ):
        raise ValueError(f"{label} OKX response 未成功")
    return document["data"]


def _validate_tls_frame(
    frame: dict,
    *,
    label: str,
    allowed_hosts: frozenset[str],
    require_request_id: bool,
) -> tuple[str, str, dict[str, str], bytes]:
    method, target, request_headers, body = _parse_http_request(
        frame["request_raw"],
        label,
    )
    _status, response_headers, _document = _parse_http(
        frame["response_raw"],
        label,
    )
    host = request_headers.get("host", "").lower()
    required_transport = {
        "x-stage-c-peer-address",
        "x-stage-c-peer-port",
        "x-stage-c-tls-version",
        "x-stage-c-tls-cipher",
        "x-stage-c-peer-cert-sha256",
        "x-stage-c-peer-spki-sha256",
    }
    if (
        host not in allowed_hosts
        or not required_transport <= set(response_headers)
        or not all(
            _SHA256.fullmatch(response_headers[key])
            for key in {
                "x-stage-c-peer-cert-sha256",
                "x-stage-c-peer-spki-sha256",
            }
        )
        or not response_headers["x-stage-c-peer-port"].isdigit()
        or not 1 <= int(response_headers["x-stage-c-peer-port"]) <= 65535
        or (
            require_request_id
            and not (
                response_headers.get("ok-trace-id")
                or response_headers.get("x-request-id")
            )
        )
    ):
        raise ValueError(f"{label} TLS peer/request-id evidence 非法")
    return method, target, request_headers, body


_OKX_PATH_BY_OPERATION = {
    "account-config": ("/api/v5/account/config", frozenset()),
    "pending-orders": (
        "/api/v5/trade/orders-pending",
        frozenset({"instType", "instId"}),
    ),
    "pending-algos": (
        "/api/v5/trade/orders-algo-pending",
        frozenset({"ordType", "instId", "algoId"}),
    ),
    "order": (
        "/api/v5/trade/order",
        frozenset({"instId", "ordId", "clOrdId"}),
    ),
    "fills-history": (
        "/api/v5/trade/fills-history",
        frozenset({"instType", "instId", "ordId", "limit"}),
    ),
    "algo-history": (
        "/api/v5/trade/orders-algo-history",
        frozenset({"ordType", "state", "instId", "algoId"}),
    ),
    "algo-order": (
        "/api/v5/trade/order-algo",
        frozenset({"algoClOrdId"}),
    ),
    "balance": (
        "/api/v5/account/balance",
        frozenset({"ccy"}),
    ),
    "instrument": (
        "/api/v5/public/instruments",
        frozenset({"instType", "instId"}),
    ),
}


def _valid_exact_okx_query(operation: str, query: dict[str, list[str]]) -> bool:
    scalar = {key: values[0] for key, values in query.items()}
    keys = set(scalar)
    if operation == "account-config":
        return not keys
    if operation == "pending-orders":
        return keys == {"instType", "instId"} and scalar["instType"] == "SPOT"
    if operation == "pending-algos":
        return (
            keys in ({"ordType", "instId"}, {"ordType", "instId", "algoId"})
            and scalar["ordType"] == "oco"
        )
    if operation == "order":
        return keys == {"instId", "clOrdId"}
    if operation == "fills-history":
        return scalar.get("instType") == "SPOT" and scalar.get("limit") == "100" and keys == {
            "instType", "instId", "ordId", "limit"
        }
    if operation == "algo-history":
        return (
            keys == {"ordType", "state", "instId", "algoId"}
            and scalar["ordType"] == "oco"
            and scalar["state"] == "canceled"
        )
    if operation == "algo-order":
        return keys == {"algoClOrdId"}
    if operation == "balance":
        return keys == {"ccy"}
    if operation == "instrument":
        return (
            keys == {"instType", "instId"}
            and scalar["instType"] == "SPOT"
        )
    return False


def _validate_okx_frames(
    frames: list[dict],
    *,
    challenge: dict,
    label: str,
) -> None:
    if frames[-1]["operation"] != "account-config":
        raise ValueError(f"{label} 缺少同 challenge OKX account config")
    observer_bindings = challenge.get("okx_observer_bindings")
    if not isinstance(observer_bindings, dict) or set(observer_bindings) != {
        "observer_api_key_fingerprint",
        "tls_certificate_sha256",
        "tls_spki_sha256",
    }:
        raise ValueError(f"{label} 缺少预注册 OKX observer/TLS binding")
    api_key_fingerprints: set[str] = set()
    for frame in frames:
        expected = _OKX_PATH_BY_OPERATION.get(frame["operation"])
        if expected is None:
            raise ValueError(f"{label} OKX operation 未注册")
        method, target, request_headers, body = _validate_tls_frame(
            frame,
            label=f"{label}/{frame['operation']}",
            allowed_hosts=frozenset({"www.okx.com", "openapi.okx.com"}),
            require_request_id=True,
        )
        parsed = urllib.parse.urlsplit(target)
        query = urllib.parse.parse_qs(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
        ) if parsed.query else {}
        api_key_fingerprint = request_headers.get(
            "x-stage-c-api-key-fingerprint",
            "",
        )
        _status, response_headers, _document = _parse_http(
            frame["response_raw"],
            f"{label}/{frame['operation']}",
        )
        if (
            method != "GET"
            or body
            or parsed.path != expected[0]
            or not set(query) <= expected[1]
            or any(
                len(values) != 1 or not values[0]
                for values in query.values()
            )
            or not _SHA256.fullmatch(api_key_fingerprint)
            or request_headers.get("x-simulated-trading") != "1"
            or api_key_fingerprint
            != observer_bindings["observer_api_key_fingerprint"]
            or response_headers.get("x-stage-c-peer-cert-sha256")
            != observer_bindings["tls_certificate_sha256"]
            or response_headers.get("x-stage-c-peer-spki-sha256")
            != observer_bindings["tls_spki_sha256"]
            or not _valid_exact_okx_query(frame["operation"], query)
        ):
            raise ValueError(
                f"{label}/{frame['operation']} OKX request 未精确绑定"
            )
        api_key_fingerprints.add(api_key_fingerprint)
    if len(api_key_fingerprints) != 1:
        raise ValueError(f"{label} OKX frames 禁止混用不同 API key")
    config = _one_row(
        _okx_rows(frames[-1], f"{label}/account-config"),
        f"{label}/account-config",
    )
    if str(config.get("uid", "")) != challenge["identity"]["account_uid"]:
        raise ValueError(f"{label} OKX account UID 未绑定 release identity")


def _one_row(rows: list[dict], label: str) -> dict:
    if len(rows) != 1:
        raise ValueError(f"{label} 要求恰好一行")
    return rows[0]


def _okx_query(frame: dict, label: str) -> dict[str, str]:
    _method, target, _headers, _body = _parse_http_request(
        frame["request_raw"],
        label,
    )
    parsed = urllib.parse.urlsplit(target)
    values = urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True,
        strict_parsing=True,
    ) if parsed.query else {}
    if any(len(items) != 1 or not items[0] for items in values.values()):
        raise ValueError(f"{label} OKX query 非法")
    return {key: items[0] for key, items in values.items()}


def _require_query_bindings(
    frame: dict,
    *,
    label: str,
    required: dict[str, str],
) -> dict[str, str]:
    query = _okx_query(frame, label)
    if any(query.get(key) != value for key, value in required.items()):
        raise ValueError(f"{label} OKX query locator 未精确绑定")
    return query


def _external_order_row(
    frame: dict,
    *,
    scenario: str,
    challenge: dict,
    label: str,
) -> tuple[dict, str]:
    expected_cl_ord_id = stable_client_order_id(
        scenario=scenario,
        challenge_id=challenge["challenge_id"],
        purpose="fault",
    )
    query = _okx_query(frame, label)
    if (
        set(query) != {"instId", "clOrdId"}
        or query["clOrdId"].upper() != expected_cl_ord_id
    ):
        raise ValueError(f"{label} 未查询 exact challenge clOrdId")
    matches = [
        row
        for row in _okx_rows(frame, label)
        if str(row.get("instId", "")) == query["instId"]
        and str(row.get("clOrdId", "")).upper() == expected_cl_ord_id
        and str(row.get("ordId", "")).strip()
    ]
    return _one_row(matches, f"{label}/owned-order"), query["instId"]


def _sqlite_rows(frame: dict, label: str) -> tuple[list[str], list[list]]:
    try:
        request = json.loads(frame["request_raw"])
        response = json.loads(frame["response_raw"])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} SQLite raw JSON 非法") from exc
    if request.get("schema") == (
        "okx-quant.stage-c-sqlite-snapshot-request/v1"
    ):
        if (
            set(request) != {
                "schema",
                "query_name",
                "parameters",
                "snapshot_sha256",
                "snapshot_response_sha256",
            }
            or not _SHA256.fullmatch(str(request["snapshot_sha256"]))
            or request["snapshot_response_sha256"]
            != hashlib.sha256(frame["response_raw"]).hexdigest()
            or not isinstance(response, dict)
            or set(response)
            != {"schema", "live_database", "snapshot", "results"}
            or response["schema"]
            != "okx-quant.stage-c-sqlite-snapshot/v1"
            or not isinstance(response["live_database"], dict)
            or not isinstance(response["snapshot"], dict)
            or not isinstance(response["results"], list)
            or response["snapshot"].get("database_sha256")
            != request["snapshot_sha256"]
            or response["snapshot"].get("quick_check") != "ok"
            or response["snapshot"].get("journal_mode")
            not in {"wal", "delete", "truncate", "persist"}
        ):
            raise ValueError(f"{label} SQLite snapshot schema/hash 非法")
        matches = [
            result
            for result in response["results"]
            if isinstance(result, dict)
            and result.get("query_name") == request["query_name"]
            and result.get("parameters") == request["parameters"]
        ]
        result = _one_row(matches, f"{label} snapshot result")
        if (
            set(result)
            != {
                "query_name",
                "parameters",
                "query_sha256",
                "columns",
                "rows",
            }
            or not _SHA256.fullmatch(str(result["query_sha256"]))
        ):
            raise ValueError(f"{label} SQLite snapshot result 非法")
        snapshot_raw = _decode_opaque(
            response["snapshot"].get("database_bytes"),
            f"{label} SQLite snapshot bytes",
        )
        if hashlib.sha256(snapshot_raw).hexdigest() != (
            request["snapshot_sha256"]
        ):
            raise ValueError(f"{label} SQLite snapshot bytes 未绑定")
        query = _SQLITE_QUERIES.get(request["query_name"])
        if (
            query is None
            or hashlib.sha256(query.encode()).hexdigest()
            != result["query_sha256"]
        ):
            raise ValueError(f"{label} SQLite fixed query hash 不一致")
        # A WAL-mode database cannot be queried reliably after
        # ``Connection.deserialize`` because SQLite attempts to open a WAL
        # beside the in-memory pseudo-path.  Verify the exact captured bytes
        # through a private immutable file instead.
        with tempfile.NamedTemporaryFile(
            prefix="okx-stage-c-verify-",
            suffix=".sqlite",
        ) as snapshot_file:
            snapshot_file.write(snapshot_raw)
            snapshot_file.flush()
            verifier = sqlite3.connect(
                f"file:{snapshot_file.name}?mode=ro&immutable=1",
                uri=True,
            )
            verifier.row_factory = sqlite3.Row
            try:
                verified_rows = verifier.execute(
                    query,
                    tuple(request["parameters"]),
                ).fetchall()
                verified_columns = (
                    list(verified_rows[0].keys()) if verified_rows else []
                )
                verified_values = [list(row) for row in verified_rows]
            finally:
                verifier.close()
        if (
            verified_columns != result["columns"]
            or verified_values != result["rows"]
        ):
            raise ValueError(
                f"{label} SQLite rows 无法从 snapshot bytes 重算"
            )
        frame["sqlite_request"] = request
        frame["sqlite_snapshot_sha256"] = request["snapshot_sha256"]
        columns = result["columns"]
        rows = result["rows"]
    else:
        if (
            not isinstance(request, dict)
            or set(request) != {
                "database",
                "database_sha256",
                "query_name",
                "query_sha256",
                "parameters",
            }
            or not _SHA256.fullmatch(str(request["database_sha256"]))
            or not _SHA256.fullmatch(str(request["query_sha256"]))
            or not isinstance(response, dict)
            or set(response) != {"columns", "rows"}
        ):
            raise ValueError(f"{label} SQLite request/response schema 非法")
        frame["sqlite_request"] = request
        columns = response["columns"]
        rows = response["rows"]
    if (
        not isinstance(columns, list)
        or not isinstance(rows, list)
        or any(
            not isinstance(row, list) or len(row) != len(columns)
            for row in rows
        )
    ):
        raise ValueError(f"{label} SQLite rows 非法")
    return columns, rows


def _row_objects(frame: dict, label: str) -> list[dict]:
    columns, rows = _sqlite_rows(frame, label)
    if (
        any(not isinstance(column, str) or not column for column in columns)
        or len(set(columns)) != len(columns)
    ):
        raise ValueError(f"{label} SQLite columns 非法")
    return [dict(zip(columns, row, strict=True)) for row in rows]


def _systemd_values(frame: dict, label: str) -> dict[str, str]:
    try:
        text = frame["response_raw"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} systemd response 非 UTF-8") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            if key in values:
                raise ValueError(f"{label} systemd property 重复")
            values[key] = value
    if set(values) != _SYSTEMD_FIELDS:
        raise ValueError(f"{label} systemd properties 不完整")
    return values


def _decimal(value: object, label: str, *, positive: bool = False) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"{label} decimal 非法")
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"{label} decimal 非法") from exc
    if not parsed.is_finite() or (positive and parsed <= 0):
        raise ValueError(f"{label} decimal 非法")
    return format(parsed, "f")


def _system_event(frame: dict, *, kind: str, challenge_id: str) -> dict:
    rows = _row_objects(frame, kind)
    row = _one_row(rows, kind)
    request = frame["sqlite_request"]
    if (
        request["query_name"] != "stage-c-system-event"
        or request["parameters"] != [kind, challenge_id]
        or row.get("event_name") != kind
        or row.get("correlation_id") != challenge_id
    ):
        raise ValueError(f"{kind} SQLite event 未绑定 challenge")
    try:
        payload = json.loads(row["payload_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{kind} payload_json 非法") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{kind} payload 必须是 object")
    return payload


def _protection_ownership(frame: dict) -> dict:
    rows = _row_objects(frame, "journal.protection_ownership")
    row = _one_row(rows, "journal.protection_ownership")
    request = frame["sqlite_request"]
    expected_parameters = [
        str(row.get("parent_cl_ord_id", "")),
        str(row.get("algo_cl_ord_id", "")),
        str(row.get("exchange_algo_id", "")),
    ]
    if (
        request["query_name"] != "stage-c-protection-ownership"
        or request["parameters"] != expected_parameters
        or str(row.get("parent_side", "")).lower() != "buy"
        or not all(expected_parameters)
        or not str(row.get("parent_exchange_ord_id", "")).strip()
        or not str(row.get("parent_intent_id", "")).strip()
    ):
        raise ValueError("journal protection ownership 未唯一绑定查询")
    return {
        "parent_intent_id": str(row["parent_intent_id"]),
        "parent_cl_ord_id": str(row["parent_cl_ord_id"]),
        "parent_ord_id": str(row["parent_exchange_ord_id"]),
        "inst_id": str(row["inst_id"]),
        "algo_cl_ord_id": str(row["algo_cl_ord_id"]),
        "algo_id": str(row["exchange_algo_id"]),
        "protected_qty": _decimal(
            row["protected_qty"],
            "journal protected qty",
            positive=True,
        ),
        "state": str(row["state"]),
        "updated_at": row["updated_at"],
        "snapshot_sha256": request.get(
            "snapshot_sha256",
            request.get("database_sha256"),
        ),
    }


def _parse_frames(envelope: dict, expected_source: str) -> list[dict]:
    frames = envelope["acquisitions"]
    if not isinstance(frames, list) or not 1 <= len(frames) <= 4:
        raise ValueError("Stage-C live acquisition frames 非法")
    parsed = []
    for frame in frames:
        if not isinstance(frame, dict) or set(frame) != _FRAME_KEYS:
            raise ValueError("Stage-C live acquisition frame schema 非法")
        if (
            frame["primitive"] != _SOURCE_PRIMITIVE.get(expected_source)
            or
            frame["source"] != expected_source
            or type(frame["returncode"]) is not int
            or frame["returncode"] != 0
            or not isinstance(frame["operation"], str)
            or not frame["operation"]
        ):
            raise ValueError("Stage-C live acquisition frame source/result 非法")
        parsed.append({
            **frame,
            "request_raw": _decode_opaque(
                frame["request"],
                "Stage-C live request",
            ),
            "response_raw": _decode_opaque(
                frame["response"],
                "Stage-C live response",
            ),
        })
    return parsed


def _validate_operation_allowlist(
    *,
    scenario: str,
    kind: str,
    frames: list[dict],
) -> None:
    expected = _COMMON_OPERATION_ALLOWLIST.get(kind)
    if expected is None:
        expected = _SCENARIO_OPERATION_ALLOWLIST.get(
            scenario,
            {},
        ).get(kind)
    actual = tuple(frame["operation"] for frame in frames)
    if expected is None or actual != expected:
        raise ValueError(
            f"Stage-C {scenario}/{kind} acquisition operation 非 allow-list: "
            f"expected={expected}, actual={actual}"
        )


def _validate_systemd_workload(values: dict[str, str], workload: dict) -> None:
    try:
        pid = int(values["MainPID"])
    except ValueError as exc:
        raise ValueError("Stage-C systemd MainPID 非法") from exc
    expected_unit = workload["cgroup"].removeprefix("/system.slice/")
    if (
        values["Id"] != expected_unit
        or values["InvocationID"].lower()
        != workload["systemd_invocation_id"].replace("-", "").lower()
        or pid != workload["pid"]
        or values["ControlGroup"] != workload["cgroup"]
        or values["ActiveState"] != "active"
        or values["SubState"] not in {"running", "start-post"}
    ):
        raise ValueError("Stage-C systemd live snapshot 未绑定 frozen workload")


def _journal_common(kind: str, frame: dict) -> dict:
    rows = _row_objects(frame, kind)
    request = frame["sqlite_request"]
    expected_query = {
        "reconciliation.completed": "reconciliations",
        "journal.integrity": "integrity",
        "journal.duplicate_buy_audit": "duplicate-buy-audit",
        "journal.positions": "positions",
        "runtime.mode": "system-mode",
        "startup.reconciliation": "reconciliations",
    }[kind]
    if request["query_name"] != expected_query or request["parameters"]:
        raise ValueError(f"{kind} SQLite query 不符合固定 adapter")
    if kind == "reconciliation.completed":
        row = _one_row(rows, kind)
        try:
            details = json.loads(row["details_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("reconciliation details_json 非法") from exc
        unresolved = details.get("unresolved", [])
        return {
            "run_id": row["run_id"],
            "status": row["status"],
            "mismatch_count": row["mismatch_count"],
            "repaired_count": row["repaired_count"],
            "unresolved": unresolved,
        }
    if kind == "journal.integrity":
        result = _one_row(rows, kind)
        value = next(iter(result.values()))
        return {
            "result": value,
            "database_sha256": request.get(
                "snapshot_sha256",
                request.get("database_sha256"),
            ),
        }
    if kind == "journal.duplicate_buy_audit":
        return {
            "count": len(rows),
            "intent_ids": [str(row["intent_id"]) for row in rows],
        }
    if kind == "journal.positions":
        positions = []
        for row in rows:
            quantity = _decimal(row["base_qty"], "position base_qty")
            if Decimal(quantity) <= 0:
                continue
            state = str(
                row["latest_protection_state"]
                or row["protection_status"]
            )
            positions.append({
                "inst_id": row["inst_id"],
                "base_qty": quantity,
                "protection_state": state,
            })
        return {"positions": positions}
    if kind == "runtime.mode":
        row = _one_row(rows, kind)
        if row != {"key": "mode", "value": row.get("value")}:
            raise ValueError("runtime.mode SQLite row 非法")
        return {"mode": row["value"]}
    row = _one_row(rows, kind)
    started = float(row["started_at"])
    completed = float(row["completed_at"])
    if (
        not math.isfinite(started)
        or not math.isfinite(completed)
        or completed < started
    ):
        raise ValueError("startup reconciliation timestamps 非法")
    return {"seconds": completed - started}


def _exchange_common(
    kind: str,
    frames: list[dict],
    challenge: dict,
) -> dict:
    _validate_okx_frames(
        frames,
        challenge=challenge,
        label=kind,
    )
    rows = _okx_rows(frames[0], kind)
    if kind == "exchange.pending_orders":
        query = _okx_query(frames[0], kind)
        inst_id = query.get("instId", "")
        if not inst_id or any(
            str(row.get("instId", "")) != inst_id for row in rows
        ):
            raise ValueError("pending orders 未严格绑定 instId")
        return {
            "order_ids": [
                str(row["ordId"]) for row in rows if str(row.get("ordId", ""))
            ]
        }
    if kind == "exchange.pending_algos":
        query = _okx_query(frames[0], kind)
        inst_id = query.get("instId", "")
        if not inst_id or any(
            str(row.get("instId", "")) != inst_id for row in rows
        ):
            raise ValueError("pending algos 未严格绑定 instId")
        return {
            "algo_ids": [
                str(row["algoId"]) for row in rows
                if str(row.get("algoId", ""))
            ]
        }
    balances: dict[str, str] = {}
    for account in rows:
        details = account.get("details", [])
        if not isinstance(details, list):
            raise ValueError("OKX balance details 非法")
        for row in details:
            ccy = str(row.get("ccy", ""))
            if ccy:
                balances[ccy] = _decimal(
                    row.get("eq", row.get("cashBal", "0")),
                    f"balance {ccy}",
                )
    return {"balances": balances}


def _exchange_scenario(
    scenario: str,
    kind: str,
    frames: list[dict],
    challenge: dict,
) -> dict:
    _validate_okx_frames(
        frames,
        challenge=challenge,
        label=kind,
    )
    rows = _okx_rows(frames[0], kind)
    if (
        kind == "exchange.protection.active"
        and scenario == "external-fill"
    ) or kind == "exchange.protection.canceled":
        locator = _okx_query(frames[0], f"{kind}/algo")
        rows = [
            item
            for item in rows
            if str(item.get("algoClOrdId", ""))
            == locator.get("algoClOrdId")
        ]
    row = _one_row(rows, kind)
    if kind == "exchange.order.partial":
        return {
            "ord_id": row["ordId"],
            "cl_ord_id": row["clOrdId"],
            "acc_fill_qty": _decimal(row["accFillSz"], kind, positive=True),
            "state": row["state"],
        }
    if kind == "exchange.order.cumulative_fill":
        trade_rows = (
            _okx_rows(frames[1], f"{kind}/fills")
            if len(frames) == 2
            else []
        )
        return {
            "ord_id": row["ordId"],
            "acc_fill_qty": _decimal(row["accFillSz"], kind, positive=True),
            "trade_ids": [
                str(item["tradeId"])
                for item in trade_rows
                if str(item.get("ordId", "")) == str(row["ordId"])
                and str(item.get("tradeId", ""))
            ],
        }
    if kind in {
        "exchange.protection.active",
        "exchange.protection.before_process_death",
        "exchange.protection.after_process_death",
    }:
        if kind == "exchange.protection.active" and scenario == "external-fill":
            order, inst_id = _external_order_row(
                frames[1],
                scenario=scenario,
                challenge=challenge,
                label=f"{kind}/order",
            )
            algo_id = str(row.get("algoId", ""))
            _require_query_bindings(
                frames[0],
                label=f"{kind}/algo",
                required={
                    "algoClOrdId": str(row.get("algoClOrdId", "")),
                },
            )
            instrument_query = _require_query_bindings(
                frames[2],
                label=f"{kind}/instrument",
                required={"instType": "SPOT", "instId": inst_id},
            )
            instrument = _one_row(
                _okx_rows(frames[2], f"{kind}/instrument"),
                f"{kind}/instrument",
            )
            lot = Decimal(_decimal(instrument.get("lotSz"), kind, positive=True))
            base_ccy = inst_id.split("-", 1)[0]
            position_qty = Decimal(
                _decimal(order.get("accFillSz"), kind, positive=True)
            )
            if str(order.get("feeCcy", "")).upper() == base_ccy:
                position_qty += Decimal(_decimal(order.get("fee", "0"), kind))
            protected_qty = Decimal(_decimal(row.get("sz"), kind, positive=True))
            expected_protected = (
                (position_qty / lot).to_integral_value(rounding=ROUND_DOWN)
                * lot
            )
            if (
                not algo_id
                or str(row.get("instId", "")) != inst_id
                or not str(row.get("algoClOrdId", "")).isalnum()
                or str(row.get("ordType", "")).lower() != "oco"
                or str(row.get("side", "")).lower() != "sell"
                or str(row.get("tdMode", "")).lower() != "cash"
                or instrument_query["instId"] != str(
                    instrument.get("instId", "")
                )
                or expected_protected <= 0
                or protected_qty != expected_protected
            ):
                raise ValueError("external protection 未绑定 challenge order")
        result = {
            "algo_id": row["algoId"],
            "state": row["state"],
        }
        if kind == "exchange.protection.active":
            result.update({
                "protected_qty": _decimal(row["sz"], kind, positive=True),
            })
            if scenario == "external-fill":
                result.update({
                    "inst_id": inst_id,
                    "algo_cl_ord_id": str(row["algoClOrdId"]),
                    "position_qty": format(position_qty, "f"),
                    "lot_size": format(lot, "f"),
                })
            else:
                result["ord_id"] = row.get(
                    "ordId",
                    row.get("attachAlgoOrds", [{}])[0].get("ordId", ""),
                )
        elif kind.endswith("after_process_death"):
            result["verified_by"] = "okx_rest"
        return result
    if kind == "exchange.order.external_pending":
        row, _inst_id = _external_order_row(
            frames[0],
            scenario=scenario,
            challenge=challenge,
            label=kind,
        )
        if (
            str(row.get("side", "")).lower() != "buy"
            or str(row.get("state", "")).lower()
            not in {"live", "partially_filled"}
        ):
            raise ValueError("external pending order contract 非法")
        return {
            "ord_id": row["ordId"],
            "cl_ord_id": row["clOrdId"],
            "side": row["side"],
            "state": row["state"],
            "origin": "external",
        }
    if kind == "exchange.fill.external":
        order, inst_id = _external_order_row(
            frames[0],
            scenario=scenario,
            challenge=challenge,
            label=f"{kind}/order",
        )
        cl_ord_id = str(order["clOrdId"])
        ord_id = str(order["ordId"])
        _require_query_bindings(
            frames[1],
            label=f"{kind}/fills",
            required={"instId": inst_id, "ordId": ord_id},
        )
        matching_fills = [
            item
            for item in _okx_rows(frames[1], f"{kind}/fills")
            if str(item.get("instId", "")) == inst_id
            and str(item.get("ordId", "")) == ord_id
            and str(item.get("clOrdId", "")).upper()
            == cl_ord_id.upper()
            and str(item.get("tradeId", "")).strip()
        ]
        if not matching_fills:
            raise ValueError(f"{kind}/owned-fill 要求至少一行")
        trade_ids = [str(item["tradeId"]) for item in matching_fills]
        gross_fill = sum(
            (
                Decimal(_decimal(item.get("fillSz"), kind, positive=True))
                for item in matching_fills
            ),
            Decimal("0"),
        )
        base_ccy = inst_id.split("-", 1)[0]
        net_fill = Decimal(
            _decimal(order.get("accFillSz"), kind, positive=True)
        )
        if str(order.get("feeCcy", "")).upper() == base_ccy:
            net_fill += Decimal(_decimal(order.get("fee", "0"), kind))
        if (
            str(order.get("side", "")).lower() != "buy"
            or str(order.get("state", "")).lower() != "filled"
            or any(
                str(item.get("side", "")).lower() != "buy"
                for item in matching_fills
            )
            or len(set(trade_ids)) != len(trade_ids)
            or gross_fill
            != Decimal(_decimal(order.get("accFillSz"), kind, positive=True))
            or net_fill <= 0
        ):
            raise ValueError("external fill order contract 非法")
        return {
            "ord_id": ord_id,
            "cl_ord_id": cl_ord_id,
            "inst_id": inst_id,
            "trade_ids": trade_ids,
            "side": "buy",
            "qty": format(net_fill, "f"),
            "origin": "external",
        }
    if kind == "exchange.protection.canceled":
        order, inst_id = _external_order_row(
            frames[1],
            scenario=scenario,
            challenge=challenge,
            label=f"{kind}/order",
        )
        algo_id = str(row.get("algoId", ""))
        _require_query_bindings(
            frames[0],
            label=f"{kind}/algo",
            required={
                "algoClOrdId": str(row.get("algoClOrdId", "")),
            },
        )
        if (
            not algo_id
            or str(row.get("instId", "")) != inst_id
            or not str(row.get("algoClOrdId", "")).isalnum()
            or str(row.get("ordType", "")).lower() != "oco"
            or str(row.get("side", "")).lower() != "sell"
            or str(row.get("tdMode", "")).lower() != "cash"
        ):
            raise ValueError("canceled protection 未绑定 challenge order")
        return {
            "algo_id": row["algoId"],
            "algo_cl_ord_id": row["algoClOrdId"],
            "inst_id": inst_id,
            "observed_order_id": str(order["ordId"]),
            "observed_cl_ord_id": str(order["clOrdId"]),
            "state": row["state"],
            "origin": "external",
        }
    if kind == "exchange.balance.frozen":
        order, inst_id = _external_order_row(
            frames[1],
            scenario=scenario,
            challenge=challenge,
            label=f"{kind}/order",
        )
        base_ccy = inst_id.split("-", 1)[0]
        _require_query_bindings(
            frames[0],
            label=f"{kind}/balance",
            required={"ccy": base_ccy},
        )
        if (
            str(order.get("side", "")).lower() != "sell"
            or str(order.get("state", "")).lower()
            not in {"live", "partially_filled"}
        ):
            raise ValueError("frozen balance locking order contract 非法")
        details = row.get("details", [])
        if not isinstance(details, list):
            raise ValueError("frozen balance details 非法")
        frozen = [
            item for item in details
            if str(item.get("ccy", "")).upper() == base_ccy
            and Decimal(_decimal(item.get("frozenBal", "0"), kind)) > 0
        ]
        item = _one_row(frozen, kind)
        remaining = Decimal(
            _decimal(order.get("sz", "0"), kind, positive=True)
        ) - Decimal(_decimal(order.get("accFillSz", "0"), kind))
        frozen_quantity = Decimal(_decimal(item["frozenBal"], kind))
        if remaining <= 0 or frozen_quantity < remaining:
            raise ValueError("frozen balance 未精确归属于 challenge locking order")
        return {
            "inst_id": inst_id,
            "ccy": item["ccy"],
            # Project only the challenge-owned locked slice.  Returning the
            # account-wide eq/avail values would silently attribute pre-existing
            # holdings (or unrelated frozen orders) to this challenge.
            "total": format(remaining, "f"),
            "available": "0",
            "locking_order_ids": [str(order["ordId"])],
        }
    if kind == "exchange.clordid_conflict":
        expected_prefix = f"SC{challenge['challenge_id'][:16]}".upper()
        if not str(row.get("clOrdId", "")).upper().startswith(expected_prefix):
            raise ValueError("clOrdId conflict 未绑定 challenge")
        # The current core event contract expects local_intent_id inside an
        # OKX-signed event.  Accepting a SQLite frame under the OKX source key
        # would be a cross-role laundering bug.  Keep this scenario OPEN until
        # the core protocol adds a separately signed journal event.
        raise ValueError(
            "clOrdId conflict 需要独立 journal signer 事件；"
            "禁止在 OKX source envelope 混入 local_intent_id"
        )
    raise ValueError(f"{scenario}/{kind} 尚无 OKX raw adapter")


def derive_live_native_facts(
    envelope: object,
    *,
    scenario: str,
    kind: str,
    challenge: dict,
    workload: dict,
    observed_at: str,
) -> dict:
    """Recompute one event payload solely from signed acquisition bytes."""
    if not isinstance(envelope, dict) or set(envelope) != _LIVE_ENVELOPE_KEYS:
        raise ValueError("Stage-C live acquisition envelope schema 非法")
    expected_source = _expected_source(scenario, kind)
    requested = _iso(envelope["requested_at"], "live requested_at")
    completed = _iso(
        envelope["response_completed_at"],
        "live response_completed_at",
    )
    requested_monotonic = envelope["requested_monotonic_ns"]
    completed_monotonic = envelope["response_completed_monotonic_ns"]
    observed = _iso(observed_at, "live event observed_at")
    if (
        envelope["schema"] != LIVE_ACQUISITION_SCHEMA
        or envelope["scenario"] != scenario
        or envelope["kind"] != kind
        or not isinstance(envelope["bindings"], dict)
        or requested > completed
        or type(requested_monotonic) is not int
        or type(completed_monotonic) is not int
        or requested_monotonic < 0
        or completed_monotonic <= requested_monotonic
        or abs(
            (completed - requested).total_seconds()
            - (completed_monotonic - requested_monotonic) / 1_000_000_000
        )
        > 1
        or completed > observed
        or (observed - completed).total_seconds() > 2
        or (completed - requested).total_seconds() > 30
        or requested.timestamp() < challenge["not_before"]
        or completed.timestamp() > challenge["expires_at"]
    ):
        raise ValueError("Stage-C live acquisition identity/freshness 非法")
    frames = _parse_frames(envelope, expected_source)
    _validate_operation_allowlist(
        scenario=scenario,
        kind=kind,
        frames=frames,
    )
    if kind == "driver.invoked":
        if set(envelope["bindings"]) != {"capability_attestation"}:
            raise ValueError("driver invocation bindings 非法")
        values = _systemd_values(frames[0], kind)
        driver_workload = challenge["workloads"]["fault_driver"]
        _validate_systemd_workload(values, driver_workload)
        capability = envelope["bindings"]["capability_attestation"]
        if (
            hashlib.sha256(canonical_bytes(capability)).hexdigest()
            != challenge["capability_attestation_sha256"]
            or driver_workload["parser_manifest_sha256"]
            != PARSER_MANIFEST_SHA256
        ):
            raise ValueError("driver invocation capability/parser 未绑定")
        return {
            "driver_id": SCENARIO_PROTOCOLS[scenario].driver_id,
            "workload": driver_workload,
            "driver_contract_sha256": challenge[
                "driver_contract_sha256"
            ],
            "capability_attestation": capability,
        }
    if envelope["bindings"]:
        raise ValueError(f"{kind} 不允许 caller bindings")
    if kind == "run.completed":
        values = _systemd_values(frames[0], kind)
        _validate_systemd_workload(
            values,
            challenge["workloads"]["fault_driver"],
        )
        return {"outcome": "completed"}
    if kind == "clock.sample":
        try:
            fields = frames[0]["response_raw"].decode().strip().split(",")
            system_time = abs(float(fields[3]))
            root_dispersion = abs(float(fields[11]))
            leap = fields[13].strip().lower()
        except (UnicodeDecodeError, ValueError, IndexError) as exc:
            raise ValueError("chrony tracking raw response 非法") from exc
        max_error_ms = (system_time + root_dispersion) * 1000
        return {
            "ntp_synchronized": leap in {"normal", "0"},
            "max_error_ms": max_error_ms,
        }
    if kind in {
        "reconciliation.completed",
        "journal.integrity",
        "journal.duplicate_buy_audit",
        "journal.positions",
        "runtime.mode",
        "startup.reconciliation",
    }:
        return _journal_common(kind, frames[0])
    if kind == "journal.protection_ownership":
        return _protection_ownership(frames[0])
    if kind in {
        "exchange.pending_orders",
        "exchange.pending_algos",
        "exchange.balances",
    }:
        return _exchange_common(kind, frames, challenge)
    if kind == "page.provider_receipt":
        _method, _target, request_headers, _body = _parse_http_request(
            frames[0]["request_raw"],
            kind,
        )
        _validate_tls_frame(
            frames[0],
            label=kind,
            allowed_hosts=frozenset({
                request_headers.get("host", "").lower(),
            }),
            require_request_id=True,
        )
        status, _headers, document = _parse_http(
            frames[0]["response_raw"],
            kind,
        )
        artifact = (
            document.get("artifact")
            if isinstance(document, dict)
            else None
        )
        claims = (
            artifact.get("payload")
            if isinstance(artifact, dict)
            else None
        )
        if (
            status != 200
            or not isinstance(document, dict)
            or set(document) != {"artifact"}
            or not isinstance(claims, dict)
            or claims.get("challenge_id") != challenge["challenge_id"]
            or claims.get("fault_correlation") != scenario
            or claims.get("event_name") != "page.stage_c_fault"
        ):
            raise ValueError("provider receipt raw response 非法")
        return {"artifact": artifact}
    if expected_source == "okx_collector":
        return _exchange_scenario(
            scenario,
            kind,
            frames,
            challenge,
        )
    if expected_source == "journal_collector":
        return _system_event(
            frames[0],
            kind=kind,
            challenge_id=challenge["challenge_id"],
        )
    if expected_source == "fault_controller":
        if kind == "proxy.ambiguous_write":
            raise ValueError(
                "ambiguous write 必须由 trader_http_collector 的同 fd/TLS "
                "socket write trace 证明；当前 core source contract 不支持"
            )
        try:
            request = json.loads(frames[0]["request_raw"])
            response = json.loads(frames[0]["response_raw"])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"{kind} fault response 非法") from exc
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise ValueError(f"{kind} fault response schema 非法")
        if (
            request.get("action") not in {"proxy-block", "proxy-unblock"}
            or response.get("action") != request.get("action")
            or response.get("actor_invocation_id")
            != workload["systemd_invocation_id"]
            or type(response.get("control_inode")) is not int
            or response["control_inode"] <= 0
            or response.get("readback_verified") is not True
        ):
            raise ValueError(f"{kind} fault action/readback 未绑定")
        if kind == "gateway.disconnected":
            return {
                "channel": response["channel"],
                "generation": response["generation"],
            }
        if kind == "gateway.fault_control.blocked":
            return {
                "channel": response["channel"],
                "state": response["state"],
                "control_inode": response["control_inode"],
            }
        raise ValueError(f"{kind} fault adapter 未实现")
    if expected_source == "systemd_collector":
        driver_workload = challenge["workloads"]["fault_driver"]
        try:
            request = json.loads(frames[0]["request_raw"])
            response = json.loads(frames[0]["response_raw"])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"{kind} systemd fault raw JSON 非法") from exc
        if (
            not isinstance(request, dict)
            or not isinstance(response, dict)
            or request.get("unit")
            != driver_workload["cgroup"].removeprefix("/system.slice/")
            or request.get("action")
            not in {"systemd-sigkill", "systemd-restart"}
            or response.get("returncode") != 0
            or len(frames) != 2
        ):
            raise ValueError(f"{kind} systemd fault raw schema 非法")
        after = _systemd_values(frames[1], f"{kind}/after")
        try:
            after_pid = int(after["MainPID"])
        except ValueError as exc:
            raise ValueError(f"{kind} after MainPID 非法") from exc
        if (
            after["Id"]
            != driver_workload["cgroup"].removeprefix("/system.slice/")
            or after["ControlGroup"] != driver_workload["cgroup"]
            or after["ActiveState"] != "active"
            or after_pid <= 1
            or after_pid == driver_workload["pid"]
            or after["InvocationID"].replace("-", "").lower()
            == driver_workload["systemd_invocation_id"].replace("-", "").lower()
        ):
            raise ValueError(
                f"{kind} 未证明旧进程死亡及新 InvocationID/PID"
            )
        if kind == "systemd.process_killed":
            if request["action"] != "systemd-sigkill":
                raise ValueError("process_killed 未由 SIGKILL action 产生")
            return {
                "old_pid": driver_workload["pid"],
                "signal": "SIGKILL",
                "systemd_invocation_id": driver_workload[
                    "systemd_invocation_id"
                ],
            }
        if kind == "systemd.restart_requested":
            if request["action"] != "systemd-restart":
                raise ValueError("restart_requested action 非法")
            return {
                "old_pid": driver_workload["pid"],
                "systemd_invocation_id": driver_workload[
                    "systemd_invocation_id"
                ],
            }
        raise ValueError(f"{kind} systemd adapter 未实现")
    if expected_source == "restore_verifier":
        raise ValueError(
            "backup restore 需要 S3 archive+manifest 双对象 exact-version "
            "GET、KMS/ObjectLock headers 与恢复 DB bytes 重算；"
            "当前单帧 restore contract 保持 OPEN"
        )
    raise ValueError(f"{scenario}/{kind} live raw adapter 未实现")


def _native_locator(
    *,
    source: str,
    kind: str,
    workload: dict,
    envelope: dict,
) -> dict:
    frame = _parse_frames(envelope, source)[0]
    if source == "okx_collector":
        method, target, _headers, _body = _parse_http_request(
            frame["request_raw"],
            kind,
        )
        status, headers, _document = _parse_http(frame["response_raw"], kind)
        return {
            "method": method,
            "path": target,
            "http_status": status,
            "response_headers_sha256": hashlib.sha256(
                canonical_bytes(headers)
            ).hexdigest(),
        }
    if source == "journal_collector":
        _sqlite_rows(frame, kind)
        request = frame["sqlite_request"]
        if request.get("schema") == (
            "okx-quant.stage-c-sqlite-snapshot-request/v1"
        ):
            query_sha256 = hashlib.sha256(
                _SQLITE_QUERIES[request["query_name"]].encode()
            ).hexdigest()
            database_sha256 = request["snapshot_sha256"]
        else:
            query_sha256 = request["query_sha256"]
            database_sha256 = request["database_sha256"]
        return {
            "database_sha256": database_sha256,
            "query_sha256": query_sha256,
            "snapshot_txid": (
                "sqlite-snapshot:"
                + hashlib.sha256(
                    frame["request_raw"] + b"\0" + frame["response_raw"]
                ).hexdigest()[:24]
            ),
        }
    if source == "systemd_collector":
        values = _systemd_values(frame, kind)
        return {
            "unit": values["Id"],
            "systemd_invocation_id": values["InvocationID"].lower(),
            "pid": int(values["MainPID"]),
            "cgroup": values["ControlGroup"],
        }
    if source == "clock_collector":
        return {
            "tracking_output_sha256": hashlib.sha256(
                frame["response_raw"]
            ).hexdigest()
        }
    if source == "fault_controller":
        try:
            response = json.loads(frame["response_raw"])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("fault locator raw response 非法") from exc
        return {
            "control_inode": int(response["control_inode"]),
            "actor_invocation_id": workload["systemd_invocation_id"],
        }
    if source == "provider":
        _method, target, _headers, _body = _parse_http_request(
            frame["request_raw"],
            kind,
        )
        return {
            "provider_request_id": "provider:"
            + hashlib.sha256(
                frame["request_raw"] + frame["response_raw"]
            ).hexdigest()[:24],
            "endpoint_sha256": hashlib.sha256(target.encode()).hexdigest(),
        }
    if source == "restore_verifier":
        try:
            request = json.loads(frame["request_raw"])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("restore locator request 非法") from exc
        return {
            "object_uri": request["object_uri"],
            "version_id": request["version_id"],
        }
    raise ValueError(f"{source} 尚无 live locator")


def attach_live_acquisition_attestation(
    *,
    scenario: str,
    kind: str,
    challenge: dict,
    envelope: dict,
    acquirer_private_key: Path,
) -> dict:
    """Bind native bytes to an independent acquirer workload and key."""
    source = _expected_source(scenario, kind)
    role = acquisition_role_for_source(source)
    if (
        not is_live_acquisition_envelope(envelope)
        or envelope["scenario"] != scenario
        or envelope["kind"] != kind
        or "acquisition_attestation" in envelope["bindings"]
    ):
        raise ValueError("Stage-C acquisition envelope identity 非法")
    try:
        workload = challenge["workloads"][role]
        expected_fingerprint = challenge["source_key_fingerprints"][role]
    except (KeyError, TypeError) as exc:
        raise ValueError("Stage-C challenge 缺少独立 acquirer role") from exc
    validate_workload_attestation(workload)
    if (
        ed25519_public_key_fingerprint(
            acquirer_private_key,
            private_key=True,
        )
        != expected_fingerprint
    ):
        raise ValueError("Stage-C acquirer private key 未绑定 challenge")
    unsigned_envelope = {
        **envelope,
        "bindings": dict(envelope["bindings"]),
    }
    artifact = sign_ed25519_payload(
        {
            "version": 1,
            "action": LIVE_ACQUISITION_ATTESTATION_ACTION,
            "scenario": scenario,
            "challenge_id": challenge["challenge_id"],
            "kind": kind,
            "source": source,
            "acquisition_role": role,
            "workload_binding_sha256": hashlib.sha256(
                canonical_bytes(workload)
            ).hexdigest(),
            "envelope_sha256": hashlib.sha256(
                canonical_bytes(unsigned_envelope)
            ).hexdigest(),
        },
        acquirer_private_key,
    )
    return {
        **unsigned_envelope,
        "bindings": {
            **unsigned_envelope["bindings"],
            "acquisition_attestation": artifact,
        },
    }


def verify_live_acquisition_attestation(
    *,
    scenario: str,
    kind: str,
    challenge: dict,
    envelope: dict,
    acquirer_public_key: Path,
) -> dict:
    """Verify and remove the acquirer proof before semantic projection."""
    source = _expected_source(scenario, kind)
    role = acquisition_role_for_source(source)
    if not is_live_acquisition_envelope(envelope):
        raise ValueError("Stage-C acquisition envelope schema 非法")
    bindings = envelope.get("bindings")
    if (
        not isinstance(bindings, dict)
        or "acquisition_attestation" not in bindings
    ):
        raise ValueError("Stage-C live envelope 缺少 acquisition attestation")
    artifact = bindings["acquisition_attestation"]
    remaining_bindings = {
        key: value
        for key, value in bindings.items()
        if key != "acquisition_attestation"
    }
    unsigned_envelope = {
        **envelope,
        "bindings": remaining_bindings,
    }
    claims = verify_ed25519_artifact(
        artifact,
        acquirer_public_key,
        label=f"Stage-C {role} acquisition attestation",
    )
    if set(claims) != _LIVE_ACQUISITION_ATTESTATION_KEYS:
        raise ValueError("Stage-C acquisition attestation schema 非法")
    try:
        workload = challenge["workloads"][role]
        expected_fingerprint = challenge["source_key_fingerprints"][role]
    except (KeyError, TypeError) as exc:
        raise ValueError("Stage-C challenge 缺少 acquisition role") from exc
    if (
        ed25519_public_key_fingerprint(acquirer_public_key)
        != expected_fingerprint
        or claims
        != {
            "version": 1,
            "action": LIVE_ACQUISITION_ATTESTATION_ACTION,
            "scenario": scenario,
            "challenge_id": challenge["challenge_id"],
            "kind": kind,
            "source": source,
            "acquisition_role": role,
            "workload_binding_sha256": hashlib.sha256(
                canonical_bytes(workload)
            ).hexdigest(),
            "envelope_sha256": hashlib.sha256(
                canonical_bytes(unsigned_envelope)
            ).hexdigest(),
        }
    ):
        raise ValueError("Stage-C acquisition attestation 未绑定 bytes/workload")
    return unsigned_envelope


def build_live_signed_native_event(
    *,
    scenario: str,
    challenge_id: str,
    seq: int,
    observed_at: str,
    monotonic_ns: int,
    kind: str,
    envelope: dict,
    workload: dict,
    source_private_key: Path,
) -> dict:
    """Sign a raw acquisition event; facts are deliberately not an argument."""
    source = _expected_source(scenario, kind)
    validate_workload_attestation(workload)
    completed = _iso(
        envelope["response_completed_at"],
        "live response_completed_at",
    )
    observed = _iso(observed_at, "live observed_at")
    if completed > observed or (observed - completed).total_seconds() > 2:
        raise ValueError("Stage-C event observed_at 未绑定 acquisition")
    locator = _native_locator(
        source=source,
        kind=kind,
        workload=workload,
        envelope=envelope,
    )
    native_request = {
        "operation": kind,
        "target": source,
        "transport": {
            "systemd_collector": "systemd-dbus",
            "clock_collector": "chrony-unix-socket",
            "journal_collector": "sqlite-read-transaction",
            "provider": "provider-https",
            "okx_collector": "okx-https",
            "fault_controller": "unix-control-socket",
            "restore_verifier": "s3-exact-version-get",
        }[source],
        "request_id": hashlib.sha256(
            canonical_bytes(envelope)
        ).hexdigest(),
        "requested_at": envelope["requested_at"],
        "response_completed_at": observed.isoformat(),
        "locator": locator,
    }
    claims = {
        "version": 1,
        "action": NATIVE_EVENT_ACTION,
        "scenario": scenario,
        "challenge_id": challenge_id,
        "seq": seq,
        "observed_at": observed.isoformat(),
        "monotonic_ns": monotonic_ns,
        "source": source,
        "kind": kind,
        "workload_binding_sha256": hashlib.sha256(
            canonical_bytes(workload)
        ).hexdigest(),
        "native_request": _native_bytes_descriptor(native_request),
        "native_response": _native_bytes_descriptor(envelope),
    }
    artifact = sign_ed25519_payload(claims, source_private_key)
    return {
        "schema": RAW_EVENT_SCHEMA,
        "scenario": scenario,
        "challenge_id": challenge_id,
        "seq": seq,
        "observed_at": observed.isoformat(),
        "monotonic_ns": monotonic_ns,
        "source": source,
        "kind": kind,
        "payload": {"artifact": artifact},
    }


def action_allowed(scenario: str, action: str) -> bool:
    """Return an exact allow-list decision; prefixes and globbing are absent."""
    return action in SCENARIO_ACTION_ALLOWLIST.get(scenario, ())


def monotonic_event_time(previous: int | None = None) -> int:
    current = time.monotonic_ns()
    if previous is not None and current <= previous:
        return previous + 1
    return current
