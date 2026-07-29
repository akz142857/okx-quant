#!/usr/bin/env python3
"""Credential-free synthetic monitor intended for a separate host/provider."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import requests

from okx_quant.infrastructure.evidence import sign_ed25519_payload

_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SIGNAL_MAX_AGE_SECONDS = {
    "host": 120,
    "service": 60,
    "provider": 900,
    "evidence-close": 90_000,
    "backup": 300,
}


def _https_url(value: str, *, allow_loopback_http: bool = False) -> str:
    parsed = urlparse(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if (
        not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or (parsed.scheme != "https" and not (
            allow_loopback_http and loopback and parsed.scheme == "http"
        ))
    ):
        raise ValueError("monitor URL 必须是不含凭据的 HTTPS URL")
    return value


def _get_json(url: str, timeout: float) -> tuple[int, dict, float]:
    started = time.monotonic()
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=False,
    )
    latency = time.monotonic() - started
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return response.status_code, payload, latency


def _okx_clock(url: str, timeout: float) -> dict:
    requested_at = time.time()
    status, payload, latency = _get_json(url, timeout)
    received_at = time.time()
    rows = payload.get("data", [])
    if (
        status != 200
        or payload.get("code") != "0"
        or not isinstance(rows, list)
        or len(rows) != 1
        or not isinstance(rows[0], dict)
    ):
        raise RuntimeError("external monitor 无法取得 OKX server time")
    server_time = float(rows[0]["ts"]) / 1000
    midpoint = requested_at + (received_at - requested_at) / 2
    return {
        "status": status,
        "latency_seconds": latency,
        "midpoint_offset_seconds": server_time - midpoint,
    }


def _signal_urls(
    values: list[str],
    *,
    allow_loopback_http: bool,
) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in values:
        name, separator, url = raw.partition("=")
        if (
            not separator
            or name not in _SIGNAL_MAX_AGE_SECONDS
            or name in parsed
        ):
            raise ValueError(
                "--signal-url 必须为不重复的 "
                "host|service|provider|evidence-close|backup=URL"
            )
        parsed[name] = _https_url(
            url,
            allow_loopback_http=allow_loopback_http,
        )
    if set(parsed) != set(_SIGNAL_MAX_AGE_SECONDS):
        raise ValueError("external monitor 必须配置全部五类 dead-man signal")
    return parsed


def _incident_identity(args: argparse.Namespace) -> dict:
    return {
        "target": args.target,
        "release": args.expected_release,
        "config": args.expected_config,
        "account_uid": args.expected_account_uid,
        "unit": args.expected_unit,
        "soak_epoch_id": args.soak_epoch_id,
    }


def _load_incident_state(path: Path) -> dict:
    empty = {
        "version": 1,
        "generation": 0,
        "active": False,
        "fingerprint": "",
        "event_id": "",
        "delivered": False,
    }
    if not path.exists():
        return empty
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("external monitor incident state 必须是普通文件")
    if path.stat().st_mode & 0o077:
        raise RuntimeError("external monitor incident state 必须是 0600")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "external monitor incident state 无法解析"
        ) from exc
    if (
        not isinstance(state, dict)
        or set(state) != set(empty)
        or state.get("version") != 1
        or isinstance(state.get("generation"), bool)
        or not isinstance(state.get("generation"), int)
        or state["generation"] < 0
        or not isinstance(state.get("active"), bool)
        or not isinstance(state.get("fingerprint"), str)
        or not isinstance(state.get("event_id"), str)
        or not isinstance(state.get("delivered"), bool)
        or (
            state["active"]
            and (
                not _SHA256.fullmatch(state["fingerprint"])
                or not _SHA256.fullmatch(state["event_id"])
            )
        )
        or (
            not state["active"]
            and (
                state["fingerprint"]
                or state["event_id"]
                or state["delivered"]
            )
        )
    ):
        raise RuntimeError("external monitor incident state 语义非法")
    return state


def _save_incident_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and path.is_symlink():
        raise RuntimeError("拒绝覆盖 symlink incident state")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        try:
            payload = (
                json.dumps(
                    state,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError(
                        "incident state write returned no progress"
                    )
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _advance_incident(
    state: dict,
    *,
    identity: dict,
    failures: list[str],
) -> tuple[dict, str, bool]:
    healthy_event_id = hashlib.sha256(
        json.dumps(
            {**identity, "failures": []},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if not failures:
        return {
            "version": 1,
            "generation": state["generation"],
            "active": False,
            "fingerprint": "",
            "event_id": "",
            "delivered": False,
        }, healthy_event_id, False
    fingerprint = hashlib.sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if state["active"] and state["fingerprint"] == fingerprint:
        return state, state["event_id"], not state["delivered"]
    generation = state["generation"] + 1
    event_id = hashlib.sha256(
        json.dumps(
            {
                **identity,
                "incident_generation": generation,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {
        "version": 1,
        "generation": generation,
        "active": True,
        "fingerprint": fingerprint,
        "event_id": event_id,
        "delivered": False,
    }, event_id, True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--health-url", required=True)
    parser.add_argument("--ready-url", required=True)
    parser.add_argument(
        "--signal-url",
        action="append",
        default=[],
        help=(
            "required NAME=URL; names: host, service, provider, "
            "evidence-close, backup"
        ),
    )
    parser.add_argument(
        "--okx-time-url",
        default="https://www.okx.com/api/v5/public/time",
    )
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--expected-config", required=True)
    parser.add_argument("--expected-account-uid", required=True)
    parser.add_argument("--expected-unit", required=True)
    parser.add_argument("--soak-epoch-id", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--primary-page-url", default="")
    parser.add_argument("--independent-page-url", default="")
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--allow-loopback-http", action="store_true")
    parser.add_argument("--incident-state", type=Path)
    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument("--output", type=Path)
    output_group.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not _SHA1.fullmatch(args.expected_release):
        raise ValueError("expected release 必须是 40 位 Git commit")
    if not _SHA256.fullmatch(args.expected_config):
        raise ValueError("expected config 必须是 SHA-256")
    if (
        not args.expected_account_uid.strip()
        or args.expected_unit
        != f"okx-quant-{args.target}.service"
        or not args.soak_epoch_id.strip()
    ):
        raise ValueError("monitor account/unit/soak epoch identity 非法")
    if not 0 < args.timeout <= 30:
        raise ValueError("monitor timeout 必须位于 (0,30]")
    health_url = _https_url(
        args.health_url,
        allow_loopback_http=args.allow_loopback_http,
    )
    ready_url = _https_url(
        args.ready_url,
        allow_loopback_http=args.allow_loopback_http,
    )
    signal_urls = _signal_urls(
        args.signal_url,
        allow_loopback_http=args.allow_loopback_http,
    )
    okx_time_url = _https_url(args.okx_time_url)
    if (
        not args.private_key.is_file()
        or args.private_key.is_symlink()
        or args.private_key.stat().st_mode & 0o077
    ):
        raise RuntimeError("external monitor private key 必须是 owner-only 普通文件")
    output = args.output or (
        args.output_dir
        / f"observation-{int(time.time() * 1000)}-{uuid.uuid4().hex}.json"
    )
    incident_state_path = args.incident_state or (
        args.output_dir / "incidents.json"
        if args.output_dir is not None
        else args.output.parent / ".external-monitor-incidents.json"
    )
    if incident_state_path == output:
        raise ValueError("incident state 与 evidence output 不得相同")
    if output.exists() or output.is_symlink():
        raise RuntimeError(f"拒绝覆盖 external monitor evidence: {output}")
    incident_state = _load_incident_state(incident_state_path)
    started_at = time.time()
    failures: list[str] = []
    endpoints = {}
    for name, url in (("health", health_url), ("ready", ready_url)):
        try:
            status, payload, latency = _get_json(url, args.timeout)
        except Exception as exc:  # noqa: BLE001
            status, payload, latency = 0, {}, 0.0
            failures.append(f"{name.upper()}_TRANSPORT_{type(exc).__name__}")
        endpoints[name] = {
            "status": status,
            "latency_seconds": latency,
            "live": payload.get("live"),
            "ready": payload.get("ready"),
            "release_identity": payload.get("release_identity", ""),
            "config_identity": payload.get("config_identity", ""),
            "account_uid": payload.get("account_uid", ""),
            "deployment_unit": payload.get("deployment_unit", ""),
            "soak_epoch_id": payload.get("soak_epoch_id", ""),
        }
        expected_flag = payload.get("live" if name == "health" else "ready")
        if status != 200 or expected_flag is not True:
            failures.append(f"{name.upper()}_UNHEALTHY")
        if (
            payload.get("release_identity") != args.expected_release
            or payload.get("config_identity") != args.expected_config
        ):
            failures.append(f"{name.upper()}_IDENTITY_MISMATCH")
        for field, expected in (
            ("account_uid", args.expected_account_uid),
            ("deployment_unit", args.expected_unit),
            ("soak_epoch_id", args.soak_epoch_id),
        ):
            if payload.get(field) != expected:
                failures.append(
                    f"{name.upper()}_{field.upper()}_MISMATCH"
                )
    signals = {}
    for name, url in signal_urls.items():
        label = name.upper().replace("-", "_")
        try:
            status, payload, latency = _get_json(url, args.timeout)
        except Exception as exc:  # noqa: BLE001
            status, payload, latency = 0, {}, 0.0
            failures.append(f"{label}_TRANSPORT_{type(exc).__name__}")
        observed_at = payload.get("observed_at")
        age_seconds = None
        if (
            not isinstance(observed_at, bool)
            and isinstance(observed_at, (int, float))
            and math.isfinite(observed_at)
        ):
            age_seconds = started_at - float(observed_at)
        signals[name] = {
            "status": status,
            "latency_seconds": latency,
            "ok": payload.get("ok"),
            "signal": payload.get("signal", ""),
            "observed_at": observed_at,
            "age_seconds": age_seconds,
            "maximum_age_seconds": _SIGNAL_MAX_AGE_SECONDS[name],
            "deadman_id": payload.get("deadman_id", ""),
            "target": payload.get("target", ""),
            "release_identity": payload.get("release_identity", ""),
            "config_identity": payload.get("config_identity", ""),
            "account_uid": payload.get("account_uid", ""),
            "deployment_unit": payload.get("deployment_unit", ""),
            "soak_epoch_id": payload.get("soak_epoch_id", ""),
        }
        if (
            status != 200
            or payload.get("ok") is not True
            or payload.get("signal") != name
            or not str(payload.get("deadman_id", "")).strip()
        ):
            failures.append(f"{label}_UNHEALTHY")
        if (
            age_seconds is None
            or age_seconds < -5
            or age_seconds > _SIGNAL_MAX_AGE_SECONDS[name]
        ):
            failures.append(f"{label}_DEADMAN_MISSING_OR_STALE")
        if (
            payload.get("target") != args.target
            or payload.get("release_identity") != args.expected_release
            or payload.get("config_identity") != args.expected_config
            or payload.get("account_uid") != args.expected_account_uid
            or payload.get("deployment_unit") != args.expected_unit
            or payload.get("soak_epoch_id") != args.soak_epoch_id
        ):
            failures.append(f"{label}_IDENTITY_MISMATCH")
    try:
        clock = _okx_clock(okx_time_url, args.timeout)
        if abs(clock["midpoint_offset_seconds"]) > 1:
            failures.append("CLOCK_SKEW")
    except Exception as exc:  # noqa: BLE001
        clock = {
            "status": 0,
            "latency_seconds": 0,
            "midpoint_offset_seconds": None,
        }
        failures.append(f"OKX_CLOCK_{type(exc).__name__}")
    failures = sorted(set(failures))
    page_urls: list[str] = []
    if failures:
        page_urls = [
            _https_url(value)
            for value in (
                args.primary_page_url,
                args.independent_page_url,
            )
            if value
        ]
        origins = {
            (urlparse(value).scheme, urlparse(value).netloc)
            for value in page_urls
        }
        if len(page_urls) != 2 or len(origins) != 2:
            failures.append("INDEPENDENT_PAGE_ROUTES_MISSING")
    failures = sorted(set(failures))
    incident_state, event_id, should_deliver = _advance_incident(
        incident_state,
        identity=_incident_identity(args),
        failures=failures,
    )
    _save_incident_state(incident_state_path, incident_state)
    deliveries = []
    if failures and len(page_urls) == 2 and should_deliver:
        for index, url in enumerate(page_urls):
            try:
                response = requests.post(
                    url,
                    json={
                        "event_name": "page.external_demo_synthetic",
                        "event_id": event_id,
                        "target": args.target,
                        "failures": failures,
                    },
                    timeout=args.timeout,
                    allow_redirects=False,
                )
                deliveries.append({
                    "route": (
                        "primary" if index == 0 else "independent"
                    ),
                    "http_status": response.status_code,
                    "ingestion_accepted": 200 <= response.status_code < 300,
                })
            except Exception:  # noqa: BLE001
                deliveries.append({
                    "route": (
                        "primary" if index == 0 else "independent"
                    ),
                    "http_status": 0,
                    "ingestion_accepted": False,
                })
        if all(row["ingestion_accepted"] for row in deliveries):
            incident_state = {**incident_state, "delivered": True}
            _save_incident_state(incident_state_path, incident_state)
    evidence = {
        "version": 1,
        "action": "attest-external-demo-synthetic",
        "target": args.target,
        "event_id": event_id,
        "signing_key_id": args.signing_key_id,
        "expected_release": args.expected_release,
        "expected_config": args.expected_config,
        "expected_account_uid": args.expected_account_uid,
        "expected_unit": args.expected_unit,
        "soak_epoch_id": args.soak_epoch_id,
        "started_at": started_at,
        "completed_at": time.time(),
        "endpoints": endpoints,
        "signals": signals,
        "clock": clock,
        "failures": sorted(set(failures)),
        "deliveries": deliveries,
        "ok": not failures,
    }
    artifact = sign_ed25519_payload(evidence, args.private_key)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            artifact,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    output.chmod(0o600)
    print(output)
    return 0 if evidence["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
