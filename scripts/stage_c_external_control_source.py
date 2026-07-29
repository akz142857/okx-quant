#!/usr/bin/env python3
"""Acquire common systemd/clock/provider bytes for external Stage-C runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from okx_quant.ops.stage_c_chaos_protocol import (
    acquisition_role_for_source,
    verify_stage_c_challenge,
)
from okx_quant.ops.stage_c_exact_release_drivers import (
    attach_live_acquisition_attestation,
    build_live_acquisition_envelope,
    capture_native_acquisition,
)
from okx_quant.ops.stage_c_external_bridge import RAW_COLLECTION_SCHEMA
from okx_quant.ops.stage_c_native_collectors import (
    assert_current_process_matches_workload,
    collect_clock_native,
    collect_http_native,
    collect_systemd_native,
)


def _safe_json(path: Path, *, label: str) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= 8 * 1024 * 1024
        ):
            raise ValueError(f"{label} 必须是安全普通 JSON")
        raw = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
        ):
            raise ValueError(f"{label} 读取期间变化")
    finally:
        os.close(descriptor)

    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label} JSON key 重复: {key}")
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是 JSON object")
    return value


def _exclusive_json(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"拒绝覆盖 Stage-C control source: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
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
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o640,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Stage-C control source 短写")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _wait(paths: list[Path], *, deadline: float, label: str) -> None:
    while not all(path.is_file() and not path.is_symlink() for path in paths):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Stage-C 等待 {label} 超时")
        time.sleep(0.1)


def _attested(
    *,
    scenario: str,
    kind: str,
    challenge: dict,
    acquisition,
    private_key: Path,
    bindings: dict | None = None,
) -> dict:
    envelope = build_live_acquisition_envelope(
        scenario=scenario,
        kind=kind,
        acquisitions=[acquisition],
        bindings=bindings,
    )
    return {
        "kind": kind,
        "envelope": attach_live_acquisition_attestation(
            scenario=scenario,
            kind=kind,
            challenge=challenge,
            envelope=envelope,
            acquirer_private_key=private_key,
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--role",
        required=True,
        choices=("systemd_collector", "clock_collector", "provider"),
    )
    parser.add_argument("--challenge", required=True, type=Path)
    parser.add_argument("--registrar-public-key", required=True, type=Path)
    parser.add_argument("--acquirer-private-key", required=True, type=Path)
    parser.add_argument("--capability-attestation", type=Path)
    parser.add_argument("--driver-ready-output", type=Path)
    parser.add_argument(
        "--start-after",
        action="append",
        default=[],
        type=Path,
    )
    parser.add_argument(
        "--wait-for",
        action="append",
        default=[],
        type=Path,
    )
    parser.add_argument("--provider-url-template")
    parser.add_argument("--provider-token-file", type=Path)
    parser.add_argument("--wait-seconds", type=float, default=300)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not 0 <= args.wait_seconds <= 600:
        raise ValueError("Stage-C control source wait 必须位于 0..600 秒")
    deadline = time.monotonic() + args.wait_seconds
    _wait([args.challenge], deadline=deadline, label="challenge")
    challenge_artifact = _safe_json(
        args.challenge,
        label="registrar challenge",
    )
    scenario = str(challenge_artifact.get("payload", {}).get("scenario", ""))
    challenge = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=args.registrar_public_key,
        scenario=scenario,
        now=None,
        enforce_current_window=True,
    )
    acquisition_role = acquisition_role_for_source(args.role)
    assert_current_process_matches_workload(
        challenge["workloads"][acquisition_role]
    )

    if args.role == "systemd_collector":
        if (
            args.capability_attestation is None
            or args.driver_ready_output is None
            or args.start_after
            or args.provider_url_template is not None
            or args.provider_token_file is not None
        ):
            raise ValueError("systemd source 参数组合非法")
        unit = str(
            challenge["workloads"]["fault_driver"]["cgroup"]
        ).removeprefix("/system.slice/")
        driver = _attested(
            scenario=scenario,
            kind="driver.invoked",
            challenge=challenge,
            acquisition=capture_native_acquisition(
                collect_systemd_native,
                action="show-runtime",
                unit=unit,
            ),
            private_key=args.acquirer_private_key,
            bindings={
                "capability_attestation": _safe_json(
                    args.capability_attestation,
                    label="capability attestation",
                )
            },
        )
        _exclusive_json(
            args.driver_ready_output,
            {
                "schema": "okx-quant.stage-c-driver-ready/v1",
                "scenario": scenario,
                "challenge_id": challenge["challenge_id"],
                "driver_envelope_sha256": hashlib.sha256(
                    json.dumps(
                        driver["envelope"],
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest(),
            },
        )
        _wait(args.wait_for, deadline=deadline, label="peer raw collections")
        completed = _attested(
            scenario=scenario,
            kind="run.completed",
            challenge=challenge,
            acquisition=capture_native_acquisition(
                collect_systemd_native,
                action="show-runtime",
                unit=unit,
            ),
            private_key=args.acquirer_private_key,
        )
        envelopes = [driver, completed]
    else:
        if (
            not args.start_after
            or args.capability_attestation is not None
            or args.driver_ready_output is not None
            or args.wait_for
        ):
            raise ValueError("clock/provider source 参数组合非法")
        _wait(args.start_after, deadline=deadline, label="source prerequisites")
        if args.role == "clock_collector":
            if (
                args.provider_url_template is not None
                or args.provider_token_file is not None
            ):
                raise ValueError("clock source 禁止 provider 参数")
            envelopes = [
                _attested(
                    scenario=scenario,
                    kind="clock.sample",
                    challenge=challenge,
                    acquisition=capture_native_acquisition(
                        collect_clock_native
                    ),
                    private_key=args.acquirer_private_key,
                )
            ]
        else:
            if (
                not args.provider_url_template
                or args.provider_url_template.count("{challenge_id}") != 1
                or args.provider_token_file is None
            ):
                raise ValueError("provider source URL/token 参数非法")
            token = args.provider_token_file.read_text().strip()
            if not token or "\x00" in token:
                raise ValueError("provider bearer token 非法")
            url = args.provider_url_template.format(
                challenge_id=challenge["challenge_id"]
            )
            envelopes = [
                _attested(
                    scenario=scenario,
                    kind="page.provider_receipt",
                    challenge=challenge,
                    acquisition=capture_native_acquisition(
                        collect_http_native,
                        source="provider",
                        method="GET",
                        url=url,
                        headers={
                            "Accept": "application/json",
                            "Authorization": f"Bearer {token}",
                            "X-Stage-C-Request-ID": (
                                challenge["challenge_id"]
                            ),
                        },
                    ),
                    private_key=args.acquirer_private_key,
                )
            ]
    _exclusive_json(
        args.output,
        {
            "schema": RAW_COLLECTION_SCHEMA,
            "scenario": scenario,
            "challenge_id": challenge["challenge_id"],
            "account_uid": challenge["identity"]["account_uid"],
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
