#!/usr/bin/env python3
"""Issue and consume one-shot Stage-C challenges and derive drill receipts."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from okx_quant.ops.stage_c_chaos_protocol import (
    SCENARIO_PROTOCOLS,
    build_stage_c_capability_attestation,
    build_stage_c_drill_receipt,
    build_stage_c_raw_observation_artifact,
    consume_stage_c_challenge_globally,
    derive_stage_c_raw_observation,
    driver_contract_document,
    issue_stage_c_challenge,
    verify_stage_c_challenge,
    verify_stage_c_consumption_receipt,
)
from okx_quant.ops.stage_c_native_collectors import (
    collect_native_workload_attestation,
)
from stage_c_test_harness.barriers import BARRIER_SCENARIOS
from stage_c_test_harness.pipeline import (
    PIPELINE_ACTIVATION_REQUEST_SCHEMA,
)


def _safe_bytes(path: Path, *, limit: int, label: str) -> bytes:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size <= 0
        or path.stat().st_size > limit
    ):
        raise ValueError(f"{label} 必须是 1..{limit} bytes 普通文件")
    return path.read_bytes()


def _json(path: Path, *, label: str) -> dict:
    value = json.loads(
        _safe_bytes(path, limit=2 * 1024 * 1024, label=label)
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是 JSON object")
    return value


def _exclusive_json(path: Path, value: object, *, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"拒绝覆盖 Stage-C artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        payload = (
            json.dumps(
                value,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode()
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _key_argument(
    parser: argparse.ArgumentParser,
    name: str,
    *,
    required: bool = True,
) -> None:
    parser.add_argument(name, type=Path, required=required)


def _assignments(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for raw in values:
        name, separator, path = raw.partition("=")
        if (
            not separator
            or not name.strip()
            or not path.strip()
            or name in result
        ):
            raise ValueError(f"非法/重复 source key assignment: {raw}")
        result[name] = Path(path)
    return result


def _string_assignments(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values:
        name, separator, value = raw.partition("=")
        if (
            not separator
            or not name.strip()
            or not value.strip()
            or name in result
        ):
            raise ValueError(f"非法/重复 role assignment: {raw}")
        result[name] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    contract = sub.add_parser("contract")
    contract.add_argument(
        "--scenario",
        required=True,
        choices=sorted(SCENARIO_PROTOCOLS),
    )
    contract.add_argument("--output", required=True, type=Path)

    capability = sub.add_parser("attest-capability")
    capability.add_argument(
        "--scenario",
        required=True,
        choices=sorted(SCENARIO_PROTOCOLS),
    )
    capability.add_argument("--identity", required=True, type=Path)
    capability.add_argument(
        "--role-unit",
        action="append",
        default=[],
        metavar="ROLE=SYSTEMD_UNIT",
    )
    capability.add_argument(
        "--native-attestation",
        action="append",
        default=[],
        metavar="ROLE=JSON_PATH",
        help="由隔离/远端 role 安全传入的原始 systemd/proc/STS attestation",
    )
    capability.add_argument(
        "--source-public-key",
        action="append",
        default=[],
        metavar="ROLE=PATH",
    )
    _key_argument(capability, "--authority-private-key")
    capability.add_argument("--lifetime-seconds", type=int, default=600)
    capability.add_argument("--output", required=True, type=Path)

    issue = sub.add_parser("issue-challenge")
    issue.add_argument(
        "--scenario",
        required=True,
        choices=sorted(SCENARIO_PROTOCOLS),
    )
    issue.add_argument(
        "--capability-attestation",
        required=True,
        type=Path,
    )
    issue.add_argument(
        "--consumption-backend",
        required=True,
        type=Path,
    )
    issue.add_argument(
        "--okx-observer-bindings",
        type=Path,
        help="exact-release frozen observer API key and TLS certificate/SPKI hashes",
    )
    issue.add_argument(
        "--barrier-recovery-bindings",
        type=Path,
        help="barrier-only frozen observer API key and TLS certificate/SPKI hashes",
    )
    _key_argument(issue, "--capability-authority-public-key")
    _key_argument(issue, "--registrar-private-key")
    issue.add_argument("--lifetime-seconds", type=int, default=600)
    issue.add_argument("--output", required=True, type=Path)

    consume = sub.add_parser("consume-challenge")
    consume.add_argument(
        "--scenario",
        choices=sorted(SCENARIO_PROTOCOLS),
        help="可选交叉检查；实际场景始终从签名 challenge 派生",
    )
    consume.add_argument("--challenge", required=True, type=Path)
    _key_argument(consume, "--registrar-public-key")
    _key_argument(consume, "--consumer-private-key")
    consume.add_argument(
        "--aws-executable",
        type=Path,
        default=Path("/usr/bin/aws"),
    )
    consume.add_argument("--input-wait-seconds", type=float, default=0)
    consume.add_argument("--output", required=True, type=Path)

    activate = sub.add_parser("build-barrier-activation")
    activate.add_argument(
        "--scenario",
        required=True,
        choices=sorted(BARRIER_SCENARIOS),
    )
    activate.add_argument("--challenge", required=True, type=Path)
    activate.add_argument(
        "--consumption-receipt",
        required=True,
        type=Path,
    )
    _key_argument(activate, "--registrar-public-key")
    _key_argument(activate, "--challenge-consumer-public-key")
    activate.add_argument("--output", required=True, type=Path)

    produce = sub.add_parser("produce")
    produce.add_argument(
        "--scenario",
        required=True,
        choices=sorted(SCENARIO_PROTOCOLS),
    )
    produce.add_argument("--challenge", required=True, type=Path)
    produce.add_argument("--raw-events", required=True, type=Path)
    produce.add_argument("--raw-object-uri", required=True)
    produce.add_argument("--raw-version-id", required=True)
    produce.add_argument("--observer-id", required=True)
    _key_argument(produce, "--registrar-public-key")
    _key_argument(produce, "--capability-authority-public-key")
    produce.add_argument(
        "--source-public-key",
        action="append",
        default=[],
        metavar="ROLE=PATH",
    )
    _key_argument(produce, "--raw-observer-private-key")
    produce.add_argument("--observation-output", required=True, type=Path)
    produce.add_argument("--receipt-output", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "contract":
        _exclusive_json(
            args.output,
            driver_contract_document(args.scenario),
            mode=0o644,
        )
        return 0
    if args.command == "attest-capability":
        role_units = _string_assignments(args.role_unit)
        native_paths = _assignments(args.native_attestation)
        if set(role_units).intersection(native_paths):
            raise ValueError("capability role 不得同时来自 unit 与 native artifact")
        artifact = build_stage_c_capability_attestation(
            scenario=args.scenario,
            identity=_json(args.identity, label="Stage-C identity"),
            native_attestations={
                role: collect_native_workload_attestation(unit=unit)
                for role, unit in role_units.items()
            }
            | {
                role: _json(
                    path,
                    label=f"{role} native workload attestation",
                )
                for role, path in native_paths.items()
            },
            source_public_keys=_assignments(args.source_public_key),
            authority_private_key=args.authority_private_key,
            lifetime_seconds=args.lifetime_seconds,
        )
        _exclusive_json(args.output, artifact, mode=0o640)
        return 0
    if args.command == "issue-challenge":
        artifact = issue_stage_c_challenge(
            scenario=args.scenario,
            capability_attestation=_json(
                args.capability_attestation,
                label="capability attestation",
            ),
            capability_authority_public_key=(
                args.capability_authority_public_key
            ),
            registrar_private_key=args.registrar_private_key,
            consumption_backend=_json(
                args.consumption_backend,
                label="global consumption backend",
            ),
            okx_observer_bindings=(
                _json(
                    args.okx_observer_bindings,
                    label="exact-release OKX observer bindings",
                )
                if args.okx_observer_bindings is not None
                else None
            ),
            barrier_recovery_bindings=(
                _json(
                    args.barrier_recovery_bindings,
                    label="barrier recovery bindings",
                )
                if args.barrier_recovery_bindings is not None
                else None
            ),
            lifetime_seconds=args.lifetime_seconds,
        )
        _exclusive_json(args.output, artifact, mode=0o640)
        return 0
    if args.command == "consume-challenge":
        if not 0 <= args.input_wait_seconds <= 600:
            raise ValueError("Stage-C consume input wait 必须位于 0..600 秒")
        deadline = time.monotonic() + args.input_wait_seconds
        while not (
            args.challenge.is_file()
            and not args.challenge.is_symlink()
        ):
            if time.monotonic() >= deadline:
                raise TimeoutError("Stage-C consumer 等待 challenge 超时")
            time.sleep(0.1)
        challenge_artifact = _json(
            args.challenge,
            label="registrar challenge",
        )
        if (
            args.scenario is not None
            and challenge_artifact.get("payload", {}).get("scenario")
            != args.scenario
        ):
            raise ValueError("consume scenario 与 signed challenge 不一致")
        receipt = consume_stage_c_challenge_globally(
            challenge_artifact=challenge_artifact,
            registrar_public_key=args.registrar_public_key,
            consumer_private_key=args.consumer_private_key,
            aws_executable=args.aws_executable,
        )
        _exclusive_json(args.output, receipt, mode=0o640)
        return 0
    if args.command == "build-barrier-activation":
        challenge_artifact = _json(
            args.challenge,
            label="registrar challenge",
        )
        verify_stage_c_challenge(
            challenge_artifact,
            registrar_public_key=args.registrar_public_key,
            scenario=args.scenario,
            now=None,
            enforce_current_window=True,
        )
        consumption_receipt = _json(
            args.consumption_receipt,
            label="global challenge consumption receipt",
        )
        verify_stage_c_consumption_receipt(
            consumption_receipt,
            challenge_artifact=challenge_artifact,
            registrar_public_key=args.registrar_public_key,
            consumer_public_key=args.challenge_consumer_public_key,
        )
        _exclusive_json(
            args.output,
            {
                "schema": PIPELINE_ACTIVATION_REQUEST_SCHEMA,
                "scenario": args.scenario,
                "challenge_artifact": challenge_artifact,
                "consumption_receipt": consumption_receipt,
            },
        )
        return 0

    challenge = _json(args.challenge, label="registrar challenge")
    raw_bytes = _safe_bytes(
        args.raw_events,
        limit=8 * 1024 * 1024,
        label="native raw events",
    )
    first_line = raw_bytes.splitlines()[0]
    first_event = json.loads(first_line)
    embedded_challenge = (
        first_event.get("payload", {}).get("artifact")
        if isinstance(first_event, dict)
        else None
    )
    if embedded_challenge != challenge:
        raise ValueError(
            "raw event stream 的 challenge 与待消费 artifact 不同"
        )
    source_public_keys = _assignments(args.source_public_key)
    derived = derive_stage_c_raw_observation(
        raw_bytes,
        scenario=args.scenario,
        registrar_public_key=args.registrar_public_key,
        capability_authority_public_key=(
            args.capability_authority_public_key
        ),
        provider_public_key=source_public_keys[
            "provider_receipt_authority"
        ],
        raw_observer_public_key=source_public_keys["parser_signer"],
        source_public_keys=source_public_keys,
        barrier_attestor_public_key=source_public_keys.get(
            "barrier_attestor"
        ),
        kill_controller_public_key=source_public_keys.get(
            "kill_controller"
        ),
        require_production_evidence=True,
    )
    observation = build_stage_c_raw_observation_artifact(
        derived,
        source={
            "collector": "stage-c-native-jsonl-collector/v1",
            "object_uri": args.raw_object_uri,
            "version_id": args.raw_version_id,
            "sha256": derived["raw_sha256"],
            "bytes": derived["raw_bytes"],
        },
        observer_id=args.observer_id,
        observer_private_key=args.raw_observer_private_key,
    )
    receipt = build_stage_c_drill_receipt(
        derived,
        raw_observation_artifact=observation,
    )
    _exclusive_json(args.observation_output, observation)
    _exclusive_json(args.receipt_output, receipt, mode=0o644)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
