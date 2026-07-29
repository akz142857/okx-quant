#!/usr/bin/env python3
"""Challenge-bound two-phase OKX Demo actor for four external scenarios."""

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

from main import make_client
from okx_quant.application.approval import canonical_bytes
from okx_quant.client.rest import OKXAPIError
from okx_quant.config import load_yaml
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.ops.stage_c_chaos_protocol import (
    verify_stage_c_challenge,
    verify_stage_c_consumption_receipt,
)
from okx_quant.ops.stage_c_external_executors import (
    EXTERNAL_SCENARIOS,
    REPORT_SCHEMA,
    STAGE_C_DEMO_CONFIRMATION,
    ExternalScenarioReport,
    StageCExternalScenarioExecutor,
    external_scenario_implementation_manifests,
    external_scenario_mutation_self_check,
)
from okx_quant.ops.stage_c_native_collectors import (
    assert_current_process_matches_workload,
)

__all__ = ("make_client",)


def _json(path: Path, *, label: str, limit: int = 2 * 1024 * 1024) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= limit
        ):
            raise ValueError(
                f"{label} 必须是 1..{limit} bytes 普通文件"
            )
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


def _exclusive_json(path: Path, value: object, *, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"拒绝覆盖 Stage-C artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        payload = (
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
            mode,
            dir_fd=parent,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Stage-C artifact 短写")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


class OKXDemoExternalActor:
    """Concrete adapter using the repository OKX client and command journal."""

    def __init__(self, *, client, journal: SQLiteJournal):
        self.client = client
        self.journal = journal
        self.simulated = bool(client.simulated)

    def close(self) -> None:
        self.journal.close()

    def account_uid(self) -> str:
        return str(self.client.get_account_config().get("uid", ""))

    def instrument(self, inst_id: str) -> dict:
        return self.client.get_instrument(inst_id)

    def ticker(self, inst_id: str) -> dict:
        return self.client.get_ticker(inst_id)

    def balance(self, ccy: str) -> dict:
        rows = self.client.get_balance(ccy)
        if len(rows) != 1 or not isinstance(rows[0], dict):
            raise RuntimeError("OKX balance 返回不是唯一 account snapshot")
        return rows[0]

    def open_orders(self, inst_id: str) -> list[dict]:
        return self.client.get_open_orders(inst_id)

    def pending_algos(self, inst_id: str) -> list[dict]:
        return self.client.get_pending_algo_orders(inst_id=inst_id)

    def order(self, inst_id: str, cl_ord_id: str) -> dict:
        try:
            return self.client.get_order(
                inst_id,
                cl_ord_id=cl_ord_id,
            )
        except OKXAPIError as exc:
            if exc.code == "51603":
                return {}
            raise

    def place_order(
        self,
        *,
        inst_id: str,
        side: str,
        ord_type: str,
        size: str,
        cl_ord_id: str,
        price: str = "",
        target_currency: str = "",
    ) -> dict:
        return self.client.place_order(
            inst_id,
            side,
            ord_type,
            size,
            px=price or None,
            tgt_ccy=target_currency or None,
            cl_ord_id=cl_ord_id,
        )

    def cancel_order(self, *, inst_id: str, cl_ord_id: str) -> dict:
        return self.client.cancel_order(
            inst_id,
            cl_ord_id=cl_ord_id,
        )

    def cancel_algo(self, *, inst_id: str, algo_id: str) -> dict:
        return self.client.cancel_algo_order(inst_id, algo_id)

    def reconcile(
        self,
        *,
        command_id: str,
        scenario: str,
        challenge_id: str,
        targets: dict[str, str],
        timeout_s: float,
    ) -> dict:
        existing = self.journal.get_control_command(command_id)
        if existing is None:
            self.journal.enqueue_control_command(
                "reconcile-now",
                {
                    "stage_c": {
                        "scenario": scenario,
                        "challenge_id": challenge_id,
                        "targets": targets,
                    }
                },
                command_id=command_id,
            )
        else:
            stage_c = existing.get("payload", {}).get("stage_c", {})
            if stage_c != {
                "scenario": scenario,
                "challenge_id": challenge_id,
                "targets": targets,
            }:
                raise RuntimeError(
                    "stable reconcile command_id 已绑定不同 payload"
                )
        deadline = time.monotonic() + timeout_s
        while time.monotonic() <= deadline:
            command = self.journal.get_control_command(command_id)
            if command and command["status"] in {"completed", "failed"}:
                return command
            time.sleep(0.25)
        return {
            "command_id": command_id,
            "status": "pending",
            "result": {"message": "runtime reconcile timeout"},
        }

    def protection_ownership(
        self,
        *,
        inst_id: str,
        parent_cl_ord_id: str,
        parent_ord_id: str,
    ) -> dict:
        try:
            chain = self.journal.audit_order_chain(parent_cl_ord_id)
        except KeyError:
            return {}
        intent = chain.get("intent", {})
        protections = chain.get("protections", [])
        if (
            not isinstance(intent, dict)
            or not isinstance(protections, list)
            or intent.get("cl_ord_id") != parent_cl_ord_id
            or intent.get("exchange_ord_id") != parent_ord_id
            or intent.get("inst_id") != inst_id
            or len(protections) != 1
            or not isinstance(protections[0], dict)
        ):
            return {}
        protection = protections[0]
        if (
            protection.get("parent_intent_id") != intent.get("intent_id")
            or protection.get("inst_id") != inst_id
            or not protection.get("exchange_algo_id")
            or not protection.get("algo_cl_ord_id")
        ):
            return {}
        return {
            "parent_intent_id": str(intent["intent_id"]),
            "parent_cl_ord_id": parent_cl_ord_id,
            "parent_ord_id": parent_ord_id,
            "inst_id": inst_id,
            "algo_cl_ord_id": str(protection["algo_cl_ord_id"]),
            "algo_id": str(protection["exchange_algo_id"]),
            "protected_qty": str(protection["protected_qty"]),
        }

    def postcondition_event(
        self,
        *,
        event_name: str,
        challenge_id: str,
    ) -> dict | None:
        rows = self.journal.list_events(event_name)
        matches = [
            row
            for row in rows
            if row.get("correlation_id") == challenge_id
        ]
        return matches[-1] if matches else None


def _report(value: dict) -> ExternalScenarioReport:
    if value.get("schema") != REPORT_SCHEMA:
        raise ValueError("Stage-C cleanup report schema 非法")
    fields = set(ExternalScenarioReport.__dataclass_fields__)
    if set(value) != fields:
        raise ValueError("Stage-C cleanup report fields 非法")
    return ExternalScenarioReport(**value)


def _validated_config(path: Path) -> tuple[dict, Path]:
    cfg = load_yaml(str(path))
    okx = cfg.get("okx", {})
    production = cfg.get("production", {})
    if (
        not isinstance(okx, dict)
        or okx.get("simulated") is not True
        or not all(
            str(okx.get(name, "")).strip()
            for name in ("api_key", "secret_key", "passphrase")
        )
        or (
            isinstance(production, dict)
            and production.get("environment", "demo") != "demo"
        )
    ):
        raise ValueError(
            "Stage-C external actor 要求 OKX Demo credentials/simulated=true"
        )
    journal = (
        Path(str(production["journal_path"]))
        if isinstance(production, dict) and production.get("journal_path")
        else Path("state/demo-chaos/trading.db")
    )
    return cfg, journal


def _actor_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument(
        "--confirm",
        required=True,
        help=f"必须精确为 {STAGE_C_DEMO_CONFIRMATION}",
    )
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--poll-interval", type=float, default=0.25)
    parser.add_argument("--authorization-wait-seconds", type=float, default=0)
    parser.add_argument("--output", required=True, type=Path)


def _wait_for_authorization_files(args) -> None:
    timeout = float(args.authorization_wait_seconds)
    if timeout < 0 or timeout > 600:
        raise ValueError("Stage-C authorization wait 必须位于 0..600 秒")
    deadline = time.monotonic() + timeout
    paths = (args.challenge, args.consumption_receipt)
    while True:
        if all(path.is_file() and not path.is_symlink() for path in paths):
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("Stage-C challenge/consumption receipt 未就绪")
        time.sleep(0.1)


def _assert_live_fault_driver(challenge: dict) -> None:
    assert_current_process_matches_workload(
        challenge["workloads"]["fault_driver"]
    )


def _verified_authorization(args, *, enforce_current_window: bool) -> tuple[dict, dict]:
    challenge_artifact = _json(
        args.challenge,
        label="Stage-C registrar challenge",
    )
    requested_scenario = (
        args.scenario
        if getattr(args, "scenario", None)
        else str(challenge_artifact.get("payload", {}).get("scenario", ""))
    )
    challenge = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=args.registrar_public_key,
        scenario=requested_scenario,
        now=None,
        enforce_current_window=enforce_current_window,
    )
    claims = verify_stage_c_consumption_receipt(
        _json(args.consumption_receipt, label="Stage-C consumption receipt"),
        challenge_artifact=challenge_artifact,
        registrar_public_key=args.registrar_public_key,
        consumer_public_key=args.consumer_public_key,
    )
    _assert_live_fault_driver(challenge)
    return challenge, claims


def _record_pre_intent_checkpoint(
    journal: SQLiteJournal,
    *,
    challenge: dict,
    consumption_claims: dict,
    inst_id: str,
) -> None:
    action_inventory = {
        "external-pending-buy": ["place_limit_buy", "reconcile"],
        "external-fill": ["place_market_buy", "reconcile", "protect"],
        "external-protection-cancel": ["cancel_owned_oco", "reconcile"],
        "frozen-balance": ["seed_position", "place_locking_sell", "reconcile"],
    }[challenge["scenario"]]
    payload = {
        "challenge_id": challenge["challenge_id"],
        "scenario": challenge["scenario"],
        "inst_id": inst_id,
        "challenge_sha256": hashlib.sha256(
            canonical_bytes(challenge)
        ).hexdigest(),
        "consumption_claims_sha256": hashlib.sha256(
            canonical_bytes(consumption_claims)
        ).hexdigest(),
        "action_inventory_sha256": hashlib.sha256(
            canonical_bytes(action_inventory)
        ).hexdigest(),
        "state": "authorized_before_exchange_mutation",
    }
    dedupe = f"stage-c-pre-intent:{challenge['challenge_id']}"
    created = journal.record_event_once(
        dedupe,
        "stage_c_external_pre_intent_authorized",
        severity="warning",
        correlation_id=challenge["challenge_id"],
        payload=payload,
    )
    if not created:
        matches = [
            item
            for item in journal.list_events(
                "stage_c_external_pre_intent_authorized"
            )
            if item["correlation_id"] == challenge["challenge_id"]
        ]
        if len(matches) != 1 or matches[0]["payload"] != payload:
            raise ValueError("Stage-C durable pre-intent checkpoint 冲突")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare")
    prepare.add_argument(
        "--scenario",
        choices=sorted(EXTERNAL_SCENARIOS),
    )
    prepare.add_argument("--challenge", required=True, type=Path)
    prepare.add_argument(
        "--registrar-public-key",
        required=True,
        type=Path,
    )
    prepare.add_argument(
        "--consumption-receipt",
        required=True,
        type=Path,
    )
    prepare.add_argument(
        "--consumer-public-key",
        required=True,
        type=Path,
    )
    prepare.add_argument("--inst", required=True)
    prepare.add_argument(
        "--start-after-driver-ready",
        type=Path,
        help="必须在任何 exchange mutation 前由 systemd acquirer 写入",
    )
    prepare.add_argument(
        "--hold-until",
        action="append",
        default=[],
        type=Path,
        help="写出 report 后保持同一 PID，直到所有 raw collection marker 就绪",
    )
    prepare.add_argument("--hold-timeout-seconds", type=float, default=0)
    _actor_args(prepare)

    cleanup = sub.add_parser("cleanup")
    cleanup.add_argument("--report", required=True, type=Path)
    cleanup.add_argument("--challenge", required=True, type=Path)
    cleanup.add_argument(
        "--registrar-public-key",
        required=True,
        type=Path,
    )
    cleanup.add_argument(
        "--consumption-receipt",
        required=True,
        type=Path,
    )
    cleanup.add_argument(
        "--consumer-public-key",
        required=True,
        type=Path,
    )
    cleanup.add_argument(
        "--required-collection",
        action="append",
        default=[],
        type=Path,
    )
    _actor_args(cleanup)

    self_check = sub.add_parser("self-check")
    self_check.add_argument(
        "--scenario",
        choices=sorted(EXTERNAL_SCENARIOS),
        required=True,
    )
    self_check.add_argument("--output", required=True, type=Path)

    manifest = sub.add_parser("manifest")
    manifest.add_argument("--output", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "manifest":
        _exclusive_json(
            args.output,
            {
                "schema": (
                    "okx-quant.stage-c-external-implementation-set/v1"
                ),
                "scenarios": external_scenario_implementation_manifests(),
            },
        )
        return 0
    if args.command == "self-check":
        _exclusive_json(
            args.output,
            external_scenario_mutation_self_check(args.scenario),
        )
        return 2
    if args.command == "prepare":
        _wait_for_authorization_files(args)
        challenge, consumption_claims = _verified_authorization(
            args,
            enforce_current_window=True,
        )
        if args.start_after_driver_ready is not None:
            deadline = (
                time.monotonic() + float(args.authorization_wait_seconds)
            )
            while not (
                args.start_after_driver_ready.is_file()
                and not args.start_after_driver_ready.is_symlink()
            ):
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "Stage-C actor 等待 driver invocation raw proof 超时"
                    )
                time.sleep(0.1)
        cfg, configured_journal = _validated_config(args.config)
        journal_path = args.journal or configured_journal
        actor = OKXDemoExternalActor(
            client=make_client(cfg),
            journal=SQLiteJournal(journal_path),
        )
        try:
            _record_pre_intent_checkpoint(
                actor.journal,
                challenge=challenge,
                consumption_claims=consumption_claims,
                inst_id=args.inst,
            )
            report = StageCExternalScenarioExecutor(
                actor,
                timeout_s=args.timeout,
                poll_interval_s=args.poll_interval,
            ).prepare(
                scenario=challenge["scenario"],
                challenge=challenge,
                inst_id=args.inst,
                confirmation=args.confirm,
            )
            _exclusive_json(args.output, report.as_dict(), mode=0o640)
            if not 0 <= args.hold_timeout_seconds <= 600:
                raise ValueError("Stage-C actor hold timeout 必须位于 0..600 秒")
            deadline = time.monotonic() + args.hold_timeout_seconds
            while not all(
                path.is_file() and not path.is_symlink()
                for path in args.hold_until
            ):
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "Stage-C actor 等待 final raw collection 超时"
                    )
                time.sleep(0.1)
            return 0 if report.status == "awaiting_independent_collection" else 1
        finally:
            actor.close()
    deadline = time.monotonic() + float(args.authorization_wait_seconds)
    while not all(
        path.is_file() and not path.is_symlink()
        for path in args.required_collection
    ):
        if time.monotonic() >= deadline:
            raise TimeoutError("Stage-C cleanup 等待独立 raw collection 超时")
        time.sleep(0.1)
    prepared = _report(
        _json(
            args.report,
            label="Stage-C prepared report",
        )
    )
    challenge, consumption_claims = _verified_authorization(
        args,
        enforce_current_window=False,
    )
    cfg, configured_journal = _validated_config(args.config)
    journal_path = args.journal or configured_journal
    actor = OKXDemoExternalActor(
        client=make_client(cfg),
        journal=SQLiteJournal(journal_path),
    )
    try:
        report = StageCExternalScenarioExecutor(
            actor,
            timeout_s=args.timeout,
            poll_interval_s=args.poll_interval,
        ).cleanup(
            prepared,
            confirmation=args.confirm,
            challenge=challenge,
            consumption_claims=consumption_claims,
        )
        _exclusive_json(args.output, report.as_dict())
        return 0 if report.status == "cleanup_completed" else 1
    finally:
        actor.close()


if __name__ == "__main__":
    raise SystemExit(main())
