#!/usr/bin/env python3
"""Run exact-release Demo Chaos WS/restart drills and retain every result."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import make_client
from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.config import ProductionSettings, load_yaml
from okx_quant.infrastructure.evidence import (
    build_release_identity,
    redacted_config_hash,
)
from okx_quant.ops.demo_chaos_evidence import (
    AUTOMATED_EXACT_RELEASE_SCENARIOS,
    INDEPENDENT_OBSERVATION_SCENARIOS,
    SCENARIO_BY_NAME,
    DrillArtifactClass,
    expected_transitions_for,
    scenario_names,
    validate_drill_receipt,
    verify_independent_raw_observation_artifact,
)
from okx_quant.ops.demo_preflight import DemoDeploymentProfile, balance_details

CONFIRMATION = "I_UNDERSTAND_DEMO_CHAOS"
SCENARIOS = scenario_names()
IMPLEMENTED_EXACT_RELEASE_SCENARIOS = AUTOMATED_EXACT_RELEASE_SCENARIOS


def _run(argv: list[str], *, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        text=True,
        capture_output=True,
        check=True,
        timeout=timeout,
    )


def _systemctl_show(unit: str) -> dict[str, str]:
    result = _run(
        [
            "systemctl",
            "show",
            unit,
            "--property=ActiveState,SubState,MainPID,FragmentPath",
            "--no-pager",
        ]
    )
    values = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    if (
        values.get("ActiveState") != "active"
        or values.get("SubState") != "running"
        or int(values.get("MainPID", "0")) <= 0
    ):
        raise RuntimeError(f"Chaos unit 未运行: {values}")
    return values


def _read_events(database: Path, *, since: float) -> list[dict]:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT event_id, event_name, severity, correlation_id,
                   payload_json, created_at
            FROM system_events
            WHERE created_at >= ?
            ORDER BY created_at, event_id
            """,
            (since,),
        ).fetchall()
    finally:
        connection.close()
    return [
        {
            **{
                key: row[key]
                for key in (
                    "event_id",
                    "event_name",
                    "severity",
                    "correlation_id",
                    "created_at",
                )
            },
            "payload": json.loads(row["payload_json"]),
        }
        for row in rows
    ]


def _mode(database: Path) -> str:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT value FROM system_state WHERE key='mode'"
        ).fetchone()
    finally:
        connection.close()
    return str(row[0]) if row else ""


def _reconciliations(database: Path, *, since: float) -> list[dict]:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT run_id, status, mismatch_count, repaired_count,
                   details_json, started_at, completed_at
            FROM reconciliation_runs
            WHERE started_at >= ?
            ORDER BY started_at, run_id
            """,
            (since,),
        ).fetchall()
    finally:
        connection.close()
    return [
        {
            "run_id": row["run_id"],
            "status": row["status"],
            "mismatch_count": row["mismatch_count"],
            "repaired_count": row["repaired_count"],
            "details": json.loads(row["details_json"]),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }
        for row in rows
    ]


def _integrity(database: Path) -> str:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
    finally:
        connection.close()
    return str(row[0]) if row else ""


def _page_receipt(
    database: Path,
    *,
    since: float,
    scenario: str,
) -> dict | None:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT d.event_id, o.event_name, o.payload_json,
                   d.provider_event_id, d.provider_artifact_sha256,
                   d.provider_received_at, d.human_ack_at
            FROM alert_deliveries AS d
            JOIN outbox_events AS o USING(event_id)
            WHERE d.priority='P0' AND o.created_at >= ?
            ORDER BY o.created_at DESC, d.event_id DESC
            """,
            (since,),
        ).fetchall()
    finally:
        connection.close()
    row = None
    fault_correlation = ""
    for candidate in rows:
        payload = json.loads(candidate["payload_json"])
        if (
            scenario.startswith("ws-")
            and candidate["event_name"]
            == "page.ws_error_budget_exhausted"
            and payload.get("channel") == scenario.removeprefix("ws-")
        ):
            row = candidate
            fault_correlation = str(payload["channel"])
            break
        if (
            scenario.startswith("restart-")
            and candidate["event_name"] == "page.external_watchdog"
        ):
            row = candidate
            fault_correlation = str(
                payload.get("unit") or payload.get("target") or ""
            )
            if fault_correlation:
                break
    if row is None:
        return None
    return {
        "required": True,
        "event_id": str(row["event_id"]),
        "event_name": str(row["event_name"]),
        "fault_correlation": fault_correlation,
        "provider_event_id": str(row["provider_event_id"]),
        "provider_artifact_sha256": str(
            row["provider_artifact_sha256"]
        ),
        "provider_received_at": row["provider_received_at"],
        "human_ack_at": row["human_ack_at"],
    }


def _wait_until(predicate, *, timeout: float, label: str) -> float:
    started = time.monotonic()
    deadline = started + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return time.monotonic() - started
            last = repr(value)
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(0.25)
    raise TimeoutError(f"{label} 未在 {timeout}s 达成；last={last}")


def _ready(profile: DemoDeploymentProfile) -> bool:
    result = subprocess.run(
        [
            "ip",
            "netns",
            "exec",
            profile.network_namespace.name,
            "curl",
            "--fail",
            "--silent",
            f"http://127.0.0.1:{profile.metrics_port}/readyz",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=3,
    )
    if result.returncode != 0:
        return False
    payload = json.loads(result.stdout)
    return payload.get("ready") is True


def _write_control(path: Path, state: str) -> None:
    if os.geteuid() != 0:
        raise PermissionError("Chaos fault control 必须由 root 操作")
    if state not in {"open", "blocked"}:
        raise ValueError("fault state 非法")
    if not path.is_relative_to("/run/okx-quant-chaos-fault"):
        raise ValueError("fault control 不在受控目录")
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("fault control owner/mode 非法")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
    )
    try:
        os.write(descriptor, (state + "\n").encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _buy_ids(client, *, since_ms: int) -> list[str]:
    return sorted(
        str(row.get("ordId", ""))
        for row in client.get_order_history(limit=100)
        if str(row.get("side", "")).lower() == "buy"
        and int(row.get("cTime", row.get("uTime", "0")) or 0) >= since_ms
    )


def _all_pending_algos(client) -> list[dict]:
    result = []
    for order_type in (
        "conditional",
        "oco",
        "trigger",
        "move_order_stop",
        "iceberg",
        "twap",
    ):
        result.extend(
            client.get(
                "/api/v5/trade/orders-algo-pending",
                {"ordType": order_type},
                auth=True,
            )
            or []
        )
    return result


def _postcondition(client, database: Path, *, since: float) -> dict:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        positions = [
            dict(row)
            for row in connection.execute(
                "SELECT inst_id, base_qty, protection_status FROM positions "
                "WHERE CAST(base_qty AS REAL) > 0"
            ).fetchall()
        ]
        duplicate_buy_count = int(
            connection.execute(
                """
                SELECT COALESCE(SUM(duplicate_buy_count), 0)
                FROM probe_runs WHERE created_at >= ?
                """,
                (since,),
            ).fetchone()[0]
        )
    finally:
        connection.close()
    algos = _all_pending_algos(client)
    protected = {
        str(row.get("instId", ""))
        for row in algos
        if str(row.get("state", "")).lower() in {"live", "effective"}
    }
    mode = _mode(database)
    uncovered = [
        row["inst_id"]
        for row in positions
        if row["inst_id"] not in protected
        and mode not in {"emergency_exit", "halted", "manual_review"}
    ]
    result = {
        "mode": mode,
        "journal_integrity": _integrity(database),
        "pending_order_count": len(client.get_open_orders()),
        "pending_algo_count": len(algos),
        "local_nonzero_position_count": len(positions),
        "duplicate_buy_count": duplicate_buy_count,
        "uncovered_instruments": uncovered,
        "balances": {
            ccy: str(quantity)
            for ccy, quantity in sorted(
                balance_details(client.get_balance()).items()
            )
            if quantity > 0
        },
        "reconciliations": _reconciliations(database, since=since),
    }
    if result["journal_integrity"] != "ok" or uncovered:
        raise RuntimeError(f"Chaos post-condition 失败: {result}")
    return result


def _receipt_reconciliation(postcondition: dict) -> dict:
    rows = postcondition.get("reconciliations", [])
    unresolved: list[str] = []
    for row in rows:
        details = row.get("details", {})
        values = details.get("unresolved", []) if isinstance(details, dict) else []
        if isinstance(values, list):
            unresolved.extend(str(item) for item in values if str(item))
        if row.get("status") not in {"ok"}:
            unresolved.append(
                f"{row.get('run_id', 'unknown')}:{row.get('status', 'missing')}"
            )
    return {
        "required": True,
        "run_ids": [str(row["run_id"]) for row in rows],
        "mismatch_count": sum(int(row["mismatch_count"]) for row in rows),
        "repaired_count": sum(int(row["repaired_count"]) for row in rows),
        "unresolved": sorted(set(unresolved)),
    }


def _receipt_postcondition(
    postcondition: dict,
    *,
    startup_reconciliation_seconds: float | None,
) -> dict:
    uncovered = [
        str(item) for item in postcondition.get("uncovered_instruments", [])
    ]
    reconciliation = _receipt_reconciliation(postcondition)
    residual = list(uncovered)
    residual.extend(reconciliation["unresolved"])
    if postcondition.get("journal_integrity") != "ok":
        residual.append("journal_integrity_not_ok")
    return {
        "journal_integrity": str(
            postcondition.get("journal_integrity", "unknown")
        ),
        "mode": str(postcondition.get("mode", "")),
        "duplicate_buy_count": int(
            postcondition.get("duplicate_buy_count", 0)
        ),
        "uncovered_instruments": uncovered,
        "pending_order_count": int(
            postcondition.get("pending_order_count", 0)
        ),
        "pending_algo_count": int(
            postcondition.get("pending_algo_count", 0)
        ),
        "local_nonzero_position_count": int(
            postcondition.get("local_nonzero_position_count", 0)
        ),
        "balances": dict(postcondition.get("balances", {})),
        "residual_risk": sorted(set(residual)),
        "startup_reconciliation_seconds": startup_reconciliation_seconds,
    }


def _failed_postcondition() -> dict:
    return {
        "journal_integrity": "unknown",
        "mode": "",
        "duplicate_buy_count": 0,
        "uncovered_instruments": [],
        "pending_order_count": 0,
        "pending_algo_count": 0,
        "local_nonzero_position_count": 0,
        "balances": {},
        "residual_risk": ["postcondition_unavailable"],
        "startup_reconciliation_seconds": None,
    }


def _load_raw_observation(
    path: Path,
    *,
    public_key: Path,
) -> tuple[dict, dict]:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size <= 0
        or path.stat().st_size > 2 * 1024 * 1024
    ):
        raise RuntimeError(
            "independent raw observation 必须是 2MiB 内普通文件"
        )
    artifact = json.loads(path.read_text(encoding="utf-8"))
    claims = verify_ed25519_artifact(
        artifact,
        public_key,
        label="independent raw chaos observation",
    )
    return artifact, claims


def _actual_transitions(
    scenario: str,
    details: dict,
) -> list[dict]:
    expected = expected_transitions_for(scenario)
    if scenario.startswith("ws-") and scenario in IMPLEMENTED_EXACT_RELEASE_SCENARIOS:
        degraded_at = float(details["degraded_observed_at"])
        recovered_at = float(details["recovery_observed_at"])
        evidence_ids = [str(item) for item in details["event_ids"]]
        return [
            {
                "transition_id": expected[0]["transition_id"],
                "from_state": expected[0]["from_state"],
                "to_state": expected[0]["to_state"],
                "observed_at": datetime.fromtimestamp(
                    degraded_at,
                    UTC,
                ).isoformat(),
                "evidence_ids": evidence_ids,
            },
            {
                "transition_id": expected[1]["transition_id"],
                "from_state": expected[1]["from_state"],
                "to_state": expected[1]["to_state"],
                "observed_at": datetime.fromtimestamp(
                    recovered_at,
                    UTC,
                ).isoformat(),
                "evidence_ids": [
                    str(details["recovery_event_id"]),
                    f"ws-generation:{details['generation']}",
                ],
            },
        ]
    if scenario in {"restart-sigterm", "restart-sigkill"}:
        restart_at = datetime.fromisoformat(
            str(details["fault_started_at"])
        ).timestamp()
        ready_at = float(details["ready_observed_at"])
        return [
            {
                "transition_id": expected[0]["transition_id"],
                "from_state": expected[0]["from_state"],
                "to_state": expected[0]["to_state"],
                "observed_at": datetime.fromtimestamp(
                    restart_at,
                    UTC,
                ).isoformat(),
                "evidence_ids": [
                    f"systemd-old-pid:{details['old_pid']}",
                    f"signal:{details['signal']}",
                ],
            },
            {
                "transition_id": expected[1]["transition_id"],
                "from_state": expected[1]["from_state"],
                "to_state": expected[1]["to_state"],
                "observed_at": datetime.fromtimestamp(
                    ready_at,
                    UTC,
                ).isoformat(),
                "evidence_ids": [
                    f"systemd-new-pid:{details['new_pid']}",
                    str(details["fragment_path"]),
                ],
            },
        ]
    return []


def _ws_scenario(
    *,
    channel: str,
    profile: DemoDeploymentProfile,
    database: Path,
    client,
) -> dict:
    if not _ready(profile):
        raise RuntimeError("WS drill 开始前 runtime 不是 READY")
    control = Path(f"/run/okx-quant-chaos-fault/{channel}.state")
    started = time.time()
    since_ms = int(started * 1000)
    _write_control(control, "blocked")
    try:
        degraded_s = _wait_until(
            lambda: _mode(database) in {
                "degraded",
                "halted",
                "emergency_exit",
                "manual_review",
            },
            timeout=20,
            label=f"{channel} 断线降级",
        )
        degraded_observed_at = time.time()
        buys_during_fault = _buy_ids(client, since_ms=since_ms)
        if buys_during_fault:
            raise RuntimeError(
                f"{channel} 断线期间出现 BUY: {buys_during_fault}"
            )
    finally:
        _write_control(control, "open")
    recovery_s = _wait_until(
        lambda: _ready(profile),
        timeout=60,
        label=f"{channel} REST baseline 后 READY",
    )
    recovery_observed_at = time.time()
    events = _read_events(database, since=started)
    recovery = [
        row
        for row in events
        if row["event_name"] == "websocket_recovery_completed"
        and row["payload"].get("channel") == channel
        and row["payload"].get("safe") is True
    ]
    subscriptions = [
        row
        for row in events
        if row["event_name"] == "websocket_subscription_ready"
        and row["payload"].get("channel") == channel
    ]
    if (
        not recovery
        or not subscriptions
        or recovery[-1]["payload"].get("generation")
        != subscriptions[-1]["payload"].get("generation")
    ):
        raise RuntimeError(
            f"{channel} 未证明同 generation subscribe + REST baseline"
        )
    return {
        "channel": channel,
        "fault_started_at": datetime.fromtimestamp(started, UTC).isoformat(),
        "degraded_within_seconds": degraded_s,
        "recovered_within_seconds": recovery_s,
        "degraded_observed_at": degraded_observed_at,
        "recovery_observed_at": recovery_observed_at,
        "buy_order_ids_during_fault": buys_during_fault,
        "event_ids": [row["event_id"] for row in events],
        "event_trace": events,
        "recovery_event_id": recovery[-1]["event_id"],
        "generation": recovery[-1]["payload"]["generation"],
    }


def _restart_scenario(
    *,
    signal: str,
    unit: str,
    profile: DemoDeploymentProfile,
    database: Path,
    client,
) -> dict:
    before_state = _postcondition(client, database, since=0)
    if (
        before_state["local_nonzero_position_count"] != 0
        or before_state["pending_order_count"] != 0
        or before_state["pending_algo_count"] != 0
    ):
        raise RuntimeError(
            f"{signal} flat restart 前账户并非 flat: {before_state}"
        )
    before = _systemctl_show(unit)
    started = time.time()
    if signal == "SIGTERM":
        _run(["systemctl", "restart", unit], timeout=180)
    else:
        _run(
            [
                "systemctl",
                "kill",
                "--kill-who=main",
                f"--signal={signal}",
                unit,
            ]
        )
    ready_s = _wait_until(
        lambda: (
            _systemctl_show(unit)["MainPID"] != before["MainPID"]
            and _ready(profile)
        ),
        timeout=60,
        label=f"{signal} 后新 PID READY",
    )
    ready_observed_at = time.time()
    after = _systemctl_show(unit)
    return {
        "signal": signal,
        "fault_started_at": datetime.fromtimestamp(started, UTC).isoformat(),
        "old_pid": int(before["MainPID"]),
        "new_pid": int(after["MainPID"]),
        "ready_within_seconds": ready_s,
        "ready_observed_at": ready_observed_at,
        "fragment_path": after["FragmentPath"],
        "flat_precondition": {
            "local_nonzero_position_count": 0,
            "pending_order_count": 0,
            "pending_algo_count": 0,
        },
    }


def _publish(
    *,
    result_path: Path,
    identity_path: Path,
    args: argparse.Namespace,
) -> None:
    _run(
        [
            sys.executable,
            str(Path(__file__).with_name("immutable_evidence_bundle.py")),
            "publish",
            "--kind",
            (
                "chaos"
                if SCENARIO_BY_NAME[args.scenario].work_package == "WP4"
                else "restart"
            ),
            "--identity",
            str(identity_path),
            "--component",
            f"drill-result={result_path}",
            "--s3-prefix",
            args.s3_prefix,
            "--retain-until",
            args.retain_until,
            "--kms-key-id",
            args.kms_key_id,
            "--private-key",
            str(args.bundle_private_key),
            "--signing-key-id",
            args.signing_key_id,
            "--manifest-output",
            str(args.manifest_output),
            "--receipt-output",
            str(args.bundle_receipt_output),
        ],
        timeout=300,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--scenario", required=True, choices=SCENARIOS)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--soak-epoch-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--identity-output", required=True, type=Path)
    parser.add_argument("--manifest-output", required=True, type=Path)
    parser.add_argument("--bundle-receipt-output", required=True, type=Path)
    parser.add_argument("--s3-prefix", required=True)
    parser.add_argument("--retain-until", required=True)
    parser.add_argument("--kms-key-id", required=True)
    parser.add_argument("--bundle-private-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--page-receipt-timeout", type=float, default=60)
    parser.add_argument("--raw-observation", type=Path)
    parser.add_argument("--raw-observation-public-key", type=Path)
    parser.add_argument("--observation-challenge-id", default="")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"--confirm 必须为 {CONFIRMATION}")
    spec = SCENARIO_BY_NAME[args.scenario]
    if spec.artifact_class is DrillArtifactClass.INSTRUMENTED_TEST_ONLY:
        raise SystemExit(
            "instrumented barrier 禁止由 exact-release Chaos runner 执行；"
            "必须使用不同 test-only artifact identity/harness"
        )
    independent_adapter = (
        args.scenario in INDEPENDENT_OBSERVATION_SCENARIOS
    )
    if independent_adapter and (
        args.raw_observation is None
        or args.raw_observation_public_key is None
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            args.observation_challenge_id,
        )
    ):
        raise SystemExit(
            f"{args.scenario} 禁止本机手填结果；必须提供独立签名 "
            "--raw-observation、--raw-observation-public-key 和 "
            "32-hex --observation-challenge-id"
        )
    if not independent_adapter and (
        args.raw_observation is not None
        or args.raw_observation_public_key is not None
        or args.observation_challenge_id
    ):
        raise SystemExit(
            f"{args.scenario} 使用 automated_control adapter，"
            "禁止注入 raw observation"
        )
    if (
        not math.isfinite(args.page_receipt_timeout)
        or not 1 <= args.page_receipt_timeout <= 300
    ):
        raise SystemExit("--page-receipt-timeout 必须位于 1..300 秒")
    for path in (
        args.output,
        args.identity_output,
        args.manifest_output,
        args.bundle_receipt_output,
    ):
        if path.exists() or path.is_symlink():
            raise SystemExit(f"拒绝覆盖证据: {path}")
    cfg = load_yaml(str(args.config))
    settings = ProductionSettings.from_config(
        cfg,
        require_external_controls=False,
    )
    profile = DemoDeploymentProfile.from_config(cfg)
    if (
        settings.environment != "demo"
        or cfg.get("okx", {}).get("simulated") is not True
        or profile.role != "chaos"
        or settings.shadow_mode
    ):
        raise SystemExit("Chaos matrix 只允许隔离 demo-chaos 配置")
    account = make_client(cfg).get_account_config()
    if str(account.get("uid", "")) != profile.account_uid:
        raise SystemExit("Chaos account UID 与配置不一致")
    release = build_release_identity(profile.release_root)
    if not release["workspace_clean"]:
        raise SystemExit("Chaos matrix 只接受 clean exact release")
    bundle_identity = {
        "git_commit": release["git_commit"],
        "config_sha256": redacted_config_hash(cfg),
        "account_uid": profile.account_uid,
        "environment": "demo",
        "unit": profile.unit_name,
        "soak_epoch_id": args.soak_epoch_id,
        "phase": "chaos",
    }
    args.identity_output.parent.mkdir(parents=True, exist_ok=True)
    args.identity_output.write_text(
        json.dumps(bundle_identity, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    receipt_identity = {
        "git_commit": release["git_commit"],
        "git_tree_hash": release["git_tree_hash"],
        "source_manifest_sha256": release["source_manifest_sha256"],
        "artifact_sha256": release["source_manifest_sha256"],
        "artifact_build_id": (
            f"exact-release:{release['git_commit']}:"
            f"{release['source_manifest_sha256'][:16]}"
        ),
        "config_sha256": bundle_identity["config_sha256"],
        "account_uid": profile.account_uid,
        "environment": "demo",
        "unit": profile.unit_name,
        "soak_epoch_id": args.soak_epoch_id,
        "workspace_clean": release["workspace_clean"],
        "test_hooks_present": False,
    }
    started = time.time()
    run_id = (
        args.observation_challenge_id
        if independent_adapter
        else uuid.uuid4().hex
    )
    errors: list[str] = []
    details: dict = {}
    raw_observation: dict | None = None
    raw_claims: dict | None = None
    client = make_client(cfg)
    if independent_adapter:
        assert args.raw_observation is not None
        assert args.raw_observation_public_key is not None
        raw_observation, raw_claims = _load_raw_observation(
            args.raw_observation,
            public_key=args.raw_observation_public_key,
        )
        if (
            raw_claims.get("scenario") != args.scenario
            or raw_claims.get("challenge_id") != run_id
            or raw_claims.get("identity") != receipt_identity
        ):
            raise SystemExit(
                "independent raw observation 未绑定当前 "
                "scenario/challenge/exact release identity"
            )
        started = datetime.fromisoformat(
            str(raw_claims["started_at"])
        ).timestamp()
        errors = list(raw_claims.get("errors", []))
    else:
        try:
            _systemctl_show(profile.unit_name)
            if args.scenario in {"ws-public", "ws-private", "ws-business"}:
                details = _ws_scenario(
                    channel=args.scenario.removeprefix("ws-"),
                    profile=profile,
                    database=Path(settings.journal_path),
                    client=client,
                )
            else:
                details = _restart_scenario(
                    signal=(
                        "SIGTERM"
                        if args.scenario == "restart-sigterm"
                        else "SIGKILL"
                    ),
                    unit=profile.unit_name,
                    profile=profile,
                    database=Path(settings.journal_path),
                    client=client,
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{type(exc).__name__}: {exc}")
    page_receipt = {
        "required": True,
        "event_id": "",
        "event_name": "",
        "fault_correlation": "",
        "provider_event_id": "",
        "provider_artifact_sha256": "",
        "provider_received_at": None,
        "human_ack_at": None,
    }
    if independent_adapter:
        assert raw_claims is not None
        page_receipt = raw_claims["page_receipt"]
    else:
        try:
            _wait_until(
                lambda: (
                    (receipt := _page_receipt(
                        Path(settings.journal_path),
                        since=started,
                        scenario=args.scenario,
                    ))
                    and receipt["provider_received_at"] is not None
                    and receipt
                ),
                timeout=args.page_receipt_timeout,
                label="Page provider receipt",
            )
            page_receipt = _page_receipt(
                Path(settings.journal_path),
                since=started,
                scenario=args.scenario,
            ) or page_receipt
        except Exception as exc:  # noqa: BLE001
            errors.append(f"page receipt: {type(exc).__name__}: {exc}")
    raw_postcondition: dict = {}
    if independent_adapter:
        assert raw_claims is not None
        reconciliation = raw_claims["reconciliation"]
        postcondition = raw_claims["postcondition"]
        completed = datetime.fromisoformat(
            str(raw_claims["completed_at"])
        )
    else:
        try:
            raw_postcondition = _postcondition(
                client,
                Path(settings.journal_path),
                since=started,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"postcondition: {type(exc).__name__}: {exc}")
        startup_seconds = (
            float(details["ready_within_seconds"])
            if "ready_within_seconds" in details
            else None
        )
        reconciliation = (
            _receipt_reconciliation(raw_postcondition)
            if raw_postcondition
            else {
                "required": True,
                "run_ids": [],
                "mismatch_count": 0,
                "repaired_count": 0,
                "unresolved": ["reconciliation_unavailable"],
            }
        )
        postcondition = (
            _receipt_postcondition(
                raw_postcondition,
                startup_reconciliation_seconds=startup_seconds,
            )
            if raw_postcondition
            else _failed_postcondition()
        )
        completed = datetime.now(UTC)
    result = {
        "version": 2,
        "action": "attest-demo-chaos-drill-v2",
        "scenario": args.scenario,
        "work_package": spec.work_package,
        "artifact_class": spec.artifact_class.value,
        "started_at": datetime.fromtimestamp(started, UTC).isoformat(),
        "completed_at": completed.isoformat(),
        "identity": receipt_identity,
        "execution": {
            "run_id": run_id,
            "executor": "scripts/demo_chaos_matrix.py",
            "host_id": os.uname().nodename,
            "fault_mechanism": (
                str(raw_claims["fault_mechanism"])
                if raw_claims is not None
                else args.scenario
            ),
            "evidence_origin": "real_demo_black_box",
            "adapter": (
                "independent_raw_observation"
                if independent_adapter
                else "automated_control"
            ),
            "raw_observation": raw_observation,
        },
        "expected_transitions": expected_transitions_for(args.scenario),
        "actual_transitions": (
            raw_claims["actual_transitions"]
            if raw_claims is not None
            else (
                _actual_transitions(
                    args.scenario,
                    details,
                )
                if details
                else []
            )
        ),
        "reconciliation": reconciliation,
        "page_receipt": page_receipt,
        "postcondition": postcondition,
        "errors": errors,
        "passed": not errors,
    }
    try:
        validate_drill_receipt(result)
    except ValueError as exc:
        if result["passed"]:
            result["errors"].append(f"strict receipt acceptance: {exc}")
            result["passed"] = False
            validate_drill_receipt(result)
        else:
            raise
    if independent_adapter:
        assert args.raw_observation_public_key is not None
        verify_independent_raw_observation_artifact(
            raw_observation,
            receipt=result,
            observer_public_key=args.raw_observation_public_key,
            publisher_key=args.bundle_private_key,
            publisher_key_is_private=True,
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )
    _publish(
        result_path=args.output,
        identity_path=args.identity_output,
        args=args,
    )
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
