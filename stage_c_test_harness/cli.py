"""Fixed command surface for the isolated Stage-C barrier artifact."""

from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import stat
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from main import load_config, load_env_file
from okx_quant.application.approval import (
    canonical_bytes,
    production_config_hash,
    verify_ed25519_artifact,
)
from okx_quant.config import ProductionSettings
from okx_quant.infrastructure.evidence import ed25519_public_key_fingerprint
from okx_quant.ops.demo_preflight import normalize_okx_permissions
from okx_quant.ops.stage_c_chaos_protocol import (
    verify_stage_c_challenge,
    verify_stage_c_consumption_receipt,
)
from stage_c_test_harness.barriers import (
    BARRIER_SCENARIOS,
    BarrierHook,
    BarrierStateStore,
    _atomic_new,
    _safe_json,
    attest_barrier_reached,
    barrier_capability_self_check,
    consume_barrier_phase_globally,
    execute_systemd_kill,
    load_marker,
    validate_recovery_bundle,
)
from stage_c_test_harness.pipeline import (
    activate_pipeline_barrier,
    build_pipeline_runtime,
    fixed_pipeline_main_argv,
    read_self_cgroup,
    stage_c_application_preflight,
    tls_certificate_identity,
    verify_pipeline_activation,
    verify_pipeline_recovery_activation,
    wait_for_pipeline_activation,
)
from stage_c_test_harness.recovery import (
    assemble_native_recovery_bundle,
    collect_journal_recovery_payload,
    collect_okx_recovery_payload,
    collect_systemd_recovery_payload,
    project_native_recovery_bundle,
    sign_recovery_source_payload,
    verify_recovery_source_artifact,
)
from stage_c_test_harness.tls_ack_proxy import (
    TLSAckHoldingProxyController,
    TLSDemoPassthroughController,
    build_tls_ack_holding_server,
    build_tls_demo_passthrough_server,
)


def _challenge(args) -> tuple[dict, dict]:
    artifact = _safe_json(args.challenge, label="registrar challenge")
    claims = verify_stage_c_challenge(
        artifact,
        registrar_public_key=args.registrar_public_key,
        scenario=args.scenario,
        now=None,
        enforce_current_window=True,
    )
    return artifact, claims


def _backend(path: Path) -> dict:
    return _safe_json(path, label="DynamoDB backend")


def _read_scenario_file(path: Path) -> str:
    """Read a run-scoped scenario credential without following links."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("Stage-C scenario credential 无法安全读取") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 256:
            raise ValueError("Stage-C scenario credential 类型/长度非法")
        raw = b""
        while len(raw) <= 256:
            chunk = os.read(fd, 257 - len(raw))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (
        len(raw) > 256
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise ValueError("Stage-C scenario credential 读取期间发生变化")
    try:
        scenario = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Stage-C scenario credential 必须为 ASCII") from exc
    if scenario not in BARRIER_SCENARIOS or raw.strip() != scenario.encode():
        raise ValueError("Stage-C scenario credential 内容非法")
    return scenario


def _add_scenario_argument(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", choices=sorted(BARRIER_SCENARIOS))
    group.add_argument("--scenario-file", type=Path)


def _resolve_scenario(args: argparse.Namespace) -> None:
    path = getattr(args, "scenario_file", None)
    if path is not None:
        args.scenario = _read_scenario_file(path)


def _wait_json(path: Path, *, label: str, timeout_seconds: int) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_symlink():
            raise ValueError(f"{label} 禁止符号链接")
        if path.is_file():
            return _safe_json(path, label=label)
        time.sleep(0.05)
    raise TimeoutError(f"等待 {label} 超时")


def _load_trader_account_binding(
    okx_cfg: dict,
    *,
    expected_account_uid: str,
) -> tuple[dict, tuple[str, ...], str]:
    """Acquire the actual trader key UID/permissions before activation."""
    from okx_quant.client.rest import OKXRestClient

    api_key = str(okx_cfg.get("api_key", ""))
    account_config = OKXRestClient(
        api_key=api_key,
        secret_key=str(okx_cfg.get("secret_key", "")),
        passphrase=str(okx_cfg.get("passphrase", "")),
        simulated=True,
        proxy=str(okx_cfg.get("proxy", "")),
        base_url="https://openapi.okx.com",
        timeout=int(okx_cfg.get("timeout", 15)),
        max_retries=1,
    ).get_account_config()
    actual_permissions = tuple(sorted(normalize_okx_permissions(
        account_config.get("perm")
    )))
    if (
        str(account_config.get("uid", "")) != expected_account_uid
        or actual_permissions != ("read", "trade")
    ):
        raise ValueError("Stage-C trader API key UID/权限 未绑定 challenge config")
    return (
        account_config,
        actual_permissions,
        hashlib.sha256(api_key.encode()).hexdigest(),
    )


def _run_pipeline(args) -> int:
    request = wait_for_pipeline_activation(
        args.activation_request,
        timeout_seconds=args.activation_wait_seconds,
    )
    load_env_file(str(args.env_file))
    cfg = load_config(str(args.config))
    settings = ProductionSettings.from_config(cfg)
    okx_cfg = cfg.get("okx", {})
    expected_base_url = (
        "https://127.0.0.1:9443"
        if args.scenario == "barrier-post-before-ack"
        else "https://openapi.okx.com"
    )
    if (
        settings.environment != "demo"
        or settings.shadow_mode
        or args.inst not in settings.allowed_instruments
        or set(settings.api_permissions) != {"read", "trade"}
        or cfg.get("okx", {}).get("simulated") is not True
        or cfg.get("okx", {}).get("base_url") != expected_base_url
    ):
        raise ValueError(
            "Stage-C pipeline 只允许隔离 Active Demo validation-probe 配置"
        )
    account_config, actual_permissions, api_key_fingerprint = (
        _load_trader_account_binding(
            okx_cfg,
            expected_account_uid=settings.account_id,
        )
    )
    main_argv = fixed_pipeline_main_argv(
        config=args.config.resolve(),
        env_file=args.env_file.resolve(),
        inst_id=args.inst,
    )
    archive_arg = Path(sys.argv[0])
    if archive_arg.is_symlink():
        raise ValueError("Stage-C instrumented archive 禁止符号链接")
    archive_path = archive_arg.resolve(strict=True)
    interpreter_path = Path("/proc/self/exe").resolve(strict=True)
    recovery_mode = args.marker_output.is_file()
    if args.marker_output.is_symlink():
        raise ValueError("Stage-C marker 禁止符号链接")
    activation_arguments = {
        "request": request,
        "scenario": args.scenario,
        "registrar_public_key": args.registrar_public_key,
        "challenge_consumer_public_key": (
            args.challenge_consumer_public_key
        ),
        "fault_driver_private_key": args.fault_driver_private_key,
        "config_sha256": production_config_hash(settings, cfg),
        "account_uid": str(account_config["uid"]),
        "api_key_fingerprint": api_key_fingerprint,
        "api_permissions": actual_permissions,
        "main_argv": main_argv,
        "archive_path": archive_path,
        "interpreter_path": interpreter_path,
        "actual_pid": os.getpid(),
        "actual_uid": os.getuid(),
        "actual_cgroup": read_self_cgroup(),
        "actual_invocation_id": os.environ.get("INVOCATION_ID", ""),
        **(
            tls_certificate_identity(args.tls_certificate)
            if args.scenario == "barrier-post-before-ack"
            and args.tls_certificate is not None
            else {
                "tls_certificate_sha256": None,
                "tls_spki_sha256": None,
            }
        ),
    }
    if recovery_mode:
        challenge, activation, activation_claims = (
            verify_pipeline_recovery_activation(
            **activation_arguments,
            kill_artifact=_wait_json(
                args.kill_artifact,
                label="Stage-C kill artifact",
                timeout_seconds=args.activation_wait_seconds,
            ),
            kill_public_key=args.kill_public_key,
            include_claims=True,
            )
        )
        _atomic_new(
            args.recovery_activation_attestation_output,
            activation,
            mode=0o640,
        )
    else:
        challenge, activation, activation_claims = verify_pipeline_activation(
            **activation_arguments,
            include_claims=True,
        )
        _atomic_new(args.activation_attestation_output, activation, mode=0o640)
    invocation_id = challenge["workloads"]["fault_driver"][
        "systemd_invocation_id"
    ]
    proxy_server = None
    if args.scenario == "barrier-post-before-ack":
        if args.tls_certificate is None or args.tls_private_key is None:
            raise ValueError("POST-before-ACK 缺少隔离 TLS proxy credential")
        if recovery_mode:
            proxy_server = build_tls_demo_passthrough_server(
                host="127.0.0.1",
                port=9443,
                certificate=args.tls_certificate,
                private_key=args.tls_private_key,
                controller=TLSDemoPassthroughController(),
            )
        else:
            hook = BarrierHook(
                challenge=challenge,
                state_store=BarrierStateStore(args.state_database),
                marker_output=args.marker_output,
                systemd_invocation_id=invocation_id,
                pid=os.getpid(),
            )
            controller = TLSAckHoldingProxyController(
                challenge=challenge,
                hook=hook,
                proof_output=args.proof_output,
                upstream_base_url="https://openapi.okx.com",
                target_pid=os.getpid(),
            )
            proxy_server = build_tls_ack_holding_server(
                host="127.0.0.1",
                port=9443,
                certificate=args.tls_certificate,
                private_key=args.tls_private_key,
                controller=controller,
            )
        threading.Thread(
            target=proxy_server.serve_forever,
            name="stage-c-tls-ack-proxy",
            daemon=True,
        ).start()
    elif not recovery_mode:
        activate_pipeline_barrier(build_pipeline_runtime(
            challenge=challenge,
            state_database=args.state_database,
            marker_output=args.marker_output,
            proof_output=args.proof_output,
            systemd_invocation_id=invocation_id,
            pid=os.getpid(),
        ))
    # Exact-release main.py is untouched.  The hermetic instrumented wrapper
    # installs the challenge-bound process receipt only for this invocation.
    import main as application_module
    from okx_quant.application.demo_probe import DemoProbeSaga, ProbeState
    from okx_quant.application.runtime import ProductionRuntime

    previous_argv = sys.argv
    previous_preflight = application_module._validate_demo_deployment
    previous_make_client = application_module.make_client
    previous_runtime_start = ProductionRuntime.start
    previous_probe_advance = DemoProbeSaga._advance_state
    application_module._validate_demo_deployment = (
        lambda parsed_args, parsed_cfg, parsed_settings, **_kwargs: (
            stage_c_application_preflight(
                parsed_args,
                parsed_cfg,
                parsed_settings,
                challenge=challenge,
                activation=activation_claims,
                process_argv=list(sys.argv),
            )
        )
    )
    if args.scenario == "barrier-post-before-ack":
        ca_bundle = str(args.tls_certificate.resolve(strict=True))

        def _stage_c_make_client(parsed_cfg):
            client = previous_make_client(parsed_cfg)
            client.ca_bundle = ca_bundle
            client._reset_session()
            return client

        application_module.make_client = _stage_c_make_client
    if recovery_mode:
        # Hold the recovered validation probe at the first safely protected
        # state.  Without this test-only evidence hold, the normal saga would
        # immediately cancel protection/exit and cross-source final cuts could
        # describe states that never coexisted.
        def _held_probe_advance(self, row, *, owner, fencing_token):
            if ProbeState(row["state"]) is ProbeState.PROTECTED:
                return row
            return previous_probe_advance(
                self,
                row,
                owner=owner,
                fencing_token=fencing_token,
            )

        def _checkpointed_runtime_start(self):
            previous_runtime_start(self)
            with sqlite3.connect(str(self.journal.path)) as connection:
                reconciliation = connection.execute(
                    "SELECT run_id, completed_at FROM reconciliation_runs "
                    "WHERE status='ok' AND completed_at IS NOT NULL "
                    "ORDER BY started_at DESC, run_id DESC LIMIT 1"
                ).fetchone()
            if reconciliation is None:
                raise RuntimeError("Stage-C recovery checkpoint 缺少完成的 reconciliation")
            invocation = os.environ.get("INVOCATION_ID", "")
            checkpoint_id = hashlib.sha256(canonical_bytes({
                "challenge_id": challenge["challenge_id"],
                "pid": os.getpid(),
                "systemd_invocation_id": invocation,
                "reconciliation_run_id": reconciliation[0],
            })).hexdigest()
            self.journal.record_event(
                "stage_c_recovery_evidence_ready",
                correlation_id=challenge["challenge_id"],
                payload={
                    "checkpoint_id": checkpoint_id,
                    "challenge_id": challenge["challenge_id"],
                    "scenario": challenge["scenario"],
                    "pid": os.getpid(),
                    "systemd_invocation_id": invocation,
                    "reconciliation_run_id": reconciliation[0],
                    "reconciliation_completed_at": reconciliation[1],
                    "evidence_hold": True,
                },
            )

        DemoProbeSaga._advance_state = _held_probe_advance
        ProductionRuntime.start = _checkpointed_runtime_start
    sys.argv = main_argv
    try:
        application_module.main()
    finally:
        sys.argv = previous_argv
        application_module._validate_demo_deployment = previous_preflight
        application_module.make_client = previous_make_client
        ProductionRuntime.start = previous_runtime_start
        DemoProbeSaga._advance_state = previous_probe_advance
        if proxy_server is not None:
            proxy_server.server_close()
    raise RuntimeError(
        "Stage-C instrumented trader 在到达/被杀 barrier 前异常退出"
    )


def _collect_recovery(args) -> int:
    _artifact, challenge = _challenge(args)
    reached_artifact = _safe_json(
        args.reached_artifact,
        label="Stage-C reached artifact",
    )
    kill_artifact = _safe_json(
        args.kill_artifact,
        label="Stage-C kill artifact",
    )
    native = assemble_native_recovery_bundle(
        challenge=challenge,
        marker_path=args.marker,
        proof_path=args.proof,
        source_artifacts={
            "journal_collector": _safe_json(
                args.journal_artifact,
                label="Stage-C journal source artifact",
            ),
            "okx_collector": _safe_json(
                args.okx_artifact,
                label="Stage-C OKX source artifact",
            ),
            "systemd_collector": _safe_json(
                args.systemd_artifact,
                label="Stage-C systemd source artifact",
            ),
        },
        journal_readiness_artifact=_safe_json(
            args.journal_readiness_artifact,
            label="Stage-C journal readiness artifact",
        ),
        source_public_keys={
            "journal_collector": args.journal_public_key,
            "okx_collector": args.okx_public_key,
            "systemd_collector": args.systemd_public_key,
        },
        reached_artifact=reached_artifact,
        kill_artifact=kill_artifact,
    )
    core = project_native_recovery_bundle(
        native,
        challenge=challenge,
        reached_artifact=reached_artifact,
        reached_public_key=args.reached_public_key,
        kill_artifact=kill_artifact,
        kill_public_key=args.kill_public_key,
        source_public_keys={
            "journal_collector": args.journal_public_key,
            "okx_collector": args.okx_public_key,
            "systemd_collector": args.systemd_public_key,
        },
    )
    validate_recovery_bundle(
        core,
        challenge=challenge,
        reached_artifact=reached_artifact,
        reached_public_key=args.reached_public_key,
        kill_artifact=kill_artifact,
        kill_public_key=args.kill_public_key,
    )
    _atomic_new(args.native_output, native, mode=0o640)
    _atomic_new(args.core_output, core, mode=0o640)
    return 0


def _collect_recovery_source(args, *, challenge: dict | None = None) -> int:
    if challenge is None:
        _artifact, challenge = _challenge(args)
    reached_artifact = _safe_json(
        args.reached_artifact,
        label="Stage-C source reached artifact",
    )
    kill_artifact = _safe_json(
        args.kill_artifact,
        label="Stage-C source kill artifact",
    )
    reached = verify_ed25519_artifact(
        reached_artifact,
        args.reached_public_key,
        label="Stage-C source reached",
    )
    killed = verify_ed25519_artifact(
        kill_artifact,
        args.kill_public_key,
        label="Stage-C source kill",
    )
    if (
        ed25519_public_key_fingerprint(args.reached_public_key)
        != challenge["barrier_attestor_key_fingerprint"]
        or ed25519_public_key_fingerprint(args.kill_public_key)
        != challenge["kill_controller_key_fingerprint"]
        or reached.get("challenge_id") != challenge["challenge_id"]
        or killed.get("challenge_id") != challenge["challenge_id"]
        or killed.get("reached_artifact_sha256")
        != hashlib.sha256(canonical_bytes(reached_artifact)).hexdigest()
    ):
        raise ValueError("Stage-C recovery source predecessor chain 非法")
    kill_at = datetime.fromisoformat(str(killed["observed_at"]))
    predecessors: dict[str, dict] = {}
    if args.source == "journal_collector":
        if (
            args.readiness_output is None
            or args.okx_final_artifact is None
            or args.okx_final_public_key is None
        ):
            raise ValueError("Stage-C journal source 缺少 readiness/final cut 参数")
        readiness_payload = collect_journal_recovery_payload(
            challenge=challenge,
            marker_path=args.marker,
            proof_path=args.proof,
            database=args.database,
            required_after=kill_at,
        )
        readiness = sign_recovery_source_payload(
            source="journal_collector",
            payload=readiness_payload,
            challenge=challenge,
            private_key=args.source_private_key,
            collected_at=readiness_payload["collected_at"],
            reached_artifact=reached_artifact,
            kill_artifact=kill_artifact,
            phase="readiness",
        )
        _atomic_new(args.readiness_output, readiness, mode=0o640)
        okx_final = _wait_json(
            args.okx_final_artifact,
            label="Stage-C OKX final artifact",
            timeout_seconds=args.activation_wait_seconds,
        )
        verify_recovery_source_artifact(
            okx_final,
            source="okx_collector",
            challenge=challenge,
            public_key=args.okx_final_public_key,
            reached_artifact=reached_artifact,
            kill_artifact=kill_artifact,
            predecessor_artifacts={"journal_readiness": readiness},
        )
        payload = collect_journal_recovery_payload(
            challenge=challenge,
            marker_path=args.marker,
            proof_path=args.proof,
            database=args.database,
            required_after=kill_at,
        )
        predecessors = {
            "journal_readiness": readiness,
            "okx_final": okx_final,
        }
    elif args.source == "okx_collector":
        if (
            args.journal_readiness_artifact is None
            or args.journal_readiness_public_key is None
        ):
            raise ValueError("Stage-C OKX source 缺少独立 journal readiness")
        journal_readiness = _wait_json(
            args.journal_readiness_artifact,
            label="Stage-C journal readiness artifact",
            timeout_seconds=args.activation_wait_seconds,
        )
        verify_recovery_source_artifact(
            journal_readiness,
            source="journal_collector",
            challenge=challenge,
            public_key=args.journal_readiness_public_key,
            reached_artifact=reached_artifact,
            kill_artifact=kill_artifact,
            expected_phase="readiness",
        )
        load_env_file(str(args.env_file))
        cfg = load_config(str(args.config))
        settings = ProductionSettings.from_config(cfg)
        okx = cfg.get("okx", {})
        if (
            settings.environment != "demo"
            or settings.shadow_mode
            or set(settings.api_permissions) != {"read"}
            or okx.get("simulated") is not True
            or settings.account_id != challenge["identity"]["account_uid"]
            or "BTC-USDT" not in settings.allowed_instruments
            or not all(
                str(okx.get(name, "")).strip()
                for name in ("api_key", "secret_key", "passphrase")
            )
        ):
            raise ValueError("Stage-C OKX source 配置未绑定 Demo challenge")
        payload = collect_okx_recovery_payload(
            challenge=challenge,
            marker_path=args.marker,
            proof_path=args.proof,
            api_key=str(okx["api_key"]),
            secret_key=str(okx["secret_key"]),
            passphrase=str(okx["passphrase"]),
            journal_readiness_sha256=hashlib.sha256(
                canonical_bytes(journal_readiness)
            ).hexdigest(),
        )
        predecessors = {"journal_readiness": journal_readiness}
    else:
        if (
            args.runtime_unit != challenge["identity"]["unit"]
            or args.journal_readiness_artifact is None
            or args.journal_readiness_public_key is None
            or args.okx_final_artifact is None
            or args.okx_final_public_key is None
        ):
            raise ValueError("Stage-C systemd source unit 未绑定 challenge")
        journal_readiness = _wait_json(
            args.journal_readiness_artifact,
            label="Stage-C journal readiness artifact",
            timeout_seconds=args.activation_wait_seconds,
        )
        verify_recovery_source_artifact(
            journal_readiness,
            source="journal_collector",
            challenge=challenge,
            public_key=args.journal_readiness_public_key,
            reached_artifact=reached_artifact,
            kill_artifact=kill_artifact,
            expected_phase="readiness",
        )
        okx_final = _wait_json(
            args.okx_final_artifact,
            label="Stage-C OKX final artifact",
            timeout_seconds=args.activation_wait_seconds,
        )
        verify_recovery_source_artifact(
            okx_final,
            source="okx_collector",
            challenge=challenge,
            public_key=args.okx_final_public_key,
            reached_artifact=reached_artifact,
            kill_artifact=kill_artifact,
            predecessor_artifacts={"journal_readiness": journal_readiness},
        )
        payload = collect_systemd_recovery_payload(
            challenge=challenge,
            marker_path=args.marker,
            proof_path=args.proof,
            runtime_unit=args.runtime_unit,
            required_after=kill_at,
        )
        predecessors = {
            "journal_readiness": journal_readiness,
            "okx_final": okx_final,
        }
    signed = sign_recovery_source_payload(
        source=args.source,
        payload=payload,
        challenge=challenge,
        private_key=args.source_private_key,
        collected_at=payload["collected_at"],
        reached_artifact=reached_artifact,
        kill_artifact=kill_artifact,
        predecessor_artifacts=predecessors,
    )
    _atomic_new(args.output, signed, mode=0o640)
    return 0


def _run_recovery_source(args) -> int:
    """Wait in the attested source workload, then acquire after signed kill."""
    request = wait_for_pipeline_activation(
        args.activation_request,
        timeout_seconds=args.activation_wait_seconds,
    )
    if request["scenario"] != args.scenario:
        raise ValueError("Stage-C recovery source activation scenario 串线")
    challenge = verify_stage_c_challenge(
        request["challenge_artifact"],
        registrar_public_key=args.registrar_public_key,
        scenario=args.scenario,
        now=None,
        enforce_current_window=True,
    )
    verify_stage_c_consumption_receipt(
        request["consumption_receipt"],
        challenge_artifact=request["challenge_artifact"],
        registrar_public_key=args.registrar_public_key,
        consumer_public_key=args.challenge_consumer_public_key,
    )
    killed_artifact = _wait_json(
        args.kill_artifact,
        label="Stage-C recovery source kill artifact",
        timeout_seconds=args.activation_wait_seconds,
    )
    killed = verify_ed25519_artifact(
        killed_artifact,
        args.kill_public_key,
        label="Stage-C recovery source kill",
    )
    if (
        ed25519_public_key_fingerprint(args.kill_public_key)
        != challenge["kill_controller_key_fingerprint"]
        or killed.get("nonce") != challenge["barrier_nonce"]
        or killed.get("artifact_sha256")
        != challenge["identity"]["artifact_sha256"]
        or killed.get("old_pid")
        != challenge["workloads"]["fault_driver"]["pid"]
        or killed.get("action") != "attest-stage-c-process-kill-v2"
        or killed.get("challenge_id") != challenge["challenge_id"]
        or killed.get("scenario") != challenge["scenario"]
        or killed.get("old_process_inactive") is not True
    ):
        raise ValueError("Stage-C recovery source predecessor kill 非法")
    return _collect_recovery_source(args, challenge=challenge)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)

    self_check = sub.add_parser("self-check", allow_abbrev=False)
    _add_scenario_argument(self_check)
    self_check.add_argument("--output", type=Path, required=True)

    run_pipeline = sub.add_parser("run-pipeline", allow_abbrev=False)
    _add_scenario_argument(run_pipeline)
    run_pipeline.add_argument("--activation-request", type=Path, required=True)
    run_pipeline.add_argument("--registrar-public-key", type=Path, required=True)
    run_pipeline.add_argument(
        "--challenge-consumer-public-key",
        type=Path,
        required=True,
    )
    run_pipeline.add_argument(
        "--fault-driver-private-key",
        type=Path,
        required=True,
    )
    run_pipeline.add_argument("--kill-artifact", type=Path, required=True)
    run_pipeline.add_argument("--kill-public-key", type=Path, required=True)
    run_pipeline.add_argument("--config", type=Path, required=True)
    run_pipeline.add_argument("--env-file", type=Path, required=True)
    run_pipeline.add_argument("--inst", required=True)
    run_pipeline.add_argument("--state-database", type=Path, required=True)
    run_pipeline.add_argument("--marker-output", type=Path, required=True)
    run_pipeline.add_argument("--proof-output", type=Path, required=True)
    run_pipeline.add_argument("--tls-certificate", type=Path)
    run_pipeline.add_argument("--tls-private-key", type=Path)
    run_pipeline.add_argument(
        "--activation-attestation-output",
        type=Path,
        required=True,
    )
    run_pipeline.add_argument(
        "--recovery-activation-attestation-output",
        type=Path,
        required=True,
    )
    run_pipeline.add_argument(
        "--activation-wait-seconds",
        type=int,
        default=600,
    )

    consume = sub.add_parser("consume-phase", allow_abbrev=False)
    _add_scenario_argument(consume)
    consume.add_argument("--phase", choices=("reached", "kill"), required=True)
    consume.add_argument("--challenge", type=Path, required=True)
    consume.add_argument("--registrar-public-key", type=Path, required=True)
    consume.add_argument("--backend", type=Path, required=True)
    consume.add_argument("--consumer-private-key", type=Path, required=True)
    consume.add_argument("--output", type=Path, required=True)

    attest = sub.add_parser("attest-reached", allow_abbrev=False)
    _add_scenario_argument(attest)
    attest.add_argument("--challenge", type=Path, required=True)
    attest.add_argument("--registrar-public-key", type=Path, required=True)
    attest.add_argument("--marker", type=Path, required=True)
    attest.add_argument("--proof", type=Path, required=True)
    attest.add_argument("--phase-consumption", type=Path, required=True)
    attest.add_argument("--phase-consumer-public-key", type=Path, required=True)
    attest.add_argument("--attestor-private-key", type=Path, required=True)
    attest.add_argument("--output", type=Path, required=True)

    kill = sub.add_parser("kill", allow_abbrev=False)
    _add_scenario_argument(kill)
    kill.add_argument("--challenge", type=Path, required=True)
    kill.add_argument("--registrar-public-key", type=Path, required=True)
    kill.add_argument("--reached-artifact", type=Path, required=True)
    kill.add_argument("--reached-public-key", type=Path, required=True)
    kill.add_argument("--reached-consumption", type=Path, required=True)
    kill.add_argument("--reached-consumer-public-key", type=Path, required=True)
    kill.add_argument("--kill-consumption", type=Path, required=True)
    kill.add_argument("--kill-consumer-public-key", type=Path, required=True)
    kill.add_argument("--kill-private-key", type=Path, required=True)
    kill.add_argument("--unit", required=True)
    kill.add_argument("--output", type=Path, required=True)

    collect_recovery = sub.add_parser(
        "collect-recovery",
        allow_abbrev=False,
    )
    _add_scenario_argument(collect_recovery)
    collect_recovery.add_argument("--challenge", type=Path, required=True)
    collect_recovery.add_argument(
        "--registrar-public-key",
        type=Path,
        required=True,
    )
    collect_recovery.add_argument("--marker", type=Path, required=True)
    collect_recovery.add_argument("--proof", type=Path, required=True)
    collect_recovery.add_argument(
        "--reached-artifact",
        type=Path,
        required=True,
    )
    collect_recovery.add_argument(
        "--reached-public-key",
        type=Path,
        required=True,
    )
    collect_recovery.add_argument(
        "--kill-artifact",
        type=Path,
        required=True,
    )
    collect_recovery.add_argument(
        "--kill-public-key",
        type=Path,
        required=True,
    )
    collect_recovery.add_argument("--native-output", type=Path, required=True)
    collect_recovery.add_argument("--core-output", type=Path, required=True)
    collect_recovery.add_argument(
        "--journal-readiness-artifact",
        type=Path,
        required=True,
    )
    for name in ("journal", "okx", "systemd"):
        collect_recovery.add_argument(
            f"--{name}-artifact",
            type=Path,
            required=True,
        )
        collect_recovery.add_argument(
            f"--{name}-public-key",
            type=Path,
            required=True,
        )

    collect_source = sub.add_parser(
        "collect-recovery-source",
        allow_abbrev=False,
    )
    _add_scenario_argument(collect_source)
    collect_source.add_argument("--challenge", type=Path, required=True)
    collect_source.add_argument(
        "--registrar-public-key",
        type=Path,
        required=True,
    )
    collect_source.add_argument(
        "--source",
        choices=("journal_collector", "okx_collector", "systemd_collector"),
        required=True,
    )
    collect_source.add_argument("--marker", type=Path, required=True)
    collect_source.add_argument("--proof", type=Path, required=True)
    collect_source.add_argument("--reached-artifact", type=Path, required=True)
    collect_source.add_argument("--reached-public-key", type=Path, required=True)
    collect_source.add_argument("--kill-artifact", type=Path, required=True)
    collect_source.add_argument("--kill-public-key", type=Path, required=True)
    collect_source.add_argument(
        "--source-private-key",
        type=Path,
        required=True,
    )
    collect_source.add_argument("--database", type=Path)
    collect_source.add_argument("--config", type=Path)
    collect_source.add_argument("--env-file", type=Path)
    collect_source.add_argument("--runtime-unit")
    collect_source.add_argument("--journal-readiness-artifact", type=Path)
    collect_source.add_argument("--journal-readiness-public-key", type=Path)
    collect_source.add_argument("--readiness-output", type=Path)
    collect_source.add_argument("--okx-final-artifact", type=Path)
    collect_source.add_argument("--okx-final-public-key", type=Path)
    collect_source.add_argument("--output", type=Path, required=True)
    collect_source.add_argument(
        "--activation-wait-seconds",
        type=int,
        default=900,
    )

    run_source = sub.add_parser(
        "run-recovery-source",
        allow_abbrev=False,
    )
    _add_scenario_argument(run_source)
    run_source.add_argument("--activation-request", type=Path, required=True)
    run_source.add_argument(
        "--registrar-public-key",
        type=Path,
        required=True,
    )
    run_source.add_argument(
        "--challenge-consumer-public-key",
        type=Path,
        required=True,
    )
    run_source.add_argument("--kill-artifact", type=Path, required=True)
    run_source.add_argument("--kill-public-key", type=Path, required=True)
    run_source.add_argument("--reached-artifact", type=Path, required=True)
    run_source.add_argument("--reached-public-key", type=Path, required=True)
    run_source.add_argument(
        "--source",
        choices=("journal_collector", "okx_collector", "systemd_collector"),
        required=True,
    )
    run_source.add_argument("--marker", type=Path, required=True)
    run_source.add_argument("--proof", type=Path, required=True)
    run_source.add_argument(
        "--source-private-key",
        type=Path,
        required=True,
    )
    run_source.add_argument("--database", type=Path)
    run_source.add_argument("--config", type=Path)
    run_source.add_argument("--env-file", type=Path)
    run_source.add_argument("--runtime-unit")
    run_source.add_argument("--journal-readiness-artifact", type=Path)
    run_source.add_argument("--journal-readiness-public-key", type=Path)
    run_source.add_argument("--readiness-output", type=Path)
    run_source.add_argument("--okx-final-artifact", type=Path)
    run_source.add_argument("--okx-final-public-key", type=Path)
    run_source.add_argument("--output", type=Path, required=True)
    run_source.add_argument(
        "--activation-wait-seconds",
        type=int,
        default=900,
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    _resolve_scenario(args)
    if args.command == "self-check":
        report = barrier_capability_self_check(scenario=args.scenario)
        _atomic_new(args.output, report, mode=0o640)
        return 2
    if args.command == "run-pipeline":
        return _run_pipeline(args)
    if args.command == "collect-recovery":
        return _collect_recovery(args)
    if args.command == "collect-recovery-source":
        return _collect_recovery_source(args)
    if args.command == "run-recovery-source":
        return _run_recovery_source(args)
    if args.command == "consume-phase":
        _artifact, challenge = _challenge(args)
        receipt = consume_barrier_phase_globally(
            challenge=challenge,
            phase=args.phase,
            private_key=args.consumer_private_key,
            backend=_backend(args.backend),
        )
        _atomic_new(args.output, receipt, mode=0o640)
        return 0
    if args.command == "attest-reached":
        _artifact, challenge = _challenge(args)
        result = attest_barrier_reached(
            marker=load_marker(args.marker),
            boundary_proof=_safe_json(
                args.proof,
                label="Stage-C boundary proof",
            ),
            challenge=challenge,
            phase_consumption=_safe_json(
                args.phase_consumption,
                label="reached consumption",
            ),
            phase_consumer_public_key=args.phase_consumer_public_key,
            private_key=args.attestor_private_key,
        )
        _atomic_new(args.output, result, mode=0o640)
        return 0
    _artifact, challenge = _challenge(args)
    result = execute_systemd_kill(
        challenge=challenge,
        reached_artifact=_safe_json(
            args.reached_artifact,
            label="reached artifact",
        ),
        reached_public_key=args.reached_public_key,
        reached_consumption=_safe_json(
            args.reached_consumption,
            label="reached consumption",
        ),
        reached_consumer_public_key=args.reached_consumer_public_key,
        kill_consumption=_safe_json(
            args.kill_consumption,
            label="kill consumption",
        ),
        kill_consumer_public_key=args.kill_consumer_public_key,
        private_key=args.kill_private_key,
        unit=args.unit,
    )
    _atomic_new(args.output, result, mode=0o640)
    return 0


if __name__ == "__main__":
    sys.exit(main())
