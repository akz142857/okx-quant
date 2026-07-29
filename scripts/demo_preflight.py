#!/usr/bin/env python3
"""Issue or verify a short-lived receipt for one isolated OKX Demo unit."""

from __future__ import annotations

import argparse
import grp
import json
import os
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import make_client
from okx_quant.application.demo_probe import validate_formal_probe_schedule
from okx_quant.client.websocket import OKXWebSocketClient
from okx_quant.config import ProductionSettings, load_yaml
from okx_quant.infrastructure.evidence import (
    credential_fingerprint,
    ed25519_public_key_fingerprint,
)
from okx_quant.ops.account_lease import SignedAccountLeaseClient
from okx_quant.ops.demo_preflight import (
    DemoDeploymentProfile,
    _receipt_identity,
    _secure_regular_file,
    assert_single_writer_available,
    balance_details,
    build_receipt,
    validate_account_state,
    validate_directory,
    validate_environment_file,
    validate_journal,
    validate_okx_permissions,
    validate_peer_isolation,
    validate_runtime_profile_binding,
    validate_unit_file,
    verify_receipt,
    wait_websocket_ready,
    write_receipt,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("issue", "verify"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", type=Path, required=True)
        child.add_argument("--receipt", type=Path, required=True)
        child.add_argument("--peer-config", type=Path, action="append", default=[])
    fingerprint = subparsers.add_parser("key-fingerprint")
    fingerprint.add_argument("--config", type=Path, required=True)
    return parser


def _load(path: Path) -> tuple[dict, ProductionSettings, DemoDeploymentProfile]:
    cfg = load_yaml(str(path))
    settings = ProductionSettings.from_config(
        cfg,
        require_external_controls=False,
    )
    profile = DemoDeploymentProfile.from_config(cfg)
    validate_runtime_profile_binding(profile, settings, cfg)
    if (
        settings.memory_high_bytes != 524288000
        or settings.memory_max_bytes != 629145600
        or settings.limit_nofile != 4096
        or settings.tasks_max != 128
    ):
        raise RuntimeError("Demo 资源配置与受控 systemd hard limits 不一致")
    return cfg, settings, profile


def _account_uid(cfg: dict) -> str:
    value = str(cfg.get("demo_validation", {}).get("account_uid", "")).strip()
    if not value:
        raise RuntimeError("demo_validation.account_uid 不能为空")
    return value


def _offline_identity(
    cfg: dict,
    profile: DemoDeploymentProfile,
    config_path: Path,
) -> dict:
    return _receipt_identity(
        cfg=cfg,
        profile=profile,
        account_uid=_account_uid(cfg),
        config_path=config_path,
    )


def _issue(
    *,
    cfg: dict,
    settings: ProductionSettings,
    profile: DemoDeploymentProfile,
    peer_paths: list[Path],
    receipt_path: Path,
    config_path: Path,
) -> dict:
    if receipt_path != profile.receipt_path:
        raise RuntimeError("--receipt 与受控配置不一致")
    if os.geteuid() != 0:
        raise PermissionError("受控 Demo preflight receipt 必须由 root 签发")
    validate_environment_file(profile)
    validate_unit_file(profile)
    _secure_regular_file(
        profile.backup_receipt_public_key,
        root_owned=True,
    )
    alert_keys = (
        profile.alert_provider_receipt_public_key,
        profile.alert_human_ack_public_key,
        profile.alert_escalation_public_key,
    )
    for alert_key in alert_keys:
        _secure_regular_file(alert_key, root_owned=True)
    if len({ed25519_public_key_fingerprint(alert_key) for alert_key in alert_keys}) != 3:
        raise RuntimeError("provider/human/escalation receipt 必须使用三个不同公钥")
    if profile.external_lease_public_key is not None:
        _secure_regular_file(
            profile.external_lease_public_key,
            root_owned=True,
        )
        lease = SignedAccountLeaseClient(
            base_url=profile.external_lease_url,
            public_key=profile.external_lease_public_key,
            token_env=profile.external_lease_token_env,
            account_uid=profile.account_uid,
            broker_id=profile.external_lease_broker_id,
            ttl_s=profile.external_lease_ttl_s,
        )
        try:
            lease.start(holder_id=secrets.token_hex(16))
        finally:
            lease.stop()
    if profile.role == "active":
        if profile.probe_schedule_path is None:
            raise RuntimeError("Demo Active 必须配置 formal probe schedule")
        _secure_regular_file(
            profile.probe_schedule_path,
            root_owned=True,
        )
        validate_formal_probe_schedule(
            json.loads(profile.probe_schedule_path.read_text(encoding="utf-8"))
        )
    _offline_identity(cfg, profile, config_path)
    pwd_module = __import__("pwd")
    unix_uid = pwd_module.getpwnam(profile.unix_user).pw_uid
    pwd_module.getpwnam(profile.monitor_user)
    data_gid = grp.getgrnam(profile.unix_group).gr_gid
    for directory in (profile.state_dir, profile.log_dir):
        validate_directory(
            directory,
            allowed_uids={0, unix_uid},
            expected_gid=data_gid,
            allowed_modes=({0o750, 0o2750} if directory == profile.state_dir else {0o750}),
            min_free_bytes=profile.min_free_bytes,
            min_free_inodes=profile.min_free_inodes,
        )
    backup_uid = pwd_module.getpwnam(profile.backup_user).pw_uid
    validate_directory(
        profile.backup_dir,
        allowed_uids={0, backup_uid},
        expected_gid=data_gid,
        allowed_modes={0o750},
        min_free_bytes=profile.min_free_bytes,
        min_free_inodes=profile.min_free_inodes,
    )
    validate_directory(
        profile.operator_inbox_dir.parent,
        allowed_uids={0, unix_uid},
        expected_gid=data_gid,
        allowed_modes={0o750, 0o2750},
        min_free_bytes=profile.min_free_bytes,
        min_free_inodes=profile.min_free_inodes,
    )
    client = make_client(cfg)
    account_config = client.get_account_config()
    actual_uid = str(account_config.get("uid", "")).strip()
    expected_uid = _account_uid(cfg)
    if actual_uid != expected_uid:
        raise RuntimeError(f"OKX account UID 串线: expected={expected_uid}, actual={actual_uid}")
    validate_okx_permissions(profile.role, account_config.get("perm"))
    actual_fingerprint = credential_fingerprint(str(cfg["okx"]["api_key"]))
    if actual_fingerprint != profile.key_fingerprint:
        raise RuntimeError("API key fingerprint 与 Demo 配置不一致")
    server = client.get("/api/v5/public/time")
    server_time = int(server[0]["ts"]) / 1000
    skew = abs(time.time() - server_time)
    if skew > settings.max_clock_skew_s:
        raise RuntimeError(f"主机时钟偏差 {skew:.3f}s 超过 {settings.max_clock_skew_s}s")
    local_positions = validate_journal(
        Path(settings.journal_path),
        account_uid=actual_uid,
    )
    instruments = client.get_instruments("SPOT")
    pending_algos = []
    for order_type in (
        "conditional",
        "oco",
        "trigger",
        "move_order_stop",
        "iceberg",
        "twap",
    ):
        pending_algos.extend(
            client.get(
                "/api/v5/trade/orders-algo-pending",
                {"ordType": order_type},
                auth=True,
            )
            or []
        )
    validate_account_state(
        role=profile.role,
        balances=balance_details(client.get_balance()),
        instruments=instruments,
        pending_orders=client.get_open_orders(),
        pending_algos=pending_algos,
        local_positions=local_positions,
    )
    peers = []
    for peer_path in peer_paths:
        peer_cfg, _, peer_profile = _load(peer_path)
        peers.append((peer_profile, _account_uid(peer_cfg)))
    validate_peer_isolation(
        profile,
        peers,
        account_uid=actual_uid,
        resolve_system_identity=True,
    )
    assert_single_writer_available(
        Path(settings.lock_path),
        owner_uid=unix_uid,
    )
    websocket = OKXWebSocketClient(
        api_key=str(cfg["okx"]["api_key"]),
        secret_key=str(cfg["okx"]["secret_key"]),
        passphrase=str(cfg["okx"]["passphrase"]),
        simulated=True,
        connection_targets=profile.websocket_targets(),
    )
    websocket.subscribe_ticker(profile.instrument, lambda _rows: None)
    websocket.subscribe_orders("ANY", "", lambda _rows: None)
    websocket.subscribe_balance_and_position(lambda _rows: None)
    websocket.subscribe_algo_orders(lambda _rows: None)
    wait_websocket_ready(
        websocket,
        timeout_s=settings.ws_ready_timeout_s,
    )
    identity = _offline_identity(cfg, profile, config_path)
    receipt = build_receipt(
        identity,
        now=int(time.time()),
        ttl_s=profile.receipt_ttl_s,
    )
    write_receipt(receipt_path, receipt, group_gid=data_gid)
    return receipt


def main() -> int:
    args = _parser().parse_args()
    cfg, settings, profile = _load(args.config)
    if args.command == "key-fingerprint":
        print(credential_fingerprint(str(cfg["okx"]["api_key"])))
        return 0
    identity = _offline_identity(cfg, profile, args.config)
    data_gid = grp.getgrnam(profile.unix_group).gr_gid
    if args.command == "verify":
        result = verify_receipt(
            args.receipt,
            expected_identity=identity,
            expected_group_gid=data_gid,
        )
    else:
        result = _issue(
            cfg=cfg,
            settings=settings,
            profile=profile,
            peer_paths=args.peer_config,
            receipt_path=args.receipt,
            config_path=args.config,
        )
        verify_receipt(
            args.receipt,
            expected_identity=identity,
            expected_group_gid=data_gid,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
