import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import main as main_module
from okx_quant.client.websocket import ConnectionState
from okx_quant.config import ProductionSettings
from okx_quant.ops.demo_preflight import (
    DemoDeploymentProfile,
    balance_details,
    build_receipt,
    unit_launch_identity,
    validate_account_state,
    validate_environment_file,
    validate_okx_permissions,
    validate_peer_isolation,
    validate_runtime_profile_binding,
    validate_unit_file,
    verify_demo_process_context,
    verify_receipt,
    wait_websocket_ready,
    write_receipt,
)
from scripts.demo_preflight import _load


def _profile(tmp_path: Path, role: str, suffix: str) -> DemoDeploymentProfile:
    root = tmp_path / suffix
    return DemoDeploymentProfile(
        role=role,
        unit_name=f"okx-quant-demo-{role}.service",
        unit_file=root / "unit.service",
        unix_user=f"trader-{suffix}",
        unix_group=f"trader-{suffix}",
        monitor_user=f"monitor-{suffix}",
        backup_user=f"backup-{suffix}",
        environment_file=root / "trader.env",
        state_dir=root / "state",
        backup_dir=root / "backup",
        log_dir=root / "log",
        release_root=root / "release",
        receipt_path=root / "receipt.json",
        network_namespace=root / "netns",
        account_uid=f"uid-{suffix}",
        soak_epoch_id=f"epoch-{suffix}",
        key_fingerprint=(suffix[0] * 64),
        metrics_port=9200 + ord(suffix[0]),
        instrument="BTC-USDT",
        backup_receipt_path=root / "backup/last-offsite-roundtrip.json",
        backup_receipt_public_key=root / "backup-public.pem",
        backup_receipt_key_id=f"backup-{suffix}-v1",
        operator_inbox_dir=root / "state/operator-inbox",
        alert_provider_receipt_public_key=(root / "alert-provider-public.pem"),
        alert_human_ack_public_key=root / "alert-human-public.pem",
        alert_escalation_public_key=(root / "alert-escalation-public.pem"),
        external_lease_url=(
            f"https://lease-{suffix}.example" if role in {"active", "chaos"} else ""
        ),
        external_lease_public_key=(
            root / "account-lease-public.pem" if role in {"active", "chaos"} else None
        ),
        external_lease_token_env=(
            "OKX_QUANT_ACCOUNT_LEASE_TOKEN" if role in {"active", "chaos"} else ""
        ),
        external_lease_broker_id=("demo-lease-v1" if role in {"active", "chaos"} else ""),
        external_lease_ttl_s=(30 if role in {"active", "chaos"} else 0),
        cost_model_manifest={
            "model": "okx_quant.research.costs.DynamicCostModel",
            "fee_rate": 0.001,
            "minimum_slippage": 0.0005,
            "range_fraction": 0.05,
            "impact_coefficient": 0.1,
            "maximum_slippage": 0.01,
            "stress_multiplier": 1.0,
        },
        fault_proxy_targets=(
            {
                "public": {"host": "127.0.0.1", "port": 19443},
                "private": {"host": "127.0.0.1", "port": 19444},
                "business": {"host": "127.0.0.1", "port": 19445},
            }
            if role == "chaos"
            else {}
        ),
    )


def test_permission_contract_is_exact():
    assert validate_okx_permissions("shadow", "read_only") == {"read"}
    assert validate_okx_permissions("active", "read_only,trade") == {
        "read",
        "trade",
    }
    with pytest.raises(RuntimeError, match="精确"):
        validate_okx_permissions("shadow", "read_only,trade")
    with pytest.raises(RuntimeError, match="精确"):
        validate_okx_permissions("active", "read_only,trade,withdraw")


def test_balance_parser_rejects_invalid_and_sums_rows():
    assert (
        str(
            balance_details(
                [
                    {"details": [{"ccy": "BTC", "cashBal": "0.1"}]},
                    {"details": [{"ccy": "BTC", "cashBal": "0.2"}]},
                ]
            )["BTC"]
        )
        == "0.3"
    )
    with pytest.raises(RuntimeError, match="非负"):
        balance_details([{"details": [{"ccy": "BTC", "cashBal": "-1"}]}])


def test_shadow_rejects_non_dust_and_any_pending_order():
    instruments = [{"instId": "BTC-USDT", "lotSz": "0.00001", "minSz": "0.0001"}]
    validate_account_state(
        role="shadow",
        balances={
            "BTC": balance_details([{"details": [{"ccy": "BTC", "cashBal": "0.000001"}]}])["BTC"]
        },
        instruments=instruments,
        pending_orders=[],
        pending_algos=[],
        local_positions=[],
    )
    with pytest.raises(RuntimeError, match="非 dust"):
        validate_account_state(
            role="shadow",
            balances={
                "BTC": balance_details([{"details": [{"ccy": "BTC", "cashBal": "0.00001"}]}])["BTC"]
            },
            instruments=instruments,
            pending_orders=[],
            pending_algos=[],
            local_positions=[],
        )
    with pytest.raises(RuntimeError, match="普通挂单"):
        validate_account_state(
            role="shadow",
            balances={},
            instruments=instruments,
            pending_orders=[{"ordId": "1"}],
            pending_algos=[],
            local_positions=[],
        )


def test_active_requires_exchange_balance_to_match_journal():
    instruments = [{"instId": "BTC-USDT", "lotSz": "0.00001", "minSz": "0.0001"}]
    validate_account_state(
        role="active",
        balances={"BTC": balance_details([{"details": [{"ccy": "BTC", "cashBal": "0.1"}]}])["BTC"]},
        instruments=instruments,
        pending_orders=[],
        pending_algos=[],
        local_positions=[{"inst_id": "BTC-USDT", "base_qty": "0.1"}],
    )
    with pytest.raises(RuntimeError, match="不可解释持仓"):
        validate_account_state(
            role="active",
            balances={
                "BTC": balance_details([{"details": [{"ccy": "BTC", "cashBal": "0.1"}]}])["BTC"]
            },
            instruments=instruments,
            pending_orders=[],
            pending_algos=[],
            local_positions=[],
        )


def test_peer_isolation_rejects_account_and_resource_reuse(tmp_path):
    current = _profile(tmp_path, "shadow", "a")
    peer = _profile(tmp_path, "active", "b")
    validate_peer_isolation(current, [(peer, "uid-b")], account_uid="uid-a")
    with pytest.raises(RuntimeError, match="account UID"):
        validate_peer_isolation(current, [(peer, "uid-a")], account_uid="uid-a")
    colliding = DemoDeploymentProfile(
        **{
            **peer.__dict__,
            "metrics_port": current.metrics_port,
        }
    )
    with pytest.raises(RuntimeError, match="metrics_port"):
        validate_peer_isolation(
            current,
            [(colliding, "uid-b")],
            account_uid="uid-a",
        )


def _runtime_binding_fixture(profile: DemoDeploymentProfile):
    settings = SimpleNamespace(
        environment="demo",
        shadow_mode=profile.role == "shadow",
        account_id=profile.account_uid,
        metrics_host="127.0.0.1",
        metrics_port=profile.metrics_port,
        allowed_instruments=(profile.instrument,),
        journal_path=str(profile.state_dir / "trading.db"),
        lock_path=str(profile.state_dir / "trading.lock"),
        heartbeat_path=str(profile.state_dir / "heartbeat"),
        backup_dir=str(profile.backup_dir),
        release_root=str(profile.release_root),
        deployment_receipt_path=str(profile.receipt_path),
        backup_receipt_path=str(profile.backup_receipt_path),
        backup_receipt_public_key=str(profile.backup_receipt_public_key),
        backup_receipt_key_id=profile.backup_receipt_key_id,
    )
    cfg = {
        "okx": {"simulated": True},
        "logging": {"file": str(profile.log_dir / "quant.log")},
        "executor": {"state_dir": str(profile.state_dir / "legacy-state")},
    }
    return settings, cfg


def test_runtime_profile_binding_accepts_only_role_owned_paths(tmp_path):
    profile = _profile(tmp_path, "active", "a")
    settings, cfg = _runtime_binding_fixture(profile)

    validate_runtime_profile_binding(profile, settings, cfg)


def test_deployed_demo_examples_bind_every_runtime_path(monkeypatch):
    monkeypatch.setenv("OKX_API_KEY", "fixture-api-key")
    monkeypatch.setenv("OKX_SECRET_KEY", "fixture-secret")
    monkeypatch.setenv("OKX_PASSPHRASE", "fixture-passphrase")
    repository = Path(__file__).resolve().parents[1]

    for role in ("shadow", "active", "chaos"):
        _cfg, settings, profile = _load(
            repository / f"deploy/demo/config.{role}.yaml.example"
        )
        validate_runtime_profile_binding(profile, settings, _cfg)


@pytest.mark.parametrize(
    "field_name",
    [
        "journal_path",
        "lock_path",
        "heartbeat_path",
        "backup_dir",
        "release_root",
        "deployment_receipt_path",
        "backup_receipt_path",
        "backup_receipt_public_key",
    ],
)
def test_runtime_profile_binding_rejects_cross_wired_settings_path(
    tmp_path,
    field_name,
):
    profile = _profile(tmp_path, "active", "a")
    settings, cfg = _runtime_binding_fixture(profile)
    setattr(settings, field_name, str(tmp_path / "other-role" / field_name))

    with pytest.raises(RuntimeError, match=field_name):
        validate_runtime_profile_binding(profile, settings, cfg)


@pytest.mark.parametrize(
    ("section", "field_name"),
    [("logging", "file"), ("executor", "state_dir")],
)
def test_runtime_profile_binding_rejects_cross_wired_auxiliary_path(
    tmp_path,
    section,
    field_name,
):
    profile = _profile(tmp_path, "active", "a")
    settings, cfg = _runtime_binding_fixture(profile)
    cfg[section][field_name] = str(tmp_path / "other-role" / field_name)

    with pytest.raises(RuntimeError, match=re.escape(f"{section}.{field_name}")):
        validate_runtime_profile_binding(profile, settings, cfg)


def test_receipt_is_short_lived_exact_and_tamper_evident(tmp_path):
    identity = {
        "role": "shadow",
        "unit_name": "okx-quant-demo-shadow.service",
        "unit_sha256": "f" * 64,
        "unix_uid": os.getuid(),
        "unix_gid": os.getgid(),
        "account_uid": "uid-a",
        "soak_epoch_id": "epoch-a",
        "key_fingerprint": "a" * 64,
        "config_sha256": "b" * 64,
        "release_identity": {
            "git_commit": "c" * 40,
            "git_tree_hash": "d" * 40,
            "workspace_clean": True,
            "source_manifest_sha256": "e" * 64,
        },
        "launch_identity": {
            "process_argv": [
                "/opt/demo/main.py",
                "--config",
                "/etc/demo.yaml",
                "live",
                "--inst",
                "BTC-USDT",
                "--strategy",
                "ma_cross",
                "--bar",
                "1H",
                "--interval",
                "60",
                "--no-dashboard",
                "--yes",
            ],
            "strategy": "ma_cross",
            "bar": "1H",
            "instruments": ["BTC-USDT"],
            "interval_seconds": 60,
        },
        "network_namespace": "/run/netns/a",
        "network_namespace_identity": "1:2",
    }
    receipt = build_receipt(identity, now=100, ttl_s=300)
    path = tmp_path / "receipt.json"
    write_receipt(path, receipt)
    assert verify_receipt(path, expected_identity=identity, now=101) == receipt
    with pytest.raises(RuntimeError, match="过期"):
        verify_receipt(path, expected_identity=identity, now=401)
    changed = {**identity, "unit_name": "other.service"}
    with pytest.raises(RuntimeError, match="unit_name"):
        verify_receipt(path, expected_identity=changed, now=101)


def test_unit_launch_identity_is_strict_and_exact(tmp_path):
    profile = _profile(tmp_path, "active", "a")
    profile.unit_file.parent.mkdir(parents=True)
    config_path = tmp_path / "active.yaml"
    argv = [
        str(profile.release_root / ".venv/bin/python"),
        str(profile.release_root / "main.py"),
        "--config",
        str(config_path),
        "live",
        "--inst",
        "BTC-USDT",
        "--strategy",
        "validation_probe",
        "--bar",
        "1H",
        "--interval",
        "60",
        "--no-dashboard",
        "--yes",
    ]
    profile.unit_file.write_text(
        "ExecStart=" + " ".join(argv) + "\n",
        encoding="utf-8",
    )

    identity = unit_launch_identity(profile, config_path=config_path)

    assert identity == {
        "process_argv": argv[1:],
        "strategy": "validation_probe",
        "bar": "1H",
        "instruments": ["BTC-USDT"],
        "interval_seconds": 60,
    }
    profile.unit_file.write_text(
        profile.unit_file.read_text(encoding="utf-8") + "ExecStart=/bin/false\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="只能有一个"):
        unit_launch_identity(profile, config_path=config_path)


def _valid_unit_text(profile: DemoDeploymentProfile) -> str:
    return f"""[Unit]
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
User={profile.unix_user}
Group={profile.unix_group}
ProtectProc=invisible
ProcSubset=pid
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
MemoryHigh=500M
MemoryMax=600M
LimitNOFILE=4096
TasksMax=128
OOMPolicy=stop
NetworkNamespacePath={profile.network_namespace}
ReadWritePaths={profile.state_dir} {profile.log_dir}
"""


def test_unit_validation_parses_effective_directives_not_comments(tmp_path):
    profile = _profile(tmp_path, "shadow", "s")
    profile.unit_file.parent.mkdir(parents=True)
    profile.unit_file.write_text(_valid_unit_text(profile), encoding="utf-8")
    validate_unit_file(profile)

    profile.unit_file.write_text(
        _valid_unit_text(profile)
        + "\n# ProtectProc=invisible\nProtectProc=default\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="ProtectProc"):
        validate_unit_file(profile)


def test_environment_file_requires_role_group_mode_and_no_symlink_ancestor(
    tmp_path,
    monkeypatch,
):
    profile = _profile(tmp_path, "shadow", "s")
    profile.environment_file.parent.mkdir(parents=True)
    profile.environment_file.write_text("OKX_API_KEY=redacted\n", encoding="utf-8")
    profile.environment_file.chmod(0o640)
    monkeypatch.setattr(
        "okx_quant.ops.demo_preflight.grp.getgrnam",
        lambda _name: SimpleNamespace(gr_gid=os.getgid()),
    )
    validate_environment_file(profile)

    profile.environment_file.chmod(0o600)
    with pytest.raises(RuntimeError, match="0o640"):
        validate_environment_file(profile)

    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    linked_environment = linked_parent / "trader.env"
    linked_environment.write_text("OKX_API_KEY=redacted\n", encoding="utf-8")
    linked_environment.chmod(0o640)
    linked_profile = DemoDeploymentProfile(
        **{
            **profile.__dict__,
            "environment_file": linked_environment,
        }
    )
    with pytest.raises(RuntimeError, match="祖先路径非法"):
        validate_environment_file(linked_profile)


@pytest.mark.parametrize(
    ("role", "data_group"),
    [
        ("shadow", "okxquant-data-shadow"),
        ("active", "okxquant-data-active"),
        ("chaos", "okxquant-data-chaos"),
    ],
)
def test_deployed_demo_unit_and_config_share_read_only_receipt(
    role,
    data_group,
):
    repository = Path(__file__).resolve().parents[1]
    unit = repository / f"deploy/systemd/okx-quant-demo-{role}.service"
    config = repository / f"deploy/demo/config.{role}.yaml.example"
    receipt = f"/run/okx-quant-demo-preflight/{role}/receipt.json"
    unit_text = unit.read_text(encoding="utf-8")
    config_text = config.read_text(encoding="utf-8")
    assert (
        f"install -d -o root -g {data_group} -m 0750 /run/okx-quant-demo-preflight/{role}"
    ) in unit_text
    assert unit_text.count(f"--receipt {receipt}") == 2
    assert config_text.count(f'"{receipt}"') == 2
    profile = DemoDeploymentProfile(
        **{
            **_profile(
                repository / ".unit-fixture",
                role,
                role[0],
            ).__dict__,
            "unit_name": f"okx-quant-demo-{role}.service",
            "unit_file": unit,
            "release_root": Path(f"/opt/okx-quant/demo-{role}/current"),
        }
    )
    launch = unit_launch_identity(
        profile,
        config_path=Path(f"/etc/okx-quant/demo-{role}.yaml"),
    )
    assert launch["process_argv"][0] == (f"/opt/okx-quant/demo-{role}/current/main.py")
    assert launch["instruments"] == ["BTC-USDT"]


def test_process_context_uses_injectable_proc_cgroup_and_netns(tmp_path):
    configured_netns = tmp_path / "configured-netns"
    configured_netns.write_bytes(b"namespace-fixture")
    proc_root = tmp_path / "proc"
    proc_netns = proc_root / "self/ns/net"
    proc_netns.parent.mkdir(parents=True)
    os.link(configured_netns, proc_netns)
    cgroup = proc_root / "self/cgroup"
    cgroup.write_text(
        "0::/system.slice/okx-quant-demo-active.service\n",
        encoding="utf-8",
    )
    launch_argv = ["/release/main.py", "--config", "/etc/demo.yaml", "live"]
    info = configured_netns.stat()
    receipt = {
        "unix_uid": 1234,
        "unit_name": "okx-quant-demo-active.service",
        "network_namespace_identity": f"{info.st_dev}:{info.st_ino}",
        "launch_identity": {"process_argv": launch_argv},
    }

    verify_demo_process_context(
        receipt,
        process_argv=launch_argv,
        proc_root=proc_root,
        current_uid=1234,
    )
    with pytest.raises(RuntimeError, match="Unix UID"):
        verify_demo_process_context(
            receipt,
            process_argv=launch_argv,
            proc_root=proc_root,
            current_uid=4321,
        )
    with pytest.raises(RuntimeError, match="live argv"):
        verify_demo_process_context(
            receipt,
            process_argv=[*launch_argv, "--yes"],
            proc_root=proc_root,
            current_uid=1234,
        )
    cgroup.write_text(
        "0::/system.slice/other.service\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="service cgroup"):
        verify_demo_process_context(
            receipt,
            process_argv=launch_argv,
            proc_root=proc_root,
            current_uid=1234,
        )
    cgroup.write_text(
        "0::/system.slice/okx-quant-demo-active.service\n",
        encoding="utf-8",
    )
    proc_netns.unlink()
    proc_netns.write_bytes(b"different-namespace")
    with pytest.raises(RuntimeError, match="network namespace"):
        verify_demo_process_context(
            receipt,
            process_argv=launch_argv,
            proc_root=proc_root,
            current_uid=1234,
        )


def test_demo_receipt_failure_happens_before_okx_client(
    monkeypatch,
):
    settings = SimpleNamespace(environment="demo")
    monkeypatch.setattr(
        ProductionSettings,
        "from_config",
        classmethod(lambda _cls, _cfg: settings),
    )

    def reject(*_args, **_kwargs):
        raise RuntimeError("expired receipt")

    client_created = False

    def forbidden_client(_cfg):
        nonlocal client_created
        client_created = True
        raise AssertionError("OKX client must not be created")

    monkeypatch.setattr(main_module, "_validate_demo_deployment", reject)
    monkeypatch.setattr(main_module, "make_client", forbidden_client)
    args = SimpleNamespace(
        bar="1H",
        config="/etc/okx-quant/demo-active.yaml",
        safety_only=False,
    )

    with pytest.raises(SystemExit) as exc:
        main_module.cmd_live(args, {"okx": {"simulated": True}})

    assert exc.value.code == 1
    assert client_created is False


class _ReadyWebSocket:
    def __init__(self):
        self.started = False
        self.stopped = False

    def run_in_thread(self):
        self.started = True

    def connection_state(self, _name):
        return ConnectionState.READY

    def stop(self):
        self.stopped = True


def test_websocket_preflight_requires_all_three_channels():
    websocket = _ReadyWebSocket()
    result = wait_websocket_ready(websocket, timeout_s=1)
    assert result == {
        "public": "ready",
        "private": "ready",
        "business": "ready",
    }
    assert websocket.started is True
    assert websocket.stopped is True
