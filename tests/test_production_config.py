"""生产配置 fail-closed 校验。"""

import os
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import main as main_module
from main import (
    _strategy_instruments,
    _validate_production_deployment,
    cmd_init_journal,
    load_env_file,
)
from okx_quant.config import ProductionSettings, load_yaml
from okx_quant.domain.orders import SystemMode
from okx_quant.infrastructure.db import SQLiteJournal


def _config():
    return {
        "okx": {
            "api_key": "key",
            "secret_key": "secret",
            "passphrase": "pass",
            "simulated": True,
            "base_url": "https://www.okx.com",
        },
        "logging": {"level": "INFO"},
        "production": {
            "environment": "demo",
            "allowed_instruments": ["BTC-USDT"],
            "journal_path": "state/demo/trading.db",
            "lock_path": "state/demo/trading.lock",
            "backup_dir": "backups/demo",
            "heartbeat_path": "state/demo/heartbeat",
        },
    }


@pytest.mark.unit
def test_production_config_rejects_unknown_field():
    cfg = _config()
    cfg["production"]["surprise"] = True
    with pytest.raises(ValueError, match="未知字段"):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
def test_backup_cadence_cannot_be_relaxed_past_one_minute():
    cfg = _config()
    cfg["production"]["backup_interval_s"] = 61
    with pytest.raises(ValueError, match=r"\(0, 60\]"):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
def test_root_example_config_is_valid_for_demo_journal_initialization():
    cfg = load_yaml(
        str(Path(__file__).resolve().parents[1] / "config.yaml.example")
    )

    settings = ProductionSettings.from_config(
        cfg,
        require_credentials=False,
    )

    assert settings.environment == "demo"
    assert settings.journal_path == "state/demo/trading.db"
    assert settings.backup_interval_s == 60


@pytest.mark.unit
def test_production_existing_positions_never_expand_strategy_workers():
    assert _strategy_instruments(
        ["BTC-USDT"],
        ["BTC-USDT", "ETH-USDT"],
        production=True,
    ) == ["BTC-USDT"]
    assert _strategy_instruments(
        ["BTC-USDT"],
        ["BTC-USDT", "ETH-USDT"],
        production=False,
    ) == ["BTC-USDT", "ETH-USDT"]


@pytest.mark.unit
def test_direct_production_live_cannot_bypass_launch_and_receipt(
    tmp_path, monkeypatch
):
    import scripts.deployment_receipt as receipt_module
    import scripts.launch_manifest as manifest_module
    import scripts.production_gate as gate_module

    launch = {
        "version": 1,
        "strategy": "ma_cross",
        "bar": "1H",
        "instruments": ["BTC-USDT"],
        "interval_seconds": 60,
    }
    observed = {}
    monkeypatch.setattr(
        manifest_module,
        "load_launch_manifest",
        lambda _path: launch,
    )
    monkeypatch.setattr(
        gate_module,
        "_actual_runtime_identity",
        lambda **_kwargs: {"config_hash": "a" * 64},
    )
    monkeypatch.setattr(
        receipt_module,
        "validate_deployment_receipt",
        lambda *_args, **kwargs: observed.update({
            "identity": kwargs["identity"],
        }),
    )
    settings = SimpleNamespace(
        release_root=str(tmp_path),
        launch_manifest_path=str(tmp_path / "launch.json"),
        deployment_receipt_path=str(tmp_path / "receipt.json"),
        admission_approval_path=str(tmp_path / "approval.json"),
        admission_approval_public_key=str(tmp_path / "approval.pem"),
        admission_evidence_path=str(tmp_path / "evidence.json"),
    )
    args = SimpleNamespace(
        config=str(tmp_path / "config.yaml"),
        screen=0,
        strategy="ma_cross",
        bar="1H",
        inst="BTC-USDT",
        interval=60,
    )
    _validate_production_deployment(args, {}, settings)
    assert observed["identity"] == {"config_hash": "a" * 64}
    args.strategy = "rsi_mean"
    with pytest.raises(ValueError, match="未精确匹配"):
        _validate_production_deployment(args, {}, settings)


@pytest.mark.unit
def test_production_config_rejects_environment_mismatch():
    cfg = _config()
    cfg["production"]["environment"] = "production"
    cfg["production"]["account_id"] = "subaccount"
    with pytest.raises(ValueError, match="不一致"):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
def test_production_config_requires_credentials_for_live_runtime():
    cfg = _config()
    cfg["okx"]["api_key"] = ""
    with pytest.raises(ValueError, match="api_key"):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
def test_read_only_operations_can_validate_without_credentials():
    cfg = _config()
    cfg["okx"]["api_key"] = ""
    settings = ProductionSettings.from_config(
        cfg, require_credentials=False
    )
    assert settings.environment == "demo"


@pytest.mark.unit
def test_production_config_allows_hardened_absolute_service_paths():
    cfg = _config()
    cfg["production"].update({
        "journal_path": "/var/lib/okx-quant/demo/trading.db",
        "lock_path": "/var/lib/okx-quant/demo/trading.lock",
        "backup_dir": "/var/lib/okx-quant/demo/backups",
        "heartbeat_path": "/var/lib/okx-quant/demo/heartbeat",
    })
    settings = ProductionSettings.from_config(cfg)
    assert settings.journal_path.startswith("/var/lib/okx-quant/")


@pytest.mark.unit
def test_production_config_rejects_unsafe_parent_path():
    cfg = _config()
    cfg["production"]["journal_path"] = "../trading.db"
    with pytest.raises(ValueError, match="\\.\\."):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
def test_hardened_production_config_requires_and_accepts_external_controls(
    monkeypatch,
):
    cfg = _config()
    cfg["okx"]["simulated"] = False
    cfg["production"].update({
        "environment": "production",
        "account_id": "canary-subaccount",
        "journal_path": "/var/lib/okx-quant/production/trading.db",
        "lock_path": "/var/lib/okx-quant/production/trading.lock",
        "backup_dir": "/var/lib/okx-quant/production/backups",
        "heartbeat_path": "/var/lib/okx-quant/production/heartbeat",
        "offsite_backup_uri": "",
        "external_backup_managed": True,
        "resume_approval_public_key": "/etc/okx-quant/risk-approver.pub",
    })
    monkeypatch.setenv("OKX_QUANT_ALERT_WEBHOOK", "https://alerts.example")
    monkeypatch.setenv(
        "OKX_QUANT_BACKUP_PASSPHRASE", "test-only-passphrase"
    )
    settings = ProductionSettings.from_config(cfg)
    assert settings.environment == "production"


@pytest.mark.unit
def test_isolated_backup_keeps_passphrase_out_of_trader(monkeypatch):
    cfg = _config()
    cfg["okx"]["simulated"] = False
    cfg["production"].update({
        "environment": "production",
        "account_id": "canary-subaccount",
        "journal_path": "/var/lib/okx-quant/production/trading.db",
        "lock_path": "/var/lib/okx-quant/production/trading.lock",
        "backup_dir": "/var/lib/okx-quant/production/backups",
        "heartbeat_path": "/var/lib/okx-quant/production/heartbeat",
        "offsite_backup_uri": "",
        "external_backup_managed": True,
        "resume_approval_public_key": "/etc/okx-quant/risk-approver.pub",
    })
    monkeypatch.setenv("OKX_QUANT_ALERT_WEBHOOK", "https://alerts.example")
    monkeypatch.delenv("OKX_QUANT_BACKUP_PASSPHRASE", raising=False)
    assert ProductionSettings.from_config(cfg).external_backup_managed


@pytest.mark.unit
def test_production_rejects_self_managed_offsite_backup(monkeypatch):
    cfg = _config()
    cfg["okx"]["simulated"] = False
    cfg["production"].update({
        "environment": "production",
        "account_id": "canary-subaccount",
        "journal_path": "/var/lib/okx-quant/production/trading.db",
        "lock_path": "/var/lib/okx-quant/production/trading.lock",
        "backup_dir": "/var/lib/okx-quant/production/backups",
        "heartbeat_path": "/var/lib/okx-quant/production/heartbeat",
        "offsite_backup_uri": "s3://fixture/okx/",
        "resume_approval_public_key": "/etc/okx-quant/risk-approver.pub",
    })
    monkeypatch.setenv("OKX_QUANT_ALERT_WEBHOOK", "https://alerts.example")
    monkeypatch.delenv("OKX_QUANT_BACKUP_PASSPHRASE", raising=False)
    with pytest.raises(ValueError, match="隔离备份"):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
def test_production_cannot_disable_durable_runtime(monkeypatch):
    cfg = _config()
    cfg["okx"]["simulated"] = False
    cfg["production"].update({
        "enabled": False,
        "environment": "production",
    })
    with pytest.raises(ValueError, match="禁止关闭"):
        ProductionSettings.from_config(
            cfg,
            require_external_controls=False,
        )


@pytest.mark.unit
def test_production_rejects_non_okx_api_host(monkeypatch):
    cfg = _config()
    cfg["okx"].update({
        "simulated": False,
        "base_url": "https://attacker.example",
    })
    cfg["production"].update({
        "environment": "production",
    })
    with pytest.raises(ValueError, match="官方 OKX"):
        ProductionSettings.from_config(
            cfg,
            require_external_controls=False,
        )


@pytest.mark.unit
def test_production_rejects_non_integer_position_limit():
    cfg = _config()
    cfg["production"]["max_open_positions"] = 1.5
    with pytest.raises(ValueError, match="必须是整数"):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_production_rejects_non_finite_numeric_limits(value):
    cfg = _config()
    cfg["production"]["max_account_snapshot_age_s"] = value
    with pytest.raises(ValueError, match="有限"):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
def test_production_rejects_non_finite_decimal_limits():
    cfg = _config()
    cfg["production"]["max_order_loss_usdt"] = "NaN"
    with pytest.raises(ValueError, match="有限"):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("max_market_data_age_s", 31, "行情最大年龄"),
        ("max_account_snapshot_age_s", 91, "账户快照最大年龄"),
        ("max_unprotected_position_s", 11, "无保护仓位"),
        (
            "max_consecutive_infrastructure_errors",
            6,
            "连续基础设施错误",
        ),
        ("max_order_loss_usdt", 101, "硬上限"),
        ("max_position_notional_usdt", 2001, "硬上限"),
        ("max_total_exposure_usdt", 5001, "硬上限"),
        ("max_daily_loss_usdt", 251, "硬上限"),
        ("max_drawdown_ratio", 0.16, "硬上限"),
        ("max_spread_ratio", 0.011, "硬上限"),
        ("max_slippage_ratio", 0.051, "硬上限"),
        ("max_candle_range_ratio", 0.21, "硬上限"),
        ("max_open_positions", 6, "最大持仓数"),
        ("max_order_intents_per_hour", 61, "订单意图上限"),
        ("min_24h_quote_volume_usdt", 0, "成交额"),
    ],
)
def test_production_rejects_unsafe_infrastructure_limits(
    field,
    value,
    message,
):
    cfg = _config()
    cfg["production"][field] = value
    with pytest.raises(ValueError, match=message):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        [],
        ["btc-usdt"],
        ["BTC-USDT", "BTC-USDT"],
        [f"C{i}-USDT" for i in range(11)],
    ],
)
def test_production_rejects_missing_or_invalid_allowlist(value):
    cfg = _config()
    cfg["okx"]["simulated"] = False
    cfg["production"].update({
        "environment": "production",
        "allowed_instruments": value,
    })
    with pytest.raises(ValueError, match="allowed_instruments"):
        ProductionSettings.from_config(
            cfg,
            require_external_controls=False,
        )


@pytest.mark.unit
def test_production_metrics_cannot_bind_public_interface(monkeypatch):
    cfg = _config()
    cfg["okx"]["simulated"] = False
    cfg["production"].update({
        "environment": "production",
        "account_id": "canary-subaccount",
        "journal_path": "/var/lib/okx-quant/production/trading.db",
        "lock_path": "/var/lib/okx-quant/production/trading.lock",
        "backup_dir": "/var/lib/okx-quant/production/backups",
        "heartbeat_path": "/var/lib/okx-quant/production/heartbeat",
        "offsite_backup_uri": "",
        "external_backup_managed": True,
        "resume_approval_public_key": "/etc/okx-quant/risk-approver.pub",
        "metrics_host": "0.0.0.0",
    })
    monkeypatch.setenv("OKX_QUANT_ALERT_WEBHOOK", "https://alerts.example")
    monkeypatch.setenv(
        "OKX_QUANT_BACKUP_PASSPHRASE", "test-only-passphrase"
    )
    with pytest.raises(ValueError, match="回环"):
        ProductionSettings.from_config(cfg)


@pytest.mark.unit
def test_env_file_loader_never_executes_shell_syntax(tmp_path, monkeypatch):
    monkeypatch.delenv("SAFE_LITERAL", raising=False)
    path = tmp_path / "production.env"
    path.write_text("SAFE_LITERAL=$(touch /tmp/never-execute)\n", encoding="utf-8")
    load_env_file(str(path))
    assert os.environ["SAFE_LITERAL"] == "$(touch /tmp/never-execute)"


@pytest.mark.unit
def test_env_file_loader_rejects_empty_key(tmp_path):
    path = tmp_path / "invalid.env"
    path.write_text("=value\n", encoding="utf-8")
    with pytest.raises(ValueError, match="变量名非法"):
        load_env_file(str(path))


@pytest.mark.unit
def test_explicit_journal_initializer_installs_halted_identity_atomically(
    tmp_path,
):
    cfg = _config()
    path = tmp_path / "state" / "trading.db"
    cfg["production"]["journal_path"] = str(path)
    cfg["production"]["lock_path"] = str(tmp_path / "state" / "trading.lock")
    cfg["production"]["backup_dir"] = str(tmp_path / "backups")
    cfg["production"]["heartbeat_path"] = str(tmp_path / "heartbeat")
    args = SimpleNamespace(
        confirm="INIT demo",
        actor="bootstrap",
    )
    cmd_init_journal(args, cfg)
    journal = SQLiteJournal(path, must_exist=True)
    try:
        assert journal.assert_identity("demo")["initialized_by"] == "bootstrap"
        assert journal.get_mode() is SystemMode.HALTED
    finally:
        journal.close()
    assert not list(path.parent.glob(f".{path.name}.init-*.tmp"))
    with pytest.raises(SystemExit, match="拒绝覆盖"):
        cmd_init_journal(args, cfg)


@pytest.mark.unit
@pytest.mark.linux_ci_required
def test_production_journal_initializer_sets_shared_group_permissions(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "production" / "trading.db"
    settings = replace(
        ProductionSettings(),
        environment="production",
        account_id="production-account",
        journal_path=str(path),
    )
    monkeypatch.setattr(
        ProductionSettings,
        "from_config",
        classmethod(lambda _cls, *_args, **_kwargs: settings),
    )
    monkeypatch.setattr(
        main_module.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_uid=os.getuid()),
    )
    monkeypatch.setattr(
        main_module.grp,
        "getgrnam",
        lambda _name: SimpleNamespace(gr_gid=os.getgid()),
    )
    args = SimpleNamespace(
        confirm="INIT production-account",
        actor="bootstrap",
        owner_user="okxquant-trader",
        owner_group="okxquant-data",
    )

    cmd_init_journal(args, _config())

    assert path.stat().st_mode & 0o777 == 0o640
    assert path.stat().st_uid == os.getuid()
    assert path.stat().st_gid == os.getgid()
    if (
        sys.platform == "darwin"
        and path.parent.stat().st_mode & 0o2000 == 0
    ):
        pytest.skip("macOS 临时文件系统不保留 Linux setgid 目录位")
    assert path.parent.stat().st_mode & 0o7777 == 0o2750
