"""Fail-closed deployment preflight for isolated OKX Demo environments."""

from __future__ import annotations

import fcntl
import grp
import json
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from okx_quant.client.websocket import ConnectionState
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.infrastructure.evidence import (
    build_release_identity,
    credential_fingerprint,
    redacted_config_hash,
    sha256_bytes,
)
from okx_quant.research.costs import DynamicCostModel

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ROLES = {"shadow", "active", "chaos"}
_RECEIPT_KEYS = {
    "version",
    "action",
    "issued_at",
    "expires_at",
    "role",
    "unit_name",
    "unit_sha256",
    "unix_uid",
    "unix_gid",
    "account_uid",
    "soak_epoch_id",
    "key_fingerprint",
    "config_sha256",
    "release_identity",
    "launch_identity",
    "network_namespace",
    "network_namespace_identity",
}


@dataclass(frozen=True)
class DemoDeploymentProfile:
    role: str
    unit_name: str
    unit_file: Path
    unix_user: str
    unix_group: str
    monitor_user: str
    backup_user: str
    environment_file: Path
    state_dir: Path
    backup_dir: Path
    log_dir: Path
    release_root: Path
    receipt_path: Path
    network_namespace: Path
    account_uid: str
    soak_epoch_id: str
    key_fingerprint: str
    metrics_port: int
    instrument: str
    fault_proxy_targets: dict
    backup_receipt_path: Path
    backup_receipt_public_key: Path
    backup_receipt_key_id: str
    operator_inbox_dir: Path
    alert_provider_receipt_public_key: Path
    alert_human_ack_public_key: Path
    alert_escalation_public_key: Path
    external_lease_url: str
    external_lease_public_key: Path | None
    external_lease_token_env: str
    external_lease_broker_id: str
    external_lease_ttl_s: int
    cost_model_manifest: dict
    probe_schedule_path: Path | None = None
    receipt_ttl_s: int = 300
    min_free_bytes: int = 5 * 1024 * 1024 * 1024
    min_free_inodes: int = 10_000

    @classmethod
    def from_config(cls, cfg: dict) -> DemoDeploymentProfile:
        raw = cfg.get("demo_validation")
        if not isinstance(raw, dict):
            raise ValueError("缺少 demo_validation 配置")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(raw) - allowed
        missing = {
            name
            for name in allowed
            if name
            not in {
                "receipt_ttl_s",
                "min_free_bytes",
                "min_free_inodes",
                "probe_schedule_path",
            }
            and name not in raw
        }
        if unknown or missing:
            raise ValueError(
                f"demo_validation 字段非法: missing={sorted(missing)}, unknown={sorted(unknown)}"
            )
        path_fields = {
            "unit_file",
            "environment_file",
            "state_dir",
            "backup_dir",
            "log_dir",
            "release_root",
            "receipt_path",
            "network_namespace",
            "probe_schedule_path",
            "backup_receipt_path",
            "backup_receipt_public_key",
            "operator_inbox_dir",
            "alert_provider_receipt_public_key",
            "alert_human_ack_public_key",
            "alert_escalation_public_key",
            "external_lease_public_key",
        }
        values = {
            key: (Path(value) if key in path_fields and value is not None else value)
            for key, value in raw.items()
        }
        profile = cls(**values)
        profile.validate()
        return profile

    def validate(self) -> None:
        if self.role not in _ROLES:
            raise ValueError("Demo role 必须是 shadow/active/chaos")
        expected_unit = f"okx-quant-demo-{self.role}.service"
        if self.unit_name != expected_unit:
            raise ValueError(f"unit_name 必须是 {expected_unit}")
        for name in ("unix_user", "unix_group", "monitor_user", "backup_user"):
            if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", getattr(self, name)):
                raise ValueError(f"Demo {name} 非法")
        if not _SHA256.fullmatch(self.key_fingerprint):
            raise ValueError("Demo key_fingerprint 必须是 64 位 SHA-256")
        if not self.account_uid.strip():
            raise ValueError("Demo account_uid 不能为空")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", self.soak_epoch_id):
            raise ValueError("Demo soak_epoch_id 非法")
        if not re.fullmatch(r"[A-Z0-9]{2,15}-USDT", self.instrument):
            raise ValueError("Demo instrument 必须是 *-USDT 现货")
        if self.role == "chaos":
            if set(self.fault_proxy_targets) != {
                "public",
                "private",
                "business",
            }:
                raise ValueError("Chaos 必须配置三路 fault_proxy_targets")
        elif self.fault_proxy_targets:
            raise ValueError("只有 Chaos 允许配置 fault_proxy_targets")
        seen_ports: set[int] = set()
        for name, target in self.fault_proxy_targets.items():
            if (
                not isinstance(target, dict)
                or set(target) != {"host", "port"}
                or target["host"] not in {"127.0.0.1", "::1", "localhost"}
                or type(target["port"]) is not int
                or not 1 <= target["port"] <= 65535
                or target["port"] in seen_ports
            ):
                raise ValueError(f"{name} fault proxy target 非法或端口复用")
            seen_ports.add(target["port"])
        if type(self.metrics_port) is not int or not 1 <= self.metrics_port <= 65535:
            raise ValueError("Demo metrics_port 非法")
        if type(self.receipt_ttl_s) is not int or not 60 <= self.receipt_ttl_s <= 600:
            raise ValueError("Demo receipt_ttl_s 必须在 60..600 秒")
        for name in ("min_free_bytes", "min_free_inodes"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"Demo {name} 必须是正整数")
        for field_name in (
            "unit_file",
            "environment_file",
            "state_dir",
            "backup_dir",
            "log_dir",
            "release_root",
            "receipt_path",
            "network_namespace",
            "backup_receipt_path",
            "backup_receipt_public_key",
            "operator_inbox_dir",
            "alert_provider_receipt_public_key",
            "alert_human_ack_public_key",
            "alert_escalation_public_key",
        ):
            path = getattr(self, field_name)
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError(f"Demo {field_name} 必须是无 .. 的绝对路径")
        if not self.backup_receipt_key_id.strip():
            raise ValueError("Demo backup_receipt_key_id 不能为空")
        if (
            not self.operator_inbox_dir.is_relative_to(self.state_dir)
            or self.operator_inbox_dir == self.state_dir
        ):
            raise ValueError("Demo operator_inbox_dir 必须位于专属 state_dir 内")
        alert_key_paths = {
            self.alert_provider_receipt_public_key,
            self.alert_human_ack_public_key,
            self.alert_escalation_public_key,
        }
        if len(alert_key_paths) != 3:
            raise ValueError("Demo provider/human/escalation 必须配置三个不同公钥路径")
        for name in (
            "backup_receipt_public_key",
            "alert_provider_receipt_public_key",
            "alert_human_ack_public_key",
            "alert_escalation_public_key",
        ):
            if not getattr(self, name).is_relative_to("/etc/okx-quant/keys"):
                raise ValueError(f"Demo {name} 必须位于 /etc/okx-quant/keys")
        lease_url = urlparse(self.external_lease_url)
        if self.role in {"active", "chaos"}:
            if (
                lease_url.scheme != "https"
                or not lease_url.hostname
                or lease_url.username
                or lease_url.password
                or self.external_lease_public_key is None
                or not self.external_lease_public_key.is_absolute()
                or not self.external_lease_public_key.is_relative_to("/etc/okx-quant/keys")
                or not self.external_lease_token_env.strip()
                or not self.external_lease_broker_id.strip()
                or not 15 <= self.external_lease_ttl_s <= 60
            ):
                raise ValueError("Demo Active/Chaos 必须配置 HTTPS account-UID 外部租约")
        elif (
            self.external_lease_url
            or self.external_lease_public_key is not None
            or self.external_lease_token_env
            or self.external_lease_broker_id
            or self.external_lease_ttl_s != 0
        ):
            raise ValueError("Demo Shadow 不得持有 writer lease 凭据")
        if (
            not isinstance(self.cost_model_manifest, dict)
            or set(self.cost_model_manifest)
            != {
                "model",
                "fee_rate",
                "minimum_slippage",
                "range_fraction",
                "impact_coefficient",
                "maximum_slippage",
                "stress_multiplier",
            }
            or self.cost_model_manifest.get("model") != "okx_quant.research.costs.DynamicCostModel"
            or DynamicCostModel(
                **{key: value for key, value in self.cost_model_manifest.items() if key != "model"}
            ).manifest()
            != self.cost_model_manifest
        ):
            raise ValueError("Demo cost_model_manifest 非法或非规范")
        if self.probe_schedule_path is not None and (
            not self.probe_schedule_path.is_absolute() or ".." in self.probe_schedule_path.parts
        ):
            raise ValueError("Demo probe_schedule_path 必须是无 .. 的绝对路径")

    def websocket_targets(self) -> dict[str, tuple[str, int]]:
        return {
            name: (str(target["host"]), int(target["port"]))
            for name, target in self.fault_proxy_targets.items()
        }


def validate_runtime_profile_binding(
    profile: DemoDeploymentProfile,
    settings: object,
    cfg: dict,
) -> None:
    """Bind every writable/runtime path to the isolated deployment profile."""
    if (
        getattr(settings, "environment", None) != "demo"
        or cfg.get("okx", {}).get("simulated") is not True
    ):
        raise RuntimeError("Demo preflight 要求 environment=demo/simulated=true")
    if getattr(settings, "shadow_mode", None) is not (profile.role == "shadow"):
        raise RuntimeError("Demo role 与 production.shadow_mode 不一致")
    if getattr(settings, "account_id", None) != profile.account_uid:
        raise RuntimeError("production.account_id 必须等于 demo_validation.account_uid")
    if getattr(settings, "metrics_host", None) != "127.0.0.1":
        raise RuntimeError("Demo metrics_host 必须精确绑定 127.0.0.1")
    if getattr(settings, "metrics_port", None) != profile.metrics_port:
        raise RuntimeError("Demo metrics_port 与 production.metrics_port 不一致")
    if tuple(getattr(settings, "allowed_instruments", ())) != (profile.instrument,):
        raise RuntimeError("Demo allowed_instruments 必须精确等于 profile instrument")

    expected_settings_paths = {
        "journal_path": profile.state_dir / "trading.db",
        "lock_path": profile.state_dir / "trading.lock",
        "heartbeat_path": profile.state_dir / "heartbeat",
        "backup_dir": profile.backup_dir,
        "release_root": profile.release_root,
        "deployment_receipt_path": profile.receipt_path,
        "backup_receipt_path": profile.backup_receipt_path,
        "backup_receipt_public_key": profile.backup_receipt_public_key,
    }
    for field_name, expected in expected_settings_paths.items():
        actual = Path(str(getattr(settings, field_name, "")))
        if actual != expected:
            raise RuntimeError(
                f"Demo {field_name} 未绑定隔离 profile: "
                f"expected={expected}, actual={actual}"
            )
    if getattr(settings, "backup_receipt_key_id", None) != profile.backup_receipt_key_id:
        raise RuntimeError("Demo backup_receipt_key_id 与隔离 profile 不一致")

    logging_cfg = cfg.get("logging")
    if not isinstance(logging_cfg, dict):
        raise RuntimeError("Demo logging 配置必须是映射")
    expected_log = profile.log_dir / "quant.log"
    actual_log = Path(str(logging_cfg.get("file", "")))
    if actual_log != expected_log:
        raise RuntimeError(
            f"Demo logging.file 未绑定隔离 profile: "
            f"expected={expected_log}, actual={actual_log}"
        )

    executor_cfg = cfg.get("executor")
    if not isinstance(executor_cfg, dict):
        raise RuntimeError("Demo executor 配置必须是映射")
    expected_legacy_state = profile.state_dir / "legacy-state"
    actual_legacy_state = Path(str(executor_cfg.get("state_dir", "")))
    if actual_legacy_state != expected_legacy_state:
        raise RuntimeError(
            "Demo executor.state_dir 未绑定隔离 profile: "
            f"expected={expected_legacy_state}, actual={actual_legacy_state}"
        )


def normalize_okx_permissions(raw: object) -> frozenset[str]:
    """Normalize the exact OKX account/config permission vocabulary."""
    if not isinstance(raw, str):
        raise ValueError("OKX account config perm 缺失")
    result: set[str] = set()
    for token in re.split(r"[,; ]+", raw.strip().lower()):
        if not token:
            continue
        if token in {"read", "read_only", "readonly"}:
            result.add("read")
        elif token in {"trade"}:
            result.add("trade")
        else:
            result.add(token)
    return frozenset(result)


def validate_okx_permissions(role: str, raw: object) -> frozenset[str]:
    actual = normalize_okx_permissions(raw)
    expected = frozenset({"read"}) if role == "shadow" else frozenset({"read", "trade"})
    if actual != expected:
        raise RuntimeError(f"{role} API 权限必须精确为 {sorted(expected)}，实际 {sorted(actual)}")
    return actual


def _decimal(value: object, label: str) -> Decimal:
    try:
        parsed = Decimal(str(value or "0"))
    except (InvalidOperation, ValueError) as exc:
        raise RuntimeError(f"{label} 不是合法十进制数") from exc
    if not parsed.is_finite() or parsed < 0:
        raise RuntimeError(f"{label} 必须是非负有限数")
    return parsed


def balance_details(rows: object) -> dict[str, Decimal]:
    if not isinstance(rows, list):
        raise RuntimeError("OKX balance 返回结构非法")
    result: dict[str, Decimal] = {}
    for account in rows:
        if not isinstance(account, dict):
            raise RuntimeError("OKX balance account 行非法")
        details = account.get("details", [])
        if not isinstance(details, list):
            raise RuntimeError("OKX balance details 非数组")
        for item in details:
            if not isinstance(item, dict):
                raise RuntimeError("OKX balance detail 行非法")
            ccy = str(item.get("ccy", "")).strip().upper()
            if not ccy:
                raise RuntimeError("OKX balance detail 缺少 ccy")
            qty = _decimal(
                item.get("cashBal", item.get("eq", item.get("availBal", "0"))),
                f"{ccy} balance",
            )
            result[ccy] = result.get(ccy, Decimal("0")) + qty
    return result


def _instrument_dust(instrument: dict, ccy: str) -> Decimal:
    lot = _decimal(instrument.get("lotSz"), f"{ccy} lotSz")
    minimum = _decimal(instrument.get("minSz"), f"{ccy} minSz")
    positive = [value for value in (lot, minimum) if value > 0]
    if not positive:
        raise RuntimeError(f"{ccy} instrument 缺少正 lotSz/minSz")
    return min(positive)


def validate_account_state(
    *,
    role: str,
    balances: dict[str, Decimal],
    instruments: list[dict],
    pending_orders: list[dict],
    pending_algos: list[dict],
    local_positions: list[dict],
) -> None:
    if pending_orders:
        raise RuntimeError(f"{role} 账户存在 {len(pending_orders)} 个普通挂单")
    if pending_algos:
        raise RuntimeError(f"{role} 账户存在 {len(pending_algos)} 个 algo")
    instrument_by_base: dict[str, dict] = {}
    for item in instruments:
        if not isinstance(item, dict):
            continue
        inst_id = str(item.get("instId", ""))
        parts = inst_id.split("-")
        if len(parts) == 2 and parts[1] == "USDT":
            instrument_by_base[parts[0]] = item
    local = {
        str(row["inst_id"]).split("-")[0]: _decimal(
            row["base_qty"], f"{row['inst_id']} local base_qty"
        )
        for row in local_positions
    }
    unexplained: list[str] = []
    for ccy, quantity in balances.items():
        if ccy == "USDT" or quantity == 0:
            continue
        instrument = instrument_by_base.get(ccy)
        if instrument is None:
            unexplained.append(f"{ccy}={quantity}:missing_instrument")
            continue
        dust = _instrument_dust(instrument, ccy)
        if role == "shadow":
            if quantity >= dust:
                unexplained.append(f"{ccy}={quantity}:dust<{dust}")
            continue
        expected = local.get(ccy, Decimal("0"))
        if abs(quantity - expected) >= dust:
            unexplained.append(f"{ccy}={quantity}:journal={expected}:tolerance<{dust}")
    if role != "shadow":
        for ccy, expected in local.items():
            actual = balances.get(ccy, Decimal("0"))
            instrument = instrument_by_base.get(ccy)
            if instrument is None:
                unexplained.append(f"{ccy}:journal_position_missing_instrument")
                continue
            dust = _instrument_dust(instrument, ccy)
            if abs(actual - expected) >= dust:
                unexplained.append(f"{ccy}={actual}:journal={expected}:tolerance<{dust}")
    if unexplained:
        raise RuntimeError(f"{role} 账户存在非 dust 或不可解释持仓: " + "; ".join(unexplained))


def _secure_regular_file(
    path: Path,
    *,
    root_owned: bool,
    exact_mode: int | None = None,
) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"文件不存在: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise RuntimeError(f"必须是非符号链接普通文件: {path}")
    if root_owned and info.st_uid != 0:
        raise RuntimeError(f"必须由 root 持有: {path}")
    mode = stat.S_IMODE(info.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise RuntimeError(f"{path} mode 必须为 {oct(exact_mode)}，实际 {oct(mode)}")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError(f"文件不可由 group/other 写入: {path}")
    return info


def _secure_ancestors(path: Path, *, stop: Path = Path("/")) -> None:
    candidate = Path(os.path.abspath(path)).parent
    lexical_stop = Path(os.path.abspath(stop))
    while True:
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"祖先路径非法: {candidate}")
        writable_by_non_owner = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        controlled_sticky_root = (
            info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        )
        if writable_by_non_owner and not controlled_sticky_root:
            raise RuntimeError(f"祖先目录可被任意用户写入: {candidate}")
        if candidate == lexical_stop or candidate == candidate.parent:
            break
        candidate = candidate.parent


def _parse_systemd_unit(path: Path) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    section = ""
    logical_lines: list[str] = []
    pending = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if pending:
            stripped = pending + stripped
            pending = ""
        if stripped.endswith("\\"):
            pending = stripped[:-1]
            continue
        logical_lines.append(stripped)
    if pending:
        raise RuntimeError("systemd unit 存在未闭合续行")
    for line in logical_lines:
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if not section:
                raise RuntimeError("systemd unit section 不能为空")
            sections.setdefault(section, {})
            continue
        key, separator, value = line.partition("=")
        if not section or not separator or not key.strip():
            raise RuntimeError(f"systemd unit 行无法解析: {line}")
        sections.setdefault(section, {}).setdefault(
            key.strip(),
            [],
        ).append(value.strip())
    return sections


def _require_single_systemd_value(
    sections: dict[str, dict[str, list[str]]],
    *,
    section: str,
    key: str,
    expected: str,
) -> None:
    values = sections.get(section, {}).get(key, [])
    if values != [expected]:
        raise RuntimeError(
            f"systemd [{section}] {key} 必须唯一且精确为 {expected!r}，"
            f"实际 {values!r}"
        )


def _validate_loaded_systemd_unit(profile: DemoDeploymentProfile) -> None:
    result = subprocess.run(
        [
            "systemctl",
            "show",
            profile.unit_name,
            "--property=FragmentPath",
            "--property=DropInPaths",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"无法取得 systemd effective unit identity: {result.stderr.strip()}"
        )
    properties = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key] = value
    fragment = Path(properties.get("FragmentPath", ""))
    if fragment != profile.unit_file:
        raise RuntimeError(
            "systemd effective FragmentPath 与受控 unit_file 不一致"
        )
    if properties.get("DropInPaths", "").strip():
        raise RuntimeError("Demo unit 禁止使用未纳入 receipt 的 systemd drop-in")


def validate_unit_file(profile: DemoDeploymentProfile) -> None:
    controlled = profile.unit_file.is_relative_to("/etc/systemd/system")
    _secure_regular_file(profile.unit_file, root_owned=controlled)
    sections = _parse_systemd_unit(profile.unit_file)
    for section, key, expected in (
        ("Unit", "StartLimitIntervalSec", "300"),
        ("Unit", "StartLimitBurst", "5"),
        ("Service", "User", profile.unix_user),
        ("Service", "Group", profile.unix_group),
        ("Service", "ProtectProc", "invisible"),
        ("Service", "ProcSubset", "pid"),
        ("Service", "ProtectSystem", "strict"),
        ("Service", "ProtectHome", "true"),
        ("Service", "PrivateDevices", "true"),
        ("Service", "MemoryHigh", "500M"),
        ("Service", "MemoryMax", "600M"),
        ("Service", "LimitNOFILE", "4096"),
        ("Service", "TasksMax", "128"),
        ("Service", "OOMPolicy", "stop"),
        (
            "Service",
            "NetworkNamespacePath",
            str(profile.network_namespace),
        ),
        (
            "Service",
            "ReadWritePaths",
            f"{profile.state_dir} {profile.log_dir}",
        ),
    ):
        _require_single_systemd_value(
            sections,
            section=section,
            key=key,
            expected=expected,
        )
    if controlled:
        _validate_loaded_systemd_unit(profile)


def unit_launch_identity(
    profile: DemoDeploymentProfile,
    *,
    config_path: Path,
) -> dict:
    """Parse the single controlled ExecStart into an exact live launch."""
    if not config_path.is_absolute() or ".." in config_path.parts:
        raise RuntimeError("Demo config path 必须是无 .. 的绝对路径")
    lines = [
        line.strip()
        for line in profile.unit_file.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("ExecStart=")
    ]
    if len(lines) != 1:
        raise RuntimeError("Demo systemd unit 必须且只能有一个 ExecStart")
    raw = lines[0].split("=", 1)[1]
    if any(marker in raw for marker in ("$", "%", "\n", "\r")):
        raise RuntimeError("Demo ExecStart 禁止变量、specifier 或换行展开")
    try:
        argv = shlex.split(raw, posix=True)
    except ValueError as exc:
        raise RuntimeError("Demo ExecStart shell quoting 非法") from exc
    expected_python = str(profile.release_root / ".venv/bin/python")
    expected_main = str(profile.release_root / "main.py")
    if len(argv) != 15 or argv[:5] != [
        expected_python,
        expected_main,
        "--config",
        str(config_path),
        "live",
    ]:
        raise RuntimeError("Demo ExecStart executable/config/live 前缀非法")
    expected_flags = (
        "--inst",
        "--strategy",
        "--bar",
        "--interval",
        "--no-dashboard",
        "--yes",
    )
    if (
        argv[5] != expected_flags[0]
        or argv[7] != expected_flags[1]
        or argv[9] != expected_flags[2]
        or argv[11] != expected_flags[3]
        or argv[13:] != list(expected_flags[4:])
    ):
        raise RuntimeError("Demo ExecStart 参数顺序或集合不受控")
    instruments = argv[6].split(",")
    if (
        not instruments
        or len(instruments) != len(set(instruments))
        or any(not re.fullmatch(r"[A-Z0-9]{2,15}-USDT", item) for item in instruments)
    ):
        raise RuntimeError("Demo ExecStart instruments 非法")
    if instruments != list(dict.fromkeys(instruments)):
        raise RuntimeError("Demo ExecStart instruments 顺序/唯一性非法")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", argv[8]):
        raise RuntimeError("Demo ExecStart strategy 非法")
    if profile.role == "active" and argv[8] != "validation_probe":
        raise RuntimeError("Demo Active ExecStart strategy 必须是 validation_probe")
    if argv[10] not in {
        "1m",
        "3m",
        "5m",
        "15m",
        "30m",
        "1H",
        "2H",
        "4H",
        "6H",
        "12H",
        "1D",
        "1W",
    }:
        raise RuntimeError("Demo ExecStart bar 非法")
    try:
        interval_seconds = int(argv[12])
    except ValueError as exc:
        raise RuntimeError("Demo ExecStart interval 非法") from exc
    if not 1 <= interval_seconds <= 86400 or str(interval_seconds) != argv[12]:
        raise RuntimeError("Demo ExecStart interval 必须是规范正整数")
    return {
        "process_argv": argv[1:],
        "strategy": argv[8],
        "bar": argv[10],
        "instruments": instruments,
        "interval_seconds": interval_seconds,
    }


def validate_environment_file(profile: DemoDeploymentProfile) -> None:
    controlled = profile.environment_file.is_relative_to("/etc/okx-quant")
    info = _secure_regular_file(
        profile.environment_file,
        root_owned=controlled,
        exact_mode=0o640,
    )
    expected_gid = grp.getgrnam(profile.unix_group).gr_gid
    if info.st_gid != expected_gid:
        raise RuntimeError(
            "Demo environment file group 必须精确等于目标 role data group"
        )
    _secure_ancestors(profile.environment_file)


def validate_directory(
    path: Path,
    *,
    allowed_uids: set[int],
    expected_gid: int,
    allowed_modes: set[int],
    min_free_bytes: int,
    min_free_inodes: int,
) -> None:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"必须是非符号链接目录: {path}")
    if info.st_uid not in allowed_uids:
        raise RuntimeError(f"{path} owner UID 不在允许集合")
    if info.st_gid != expected_gid:
        raise RuntimeError(f"{path} group GID 与隔离数据组不一致")
    mode = stat.S_IMODE(info.st_mode)
    if mode not in allowed_modes:
        raise RuntimeError(f"{path} mode={oct(mode)} 不在 {sorted(map(oct, allowed_modes))}")
    usage = shutil.disk_usage(path)
    if usage.free < min_free_bytes:
        raise RuntimeError(f"{path} 可用磁盘不足")
    fs = os.statvfs(path)
    if fs.f_favail < min_free_inodes:
        raise RuntimeError(f"{path} 可用 inode 不足")


def validate_peer_isolation(
    current: DemoDeploymentProfile,
    peers: list[tuple[DemoDeploymentProfile, str]],
    *,
    account_uid: str,
    resolve_system_identity: bool = False,
) -> None:
    fields = (
        "key_fingerprint",
        "metrics_port",
        "unix_user",
        "monitor_user",
        "backup_user",
        "state_dir",
        "backup_dir",
        "log_dir",
        "release_root",
        "receipt_path",
        "network_namespace",
        "environment_file",
    )
    for peer, peer_account_uid in peers:
        if peer.role == current.role:
            raise RuntimeError(f"peer role 重复: {peer.role}")
        if peer_account_uid == account_uid:
            raise RuntimeError(f"{current.role}/{peer.role} 复用了 account UID")
        for field_name in fields:
            if getattr(peer, field_name) == getattr(current, field_name):
                raise RuntimeError(f"{current.role}/{peer.role} 复用了 {field_name}")
        for field_name in (
            "state_dir",
            "backup_dir",
            "log_dir",
            "release_root",
            "network_namespace",
        ):
            current_path = getattr(current, field_name)
            peer_path = getattr(peer, field_name)
            if current_path.resolve() == peer_path.resolve():
                raise RuntimeError(f"{current.role}/{peer.role} 实际复用了 {field_name}")
            if current_path.exists() and peer_path.exists():
                current_stat = current_path.stat()
                peer_stat = peer_path.stat()
                if (
                    current_stat.st_dev,
                    current_stat.st_ino,
                ) == (
                    peer_stat.st_dev,
                    peer_stat.st_ino,
                ):
                    raise RuntimeError(f"{current.role}/{peer.role} inode 复用了 {field_name}")
        if resolve_system_identity:
            for field_name in ("unix_user", "monitor_user", "backup_user"):
                current_uid = pwd.getpwnam(getattr(current, field_name)).pw_uid
                peer_uid = pwd.getpwnam(getattr(peer, field_name)).pw_uid
                if current_uid == peer_uid:
                    raise RuntimeError(f"{current.role}/{peer.role} 复用了 {field_name} UID")


def wait_websocket_ready(
    websocket: object,
    *,
    timeout_s: float,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, str]:
    deadline = monotonic() + timeout_s
    websocket.run_in_thread()
    try:
        while monotonic() < deadline:
            states = {
                name: websocket.connection_state(name) for name in ("public", "private", "business")
            }
            if all(state is ConnectionState.READY for state in states.values()):
                return {name: str(state) for name, state in states.items()}
            sleep(0.1)
        states = {
            name: str(websocket.connection_state(name))
            for name in ("public", "private", "business")
        }
        raise RuntimeError(f"三路 WebSocket 未在 {timeout_s}s READY: {states}")
    finally:
        websocket.stop()


def _namespace_identity(path: Path) -> str:
    info = path.stat()
    if path.is_symlink():
        raise RuntimeError("network namespace 不得是符号链接")
    return f"{info.st_dev}:{info.st_ino}"


def _receipt_identity(
    *,
    cfg: dict,
    profile: DemoDeploymentProfile,
    account_uid: str,
    config_path: Path,
) -> dict:
    release = build_release_identity(profile.release_root)
    if not release["workspace_clean"]:
        raise RuntimeError("Demo release workspace 必须 clean")
    unix_uid = pwd.getpwnam(profile.unix_user).pw_uid
    unix_gid = grp.getgrnam(profile.unix_group).gr_gid
    return {
        "role": profile.role,
        "unit_name": profile.unit_name,
        "unit_sha256": sha256_bytes(profile.unit_file.read_bytes()),
        "unix_uid": unix_uid,
        "unix_gid": unix_gid,
        "account_uid": account_uid,
        "soak_epoch_id": profile.soak_epoch_id,
        "key_fingerprint": credential_fingerprint(str(cfg.get("okx", {}).get("api_key", ""))),
        "config_sha256": redacted_config_hash(cfg),
        "release_identity": release,
        "launch_identity": unit_launch_identity(
            profile,
            config_path=config_path,
        ),
        "network_namespace": str(profile.network_namespace),
        "network_namespace_identity": _namespace_identity(profile.network_namespace),
    }


def build_receipt(identity: dict, *, now: int, ttl_s: int) -> dict:
    return {
        "version": 1,
        "action": "authorize-isolated-okx-demo-unit",
        "issued_at": now,
        "expires_at": now + ttl_s,
        **identity,
    }


def _controlled_receipt(path: Path) -> bool:
    return path.is_relative_to("/var/lib/okx-quant") or path.is_relative_to(
        "/run/okx-quant-demo-preflight"
    )


def _validate_controlled_receipt_parent(
    path: Path,
    *,
    expected_group_gid: int,
) -> None:
    parent_stat = path.parent.lstat()
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != 0
        or parent_stat.st_gid != expected_group_gid
        or stat.S_IMODE(parent_stat.st_mode) != 0o750
    ):
        raise RuntimeError("受控 receipt 父目录必须为 root:<目标组> 0750")


def write_receipt(
    path: Path,
    receipt: dict,
    *,
    group_gid: int | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise RuntimeError("receipt 父目录不得是符号链接")
    if _controlled_receipt(path):
        if os.geteuid() != 0 or group_gid is None:
            raise PermissionError("受控 Demo receipt 必须由 root 为目标组签发")
        _validate_controlled_receipt_parent(
            path,
            expected_group_gid=group_gid,
        )
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        if _controlled_receipt(path):
            os.fchown(descriptor, 0, group_gid)
            os.fchmod(descriptor, 0o640)
        payload = (json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n").encode()
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if _controlled_receipt(path):
        os.chown(path, 0, group_gid)
        os.chmod(path, 0o640)
    else:
        os.chmod(path, 0o600)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def verify_receipt(
    path: Path,
    *,
    expected_identity: dict,
    now: int | None = None,
    expected_group_gid: int | None = None,
) -> dict:
    controlled = _controlled_receipt(path)
    if controlled:
        if expected_group_gid is None:
            raise RuntimeError("校验受控 Demo receipt 缺少目标 group GID")
        _validate_controlled_receipt_parent(
            path,
            expected_group_gid=expected_group_gid,
        )
    _secure_regular_file(
        path,
        root_owned=controlled,
        exact_mode=0o640 if controlled else 0o600,
    )
    if controlled and path.stat().st_gid != expected_group_gid:
        raise RuntimeError("受控 Demo receipt group GID 不匹配")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != _RECEIPT_KEYS:
        raise RuntimeError("Demo preflight receipt schema 非法")
    if payload["version"] != 1 or payload["action"] != "authorize-isolated-okx-demo-unit":
        raise RuntimeError("Demo preflight receipt version/action 非法")
    clock = int(time.time()) if now is None else now
    if (
        type(payload["issued_at"]) is not int
        or type(payload["expires_at"]) is not int
        or not payload["issued_at"] <= clock <= payload["expires_at"]
    ):
        raise RuntimeError("Demo preflight receipt 已过期或尚未生效")
    for key, value in expected_identity.items():
        if payload.get(key) != value:
            raise RuntimeError(f"Demo preflight receipt 未绑定当前 {key}")
    return payload


def _process_network_namespace_identity(proc_root: Path) -> str:
    info = (proc_root / "self/ns/net").stat()
    return f"{info.st_dev}:{info.st_ino}"


def _in_expected_service_cgroup(raw: str, unit_name: str) -> bool:
    for line in raw.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path = parts[2]
        if path.startswith("/") and PurePosixPath(path).name == unit_name:
            return True
    return False


def verify_demo_process_context(
    receipt: dict,
    *,
    process_argv: list[str],
    proc_root: Path = Path("/proc"),
    current_uid: int | None = None,
) -> None:
    """Bind the receipt to this exact Unix process before any OKX client."""
    uid = os.getuid() if current_uid is None else current_uid
    if uid != receipt["unix_uid"]:
        raise RuntimeError("Demo receipt Unix UID 与当前进程不匹配")
    if process_argv != receipt["launch_identity"]["process_argv"]:
        raise RuntimeError("Demo receipt live argv 与当前进程不匹配")
    try:
        cgroup = (proc_root / "self/cgroup").read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError("无法读取当前进程 cgroup") from exc
    if not _in_expected_service_cgroup(cgroup, receipt["unit_name"]):
        raise RuntimeError("当前进程不在 receipt 指定的 systemd service cgroup")
    try:
        actual_namespace = _process_network_namespace_identity(proc_root)
    except OSError as exc:
        raise RuntimeError("无法读取当前进程 network namespace") from exc
    if actual_namespace != receipt["network_namespace_identity"]:
        raise RuntimeError("当前进程 network namespace 与 receipt 不匹配")


def validate_demo_process_receipt(
    *,
    cfg: dict,
    profile: DemoDeploymentProfile,
    config_path: Path,
    process_argv: list[str],
    proc_root: Path = Path("/proc"),
    current_uid: int | None = None,
    now: int | None = None,
) -> dict:
    """Recompute all offline identity and validate the running Demo process."""
    expected_identity = _receipt_identity(
        cfg=cfg,
        profile=profile,
        account_uid=profile.account_uid,
        config_path=config_path,
    )
    receipt = verify_receipt(
        profile.receipt_path,
        expected_identity=expected_identity,
        now=now,
        expected_group_gid=expected_identity["unix_gid"],
    )
    verify_demo_process_context(
        receipt,
        process_argv=process_argv,
        proc_root=proc_root,
        current_uid=current_uid,
    )
    return receipt


def assert_single_writer_available(
    lock_path: Path,
    *,
    owner_uid: int | None = None,
) -> None:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    existed = lock_path.exists()
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
        0o640,
    )
    try:
        if not existed and owner_uid is not None:
            os.fchown(descriptor, owner_uid, -1)
            os.fchmod(descriptor, 0o640)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("account-UID scoped 单写者租约冲突") from exc
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def validate_journal(
    path: Path,
    *,
    account_uid: str,
) -> list[dict]:
    journal = SQLiteJournal(path, must_exist=True, read_only=True)
    try:
        journal.assert_identity(account_uid)
        if not journal.health_check():
            raise RuntimeError("journal schema 不是当前最新版本")
        if not journal.integrity_check():
            raise RuntimeError("journal PRAGMA integrity_check 失败")
        return journal.list_positions()
    finally:
        journal.close()
