"""配置加载与环境变量替换

支持 ${VAR} 或 ${VAR:-default} 语法在 YAML 中引用环境变量：

    okx:
      api_key: ${OKX_API_KEY}
      secret_key: ${OKX_SECRET_KEY:-}
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(value: Any) -> Any:
    """递归替换字符串中的 ${VAR} / ${VAR:-default} 为环境变量"""
    if isinstance(value, str):
        return _ENV_PATTERN.sub(_replace, value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


def _replace(match: re.Match) -> str:
    var = match.group(1)
    default = match.group(2)
    return os.environ.get(var, default if default is not None else "")


def load_yaml(path: str) -> dict:
    """读取 YAML 并做环境变量替换"""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return expand_env(raw)


@dataclass(frozen=True)
class ProductionSettings:
    """生产运行时强类型配置；未知字段一律拒绝。"""

    enabled: bool = True
    environment: str = "demo"
    deployment_tier: str = "production"
    account_id: str = ""
    journal_path: str = "state/demo/trading.db"
    lock_path: str = "state/demo/trading.lock"
    backup_dir: str = "backups/demo"
    reconciliation_interval_s: float = 30
    max_clock_skew_s: float = 1
    ws_ready_timeout_s: float = 30
    backup_interval_s: float = 60
    backup_retention_days: int = 30
    max_order_loss_usdt: Decimal = Decimal("100")
    max_position_notional_usdt: Decimal = Decimal("2000")
    max_total_exposure_usdt: Decimal = Decimal("5000")
    max_open_positions: int = 3
    max_daily_loss_usdt: Decimal = Decimal("250")
    max_drawdown_ratio: Decimal = Decimal("0.15")
    max_order_intents_per_hour: int = 20
    max_spread_ratio: Decimal = Decimal("0.005")
    max_slippage_ratio: Decimal = Decimal("0.01")
    max_candle_range_ratio: Decimal = Decimal("0.15")
    min_24h_quote_volume_usdt: Decimal = Decimal("500000")
    max_market_data_age_s: float = 5
    max_account_snapshot_age_s: float = 90
    max_unprotected_position_s: float = 10
    max_consecutive_infrastructure_errors: int = 3
    resource_sample_interval_s: float = 60
    memory_high_bytes: int = 524288000
    memory_max_bytes: int = 629145600
    limit_nofile: int = 4096
    tasks_max: int = 128
    max_database_bytes: int = 2147483648
    max_wal_bytes: int = 268435456
    max_wal_checkpoint_age_s: int = 300
    max_database_growth_bytes_per_day: int = 268435456
    resource_min_free_bytes: int = 5368709120
    resource_min_free_inodes: int = 10000
    alert_webhook_env: str = "OKX_QUANT_ALERT_WEBHOOK"
    resume_approval_public_key: str = ""
    release_root: str = "/opt/okx-quant/current"
    launch_manifest_path: str = "/etc/okx-quant/launch.json"
    deployment_receipt_path: str = (
        "/var/lib/okx-quant/admission/deployment-receipt.json"
    )
    admission_evidence_path: str = (
        "/etc/okx-quant/admission/evidence.json"
    )
    admission_approval_path: str = (
        "/etc/okx-quant/admission/approval.json"
    )
    admission_approval_public_key: str = (
        "/etc/okx-quant/keys/risk-approval-public.pem"
    )
    heartbeat_path: str = "state/demo/heartbeat"
    offsite_backup_uri: str = ""
    external_backup_managed: bool = False
    backup_receipt_path: str = (
        "/var/lib/okx-quant-restore-evidence/daily/last-offsite-roundtrip.json"
    )
    backup_receipt_public_key: str = (
        "/etc/okx-quant/keys/restore-verifier-public.pem"
    )
    backup_receipt_key_id: str = "restore-verifier-2026q3"
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 9108
    shadow_mode: bool = False
    allowed_instruments: tuple[str, ...] = ()
    canary_transition_path: str = ""
    canary_policy_path: str = ""
    canary_activation_path: str = ""
    canary_operator_public_key: str = ""
    canary_risk_public_key: str = ""
    canary_check_verifier_public_key: str = ""
    host_image_sha256: str = ""
    ip_allowlist_sha256: str = ""
    api_permissions: tuple[str, ...] = ()
    deployment_unit: str = "okx-quant.service"

    @classmethod
    def from_config(
        cls,
        cfg: dict,
        *,
        require_credentials: bool = True,
        require_external_controls: bool = True,
    ) -> ProductionSettings:
        raw = cfg.get("production", {})
        if not isinstance(raw, dict):
            raise ValueError("production 必须是映射")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(raw) - allowed
        if unknown:
            raise ValueError(f"production 含未知字段: {sorted(unknown)}")
        decimal_fields = {
            "max_order_loss_usdt",
            "max_position_notional_usdt",
            "max_total_exposure_usdt",
            "max_daily_loss_usdt",
            "max_drawdown_ratio",
            "max_spread_ratio",
            "max_slippage_ratio",
            "max_candle_range_ratio",
            "min_24h_quote_volume_usdt",
        }
        values = {}
        for key, value in raw.items():
            if key in decimal_fields:
                values[key] = Decimal(str(value))
            elif key in {"allowed_instruments", "api_permissions"} and isinstance(
                value, (list, tuple)
            ):
                values[key] = tuple(value)
            else:
                values[key] = value
        settings = cls(**values)
        settings.validate(
            cfg,
            require_credentials=require_credentials,
            require_external_controls=require_external_controls,
        )
        return settings

    def validate(
        self,
        cfg: dict,
        *,
        require_credentials: bool = True,
        require_external_controls: bool = True,
    ) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("production.enabled 必须是布尔值")
        if type(self.shadow_mode) is not bool:
            raise ValueError("production.shadow_mode 必须是布尔值")
        if type(self.external_backup_managed) is not bool:
            raise ValueError(
                "production.external_backup_managed 必须是布尔值"
            )
        if self.environment not in {"demo", "production"}:
            raise ValueError("production.environment 只能是 demo 或 production")
        if self.deployment_tier not in {"canary", "production"}:
            raise ValueError("deployment_tier 只能是 canary 或 production")
        if self.environment == "demo" and self.deployment_tier != "production":
            raise ValueError("Demo runtime 不能声明真实资金 canary tier")
        if self.environment == "production" and not self.enabled:
            raise ValueError("实盘禁止关闭 production.enabled 生产交易内核")
        if (
            self.environment == "production"
            and not self.allowed_instruments
        ):
            raise ValueError("实盘必须显式配置非空 allowed_instruments")
        allowed_invalid = (
            not isinstance(self.allowed_instruments, tuple)
            or (
                bool(self.allowed_instruments)
                and not 1 <= len(self.allowed_instruments) <= 10
            )
            or len(set(self.allowed_instruments))
            != len(self.allowed_instruments)
            or any(
                not isinstance(inst_id, str)
                or not re.fullmatch(r"[A-Z0-9]{2,15}-USDT", inst_id)
                for inst_id in self.allowed_instruments
            )
        )
        if allowed_invalid:
            raise ValueError(
                "allowed_instruments 必须是至多 10 个唯一的 *-USDT 交易对"
            )
        okx = cfg.get("okx", {})
        simulated = okx.get("simulated")
        if type(simulated) is not bool:
            raise ValueError("okx.simulated 必须显式使用布尔值")
        expected_simulated = self.environment == "demo"
        if simulated is not expected_simulated:
            raise ValueError(
                "production.environment 与 okx.simulated 不一致"
            )
        if require_credentials:
            for field_name in ("api_key", "secret_key", "passphrase"):
                if not okx.get(field_name):
                    raise ValueError(f"缺失 OKX 密钥: okx.{field_name}")
        if (
            self.environment == "production"
            and require_external_controls
            and not self.account_id
        ):
            raise ValueError("实盘必须显式配置 production.account_id")
        if (
            self.environment == "production"
            and require_external_controls
            and not self.external_backup_managed
        ):
            raise ValueError(
                "实盘必须启用隔离备份服务 external_backup_managed"
            )
        if (
            self.environment == "production"
            and require_external_controls
            and self.offsite_backup_uri
            and not self.offsite_backup_uri.startswith("s3://")
        ):
            raise ValueError("实盘 offsite_backup_uri 当前必须使用 s3://")
        if (
            self.environment == "production"
            and require_external_controls
            and self.external_backup_managed
            and self.offsite_backup_uri
        ):
            raise ValueError(
                "隔离备份服务启用时 trader 不得持有 offsite 配置/加密材料"
            )
        if (
            self.environment == "production"
            and require_external_controls
            and not os.environ.get(self.alert_webhook_env)
        ):
            raise ValueError(
                f"实盘缺少 Page webhook 环境变量: {self.alert_webhook_env}"
            )
        if (
            self.environment == "production"
            and require_external_controls
            and not self.resume_approval_public_key
        ):
            raise ValueError("实盘必须配置独立风险审批 Ed25519 公钥")
        parsed = urlparse(str(okx.get("base_url", "")))
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("okx.base_url 必须是合法 HTTPS URL")
        if self.environment == "production":
            if (
                parsed.hostname not in {"openapi.okx.com", "www.okx.com"}
                or parsed.username
                or parsed.password
                or parsed.port not in {None, 443}
            ):
                raise ValueError("实盘 okx.base_url 必须使用官方 OKX HTTPS 域名")
            log_level = str(cfg.get("logging", {}).get("level", "INFO")).upper()
            if log_level == "DEBUG":
                raise ValueError("生产环境禁止 DEBUG 日志")
            for path_value in (
                self.journal_path,
                self.lock_path,
                self.heartbeat_path,
            ):
                lowered = path_value.lower()
                if "demo" in lowered or "test" in lowered:
                    raise ValueError("生产环境禁止使用 demo/test 状态目录")
            if require_external_controls:
                webhook = urlparse(os.environ.get(self.alert_webhook_env, ""))
                if (
                    webhook.scheme != "https"
                    or not webhook.hostname
                    or webhook.username
                    or webhook.password
                ):
                    raise ValueError("实盘 Page webhook 必须是合法 HTTPS URL")
                approval_key = Path(self.resume_approval_public_key)
                if (
                    not approval_key.is_absolute()
                    or not approval_key.is_relative_to("/etc/okx-quant")
                    or approval_key.suffix not in {".pub", ".pem"}
                ):
                    raise ValueError(
                        "实盘风险审批公钥必须是 /etc/okx-quant 下的 .pub/.pem 文件"
                    )
                controlled_paths = {
                    "release_root": (
                        self.release_root,
                        Path("/opt/okx-quant"),
                    ),
                    "launch_manifest_path": (
                        self.launch_manifest_path,
                        Path("/etc/okx-quant"),
                    ),
                    "deployment_receipt_path": (
                        self.deployment_receipt_path,
                        Path("/var/lib/okx-quant/admission"),
                    ),
                    "admission_evidence_path": (
                        self.admission_evidence_path,
                        Path("/etc/okx-quant/admission"),
                    ),
                    "admission_approval_path": (
                        self.admission_approval_path,
                        Path("/etc/okx-quant/admission"),
                    ),
                    "admission_approval_public_key": (
                        self.admission_approval_public_key,
                        Path("/etc/okx-quant/keys"),
                    ),
                    "backup_receipt_path": (
                        self.backup_receipt_path,
                        Path("/var/lib/okx-quant-restore-evidence"),
                    ),
                    "backup_receipt_public_key": (
                        self.backup_receipt_public_key,
                        Path("/etc/okx-quant/keys"),
                    ),
                }
                for name, (path_value, root) in controlled_paths.items():
                    candidate = Path(path_value)
                    if (
                        not candidate.is_absolute()
                        or not candidate.is_relative_to(root)
                        or ".." in candidate.parts
                    ):
                        raise ValueError(
                            f"实盘 {name} 必须位于受控目录 {root}"
                        )
                if not self.backup_receipt_key_id.strip():
                    raise ValueError(
                        "实盘 backup_receipt_key_id 不能为空"
                    )
                if self.deployment_tier == "canary":
                    if self.shadow_mode:
                        raise ValueError("Canary 不允许 shadow_mode")
                    if list(self.api_permissions) != ["read", "trade"]:
                        raise ValueError("Canary API 权限必须精确为 Read+Trade")
                    if self.deployment_unit != "okx-quant.service":
                        raise ValueError("Canary deployment unit 非法")
                    for name in (
                        "host_image_sha256",
                        "ip_allowlist_sha256",
                    ):
                        value = getattr(self, name)
                        if (
                            not re.fullmatch(r"[0-9a-f]{64}", value)
                            or value == "0" * 64
                        ):
                            raise ValueError(f"Canary {name} 必须是非零 SHA-256")
                    canary_paths = {
                        "canary_transition_path": (
                            self.canary_transition_path,
                            Path("/etc/okx-quant/canary"),
                        ),
                        "canary_policy_path": (
                            self.canary_policy_path,
                            Path("/etc/okx-quant/canary"),
                        ),
                        "canary_activation_path": (
                            self.canary_activation_path,
                            Path("/etc/okx-quant/canary"),
                        ),
                        "canary_operator_public_key": (
                            self.canary_operator_public_key,
                            Path("/etc/okx-quant/keys"),
                        ),
                        "canary_risk_public_key": (
                            self.canary_risk_public_key,
                            Path("/etc/okx-quant/keys"),
                        ),
                        "canary_check_verifier_public_key": (
                            self.canary_check_verifier_public_key,
                            Path("/etc/okx-quant/keys"),
                        ),
                    }
                    for name, (path_value, root) in canary_paths.items():
                        candidate = Path(path_value)
                        if (
                            not candidate.is_absolute()
                            or not candidate.is_relative_to(root)
                            or ".." in candidate.parts
                        ):
                            raise ValueError(
                                f"Canary {name} 必须位于受控目录 {root}"
                            )
        integer_fields = {
            "max_open_positions": self.max_open_positions,
            "max_order_intents_per_hour": self.max_order_intents_per_hour,
            "backup_retention_days": self.backup_retention_days,
            "metrics_port": self.metrics_port,
            "max_consecutive_infrastructure_errors": (
                self.max_consecutive_infrastructure_errors
            ),
            "memory_high_bytes": self.memory_high_bytes,
            "memory_max_bytes": self.memory_max_bytes,
            "limit_nofile": self.limit_nofile,
            "tasks_max": self.tasks_max,
            "max_database_bytes": self.max_database_bytes,
            "max_wal_bytes": self.max_wal_bytes,
            "max_wal_checkpoint_age_s": self.max_wal_checkpoint_age_s,
            "max_database_growth_bytes_per_day": (
                self.max_database_growth_bytes_per_day
            ),
            "resource_min_free_bytes": self.resource_min_free_bytes,
            "resource_min_free_inodes": self.resource_min_free_inodes,
        }
        for name, value in integer_fields.items():
            if type(value) is not int:
                raise ValueError(f"{name} 必须是整数")
        numeric_fields = {
            "reconciliation_interval_s": self.reconciliation_interval_s,
            "max_clock_skew_s": self.max_clock_skew_s,
            "ws_ready_timeout_s": self.ws_ready_timeout_s,
            "backup_interval_s": self.backup_interval_s,
            "max_market_data_age_s": self.max_market_data_age_s,
            "max_account_snapshot_age_s": self.max_account_snapshot_age_s,
            "max_unprotected_position_s": self.max_unprotected_position_s,
            "resource_sample_interval_s": self.resource_sample_interval_s,
        }
        for name, value in numeric_fields.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError(f"{name} 必须是有限数值")
        decimal_fields = {
            "max_order_loss_usdt": self.max_order_loss_usdt,
            "max_position_notional_usdt": self.max_position_notional_usdt,
            "max_total_exposure_usdt": self.max_total_exposure_usdt,
            "max_daily_loss_usdt": self.max_daily_loss_usdt,
            "max_drawdown_ratio": self.max_drawdown_ratio,
            "max_spread_ratio": self.max_spread_ratio,
            "max_slippage_ratio": self.max_slippage_ratio,
            "max_candle_range_ratio": self.max_candle_range_ratio,
            "min_24h_quote_volume_usdt": self.min_24h_quote_volume_usdt,
        }
        for name, value in decimal_fields.items():
            if not value.is_finite():
                raise ValueError(f"{name} 必须是有限十进制数")
        hard_maxima = {
            "max_order_loss_usdt": (
                self.max_order_loss_usdt,
                Decimal("100"),
            ),
            "max_position_notional_usdt": (
                self.max_position_notional_usdt,
                Decimal("2000"),
            ),
            "max_total_exposure_usdt": (
                self.max_total_exposure_usdt,
                Decimal("5000"),
            ),
            "max_daily_loss_usdt": (
                self.max_daily_loss_usdt,
                Decimal("250"),
            ),
            "max_drawdown_ratio": (
                self.max_drawdown_ratio,
                Decimal("0.15"),
            ),
            "max_spread_ratio": (
                self.max_spread_ratio,
                Decimal("0.01"),
            ),
            "max_slippage_ratio": (
                self.max_slippage_ratio,
                Decimal("0.05"),
            ),
            "max_candle_range_ratio": (
                self.max_candle_range_ratio,
                Decimal("0.20"),
            ),
        }
        for name, (value, hard_maximum) in hard_maxima.items():
            if value <= 0 or value > hard_maximum:
                raise ValueError(
                    f"{name} 必须在 (0, {hard_maximum}] 硬上限内"
                )
        if self.max_position_notional_usdt > self.max_total_exposure_usdt:
            raise ValueError("单交易对仓位上限不能超过账户总敞口上限")
        if not 1 <= self.max_open_positions <= 5:
            raise ValueError("最大持仓数必须在 1..5")
        if not 1 <= self.max_order_intents_per_hour <= 60:
            raise ValueError("每小时订单意图上限必须在 1..60")
        if self.reconciliation_interval_s <= 0 or self.reconciliation_interval_s > 30:
            raise ValueError("周期对账间隔必须在 (0, 30] 秒")
        if self.max_clock_skew_s <= 0 or self.max_clock_skew_s > 1:
            raise ValueError("最大时钟偏差必须在 (0, 1] 秒")
        if self.backup_interval_s <= 0 or self.backup_interval_s > 60:
            raise ValueError("备份间隔必须在 (0, 60] 秒")
        if self.ws_ready_timeout_s <= 0:
            raise ValueError("WS READY 超时必须大于 0")
        if not 0 < self.max_account_snapshot_age_s <= 90:
            raise ValueError("账户快照最大年龄必须在 (0, 90] 秒")
        if not 0 < self.max_market_data_age_s <= 30:
            raise ValueError("行情最大年龄必须在 (0, 30] 秒")
        if not 0 < self.max_unprotected_position_s <= 10:
            raise ValueError("无保护仓位最大持续时间必须在 (0, 10] 秒")
        if not 1 <= self.max_consecutive_infrastructure_errors <= 5:
            raise ValueError("连续基础设施错误阈值必须在 1..5")
        if not 30 <= self.resource_sample_interval_s <= 60:
            raise ValueError("资源采样间隔必须在 30..60 秒")
        if not (
            64 * 1024 * 1024
            <= self.memory_high_bytes
            < self.memory_max_bytes
        ):
            raise ValueError("MemoryHigh/MemoryMax 资源边界非法")
        if not 256 <= self.limit_nofile <= 1_048_576:
            raise ValueError("LimitNOFILE 资源边界非法")
        if not 16 <= self.tasks_max <= 65_536:
            raise ValueError("TasksMax 资源边界非法")
        if min(
            self.max_database_bytes,
            self.max_wal_bytes,
            self.max_wal_checkpoint_age_s,
            self.max_database_growth_bytes_per_day,
            self.resource_min_free_bytes,
            self.resource_min_free_inodes,
        ) <= 0:
            raise ValueError("DB/WAL 绝对上限与增长上限必须为正")
        if self.min_24h_quote_volume_usdt <= 0:
            raise ValueError("24h 最低计价成交额必须大于 0")
        if self.backup_retention_days < 30:
            raise ValueError("备份保留期不能少于 30 天")
        if not (1 <= self.metrics_port <= 65535):
            raise ValueError("metrics_port 超出合法范围")
        if (
            self.environment == "production"
            and self.metrics_host not in {"127.0.0.1", "::1", "localhost"}
        ):
            raise ValueError("实盘 metrics_host 必须绑定本机回环地址")
        for path_value in (
            self.journal_path,
            self.lock_path,
            self.backup_dir,
            self.heartbeat_path,
        ):
            if not path_value:
                raise ValueError("生产路径不能为空")
            path = Path(path_value)
            if path in {Path("/"), Path(".")}:
                raise ValueError("生产路径不能指向根目录或工作目录本身")
            if any(part == ".." for part in path.parts):
                raise ValueError("生产路径禁止包含 ..")
            if (
                self.environment == "production"
                and not path.is_absolute()
            ):
                raise ValueError("实盘状态路径必须使用绝对路径")
            if (
                self.environment == "production"
                and not path.is_relative_to("/var/lib/okx-quant")
            ):
                raise ValueError("实盘绝对状态路径必须位于 /var/lib/okx-quant")
