"""生产交易运行时：恢复门禁、单写者、WS 基线与周期对账。"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING

from okx_quant.application.approval import ResumeApprovalVerifier
from okx_quant.application.demo_probe import (
    PROBE_SOURCE,
    TERMINAL_PROBE_STATES,
    DemoProbeSaga,
)
from okx_quant.application.execution import ExecutionCoordinator
from okx_quant.application.protection import ExitCoordinator, ProtectionManager
from okx_quant.application.reconciliation import (
    Reconciler,
    ReconciliationResult,
    RecoveryGate,
)
from okx_quant.application.risk_service import ProductionRiskLimits, ProductionRiskService
from okx_quant.client.websocket import ConnectionState, OKXWebSocketClient
from okx_quant.domain.orders import (
    OrderIntent,
    OrderState,
    ProtectionState,
    SystemMode,
    to_decimal,
)
from okx_quant.exchange import Exchange
from okx_quant.infrastructure.db import JournalRepository
from okx_quant.infrastructure.metrics import MetricRegistry, MetricsServer
from okx_quant.infrastructure.okx.streams import PrivateStreamService
from okx_quant.infrastructure.operations import (
    AlertDispatcher,
    BackupService,
    HeartbeatService,
    ResourceSampler,
)
from okx_quant.ops.account_lease import SignedAccountLeaseClient
from okx_quant.ops.alert_control import apply_alert_control_request
from okx_quant.ops.backup_receipt import (
    read_verified_restore_evidence,
    validate_backup_slo_sample,
)
from okx_quant.research.canary import REQUIRED_POST_START_CHECKS
from okx_quant.research.costs import DynamicCostModel
from okx_quant.research.demo_soak import (
    CANARY_SOURCE_PRODUCER_NAMES,
    validate_canary_source_producer_inventory,
)

if TYPE_CHECKING:
    from okx_quant.risk.manager import RiskManager

logger = logging.getLogger(__name__)


class SingleInstanceLock:
    """基于 flock 的进程级独占锁。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = None

    def acquire(self) -> None:
        self._file = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._file.close()
            self._file = None
            raise RuntimeError(f"另一个交易实例已持有锁: {self.path}") from exc
        self._file.seek(0)
        self._file.truncate()
        self._file.write(str(__import__("os").getpid()))
        self._file.flush()

    def release(self) -> None:
        if self._file is None:
            return
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()
        self._file = None


class ProductionRuntime:
    """所有生产写路径共享的生命周期容器。"""

    def __init__(
        self,
        exchange: Exchange,
        journal: JournalRepository,
        *,
        risk_limits: ProductionRiskLimits | None = None,
        websocket: OKXWebSocketClient | None = None,
        lock_path: str | Path | None = None,
        reconciliation_interval_s: float = 30,
        max_clock_skew_s: float = 1,
        ws_ready_timeout_s: float = 30,
        max_unprotected_position_s: float = 10,
        max_consecutive_infrastructure_errors: int = 3,
        shadow_mode: bool = False,
        safety_only: bool = False,
        heartbeat_path: str | Path = "",
        backup_dir: str | Path = "",
        backup_interval_s: float = 60,
        backup_retention_days: int = 30,
        offsite_backup_uri: str = "",
        alert_webhook_url: str = "",
        metrics_host: str = "",
        metrics_port: int = 9108,
        expected_account_id: str = "",
        deployment_unit: str = "",
        soak_epoch_id: str = "",
        approval_public_key: str | Path = "",
        production_config_hash: str = "",
        environment: str = "demo",
        allowed_instruments: tuple[str, ...] = (),
        resource_sample_interval_s: float = 0,
        memory_high_bytes: int = 524288000,
        memory_max_bytes: int = 629145600,
        limit_nofile: int = 4096,
        tasks_max: int = 128,
        max_database_bytes: int = 2147483648,
        max_wal_bytes: int = 268435456,
        max_wal_checkpoint_age_s: int = 300,
        max_database_growth_bytes_per_day: int = 268435456,
        resource_min_free_bytes: int = 5368709120,
        resource_min_free_inodes: int = 10000,
        release_identity: str = "",
        entry_authorization_expires_at: float = 0,
        max_entry_backup_rpo_s: float = 0,
        expected_model_slippage_ratio: float = 0,
        cost_model_manifest: dict | None = None,
        demo_probe_schedule_path: str | Path = "",
        require_formal_demo_probe_schedule: bool = False,
        demo_probe_only: bool = False,
        backup_receipt_path: str | Path = "",
        backup_receipt_public_key: str | Path = "",
        backup_receipt_key_id: str = "",
        external_control_inbox_dir: str | Path = "",
        alert_provider_receipt_public_key: str | Path = "",
        alert_human_ack_public_key: str | Path = "",
        alert_escalation_public_key: str | Path = "",
        canary_activation_path: str | Path = "",
        canary_operator_public_key: str | Path = "",
        canary_risk_public_key: str | Path = "",
        canary_check_verifier_public_key: str | Path = "",
        canary_source_key_fingerprints: dict[str, str] | None = None,
        canary_source_producer_inventory: dict | None = None,
        canary_target_key_fingerprint: str = "",
        canary_transition_sha256: str = "",
        canary_policy_sha256: str = "",
        canary_target_sha256: str = "",
        runtime_boot_id: str = "",
        account_lease: SignedAccountLeaseClient | None = None,
    ):
        self.exchange = exchange
        self.journal = journal
        self.operation_lock = threading.RLock()
        self.metrics = MetricRegistry()
        limits = risk_limits or ProductionRiskLimits()
        self.limits = limits
        self._safety_only = safety_only
        # Admission failure must retain real protection and exit capabilities
        # even when the admitted strategy configuration was shadow-only.
        self.shadow_mode = shadow_mode and not safety_only
        self.expected_account_id = expected_account_id
        self.deployment_unit = deployment_unit
        self.soak_epoch_id = soak_epoch_id
        self.production_config_hash = production_config_hash
        self.release_identity = release_identity
        if (
            isinstance(entry_authorization_expires_at, bool)
            or not isinstance(entry_authorization_expires_at, (int, float))
            or not math.isfinite(float(entry_authorization_expires_at))
            or float(entry_authorization_expires_at) < 0
        ):
            raise ValueError("entry_authorization_expires_at 必须是有限非负时间戳")
        self.entry_authorization_expires_at = float(entry_authorization_expires_at)
        self._entry_authorization_expiry_reported = False
        if (
            isinstance(max_entry_backup_rpo_s, bool)
            or not isinstance(max_entry_backup_rpo_s, (int, float))
            or not math.isfinite(float(max_entry_backup_rpo_s))
            or float(max_entry_backup_rpo_s) < 0
        ):
            raise ValueError("max_entry_backup_rpo_s 必须是有限非负秒数")
        self.max_entry_backup_rpo_s = float(max_entry_backup_rpo_s)
        if (
            isinstance(expected_model_slippage_ratio, bool)
            or not isinstance(
                expected_model_slippage_ratio,
                (int, float),
            )
            or not math.isfinite(float(expected_model_slippage_ratio))
            or not 0 <= float(expected_model_slippage_ratio) <= 1
        ):
            raise ValueError("expected_model_slippage_ratio 必须位于 [0,1]")
        self.expected_model_slippage_ratio = Decimal(str(expected_model_slippage_ratio))
        self.cost_model: DynamicCostModel | None = None
        self.cost_model_hash = ""
        if cost_model_manifest is not None:
            if (
                not isinstance(cost_model_manifest, dict)
                or cost_model_manifest.get("model") != "okx_quant.research.costs.DynamicCostModel"
            ):
                raise ValueError("cost_model_manifest 非法")
            self.cost_model = DynamicCostModel(
                **{key: value for key, value in cost_model_manifest.items() if key != "model"}
            )
            if self.cost_model.manifest() != cost_model_manifest:
                raise ValueError("cost_model_manifest 必须是规范模型输出")
            if self.cost_model.maximum_slippage > float(limits.max_slippage_ratio):
                raise ValueError("cost model maximum_slippage 超过 runtime 硬限")
            self.cost_model_hash = self.cost_model.manifest_hash()
        elif self.expected_model_slippage_ratio > limits.max_slippage_ratio:
            raise ValueError("静态 expected model slippage 不得超过 runtime 硬限")
        receipt_settings = (
            bool(backup_receipt_path),
            bool(backup_receipt_public_key),
            bool(backup_receipt_key_id.strip()),
        )
        if any(receipt_settings) and not all(receipt_settings):
            raise ValueError("backup receipt path/public key/key id 必须同时配置")
        if all(receipt_settings) and not expected_account_id.strip():
            raise ValueError("backup receipt 验签必须绑定 expected_account_id")
        self.backup_receipt_path = Path(backup_receipt_path) if backup_receipt_path else None
        self.backup_receipt_public_key = (
            Path(backup_receipt_public_key) if backup_receipt_public_key else None
        )
        self.backup_receipt_key_id = backup_receipt_key_id.strip()
        self._last_backup_receipt_sha256 = ""
        self._last_backup_receipt_stat: tuple[int, int] | None = None
        self._failed_backup_receipt_identity = ""
        self._backup_rpo_breach_reported = False
        inbox_settings = (
            bool(external_control_inbox_dir),
            bool(alert_provider_receipt_public_key),
            bool(alert_human_ack_public_key),
            bool(alert_escalation_public_key),
        )
        if any(inbox_settings) and not all(inbox_settings):
            raise ValueError("external control inbox/public key 必须同时配置")
        self.external_control_inbox_dir = (
            Path(external_control_inbox_dir) if external_control_inbox_dir else None
        )
        self.alert_receipt_public_keys = (
            {
                "provider": Path(alert_provider_receipt_public_key),
                "human-ack": Path(alert_human_ack_public_key),
                "escalation": Path(alert_escalation_public_key),
            }
            if all(inbox_settings)
            else {}
        )
        self.canary_activation_path = (
            Path(canary_activation_path) if canary_activation_path else None
        )
        self.canary_operator_public_key = str(canary_operator_public_key)
        self.canary_risk_public_key = str(canary_risk_public_key)
        self.canary_check_verifier_public_key = str(canary_check_verifier_public_key)
        self.canary_source_key_fingerprints = dict(canary_source_key_fingerprints or {})
        self.canary_source_producer_inventory = dict(
            canary_source_producer_inventory or {}
        )
        if self.canary_source_producer_inventory:
            validate_canary_source_producer_inventory(
                self.canary_source_producer_inventory
            )
        self.canary_target_key_fingerprint = (
            canary_target_key_fingerprint
        )
        self.canary_transition_sha256 = canary_transition_sha256
        self.canary_policy_sha256 = canary_policy_sha256
        self.canary_target_sha256 = canary_target_sha256
        self.runtime_instance_id = uuid.uuid4().hex
        self._shadow_write_attempt_count = 0
        self.account_lease = account_lease
        self._account_lease_breach_reported = False
        if self.account_lease is not None:
            install_write_guard = getattr(
                self.exchange,
                "set_write_guard",
                None,
            )
            if not callable(install_write_guard):
                raise TypeError(
                    "启用 account coordination lease 时 exchange 必须支持最终写门禁"
                )
            install_write_guard(self._assert_account_writer_transport_guard)
        elif self.shadow_mode:
            install_write_guard = getattr(
                self.exchange,
                "set_write_guard",
                None,
            )
            if not callable(install_write_guard):
                raise TypeError(
                    "Shadow exchange 必须支持 endpoint-aware 最终写门禁"
                )
            install_write_guard(self._deny_shadow_transport_write)
        self.runtime_started_at = 0.0
        boot_path = Path("/proc/sys/kernel/random/boot_id")
        self.runtime_boot_id = runtime_boot_id.strip() or (
            boot_path.read_text(encoding="ascii").strip()
            if boot_path.is_file()
            else "non-linux-test-boot"
        )
        self._canary_activation_claims: dict | None = None
        self._canary_activation_failure_reported = False
        self._canary_startup_nonce = uuid.uuid4().hex
        self._canary_startup_hard_epoch: int | None = None
        self._canary_startup_latch_reason = "canary_post_start_activation_pending"
        self._canary_activation_consumed = False
        if self.canary_activation_path and (
            not self.canary_operator_public_key
            or not self.canary_risk_public_key
            or not self.canary_check_verifier_public_key
            or not self.expected_account_id.strip()
            or not self.deployment_unit.strip()
            or not self.soak_epoch_id.strip()
            or set(self.canary_source_key_fingerprints) != set(REQUIRED_POST_START_CHECKS)
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in self.canary_source_key_fingerprints.values()
            )
            or len(set(self.canary_source_key_fingerprints.values()))
            != len(REQUIRED_POST_START_CHECKS)
            or set(self.canary_source_producer_inventory)
            != CANARY_SOURCE_PRODUCER_NAMES
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                self.canary_target_key_fingerprint,
            )
            or not all(
                re.fullmatch(r"[0-9a-f]{64}", value)
                for value in (
                    self.canary_transition_sha256,
                    self.canary_policy_sha256,
                    self.canary_target_sha256,
                )
            )
        ):
            raise ValueError("Canary activation verifier 配置不完整")
        self.approval_verifier = (
            ResumeApprovalVerifier(approval_public_key) if approval_public_key else None
        )
        self._ws_generation = 0
        self._ws_states = {
            name: ConnectionState.DISCONNECTED for name in ("public", "private", "business")
        }
        self._ws_connection_generations = {name: 0 for name in ("public", "private", "business")}
        self._ws_connect_started_at: dict[str, float] = {}
        self._ws_disconnected_at: dict[str, float] = {}
        self.max_unprotected_position_s = max_unprotected_position_s
        self.max_consecutive_infrastructure_errors = max_consecutive_infrastructure_errors
        if (
            isinstance(self.max_unprotected_position_s, bool)
            or not isinstance(
                self.max_unprotected_position_s,
                (int, float),
            )
            or not math.isfinite(self.max_unprotected_position_s)
            or not 0 < self.max_unprotected_position_s <= 10
        ):
            raise ValueError("max_unprotected_position_s 必须在 (0, 10] 秒")
        if (
            type(self.max_consecutive_infrastructure_errors) is not int
            or not 1 <= self.max_consecutive_infrastructure_errors <= 5
        ):
            raise ValueError("max_consecutive_infrastructure_errors 必须在 1..5")
        self._consecutive_api_errors = 0
        self._consecutive_api_errors_by_endpoint: dict[str, int] = {}
        self._api_error_lock = threading.Lock()
        self._consecutive_ws_errors = 0
        self._consecutive_database_errors = 0
        self._consecutive_database_write_errors = 0
        self._handling_database_write_failure = False
        self._unprotected_since: dict[str, float] = {}
        self._unprotected_deadline_reported: set[str] = set()
        self._required_public_market_channels: set[tuple[str, str]] = set()
        self._public_market_last_event_at: dict[tuple[str, str], float] = {}
        self._public_ticker_cache: dict[
            str,
            tuple[Decimal, Decimal, Decimal, float, float],
        ] = {}
        self.max_market_data_age_s = limits.max_market_data_age_s
        self.max_candle_range_ratio = limits.max_candle_range_ratio
        self.risk_service = ProductionRiskService(exchange, journal, limits, metrics=self.metrics)
        self.execution = ExecutionCoordinator(
            exchange,
            journal,
            pre_trade_check=self.risk_service.check,
            shadow_mode=self.shadow_mode,
            max_slippage_ratio=limits.max_slippage_ratio,
            operation_lock=self.operation_lock,
            entry_guard=self._entry_guard,
            atomic_risk_guard=self.risk_service.atomic_guard,
            allowed_buy_sources=(frozenset({"demo_validation_probe"}) if demo_probe_only else None),
        )
        self.protection = ProtectionManager(
            exchange,
            journal,
            dust_usdt=Decimal("1"),
            max_market_data_age_s=limits.max_market_data_age_s,
            unknown_resolution_timeout_s=min(
                max_unprotected_position_s / 2,
                5,
            ),
        )
        self.protection.attach_to(self.execution)
        self.execution.add_fill_handler(self._record_fill_metrics)
        self.exit = ExitCoordinator(
            exchange,
            journal,
            self.execution,
            self.protection,
            operation_lock=self.operation_lock,
        )
        self.demo_probe = (
            DemoProbeSaga(
                exchange,
                journal,
                self.execution,
                self.protection,
                self.exit,
                environment=environment,
                shadow_mode=self.shadow_mode,
                account_uid=expected_account_id,
                allowed_instruments=allowed_instruments,
                probe_schedule_path=demo_probe_schedule_path,
                require_formal_schedule=(require_formal_demo_probe_schedule),
                soak_epoch_id=soak_epoch_id,
            )
            if (
                environment == "demo"
                and not self.shadow_mode
                and not safety_only
                and expected_account_id
            )
            else None
        )
        self._demo_probe_reclaim_pending = False
        self.reconciler = Reconciler(
            exchange,
            journal,
            max_market_data_age_s=limits.max_market_data_age_s,
            protection_manager=None if self.shadow_mode else self.protection,
            operation_lock=self.operation_lock,
        )
        self.recovery = RecoveryGate(self.reconciler)
        self.websocket = websocket
        self.streams = (
            PrivateStreamService(
                websocket,
                self.execution,
                journal,
                on_algo_event=self._process_algo_events,
            )
            if websocket is not None
            else None
        )
        self.lock = SingleInstanceLock(
            lock_path or journal.path.with_suffix(journal.path.suffix + ".lock")
        )
        self.reconciliation_interval_s = reconciliation_interval_s
        self.max_clock_skew_s = max_clock_skew_s
        self.ws_ready_timeout_s = ws_ready_timeout_s
        self._stop_event = threading.Event()
        self._reconcile_thread: threading.Thread | None = None
        self._control_thread: threading.Thread | None = None
        self._safety_thread: threading.Thread | None = None
        self._backup_receipt_thread: threading.Thread | None = None
        self._last_safety_completed_monotonic = time.monotonic()
        self._started = False
        self._last_reconciliation_completed_at = 0.0
        self._last_reconciliation_incident = ""
        self._last_slo_heartbeat_at = 0.0
        self._reconnect_lock = threading.Lock()
        self._ws_state_lock = threading.RLock()
        self._emergency_exit_lock = threading.Lock()
        self._emergency_exit_tasks: dict[str, threading.Thread] = {}
        self._risk_managers: dict[int, RiskManager] = {}
        client = getattr(exchange, "client", None)
        if client is not None and hasattr(client, "request_observer"):
            client.request_observer = self._observe_api_request
        add_write_observer = getattr(
            journal,
            "add_write_observer",
            None,
        )
        if callable(add_write_observer):
            add_write_observer(self._observe_database_write)
        self.heartbeat = (
            HeartbeatService(
                heartbeat_path,
                # systemd watchdog 表示进程/核心线程活性，不等同于 READY。
                # 人工 HALT/应急模式必须继续运行保护、退出和控制循环。
                health=lambda: self._liveness()[0],
            )
            if heartbeat_path
            else None
        )
        self.alerts = AlertDispatcher(journal, alert_webhook_url)
        self.backups = (
            BackupService(
                journal,
                backup_dir,
                interval_s=backup_interval_s,
                retention_days=backup_retention_days,
                offsite_uri=offsite_backup_uri,
            )
            if backup_dir
            else None
        )
        self.resources = (
            ResourceSampler(
                journal,
                database_path=journal.path,
                interval_s=resource_sample_interval_s,
                memory_high_bytes=memory_high_bytes,
                memory_max_bytes=memory_max_bytes,
                limit_nofile=limit_nofile,
                tasks_max=tasks_max,
                max_database_bytes=max_database_bytes,
                max_wal_bytes=max_wal_bytes,
                max_wal_checkpoint_age_s=max_wal_checkpoint_age_s,
                max_database_growth_bytes_per_day=(max_database_growth_bytes_per_day),
                min_free_bytes=resource_min_free_bytes,
                min_free_inodes=resource_min_free_inodes,
                release_identity=release_identity,
                config_identity=production_config_hash,
                metric_sink=lambda name, value: self.metrics.set(
                    name,
                    value,
                ),
            )
            if resource_sample_interval_s > 0
            else None
        )
        self.metrics_server = (
            MetricsServer(
                self.metrics,
                host=metrics_host,
                port=metrics_port,
                health=self._health,
                liveness=self._liveness,
            )
            if metrics_host
            else None
        )
        if self.websocket is not None:
            self.websocket.add_state_handler(self._on_ws_state)
        self.risk_service.runtime_ready_check = self._entry_ready

    def _process_algo_events(self, rows: list[dict]) -> None:
        with self.operation_lock:
            losses = self.protection.process_algo_events(rows)
            detected_at = time.time()
            for loss in losses:
                protection = loss.protection
                position = self.journal.get_position(protection.inst_id)
                qty = to_decimal(position["base_qty"]) if position is not None else Decimal("0")
                if qty <= 0:
                    continue

                # Do not fetch market data or submit the exit from this WS
                # callback. Any positive position that cannot already be
                # proven dust is frozen first; the watchdog performs the
                # controlled network exit after the deadline.
                self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
                payload = {
                    "inst_id": protection.inst_id,
                    "protection_id": protection.protection_id,
                    "exchange_algo_id": protection.exchange_algo_id,
                    "algo_cl_ord_id": protection.algo_cl_ord_id,
                    "previous_state": loss.previous_state.value,
                    "state": loss.current_state.value,
                    "position_qty": str(qty),
                    "protected_qty": str(protection.protected_qty),
                }
                self.journal.record_event(
                    "external_protection_lost",
                    severity="critical",
                    correlation_id=protection.protection_id,
                    payload=payload,
                )
                self.journal.enqueue_outbox_once(
                    (f"external-protection-lost:{protection.protection_id}"),
                    "page.external_protection_lost",
                    payload,
                )
                self._unprotected_since.setdefault(
                    protection.inst_id,
                    detected_at,
                )

    def _observe_api_request(self, endpoint: str, code: str, latency_s: float) -> None:
        self.metrics.inc("okx_api_requests_total", endpoint=endpoint, code=code)
        self.metrics.set("okx_api_latency_seconds", latency_s, endpoint=endpoint)
        successful = code == "OKX:0" or (code.isdigit() and 200 <= int(code) < 400)
        category = self._api_endpoint_category(endpoint)
        with self._api_error_lock:
            if successful:
                self._consecutive_api_errors_by_endpoint[endpoint] = 0
            else:
                self._consecutive_api_errors_by_endpoint[endpoint] = (
                    self._consecutive_api_errors_by_endpoint.get(endpoint, 0) + 1
                )
            endpoint_errors = self._consecutive_api_errors_by_endpoint[endpoint]
            # 保留原聚合字段/指标语义，但成功只能清除自己的 endpoint 故障桶。
            # 仅按 public/private 大类计数仍会让同类健康端点掩盖关键端点故障。
            self._consecutive_api_errors = max(
                self._consecutive_api_errors_by_endpoint.values(),
                default=0,
            )
        if successful:
            return
        self.journal.enqueue_outbox_once(
            (
                f"warning:api:{category}:{endpoint}:{code}:"
                f"{int(time.time() // 300)}"
            ),
            "warning.api_error_rate_elevated",
            {
                "endpoint": endpoint,
                "category": category,
                "code": code,
                "consecutive_errors": endpoint_errors,
            },
        )
        self.metrics.set(
            "consecutive_infrastructure_errors",
            endpoint_errors,
            source="api",
            category=category,
            endpoint=endpoint,
        )
        if endpoint_errors == self.max_consecutive_infrastructure_errors:
            self._latch_halted()
            self.journal.enqueue_outbox(
                "page.api_error_budget_exhausted",
                {
                    "endpoint": endpoint,
                    "category": category,
                    "code": code,
                    "consecutive_errors": endpoint_errors,
                },
            )

    @staticmethod
    def _api_endpoint_category(endpoint: str) -> str:
        if endpoint.startswith("/api/v5/account/"):
            return "private_account"
        if endpoint.startswith("/api/v5/trade/"):
            return "private_trade"
        if endpoint.startswith(("/api/v5/market/", "/api/v5/public/")):
            return "public_market"
        return "other"

    def _record_fill_metrics(self, intent: OrderIntent, delta: Decimal) -> None:
        self.metrics.set(
            "order_fill_latency_seconds",
            max(time.time() - intent.created_at, 0),
            inst=intent.inst_id,
        )
        if delta > 0:
            reference = intent.submission_reference_price
            actual = intent.avg_fill_px
            if reference > 0 and actual > 0:
                model_payload: dict = {
                    "expected_model_slippage_ratio": str(self.expected_model_slippage_ratio),
                }
                if self.cost_model is not None:
                    try:
                        candles = self.exchange.get_candles(
                            intent.inst_id,
                            "1m",
                            2,
                        )
                        if candles is None or candles.empty:
                            raise ValueError("缺少 1m cost model candle")
                        bar = candles.iloc[-1]
                        notional = float(delta * actual)
                        _fee, expected_slippage = self.cost_model(
                            intent.side,
                            bar,
                            notional,
                        )
                        model_payload = {
                            "expected_model_slippage_ratio": str(expected_slippage),
                            "cost_model_hash": self.cost_model_hash,
                            "cost_model_manifest": self.cost_model.manifest(),
                            "cost_model_inputs": {
                                "side": intent.side,
                                "notional": notional,
                                "close": float(bar["close"]),
                                "high": float(bar["high"]),
                                "low": float(bar["low"]),
                                "vol": float(bar.get("vol", 0)),
                                "vol_ccy": float(bar.get("vol_ccy", 0)),
                            },
                        }
                    except Exception as exc:  # noqa: BLE001
                        model_payload = {
                            "cost_model_hash": self.cost_model_hash,
                            "cost_model_error": (f"{type(exc).__name__}: {exc}"),
                        }
                adverse_slippage = max(
                    (
                        (actual - reference) / reference
                        if intent.side == "buy"
                        else (reference - actual) / reference
                    ),
                    Decimal("0"),
                )
                self.metrics.set(
                    "execution_slippage_ratio",
                    float(adverse_slippage),
                    inst=intent.inst_id,
                    side=intent.side,
                )
                self.metrics.set(
                    "execution_slippage_limit_ratio",
                    float(self.limits.max_slippage_ratio),
                    inst=intent.inst_id,
                    side=intent.side,
                )
                self.journal.record_event(
                    "execution_slippage_sample",
                    correlation_id=intent.intent_id,
                    payload={
                        "inst_id": intent.inst_id,
                        "side": intent.side,
                        "reference_price": str(reference),
                        "fill_price": str(actual),
                        "source": intent.source,
                        "probe_id": intent.probe_id,
                        "adverse_slippage_ratio": str(adverse_slippage),
                        **model_payload,
                    },
                )
                if adverse_slippage > self.limits.max_slippage_ratio:
                    self.journal.enqueue_outbox_once(
                        f"warning:slippage:{intent.intent_id}",
                        "warning.execution_slippage_exceeded",
                        {
                            "intent_id": intent.intent_id,
                            "inst_id": intent.inst_id,
                            "observed_ratio": str(adverse_slippage),
                            "approved_ratio": str(self.limits.max_slippage_ratio),
                        },
                    )
                elif (
                    adverse_slippage
                    >= self.limits.max_slippage_ratio * Decimal("0.80")
                ):
                    self.journal.enqueue_outbox_once(
                        f"warning:slippage-near:{intent.intent_id}",
                        "warning.execution_slippage_near_limit",
                        {
                            "intent_id": intent.intent_id,
                            "inst_id": intent.inst_id,
                            "observed_ratio": str(adverse_slippage),
                            "approved_ratio": str(
                                self.limits.max_slippage_ratio
                            ),
                            "warning_ratio": "0.80",
                        },
                    )
        if intent.side == "buy" and delta > 0:
            active = [
                protection
                for protection in self.journal.list_protections(intent.inst_id)
                if protection.state is ProtectionState.ACTIVE
                and protection.parent_intent_id == intent.intent_id
            ]
            if active:
                protection = max(active, key=lambda item: item.updated_at)
                latency = max(
                    protection.updated_at - intent.updated_at,
                    0,
                )
                self.metrics.observe(
                    "protection_activation_latency_seconds",
                    latency,
                    buckets=(0.5, 1, 2, 3, 5, 10),
                    inst=intent.inst_id,
                )
                if intent.source != PROBE_SOURCE:
                    self.journal.record_event(
                        "protection_activation_slo_sample",
                        correlation_id=intent.intent_id,
                        payload={
                            "inst_id": intent.inst_id,
                            "fill_confirmed_at": intent.updated_at,
                            "protection_active_at": protection.updated_at,
                            "latency_seconds": latency,
                            "protection_id": protection.protection_id,
                        },
                    )
        try:
            self.risk_service.enforce_account_hard_limits()
        except Exception as exc:  # noqa: BLE001
            logger.exception("成交后账户硬限额检查失败: %s", exc)
            try:
                self._latch_halted()
                self.journal.enqueue_outbox(
                    "page.post_fill_hard_limit_check_failed",
                    {
                        "intent_id": intent.intent_id,
                        "inst_id": intent.inst_id,
                        "error": str(exc),
                    },
                )
            except Exception:  # noqa: BLE001
                logger.critical(
                    "成交后硬限额检查失败且无法持久化 HALTED/Page",
                    exc_info=True,
                )

    @property
    def ready(self) -> bool:
        stream_ready = (self.streams is None or self.streams.ready) and self._public_market_ready()
        return not self.safety_only and self.journal.get_mode() is SystemMode.READY and stream_ready

    @property
    def safety_only(self) -> bool:
        """Immutable deployment-admission state for this runtime instance."""
        return self._safety_only

    def _latch_halted(
        self,
        reason: str = "runtime_hard_incident",
    ) -> SystemMode:
        """Latch a new hard incident without erasing stronger workflows."""
        with self.operation_lock:
            current = self.journal.get_mode()
            if current in {
                SystemMode.EMERGENCY_EXIT,
                SystemMode.MAINTENANCE,
            }:
                return current
            if current is SystemMode.HALTED and self.journal.get_mode_reason() == reason:
                return current
            # set_mode deliberately increments the hard epoch even for
            # HALTED -> HALTED.  A fault arriving after the Canary startup
            # hold must invalidate the activation bound to the older epoch.
            self.journal.set_mode(SystemMode.HALTED, reason=reason)
            return self.journal.get_mode()

    def register_public_market_data(
        self,
        instruments: list[str] | tuple[str, ...],
        bar: str,
    ) -> None:
        """启动前注册生产必需的 public ticker/candle 低延迟事实流。"""
        if self._started:
            raise RuntimeError("Public market subscriptions 必须在启动前注册")
        if self.websocket is None:
            raise RuntimeError("生产 public market stream 需要 WebSocket")
        self._bar_seconds(bar)
        for inst_id in sorted(set(instruments)):
            self._required_public_market_channels.update(
                {
                    ("ticker", inst_id),
                    ("candle", inst_id),
                }
            )
            self.websocket.subscribe_ticker(
                inst_id,
                lambda rows, current=inst_id: self._on_public_market_event("ticker", current, rows),
            )
            self.websocket.subscribe_candle(
                inst_id,
                bar,
                lambda rows, current=inst_id: self._on_public_market_event("candle", current, rows),
            )

    def _on_public_market_event(
        self,
        channel: str,
        inst_id: str,
        rows: list[dict] | list[list],
    ) -> None:
        if not rows:
            return
        observed_at = time.time()
        with self._ws_state_lock:
            self._public_market_last_event_at[(channel, inst_id)] = observed_at
            if channel == "ticker":
                self._cache_public_ticker(
                    inst_id,
                    rows,
                    observed_at=observed_at,
                )
        self.metrics.inc(
            "public_market_events_total",
            channel=channel,
            inst=inst_id,
        )
        self.metrics.set(
            "public_market_last_event_timestamp",
            observed_at,
            channel=channel,
            inst=inst_id,
        )

    def _cache_public_ticker(
        self,
        inst_id: str,
        rows: list[dict] | list[list],
        *,
        observed_at: float,
    ) -> None:
        """在 WS callback 内保存可用于 dust 证明的完整本地 ticker。"""
        try:
            row = rows[0]
            if not isinstance(row, dict):
                raise ValueError("ticker row 必须是对象")
            last = to_decimal(row.get("last"))
            bid = to_decimal(row.get("bidPx"))
            ask = to_decimal(row.get("askPx"))
            source_timestamp = float(row.get("ts", 0))
            if source_timestamp > 100_000_000_000:
                source_timestamp /= 1000
            if (
                not last.is_finite()
                or not bid.is_finite()
                or not ask.is_finite()
                or last <= 0
                or bid <= 0
                or ask <= 0
                or ask < bid
                or not math.isfinite(source_timestamp)
                or source_timestamp <= 0
            ):
                raise ValueError("ticker price/timestamp 非法")
        except (ArithmeticError, TypeError, ValueError):
            # 新事件已经证明当前 feed 内容不可信；不得继续用上一条低价
            # ticker 把重大仓位误判成 dust。
            self._public_ticker_cache.pop(inst_id, None)
            return
        self._public_ticker_cache[inst_id] = (
            last,
            bid,
            ask,
            source_timestamp,
            observed_at,
        )

    def _public_market_ready(self) -> bool:
        if self.websocket is None or not self.websocket.public_required:
            return True
        if not self.websocket.public_ready:
            return False
        now = time.time()
        return bool(self._required_public_market_channels) and all(
            0 <= now - self._public_market_last_event_at.get(key, 0) <= 20
            for key in self._required_public_market_channels
        )

    def _all_ws_transport_ready(self) -> bool:
        private_ready = self.streams is None or self.streams.transport_ready
        return private_ready and self._public_market_ready()

    def start(self) -> None:
        if self._started:
            return
        self.runtime_started_at = time.time()
        self.lock.acquire()
        try:
            if self.account_lease is not None:
                self.account_lease.start(
                    holder_id=self.runtime_instance_id,
                )
            hard_modes = {
                SystemMode.HALTED,
                SystemMode.EMERGENCY_EXIT,
                SystemMode.MAINTENANCE,
            }
            if self.safety_only:
                latched_mode = self._latch_halted()
            else:
                latched_mode = (
                    self.journal.get_mode() if self.journal.get_mode() in hard_modes else None
                )
            if latched_mode is None:
                self.journal.set_mode(SystemMode.STARTING)
            self._check_clock()
            self._check_account_identity()
            startup_reconciliation_started = time.monotonic()
            self.recovery.recover()
            self._last_reconciliation_completed_at = time.time()
            self.execution.start()
            if self.streams is not None:
                # 先订阅，再在同一连接 generation 上做第二次 REST baseline，
                # 覆盖“首次 REST 快照完成到 WS 订阅 ACK”之间的漏窗。
                self.streams.invalidate_baseline()
                if latched_mode is None:
                    self.journal.set_mode(SystemMode.DEGRADED)
                self.streams.start()
                deadline = time.monotonic() + self.ws_ready_timeout_s
                while time.monotonic() < deadline and not self._all_ws_transport_ready():
                    time.sleep(0.05)
                if not self._all_ws_transport_ready():
                    raise RuntimeError("WebSocket 未在门限内确认 private/business/public 订阅")
                baseline_generation = self._ws_generation
                baseline_event_sequence = self.streams.event_sequence
                result = self.reconciler.run(manage_mode=False)
                self._last_reconciliation_completed_at = time.time()
                self._sync_all_risk_managers()
                with self._ws_state_lock:
                    if (
                        not result.safe
                        or not self._all_ws_transport_ready()
                        or self._ws_generation != baseline_generation
                        or not self.streams.mark_baseline_complete(
                            baseline_event_sequence,
                            (lambda: self._promote_ready_if_safe(True))
                            if latched_mode is None
                            else None,
                        )
                    ):
                        raise RuntimeError("私有 WebSocket/REST baseline 建立期间发生变化")
            self._reclaim_demo_probes_once("startup")
            startup_reconciliation_duration = time.monotonic() - startup_reconciliation_started
            self.metrics.observe(
                "startup_reconciliation_duration_seconds",
                startup_reconciliation_duration,
                buckets=(1, 3, 5, 10, 20, 30, 60),
            )
            self.journal.record_event(
                "startup_reconciliation_slo_sample",
                payload={
                    "duration_seconds": startup_reconciliation_duration,
                    "within_60_seconds": (startup_reconciliation_duration <= 60),
                },
            )
            self._record_ws_liveness_sample(
                baseline_safe=(self.streams.ready if self.streams is not None else True)
            )
            self._install_canary_activation_hold()
            self._stop_event.clear()
            self._reconcile_thread = threading.Thread(
                target=self._periodic_reconcile,
                name="periodic-reconciler",
                daemon=False,
            )
            self._reconcile_thread.start()
            self._control_thread = threading.Thread(
                target=self._control_loop,
                name="control-command-runner",
                daemon=False,
            )
            self._control_thread.start()
            self._safety_thread = threading.Thread(
                target=self._safety_loop,
                name="position-safety-watchdog",
                daemon=False,
            )
            self._safety_thread.start()
            if self.backup_receipt_path is not None:
                self._backup_receipt_thread = threading.Thread(
                    target=self._backup_receipt_loop,
                    name="backup-receipt-ingester",
                    daemon=True,
                )
                self._backup_receipt_thread.start()
            self.alerts.start()
            if self.backups:
                self.backups.backup_once()
                self.backups.start()
            if self.resources:
                self.resources.start()
            if self.metrics_server:
                self.metrics_server.start()
            self._update_metrics()
            if self.heartbeat:
                self.heartbeat.start()
            self._started = True
            self.journal.record_event("production_runtime_ready")
        except BaseException:
            self._stop_event.set()
            self._latch_halted()
            if self.metrics_server:
                self.metrics_server.stop()
            if self.backups:
                self.backups.stop()
            if self.resources:
                self.resources.stop()
            self.alerts.stop()
            if self.heartbeat:
                self.heartbeat.stop()
            if self.streams is not None:
                self.streams.stop()
            self.execution.stop()
            if self.account_lease is not None:
                self.account_lease.stop()
            if self._safety_thread:
                self._safety_thread.join(timeout=5)
            if self._backup_receipt_thread:
                self._backup_receipt_thread.join(timeout=1)
            self.lock.release()
            raise

    def stop(self) -> None:
        if not self._started:
            self.lock.release()
            return
        self._stop_event.set()
        if self._reconcile_thread:
            self._reconcile_thread.join(timeout=10)
        if self._control_thread:
            self._control_thread.join(timeout=10)
        if self._safety_thread:
            self._safety_thread.join(timeout=10)
        if self._backup_receipt_thread:
            self._backup_receipt_thread.join(timeout=2)
        if self.metrics_server:
            self.metrics_server.stop()
        if self.backups:
            self.backups.stop()
        if self.resources:
            self.resources.stop()
        self.alerts.stop()
        if self.heartbeat:
            self.heartbeat.stop()
        if self.streams is not None:
            self.streams.stop()
        self.execution.stop()
        if self.account_lease is not None:
            self.account_lease.stop()
        self.journal.record_event("production_runtime_stopped")
        self.lock.release()
        self._started = False

    def register_risk_manager(self, risk: RiskManager) -> None:
        """把 durable fill 投影同步给旧策略层只读仓位视图。"""
        identity = id(risk)
        if identity in self._risk_managers:
            return
        self._risk_managers[identity] = risk

        def sync(intent: OrderIntent, _delta: Decimal) -> None:
            self._sync_risk_for_inst(risk, intent.inst_id, intent)

        self.execution.add_fill_handler(sync)

    def _sync_risk_for_inst(
        self,
        risk: RiskManager,
        inst_id: str,
        intent: OrderIntent | None = None,
    ) -> None:
        from okx_quant.risk.manager import PositionInfo

        row = self.journal.get_position(inst_id)
        qty = to_decimal(row["base_qty"]) if row else Decimal("0")
        if qty <= 0:
            risk.remove_position(inst_id)
            return
        current = risk.get_position(inst_id)
        stop = (
            float(intent.requested_stop_loss)
            if intent and intent.requested_stop_loss > 0
            else (current.stop_loss if current else 0)
        )
        take = (
            float(intent.requested_take_profit)
            if intent and intent.requested_take_profit > 0
            else (current.take_profit if current else 0)
        )
        risk.add_position(
            PositionInfo(
                inst_id=inst_id,
                size=float(qty),
                entry_price=float(to_decimal(row["avg_entry_px"])),
                stop_loss=stop,
                take_profit=take,
            )
        )

    def _sync_all_risk_managers(self) -> None:
        local_ids = {row["inst_id"] for row in self.journal.list_positions()}
        for risk in self._risk_managers.values():
            all_ids = local_ids | {p.inst_id for p in risk.list_positions()}
            for inst_id in all_ids:
                self._sync_risk_for_inst(risk, inst_id)

    def has_processed_candle(self, strategy_instance_id: str, inst_id: str, candle_ts: str) -> bool:
        return self.journal.has_decision(strategy_instance_id, inst_id, candle_ts)

    def persist_decision(
        self,
        *,
        strategy_instance_id: str,
        strategy_name: str,
        strategy_version: str,
        inst_id: str,
        candle_ts: str,
        signal: str,
        requested_size_pct: Decimal,
        reason: str,
        inputs_hash: str = "",
    ) -> str | None:
        try:
            decision_id = self.journal.create_decision(
                strategy_instance_id=strategy_instance_id,
                strategy_name=strategy_name,
                strategy_version=strategy_version,
                inst_id=inst_id,
                candle_ts=candle_ts,
                signal=signal,
                requested_size_pct=requested_size_pct,
                reason=reason,
                inputs_hash=inputs_hash,
            )
        except sqlite3.IntegrityError:
            return None
        self.metrics.inc(
            "strategy_decisions_total",
            strategy=strategy_name,
            signal=signal,
        )
        return decision_id

    def record_strategy_warning(
        self,
        *,
        strategy_name: str,
        strategy_version: str,
        inst_id: str,
        warning_kind: str,
        detail: str,
    ) -> None:
        """Persist signal/LLM failures to the operational Warning channel."""
        if warning_kind not in {"timeout", "error"}:
            raise ValueError("warning_kind 必须是 timeout/error")
        bucket = int(time.time() // 300)
        self.journal.enqueue_outbox_once(
            (f"strategy-warning:{strategy_version}:{inst_id}:{warning_kind}:{bucket}"),
            f"warning.strategy_signal_{warning_kind}",
            {
                "strategy_name": strategy_name,
                "strategy_version": strategy_version,
                "inst_id": inst_id,
                "detail": detail,
                "dedupe_window_seconds": 300,
            },
        )

    def validate_candle(
        self,
        strategy_instance_id: str,
        inst_id: str,
        bar: str,
        candle_ts,
        market_data=None,
    ) -> tuple[bool, str]:
        """验证已完成 K 线的新鲜度和连续性并持久化 watermark。"""
        if self.journal.has_decision(strategy_instance_id, inst_id, str(candle_ts)):
            return False, "K 线已处理"
        ts = self._timestamp_seconds(candle_ts)
        interval = self._bar_seconds(bar)
        market_valid, market_reason, unsafe_data = self._validate_signal_market_data(
            market_data,
            interval=interval,
            candle_ts=ts,
        )
        if not market_valid:
            if unsafe_data:
                self.journal.set_mode(SystemMode.DEGRADED)
            return False, market_reason
        now = time.time()
        if ts > now + self.max_clock_skew_s:
            self.journal.set_mode(SystemMode.DEGRADED)
            return False, "K 线时间在未来"
        if now - ts > interval * 2 + self.max_clock_skew_s:
            self.journal.set_mode(SystemMode.DEGRADED)
            return False, "K 线已过期"
        previous_raw = self.journal.get_candle_watermark(strategy_instance_id, inst_id, bar)
        if previous_raw:
            previous = self._timestamp_seconds(previous_raw)
            delta = ts - previous
            if delta > interval + self.max_clock_skew_s:
                self.journal.set_mode(SystemMode.DEGRADED)
                return False, "K 线存在缺口"
            if delta <= 0:
                return False, "K 线已处理"
            if delta < interval - self.max_clock_skew_s:
                self.journal.set_mode(SystemMode.DEGRADED)
                return False, "K 线时间不连续"
        return True, "通过"

    def _validate_signal_market_data(
        self,
        market_data,
        *,
        interval: int,
        candle_ts: float,
    ) -> tuple[bool, str, bool]:
        """验证策略看到的完整窗口；高波动只拒绝信号，坏数据关闭 READY。"""
        if market_data is None:
            return True, "未提供窗口", False
        if not hasattr(market_data, "columns") or market_data.empty:
            return False, "K 线窗口为空", True
        required = {"ts", "open", "high", "low", "close"}
        if missing := required - set(market_data.columns):
            return False, f"K 线缺少列: {sorted(missing)}", True
        timestamps: list[float] = []
        try:
            for row in market_data[["ts", "open", "high", "low", "close"]].itertuples(
                index=False, name=None
            ):
                row_ts = self._timestamp_seconds(row[0])
                prices = [float(value) for value in row[1:]]
                if not math.isfinite(row_ts) or not all(math.isfinite(value) for value in prices):
                    return False, "K 线含 NaN/Inf", True
                open_px, high_px, low_px, close_px = prices
                if (
                    min(prices) <= 0
                    or high_px < max(open_px, close_px, low_px)
                    or low_px > min(open_px, close_px, high_px)
                ):
                    return False, "K 线 OHLC 结构非法", True
                timestamps.append(row_ts)
        except (TypeError, ValueError, OverflowError):
            return False, "K 线字段无法解析", True
        if not timestamps:
            return False, "K 线窗口为空", True
        for previous, current in zip(timestamps, timestamps[1:], strict=False):
            delta = current - previous
            if abs(delta - interval) > max(self.max_clock_skew_s, 1):
                return False, "K 线窗口不连续或乱序", True
        if abs(timestamps[-1] - candle_ts) > self.max_clock_skew_s:
            return False, "K 线窗口末端与事件时间不一致", True
        last = market_data.iloc[-1]
        range_ratio = (to_decimal(last["high"]) - to_decimal(last["low"])) / to_decimal(
            last["close"]
        )
        if not range_ratio.is_finite() or range_ratio > self.max_candle_range_ratio:
            return False, "K 线波动率超过信号门槛", False
        return True, "通过", False

    def mark_candle_processed(
        self,
        strategy_instance_id: str,
        inst_id: str,
        bar: str,
        candle_ts,
    ) -> None:
        self.journal.set_candle_watermark(strategy_instance_id, inst_id, bar, str(candle_ts))

    def backup(self, destination: str | Path) -> None:
        self.journal.backup(destination)

    def _check_clock(self) -> None:
        requested_at = time.time()
        server_time = self.exchange.get_server_time()
        received_at = time.time()
        midpoint = requested_at + (received_at - requested_at) / 2
        offset = server_time - midpoint
        skew = abs(offset)
        self.journal.record_event(
            "clock_quality_sample",
            severity="critical" if skew > self.max_clock_skew_s else "info",
            payload={
                "okx_midpoint_offset_seconds": offset,
                "request_rtt_seconds": received_at - requested_at,
                "server_time": server_time,
            },
        )
        self.metrics.set("clock_absolute_offset_seconds", skew)
        self.metrics.set(
            "clock_request_rtt_seconds",
            received_at - requested_at,
        )
        if skew > self.max_clock_skew_s:
            raise RuntimeError(f"本机与 OKX 时间偏差 {skew:.3f}s，超过 {self.max_clock_skew_s}s")

    def _check_account_identity(self) -> None:
        if not self.expected_account_id:
            return
        actual = self.exchange.get_account_identity()
        if actual != self.expected_account_id:
            raise RuntimeError(
                "OKX 账户 UID 与 production.account_id 不匹配: "
                f"expected={self.expected_account_id}, actual={actual}"
            )
        self.journal.record_event(
            "exchange_account_identity_verified",
            payload={"account_id": actual},
        )

    def _periodic_reconcile(self) -> None:
        while not self._stop_event.wait(self.reconciliation_interval_s):
            try:
                self._periodic_reconcile_once()
            except Exception as exc:  # noqa: BLE001
                logger.exception("周期对账失败: %s", exc)
                # DEGRADED 只能收紧 READY；不能把人工 HALT/应急/维护状态放宽。
                if self.journal.get_mode() not in {
                    SystemMode.HALTED,
                    SystemMode.EMERGENCY_EXIT,
                    SystemMode.MAINTENANCE,
                }:
                    self.journal.set_mode(SystemMode.DEGRADED)
                self.journal.enqueue_outbox(
                    "page.reconciliation_failed",
                    {"error": str(exc)},
                )

    def _periodic_reconcile_once(self) -> ReconciliationResult:
        self._check_clock()
        with self._ws_state_lock:
            baseline_generation = self._ws_generation
            baseline_event_sequence = self.streams.event_sequence if self.streams is not None else 0
        result = self.reconciler.run(manage_mode=False)
        self._last_reconciliation_completed_at = time.time()
        self._sync_all_risk_managers()
        self._reclaim_demo_probes_once("periodic")
        self.metrics.inc(
            "reconciliation_mismatches_total",
            result.mismatch_count,
            type="all",
        )
        if result.repaired_count > 0:
            self.journal.enqueue_outbox_once(
                f"warning:reconciliation-repair:{result.run_id}",
                "warning.reconciliation_auto_repair",
                {
                    "run_id": result.run_id,
                    "mismatch_count": result.mismatch_count,
                    "repaired_count": result.repaired_count,
                },
            )
        self._update_metrics()
        self._record_ws_liveness_sample(
            baseline_safe=(
                result.safe and (self.streams.ready if self.streams is not None else True)
            )
        )
        risk_safe = True
        if not result.safe:
            self.journal.set_mode(SystemMode.DEGRADED)
            incident = hashlib.sha256(
                json.dumps(
                    sorted(result.unresolved),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            if incident != self._last_reconciliation_incident:
                self.journal.enqueue_outbox(
                    "page.reconciliation_mismatch",
                    {
                        "run_id": result.run_id,
                        "mismatch_count": result.mismatch_count,
                        "unresolved": result.unresolved,
                    },
                )
                self._last_reconciliation_incident = incident
            return result
        self._last_reconciliation_incident = ""
        risk_safe, _risk_reason = self.risk_service.enforce_account_hard_limits()
        if risk_safe:
            self._try_activate_canary_entries()
        with self._ws_state_lock:
            fence_changed = self._ws_generation != baseline_generation
            if not fence_changed and self.streams is not None:
                fence_intact, _ = self.streams.run_if_baseline_current(
                    baseline_event_sequence,
                    (lambda: self._promote_ready_if_safe(True) if risk_safe else False),
                )
                fence_changed = not fence_intact
            elif not fence_changed:
                self._promote_ready_if_safe(True)
            if fence_changed:
                if self.streams is not None:
                    self.streams.invalidate_baseline()
                self.journal.set_mode(SystemMode.DEGRADED)
        if fence_changed:
            # 使用新事件序列立即重建 REST baseline；不能让下个 30 秒周期
            # 之前的 /readyz 短暂误报安全。
            recovered = self._restore_after_reconnect()
            if recovered is not None:
                return recovered
            result.unresolved.append("私有 WS baseline/事件序列在对账期间发生变化")
        return result

    def _reclaim_demo_probes_once(self, phase: str) -> list[dict]:
        if self.demo_probe is None:
            return []
        with self.operation_lock:
            results = self.demo_probe.reclaim_once(
                owner=f"runtime-demo-probe:{phase}",
            )
            self._set_demo_probe_reclaim_pending(results)
            return results

    def _set_demo_probe_reclaim_pending(self, rows: list[dict]) -> None:
        self._demo_probe_reclaim_pending = any(
            row["state"] not in TERMINAL_PROBE_STATES for row in rows
        )
        if self._demo_probe_reclaim_pending and self.journal.get_mode() is SystemMode.READY:
            self.journal.set_mode(SystemMode.DEGRADED)

    def _record_ws_liveness_sample(
        self,
        *,
        baseline_safe: bool,
    ) -> None:
        if self.websocket is None:
            return
        with self._ws_state_lock:
            states = {
                name: self._ws_states[name].value for name in ("public", "private", "business")
            }
            generations = dict(self._ws_connection_generations)
            event_sequence = self.streams.event_sequence if self.streams is not None else 0
        self.journal.record_event(
            "websocket_liveness_sample",
            severity="info" if baseline_safe else "warning",
            payload={
                "states": states,
                "generations": generations,
                "baseline_safe": baseline_safe,
                "event_sequence": event_sequence,
            },
        )

    def _on_ws_state(self, name: str, state: ConnectionState) -> None:
        if name not in {"public", "private", "business"}:
            return
        now = time.time()
        with self._ws_state_lock:
            previous = self._ws_states[name]
            self._ws_generation += 1
            if state is ConnectionState.CONNECTING:
                self._ws_connection_generations[name] += 1
                self._ws_connect_started_at[name] = now
            generation = self._ws_connection_generations[name]
            self._ws_states[name] = state
        self.journal.record_event(
            "websocket_state_transition",
            severity=(
                "warning"
                if state
                in {
                    ConnectionState.BACKOFF,
                    ConnectionState.DISCONNECTED,
                    ConnectionState.STALE,
                }
                else "info"
            ),
            correlation_id=name,
            payload={
                "channel": name,
                "old_state": previous.value,
                "new_state": state.value,
                "generation": generation,
            },
        )
        if state is ConnectionState.READY:
            connect_started = self._ws_connect_started_at.get(name, now)
            self.journal.record_event(
                "websocket_subscription_ready",
                correlation_id=name,
                payload={
                    "channel": name,
                    "generation": generation,
                    "connect_subscribe_latency_seconds": max(
                        now - connect_started,
                        0,
                    ),
                },
            )
        if state in {
            ConnectionState.BACKOFF,
            ConnectionState.DISCONNECTED,
            ConnectionState.STALE,
        }:
            self._ws_disconnected_at.setdefault(name, now)
            self._consecutive_ws_errors += 1
            self.journal.enqueue_outbox_once(
                (f"warning:ws:{name}:{self._ws_generation}:{state.value}"),
                "warning.websocket_disconnected",
                {
                    "channel": name,
                    "state": state.value,
                    "generation": self._ws_generation,
                },
            )
            with self._ws_state_lock:
                if self.streams is not None:
                    self.streams.invalidate_baseline()
                if self._consecutive_ws_errors >= self.max_consecutive_infrastructure_errors:
                    self._latch_halted()
                else:
                    self.journal.set_mode(SystemMode.DEGRADED)
            self.metrics.set(
                "consecutive_infrastructure_errors",
                self._consecutive_ws_errors,
                source="ws",
            )
            if self._consecutive_ws_errors == self.max_consecutive_infrastructure_errors:
                self.journal.enqueue_outbox(
                    "page.ws_error_budget_exhausted",
                    {
                        "channel": name,
                        "state": state.value,
                        "consecutive_errors": self._consecutive_ws_errors,
                    },
                )
            return
        if state is ConnectionState.READY and self.websocket and self._all_ws_transport_ready():
            self._consecutive_ws_errors = 0
            threading.Thread(
                target=self._restore_after_reconnect,
                name="ws-reconnect-recovery",
                daemon=True,
            ).start()

    def _archive_external_control_request(
        self,
        path: Path,
        *,
        bucket: str,
    ) -> None:
        assert self.external_control_inbox_dir is not None
        destination_dir = self.external_control_inbox_dir / bucket
        destination_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = destination_dir / (f"{path.stem}-{uuid.uuid4().hex}{path.suffix}")
        path.replace(destination)

    def _ingest_external_control_inbox(self) -> None:
        """Consume file-drop requests; only this runtime mutates SQLite."""
        inbox = self.external_control_inbox_dir
        if inbox is None:
            return
        assert self.alert_receipt_public_keys
        if inbox.exists() and (inbox.is_symlink() or not inbox.is_dir()):
            raise RuntimeError("external control inbox 必须是普通目录")
        inbox.mkdir(mode=0o700, parents=True, exist_ok=True)
        for path in sorted(inbox.glob("*.json"))[:20]:
            try:
                info = path.lstat()
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or info.st_size <= 0
                    or info.st_size > 1_048_576
                ):
                    raise ValueError("external control request 文件非法")
                request = json.loads(path.read_bytes())
                result = apply_alert_control_request(
                    request,
                    journal=self.journal,
                    expected_account_id=self.expected_account_id,
                    receipt_public_keys=self.alert_receipt_public_keys,
                )
                self.journal.record_event(
                    "external_control_request_ingested",
                    correlation_id=path.stem,
                    payload={
                        "action": request.get("action"),
                        "result": result,
                    },
                )
                self._archive_external_control_request(
                    path,
                    bucket="processed",
                )
            except Exception as exc:  # noqa: BLE001
                self.journal.record_event(
                    "external_control_request_rejected",
                    severity="critical",
                    correlation_id=path.stem,
                    payload={"error": f"{type(exc).__name__}: {exc}"},
                )
                self.journal.enqueue_outbox(
                    "page.external_control_request_rejected",
                    {
                        "request": path.name,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                )
                self._archive_external_control_request(
                    path,
                    bucket="rejected",
                )

    def _control_loop(self) -> None:
        while not self._stop_event.wait(0.5):
            try:
                self._ingest_external_control_inbox()
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "external control inbox ingestion 失败: %s",
                    exc,
                )
                self._latch_halted(reason="external_control_inbox_failure")
            for command in self.journal.claim_control_commands():
                command_id = command["command_id"]
                command_type = command["command_type"]
                try:
                    with self.operation_lock:
                        if command_type == "halt-entries":
                            self.journal.set_mode(SystemMode.HALTED)
                            result = {"mode": SystemMode.HALTED.value}
                        elif command_type == "flatten-and-cancel":
                            result = self._flatten_and_cancel(
                                command_id,
                                command["payload"],
                            )
                        elif command_type == "backup-now":
                            destination = command["payload"]["destination"]
                            self.backup(destination)
                            result = {"destination": destination}
                        elif command_type == "reconcile-now":
                            outcome = self._periodic_reconcile_once()
                            result = {
                                "safe": outcome.safe,
                                "mismatch_count": outcome.mismatch_count,
                                "repaired_count": outcome.repaired_count,
                                "unresolved": outcome.unresolved,
                            }
                        elif command_type == "demo-probe":
                            if self.demo_probe is None:
                                raise RuntimeError("当前 runtime 不允许 Active Demo probe")
                            probe_id = str(command["payload"].get("probe_id", ""))
                            if not probe_id:
                                prepared = self.demo_probe.prepare(
                                    inst_id=str(command["payload"]["inst_id"]),
                                    nominal_usdt=Decimal(str(command["payload"]["nominal_usdt"])),
                                    slot=int(command["payload"]["slot"]),
                                )
                                probe_id = prepared["probe_id"]
                            row = self.demo_probe.advance(
                                probe_id,
                                owner=f"runtime:{command_id}",
                            )
                            self._set_demo_probe_reclaim_pending([row])
                            result = {
                                "probe_id": probe_id,
                                "state": row["state"],
                                "last_error": row["last_error"],
                            }
                        elif command_type == "resume-entries":
                            result = self._resume_entries(
                                command_id,
                                command["payload"],
                            )
                        else:
                            raise ValueError(f"未知控制命令: {command_type}")
                    self.journal.record_event(
                        "control_command_completed",
                        correlation_id=command_id,
                        payload={"type": command_type, "result": result},
                    )
                    self.journal.finish_control_command(command_id, success=True, result=result)
                except Exception as exc:  # noqa: BLE001
                    self._latch_halted()
                    self.journal.record_event(
                        "control_command_failed",
                        severity="critical",
                        correlation_id=command_id,
                        payload={"type": command_type, "error": str(exc)},
                    )
                    self.journal.enqueue_outbox(
                        "page.control_command_failed",
                        {
                            "command_id": command_id,
                            "type": command_type,
                            "error": str(exc),
                        },
                    )
                    self.journal.finish_control_command(
                        command_id,
                        success=False,
                        result={"error": str(exc)},
                    )

    def _resume_entries(self, command_id: str, payload: dict) -> dict:
        if self.safety_only:
            raise RuntimeError("生产准入未授权：safety-only 运行时永久拒绝恢复新增风险")
        if self._entry_authorization_expired():
            raise RuntimeError("Canary entry authorization 已过期，拒绝恢复新增风险")
        if not self._backup_entry_safe():
            raise RuntimeError("Canary backup RPO 不满足，拒绝恢复新增风险")
        if not self._canary_activation_valid():
            raise RuntimeError("Canary post-start activation 无效，拒绝恢复新增风险")
        current, hard_epoch = self.journal.get_mode_state()
        if current not in {
            SystemMode.HALTED,
            SystemMode.MAINTENANCE,
        }:
            raise RuntimeError(f"只有 HALTED/MAINTENANCE 可受控恢复，当前为 {current.value}")
        if self.approval_verifier is not None:
            claims = self.approval_verifier.verify(
                payload.get("approval"),
                command_id=command_id,
                expected_account_id=self.expected_account_id,
                expected_config_hash=self.production_config_hash,
            )
            actor = claims["actor"]
            approver = claims["risk_approver"]
        else:
            actor = str(payload.get("actor", "")).strip()
            approver = str(payload.get("risk_approver", "")).strip()
        if not actor or not approver or actor == approver:
            raise RuntimeError("恢复交易必须由不同的 operator 与 risk approver 双人确认")
        if (
            self.alerts.webhook_url
            and self.alerts.consecutive_failures >= self.max_consecutive_infrastructure_errors
        ):
            raise RuntimeError("告警投递链不健康，禁止恢复新增风险")
        if self.alerts.webhook_url:
            self.alerts.verify_delivery(
                {
                    "command_id": command_id,
                    "account_id": self.expected_account_id,
                    "config_hash": self.production_config_hash,
                    "actor": actor,
                    "risk_approver": approver,
                }
            )

        self._check_clock()
        self._check_account_identity()
        baseline_generation = self._ws_generation
        baseline_event_sequence = self.streams.event_sequence if self.streams is not None else 0
        outcome = self.reconciler.run(manage_mode=False)
        self._last_reconciliation_completed_at = time.time()
        self._sync_all_risk_managers()
        if not outcome.safe:
            raise RuntimeError("恢复前联合对账未通过: " + ", ".join(outcome.unresolved))
        with self._ws_state_lock:
            if self._ws_generation != baseline_generation:
                raise RuntimeError("恢复检查期间私有 WS connection generation 发生变化")
            if self.streams is not None:
                fence_intact, changed_raw = self.streams.run_if_baseline_current(
                    baseline_event_sequence,
                    lambda: self.journal.set_mode(
                        SystemMode.READY,
                        allow_hard_release=True,
                        expected_hard_epoch=hard_epoch,
                    ),
                )
                if not fence_intact:
                    raise RuntimeError("恢复检查期间私有 WS baseline/事件序列发生变化")
                changed = bool(changed_raw)
            else:
                changed = self.journal.set_mode(
                    SystemMode.READY,
                    allow_hard_release=True,
                    expected_hard_epoch=hard_epoch,
                )
        healthy, detail = self._health()
        if not changed or not healthy:
            self._latch_halted()
            raise RuntimeError(f"恢复后 readiness 校验失败: {detail}")
        self.journal.record_event(
            "entries_resumed",
            severity="critical",
            payload={
                "actor": actor,
                "risk_approver": approver,
                "command_id": command_id,
                "reconciliation_run_id": outcome.run_id,
            },
        )
        return {
            "mode": SystemMode.READY.value,
            "actor": actor,
            "risk_approver": approver,
            "reconciliation_run_id": outcome.run_id,
        }

    def _flatten_and_cancel(self, command_id: str, payload: dict) -> dict:
        """由运行中唯一写者执行的破坏性资金操作。"""
        requested = set(payload.get("instruments") or [])
        if self.approval_verifier is not None:
            claims = self.approval_verifier.verify(
                payload.get("approval"),
                command_id=command_id,
                expected_account_id=self.expected_account_id,
                expected_config_hash=self.production_config_hash,
                expected_action="flatten-and-cancel",
                expected_instruments=sorted(requested),
            )
            actor = claims["actor"]
            approver = claims["risk_approver"]
        else:
            actor = str(payload.get("actor", "")).strip()
            approver = str(payload.get("risk_approver", "")).strip()

        # 先以交易所事实解析签名 scope；未知 target 必须在任何交易所写操作
        # （包括取消其他交易对挂单）之前失败。
        preflight_balance = self.exchange.get_balance()
        preflight_pending = self.exchange.get_pending_orders()
        preflight_algos = self.exchange.get_pending_algo_orders()
        known = {
            f"{holding.ccy}-{self.exchange.quote_ccy}"
            for holding in preflight_balance.non_quote_holdings(self.exchange.quote_ccy)
            if to_decimal(holding.balance) > 0
        }
        known.update(order.inst_id for order in preflight_pending)
        known.update(algo.inst_id for algo in preflight_algos)
        known.update(row["inst_id"] for row in self.journal.list_positions())
        unknown_requested = requested - known
        if unknown_requested:
            raise RuntimeError(
                "请求退出/撤单的交易对不存在于交易所或本地事实: "
                + ", ".join(sorted(unknown_requested))
            )
        all_scope = not requested
        targets = requested or known

        self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
        _, flatten_hard_epoch = self.journal.get_mode_state()
        baseline = self.reconciler.run(
            reconcile_protections=False,
        )
        self._sync_all_risk_managers()
        if not baseline.safe:
            self.journal.record_event(
                "flatten_baseline_degraded",
                severity="critical",
                payload={"unresolved": baseline.unresolved},
            )
        canceled: list[str] = []
        for remote in self.exchange.get_pending_orders():
            if not remote.ord_id or remote.inst_id not in targets:
                continue
            updated = self.exchange.cancel_order(remote.inst_id, remote.ord_id)
            try:
                self.execution.process_exchange_update(updated)
            except KeyError:
                self.journal.import_external_order(updated)
            canceled.append(remote.ord_id)

        exits: list[str] = []
        errors: list[str] = []
        positions = self.journal.list_positions()
        if all_scope:
            # ALL 是动态账户 scope，不能冻结为 preflight 时看到的集合。
            latest_balance = self.exchange.get_balance()
            targets = {
                f"{holding.ccy}-{self.exchange.quote_ccy}"
                for holding in latest_balance.non_quote_holdings(self.exchange.quote_ccy)
                if to_decimal(holding.balance) > 0
            }
            targets.update(order.inst_id for order in self.exchange.get_pending_orders())
            targets.update(algo.inst_id for algo in self.exchange.get_pending_algo_orders())
            targets.update(row["inst_id"] for row in positions)
        for row in positions:
            inst_id = row["inst_id"]
            if inst_id not in targets:
                continue
            try:
                intent = self.exit.exit_position(inst_id, "flatten-and-cancel")
                if intent is None or intent.state.value != "filled":
                    errors.append(f"{inst_id}:exit_not_filled")
                else:
                    exits.append(intent.exchange_ord_id)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{inst_id}:{exc}")
        if errors:
            raise RuntimeError("; ".join(errors))

        # 以交易所余额和未决订单做 post-condition，不能只相信本地投影。
        balance = self.exchange.get_balance()
        remaining: list[str] = []
        holding_targets = set(targets)
        if all_scope:
            holding_targets.update(
                f"{holding.ccy}-{self.exchange.quote_ccy}"
                for holding in balance.non_quote_holdings(self.exchange.quote_ccy)
                if to_decimal(holding.balance) > 0
            )
        for inst_id in sorted(holding_targets):
            base_ccy = inst_id.split("-")[0]
            holding = balance.holding(base_ccy)
            qty = to_decimal(holding.balance if holding else 0)
            try:
                price = to_decimal(self.exchange.get_ticker(inst_id).last)
            except Exception:
                price = Decimal("0")
            if qty > 0 and (price <= 0 or qty * price >= self.reconciler.dust_usdt):
                remaining.append(f"{inst_id}:balance={qty}")
        for order in self.exchange.get_pending_orders():
            if all_scope or order.inst_id in targets:
                remaining.append(f"{order.inst_id}:pending_order={order.ord_id}")
        if all_scope:
            algos = self.exchange.get_pending_algo_orders()
        else:
            algos = [
                algo
                for inst_id in sorted(targets)
                for algo in self.exchange.get_pending_algo_orders(inst_id)
            ]
        for algo in algos:
            if all_scope or algo.inst_id in targets:
                remaining.append(f"{algo.inst_id}:pending_algo={algo.algo_id}")
        if remaining:
            raise RuntimeError("flatten 后交易所仍存在风险: " + "; ".join(remaining))
        if not self.journal.set_mode(
            SystemMode.HALTED,
            allow_hard_release=True,
            expected_hard_epoch=flatten_hard_epoch,
        ):
            raise RuntimeError("flatten 期间出现更新的 hard-safe 意图，拒绝解除应急状态")
        self.journal.record_event(
            "flatten_and_cancel_completed",
            severity="critical",
            correlation_id=command_id,
            payload={
                "actor": actor,
                "risk_approver": approver,
                "instruments": sorted(requested),
            },
        )
        return {
            "canceled_order_ids": canceled,
            "exit_order_ids": exits,
            "actor": actor,
            "risk_approver": approver,
        }

    def _restore_after_reconnect(self) -> ReconciliationResult | None:
        if not self._reconnect_lock.acquire(blocking=False):
            return None
        baseline_started_at = time.time()
        try:
            deadline = time.monotonic() + self.ws_ready_timeout_s
            while self.streams is not None and time.monotonic() < deadline:
                with self._ws_state_lock:
                    if not self._all_ws_transport_ready():
                        return None
                    baseline_generation = self._ws_generation
                    baseline_event_sequence = self.streams.event_sequence
                    self.streams.invalidate_baseline()

                result = self.reconciler.run(manage_mode=False)
                self._last_reconciliation_completed_at = time.time()
                self._sync_all_risk_managers()
                self._update_metrics()
                if not result.safe:
                    self.journal.set_mode(SystemMode.DEGRADED)
                    return None

                with self._ws_state_lock:
                    # REST baseline 必须完整落在同一 WS connection epoch 内。
                    # 若对账期间断线并重连，直接以新 generation 重做，不能把
                    # 跨 epoch 快照误标为 READY。
                    if (
                        self._ws_generation != baseline_generation
                        or not self._all_ws_transport_ready()
                        or not self.streams.mark_baseline_complete(
                            baseline_event_sequence,
                            lambda: self._promote_ready_if_safe(True),
                        )
                    ):
                        continue
                    completed_at = time.time()
                    for channel, disconnected_at in tuple(self._ws_disconnected_at.items()):
                        self.journal.record_event(
                            "websocket_recovery_completed",
                            correlation_id=channel,
                            payload={
                                "channel": channel,
                                "generation": (self._ws_connection_generations[channel]),
                                "disconnect_duration_seconds": max(
                                    completed_at - disconnected_at,
                                    0,
                                ),
                                "rest_baseline_duration_seconds": max(
                                    completed_at - baseline_started_at,
                                    0,
                                ),
                                "safe": True,
                            },
                        )
                        self._ws_disconnected_at.pop(channel, None)
                    return result
        except Exception as exc:  # noqa: BLE001
            logger.error("WS 重连后 REST baseline 失败: %s", exc)
        finally:
            self._reconnect_lock.release()
        return None

    def _promote_ready_if_safe(self, safe: bool) -> bool:
        if (
            not safe
            or self.safety_only
            or self._entry_authorization_expired()
            or not self._backup_entry_safe()
            or not self._canary_activation_valid()
            or self._demo_probe_reclaim_pending
        ):
            return False
        with self._ws_state_lock:
            if (
                self.alerts.webhook_url
                and self.alerts.consecutive_failures >= self.max_consecutive_infrastructure_errors
            ):
                self.journal.set_mode(SystemMode.DEGRADED)
                return False
            if self.streams is not None and not self.streams.ready:
                return False
            if not self._public_market_ready():
                return False
            if self.journal.get_mode() in {
                SystemMode.HALTED,
                SystemMode.EMERGENCY_EXIT,
                SystemMode.MAINTENANCE,
            }:
                return False
            self.journal.set_mode(SystemMode.READY)
            return self.journal.get_mode() is SystemMode.READY

    def _health(self) -> tuple[bool, dict]:
        mode = self.journal.get_mode()
        public_market_ready = self._public_market_ready()
        stream_ready = (self.streams is None or self.streams.ready) and public_market_ready
        live, liveness = self._liveness()
        alert_delivery_healthy = (
            not self.alerts.webhook_url
            or self.alerts.consecutive_failures < self.max_consecutive_infrastructure_errors
        )
        entry_authorization_valid = not self._entry_authorization_expired()
        backup_entry_safe = self._backup_entry_safe()
        canary_activation_valid = self._canary_activation_valid()
        account_lease_valid = self.account_lease is None or self.account_lease.valid()
        ok = (
            not self.safety_only
            and mode is SystemMode.READY
            and stream_ready
            and alert_delivery_healthy
            and entry_authorization_valid
            and backup_entry_safe
            and canary_activation_valid
            and account_lease_valid
            and not self._demo_probe_reclaim_pending
            and live
            and liveness["reconciliation_fresh"]
        )
        return ok, {
            "ready": ok,
            "safety_only": self.safety_only,
            "mode": mode.value,
            "stream_ready": stream_ready,
            "public_market_ready": public_market_ready,
            "alert_delivery_healthy": alert_delivery_healthy,
            "entry_authorization_valid": entry_authorization_valid,
            "entry_authorization_expires_at": (self.entry_authorization_expires_at),
            "backup_entry_safe": backup_entry_safe,
            "max_entry_backup_rpo_seconds": self.max_entry_backup_rpo_s,
            "canary_activation_valid": canary_activation_valid,
            "account_writer_lease_valid": account_lease_valid,
            "account_writer_fencing_identity": (
                self.account_lease.fencing_identity() if self.account_lease is not None else None
            ),
            "canary_activation_consumed": (self._canary_activation_consumed),
            "canary_startup_hard_epoch": (self._canary_startup_hard_epoch),
            "canary_startup_nonce": self._canary_startup_nonce,
            "canary_startup_latch_reason": (self._canary_startup_latch_reason),
            "demo_probe_reclaim_pending": (self._demo_probe_reclaim_pending),
            "runtime_instance_id": self.runtime_instance_id,
            "runtime_started_at": self.runtime_started_at,
            "boot_id": self.runtime_boot_id,
            "account_uid": self.expected_account_id,
            "deployment_unit": self.deployment_unit,
            "soak_epoch_id": self.soak_epoch_id,
            "canary_transition_sha256": self.canary_transition_sha256,
            "canary_policy_sha256": self.canary_policy_sha256,
            "canary_target_deployment_identity_sha256": self.canary_target_sha256,
            "release_identity": self.release_identity,
            "config_identity": self.production_config_hash,
            **liveness,
        }

    def _entry_ready(self) -> bool:
        return self._health()[0]

    def _entry_guard(self) -> tuple[bool, object]:
        with self._ws_state_lock:
            event_sequence = self.streams.event_sequence if self.streams is not None else 0
            lease_identity = (
                self.account_lease.fencing_identity() if self.account_lease is not None else None
            )
            return (
                self._entry_ready(),
                (self._ws_generation, event_sequence, lease_identity),
            )

    def _entry_authorization_expired(
        self,
        *,
        now: float | None = None,
    ) -> bool:
        return bool(
            self.entry_authorization_expires_at
            and (time.time() if now is None else now) >= self.entry_authorization_expires_at
        )

    def _enforce_entry_authorization(
        self,
        *,
        now: float | None = None,
    ) -> None:
        if (
            not self._entry_authorization_expired(now=now)
            or self._entry_authorization_expiry_reported
        ):
            return
        self._latch_halted()
        self.journal.record_event(
            "entry_authorization_expired",
            severity="critical",
            payload={
                "expires_at": self.entry_authorization_expires_at,
                "detected_at": time.time() if now is None else now,
            },
        )
        self.journal.enqueue_outbox(
            "page.entry_authorization_expired",
            {"expires_at": self.entry_authorization_expires_at},
        )
        self._entry_authorization_expiry_reported = True

    def _backup_entry_safe(self, *, now: float | None = None) -> bool:
        if self.max_entry_backup_rpo_s <= 0:
            return True
        latest = self.journal.latest_event("backup_slo_sample")
        if latest is None:
            return False
        payload = latest["payload"]
        current = time.time() if now is None else now
        try:
            validate_backup_slo_sample(
                payload,
                event_created_at=float(latest["created_at"]),
            )
            snapshot_completed_at = float(
                payload["snapshot_completed_at"]
            )
        except (KeyError, TypeError, ValueError):
            return False
        return bool(
            0
            <= current - snapshot_completed_at
            <= self.max_entry_backup_rpo_s
        )

    def _ingest_backup_receipt(self, *, now: float | None = None) -> bool:
        """Let the trader remain the sole writer of verified backup facts."""
        if self.backup_receipt_path is None:
            return False
        current = time.time() if now is None else now
        try:
            info = self.backup_receipt_path.lstat()
            receipt_identity = (info.st_mtime_ns, info.st_size)
            if receipt_identity == self._last_backup_receipt_stat:
                return False
            self._last_backup_receipt_stat = receipt_identity
            if (
                self.backup_receipt_path.is_symlink()
                or not self.backup_receipt_path.is_file()
                or info.st_size <= 0
                or info.st_size > 1_048_576
            ):
                raise ValueError("backup receipt 必须是 1MiB 内的非空普通文件")
            claims, digest = read_verified_restore_evidence(
                self.backup_receipt_path,
                public_key=self.backup_receipt_public_key,
                expected_account_id=self.expected_account_id,
                expected_key_id=self.backup_receipt_key_id,
                now=current,
            )
            if digest == self._last_backup_receipt_sha256:
                return False
            existing = any(
                event["correlation_id"] == digest
                for event in self.journal.list_events("backup_slo_sample")
            )
            if not existing:
                self.journal.record_event(
                    "backup_slo_sample",
                    severity="info",
                    correlation_id=digest,
                    payload={
                        **claims["backup_slo_sample"],
                        "roundtrip_started_at": claims[
                            "roundtrip_started_at"
                        ],
                        "roundtrip_completed_at": claims[
                            "roundtrip_completed_at"
                        ],
                        "evidence_artifact_sha256": digest,
                        "evidence_key_id": claims["evidence_key_id"],
                    },
                )
            self._last_backup_receipt_sha256 = digest
            self._failed_backup_receipt_identity = ""
            self._backup_rpo_breach_reported = False
            return not existing
        except FileNotFoundError:
            return False
        except Exception as exc:  # noqa: BLE001
            identity = f"{type(exc).__name__}:{exc}"
            if identity != self._failed_backup_receipt_identity:
                self.journal.record_event(
                    "backup_receipt_rejected",
                    severity="critical",
                    payload={"error": identity},
                )
                self.journal.enqueue_outbox(
                    "page.backup_receipt_rejected",
                    {"error": identity},
                )
                self._failed_backup_receipt_identity = identity
            return False

    def _enforce_backup_entry_rpo(
        self,
        *,
        now: float | None = None,
    ) -> None:
        if (
            self.max_entry_backup_rpo_s <= 0
            or self._backup_entry_safe(now=now)
            or self._backup_rpo_breach_reported
        ):
            return
        self._latch_halted()
        detected_at = time.time() if now is None else now
        self.journal.record_event(
            "entry_backup_rpo_breached",
            severity="critical",
            payload={
                "limit_seconds": self.max_entry_backup_rpo_s,
                "detected_at": detected_at,
            },
        )
        self.journal.enqueue_outbox(
            "page.entry_backup_rpo_breached",
            {"limit_seconds": self.max_entry_backup_rpo_s},
        )
        self._backup_rpo_breach_reported = True

    def _canary_activation_valid(
        self,
        *,
        now: float | None = None,
    ) -> bool:
        if self.canary_activation_path is None:
            return True
        # This artifact authorizes one CAS release, not the whole Canary
        # session.  Once consumed it can neither release a later hard epoch
        # nor shorten the separately signed Canary policy lifetime.
        if self._canary_activation_consumed:
            return True
        if self._canary_startup_hard_epoch is None:
            return False
        try:
            artifact = json.loads(self.canary_activation_path.read_text(encoding="utf-8"))
            from okx_quant.research.canary import (
                verify_post_start_activation,
            )

            claims = verify_post_start_activation(
                artifact,
                operator_public_key=self.canary_operator_public_key,
                risk_public_key=self.canary_risk_public_key,
                checks_verifier_public_key=(self.canary_check_verifier_public_key),
                source_key_fingerprints=self.canary_source_key_fingerprints,
                producer_inventory=self.canary_source_producer_inventory,
                target_key_fingerprint=(
                    self.canary_target_key_fingerprint
                ),
                transition_sha256=self.canary_transition_sha256,
                policy_sha256=self.canary_policy_sha256,
                target_deployment_identity_sha256=(self.canary_target_sha256),
                account_uid=self.expected_account_id,
                deployment_unit=self.deployment_unit,
                demo_soak_epoch_id=self.soak_epoch_id,
                runtime_instance_id=self.runtime_instance_id,
                boot_id=self.runtime_boot_id,
                expected_startup_hard_epoch=(self._canary_startup_hard_epoch),
                startup_nonce=self._canary_startup_nonce,
                latch_reason=self._canary_startup_latch_reason,
                now=int(time.time() if now is None else now),
            )
        except (OSError, ValueError, json.JSONDecodeError):
            return False
        self._canary_activation_claims = claims
        return True

    def _install_canary_activation_hold(self) -> bool:
        """Create the one hard epoch a post-start token may release."""
        if self.canary_activation_path is None:
            return False
        with self.operation_lock:
            current, _epoch = self.journal.get_mode_state()
            current_reason = self.journal.get_mode_reason()
            if current in {
                SystemMode.EMERGENCY_EXIT,
                SystemMode.MAINTENANCE,
            } or (current is SystemMode.HALTED and current_reason != "journal_initialized_halted"):
                return False
            if not self.journal.set_mode(
                SystemMode.HALTED,
                reason=self._canary_startup_latch_reason,
            ):
                return False
            mode, hard_epoch = self.journal.get_mode_state()
            if (
                mode is not SystemMode.HALTED
                or self.journal.get_mode_reason() != self._canary_startup_latch_reason
            ):
                return False
            self._canary_startup_hard_epoch = hard_epoch
            self.journal.record_event_once(
                f"canary-startup-hold:{self.runtime_instance_id}",
                "canary_startup_activation_hold",
                severity="critical",
                payload={
                    "runtime_instance_id": self.runtime_instance_id,
                    "boot_id": self.runtime_boot_id,
                    "startup_nonce": self._canary_startup_nonce,
                    "hard_epoch": hard_epoch,
                    "latch_reason": self._canary_startup_latch_reason,
                },
            )
            return True

    def _try_activate_canary_entries(self) -> bool:
        if (
            self.canary_activation_path is None
            or self._canary_activation_consumed
            or self._canary_startup_hard_epoch is None
            or self._entry_authorization_expired()
            or not self._backup_entry_safe()
        ):
            return False
        with self.operation_lock, self._ws_state_lock:
            # Reverify inside the same operation/WS critical section so expiry
            # or artifact replacement while waiting for the locks cannot
            # promote a stale authorization.
            if not self._canary_activation_valid():
                return False
            if (
                self.streams is not None and not self.streams.ready
            ) or not self._public_market_ready():
                return False
            mode, hard_epoch = self.journal.get_mode_state()
            if (
                mode is not SystemMode.HALTED
                or hard_epoch != self._canary_startup_hard_epoch
                or self.journal.get_mode_reason() != self._canary_startup_latch_reason
                or self._canary_activation_claims is None
                or self._canary_activation_claims["expected_startup_hard_epoch"] != hard_epoch
            ):
                return False
            changed = self.journal.set_mode(
                SystemMode.READY,
                allow_hard_release=True,
                expected_hard_epoch=hard_epoch,
                reason="canary_startup_activation_consumed",
            )
            if not changed:
                return False
            self._canary_activation_consumed = True
            self.journal.record_event(
                "canary_entries_activated",
                severity="critical",
                payload={
                    "runtime_instance_id": self.runtime_instance_id,
                    "boot_id": self.runtime_boot_id,
                    "startup_nonce": self._canary_startup_nonce,
                    "released_hard_epoch": hard_epoch,
                    "activation_expires_at": (
                        self._canary_activation_claims["expires_at"]
                        if self._canary_activation_claims
                        else 0
                    ),
                },
            )
            return True

    def _enforce_canary_activation(
        self,
        *,
        now: float | None = None,
    ) -> None:
        if self.canary_activation_path is None:
            return
        if self._canary_activation_consumed:
            return
        if self._canary_activation_valid(now=now):
            self._canary_activation_failure_reported = False
            return
        if self._canary_activation_failure_reported:
            return
        mode, hard_epoch = self.journal.get_mode_state()
        if not (
            mode is SystemMode.HALTED
            and hard_epoch == self._canary_startup_hard_epoch
            and self.journal.get_mode_reason() == self._canary_startup_latch_reason
        ):
            self._latch_halted("canary_activation_invalid")
        self.journal.enqueue_outbox(
            "page.canary_activation_missing_or_expired",
            {
                "runtime_instance_id": self.runtime_instance_id,
                "boot_id": self.runtime_boot_id,
            },
        )
        self._canary_activation_failure_reported = True

    def _liveness(self) -> tuple[bool, dict]:
        """systemd watchdog 的进程活性；HALTED/DEGRADED 仍可健康存活。"""
        mode = self.journal.get_mode()
        threads = {
            "execution": self.execution._thread,
            "reconciliation": self._reconcile_thread,
            "control": self._control_thread,
            "alerts": self.alerts._thread,
            "safety": self._safety_thread,
        }
        if self._backup_receipt_thread is not None:
            threads["backup_receipt"] = self._backup_receipt_thread
        if self.backups is not None:
            threads["backup"] = self.backups._thread
        if self.resources is not None:
            threads["resources"] = self.resources._thread
        if self.websocket is not None:
            threads["websocket"] = self.websocket._thread
        thread_alive = {
            name: thread is not None and thread.is_alive() for name, thread in threads.items()
        }
        # 构造完成但尚未 start 时供诊断使用；Heartbeat 只在全部线程启动后运行。
        safety_age = max(
            time.monotonic() - self._last_safety_completed_monotonic,
            0,
        )
        safety_fresh = safety_age <= 5
        core_thread_names = set(thread_alive) - {"backup_receipt"}
        core_threads_healthy = (
            all(thread_alive[name] for name in core_thread_names) and safety_fresh
            if self._started or self.heartbeat
            else True
        )
        reconciliation_age = (
            max(time.time() - self._last_reconciliation_completed_at, 0)
            if self._last_reconciliation_completed_at
            else float("inf")
        )
        reconciliation_fresh = reconciliation_age <= max(self.reconciliation_interval_s * 3, 60)
        try:
            database_healthy = self.journal.health_check()
        except Exception as exc:  # noqa: BLE001
            logger.exception("数据库健康检查失败: %s", exc)
            database_healthy = False
        self._observe_database_health(database_healthy)
        # 对账陈旧会关闭 READY/新增风险，但不能触发 systemd 重启风暴：
        # HALTED/网络隔离时进程仍须存活以维护保护单、退出与控制面。
        projection_healthy = self.execution.projection_healthy
        live = database_healthy and core_threads_healthy and projection_healthy
        return live, {
            "live": live,
            # Canary activation is intentionally generated only after the
            # restarted safety kernel is observable.  Expose the ephemeral
            # binding on /healthz (not only /readyz, which must remain 503
            # while the activation hold is in force).
            "mode": mode.value,
            "runtime_instance_id": self.runtime_instance_id,
            "runtime_started_at": self.runtime_started_at,
            "boot_id": self.runtime_boot_id,
            "account_uid": self.expected_account_id,
            "deployment_unit": self.deployment_unit,
            "soak_epoch_id": self.soak_epoch_id,
            "canary_transition_sha256": self.canary_transition_sha256,
            "canary_policy_sha256": self.canary_policy_sha256,
            "canary_target_deployment_identity_sha256": self.canary_target_sha256,
            "canary_activation_consumed": (self._canary_activation_consumed),
            "canary_startup_hard_epoch": (self._canary_startup_hard_epoch),
            "canary_startup_nonce": self._canary_startup_nonce,
            "canary_startup_latch_reason": (self._canary_startup_latch_reason),
            "release_identity": self.release_identity,
            "config_identity": self.production_config_hash,
            "database_healthy": database_healthy,
            "order_projection_healthy": projection_healthy,
            "core_threads": thread_alive,
            "safety_loop_age_seconds": safety_age,
            "safety_loop_fresh": safety_fresh,
            "reconciliation_age_seconds": reconciliation_age,
            "reconciliation_fresh": reconciliation_fresh,
        }

    def _observe_database_health(self, healthy: bool) -> None:
        if healthy:
            self._consecutive_database_errors = 0
            self.metrics.set(
                "consecutive_infrastructure_errors",
                0,
                source="database",
            )
            return
        self._consecutive_database_errors += 1
        self.metrics.set(
            "consecutive_infrastructure_errors",
            self._consecutive_database_errors,
            source="database",
        )
        if self._consecutive_database_errors != self.max_consecutive_infrastructure_errors:
            return
        try:
            self._latch_halted()
            self.journal.enqueue_outbox(
                "page.database_error_budget_exhausted",
                {
                    "consecutive_errors": (self._consecutive_database_errors),
                },
            )
        except Exception as exc:  # noqa: BLE001
            # 数据库故障可能阻止持久化锁停/告警；必须留下独立进程日志，
            # 而 liveness=False 会阻止 READY 并触发外部 watchdog。
            logger.critical(
                "数据库错误预算耗尽且无法持久化 HALTED: %s",
                exc,
            )

    def _observe_database_write(
        self,
        successful: bool,
        error: BaseException | None,
    ) -> None:
        if successful:
            if self._handling_database_write_failure:
                return
            self._consecutive_database_write_errors = 0
            self.metrics.set(
                "consecutive_infrastructure_errors",
                0,
                source="database_write",
            )
            return
        self._consecutive_database_write_errors += 1
        self.metrics.set(
            "consecutive_infrastructure_errors",
            self._consecutive_database_write_errors,
            source="database_write",
        )
        if (
            self._consecutive_database_write_errors < self.max_consecutive_infrastructure_errors
            or self._handling_database_write_failure
        ):
            return
        self._handling_database_write_failure = True
        exhausted_count = self._consecutive_database_write_errors
        try:
            self._latch_halted()
            self.journal.enqueue_outbox(
                "page.database_write_error_budget_exhausted",
                {
                    "consecutive_errors": (exhausted_count),
                    "error": str(error),
                },
            )
        except Exception as halt_error:  # noqa: BLE001
            logger.critical(
                "数据库写错误预算耗尽且无法持久化 HALTED: %s",
                halt_error,
            )
        finally:
            self._handling_database_write_failure = False

    def _safety_loop(self) -> None:
        interval = min(max(self.max_unprotected_position_s / 4, 0.25), 1)
        while not self._stop_event.wait(interval):
            try:
                self._enforce_unprotected_deadline()
                self._enforce_entry_authorization()
                self._enforce_account_writer_lease()
                self._enforce_backup_entry_rpo()
                self._enforce_canary_activation()
            except Exception as exc:  # noqa: BLE001
                logger.exception("持仓安全 watchdog 失败: %s", exc)
                self._latch_halted()
                self.journal.enqueue_outbox(
                    "page.position_safety_watchdog_failed",
                    {"error": str(exc)},
                )
            finally:
                self._last_safety_completed_monotonic = time.monotonic()

    def _backup_receipt_loop(self) -> None:
        """Isolate filesystem/signature I/O from the position deadline loop."""
        while not self._stop_event.wait(1):
            try:
                self._ingest_backup_receipt()
            except Exception as exc:  # pragma: no cover - final containment
                logger.exception("backup receipt ingestion 线程失败: %s", exc)

    def _enforce_account_writer_lease(self) -> None:
        if (
            self.account_lease is None
            or self.account_lease.valid()
            or self._account_lease_breach_reported
        ):
            return
        self._account_lease_breach_reported = True
        self._latch_halted(reason="account_writer_lease_lost")
        self.journal.record_event(
            "account_writer_lease_lost",
            severity="critical",
            payload={
                "account_id": self.expected_account_id,
                "last_error": self.account_lease.last_error,
            },
        )
        self.journal.enqueue_outbox(
            "page.account_writer_lease_lost",
            {
                "account_id": self.expected_account_id,
                "last_error": self.account_lease.last_error,
            },
        )

    def _assert_account_writer_transport_guard(
        self,
        _method: str,
        _endpoint: str,
    ) -> None:
        """所有交易写在 socket write 紧前执行的协调租约门禁。"""
        lease = self.account_lease
        if (
            lease is None
            or (
                lease.valid()
                and lease.fencing_identity() is not None
            )
        ):
            return
        raise RuntimeError(
            "account coordination lease 在 transport boundary 已失效"
        )

    def _deny_shadow_transport_write(
        self,
        method: str,
        endpoint: str,
    ) -> None:
        """Persist an attempted Shadow write and deny it before socket I/O."""
        self._shadow_write_attempt_count += 1
        payload = {
            "method": method,
            "endpoint": endpoint,
            "attempt_count": self._shadow_write_attempt_count,
            "account_uid": self.expected_account_id,
            "deployment_unit": self.deployment_unit,
            "soak_epoch_id": self.soak_epoch_id,
            "runtime_instance_id": self.runtime_instance_id,
            "boot_id": self.runtime_boot_id,
        }
        self.metrics.inc(
            "shadow_write_endpoint_attempts_total",
            method=method,
            endpoint=endpoint,
        )
        try:
            self.journal.record_event(
                "shadow_write_endpoint_attempt",
                severity="critical",
                correlation_id=self.runtime_instance_id,
                payload=payload,
            )
            self.journal.set_mode(SystemMode.HALTED)
            self.journal.enqueue_outbox_once(
                (
                    "shadow-write:"
                    f"{self.expected_account_id}:"
                    f"{self.runtime_boot_id}:"
                    f"{self.runtime_instance_id}"
                ),
                "page.shadow_write_endpoint_attempt",
                payload,
            )
        finally:
            raise PermissionError(
                f"Shadow transport deny: {method} {endpoint}"
            )

    def _enforce_unprotected_deadline(
        self,
        *,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        live_instruments: set[str] = set()
        for row in self.journal.list_positions():
            inst_id = row["inst_id"]
            qty = to_decimal(row["base_qty"])
            if qty <= 0:
                continue
            live_instruments.add(inst_id)
            if self._position_fully_protected_from_journal(inst_id, qty):
                self._unprotected_since.pop(inst_id, None)
                self._unprotected_deadline_reported.discard(inst_id)
                continue
            mark = self._fresh_valid_mark_for_dust(inst_id)
            if mark is not None and qty * mark < self.reconciler.dust_usdt:
                self._unprotected_since.pop(inst_id, None)
                self._unprotected_deadline_reported.discard(inst_id)
                self.metrics.set(
                    "unprotected_position_seconds",
                    0,
                    inst=inst_id,
                )
                continue
            first_detection = inst_id not in self._unprotected_since
            started = self._unprotected_since.setdefault(inst_id, now)
            age = max(now - started, 0)
            self.metrics.set(
                "unprotected_position_seconds",
                age,
                inst=inst_id,
            )
            if first_detection:
                # 不变量要求非 dust 仓位必须有保护或处于 emergency。
                # 首次发现立即锁存并 Page；deadline 只决定何时强制平仓。
                self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
                self.journal.enqueue_outbox(
                    "page.unprotected_position_detected",
                    {
                        "inst_id": inst_id,
                        "qty": str(qty),
                        "age_seconds": 0,
                    },
                )
            if (
                age < self.max_unprotected_position_s
                or inst_id in self._unprotected_deadline_reported
            ):
                continue
            self._unprotected_deadline_reported.add(inst_id)
            self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
            self.journal.enqueue_outbox(
                "page.unprotected_position_deadline",
                {
                    "inst_id": inst_id,
                    "qty": str(qty),
                    "age_seconds": age,
                },
            )
            self._schedule_emergency_exit(inst_id)
        for inst_id in set(self._unprotected_since) - live_instruments:
            self._unprotected_since.pop(inst_id, None)
            self._unprotected_deadline_reported.discard(inst_id)

    def _position_fully_protected_from_journal(
        self,
        inst_id: str,
        qty: Decimal,
    ) -> bool:
        """安全 loop 只读 durable projection，不为余量判断发起 REST。"""
        protections = self.journal.list_protections(
            inst_id,
            active_only=True,
        )
        return bool(
            len(protections) == 1
            and protections[0].state is ProtectionState.ACTIVE
            and protections[0].protected_qty == qty
        )

    def _fresh_valid_mark_for_dust(self, inst_id: str) -> Decimal | None:
        """只读有年龄上限的 WS 本地 ticker；缺失时保守视为非 dust。"""
        with self._ws_state_lock:
            snapshot = self._public_ticker_cache.get(inst_id)
        if snapshot is None:
            return None
        last, bid, ask, source_timestamp, observed_at = snapshot
        now = time.time()
        if (
            not last.is_finite()
            or not bid.is_finite()
            or not ask.is_finite()
            or last <= 0
            or bid <= 0
            or ask <= 0
            or ask < bid
            or not math.isfinite(source_timestamp)
            or not math.isfinite(observed_at)
            or now - source_timestamp > self.max_market_data_age_s
            or source_timestamp - now > self.max_market_data_age_s
            or now - observed_at > self.max_market_data_age_s
            or observed_at - now > self.max_market_data_age_s
        ):
            return None
        return last

    def _schedule_emergency_exit(self, inst_id: str) -> None:
        """去重投递退出 worker；safety loop 本身绝不等待交易所网络。"""
        with self._emergency_exit_lock:
            existing = self._emergency_exit_tasks.get(inst_id)
            if existing is not None and existing.is_alive():
                return
            worker = threading.Thread(
                target=self._run_emergency_exit,
                args=(inst_id,),
                name=f"emergency-exit-{inst_id}",
                daemon=True,
            )
            self._emergency_exit_tasks[inst_id] = worker
            try:
                worker.start()
            except BaseException:
                self._emergency_exit_tasks.pop(inst_id, None)
                self._unprotected_deadline_reported.discard(inst_id)
                raise

    def _run_emergency_exit(self, inst_id: str) -> None:
        try:
            intent = self.exit.exit_position(
                inst_id,
                "unprotected position deadline",
            )
            if intent is None or intent.state is not OrderState.FILLED:
                state = intent.state.value if intent is not None else "none"
                raise RuntimeError(f"紧急退出未确认 FILLED，state={state}")
        except Exception as exc:  # noqa: BLE001
            # REJECTED/CANCELED 不是成功退出；清除 marker，让 watchdog
            # 后续继续尝试，而不是永久压制重试。
            self._unprotected_deadline_reported.discard(inst_id)
            try:
                self.journal.enqueue_outbox(
                    "page.emergency_exit_failed",
                    {
                        "inst_id": inst_id,
                        "error": str(exc),
                    },
                )
            except Exception:  # pragma: no cover - final containment
                logger.critical(
                    "紧急退出失败且无法持久化 Page: %s",
                    inst_id,
                    exc_info=True,
                )
        finally:
            with self._emergency_exit_lock:
                current = self._emergency_exit_tasks.get(inst_id)
                if current is threading.current_thread():
                    self._emergency_exit_tasks.pop(inst_id, None)

    def _update_metrics(self) -> None:
        mode = self.journal.get_mode()
        sampled_at = time.time()
        if sampled_at - self._last_slo_heartbeat_at >= 5:
            self.journal.record_event(
                "runtime_heartbeat_sample",
                payload={
                    "healthy": True,
                    "mode": mode.value,
                    "pid": os.getpid(),
                    "boot_id": self.runtime_boot_id,
                    "runtime_instance_id": self.runtime_instance_id,
                    "account_uid": self.expected_account_id,
                    "deployment_unit": self.deployment_unit,
                    "soak_epoch_id": self.soak_epoch_id,
                    "shadow_mode": self.shadow_mode,
                    "shadow_write_attempt_count": (
                        self._shadow_write_attempt_count
                    ),
                },
            )
            self._last_slo_heartbeat_at = sampled_at
        for candidate in SystemMode:
            self.metrics.set(
                "system_mode",
                1 if candidate is mode else 0,
                mode=candidate.value,
            )
        state_counts = self.journal.intent_state_counts()
        for state, count in state_counts.items():
            self.metrics.set("order_intents", count, state=state)
        unknown = state_counts.get("unknown", 0)
        self.metrics.set("unknown_orders_total", unknown)
        unknown_buys = [
            intent
            for intent in self.journal.list_nonterminal_intents()
            if intent.side == "buy" and intent.state is OrderState.UNKNOWN
        ]
        self.metrics.set(
            "unknown_buy_oldest_age_seconds",
            max(
                (max(time.time() - intent.updated_at, 0) for intent in unknown_buys),
                default=0,
            ),
        )
        snapshot = self.journal.latest_account_snapshot()
        age = max(time.time() - float(snapshot["captured_at"]), 0) if snapshot else float("inf")
        self.metrics.set("account_snapshot_age_seconds", age)
        self.metrics.set(
            "account_snapshot_max_age_seconds",
            self.limits.max_account_snapshot_age_s,
        )
        if age > self.limits.max_account_snapshot_age_s:
            self.journal.enqueue_outbox_once(
                f"warning:snapshot-stale:{int(time.time() // 300)}",
                "warning.account_snapshot_stale",
                {
                    "age_seconds": age,
                    "limit_seconds": (self.limits.max_account_snapshot_age_s),
                },
            )
        elif age >= self.limits.max_account_snapshot_age_s * 0.80:
            self.journal.enqueue_outbox_once(
                f"warning:snapshot-near-stale:{int(time.time() // 300)}",
                "warning.account_snapshot_near_stale",
                {
                    "age_seconds": age,
                    "limit_seconds": (
                        self.limits.max_account_snapshot_age_s
                    ),
                    "warning_ratio": 0.80,
                },
            )
        for channel, inst_id in sorted(
            self._required_public_market_channels
        ):
            observed_at = self._public_market_last_event_at.get(
                (channel, inst_id),
                0,
            )
            market_age = (
                max(sampled_at - observed_at, 0)
                if observed_at
                else float("inf")
            )
            self.metrics.set(
                "market_data_age_seconds",
                market_age,
                channel=channel,
                inst=inst_id,
            )
            self.metrics.set(
                "market_data_max_age_seconds",
                self.max_market_data_age_s,
                channel=channel,
                inst=inst_id,
            )
            if market_age >= self.max_market_data_age_s * 0.80:
                self.journal.enqueue_outbox_once(
                    (
                        "warning:market-data-near-stale:"
                        f"{channel}:{inst_id}:"
                        f"{int(sampled_at // 300)}"
                    ),
                    "warning.market_data_near_stale",
                    {
                        "channel": channel,
                        "inst_id": inst_id,
                        "age_seconds": market_age,
                        "limit_seconds": self.max_market_data_age_s,
                        "warning_ratio": 0.80,
                    },
                )
        unpublished = self.journal.get_unpublished_outbox()
        oldest_alert_age = (
            max(time.time() - float(unpublished[0]["created_at"]), 0) if unpublished else 0
        )
        self.metrics.set("alert_outbox_pending", len(unpublished))
        self.metrics.set("alert_outbox_oldest_age_seconds", oldest_alert_age)
        self.metrics.set(
            "alert_delivery_consecutive_failures",
            self.alerts.consecutive_failures,
        )
        self.metrics.set(
            "alert_last_success_age_seconds",
            (
                max(time.time() - self.alerts.last_success_at, 0)
                if self.alerts.last_success_at
                else float("inf")
            ),
        )
        backup_samples = self.journal.list_events("backup_slo_sample")
        if backup_samples:
            backup_payload = backup_samples[-1]["payload"]
            snapshot_completed_at = float(backup_payload.get("snapshot_completed_at", 0))
            recovery_point_age = max(
                time.time() - snapshot_completed_at,
                0,
            )
            backup_ok = (
                backup_payload.get("integrity") == "ok"
                and bool(backup_payload.get("version_id"))
                and backup_payload.get("offsite_readback_at") is not None
            )
        else:
            recovery_point_age = float("inf")
            backup_ok = False
        self.metrics.set(
            "backup_recovery_point_age_seconds",
            recovery_point_age,
            location="local",
        )
        self.metrics.set(
            "backup_recovery_point_age_seconds",
            recovery_point_age,
            location="offsite",
        )
        self.metrics.set("backup_last_verification_ok", float(backup_ok))
        for row in self.journal.list_positions():
            inst_id = row["inst_id"]
            try:
                price = to_decimal(self.exchange.get_ticker(inst_id).last)
            except Exception:  # noqa: BLE001
                price = Decimal("0")
            qty = to_decimal(row["base_qty"])
            self.metrics.set(
                "position_notional_usdt",
                float(qty * price),
                inst=inst_id,
            )
            protected = self.reconciler.position_safely_protected(
                inst_id,
                qty,
            )
            unprotected_since = self._unprotected_since.get(inst_id)
            self.metrics.set(
                "unprotected_position_seconds",
                (
                    0
                    if protected or unprotected_since is None
                    else max(time.time() - unprotected_since, 0)
                ),
                inst=inst_id,
            )
        positions = self.journal.list_positions()
        self.metrics.set(
            "daily_realized_pnl",
            float(
                sum(
                    (to_decimal(row["realized_pnl"]) for row in positions),
                    Decimal("0"),
                )
            ),
        )
        equities = self.journal.account_equities_since(time.time() - 86400)
        drawdown = 0.0
        if equities:
            peak = max(equities)
            if peak > 0:
                drawdown = float((peak - equities[-1]) / peak)
        self.metrics.set("current_drawdown_ratio", drawdown)
        if self.websocket:
            channels = ["private", "business"]
            if self.websocket.public_required:
                channels.append("public")
            for channel in channels:
                self.metrics.set(
                    "ws_connected",
                    1 if self.websocket.connection_state(channel) is ConnectionState.READY else 0,
                    channel=channel,
                )
                self.metrics.set(
                    "ws_last_message_age_seconds",
                    self.websocket.last_message_age(channel),
                    channel=channel,
                )

    @staticmethod
    def _timestamp_seconds(value) -> float:
        if hasattr(value, "timestamp"):
            return float(value.timestamp())
        text = str(value)
        try:
            numeric = float(text)
            return numeric / 1000 if numeric > 10_000_000_000 else numeric
        except ValueError:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.timestamp()

    @staticmethod
    def _bar_seconds(bar: str) -> int:
        units = {
            "m": 60,
            "H": 3600,
            "D": 86400,
            "W": 604800,
        }
        if len(bar) < 2 or bar[-1] not in units:
            raise ValueError(f"非法 K 线周期: {bar}")
        return int(bar[:-1]) * units[bar[-1]]

    @staticmethod
    def config_hash(config: dict) -> str:
        safe = json.dumps(
            config,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
        return hashlib.sha256(safe).hexdigest()
