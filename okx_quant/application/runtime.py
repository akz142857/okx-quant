"""生产交易运行时：恢复门禁、单写者、WS 基线与周期对账。"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import math
import sqlite3
import threading
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING

from okx_quant.application.approval import ResumeApprovalVerifier
from okx_quant.application.execution import ExecutionCoordinator
from okx_quant.application.protection import ExitCoordinator, ProtectionManager
from okx_quant.application.reconciliation import (
    Reconciler,
    ReconciliationResult,
    RecoveryGate,
    fresh_valid_mark_for_dust,
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
        backup_interval_s: float = 300,
        backup_retention_days: int = 30,
        offsite_backup_uri: str = "",
        alert_webhook_url: str = "",
        metrics_host: str = "",
        metrics_port: int = 9108,
        expected_account_id: str = "",
        approval_public_key: str | Path = "",
        production_config_hash: str = "",
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
        self.production_config_hash = production_config_hash
        self.approval_verifier = (
            ResumeApprovalVerifier(approval_public_key)
            if approval_public_key
            else None
        )
        self._ws_generation = 0
        self.max_unprotected_position_s = max_unprotected_position_s
        self.max_consecutive_infrastructure_errors = (
            max_consecutive_infrastructure_errors
        )
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
            raise ValueError(
                "max_consecutive_infrastructure_errors 必须在 1..5"
            )
        self._consecutive_api_errors = 0
        self._consecutive_ws_errors = 0
        self._consecutive_database_errors = 0
        self._consecutive_database_write_errors = 0
        self._handling_database_write_failure = False
        self._unprotected_since: dict[str, float] = {}
        self._unprotected_deadline_reported: set[str] = set()
        self._required_public_market_channels: set[tuple[str, str]] = set()
        self._public_market_last_event_at: dict[tuple[str, str], float] = {}
        self.max_market_data_age_s = limits.max_market_data_age_s
        self.max_candle_range_ratio = limits.max_candle_range_ratio
        self.risk_service = ProductionRiskService(
            exchange, journal, limits, metrics=self.metrics
        )
        self.execution = ExecutionCoordinator(
            exchange,
            journal,
            pre_trade_check=self.risk_service.check,
            shadow_mode=self.shadow_mode,
            max_slippage_ratio=limits.max_slippage_ratio,
            operation_lock=self.operation_lock,
            entry_guard=self._entry_guard,
            atomic_risk_guard=self.risk_service.atomic_guard,
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
        self._started = False
        self._last_reconciliation_completed_at = 0.0
        self._last_reconciliation_incident = ""
        self._reconnect_lock = threading.Lock()
        self._ws_state_lock = threading.RLock()
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
            self.protection.process_algo_events(rows)

    def _observe_api_request(
        self, endpoint: str, code: str, latency_s: float
    ) -> None:
        self.metrics.inc(
            "okx_api_requests_total", endpoint=endpoint, code=code
        )
        self.metrics.set(
            "okx_api_latency_seconds", latency_s, endpoint=endpoint
        )
        successful = code == "OKX:0" or (
            code.isdigit() and 200 <= int(code) < 400
        )
        if successful:
            self._consecutive_api_errors = 0
            return
        self._consecutive_api_errors += 1
        self.journal.enqueue_outbox_once(
            (
                f"warning:api:{endpoint}:{code}:"
                f"{int(time.time() // 300)}"
            ),
            "warning.api_error_rate_elevated",
            {
                "endpoint": endpoint,
                "code": code,
                "consecutive_errors": self._consecutive_api_errors,
            },
        )
        self.metrics.set(
            "consecutive_infrastructure_errors",
            self._consecutive_api_errors,
            source="api",
        )
        if (
            self._consecutive_api_errors
            == self.max_consecutive_infrastructure_errors
        ):
            self._latch_halted()
            self.journal.enqueue_outbox(
                "page.api_error_budget_exhausted",
                {
                    "endpoint": endpoint,
                    "code": code,
                    "consecutive_errors": self._consecutive_api_errors,
                },
            )

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
                self.journal.record_event(
                    "execution_slippage_sample",
                    correlation_id=intent.intent_id,
                    payload={
                        "inst_id": intent.inst_id,
                        "side": intent.side,
                        "reference_price": str(reference),
                        "fill_price": str(actual),
                        "adverse_slippage_ratio": str(
                            adverse_slippage
                        ),
                    },
                )
                if (
                    adverse_slippage
                    > self.limits.max_slippage_ratio
                ):
                    self.journal.enqueue_outbox_once(
                        f"warning:slippage:{intent.intent_id}",
                        "warning.execution_slippage_exceeded",
                        {
                            "intent_id": intent.intent_id,
                            "inst_id": intent.inst_id,
                            "observed_ratio": str(adverse_slippage),
                            "approved_ratio": str(
                                self.limits.max_slippage_ratio
                            ),
                        },
                    )
        if intent.side == "buy" and delta > 0:
            active = [
                protection
                for protection in self.journal.list_protections(
                    intent.inst_id
                )
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
        stream_ready = (
            (self.streams is None or self.streams.ready)
            and self._public_market_ready()
        )
        return (
            not self.safety_only
            and self.journal.get_mode() is SystemMode.READY
            and stream_ready
        )

    @property
    def safety_only(self) -> bool:
        """Immutable deployment-admission state for this runtime instance."""
        return self._safety_only

    def _latch_halted(self) -> SystemMode:
        """Tighten ordinary modes without weakening an existing hard-safe mode."""
        current = self.journal.get_mode()
        if current in {
            SystemMode.HALTED,
            SystemMode.EMERGENCY_EXIT,
            SystemMode.MAINTENANCE,
        }:
            return current
        self.journal.set_mode(SystemMode.HALTED)
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
            self._required_public_market_channels.update({
                ("ticker", inst_id),
                ("candle", inst_id),
            })
            self.websocket.subscribe_ticker(
                inst_id,
                lambda rows, current=inst_id: self._on_public_market_event(
                    "ticker", current, rows
                ),
            )
            self.websocket.subscribe_candle(
                inst_id,
                bar,
                lambda rows, current=inst_id: self._on_public_market_event(
                    "candle", current, rows
                ),
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
        self._public_market_last_event_at[(channel, inst_id)] = observed_at
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
        private_ready = (
            self.streams is None or self.streams.transport_ready
        )
        return private_ready and self._public_market_ready()

    def start(self) -> None:
        if self._started:
            return
        self.lock.acquire()
        try:
            hard_modes = {
                SystemMode.HALTED,
                SystemMode.EMERGENCY_EXIT,
                SystemMode.MAINTENANCE,
            }
            if self.safety_only:
                latched_mode = self._latch_halted()
            else:
                latched_mode = (
                    self.journal.get_mode()
                    if self.journal.get_mode() in hard_modes
                    else None
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
                while (
                    time.monotonic() < deadline
                    and not self._all_ws_transport_ready()
                ):
                    time.sleep(0.05)
                if not self._all_ws_transport_ready():
                    raise RuntimeError(
                        "WebSocket 未在门限内确认 private/business/public 订阅"
                    )
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
                            (
                                lambda: self.journal.set_mode(
                                    SystemMode.READY
                                )
                            )
                            if latched_mode is None
                            else None,
                        )
                    ):
                        raise RuntimeError("私有 WebSocket/REST baseline 建立期间发生变化")
            startup_reconciliation_duration = (
                time.monotonic() - startup_reconciliation_started
            )
            self.metrics.observe(
                "startup_reconciliation_duration_seconds",
                startup_reconciliation_duration,
                buckets=(1, 3, 5, 10, 20, 30, 60),
            )
            self.journal.record_event(
                "startup_reconciliation_slo_sample",
                payload={
                    "duration_seconds": startup_reconciliation_duration,
                    "within_60_seconds": (
                        startup_reconciliation_duration <= 60
                    ),
                },
            )
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
            self.alerts.start()
            if self.backups:
                self.backups.backup_once()
                self.backups.start()
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
            self.alerts.stop()
            if self.heartbeat:
                self.heartbeat.stop()
            if self.streams is not None:
                self.streams.stop()
            self.execution.stop()
            if self._safety_thread:
                self._safety_thread.join(timeout=5)
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
        if self.metrics_server:
            self.metrics_server.stop()
        if self.backups:
            self.backups.stop()
        self.alerts.stop()
        if self.heartbeat:
            self.heartbeat.stop()
        if self.streams is not None:
            self.streams.stop()
        self.execution.stop()
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
        risk.add_position(PositionInfo(
            inst_id=inst_id,
            size=float(qty),
            entry_price=float(to_decimal(row["avg_entry_px"])),
            stop_loss=stop,
            take_profit=take,
        ))

    def _sync_all_risk_managers(self) -> None:
        local_ids = {row["inst_id"] for row in self.journal.list_positions()}
        for risk in self._risk_managers.values():
            all_ids = local_ids | {p.inst_id for p in risk.list_positions()}
            for inst_id in all_ids:
                self._sync_risk_for_inst(risk, inst_id)

    def has_processed_candle(
        self, strategy_instance_id: str, inst_id: str, candle_ts: str
    ) -> bool:
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
            (
                f"strategy-warning:{strategy_version}:{inst_id}:"
                f"{warning_kind}:{bucket}"
            ),
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
        if self.journal.has_decision(
            strategy_instance_id, inst_id, str(candle_ts)
        ):
            return False, "K 线已处理"
        ts = self._timestamp_seconds(candle_ts)
        interval = self._bar_seconds(bar)
        market_valid, market_reason, unsafe_data = (
            self._validate_signal_market_data(
                market_data,
                interval=interval,
                candle_ts=ts,
            )
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
        previous_raw = self.journal.get_candle_watermark(
            strategy_instance_id, inst_id, bar
        )
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
            for row in market_data[
                ["ts", "open", "high", "low", "close"]
            ].itertuples(index=False, name=None):
                row_ts = self._timestamp_seconds(row[0])
                prices = [float(value) for value in row[1:]]
                if (
                    not math.isfinite(row_ts)
                    or not all(math.isfinite(value) for value in prices)
                ):
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
        range_ratio = (
            to_decimal(last["high"]) - to_decimal(last["low"])
        ) / to_decimal(last["close"])
        if (
            not range_ratio.is_finite()
            or range_ratio > self.max_candle_range_ratio
        ):
            return False, "K 线波动率超过信号门槛", False
        return True, "通过", False

    def mark_candle_processed(
        self,
        strategy_instance_id: str,
        inst_id: str,
        bar: str,
        candle_ts,
    ) -> None:
        self.journal.set_candle_watermark(
            strategy_instance_id, inst_id, bar, str(candle_ts)
        )

    def backup(self, destination: str | Path) -> None:
        self.journal.backup(destination)

    def _check_clock(self) -> None:
        server_time = self.exchange.get_server_time()
        skew = abs(time.time() - server_time)
        if skew > self.max_clock_skew_s:
            raise RuntimeError(
                f"本机与 OKX 时间偏差 {skew:.3f}s，超过 {self.max_clock_skew_s}s"
            )

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
        with self._ws_state_lock:
            baseline_generation = self._ws_generation
            baseline_event_sequence = (
                self.streams.event_sequence
                if self.streams is not None
                else 0
            )
        result = self.reconciler.run(manage_mode=False)
        self._last_reconciliation_completed_at = time.time()
        self._sync_all_risk_managers()
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
        self.risk_service.enforce_account_hard_limits()
        with self._ws_state_lock:
            fence_changed = self._ws_generation != baseline_generation
            if not fence_changed and self.streams is not None:
                fence_intact, _ = self.streams.run_if_baseline_current(
                    baseline_event_sequence,
                    lambda: self._promote_ready_if_safe(True),
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

    def _on_ws_state(self, name: str, state: ConnectionState) -> None:
        if name not in {"public", "private", "business"}:
            return
        with self._ws_state_lock:
            self._ws_generation += 1
        if state in {
            ConnectionState.BACKOFF,
            ConnectionState.DISCONNECTED,
            ConnectionState.STALE,
        }:
            self._consecutive_ws_errors += 1
            self.journal.enqueue_outbox_once(
                (
                    f"warning:ws:{name}:{self._ws_generation}:"
                    f"{state.value}"
                ),
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
                if (
                    self._consecutive_ws_errors
                    >= self.max_consecutive_infrastructure_errors
                ):
                    self._latch_halted()
                else:
                    self.journal.set_mode(SystemMode.DEGRADED)
            self.metrics.set(
                "consecutive_infrastructure_errors",
                self._consecutive_ws_errors,
                source="ws",
            )
            if (
                self._consecutive_ws_errors
                == self.max_consecutive_infrastructure_errors
            ):
                self.journal.enqueue_outbox(
                    "page.ws_error_budget_exhausted",
                    {
                        "channel": name,
                        "state": state.value,
                        "consecutive_errors": self._consecutive_ws_errors,
                    },
                )
            return
        if (
            state is ConnectionState.READY
            and self.websocket
            and self._all_ws_transport_ready()
        ):
            self._consecutive_ws_errors = 0
            threading.Thread(
                target=self._restore_after_reconnect,
                name="ws-reconnect-recovery",
                daemon=True,
            ).start()

    def _control_loop(self) -> None:
        while not self._stop_event.wait(0.5):
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
                    self.journal.finish_control_command(
                        command_id, success=True, result=result
                    )
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
            raise RuntimeError(
                "生产准入未授权：safety-only 运行时永久拒绝恢复新增风险"
            )
        current, hard_epoch = self.journal.get_mode_state()
        if current not in {
            SystemMode.HALTED,
            SystemMode.MAINTENANCE,
        }:
            raise RuntimeError(
                f"只有 HALTED/MAINTENANCE 可受控恢复，当前为 {current.value}"
            )
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
            and self.alerts.consecutive_failures
            >= self.max_consecutive_infrastructure_errors
        ):
            raise RuntimeError("告警投递链不健康，禁止恢复新增风险")
        if self.alerts.webhook_url:
            self.alerts.verify_delivery({
                "command_id": command_id,
                "account_id": self.expected_account_id,
                "config_hash": self.production_config_hash,
                "actor": actor,
                "risk_approver": approver,
            })

        self._check_clock()
        self._check_account_identity()
        baseline_generation = self._ws_generation
        baseline_event_sequence = (
            self.streams.event_sequence if self.streams is not None else 0
        )
        outcome = self.reconciler.run(manage_mode=False)
        self._last_reconciliation_completed_at = time.time()
        self._sync_all_risk_managers()
        if not outcome.safe:
            raise RuntimeError(
                "恢复前联合对账未通过: "
                + ", ".join(outcome.unresolved)
            )
        with self._ws_state_lock:
            if self._ws_generation != baseline_generation:
                raise RuntimeError("恢复检查期间私有 WS connection generation 发生变化")
            if self.streams is not None:
                fence_intact, changed_raw = (
                    self.streams.run_if_baseline_current(
                        baseline_event_sequence,
                        lambda: self.journal.set_mode(
                            SystemMode.READY,
                            allow_hard_release=True,
                            expected_hard_epoch=hard_epoch,
                        ),
                    )
                )
                if not fence_intact:
                    raise RuntimeError(
                        "恢复检查期间私有 WS baseline/事件序列发生变化"
                    )
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
            for holding in preflight_balance.non_quote_holdings(
                self.exchange.quote_ccy
            )
            if to_decimal(holding.balance) > 0
        }
        known.update(order.inst_id for order in preflight_pending)
        known.update(algo.inst_id for algo in preflight_algos)
        known.update(
            row["inst_id"] for row in self.journal.list_positions()
        )
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
                for holding in latest_balance.non_quote_holdings(
                    self.exchange.quote_ccy
                )
                if to_decimal(holding.balance) > 0
            }
            targets.update(
                order.inst_id for order in self.exchange.get_pending_orders()
            )
            targets.update(
                algo.inst_id
                for algo in self.exchange.get_pending_algo_orders()
            )
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
                for holding in balance.non_quote_holdings(
                    self.exchange.quote_ccy
                )
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
                remaining.append(
                    f"{algo.inst_id}:pending_algo={algo.algo_id}"
                )
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
                    return result
        except Exception as exc:  # noqa: BLE001
            logger.error("WS 重连后 REST baseline 失败: %s", exc)
        finally:
            self._reconnect_lock.release()
        return None

    def _promote_ready_if_safe(self, safe: bool) -> bool:
        if not safe or self.safety_only:
            return False
        with self._ws_state_lock:
            if (
                self.alerts.webhook_url
                and self.alerts.consecutive_failures
                >= self.max_consecutive_infrastructure_errors
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
        stream_ready = (
            (self.streams is None or self.streams.ready)
            and public_market_ready
        )
        live, liveness = self._liveness()
        alert_delivery_healthy = (
            not self.alerts.webhook_url
            or self.alerts.consecutive_failures
            < self.max_consecutive_infrastructure_errors
        )
        ok = (
            not self.safety_only
            and mode is SystemMode.READY
            and stream_ready
            and alert_delivery_healthy
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
            **liveness,
        }

    def _entry_ready(self) -> bool:
        return self._health()[0]

    def _entry_guard(self) -> tuple[bool, object]:
        with self._ws_state_lock:
            event_sequence = (
                self.streams.event_sequence if self.streams is not None else 0
            )
            return (
                self._entry_ready(),
                (self._ws_generation, event_sequence),
            )

    def _liveness(self) -> tuple[bool, dict]:
        """systemd watchdog 的进程活性；HALTED/DEGRADED 仍可健康存活。"""
        threads = {
            "execution": self.execution._thread,
            "reconciliation": self._reconcile_thread,
            "control": self._control_thread,
            "alerts": self.alerts._thread,
            "safety": self._safety_thread,
        }
        if self.backups is not None:
            threads["backup"] = self.backups._thread
        if self.websocket is not None:
            threads["websocket"] = self.websocket._thread
        thread_alive = {
            name: thread is not None and thread.is_alive()
            for name, thread in threads.items()
        }
        # 构造完成但尚未 start 时供诊断使用；Heartbeat 只在全部线程启动后运行。
        core_threads_healthy = (
            all(thread_alive.values()) if self._started or self.heartbeat else True
        )
        reconciliation_age = (
            max(time.time() - self._last_reconciliation_completed_at, 0)
            if self._last_reconciliation_completed_at
            else float("inf")
        )
        reconciliation_fresh = (
            reconciliation_age
            <= max(self.reconciliation_interval_s * 3, 60)
        )
        try:
            database_healthy = self.journal.health_check()
        except Exception as exc:  # noqa: BLE001
            logger.exception("数据库健康检查失败: %s", exc)
            database_healthy = False
        self._observe_database_health(database_healthy)
        # 对账陈旧会关闭 READY/新增风险，但不能触发 systemd 重启风暴：
        # HALTED/网络隔离时进程仍须存活以维护保护单、退出与控制面。
        projection_healthy = self.execution.projection_healthy
        live = (
            database_healthy
            and core_threads_healthy
            and projection_healthy
        )
        return live, {
            "live": live,
            "database_healthy": database_healthy,
            "order_projection_healthy": projection_healthy,
            "core_threads": thread_alive,
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
        if (
            self._consecutive_database_errors
            != self.max_consecutive_infrastructure_errors
        ):
            return
        try:
            self._latch_halted()
            self.journal.enqueue_outbox(
                "page.database_error_budget_exhausted",
                {
                    "consecutive_errors": (
                        self._consecutive_database_errors
                    ),
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
            self._consecutive_database_write_errors
            < self.max_consecutive_infrastructure_errors
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
                    "consecutive_errors": (
                        exhausted_count
                    ),
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
            except Exception as exc:  # noqa: BLE001
                logger.exception("持仓安全 watchdog 失败: %s", exc)
                self._latch_halted()
                self.journal.enqueue_outbox(
                    "page.position_safety_watchdog_failed",
                    {"error": str(exc)},
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
            live_instruments.add(inst_id)
            if self.reconciler.position_safely_protected(inst_id, qty):
                self._unprotected_since.pop(inst_id, None)
                self._unprotected_deadline_reported.discard(inst_id)
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
            try:
                intent = self.exit.exit_position(
                    inst_id,
                    "unprotected position deadline",
                )
                if intent is None or intent.state is not OrderState.FILLED:
                    state = intent.state.value if intent is not None else "none"
                    raise RuntimeError(
                        f"紧急退出未确认 FILLED，state={state}"
                    )
            except Exception as exc:
                # REJECTED/CANCELED 不是成功退出；清除 marker，让 watchdog
                # 后续继续尝试，而不是永久压制重试。
                self._unprotected_deadline_reported.discard(inst_id)
                self.journal.enqueue_outbox(
                    "page.emergency_exit_failed",
                    {
                        "inst_id": inst_id,
                        "error": str(exc),
                    },
                )
        for inst_id in set(self._unprotected_since) - live_instruments:
            self._unprotected_since.pop(inst_id, None)
            self._unprotected_deadline_reported.discard(inst_id)

    def _fresh_valid_mark_for_dust(self, inst_id: str) -> Decimal | None:
        """仅以新鲜、有限且 BBO 一致的事实证明仓位属于 dust。"""
        return fresh_valid_mark_for_dust(
            self.exchange,
            inst_id,
            max_age_s=self.max_market_data_age_s,
        )

    def _update_metrics(self) -> None:
        mode = self.journal.get_mode()
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
                (
                    max(time.time() - intent.updated_at, 0)
                    for intent in unknown_buys
                ),
                default=0,
            ),
        )
        snapshot = self.journal.latest_account_snapshot()
        age = (
            max(time.time() - float(snapshot["captured_at"]), 0)
            if snapshot
            else float("inf")
        )
        self.metrics.set("account_snapshot_age_seconds", age)
        if age > self.limits.max_account_snapshot_age_s:
            self.journal.enqueue_outbox_once(
                f"warning:snapshot-stale:{int(time.time() // 300)}",
                "warning.account_snapshot_stale",
                {
                    "age_seconds": age,
                    "limit_seconds": (
                        self.limits.max_account_snapshot_age_s
                    ),
                },
            )
        unpublished = self.journal.get_unpublished_outbox()
        oldest_alert_age = (
            max(time.time() - float(unpublished[0]["created_at"]), 0)
            if unpublished
            else 0
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
            float(sum(
                (to_decimal(row["realized_pnl"]) for row in positions),
                Decimal("0"),
            )),
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
                    1
                    if self.websocket.connection_state(channel)
                    is ConnectionState.READY
                    else 0,
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
