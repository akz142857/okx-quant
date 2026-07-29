"""SQLite WAL 订单日志和交易投影。

发送交易请求前，订单意图必须已经同步提交到此日志。
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import stat
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from okx_quant.domain.orders import (
    ExchangeOrder,
    Fill,
    IntentRiskGuard,
    OrderIntent,
    OrderState,
    SystemMode,
    parse_decimal_fact,
    to_decimal,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    strategy_instance_id TEXT NOT NULL,
    strategy_name TEXT NOT NULL,
    strategy_version TEXT NOT NULL DEFAULT '',
    inst_id TEXT NOT NULL,
    candle_ts TEXT NOT NULL,
    signal TEXT NOT NULL,
    requested_size_pct TEXT NOT NULL DEFAULT '0',
    reason TEXT NOT NULL DEFAULT '',
    inputs_hash TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    UNIQUE(strategy_instance_id, inst_id, candle_ts)
);

CREATE TABLE IF NOT EXISTS order_intents (
    intent_id TEXT PRIMARY KEY,
    cl_ord_id TEXT NOT NULL UNIQUE,
    decision_id TEXT,
    inst_id TEXT NOT NULL,
    side TEXT NOT NULL CHECK(side IN ('buy', 'sell')),
    requested_base_qty TEXT NOT NULL,
    reserved_quote TEXT NOT NULL DEFAULT '0',
    submission_reference_price TEXT NOT NULL DEFAULT '0',
    requested_stop_loss TEXT NOT NULL DEFAULT '0',
    requested_take_profit TEXT NOT NULL DEFAULT '0',
    state TEXT NOT NULL,
    exchange_ord_id TEXT UNIQUE,
    exchange_state TEXT NOT NULL DEFAULT '',
    acc_fill_qty TEXT NOT NULL DEFAULT '0',
    avg_fill_px TEXT NOT NULL DEFAULT '0',
    fee TEXT NOT NULL DEFAULT '0',
    fee_ccy TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'strategy',
    probe_id TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 0,
    last_error_code TEXT NOT NULL DEFAULT '',
    last_error_message TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY(decision_id) REFERENCES decisions(decision_id)
);
CREATE INDEX IF NOT EXISTS idx_order_intents_state_updated
    ON order_intents(state, updated_at);
CREATE INDEX IF NOT EXISTS idx_order_intents_inst_state
    ON order_intents(inst_id, state);

CREATE TABLE IF NOT EXISTS order_events (
    event_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL,
    state_from TEXT NOT NULL,
    state_to TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    FOREIGN KEY(intent_id) REFERENCES order_intents(intent_id)
);
CREATE INDEX IF NOT EXISTS idx_order_events_intent_created
    ON order_events(intent_id, created_at);

CREATE TABLE IF NOT EXISTS fills (
    fill_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL,
    exchange_ord_id TEXT NOT NULL,
    inst_id TEXT NOT NULL,
    side TEXT NOT NULL,
    fill_qty TEXT NOT NULL,
    fill_px TEXT NOT NULL,
    fee TEXT NOT NULL DEFAULT '0',
    fee_ccy TEXT NOT NULL DEFAULT '',
    trade_id TEXT NOT NULL DEFAULT '',
    exchange_ts REAL NOT NULL DEFAULT 0,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL,
    FOREIGN KEY(intent_id) REFERENCES order_intents(intent_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fills_trade
    ON fills(inst_id, trade_id) WHERE trade_id != '';

CREATE TABLE IF NOT EXISTS positions (
    inst_id TEXT PRIMARY KEY,
    base_qty TEXT NOT NULL DEFAULT '0',
    available_qty TEXT NOT NULL DEFAULT '0',
    avg_entry_px TEXT NOT NULL DEFAULT '0',
    realized_pnl TEXT NOT NULL DEFAULT '0',
    highest_since_entry TEXT NOT NULL DEFAULT '0',
    protection_status TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS realized_pnl_events (
    event_id TEXT PRIMARY KEY,
    fill_id TEXT NOT NULL UNIQUE,
    inst_id TEXT NOT NULL,
    realized_pnl TEXT NOT NULL,
    realized_at REAL NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY(fill_id) REFERENCES fills(fill_id)
);
CREATE INDEX IF NOT EXISTS idx_realized_pnl_events_time
    ON realized_pnl_events(realized_at);

CREATE TABLE IF NOT EXISTS reconciliation_adjustments (
    adjustment_id TEXT PRIMARY KEY,
    inst_id TEXT NOT NULL,
    old_qty TEXT NOT NULL,
    new_qty TEXT NOT NULL,
    new_available_qty TEXT NOT NULL DEFAULT '0',
    new_avg_entry_px TEXT NOT NULL DEFAULT '0',
    new_realized_pnl TEXT NOT NULL DEFAULT '0',
    snapshot_complete INTEGER NOT NULL DEFAULT 1,
    reason TEXT NOT NULL,
    reconciliation_run_id TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_reservations (
    reservation_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL UNIQUE,
    inst_id TEXT NOT NULL,
    reserved_quote TEXT NOT NULL DEFAULT '0',
    reserved_slot INTEGER NOT NULL DEFAULT 1,
    released_at REAL,
    created_at REAL NOT NULL,
    FOREIGN KEY(intent_id) REFERENCES order_intents(intent_id)
);

CREATE TABLE IF NOT EXISTS protective_orders (
    protection_id TEXT PRIMARY KEY,
    inst_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    protected_qty TEXT NOT NULL,
    trigger_px TEXT NOT NULL,
    take_profit_px TEXT NOT NULL DEFAULT '0',
    order_px TEXT NOT NULL DEFAULT '-1',
    state TEXT NOT NULL,
    algo_cl_ord_id TEXT NOT NULL UNIQUE,
    exchange_algo_id TEXT UNIQUE,
    parent_intent_id TEXT,
    version INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_protective_inst_state
    ON protective_orders(inst_id, state);

CREATE TABLE IF NOT EXISTS reconciliation_runs (
    run_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    mismatch_count INTEGER NOT NULL DEFAULT 0,
    repaired_count INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    started_at REAL NOT NULL,
    completed_at REAL
);

CREATE TABLE IF NOT EXISTS account_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    total_equity_quote TEXT NOT NULL,
    available_quote TEXT NOT NULL,
    holdings_json TEXT NOT NULL,
    source TEXT NOT NULL,
    captured_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS system_events (
    event_id TEXT PRIMARY KEY,
    event_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    correlation_id TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_events_name_created
ON system_events(event_name, created_at DESC, event_id DESC);

CREATE TABLE IF NOT EXISTS outbox_events (
    event_id TEXT PRIMARY KEY,
    event_name TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    published_at REAL
);

CREATE TABLE IF NOT EXISTS alert_deliveries (
    event_id TEXT PRIMARY KEY,
    priority TEXT NOT NULL CHECK(priority IN ('P0', 'P1')),
    state TEXT NOT NULL CHECK(
        state IN (
            'pending', 'retry', 'ingested', 'provider_received',
            'acknowledged', 'escalated', 'dlq'
        )
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
    next_attempt_at REAL NOT NULL,
    ingestion_accepted_at REAL,
    provider_received_at REAL,
    provider_event_id TEXT NOT NULL DEFAULT '',
    human_ack_at REAL,
    human_ack_actor TEXT NOT NULL DEFAULT '',
    escalation_at REAL,
    last_http_status INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    dlq_at REAL,
    provider_artifact_sha256 TEXT NOT NULL DEFAULT '',
    human_ack_artifact_sha256 TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY(event_id) REFERENCES outbox_events(event_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_due
    ON alert_deliveries(state, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_created
    ON alert_deliveries(created_at);

CREATE TABLE IF NOT EXISTS alert_delivery_attempts (
    attempt_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    attempt_no INTEGER NOT NULL CHECK(attempt_no > 0),
    started_at REAL NOT NULL,
    completed_at REAL NOT NULL,
    http_status INTEGER,
    ingestion_accepted INTEGER NOT NULL CHECK(ingestion_accepted IN (0, 1)),
    error TEXT NOT NULL DEFAULT '',
    UNIQUE(event_id, attempt_no),
    FOREIGN KEY(event_id) REFERENCES alert_deliveries(event_id)
);

CREATE TABLE IF NOT EXISTS system_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS journal_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    account_id TEXT NOT NULL UNIQUE,
    initial_config_hash TEXT NOT NULL,
    initialized_by TEXT NOT NULL,
    initialized_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS exit_leases (
    inst_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS candle_watermarks (
    strategy_instance_id TEXT NOT NULL,
    inst_id TEXT NOT NULL,
    bar TEXT NOT NULL,
    candle_ts TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY(strategy_instance_id, inst_id, bar)
);

CREATE TABLE IF NOT EXISTS control_commands (
    command_id TEXT PRIMARY KEY,
    command_type TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    started_at REAL,
    completed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_control_commands_status_created
    ON control_commands(status, created_at);

CREATE TABLE IF NOT EXISTS probe_runs (
    probe_id TEXT PRIMARY KEY CHECK(length(probe_id) = 32),
    account_uid TEXT NOT NULL,
    utc_day TEXT NOT NULL,
    slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 2),
    inst_id TEXT NOT NULL,
    nominal_usdt TEXT NOT NULL
        CHECK(CAST(nominal_usdt AS REAL) BETWEEN 5 AND 10),
    state TEXT NOT NULL CHECK(state IN (
        'PREPARED','BUY_SUBMITTING','BUY_UNKNOWN','BUY_FILLED',
        'PROTECTING','PROTECTED','CLEANING','DONE','REJECTED',
        'MANUAL_REVIEW','FAILED'
    )),
    buy_cl_ord_id TEXT NOT NULL UNIQUE,
    algo_cl_ord_id TEXT NOT NULL UNIQUE,
    buy_intent_id TEXT UNIQUE,
    exit_intent_id TEXT UNIQUE,
    baseline_base_balance TEXT NOT NULL DEFAULT '0',
    final_base_balance TEXT NOT NULL DEFAULT '0',
    expected_base_dust TEXT NOT NULL DEFAULT '0',
    duplicate_buy_count INTEGER NOT NULL DEFAULT 0
        CHECK(duplicate_buy_count >= 0),
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_expires_at REAL NOT NULL DEFAULT 0,
    fencing_token INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(account_uid, utc_day, slot)
);
CREATE INDEX IF NOT EXISTS idx_probe_runs_state_updated
    ON probe_runs(state, updated_at);
"""
LATEST_SCHEMA_VERSION = 11
_FORMAL_PROBE_SCHEDULE_STATE_KEY = "formal_probe_schedule_binding_v1"
_FORMAL_PROBE_SCHEDULE_KEYS = {
    "version",
    "action",
    "schedule_id",
    "created_at",
    "slots",
}
_FORMAL_PROBE_SLOT_KEYS = {
    "day",
    "slot",
    "inst_id",
    "direction",
    "window_start",
    "window_end",
    "spread_min_bps",
    "spread_max_bps",
    "volatility_min_bps",
    "volatility_max_bps",
}


class SQLiteJournal:
    """线程安全的单写者 SQLite repository。"""

    def __init__(
        self,
        path: str | Path,
        *,
        must_exist: bool = False,
        read_only: bool = False,
    ):
        self.path = Path(path)
        if (must_exist or read_only) and (
            not self.path.is_file()
            or self.path.is_symlink()
            or self.path.stat().st_size <= 0
        ):
            raise FileNotFoundError(
                f"交易日志不存在、为空或不是普通文件: {self.path}"
            )
        if not read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists() and self.path.stat().st_size > 0
        self._lock = threading.RLock()
        self._write_observers: list[
            Callable[[bool, BaseException | None], None]
        ] = []
        target = (
            f"file:{self.path}?mode=ro"
            if read_only
            else str(self.path)
        )
        self._conn = sqlite3.connect(
            target,
            timeout=10,
            isolation_level=None,
            check_same_thread=False,
            uri=read_only,
        )
        self._conn.row_factory = sqlite3.Row
        self._read_only = read_only
        if read_only:
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._capture_path_identity()
            return
        self._configure()
        self._capture_path_identity()
        try:
            if existed:
                current = self._schema_version()
                if current > LATEST_SCHEMA_VERSION:
                    raise RuntimeError(
                        f"数据库 schema v{current} 高于当前程序支持的 "
                        f"v{LATEST_SCHEMA_VERSION}，拒绝用旧二进制启动"
                    )
                if current < LATEST_SCHEMA_VERSION:
                    self._backup_before_migration(current)
                    self._latch_maintenance_for_migration()
            self.migrate()
        except BaseException:
            self._conn.close()
            raise

    def _schema_version(self) -> int:
        try:
            row = self._conn.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
            return int(row[0] or 0)
        except sqlite3.DatabaseError:
            return 0

    def _capture_path_identity(self) -> None:
        path_stat = self.path.lstat()
        if not stat.S_ISREG(path_stat.st_mode) or self.path.is_symlink():
            raise RuntimeError("交易日志路径必须是非符号链接普通文件")
        self._path_identity = (path_stat.st_dev, path_stat.st_ino)

    def _path_is_current(self) -> bool:
        try:
            path_stat = self.path.lstat()
        except OSError:
            return False
        return bool(
            stat.S_ISREG(path_stat.st_mode)
            and not self.path.is_symlink()
            and (path_stat.st_dev, path_stat.st_ino) == self._path_identity
        )

    def _backup_before_migration(self, current: int) -> None:
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        destination = self.path.with_name(
            f"{self.path.name}.pre-migration-v{current}-{timestamp}.db"
        )
        target = sqlite3.connect(str(destination))
        try:
            self._conn.backup(target)
        finally:
            target.close()

    def _latch_maintenance_for_migration(self) -> None:
        """旧库迁移开始前持久锁存 MAINTENANCE，禁止自动恢复交易。"""
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS system_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
        now = time.time()
        with self.transaction() as conn:
            epoch_row = conn.execute(
                "SELECT value FROM system_state WHERE key='mode_epoch'"
            ).fetchone()
            epoch = int(epoch_row["value"]) if epoch_row else 0
            conn.execute(
                """
                INSERT INTO system_state(key, value, updated_at)
                VALUES('mode', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value, updated_at=excluded.updated_at
                """,
                (SystemMode.MAINTENANCE.value, now),
            )
            conn.execute(
                """
                INSERT INTO system_state(key, value, updated_at)
                VALUES('mode_epoch', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value, updated_at=excluded.updated_at
                """,
                (str(epoch + 1), now),
            )

    def _configure(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=10000")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        successful = False
        database_error: BaseException | None = None
        try:
            with self._lock:
                if not self._path_is_current():
                    database_error = sqlite3.OperationalError(
                        "交易日志路径已删除或 inode 已替换"
                    )
                    raise database_error
                try:
                    self._conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error as exc:
                    database_error = exc
                    raise
                try:
                    yield self._conn
                except BaseException as exc:
                    try:
                        self._conn.execute("ROLLBACK")
                    except sqlite3.Error as rollback_error:
                        database_error = rollback_error
                    if (
                        isinstance(exc, sqlite3.Error)
                        and not isinstance(exc, sqlite3.IntegrityError)
                    ):
                        database_error = exc
                    raise
                else:
                    try:
                        self._conn.execute("COMMIT")
                        successful = True
                    except sqlite3.Error as exc:
                        database_error = exc
                        with suppress(sqlite3.Error):
                            self._conn.execute("ROLLBACK")
                        raise
        finally:
            if successful or database_error is not None:
                self._notify_write_observers(
                    successful,
                    database_error,
                )

    def add_write_observer(
        self,
        observer: Callable[[bool, BaseException | None], None],
    ) -> None:
        self._write_observers.append(observer)

    def _notify_write_observers(
        self,
        successful: bool,
        error: BaseException | None,
    ) -> None:
        for observer in tuple(self._write_observers):
            with suppress(Exception):
                observer(successful, error)

    def migrate(self) -> None:
        migrations = (
            self._migration_001_bootstrap,
            self._migration_002_order_risk_fields,
            self._migration_003_protection_take_profit,
            self._migration_004_reconciliation_schema,
            self._migration_005_operations_schema,
            self._migration_006_identity_schema,
            self._migration_007_control_schema,
            self._migration_008_submission_reference,
            self._migration_009_reconciliation_checkpoints,
            self._migration_010_demo_probe_saga,
            self._migration_011_durable_alert_delivery,
        )
        current = self._schema_version()
        versions = [
            int(row["version"])
            for row in self._conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ] if current else []
        if versions and versions != list(range(1, current + 1)):
            raise RuntimeError("schema_migrations 存在缺口或乱序")
        for version in range(current + 1, LATEST_SCHEMA_VERSION + 1):
            migration = migrations[version - 1]
            with self.transaction() as conn:
                migration(conn)
                conn.execute(
                    """
                    INSERT INTO schema_migrations(version, applied_at)
                    VALUES(?, ?)
                    """,
                    (version, time.time()),
                )
                recorded = conn.execute(
                    "SELECT MAX(version) FROM schema_migrations"
                ).fetchone()[0]
                if int(recorded) != version:
                    raise RuntimeError(
                        f"migration v{version} 未形成连续版本"
                    )
        with self.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO system_state(key, value, updated_at) VALUES('mode', ?, ?)",
                (SystemMode.STARTING.value, time.time()),
            )
            conn.execute(
                "INSERT OR IGNORE INTO system_state(key, value, updated_at) VALUES('mode_epoch', '0', ?)",
                (time.time(),),
            )

    @staticmethod
    def _execute_schema_conn(conn: sqlite3.Connection) -> None:
        for statement in _SCHEMA.split(";"):
            if statement.strip():
                conn.execute(statement)

    @staticmethod
    def _ensure_column_conn(
        conn: sqlite3.Connection,
        table: str,
        column: str,
        declaration: str,
    ) -> None:
        columns = {
            row["name"]
            for row in conn.execute(
                f"PRAGMA table_info({table})"
            ).fetchall()
        }
        if column not in columns:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
            )

    @classmethod
    def _migration_001_bootstrap(cls, conn: sqlite3.Connection) -> None:
        cls._execute_schema_conn(conn)

    @classmethod
    def _migration_002_order_risk_fields(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)
        cls._ensure_column_conn(
            conn,
            "order_intents",
            "requested_stop_loss",
            "TEXT NOT NULL DEFAULT '0'",
        )
        cls._ensure_column_conn(
            conn,
            "order_intents",
            "requested_take_profit",
            "TEXT NOT NULL DEFAULT '0'",
        )

    @classmethod
    def _migration_003_protection_take_profit(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)
        cls._ensure_column_conn(
            conn,
            "protective_orders",
            "take_profit_px",
            "TEXT NOT NULL DEFAULT '0'",
        )

    @classmethod
    def _migration_004_reconciliation_schema(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)

    @classmethod
    def _migration_005_operations_schema(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)

    @classmethod
    def _migration_006_identity_schema(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)

    @classmethod
    def _migration_007_control_schema(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)

    @classmethod
    def _migration_008_submission_reference(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)
        cls._ensure_column_conn(
            conn,
            "order_intents",
            "submission_reference_price",
            "TEXT NOT NULL DEFAULT '0'",
        )

    @classmethod
    def _migration_009_reconciliation_checkpoints(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)
        cls._ensure_column_conn(
            conn,
            "reconciliation_adjustments",
            "new_available_qty",
            "TEXT NOT NULL DEFAULT '0'",
        )
        cls._ensure_column_conn(
            conn,
            "reconciliation_adjustments",
            "new_avg_entry_px",
            "TEXT NOT NULL DEFAULT '0'",
        )
        cls._ensure_column_conn(
            conn,
            "reconciliation_adjustments",
            "new_realized_pnl",
            "TEXT NOT NULL DEFAULT '0'",
        )
        # v8 及更早的调整没有完整会计事实。迁移后保持“不完整”，
        # 重建流程会拒绝猜测成本价或已实现盈亏。
        cls._ensure_column_conn(
            conn,
            "reconciliation_adjustments",
            "snapshot_complete",
            "INTEGER NOT NULL DEFAULT 0",
        )

    @classmethod
    def _migration_010_demo_probe_saga(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)
        cls._ensure_column_conn(
            conn,
            "order_intents",
            "source",
            "TEXT NOT NULL DEFAULT 'strategy'",
        )
        cls._ensure_column_conn(
            conn,
            "order_intents",
            "probe_id",
            "TEXT NOT NULL DEFAULT ''",
        )

    @classmethod
    def _migration_011_durable_alert_delivery(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        cls._execute_schema_conn(conn)
        conn.execute(
            """
            INSERT OR IGNORE INTO alert_deliveries(
                event_id, priority, state, next_attempt_at,
                created_at, updated_at
            )
            SELECT
                event_id,
                CASE WHEN event_name LIKE 'page.%' THEN 'P0' ELSE 'P1' END,
                CASE WHEN published_at IS NULL THEN 'pending' ELSE 'ingested' END,
                created_at,
                created_at,
                COALESCE(published_at, created_at)
            FROM outbox_events
            """
        )

    def initialize_identity(
        self,
        *,
        account_id: str,
        initial_config_hash: str,
        actor: str,
    ) -> None:
        """原子写入不可变账户身份、初始化 marker 和 HALTED。"""
        if not account_id.strip() or not actor.strip():
            raise ValueError("journal identity 的 account_id/actor 不能为空")
        if not re.fullmatch(r"[0-9a-f]{64}", initial_config_hash):
            raise ValueError("initial_config_hash 必须是 64 位小写 SHA-256")
        now = time.time()
        with self.transaction() as conn:
            if conn.execute(
                "SELECT 1 FROM journal_identity WHERE singleton=1"
            ).fetchone():
                raise RuntimeError("交易日志 identity 已初始化，禁止覆盖")
            conn.execute(
                """
                INSERT INTO journal_identity(
                    singleton, account_id, initial_config_hash,
                    initialized_by, initialized_at
                ) VALUES(1,?,?,?,?)
                """,
                (
                    account_id.strip(),
                    initial_config_hash,
                    actor.strip(),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO system_state(key, value, updated_at)
                VALUES('mode', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value, updated_at=excluded.updated_at
                """,
                (SystemMode.HALTED.value, now),
            )
            conn.execute(
                """
                INSERT INTO system_state(key, value, updated_at)
                VALUES('mode_epoch', '1', ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=CAST(system_state.value AS INTEGER) + 1,
                    updated_at=excluded.updated_at
                """,
                (now,),
            )
            conn.execute(
                """
                INSERT INTO system_state(key, value, updated_at)
                VALUES('mode_reason', 'journal_initialized_halted', ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value, updated_at=excluded.updated_at
                """,
                (now,),
            )
            conn.execute(
                """
                INSERT INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?, 'production_journal_initialized',
                         'critical', '', ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    json.dumps({
                        "actor": actor.strip(),
                        "account_id": account_id.strip(),
                        "config_hash": initial_config_hash,
                    }, ensure_ascii=False),
                    now,
                ),
            )

    def get_identity(self) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM journal_identity WHERE singleton=1"
            ).fetchone()
        return dict(row) if row else None

    def assert_identity(self, expected_account_id: str) -> dict:
        identity = self.get_identity()
        if identity is None:
            raise RuntimeError("交易日志缺少原子初始化 marker/account identity")
        if identity["account_id"] != expected_account_id:
            raise RuntimeError(
                "交易日志绑定账户与配置账户不匹配: "
                f"journal={identity['account_id']}, "
                f"config={expected_account_id}"
            )
        return identity

    def integrity_check(self) -> bool:
        with self._lock:
            row = self._conn.execute("PRAGMA integrity_check").fetchone()
            return bool(row and row[0] == "ok")

    def health_check(self) -> bool:
        """高频活性探针；完整 integrity_check 仅用于启动/备份/演练。"""
        with self._lock:
            if not self._path_is_current():
                return False
            row = self._conn.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
            return bool(row and row[0] == LATEST_SCHEMA_VERSION)

    def passive_wal_checkpoint(self) -> dict:
        """Run a non-blocking WAL checkpoint and return auditable counters."""
        with self._lock:
            row = self._conn.execute(
                "PRAGMA wal_checkpoint(PASSIVE)"
            ).fetchone()
            page_size_row = self._conn.execute("PRAGMA page_size").fetchone()
        if row is None or len(row) != 3:
            raise RuntimeError("SQLite WAL checkpoint 返回结构非法")
        if page_size_row is None or len(page_size_row) != 1:
            raise RuntimeError("SQLite page_size 返回结构非法")
        busy, log_frames, checkpointed_frames = map(int, row)
        page_size_bytes = int(page_size_row[0])
        if (
            min(busy, log_frames, checkpointed_frames) < 0
            or checkpointed_frames > log_frames
            or page_size_bytes <= 0
        ):
            raise RuntimeError("SQLite WAL checkpoint 返回非法计数")
        backlog_frames = log_frames - checkpointed_frames
        return {
            "busy": busy,
            "log_frames": log_frames,
            "checkpointed_frames": checkpointed_frames,
            "backlog_frames": backlog_frames,
            "page_size_bytes": page_size_bytes,
            "backlog_bytes": backlog_frames * (page_size_bytes + 24),
            "completed_at": time.time(),
        }

    def create_decision(
        self,
        *,
        strategy_instance_id: str,
        strategy_name: str,
        inst_id: str,
        candle_ts: str,
        signal: str,
        requested_size_pct: Decimal = Decimal("0"),
        reason: str = "",
        strategy_version: str = "",
        inputs_hash: str = "",
        decision_id: str | None = None,
    ) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", strategy_version):
            raise ValueError("strategy_version 必须是 64 位小写 SHA-256")
        decision_id = decision_id or uuid.uuid4().hex
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO decisions(
                    decision_id, strategy_instance_id, strategy_name, strategy_version,
                    inst_id, candle_ts, signal, requested_size_pct, reason, inputs_hash,
                    created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    decision_id,
                    strategy_instance_id,
                    strategy_name,
                    strategy_version,
                    inst_id,
                    candle_ts,
                    signal,
                    str(requested_size_pct),
                    reason,
                    inputs_hash,
                    time.time(),
                ),
            )
        return decision_id

    def has_decision(
        self,
        strategy_instance_id: str,
        inst_id: str,
        candle_ts: str,
    ) -> bool:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT 1 FROM decisions
                WHERE strategy_instance_id=? AND inst_id=? AND candle_ts=?
                """,
                (strategy_instance_id, inst_id, candle_ts),
            ).fetchone()
        return row is not None

    def get_candle_watermark(
        self, strategy_instance_id: str, inst_id: str, bar: str
    ) -> str:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT candle_ts FROM candle_watermarks
                WHERE strategy_instance_id=? AND inst_id=? AND bar=?
                """,
                (strategy_instance_id, inst_id, bar),
            ).fetchone()
        return str(row["candle_ts"]) if row else ""

    def set_candle_watermark(
        self,
        strategy_instance_id: str,
        inst_id: str,
        bar: str,
        candle_ts: str,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO candle_watermarks(
                    strategy_instance_id, inst_id, bar, candle_ts, updated_at
                ) VALUES(?,?,?,?,?)
                ON CONFLICT(strategy_instance_id, inst_id, bar) DO UPDATE SET
                    candle_ts=excluded.candle_ts,
                    updated_at=excluded.updated_at
                """,
                (strategy_instance_id, inst_id, bar, candle_ts, time.time()),
            )

    def recent_intent_count(self, since: float, *, side: str = "") -> int:
        sql = "SELECT COUNT(*) AS n FROM order_intents WHERE created_at>=?"
        params: list[object] = [since]
        if side:
            sql += " AND side=?"
            params.append(side)
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return int(row["n"]) if row else 0

    def intent_state_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT state, COUNT(*) AS n FROM order_intents GROUP BY state"
            ).fetchall()
        return {str(row["state"]): int(row["n"]) for row in rows}

    def active_reserved_quote(self) -> Decimal:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT reserved_quote FROM risk_reservations
                WHERE released_at IS NULL
                """
            ).fetchall()
        return sum((to_decimal(row["reserved_quote"]) for row in rows), Decimal("0"))

    def active_reserved_instruments(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT DISTINCT inst_id FROM risk_reservations
                WHERE released_at IS NULL AND reserved_slot=1
                """
            ).fetchall()
        return {str(row["inst_id"]) for row in rows}

    def has_nonterminal_intent(self, inst_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT 1 FROM order_intents
                WHERE inst_id=? AND state NOT IN ('filled','canceled','rejected')
                LIMIT 1
                """,
                (inst_id,),
            ).fetchone()
        return row is not None

    def latest_account_snapshot(self) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM account_snapshots
                ORDER BY captured_at DESC LIMIT 1
                """
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["holdings"] = json.loads(result.pop("holdings_json"))
        return result

    def account_equities_since(self, since: float) -> list[Decimal]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT total_equity_quote FROM account_snapshots
                WHERE captured_at>=? ORDER BY captured_at
                """,
                (since,),
            ).fetchall()
        return [to_decimal(row["total_equity_quote"]) for row in rows]

    def audit_order_chain(self, client_order_id: str) -> dict:
        """返回一个 clOrdId 的决策—订单—成交—保护完整审计链。"""
        intent = self.find_intent(cl_ord_id=client_order_id)
        if intent is None:
            raise KeyError(f"未找到 clOrdId: {client_order_id}")
        with self._lock:
            decision = None
            if intent.decision_id:
                row = self._conn.execute(
                    "SELECT * FROM decisions WHERE decision_id=?",
                    (intent.decision_id,),
                ).fetchone()
                decision = dict(row) if row else None
            events = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT * FROM order_events WHERE intent_id=? ORDER BY created_at",
                    (intent.intent_id,),
                ).fetchall()
            ]
            fills = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT * FROM fills WHERE intent_id=? ORDER BY created_at",
                    (intent.intent_id,),
                ).fetchall()
            ]
            protections = [
                dict(row)
                for row in self._conn.execute(
                    """
                    SELECT * FROM protective_orders
                    WHERE parent_intent_id=? ORDER BY created_at
                    """,
                    (intent.intent_id,),
                ).fetchall()
            ]
        return {
            "decision": decision,
            "intent": {
                key: (value.value if hasattr(value, "value") else str(value)
                      if isinstance(value, Decimal) else value)
                for key, value in intent.__dict__.items()
            },
            "events": events,
            "fills": fills,
            "protections": protections,
        }

    def enqueue_control_command(
        self,
        command_type: str,
        payload: dict | None = None,
        *,
        command_id: str | None = None,
    ) -> str:
        command_id = command_id or uuid.uuid4().hex
        if not re.fullmatch(r"[0-9a-f]{32}", command_id):
            raise ValueError("control command_id 必须是 32 位小写十六进制")
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO control_commands(
                    command_id, command_type, payload_json, status, created_at
                ) VALUES(?,?,?,'pending',?)
                """,
                (
                    command_id,
                    command_type,
                    json.dumps(payload or {}, ensure_ascii=False, default=str),
                    time.time(),
                ),
            )
        return command_id

    def claim_control_commands(self, limit: int = 10) -> list[dict]:
        with self.transaction() as conn:
            rows = conn.execute(
                """
                SELECT * FROM control_commands
                WHERE status='pending' ORDER BY created_at LIMIT ?
                """,
                (limit,),
            ).fetchall()
            now = time.time()
            for row in rows:
                conn.execute(
                    """
                    UPDATE control_commands
                    SET status='running', started_at=?
                    WHERE command_id=? AND status='pending'
                    """,
                    (now, row["command_id"]),
                )
        return [
            {
                **dict(row),
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def finish_control_command(
        self, command_id: str, *, success: bool, result: dict
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE control_commands SET
                    status=?, result_json=?, completed_at=?
                WHERE command_id=?
                """,
                (
                    "completed" if success else "failed",
                    json.dumps(result, ensure_ascii=False, default=str),
                    time.time(),
                    command_id,
                ),
            )

    def get_control_command(self, command_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM control_commands WHERE command_id=?",
                (command_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result.pop("payload_json"))
        result["result"] = json.loads(result.pop("result_json"))
        return result

    @staticmethod
    def _canonical_json_bytes(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    @classmethod
    def _validate_formal_probe_schedule_binding(
        cls,
        *,
        account_uid: str,
        soak_epoch_id: str,
        schedule: object,
        schedule_sha256: str,
    ) -> dict:
        if (
            not account_uid.strip()
            or not soak_epoch_id.strip()
            or not re.fullmatch(r"[0-9a-f]{64}", schedule_sha256)
            or not isinstance(schedule, dict)
            or set(schedule) != _FORMAL_PROBE_SCHEDULE_KEYS
            or schedule.get("version") != 2
            or schedule.get("action") != "precommit-demo-probe-schedule"
            or not str(schedule.get("schedule_id", "")).strip()
        ):
            raise ValueError("formal probe schedule DB binding identity 非法")
        try:
            created_at = datetime.fromisoformat(str(schedule["created_at"]))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "formal probe schedule created_at 非法"
            ) from exc
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ValueError("formal probe schedule created_at 必须带时区")
        if hashlib.sha256(
            cls._canonical_json_bytes(schedule)
        ).hexdigest() != schedule_sha256:
            raise ValueError("formal probe schedule hash 与 frozen bytes 不一致")
        slots = schedule["slots"]
        if not isinstance(slots, list) or len(slots) != 30:
            raise ValueError("formal probe schedule DB binding 必须精确 30 日")
        days: list[date] = []
        slot_bindings: list[dict] = []
        for item in slots:
            if (
                not isinstance(item, dict)
                or set(item) != _FORMAL_PROBE_SLOT_KEYS
                or item["slot"] != 1
                or item["direction"] != "buy_then_exit"
                or not re.fullmatch(
                    r"[A-Z0-9]+-USDT",
                    str(item["inst_id"]),
                )
            ):
                raise ValueError(
                    "formal probe schedule DB slot 必须为每日唯一 slot=1"
                )
            try:
                day = date.fromisoformat(str(item["day"]))
                started = datetime.fromisoformat(
                    str(item["window_start"])
                ).astimezone(UTC)
                ended = datetime.fromisoformat(
                    str(item["window_end"])
                ).astimezone(UTC)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "formal probe schedule DB slot 时间非法"
                ) from exc
            if (
                started.date() != day
                or ended.date() != day
                or not started < ended
                or created_at.astimezone(UTC) >= started
            ):
                raise ValueError(
                    "formal probe schedule DB slot 日期/窗口非法"
                )
            days.append(day)
            slot_bindings.append({
                "day": day.isoformat(),
                "slot": 1,
                "inst_id": str(item["inst_id"]),
            })
        ordered_days = sorted(days)
        if (
            len(set(days)) != 30
            or any(
                right - left != timedelta(days=1)
                for left, right in zip(
                    ordered_days,
                    ordered_days[1:],
                    strict=False,
                )
            )
        ):
            raise ValueError(
                "formal probe schedule DB binding 必须是连续且每日精确一次"
            )
        return {
            "version": 1,
            "account_uid": account_uid,
            "soak_epoch_id": soak_epoch_id,
            "schedule_id": str(schedule["schedule_id"]),
            "schedule_sha256": schedule_sha256,
            "slots": sorted(slot_bindings, key=lambda row: row["day"]),
        }

    def bind_formal_probe_schedule(
        self,
        *,
        account_uid: str,
        soak_epoch_id: str,
        schedule: object,
        schedule_sha256: str,
    ) -> dict:
        binding = self._validate_formal_probe_schedule_binding(
            account_uid=account_uid,
            soak_epoch_id=soak_epoch_id,
            schedule=schedule,
            schedule_sha256=schedule_sha256,
        )
        encoded = self._canonical_json_bytes(binding).decode("utf-8")
        with self.transaction() as conn:
            existing = conn.execute(
                "SELECT value FROM system_state WHERE key=?",
                (_FORMAL_PROBE_SCHEDULE_STATE_KEY,),
            ).fetchone()
            if existing is not None and existing["value"] != encoded:
                raise RuntimeError(
                    "formal probe schedule 已冻结，禁止替换 epoch/schedule"
                )
            conn.execute(
                """
                INSERT OR IGNORE INTO system_state(key, value, updated_at)
                VALUES(?, ?, ?)
                """,
                (_FORMAL_PROBE_SCHEDULE_STATE_KEY, encoded, time.time()),
            )
        return binding

    @staticmethod
    def _formal_probe_schedule_binding_conn(
        conn: sqlite3.Connection,
    ) -> dict | None:
        row = conn.execute(
            "SELECT value FROM system_state WHERE key=?",
            (_FORMAL_PROBE_SCHEDULE_STATE_KEY,),
        ).fetchone()
        if row is None:
            return None
        try:
            binding = json.loads(row["value"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "durable formal probe schedule binding 损坏"
            ) from exc
        if (
            not isinstance(binding, dict)
            or set(binding)
            != {
                "version",
                "account_uid",
                "soak_epoch_id",
                "schedule_id",
                "schedule_sha256",
                "slots",
            }
            or binding["version"] != 1
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(binding["schedule_sha256"]),
            )
            or not isinstance(binding["slots"], list)
            or len(binding["slots"]) != 30
        ):
            raise RuntimeError(
                "durable formal probe schedule binding schema 非法"
            )
        return binding

    @classmethod
    def _assert_formal_probe_slot_conn(
        cls,
        conn: sqlite3.Connection,
        *,
        account_uid: str,
        soak_epoch_id: str,
        schedule_sha256: str,
        utc_day: str,
        slot: int,
        inst_id: str,
    ) -> bool:
        binding = cls._formal_probe_schedule_binding_conn(conn)
        if binding is None:
            if soak_epoch_id or schedule_sha256:
                raise RuntimeError(
                    "formal probe capability 缺少 durable frozen schedule"
                )
            return False
        matches = [
            item
            for item in binding["slots"]
            if (
                isinstance(item, dict)
                and set(item) == {"day", "slot", "inst_id"}
                and item["day"] == utc_day
            )
        ]
        if (
            binding["account_uid"] != account_uid
            or binding["soak_epoch_id"] != soak_epoch_id
            or binding["schedule_sha256"] != schedule_sha256
            or slot != 1
            or len(matches) != 1
            or matches[0] != {
                "day": utc_day,
                "slot": 1,
                "inst_id": inst_id,
            }
        ):
            raise RuntimeError(
                "formal probe capability 与 frozen epoch/schedule/day/slot 不一致"
            )
        return True

    def create_probe_run(
        self,
        *,
        probe_id: str,
        account_uid: str,
        utc_day: str,
        slot: int,
        inst_id: str,
        nominal_usdt: Decimal,
        buy_cl_ord_id: str,
        algo_cl_ord_id: str,
        baseline_base_balance: Decimal,
        soak_epoch_id: str = "",
        formal_schedule_sha256: str = "",
    ) -> dict:
        if (
            not re.fullmatch(r"[0-9a-f]{32}", probe_id)
            or not account_uid.strip()
            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", utc_day)
            or slot not in {1, 2}
            or not re.fullmatch(r"[A-Z0-9]+-USDT", inst_id)
            or not Decimal("5") <= nominal_usdt <= Decimal("10")
            or not re.fullmatch(r"[A-Za-z0-9]{1,32}", buy_cl_ord_id)
            or not re.fullmatch(r"[A-Za-z0-9]{1,32}", algo_cl_ord_id)
        ):
            raise ValueError("probe PREPARED identity/policy 非法")
        now = time.time()
        with self.transaction() as conn:
            formal = self._assert_formal_probe_slot_conn(
                conn,
                account_uid=account_uid,
                soak_epoch_id=soak_epoch_id,
                schedule_sha256=formal_schedule_sha256,
                utc_day=utc_day,
                slot=slot,
                inst_id=inst_id,
            )
            existing = conn.execute(
                """
                SELECT COUNT(*) FROM probe_runs
                WHERE account_uid=? AND utc_day=?
                """,
                (account_uid, utc_day),
            ).fetchone()[0]
            if int(existing) >= (1 if formal else 2):
                raise RuntimeError("该账户 UTC 日 probe 配额已耗尽")
            unresolved = conn.execute(
                """
                SELECT probe_id FROM probe_runs
                WHERE account_uid=?
                  AND state NOT IN ('DONE','REJECTED','FAILED')
                LIMIT 1
                """,
                (account_uid,),
            ).fetchone()
            if unresolved is not None:
                raise RuntimeError("该账户已有未决 probe saga")
            pending = conn.execute(
                """
                SELECT intent_id FROM order_intents
                WHERE state NOT IN ('filled','canceled','rejected')
                LIMIT 1
                """
            ).fetchone()
            if pending is not None:
                raise RuntimeError("账户存在未决普通订单，禁止 PREPARED")
            positive_positions = [
                row
                for row in conn.execute(
                    "SELECT inst_id, base_qty FROM positions"
                ).fetchall()
                if parse_decimal_fact(
                    row["base_qty"],
                    "positions.base_qty",
                    nonnegative=True,
                )
                > 0
            ]
            if positive_positions:
                raise RuntimeError("账户存在非 probe 仓位，禁止 PREPARED")
            conn.execute(
                """
                INSERT INTO probe_runs(
                    probe_id, account_uid, utc_day, slot, inst_id,
                    nominal_usdt, state, buy_cl_ord_id, algo_cl_ord_id,
                    baseline_base_balance, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,'PREPARED',?,?,?,?,?)
                """,
                (
                    probe_id,
                    account_uid,
                    utc_day,
                    slot,
                    inst_id,
                    str(nominal_usdt),
                    buy_cl_ord_id,
                    algo_cl_ord_id,
                    str(baseline_base_balance),
                    now,
                    now,
                ),
            )
        result = self.get_probe_run(probe_id)
        assert result is not None
        return result

    def get_probe_run(self, probe_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM probe_runs WHERE probe_id=?",
                (probe_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def list_probe_runs(
        self,
        *,
        account_uid: str = "",
        utc_day: str = "",
        unresolved_only: bool = False,
    ) -> list[dict]:
        query = "SELECT * FROM probe_runs WHERE 1=1"
        params: list[object] = []
        if account_uid:
            query += " AND account_uid=?"
            params.append(account_uid)
        if utc_day:
            query += " AND utc_day=?"
            params.append(utc_day)
        if unresolved_only:
            query += " AND state NOT IN ('DONE','REJECTED','FAILED')"
        query += " ORDER BY created_at, probe_id"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def acquire_probe_lease(
        self,
        probe_id: str,
        owner: str,
        *,
        ttl_s: float = 30,
    ) -> tuple[int, dict] | None:
        if (
            not owner.strip()
            or not math.isfinite(ttl_s)
            or not 1 <= ttl_s <= 300
        ):
            raise ValueError("probe lease owner/ttl 非法")
        now = time.time()
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM probe_runs WHERE probe_id=?",
                (probe_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"probe 不存在: {probe_id}")
            if row["state"] in {"DONE", "REJECTED", "FAILED"}:
                return None
            if (
                row["lease_owner"]
                and row["lease_owner"] != owner
                and float(row["lease_expires_at"]) > now
            ):
                return None
            token = int(row["fencing_token"]) + 1
            cursor = conn.execute(
                """
                UPDATE probe_runs
                SET lease_owner=?, lease_expires_at=?, fencing_token=?,
                    version=version+1, updated_at=?
                WHERE probe_id=? AND version=?
                """,
                (
                    owner,
                    now + ttl_s,
                    token,
                    now,
                    probe_id,
                    row["version"],
                ),
            )
            if cursor.rowcount != 1:
                return None
        updated = self.get_probe_run(probe_id)
        assert updated is not None
        return token, updated

    def transition_probe_run(
        self,
        probe_id: str,
        *,
        owner: str,
        fencing_token: int,
        expected_states: tuple[str, ...],
        new_state: str,
        changes: dict | None = None,
    ) -> dict:
        allowed_fields = {
            "buy_intent_id",
            "exit_intent_id",
            "final_base_balance",
            "expected_base_dust",
            "duplicate_buy_count",
            "last_error",
        }
        changes = changes or {}
        if not expected_states or set(changes) - allowed_fields:
            raise ValueError("probe transition expected state/changes 非法")
        now = time.time()
        assignments = ["state=?", "version=version+1", "updated_at=?"]
        params: list[object] = [new_state, now]
        for key, value in changes.items():
            assignments.append(f"{key}=?")
            params.append(str(value) if isinstance(value, Decimal) else value)
        placeholders = ",".join("?" for _ in expected_states)
        params.extend(
            [
                probe_id,
                owner,
                fencing_token,
                now,
                *expected_states,
            ]
        )
        with self.transaction() as conn:
            cursor = conn.execute(
                f"""
                UPDATE probe_runs SET {", ".join(assignments)}
                WHERE probe_id=? AND lease_owner=? AND fencing_token=?
                  AND lease_expires_at>? AND state IN ({placeholders})
                """,
                params,
            )
            if cursor.rowcount != 1:
                raise RuntimeError("probe transition lease/fence/state 冲突")
        updated = self.get_probe_run(probe_id)
        assert updated is not None
        return updated

    def release_probe_lease(
        self,
        probe_id: str,
        *,
        owner: str,
        fencing_token: int,
    ) -> bool:
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE probe_runs
                SET lease_owner='', lease_expires_at=0,
                    version=version+1, updated_at=?
                WHERE probe_id=? AND lease_owner=? AND fencing_token=?
                """,
                (time.time(), probe_id, owner, fencing_token),
            )
        return cursor.rowcount == 1

    def create_order_intent(
        self,
        intent: OrderIntent,
        *,
        risk_guard: IntentRiskGuard | None = None,
        probe_lease_owner: str = "",
        probe_fencing_token: int = 0,
    ) -> OrderIntent:
        if intent.state is not OrderState.CREATED:
            raise ValueError("新订单意图必须从 CREATED 开始")
        persisted = intent.transition(
            OrderState.PERSISTED,
            created_at=intent.created_at or time.time(),
        )
        with self.transaction() as conn:
            if persisted.side == "buy" and persisted.source == "demo_validation_probe":
                self._assert_probe_order_capability_conn(
                    conn,
                    persisted,
                    owner=probe_lease_owner,
                    fencing_token=probe_fencing_token,
                    require_persisted_intent=False,
                )
            elif probe_lease_owner or probe_fencing_token:
                raise ValueError("非 Demo probe BUY 禁止携带 probe capability")
            if persisted.side == "buy" and risk_guard is not None:
                self._assert_buy_risk_guard_conn(
                    conn,
                    persisted,
                    risk_guard,
                )
            conn.execute(
                """
                INSERT INTO order_intents(
                    intent_id, cl_ord_id, decision_id, inst_id, side,
                    requested_base_qty, reserved_quote,
                    submission_reference_price,
                    requested_stop_loss, requested_take_profit,
                    state, exchange_ord_id,
                    exchange_state, acc_fill_qty, avg_fill_px, fee, fee_ccy,
                    source, probe_id, version, last_error_code,
                    last_error_message, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                self._intent_values(persisted),
            )
            conn.execute(
                """
                INSERT INTO order_events(
                    event_id, intent_id, state_from, state_to, payload_json, created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    uuid.uuid4().hex,
                    persisted.intent_id,
                    OrderState.CREATED.value,
                    OrderState.PERSISTED.value,
                    "{}",
                    time.time(),
                ),
            )
            if persisted.reserved_quote > 0 or persisted.side == "buy":
                conn.execute(
                    """
                    INSERT INTO risk_reservations(
                        reservation_id, intent_id, inst_id, reserved_quote,
                        reserved_slot, created_at
                    ) VALUES(?,?,?,?,1,?)
                    """,
                    (
                        uuid.uuid4().hex,
                        persisted.intent_id,
                        persisted.inst_id,
                        str(persisted.reserved_quote),
                        time.time(),
                    ),
                )
        return persisted

    @classmethod
    def _assert_probe_order_capability_conn(
        cls,
        conn: sqlite3.Connection,
        intent: OrderIntent,
        *,
        owner: str,
        fencing_token: int,
        require_persisted_intent: bool,
    ) -> None:
        now = time.time()
        row = conn.execute(
            """
            SELECT probe_id, account_uid, utc_day, slot, inst_id,
                   nominal_usdt, state, buy_cl_ord_id,
                   buy_intent_id, lease_owner, lease_expires_at, fencing_token
            FROM probe_runs WHERE probe_id=?
            """,
            (intent.probe_id,),
        ).fetchone()
        existing = conn.execute(
            """
            SELECT intent_id, cl_ord_id, inst_id FROM order_intents
            WHERE source='demo_validation_probe' AND side='buy' AND probe_id=?
            """,
            (intent.probe_id,),
        ).fetchall()
        binding = cls._formal_probe_schedule_binding_conn(conn)
        if row is not None and binding is not None:
            cls._assert_formal_probe_slot_conn(
                conn,
                account_uid=str(row["account_uid"]),
                soak_epoch_id=str(binding["soak_epoch_id"]),
                schedule_sha256=str(binding["schedule_sha256"]),
                utc_day=str(row["utc_day"]),
                slot=int(row["slot"]),
                inst_id=str(row["inst_id"]),
            )
        if (
            row is None
            or not owner
            or type(fencing_token) is not int
            or fencing_token <= 0
            or row["state"] != "BUY_SUBMITTING"
            or row["inst_id"] != intent.inst_id
            or row["buy_cl_ord_id"] != intent.cl_ord_id
            or row["buy_intent_id"] is not None
            or row["lease_owner"] != owner
            or int(row["fencing_token"]) != fencing_token
            or float(row["lease_expires_at"]) <= now
            or not Decimal("5") <= Decimal(str(row["nominal_usdt"])) <= Decimal("10")
            or (
                require_persisted_intent
                and (
                    len(existing) != 1
                    or existing[0]["cl_ord_id"] != intent.cl_ord_id
                    or existing[0]["inst_id"] != intent.inst_id
                )
            )
            or (not require_persisted_intent and existing)
        ):
            raise RuntimeError(
                "Demo probe BUY capability 与 durable saga state/lease/fence 不一致"
            )

    def assert_probe_order_capability(
        self,
        *,
        probe_id: str,
        owner: str,
        fencing_token: int,
        cl_ord_id: str,
        inst_id: str,
    ) -> None:
        """Recheck the same capability immediately before an exchange write."""
        intent = OrderIntent(
            intent_id="probe-pre-send",
            cl_ord_id=cl_ord_id,
            inst_id=inst_id,
            side="buy",
            requested_base_qty=Decimal("1"),
            source="demo_validation_probe",
            probe_id=probe_id,
        )
        with self._lock:
            self._assert_probe_order_capability_conn(
                self._conn,
                intent,
                owner=owner,
                fencing_token=fencing_token,
                require_persisted_intent=True,
            )

    @staticmethod
    def _assert_buy_risk_guard_conn(
        conn: sqlite3.Connection,
        intent: OrderIntent,
        guard: IntentRiskGuard,
    ) -> None:
        """在 BEGIN IMMEDIATE 内重验 mode/snapshot/pending/cash/slot/rate。"""
        state_rows = {
            row["key"]: row["value"]
            for row in conn.execute(
                """
                SELECT key, value FROM system_state
                WHERE key IN ('mode', 'mode_epoch')
                """
            ).fetchall()
        }
        if (
            state_rows.get("mode") != SystemMode.READY.value
            or int(state_rows.get("mode_epoch", "-1"))
            != guard.mode_epoch
        ):
            raise RuntimeError("BUY 持久化事务发现 mode/epoch 已变化")
        snapshot = conn.execute(
            """
            SELECT snapshot_id, available_quote, captured_at
            FROM account_snapshots
            ORDER BY captured_at DESC LIMIT 1
            """
        ).fetchone()
        if snapshot is None or snapshot["snapshot_id"] != guard.snapshot_id:
            raise RuntimeError("BUY 持久化事务发现账户快照版本已变化")
        snapshot_age = time.time() - float(snapshot["captured_at"])
        if (
            not math.isfinite(snapshot_age)
            or snapshot_age < -guard.max_snapshot_age_s
            or snapshot_age > guard.max_snapshot_age_s
        ):
            raise RuntimeError("BUY 持久化事务发现账户快照已过期")
        pending = conn.execute(
            """
            SELECT 1 FROM order_intents
            WHERE inst_id=?
              AND state NOT IN ('filled','canceled','rejected')
            LIMIT 1
            """,
            (intent.inst_id,),
        ).fetchone()
        if pending is not None:
            raise RuntimeError("BUY 持久化事务发现同交易对未决订单")
        recent_count = conn.execute(
            "SELECT COUNT(*) FROM order_intents WHERE created_at>=?",
            (time.time() - 3600,),
        ).fetchone()[0]
        if recent_count >= guard.max_order_intents_per_hour:
            raise RuntimeError("BUY 持久化事务发现每小时意图预算耗尽")
        reservations = conn.execute(
            """
            SELECT inst_id, reserved_quote
            FROM risk_reservations
            WHERE released_at IS NULL
            """
        ).fetchall()
        reserved_quote = sum(
            (
                parse_decimal_fact(
                    row["reserved_quote"],
                    "risk_reservations.reserved_quote",
                    nonnegative=True,
                )
                for row in reservations
            ),
            Decimal("0"),
        )
        available_quote = parse_decimal_fact(
            snapshot["available_quote"],
            "account_snapshots.available_quote",
            nonnegative=True,
        )
        if reserved_quote + intent.reserved_quote > available_quote:
            raise RuntimeError("BUY 持久化事务发现可用现金预算不足")
        occupied = {
            str(row["inst_id"])
            for row in reservations
        }
        for row in conn.execute(
            "SELECT inst_id, base_qty FROM positions"
        ).fetchall():
            if parse_decimal_fact(
                row["base_qty"],
                "positions.base_qty",
                nonnegative=True,
            ) > 0:
                occupied.add(str(row["inst_id"]))
        if (
            intent.inst_id not in occupied
            and len(occupied) >= guard.max_open_positions
        ):
            raise RuntimeError("BUY 持久化事务发现持仓槽位预算耗尽")

    def get_intent(self, intent_id: str) -> OrderIntent | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM order_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
        return self._row_to_intent(row) if row else None

    def find_intent(
        self, *, cl_ord_id: str = "", exchange_ord_id: str = ""
    ) -> OrderIntent | None:
        if not cl_ord_id and not exchange_ord_id:
            raise ValueError("至少提供 cl_ord_id 或 exchange_ord_id")
        column, value = (
            ("exchange_ord_id", exchange_ord_id)
            if exchange_ord_id
            else ("cl_ord_id", cl_ord_id)
        )
        with self._lock:
            row = self._conn.execute(
                f"SELECT * FROM order_intents WHERE {column}=?", (value,)
            ).fetchone()
        return self._row_to_intent(row) if row else None

    def update_intent(
        self,
        intent: OrderIntent,
        new_state: OrderState,
        *,
        fill_to_apply: Fill | None = None,
        **changes,
    ) -> OrderIntent:
        updated = intent.transition(new_state, **changes)
        with self.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE order_intents SET
                    state=?, exchange_ord_id=?, exchange_state=?, acc_fill_qty=?,
                    avg_fill_px=?, fee=?, fee_ccy=?, version=?,
                    last_error_code=?, last_error_message=?, updated_at=?
                WHERE intent_id=? AND version=?
                """,
                (
                    updated.state.value,
                    updated.exchange_ord_id or None,
                    updated.exchange_state,
                    str(updated.acc_fill_qty),
                    str(updated.avg_fill_px),
                    str(updated.fee),
                    updated.fee_ccy,
                    updated.version,
                    updated.last_error_code,
                    updated.last_error_message,
                    updated.updated_at,
                    updated.intent_id,
                    intent.version,
                ),
            )
            if cur.rowcount != 1:
                raise RuntimeError(f"订单意图并发更新冲突: {intent.intent_id}")
            conn.execute(
                """
                INSERT INTO order_events(
                    event_id, intent_id, state_from, state_to, payload_json, created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    uuid.uuid4().hex,
                    intent.intent_id,
                    intent.state.value,
                    updated.state.value,
                    json.dumps({
                        "exchange_ord_id": updated.exchange_ord_id,
                        "exchange_state": updated.exchange_state,
                        "acc_fill_qty": str(updated.acc_fill_qty),
                        "error_code": updated.last_error_code,
                    }, ensure_ascii=False),
                    time.time(),
                ),
            )
            if updated.state.is_terminal:
                conn.execute(
                    "UPDATE risk_reservations SET released_at=? "
                    "WHERE intent_id=? AND released_at IS NULL",
                    (time.time(), intent.intent_id),
                )
            if fill_to_apply is not None:
                self._insert_fill_and_project_conn(conn, fill_to_apply)
        return updated

    def apply_exchange_order(self, order: ExchangeOrder) -> tuple[OrderIntent, Decimal]:
        intent = (
            self.find_intent(exchange_ord_id=order.ord_id)
            if order.ord_id
            else None
        )
        if intent is None and order.cl_ord_id:
            intent = self.find_intent(cl_ord_id=order.cl_ord_id)
        if intent is None:
            raise KeyError(f"找不到交易所订单对应的本地意图: {order.ord_id}/{order.cl_ord_id}")
        if (
            order.ord_id
            and intent.exchange_ord_id
            and order.ord_id != intent.exchange_ord_id
        ):
            raise ValueError(
                "交易所 ordId 与本地 clOrdId 映射冲突: "
                f"{intent.exchange_ord_id} != {order.ord_id}"
            )

        if order.acc_fill_qty < intent.acc_fill_qty:
            # 乱序旧消息不能让累计成交倒退。
            return intent, Decimal("0")
        delta = order.acc_fill_qty - intent.acc_fill_qty
        fee_delta = (
            order.fee - intent.fee
            if order.fee_ccy == intent.fee_ccy or not intent.fee_ccy
            else Decimal("0")
        )
        if (
            intent.state.is_terminal
            and delta == 0
            and fee_delta == 0
        ):
            # 终态不能被迟到 live 消息倒退，但更高累计成交或费用修正仍必须投影。
            return intent, Decimal("0")

        target_state = order.state
        if intent.state.is_terminal or (
            target_state is OrderState.UNKNOWN
            and intent.state is not OrderState.UNKNOWN
        ):
            target_state = intent.state
        changes = {
            "exchange_ord_id": order.ord_id or intent.exchange_ord_id,
            "exchange_state": order.state.value,
            "acc_fill_qty": order.acc_fill_qty,
            "avg_fill_px": order.avg_fill_px or intent.avg_fill_px,
            "fee": order.fee,
            "fee_ccy": order.fee_ccy,
        }

        fill = None
        if delta > 0 or fee_delta != 0:
            cumulative_quote = order.acc_fill_qty * order.avg_fill_px
            prior_quote = intent.acc_fill_qty * intent.avg_fill_px
            delta_quote = cumulative_quote - prior_quote
            delta_fill_px = (
                delta_quote / delta
                if delta > 0 and delta_quote > 0
                else order.avg_fill_px
            )
            idempotency_key = (
                f"trade:{order.inst_id}:{order.trade_id}"
                if order.trade_id and delta > 0
                else (
                    f"order:{order.ord_id}:{order.acc_fill_qty}:{order.state.value}"
                    if delta > 0
                    else f"fee:{order.ord_id}:{order.fee}:{order.fee_ccy}"
                )
            )
            fill = Fill(
                fill_id=uuid.uuid4().hex,
                intent_id=intent.intent_id,
                exchange_ord_id=order.ord_id,
                inst_id=order.inst_id,
                side=order.side,
                fill_qty=delta,
                fill_px=delta_fill_px,
                fee=fee_delta,
                fee_ccy=order.fee_ccy,
                trade_id=order.trade_id,
                exchange_ts=order.update_ts,
                idempotency_key=idempotency_key,
            )
        # 状态、事件、reservation、fill 和 position 必须在同一事务提交。
        # 否则 ACK 后进程崩溃会留下“终态订单但无仓位投影”。
        updated = self.update_intent(
            intent,
            target_state,
            fill_to_apply=fill,
            **changes,
        )
        return updated, delta

    def _insert_fill_and_project(self, fill: Fill) -> None:
        with self.transaction() as conn:
            self._insert_fill_and_project_conn(conn, fill)

    def _insert_fill_and_project_conn(
        self, conn: sqlite3.Connection, fill: Fill
    ) -> None:
        cur = conn.execute(
                """
                INSERT OR IGNORE INTO fills(
                    fill_id, intent_id, exchange_ord_id, inst_id, side,
                    fill_qty, fill_px, fee, fee_ccy, trade_id, exchange_ts,
                    idempotency_key, created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    fill.fill_id,
                    fill.intent_id,
                    fill.exchange_ord_id,
                    fill.inst_id,
                    fill.side,
                    str(fill.fill_qty),
                    str(fill.fill_px),
                    str(fill.fee),
                    fill.fee_ccy,
                    fill.trade_id,
                    fill.exchange_ts,
                    fill.idempotency_key,
                    time.time(),
                ),
        )
        if cur.rowcount != 1:
            return
        row = conn.execute(
            "SELECT * FROM positions WHERE inst_id=?", (fill.inst_id,)
        ).fetchone()
        old_qty = to_decimal(row["base_qty"]) if row else Decimal("0")
        old_avg = to_decimal(row["avg_entry_px"]) if row else Decimal("0")
        old_realized = to_decimal(row["realized_pnl"]) if row else Decimal("0")
        new_qty, new_avg, new_realized = self._project_fill_values(
            old_qty=old_qty,
            old_avg=old_avg,
            old_realized=old_realized,
            inst_id=fill.inst_id,
            side=fill.side,
            fill_qty=fill.fill_qty,
            fill_px=fill.fill_px,
            fee=fill.fee,
            fee_ccy=fill.fee_ccy,
        )
        realized_delta = new_realized - old_realized
        now = time.time()
        conn.execute(
            """
            INSERT INTO positions(
                inst_id, base_qty, available_qty, avg_entry_px,
                realized_pnl, highest_since_entry, protection_status,
                version, updated_at
            ) VALUES(?,?,?,?,?,?,?,0,?)
            ON CONFLICT(inst_id) DO UPDATE SET
                base_qty=excluded.base_qty,
                available_qty=excluded.available_qty,
                avg_entry_px=excluded.avg_entry_px,
                realized_pnl=excluded.realized_pnl,
                version=positions.version + 1,
                updated_at=excluded.updated_at
            """,
            (
                fill.inst_id,
                str(new_qty),
                str(new_qty),
                str(new_avg),
                str(new_realized),
                str(new_avg),
                "",
                now,
            ),
        )
        if fill.side == "sell":
            conn.execute(
                """
                INSERT OR IGNORE INTO realized_pnl_events(
                    event_id, fill_id, inst_id, realized_pnl,
                    realized_at, created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    uuid.uuid4().hex,
                    fill.fill_id,
                    fill.inst_id,
                    str(realized_delta),
                    fill.exchange_ts if fill.exchange_ts > 0 else now,
                    now,
                ),
            )

    @staticmethod
    def _project_fill_values(
        *,
        old_qty: Decimal,
        old_avg: Decimal,
        old_realized: Decimal,
        inst_id: str,
        side: str,
        fill_qty: Decimal,
        fill_px: Decimal,
        fee: Decimal,
        fee_ccy: str,
    ) -> tuple[Decimal, Decimal, Decimal]:
        """Pure accounting reducer shared by live writes and ledger rebuilds."""
        base_ccy = inst_id.split("-")[0]
        quote_ccy = inst_id.split("-")[-1]
        if side == "buy":
            # OKX 的 fee 为有符号值（费用为负、返佣为正）。基础币种
            # 手续费必须进入净到账数量，否则退出会长期多记仓位。
            net_fill_qty = fill_qty
            if fee_ccy == base_ccy:
                net_fill_qty = (
                    fee
                    if fill_qty == 0
                    else max(fill_qty + fee, Decimal("0"))
                )
            new_qty = max(old_qty + net_fill_qty, Decimal("0"))
            new_avg = (
                ((old_qty * old_avg) + (fill_qty * fill_px)) / new_qty
                if new_qty > 0
                else Decimal("0")
            )
            new_realized = old_realized
        else:
            closed_qty = min(old_qty, fill_qty)
            new_qty = max(old_qty - fill_qty, Decimal("0"))
            new_avg = old_avg if new_qty > 0 else Decimal("0")
            quote_fee = fee if fee_ccy == quote_ccy else Decimal("0")
            new_realized = (
                old_realized
                + closed_qty * (fill_px - old_avg)
                + quote_fee
            )
        return new_qty, new_avg, new_realized

    def realized_pnl_since(self, since: float) -> Decimal:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT realized_pnl
                FROM realized_pnl_events
                WHERE realized_at >= ?
                """,
                (since,),
            ).fetchall()
        return sum(
            (to_decimal(row["realized_pnl"]) for row in rows),
            Decimal("0"),
        )

    def list_nonterminal_intents(self, inst_id: str = "") -> list[OrderIntent]:
        terminals = tuple(s.value for s in OrderState if s.is_terminal)
        placeholders = ",".join("?" for _ in terminals)
        sql = f"SELECT * FROM order_intents WHERE state NOT IN ({placeholders})"
        params: list[object] = list(terminals)
        if inst_id:
            sql += " AND inst_id=?"
            params.append(inst_id)
        sql += " ORDER BY created_at"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_intent(r) for r in rows]

    def import_external_order(
        self,
        order: ExchangeOrder,
        *,
        reserved_quote: Decimal = Decimal("0"),
    ) -> OrderIntent:
        """导入交易所存在但本地缺失的订单，冻结后交由对账解释。"""
        existing = (
            self.find_intent(exchange_ord_id=order.ord_id)
            if order.ord_id
            else None
        )
        if existing is None and order.cl_ord_id:
            existing = self.find_intent(cl_ord_id=order.cl_ord_id)
        if existing:
            return existing
        intent = OrderIntent(
            intent_id=uuid.uuid4().hex,
            cl_ord_id=order.cl_ord_id or f"EXT{uuid.uuid4().hex[:25].upper()}",
            inst_id=order.inst_id,
            side=order.side,
            requested_base_qty=order.requested_qty,
            reserved_quote=reserved_quote,
            state=OrderState.CREATED,
            last_error_code="EXTERNAL_ORDER",
            last_error_message=(
                "交易所订单不属于当前运行实例；终态前禁止自动放行新增风险"
            ),
            created_at=order.update_ts or time.time(),
        )
        intent = self.create_order_intent(intent)
        intent = self.update_intent(intent, OrderState.SUBMITTING)
        imported, _ = self.apply_exchange_order(order)
        return imported

    def get_position(self, inst_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM positions WHERE inst_id=?", (inst_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_positions(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM positions ORDER BY inst_id"
            ).fetchall()
        # SQLite REAL 是二进制浮点，极小或高精度仓位会被舍入。资金事实
        # 始终以 TEXT 取回后由 Decimal 比较。
        return [
            dict(row)
            for row in rows
            if parse_decimal_fact(
                row["base_qty"],
                "positions.base_qty",
                nonnegative=True,
            ) > 0
        ]

    def reconcile_position(
        self,
        inst_id: str,
        new_qty: Decimal,
        *,
        available_qty: Decimal | None = None,
        reference_price: Decimal = Decimal("0"),
        reason: str,
        run_id: str = "",
    ) -> None:
        new_qty = parse_decimal_fact(
            new_qty,
            "reconciliation.new_qty",
            nonnegative=True,
        )
        reference_price = parse_decimal_fact(
            reference_price,
            "reconciliation.reference_price",
            nonnegative=True,
        )
        available = parse_decimal_fact(
            new_qty if available_qty is None else available_qty,
            "reconciliation.available_qty",
            nonnegative=True,
        )
        if available > new_qty:
            raise ValueError("对账 available_qty 不能大于 new_qty")
        now = time.time()
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM positions WHERE inst_id=?", (inst_id,)
            ).fetchone()
            old_qty = to_decimal(row["base_qty"]) if row else Decimal("0")
            old_avg = to_decimal(row["avg_entry_px"]) if row else Decimal("0")
            old_realized = (
                to_decimal(row["realized_pnl"]) if row else Decimal("0")
            )
            avg = (
                old_avg
                if new_qty > 0 and old_avg > 0
                else reference_price if new_qty > 0 else Decimal("0")
            )
            conn.execute(
                """
                INSERT INTO positions(
                    inst_id, base_qty, available_qty, avg_entry_px,
                    realized_pnl, highest_since_entry, protection_status,
                    version, updated_at
                ) VALUES(?,?,?,?,?,?,?,0,?)
                ON CONFLICT(inst_id) DO UPDATE SET
                    base_qty=excluded.base_qty,
                    available_qty=excluded.available_qty,
                    avg_entry_px=excluded.avg_entry_px,
                    realized_pnl=excluded.realized_pnl,
                    version=positions.version + 1,
                    updated_at=excluded.updated_at
                """,
                (
                    inst_id,
                    str(new_qty),
                    str(available),
                    str(avg),
                    str(old_realized),
                    str(avg),
                    "",
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO reconciliation_adjustments(
                    adjustment_id, inst_id, old_qty, new_qty,
                    new_available_qty, new_avg_entry_px, new_realized_pnl,
                    snapshot_complete, reason, reconciliation_run_id,
                    created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    uuid.uuid4().hex,
                    inst_id,
                    str(old_qty),
                    str(new_qty),
                    str(available),
                    str(avg),
                    str(old_realized),
                    1,
                    reason,
                    run_id or None,
                    now,
                ),
            )

    def rebuild_position_projection(
        self,
        inst_id: str = "",
        *,
        apply: bool = False,
    ) -> dict:
        """Recompute accounting state from fills and reconciliation checkpoints.

        A repair is only permitted while risk taking is latched off.  Legacy
        adjustments without a complete accounting checkpoint make the result
        diagnostic-only; the method refuses to invent missing facts.
        """
        if apply:
            with self.transaction() as conn:
                mode_row = conn.execute(
                    "SELECT value FROM system_state WHERE key='mode'"
                ).fetchone()
                mode = SystemMode(
                    mode_row["value"] if mode_row else SystemMode.STARTING.value
                )
                if mode not in {SystemMode.MAINTENANCE, SystemMode.HALTED}:
                    raise RuntimeError(
                        "仓位投影修复只允许在 MAINTENANCE/HALTED 模式执行"
                    )
                report, projections = self._rebuild_projection_conn(
                    conn,
                    inst_id,
                )
                if not report:
                    raise RuntimeError("没有可重建的仓位事件")
                incomplete = [
                    item["inst_id"]
                    for item in report
                    if not item["complete"]
                ]
                if incomplete:
                    raise RuntimeError(
                        "历史事件不足，拒绝猜测仓位投影: "
                        + ",".join(incomplete)
                    )
                now = time.time()
                for instrument, projected in projections.items():
                    conn.execute(
                        """
                        INSERT INTO positions(
                            inst_id, base_qty, available_qty, avg_entry_px,
                            realized_pnl, highest_since_entry,
                            protection_status, version, updated_at
                        ) VALUES(?,?,?,?,?,?,?,0,?)
                        ON CONFLICT(inst_id) DO UPDATE SET
                            base_qty=excluded.base_qty,
                            available_qty=excluded.available_qty,
                            avg_entry_px=excluded.avg_entry_px,
                            realized_pnl=excluded.realized_pnl,
                            version=positions.version + 1,
                            updated_at=excluded.updated_at
                        """,
                        (
                            instrument,
                            str(projected["base_qty"]),
                            str(projected["available_qty"]),
                            str(projected["avg_entry_px"]),
                            str(projected["realized_pnl"]),
                            str(projected["avg_entry_px"]),
                            "",
                            now,
                        ),
                    )
                conn.execute(
                    """
                    INSERT INTO system_events(
                        event_id, event_name, severity, correlation_id,
                        payload_json, created_at
                    ) VALUES(?,?,?,?,?,?)
                    """,
                    (
                        uuid.uuid4().hex,
                        "position_projection_rebuilt",
                        "warning",
                        "",
                        json.dumps(
                            {
                                "inst_id": inst_id,
                                "instruments": sorted(projections),
                                "mode": mode.value,
                            },
                            ensure_ascii=False,
                        ),
                        now,
                    ),
                )
                for item in report:
                    item["matches_after_apply"] = True
                return {
                    "applied": True,
                    "complete": True,
                    "positions": report,
                }
        with self._lock:
            report, _ = self._rebuild_projection_conn(self._conn, inst_id)
        return {
            "applied": False,
            "complete": bool(report)
            and all(item["complete"] for item in report),
            "positions": report,
        }

    def _rebuild_projection_conn(
        self,
        conn: sqlite3.Connection,
        inst_id: str,
    ) -> tuple[list[dict], dict[str, dict[str, Decimal]]]:
        where = " WHERE inst_id=?" if inst_id else ""
        params = (inst_id,) if inst_id else ()
        fills = conn.execute(
            f"SELECT rowid AS source_rowid, * FROM fills{where}",
            params,
        ).fetchall()
        adjustments = conn.execute(
            "SELECT rowid AS source_rowid, * "
            f"FROM reconciliation_adjustments{where}",
            params,
        ).fetchall()
        current_rows = conn.execute(
            f"SELECT * FROM positions{where}",
            params,
        ).fetchall()
        current = {row["inst_id"]: row for row in current_rows}
        instruments = sorted(
            set(current)
            | {row["inst_id"] for row in fills}
            | {row["inst_id"] for row in adjustments}
        )
        projections: dict[str, dict[str, Decimal]] = {}
        reports: list[dict] = []
        for instrument in instruments:
            state = {
                "base_qty": Decimal("0"),
                "available_qty": Decimal("0"),
                "avg_entry_px": Decimal("0"),
                "realized_pnl": Decimal("0"),
            }
            events: list[tuple[float, int, int, str, sqlite3.Row]] = []
            events.extend(
                (
                    float(row["created_at"]),
                    0,
                    int(row["source_rowid"]),
                    "fill",
                    row,
                )
                for row in fills
                if row["inst_id"] == instrument
            )
            events.extend(
                (
                    float(row["created_at"]),
                    1,
                    int(row["source_rowid"]),
                    "adjustment",
                    row,
                )
                for row in adjustments
                if row["inst_id"] == instrument
            )
            complete = bool(events)
            for _, _, _, event_kind, row in sorted(events):
                if event_kind == "fill":
                    qty = parse_decimal_fact(
                        row["fill_qty"],
                        "fills.fill_qty",
                        nonnegative=True,
                    )
                    price = parse_decimal_fact(
                        row["fill_px"],
                        "fills.fill_px",
                        nonnegative=True,
                    )
                    fee = parse_decimal_fact(row["fee"], "fills.fee")
                    (
                        state["base_qty"],
                        state["avg_entry_px"],
                        state["realized_pnl"],
                    ) = self._project_fill_values(
                        old_qty=state["base_qty"],
                        old_avg=state["avg_entry_px"],
                        old_realized=state["realized_pnl"],
                        inst_id=instrument,
                        side=row["side"],
                        fill_qty=qty,
                        fill_px=price,
                        fee=fee,
                        fee_ccy=row["fee_ccy"],
                    )
                    state["available_qty"] = state["base_qty"]
                    continue
                if int(row["snapshot_complete"]) != 1:
                    complete = False
                state["base_qty"] = parse_decimal_fact(
                    row["new_qty"],
                    "reconciliation_adjustments.new_qty",
                    nonnegative=True,
                )
                state["available_qty"] = parse_decimal_fact(
                    row["new_available_qty"],
                    "reconciliation_adjustments.new_available_qty",
                    nonnegative=True,
                )
                state["avg_entry_px"] = parse_decimal_fact(
                    row["new_avg_entry_px"],
                    "reconciliation_adjustments.new_avg_entry_px",
                    nonnegative=True,
                )
                state["realized_pnl"] = parse_decimal_fact(
                    row["new_realized_pnl"],
                    "reconciliation_adjustments.new_realized_pnl",
                )
                if state["available_qty"] > state["base_qty"]:
                    raise RuntimeError(
                        f"{instrument} 对账检查点 available_qty > base_qty"
                    )
            projections[instrument] = state
            existing = current.get(instrument)
            current_state = {
                field: (
                    parse_decimal_fact(
                        existing[field],
                        f"positions.{field}",
                        nonnegative=field != "realized_pnl",
                    )
                    if existing
                    else Decimal("0")
                )
                for field in state
            }
            reports.append(
                {
                    "inst_id": instrument,
                    "complete": complete,
                    "source_event_count": len(events),
                    "matches": current_state == state,
                    "current": {
                        key: str(value)
                        for key, value in current_state.items()
                    },
                    "projected": {
                        key: str(value) for key, value in state.items()
                    },
                }
            )
        return reports, projections

    def record_account_snapshot(
        self,
        *,
        total_equity_quote: Decimal,
        available_quote: Decimal,
        holdings: list[dict],
        source: str,
    ) -> str:
        snapshot_id = uuid.uuid4().hex
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO account_snapshots(
                    snapshot_id, total_equity_quote, available_quote,
                    holdings_json, source, captured_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    snapshot_id,
                    str(total_equity_quote),
                    str(available_quote),
                    json.dumps(holdings, ensure_ascii=False, default=str),
                    source,
                    time.time(),
                ),
            )
        return snapshot_id

    def start_reconciliation(self) -> str:
        run_id = uuid.uuid4().hex
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO reconciliation_runs(
                    run_id, status, mismatch_count, repaired_count,
                    details_json, started_at
                ) VALUES(?, 'running', 0, 0, '{}', ?)
                """,
                (run_id, time.time()),
            )
        return run_id

    def finish_reconciliation(
        self,
        run_id: str,
        *,
        status: str,
        mismatch_count: int,
        repaired_count: int,
        details: dict,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE reconciliation_runs SET
                    status=?, mismatch_count=?, repaired_count=?,
                    details_json=?, completed_at=?
                WHERE run_id=?
                """,
                (
                    status,
                    mismatch_count,
                    repaired_count,
                    json.dumps(details, ensure_ascii=False, default=str),
                    time.time(),
                    run_id,
                ),
            )

    def enqueue_outbox(self, event_name: str, payload: dict) -> str:
        event_id = uuid.uuid4().hex
        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO outbox_events(
                    event_id, event_name, payload_json, created_at
                ) VALUES(?,?,?,?)
                """,
                (
                    event_id,
                    event_name,
                    json.dumps(payload, ensure_ascii=False, default=str),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO alert_deliveries(
                    event_id, priority, state, next_attempt_at,
                    created_at, updated_at
                ) VALUES(?,?, 'pending', ?, ?, ?)
                """,
                (
                    event_id,
                    "P0" if event_name.startswith("page.") else "P1",
                    now,
                    now,
                    now,
                ),
            )
        return event_id

    def enqueue_outbox_once(
        self,
        deduplication_key: str,
        event_name: str,
        payload: dict,
    ) -> str:
        if not deduplication_key:
            raise ValueError("outbox deduplication_key 不能为空")
        event_id = hashlib.sha256(
            f"outbox:{deduplication_key}".encode()
        ).hexdigest()
        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO outbox_events(
                    event_id, event_name, payload_json, created_at
                ) VALUES(?,?,?,?)
                """,
                (
                    event_id,
                    event_name,
                    json.dumps(payload, ensure_ascii=False, default=str),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO alert_deliveries(
                    event_id, priority, state, next_attempt_at,
                    created_at, updated_at
                ) VALUES(?,?, 'pending', ?, ?, ?)
                """,
                (
                    event_id,
                    "P0" if event_name.startswith("page.") else "P1",
                    now,
                    now,
                    now,
                ),
            )
        return event_id

    def get_unpublished_outbox(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM outbox_events
                WHERE published_at IS NULL
                ORDER BY created_at LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_outbox_published(self, event_id: str) -> None:
        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                "UPDATE outbox_events SET published_at=? WHERE event_id=?",
                (now, event_id),
            )
            conn.execute(
                """
                UPDATE alert_deliveries
                SET state=CASE
                        WHEN state IN ('pending', 'retry') THEN 'ingested'
                        ELSE state
                    END,
                    ingestion_accepted_at=COALESCE(
                        ingestion_accepted_at, ?
                    ),
                    updated_at=?
                WHERE event_id=?
                """,
                (now, now, event_id),
            )

    def get_due_alerts(
        self,
        *,
        now: float | None = None,
        limit: int = 100,
    ) -> list[dict]:
        current = time.time() if now is None else now
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT o.event_id, o.event_name, o.payload_json, o.created_at,
                       d.priority, d.state, d.attempt_count,
                       d.next_attempt_at
                FROM outbox_events AS o
                JOIN alert_deliveries AS d USING(event_id)
                WHERE o.published_at IS NULL
                  AND d.state IN ('pending', 'retry')
                  AND d.next_attempt_at <= ?
                ORDER BY d.next_attempt_at, o.created_at
                LIMIT ?
                """,
                (current, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_alert_attempt(
        self,
        event_id: str,
        *,
        started_at: float,
        completed_at: float,
        http_status: int | None,
        ingestion_accepted: bool,
        error: str = "",
        max_attempts: int = 8,
    ) -> dict:
        if (
            not event_id
            or isinstance(started_at, bool)
            or isinstance(completed_at, bool)
            or completed_at < started_at
            or type(ingestion_accepted) is not bool
            or type(max_attempts) is not int
            or max_attempts < 1
        ):
            raise ValueError("alert delivery attempt 参数非法")
        if (
            http_status is not None
            and (type(http_status) is not int or not 100 <= http_status <= 599)
        ):
            raise ValueError("alert HTTP status 非法")
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM alert_deliveries WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"未知 alert event_id: {event_id}")
            if row["state"] not in {"pending", "retry"}:
                return dict(row)
            attempt_no = int(row["attempt_count"]) + 1
            conn.execute(
                """
                INSERT INTO alert_delivery_attempts(
                    attempt_id, event_id, attempt_no, started_at,
                    completed_at, http_status, ingestion_accepted, error
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    uuid.uuid4().hex,
                    event_id,
                    attempt_no,
                    started_at,
                    completed_at,
                    http_status,
                    int(ingestion_accepted),
                    error[:1000],
                ),
            )
            if ingestion_accepted:
                state = "ingested"
                next_attempt = completed_at
                dlq_at = None
                conn.execute(
                    "UPDATE outbox_events SET published_at=? WHERE event_id=?",
                    (completed_at, event_id),
                )
            elif attempt_no >= max_attempts:
                state = "dlq"
                next_attempt = completed_at
                dlq_at = completed_at
            else:
                state = "retry"
                deterministic_jitter = (
                    int(hashlib.sha256(event_id.encode()).hexdigest()[:4], 16)
                    % 1000
                ) / 1000
                next_attempt = completed_at + min(
                    2 ** min(attempt_no, 8) + deterministic_jitter,
                    300,
                )
                dlq_at = None
            conn.execute(
                """
                UPDATE alert_deliveries
                SET state=?, attempt_count=?, next_attempt_at=?,
                    ingestion_accepted_at=CASE
                        WHEN ? THEN ? ELSE ingestion_accepted_at
                    END,
                    last_http_status=?, last_error=?, dlq_at=?,
                    updated_at=?
                WHERE event_id=?
                """,
                (
                    state,
                    attempt_no,
                    next_attempt,
                    int(ingestion_accepted),
                    completed_at,
                    http_status,
                    error[:1000],
                    dlq_at,
                    completed_at,
                    event_id,
                ),
            )
            updated = conn.execute(
                "SELECT * FROM alert_deliveries WHERE event_id=?",
                (event_id,),
            ).fetchone()
        return dict(updated)

    def record_alert_provider_received(
        self,
        event_id: str,
        *,
        provider_received_at: float,
        provider_event_id: str,
        artifact_sha256: str,
    ) -> dict:
        if (
            not provider_event_id.strip()
            or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)
        ):
            raise ValueError("provider receipt identity 非法")
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM alert_deliveries WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"未知 alert event_id: {event_id}")
            if (
                isinstance(provider_received_at, bool)
                or not isinstance(provider_received_at, (int, float))
                or provider_received_at < float(row["created_at"])
                or provider_received_at > time.time() + 300
            ):
                raise ValueError("provider received 时间非法")
            if row["provider_received_at"] is not None and (
                float(row["provider_received_at"]) != provider_received_at
                or row["provider_event_id"] != provider_event_id
                or row["provider_artifact_sha256"] != artifact_sha256
            ):
                raise RuntimeError("provider receipt 与已锁存事实冲突")
            state = (
                "acknowledged"
                if row["human_ack_at"] is not None
                else "provider_received"
            )
            conn.execute(
                """
                UPDATE alert_deliveries
                SET state=?, provider_received_at=?, provider_event_id=?,
                    provider_artifact_sha256=?, updated_at=?
                WHERE event_id=?
                """,
                (
                    state,
                    provider_received_at,
                    provider_event_id,
                    artifact_sha256,
                    time.time(),
                    event_id,
                ),
            )
            updated = conn.execute(
                "SELECT * FROM alert_deliveries WHERE event_id=?",
                (event_id,),
            ).fetchone()
        return dict(updated)

    def record_alert_human_ack(
        self,
        event_id: str,
        *,
        human_ack_at: float,
        actor: str,
        artifact_sha256: str,
    ) -> dict:
        if (
            not actor.strip()
            or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)
        ):
            raise ValueError("human ack identity 非法")
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM alert_deliveries WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"未知 alert event_id: {event_id}")
            if row["provider_received_at"] is None:
                raise RuntimeError("human ack 不能先于 provider_received")
            if (
                isinstance(human_ack_at, bool)
                or not isinstance(human_ack_at, (int, float))
                or human_ack_at < float(row["provider_received_at"])
                or human_ack_at > time.time() + 300
            ):
                raise ValueError("human ack 时间非法")
            if row["human_ack_at"] is not None and (
                float(row["human_ack_at"]) != human_ack_at
                or row["human_ack_actor"] != actor
                or row["human_ack_artifact_sha256"] != artifact_sha256
            ):
                raise RuntimeError("human ack 与已锁存事实冲突")
            conn.execute(
                """
                UPDATE alert_deliveries
                SET state='acknowledged', human_ack_at=?,
                    human_ack_actor=?, human_ack_artifact_sha256=?,
                    updated_at=?
                WHERE event_id=?
                """,
                (
                    human_ack_at,
                    actor,
                    artifact_sha256,
                    time.time(),
                    event_id,
                ),
            )
            updated = conn.execute(
                "SELECT * FROM alert_deliveries WHERE event_id=?",
                (event_id,),
            ).fetchone()
        return dict(updated)

    def record_alert_escalation(
        self,
        event_id: str,
        *,
        escalation_at: float | None = None,
    ) -> dict:
        occurred = time.time() if escalation_at is None else escalation_at
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM alert_deliveries WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"未知 alert event_id: {event_id}")
            if row["human_ack_at"] is not None:
                raise RuntimeError("已人工 ACK 的告警不得标记无人响应升级")
            conn.execute(
                """
                UPDATE alert_deliveries
                SET state='escalated', escalation_at=COALESCE(
                    escalation_at, ?
                ), updated_at=?
                WHERE event_id=?
                """,
                (occurred, time.time(), event_id),
            )
            updated = conn.execute(
                "SELECT * FROM alert_deliveries WHERE event_id=?",
                (event_id,),
            ).fetchone()
        return dict(updated)

    def list_alert_deliveries(
        self,
        *,
        started_at: float = 0,
        ended_at: float = float("inf"),
    ) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM alert_deliveries
                WHERE created_at >= ? AND created_at < ?
                ORDER BY created_at, event_id
                """,
                (started_at, ended_at),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_mode(
        self,
        mode: SystemMode,
        *,
        allow_hard_release: bool = False,
        expected_hard_epoch: int | None = None,
        reason: str = "",
    ) -> bool:
        hard_modes = {
            SystemMode.HALTED,
            SystemMode.EMERGENCY_EXIT,
            SystemMode.MAINTENANCE,
        }
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT value, updated_at FROM system_state WHERE key='mode'"
            ).fetchone()
            epoch_row = conn.execute(
                "SELECT value FROM system_state WHERE key='mode_epoch'"
            ).fetchone()
            current = (
                SystemMode(row["value"]) if row else SystemMode.STARTING
            )
            changed_at = time.time()
            previous_updated_at = (
                float(row["updated_at"]) if row is not None else changed_at
            )
            epoch = int(epoch_row["value"]) if epoch_row else 0
            if allow_hard_release and expected_hard_epoch is None:
                raise ValueError("硬状态释放必须携带 expected_hard_epoch")
            if (
                expected_hard_epoch is not None
                and epoch != expected_hard_epoch
            ):
                return False
            if (
                current in hard_modes
                and mode not in hard_modes
                and not allow_hard_release
            ):
                return False
            if (
                current in {
                    SystemMode.EMERGENCY_EXIT,
                    SystemMode.MAINTENANCE,
                }
                and mode is SystemMode.HALTED
                and not allow_hard_release
            ):
                # A generic halt must not erase an emergency-exit workflow or
                # an explicit maintenance latch.
                return False
            conn.execute(
                """
                INSERT INTO system_state(key, value, updated_at) VALUES('mode', ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (mode.value, changed_at),
            )
            conn.execute(
                """
                INSERT INTO system_state(key, value, updated_at)
                VALUES('mode_reason', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value, updated_at=excluded.updated_at
                """,
                (reason or "runtime_transition", changed_at),
            )
            if mode in hard_modes:
                conn.execute(
                    """
                    INSERT INTO system_state(key, value, updated_at)
                    VALUES('mode_epoch', ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value=excluded.value, updated_at=excluded.updated_at
                    """,
                    (str(epoch + 1), changed_at),
                )
            if current is not mode:
                conn.execute(
                    """
                    INSERT INTO system_events(
                        event_id, event_name, severity, correlation_id,
                        payload_json, created_at
                    ) VALUES(?,?,?,?,?,?)
                    """,
                    (
                        uuid.uuid4().hex,
                        "runtime_readiness_transition",
                        "info",
                        "",
                        json.dumps(
                            {
                                "old_mode": current.value,
                                "new_mode": mode.value,
                                "reason": reason or "runtime_transition",
                                "previous_mode_duration_seconds": max(
                                    changed_at - previous_updated_at,
                                    0,
                                ),
                            },
                            ensure_ascii=False,
                        ),
                        changed_at,
                    ),
                )
            return True

    def get_mode_state(self) -> tuple[SystemMode, int]:
        with self._lock:
            rows = {
                row["key"]: row["value"]
                for row in self._conn.execute(
                    """
                    SELECT key, value FROM system_state
                    WHERE key IN ('mode', 'mode_epoch')
                    """
                ).fetchall()
            }
        return (
            SystemMode(rows.get("mode", SystemMode.STARTING.value)),
            int(rows.get("mode_epoch", "0")),
        )

    def get_mode_reason(self) -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM system_state WHERE key='mode_reason'"
            ).fetchone()
        return str(row["value"]) if row else ""

    def get_mode(self) -> SystemMode:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM system_state WHERE key='mode'"
            ).fetchone()
        return SystemMode(row["value"]) if row else SystemMode.STARTING

    def create_protection(self, protection) -> object:

        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO protective_orders(
                    protection_id, inst_id, kind, protected_qty, trigger_px,
                    take_profit_px, order_px, state, algo_cl_ord_id, exchange_algo_id,
                    parent_intent_id, version, last_error, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    protection.protection_id,
                    protection.inst_id,
                    protection.kind,
                    str(protection.protected_qty),
                    str(protection.trigger_px),
                    str(protection.take_profit_px),
                    str(protection.order_px),
                    protection.state.value,
                    protection.algo_cl_ord_id,
                    protection.exchange_algo_id or None,
                    protection.parent_intent_id or None,
                    protection.version,
                    protection.last_error,
                    protection.created_at or now,
                    protection.updated_at or now,
                ),
            )
        return protection

    def update_protection(
        self,
        protection,
        *,
        state,
        exchange_algo_id: str | None = None,
        protected_qty: Decimal | None = None,
        trigger_px: Decimal | None = None,
        take_profit_px: Decimal | None = None,
        last_error: str | None = None,
    ):

        updated = protection.transition(
            state,
            exchange_algo_id=(
                exchange_algo_id
                if exchange_algo_id is not None
                else protection.exchange_algo_id
            ),
            protected_qty=(
                protected_qty if protected_qty is not None else protection.protected_qty
            ),
            trigger_px=trigger_px if trigger_px is not None else protection.trigger_px,
            take_profit_px=(
                take_profit_px
                if take_profit_px is not None
                else protection.take_profit_px
            ),
            last_error=last_error if last_error is not None else protection.last_error,
        )
        with self.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE protective_orders SET
                    protected_qty=?, trigger_px=?, take_profit_px=?,
                    state=?, exchange_algo_id=?,
                    version=?, last_error=?, updated_at=?
                WHERE protection_id=? AND version=?
                """,
                (
                    str(updated.protected_qty),
                    str(updated.trigger_px),
                    str(updated.take_profit_px),
                    updated.state.value,
                    updated.exchange_algo_id or None,
                    updated.version,
                    updated.last_error,
                    updated.updated_at,
                    updated.protection_id,
                    protection.version,
                ),
            )
            if cur.rowcount != 1:
                raise RuntimeError(
                    f"保护单并发更新冲突: {protection.protection_id}"
                )
            conn.execute(
                "UPDATE positions SET protection_status=?, updated_at=? WHERE inst_id=?",
                (updated.state.value, time.time(), updated.inst_id),
            )
        return updated

    def find_protection(
        self,
        *,
        protection_id: str = "",
        algo_cl_ord_id: str = "",
        exchange_algo_id: str = "",
    ):
        from okx_quant.domain.orders import ProtectionOrder, ProtectionState

        filters = [
            ("protection_id", protection_id),
            ("exchange_algo_id", exchange_algo_id),
            ("algo_cl_ord_id", algo_cl_ord_id),
        ]
        selected = [(column, value) for column, value in filters if value]
        if not selected:
            raise ValueError("需要保护单标识")
        where = " OR ".join(f"{column}=?" for column, _ in selected)
        with self._lock:
            row = self._conn.execute(
                f"SELECT * FROM protective_orders WHERE {where} LIMIT 1",
                tuple(value for _, value in selected),
            ).fetchone()
        if not row:
            return None
        return ProtectionOrder(
            protection_id=row["protection_id"],
            inst_id=row["inst_id"],
            kind=row["kind"],
            protected_qty=to_decimal(row["protected_qty"]),
            trigger_px=to_decimal(row["trigger_px"]),
            take_profit_px=to_decimal(row["take_profit_px"]),
            order_px=to_decimal(row["order_px"]),
            state=ProtectionState(row["state"]),
            algo_cl_ord_id=row["algo_cl_ord_id"],
            exchange_algo_id=row["exchange_algo_id"] or "",
            parent_intent_id=row["parent_intent_id"] or "",
            version=int(row["version"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            last_error=row["last_error"],
        )

    def list_protections(self, inst_id: str = "", *, active_only: bool = False) -> list:
        sql = "SELECT protection_id FROM protective_orders WHERE 1=1"
        params: list[object] = []
        if inst_id:
            sql += " AND inst_id=?"
            params.append(inst_id)
        if active_only:
            sql += " AND state IN ('required','submitting','active','amending','unknown')"
        sql += " ORDER BY created_at"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [
            self.find_protection(protection_id=row["protection_id"])
            for row in rows
        ]

    def has_active_protection(
        self, inst_id: str, required_qty: Decimal = Decimal("0")
    ) -> bool:
        protections = self.list_protections(inst_id, active_only=True)
        return (
            len(protections) == 1
            and protections[0].state.value == "active"
            and protections[0].protected_qty == required_qty
        )

    def record_event(
        self,
        event_name: str,
        *,
        severity: str = "info",
        correlation_id: str = "",
        payload: dict | None = None,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    uuid.uuid4().hex,
                    event_name,
                    severity,
                    correlation_id,
                    json.dumps(payload or {}, ensure_ascii=False, default=str),
                    time.time(),
                ),
            )

    def record_event_once(
        self,
        deduplication_key: str,
        event_name: str,
        *,
        severity: str = "info",
        correlation_id: str = "",
        payload: dict | None = None,
    ) -> bool:
        """Persist an immutable fact exactly once across crash replays."""
        if not deduplication_key:
            raise ValueError("event deduplication_key 不能为空")
        event_id = hashlib.sha256(
            f"system-event:{deduplication_key}".encode()
        ).hexdigest()
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO system_events(
                    event_id, event_name, severity, correlation_id,
                    payload_json, created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    event_id,
                    event_name,
                    severity,
                    correlation_id,
                    json.dumps(
                        payload or {},
                        ensure_ascii=False,
                        default=str,
                    ),
                    time.time(),
                ),
            )
        return cursor.rowcount == 1

    def list_events(
        self,
        event_name: str = "",
        *,
        since: float = 0,
    ) -> list[dict]:
        query = "SELECT * FROM system_events WHERE created_at >= ?"
        params: list[object] = [since]
        if event_name:
            query += " AND event_name = ?"
            params.append(event_name)
        query += " ORDER BY created_at, event_id"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            result.append(item)
        return result

    def latest_event(self, event_name: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM system_events
                WHERE event_name=?
                ORDER BY created_at DESC, event_id DESC
                LIMIT 1
                """,
                (event_name,),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        return item

    def acquire_exit_lease(self, inst_id: str, owner_id: str, ttl_s: float = 30) -> bool:
        now = time.time()
        with self.transaction() as conn:
            conn.execute("DELETE FROM exit_leases WHERE expires_at<=?", (now,))
            try:
                conn.execute(
                    "INSERT INTO exit_leases(inst_id, owner_id, expires_at, created_at) "
                    "VALUES(?,?,?,?)",
                    (inst_id, owner_id, now + ttl_s, now),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def owns_exit_lease(self, inst_id: str, owner_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT 1 FROM exit_leases
                WHERE inst_id=? AND owner_id=? AND expires_at>?
                """,
                (inst_id, owner_id, time.time()),
            ).fetchone()
        return row is not None

    def release_exit_lease(self, inst_id: str, owner_id: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "DELETE FROM exit_leases WHERE inst_id=? AND owner_id=?",
                (inst_id, owner_id),
            )

    def backup(self, destination: str | Path) -> None:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(str(destination))
        try:
            with self._lock:
                self._conn.backup(target)
        finally:
            target.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _intent_values(intent: OrderIntent) -> tuple:
        return (
            intent.intent_id,
            intent.cl_ord_id,
            intent.decision_id or None,
            intent.inst_id,
            intent.side,
            str(intent.requested_base_qty),
            str(intent.reserved_quote),
            str(intent.submission_reference_price),
            str(intent.requested_stop_loss),
            str(intent.requested_take_profit),
            intent.state.value,
            intent.exchange_ord_id or None,
            intent.exchange_state,
            str(intent.acc_fill_qty),
            str(intent.avg_fill_px),
            str(intent.fee),
            intent.fee_ccy,
            intent.source,
            intent.probe_id,
            intent.version,
            intent.last_error_code,
            intent.last_error_message,
            intent.created_at,
            intent.updated_at,
        )

    @staticmethod
    def _row_to_intent(row: sqlite3.Row) -> OrderIntent:
        return OrderIntent(
            intent_id=row["intent_id"],
            cl_ord_id=row["cl_ord_id"],
            decision_id=row["decision_id"] or "",
            inst_id=row["inst_id"],
            side=row["side"],
            requested_base_qty=to_decimal(row["requested_base_qty"]),
            reserved_quote=to_decimal(row["reserved_quote"]),
            submission_reference_price=to_decimal(
                row["submission_reference_price"]
            ),
            requested_stop_loss=to_decimal(row["requested_stop_loss"]),
            requested_take_profit=to_decimal(row["requested_take_profit"]),
            state=OrderState(row["state"]),
            exchange_ord_id=row["exchange_ord_id"] or "",
            exchange_state=row["exchange_state"],
            acc_fill_qty=to_decimal(row["acc_fill_qty"]),
            avg_fill_px=to_decimal(row["avg_fill_px"]),
            fee=to_decimal(row["fee"]),
            fee_ccy=row["fee_ccy"],
            source=row["source"],
            probe_id=row["probe_id"],
            version=int(row["version"]),
            last_error_code=row["last_error_code"],
            last_error_message=row["last_error_message"],
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
        )
