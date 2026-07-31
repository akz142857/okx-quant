#!/usr/bin/env python3
"""Run the Web Dashboard with isolated, continuously updated synthetic data."""

from __future__ import annotations

import argparse
import math
import tempfile
import threading
import time
import uuid
from decimal import Decimal
from pathlib import Path

from okx_quant.domain.orders import SystemMode
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.web_dashboard import DashboardReadModel
from okx_quant.web_dashboard.server import DashboardServer


def _seed_preview(journal: SQLiteJournal, *, now: float | None = None) -> None:
    current = time.time() if now is None else now
    journal.initialize_identity(
        account_id="synthetic-preview-account",
        initial_config_hash="d" * 64,
        actor="dashboard-preview",
    )
    if not journal.set_mode(
        SystemMode.READY,
        allow_hard_release=True,
        expected_hard_epoch=1,
        reason="synthetic_preview_running",
    ):
        raise RuntimeError("无法把合成预览账本切换到 READY")

    with journal.transaction() as connection:
        connection.execute(
            """
            INSERT INTO system_state(key, value, updated_at)
            VALUES('dashboard_data_class', 'synthetic_preview', ?)
            """,
            (current,),
        )

    for index in range(48):
        phase = index / 5
        equity = Decimal("5000") + Decimal(str(index * 0.18 + math.sin(phase) * 2.4))
        available = equity - Decimal("24.75")
        snapshot_id = journal.record_account_snapshot(
            total_equity_quote=equity,
            available_quote=available,
            holdings=[
                {"ccy": "USDT", "balance": str(available)},
                {"ccy": "DOGE", "balance": "350"},
            ],
            source="synthetic_preview",
        )
        with journal.transaction() as connection:
            connection.execute(
                "UPDATE account_snapshots SET captured_at=? WHERE snapshot_id=?",
                (current - (47 - index) * 300, snapshot_id),
            )

    journal.reconcile_position(
        "DOGE-USDT",
        Decimal("350"),
        available_qty=Decimal("350"),
        reference_price=Decimal("0.0707"),
        reason="synthetic_preview",
    )
    journal.reconcile_position(
        "BTC-USDT",
        Decimal("0.00035"),
        available_qty=Decimal("0.00035"),
        reference_price=Decimal("117500"),
        reason="synthetic_preview",
    )

    with journal.transaction() as connection:
        position_rows = (
            ("DOGE-USDT", "oco", "350", "0.0685", "0.0752", "active"),
            ("BTC-USDT", "conditional", "0.00035", "114800", "122000", "active"),
        )
        for index, row in enumerate(position_rows, start=1):
            inst_id, kind, quantity, stop, take, state = row
            connection.execute(
                """
                INSERT INTO protective_orders(
                    protection_id, inst_id, kind, protected_qty, trigger_px,
                    take_profit_px, state, algo_cl_ord_id, exchange_algo_id,
                    created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    f"preview-protection-{index}",
                    inst_id,
                    kind,
                    quantity,
                    stop,
                    take,
                    state,
                    f"preview-algo-client-{index}",
                    f"preview-algo-exchange-{index}",
                    current - 1400,
                    current - 18,
                ),
            )
            connection.execute(
                """
                UPDATE positions
                SET protection_status='active', updated_at=?
                WHERE inst_id=?
                """,
                (current - 18, inst_id),
            )

        orders = (
            ("DOGE-USDT", "buy", "350", "filled", "350", "0.0707", "", ""),
            ("BTC-USDT", "buy", "0.00035", "filled", "0.00035", "117500", "", ""),
            ("DOGE-USDT", "sell", "120", "filled", "120", "0.0714", "", ""),
            ("ETH-USDT", "buy", "0.01", "rejected", "0", "0", "51020", "Order quantity below minimum"),
            ("BTC-USDT", "sell", "0.0001", "live", "0", "0", "", ""),
        )
        for index, order in enumerate(orders, start=1):
            inst_id, side, quantity, state, filled, price, code, message = order
            connection.execute(
                """
                INSERT INTO order_intents(
                    intent_id, cl_ord_id, inst_id, side,
                    requested_base_qty, state, exchange_ord_id,
                    exchange_state, acc_fill_qty, avg_fill_px,
                    fee, fee_ccy, source, last_error_code,
                    last_error_message, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    f"preview-intent-{index}",
                    f"preview-client-order-{index}",
                    inst_id,
                    side,
                    quantity,
                    state,
                    f"preview-exchange-order-{index}",
                    state,
                    filled,
                    price,
                    "-0.001",
                    "USDT",
                    "synthetic_preview",
                    code,
                    message,
                    current - (6 - index) * 780,
                    current - (6 - index) * 180,
                ),
            )

        connection.execute(
            """
            INSERT INTO reconciliation_runs(
                run_id, status, mismatch_count, repaired_count,
                details_json, started_at, completed_at
            ) VALUES(?, 'completed', 0, 0, '{}', ?, ?)
            """,
            ("preview-reconciliation", current - 42, current - 41),
        )

    events = (
        ("websocket_subscription_ready", "info", {"channel": "public", "latency_ms": 76}),
        ("account_snapshot_refreshed", "info", {"equity": "5007.42", "source": "synthetic"}),
        ("protection_order_verified", "info", {"inst_id": "DOGE-USDT", "state": "active"}),
        ("reconciliation_completed", "info", {"mismatches": 0, "repaired": 0}),
        ("market_data_freshness_warning", "warning", {"age_ms": 1240, "budget_ms": 1000}),
    )
    for name, severity, payload in events:
        journal.record_event(name, severity=severity, payload=payload)


class _SyntheticUpdater:
    def __init__(self, journal: SQLiteJournal):
        self.journal = journal
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="dashboard-synthetic-updater",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=5)

    def _run(self) -> None:
        tick = 0
        while not self.stop_event.wait(5):
            tick += 1
            equity = Decimal("5008") + Decimal(
                str(math.sin(tick / 3) * 1.6 + tick * 0.04)
            )
            self.journal.record_account_snapshot(
                total_equity_quote=equity,
                available_quote=equity - Decimal("24.75"),
                holdings=[
                    {"ccy": "USDT", "balance": str(equity - Decimal("24.75"))},
                    {"ccy": "DOGE", "balance": "350"},
                ],
                source="synthetic_preview",
            )
            if tick % 3 == 0:
                self.journal.record_event(
                    "dashboard_preview_tick",
                    payload={
                        "tick": tick,
                        "observation_id": uuid.uuid4().hex[:12],
                    },
                )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="使用隔离合成数据预览全部 Dashboard 功能"
    )
    parser.add_argument("--port", type=int, default=9180)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="okx-dashboard-preview-") as directory:
        database = Path(directory) / "synthetic-preview.db"
        journal = SQLiteJournal(database)
        _seed_preview(journal)
        updater = _SyntheticUpdater(journal)
        server = DashboardServer(
            DashboardReadModel(database),
            host="127.0.0.1",
            port=args.port,
        )
        server.start()
        updater.start()
        print()
        print("SYNTHETIC PREVIEW：不连接 OKX、不读取密钥、不下单")
        print(f"打开 http://127.0.0.1:{server.port}")
        print("按 Ctrl+C 停止并自动删除临时数据")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0
        finally:
            updater.stop()
            server.stop()
            journal.close()


if __name__ == "__main__":
    raise SystemExit(main())
