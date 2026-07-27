"""把 OKX 私有 WS 消息投影到订单日志。"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from okx_quant.application.execution import ExecutionCoordinator
from okx_quant.client.websocket import ConnectionState, OKXWebSocketClient
from okx_quant.domain.orders import (
    ExchangeOrder,
    OrderState,
    SystemMode,
    map_exchange_order_state,
    parse_decimal_fact,
)
from okx_quant.infrastructure.db import JournalRepository

logger = logging.getLogger(__name__)


def map_order_event(raw: dict) -> ExchangeOrder:
    inst_id = str(raw.get("instId", "")).strip()
    side = str(raw.get("side", "")).lower()
    ord_id = str(raw.get("ordId", "")).strip()
    raw_state = str(raw.get("state", ""))
    state = map_exchange_order_state(raw_state)
    if not inst_id:
        raise ValueError("orders WS instId 缺失")
    if side not in {"buy", "sell"}:
        raise ValueError(f"orders WS side 非法: {side!r}")
    if not ord_id:
        raise ValueError("orders WS ordId 缺失")
    if state is OrderState.UNKNOWN:
        raise ValueError(f"orders WS state 未知: {raw_state!r}")
    requested_qty = parse_decimal_fact(
        raw.get("sz"),
        "orders.sz",
        positive=True,
    )
    acc_fill_qty = parse_decimal_fact(
        raw.get("accFillSz"),
        "orders.accFillSz",
        nonnegative=True,
    )
    avg_fill_px = parse_decimal_fact(
        raw.get("avgPx") or raw.get("fillPx"),
        "orders.avgPx",
        default="0",
        nonnegative=True,
    )
    if state in {OrderState.FILLED, OrderState.PARTIALLY_FILLED} and (
        acc_fill_qty <= 0 or avg_fill_px <= 0
    ):
        raise ValueError(
            "已成交 orders WS 事实必须包含正数 accFillSz 和 avgPx"
        )
    return ExchangeOrder(
        inst_id=inst_id,
        side=side,
        state=state,
        ord_id=ord_id,
        cl_ord_id=str(raw.get("clOrdId", "")),
        requested_qty=requested_qty,
        acc_fill_qty=acc_fill_qty,
        avg_fill_px=avg_fill_px,
        fee=parse_decimal_fact(
            raw.get("fee"),
            "orders.fee",
            default="0",
        ),
        fee_ccy=str(raw.get("feeCcy", "")),
        trade_id=str(raw.get("tradeId", "")),
        update_ts=float(raw.get("uTime", 0) or 0) / 1000,
        raw=dict(raw),
    )


class PrivateStreamService:
    """orders / balance_and_position / orders-algo 的生产接入层。"""

    def __init__(
        self,
        ws: OKXWebSocketClient,
        coordinator: ExecutionCoordinator,
        journal: JournalRepository,
        *,
        on_algo_event: Callable[[list[dict]], None] | None = None,
        stale_after_s: float = 30,
    ):
        self.ws = ws
        self.coordinator = coordinator
        self.journal = journal
        self.on_algo_event = on_algo_event
        self.stale_after_s = stale_after_s
        self._baseline_complete = False
        self._event_sequence = 0
        self._inflight_events = 0
        self._event_lock = threading.RLock()
        self._register()

    def _register(self) -> None:
        self.ws.subscribe_orders("ANY", "", self._on_orders)
        self.ws.subscribe_balance_and_position(self._on_balance)
        self.ws.subscribe_algo_orders(self._on_algos)
        self.ws.add_state_handler(self._on_state)

    def mark_baseline_complete(
        self,
        expected_event_sequence: int | None = None,
        on_complete: Callable[[], object] | None = None,
    ) -> bool:
        """在事件 fence 内提交 REST baseline，并可原子执行 READY 切换。"""
        with self._event_lock:
            if (
                expected_event_sequence is not None
                and (
                    self._event_sequence != expected_event_sequence
                    or self._inflight_events
                )
            ):
                return False
            self._baseline_complete = True
            if on_complete is not None:
                on_complete()
            return True

    def run_if_baseline_current(
        self,
        expected_event_sequence: int,
        callback: Callable[[], object],
    ) -> tuple[bool, object | None]:
        """仅在 baseline/token 仍有效时，于事件锁内执行状态切换。

        `_begin_event` 必须取得同一把锁，因此私有事件不可能插入最后一次
        token 校验与 callback（通常是 READY 切换）之间。
        """
        with self._event_lock:
            if (
                self._event_sequence != expected_event_sequence
                or self._inflight_events
                or not self._baseline_complete
                or not self.transport_ready
            ):
                return False, None
            return True, callback()

    def invalidate_baseline(self) -> None:
        with self._event_lock:
            self._baseline_complete = False

    @property
    def event_sequence(self) -> int:
        with self._event_lock:
            return self._event_sequence

    def _begin_event(self) -> None:
        with self._event_lock:
            self._event_sequence += 1
            self._inflight_events += 1

    def _finish_event(self) -> None:
        with self._event_lock:
            self._inflight_events = max(self._inflight_events - 1, 0)

    @property
    def ready(self) -> bool:
        with self._event_lock:
            baseline_ready = (
                self._baseline_complete and self._inflight_events == 0
            )
        return baseline_ready and self.transport_ready

    @property
    def transport_ready(self) -> bool:
        return self.ws.private_ready and not self.is_stale()

    def is_stale(self) -> bool:
        names = ("private", "business")
        # orders/algo 通道可能长时间没有业务事件；底层 ping_timeout 负责
        # 活性判断，不能因“没有成交”把健康连接误判为 stale。
        return any(
            self.ws.connection_state(name) is not ConnectionState.READY
            for name in names
        )

    def _on_orders(self, rows: list[dict]) -> None:
        self._begin_event()
        try:
            self._project_orders(rows)
        finally:
            self._finish_event()

    def _project_orders(self, rows: list[dict]) -> None:
        for row in rows:
            try:
                update = map_order_event(row)
            except Exception as exc:
                # 无效 WS 数值不是“零成交”事实。冻结系统并独立 Page，
                # 等 REST 对账取得可验证快照后才能恢复。
                correlation_id = str(
                    row.get("ordId") or row.get("clOrdId") or "unknown"
                )
                self.journal.set_mode(SystemMode.HALTED)
                self.journal.record_event(
                    "private_order_fact_invalid",
                    severity="critical",
                    correlation_id=correlation_id,
                    payload={"error": str(exc), "raw": row},
                )
                self.journal.enqueue_outbox_once(
                    f"private-order-fact-invalid:{correlation_id}",
                    "page.private_order_fact_invalid",
                    {
                        "ord_id": str(row.get("ordId", "")),
                        "cl_ord_id": str(row.get("clOrdId", "")),
                        "inst_id": str(row.get("instId", "")),
                        "error": str(exc),
                    },
                )
                raise
            try:
                self.coordinator.process_exchange_update(update)
            except KeyError:
                imported = self.coordinator.import_external_update(update)
                self.journal.set_mode(SystemMode.DEGRADED)
                self.journal.record_event(
                    "external_order_from_ws",
                    severity="critical",
                    correlation_id=imported.intent_id,
                    payload={"ord_id": update.ord_id, "inst_id": update.inst_id},
                )
            except ValueError as exc:
                self.journal.set_mode(SystemMode.DEGRADED)
                self.journal.record_event(
                    "out_of_order_illegal_transition",
                    severity="warning",
                    correlation_id=update.ord_id,
                    payload={"error": str(exc), "raw": row},
                )
            except Exception as exc:
                # 私有订单事件是资金事实。投影失败（特别是 DB 写失败）不能
                # 只留一条 websocket 日志并继续 READY。
                try:
                    self.journal.set_mode(SystemMode.HALTED)
                    self.journal.record_event(
                        "private_order_projection_failed",
                        severity="critical",
                        correlation_id=update.ord_id,
                        payload={"error": str(exc), "raw": row},
                    )
                    self.journal.enqueue_outbox(
                        "page.private_order_projection_failed",
                        {
                            "ord_id": update.ord_id,
                            "inst_id": update.inst_id,
                            "error": str(exc),
                        },
                    )
                finally:
                    raise

    def _on_balance(self, rows: list[dict]) -> None:
        self._begin_event()
        try:
            # 保留原始事件用于审计；周期性 Reconciler 负责联合解释余额差异。
            self.journal.record_event(
                "balance_position_ws_update",
                payload={"rows": rows},
            )
            # 余额是账户级权威事实；在 REST 联合对账确认订单/成交/保护
            # 投影前冻结新增风险，不能仅记日志后继续 READY。
            self.journal.set_mode(SystemMode.DEGRADED)
        finally:
            self._finish_event()

    def _on_algos(self, rows: list[dict]) -> None:
        self._begin_event()
        try:
            try:
                if self.on_algo_event:
                    self.on_algo_event(rows)
                else:
                    self.journal.record_event(
                        "algo_ws_update", payload={"rows": rows}
                    )
            except Exception as exc:
                try:
                    self.journal.set_mode(SystemMode.HALTED)
                    self.journal.record_event(
                        "private_algo_projection_failed",
                        severity="critical",
                        payload={"error": str(exc), "rows": rows},
                    )
                    self.journal.enqueue_outbox(
                        "page.private_algo_projection_failed",
                        {"error": str(exc)},
                    )
                finally:
                    raise
        finally:
            self._finish_event()

    def _on_state(self, name: str, state: ConnectionState) -> None:
        if name not in {"private", "business"}:
            return
        self.journal.record_event(
            "ws_state_changed",
            severity="warning" if state in {
                ConnectionState.BACKOFF,
                ConnectionState.STALE,
                ConnectionState.DISCONNECTED,
            } else "info",
            payload={"connection": name, "state": state.value},
        )
        if state in {
            ConnectionState.BACKOFF,
            ConnectionState.STALE,
            ConnectionState.DISCONNECTED,
        }:
            # 断线只冻结新增风险；退出和对账仍可运行。
            self.journal.set_mode(SystemMode.DEGRADED)

    def start(self) -> None:
        self.ws.run_in_thread()

    def stop(self) -> None:
        self.ws.stop()
