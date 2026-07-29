"""持久化、幂等的单写者订单执行协调器。"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import re
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass, replace
from decimal import Decimal

import requests

from okx_quant.domain.orders import (
    ExchangeOrder,
    IntentRiskGuard,
    OrderIntent,
    OrderState,
    SystemMode,
    generate_client_order_id,
    to_decimal,
)
from okx_quant.exchange import Exchange
from okx_quant.infrastructure.db import JournalRepository

logger = logging.getLogger(__name__)


def is_ambiguous_write_error(exc: Exception) -> bool:
    """写请求无法证明未到达交易所时，必须按 UNKNOWN 处理。"""
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    if not isinstance(exc, requests.RequestException):
        return False
    if isinstance(exc, requests.HTTPError):
        status = (
            exc.response.status_code
            if exc.response is not None
            else 0
        )
        # 408/425/429 可能来自超时代理、过早请求或限流层，不能证明
        # 交易所没有接受写请求；与 5xx/无响应一样按 UNKNOWN。
        return not (
            400 <= status < 500
            and status not in {408, 425, 429}
        )
    return True


@dataclass(frozen=True)
class ExecutionRequest:
    inst_id: str
    side: str
    base_qty: Decimal
    reserved_quote: Decimal = Decimal("0")
    reference_price: Decimal = Decimal("0")
    decision_id: str = ""
    stop_loss: Decimal = Decimal("0")
    take_profit: Decimal = Decimal("0")
    cl_ord_id: str = ""
    source: str = "strategy"
    probe_id: str = ""
    probe_lease_owner: str = ""
    probe_fencing_token: int = 0


class ExecutionCoordinator:
    """唯一可调用交易所下单接口的组件。

    可以同步使用 ``submit``，也可以启动后台单写者线程后使用 ``enqueue``。
    """

    def __init__(
        self,
        exchange: Exchange,
        journal: JournalRepository,
        *,
        pre_trade_check: Callable[[ExecutionRequest], tuple[bool, str]] | None = None,
        on_fill: Callable[[OrderIntent, Decimal], None] | None = None,
        shadow_mode: bool = False,
        max_slippage_ratio: Decimal | None = None,
        operation_lock: threading.RLock | None = None,
        entry_guard: Callable[[], tuple[bool, object]] | None = None,
        atomic_risk_guard: (
            Callable[[ExecutionRequest], IntentRiskGuard] | None
        ) = None,
        allowed_buy_sources: frozenset[str] | None = None,
    ):
        self.exchange = exchange
        self.journal = journal
        self.pre_trade_check = pre_trade_check
        self.shadow_mode = shadow_mode
        self.max_slippage_ratio = max_slippage_ratio
        self.operation_lock = operation_lock or threading.RLock()
        self.entry_guard = entry_guard
        self.atomic_risk_guard = atomic_risk_guard
        self.allowed_buy_sources = allowed_buy_sources
        self._projection_healthy = threading.Event()
        self._projection_healthy.set()
        self._fill_handlers: list[Callable[[OrderIntent, Decimal], None]] = []
        if on_fill:
            self._fill_handlers.append(on_fill)
        self._queue: queue.Queue[tuple[ExecutionRequest, Future] | None] = queue.Queue(maxsize=1000)
        self._thread: threading.Thread | None = None
        self._running = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running.set()
        self._thread = threading.Thread(
            target=self._run,
            name="execution-coordinator",
            daemon=False,
        )
        self._thread.start()

    def stop(self, timeout: float = 10) -> None:
        self._running.clear()
        self._queue.put(None)
        if self._thread:
            self._thread.join(timeout=timeout)

    def enqueue(self, request: ExecutionRequest) -> Future:
        future: Future = Future()
        self._queue.put((request, future), timeout=5)
        return future

    def add_fill_handler(
        self, callback: Callable[[OrderIntent, Decimal], None]
    ) -> None:
        self._fill_handlers.append(callback)

    def _run(self) -> None:
        while self._running.is_set() or not self._queue.empty():
            item = self._queue.get()
            if item is None:
                break
            request, future = item
            if future.cancelled():
                continue
            try:
                future.set_result(self.submit(request))
            except BaseException as exc:  # noqa: BLE001
                future.set_exception(exc)

    def submit(self, request: ExecutionRequest) -> OrderIntent:
        with self.operation_lock:
            return self._submit(request)

    def _submit(self, request: ExecutionRequest) -> OrderIntent:
        if request.side not in {"buy", "sell"}:
            raise ValueError(f"无效订单方向: {request.side}")
        if request.base_qty <= 0:
            raise ValueError("下单数量必须大于 0")
        if request.cl_ord_id and not re.fullmatch(
            r"[A-Za-z0-9]{1,32}",
            request.cl_ord_id,
        ):
            raise ValueError("cl_ord_id 必须是 1..32 位字母数字")
        if request.source == "demo_validation_probe" and request.side == "buy" and (
            not request.probe_id
            or not request.probe_lease_owner
            or request.probe_fencing_token <= 0
        ):
            raise ValueError("Demo probe intent 必须绑定当前 saga lease capability")
        if request.source == "demo_validation_probe" and not request.probe_id:
            raise ValueError("Demo probe intent 必须绑定 probe_id")
        if request.source != "demo_validation_probe" and (
            request.probe_id
            or request.probe_lease_owner
            or request.probe_fencing_token
        ):
            raise ValueError("非 Demo probe intent 禁止携带 probe capability")
        if (
            request.side == "buy"
            and self.allowed_buy_sources is not None
            and request.source not in self.allowed_buy_sources
        ):
            raise RuntimeError(
                f"当前部署禁止 BUY source={request.source}"
            )
        if request.side == "buy" and not self._projection_healthy.is_set():
            raise RuntimeError("订单投影已失败，禁止新增风险直至重启恢复")

        mode = self.journal.get_mode()
        if request.side == "buy" and not mode.allows_new_risk:
            raise RuntimeError(f"系统模式 {mode.value} 禁止新增风险")
        entry_token = self._capture_entry_guard() if request.side == "buy" else None

        if request.side == "buy" and self.pre_trade_check is not None:
            # 风险预留必须由执行内核按权威行情计算，不能信任调用者传入的
            # reserved_quote。最坏成交价包含交易所下单层的滑点上限。
            ticker = self.exchange.get_ticker(request.inst_id)
            reference_price = to_decimal(ticker.ask or ticker.last)
            if reference_price <= 0:
                raise RuntimeError("无法取得有效 BUY 风险价格")
            slippage = self.max_slippage_ratio or Decimal("0")
            authoritative_reserve = (
                request.base_qty * reference_price * (Decimal("1") + slippage)
            )
            request = replace(
                request,
                reserved_quote=max(
                    request.reserved_quote,
                    authoritative_reserve,
                ),
                reference_price=reference_price,
            )

        if self.pre_trade_check:
            allowed, reason = self.pre_trade_check(request)
            if not allowed:
                raise RuntimeError(f"下单前风控拒绝: {reason}")
        if request.side == "sell" and request.reference_price <= 0:
            # 退出绝不能因行情故障被阻塞；仅在可取得时记录滑点基准。
            try:
                ticker = self.exchange.get_ticker(request.inst_id)
                reference = to_decimal(ticker.bid or ticker.last)
                if reference.is_finite() and reference > 0:
                    request = replace(
                        request,
                        reference_price=reference,
                    )
            except Exception:  # noqa: BLE001
                pass
        if request.side == "buy":
            self._assert_entry_guard(entry_token)

        intent = OrderIntent(
            intent_id=uuid.uuid4().hex,
            cl_ord_id=(
                request.cl_ord_id
                or generate_client_order_id(request.side)
            ),
            decision_id=request.decision_id,
            inst_id=request.inst_id,
            side=request.side,
            requested_base_qty=request.base_qty,
            reserved_quote=request.reserved_quote,
            submission_reference_price=request.reference_price,
            requested_stop_loss=request.stop_loss,
            requested_take_profit=request.take_profit,
            source=request.source,
            probe_id=request.probe_id,
            created_at=time.time(),
        )
        atomic_guard = (
            self.atomic_risk_guard(request)
            if request.side == "buy" and self.atomic_risk_guard is not None
            else None
        )
        intent = self.journal.create_order_intent(
            intent,
            risk_guard=atomic_guard,
            probe_lease_owner=request.probe_lease_owner,
            probe_fencing_token=request.probe_fencing_token,
        )
        if request.side == "buy":
            try:
                self._assert_entry_guard(entry_token)
            except RuntimeError as exc:
                self.journal.update_intent(
                    intent,
                    OrderState.REJECTED,
                    last_error_code="ENTRY_GUARD_CHANGED",
                    last_error_message=str(exc),
                )
                raise
        if self.shadow_mode:
            intent = self.journal.update_intent(
                intent,
                OrderState.REJECTED,
                last_error_code="SHADOW_NOT_SUBMITTED",
                last_error_message="shadow mode 仅记录意图，不向交易所提交",
            )
            self.journal.record_event(
                "shadow_order_intent",
                correlation_id=intent.intent_id,
                payload={
                    "inst_id": intent.inst_id,
                    "side": intent.side,
                    "requested_base_qty": str(intent.requested_base_qty),
                    "source": intent.source,
                    "probe_id": intent.probe_id,
                },
            )
            return intent
        intent = self.journal.update_intent(intent, OrderState.SUBMITTING)
        if request.side == "buy":
            try:
                self._assert_entry_guard(entry_token)
            except RuntimeError as exc:
                self.journal.update_intent(
                    intent,
                    OrderState.CANCELED,
                    last_error_code="ENTRY_GUARD_CHANGED",
                    last_error_message=str(exc),
                )
                raise
        self.journal.record_event(
            "order_submitting",
            correlation_id=intent.intent_id,
            payload={
                "inst_id": intent.inst_id,
                "side": intent.side,
                "cl_ord_id": intent.cl_ord_id,
                "source": intent.source,
                "probe_id": intent.probe_id,
                "entry_fence_sha256": (
                    hashlib.sha256(
                        json.dumps(
                            entry_token,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest()
                    if request.side == "buy"
                    else ""
                ),
            },
        )
        # `order_submitting` 本身是可注入/可阻塞的 durable 写；这里先快速
        # 拒绝已经失效的门禁。真正的最终校验由 pre_send_guard 穿透到
        # REST，在全局 rate-limit 等待完成后、socket write 紧前执行。
        if request.side == "buy":
            try:
                self._assert_entry_guard(entry_token)
            except RuntimeError as exc:
                self.journal.update_intent(
                    intent,
                    OrderState.CANCELED,
                    last_error_code="ENTRY_GUARD_CHANGED",
                    last_error_message=str(exc),
                )
                raise

        pre_send_guard: Callable[[], None] | None = None
        if request.side == "buy":
            def assert_buy_transport_capability() -> None:
                self._assert_entry_guard(entry_token)
                if request.source == "demo_validation_probe":
                    self.journal.assert_probe_order_capability(
                        probe_id=request.probe_id,
                        owner=request.probe_lease_owner,
                        fencing_token=request.probe_fencing_token,
                        cl_ord_id=intent.cl_ord_id,
                        inst_id=request.inst_id,
                    )

            pre_send_guard = assert_buy_transport_capability

        try:
            result = self.exchange.place_market_order(
                inst_id=request.inst_id,
                side=request.side,
                size=request.base_qty,
                tgt_ccy="base_ccy",
                cl_ord_id=intent.cl_ord_id,
                max_slippage=self.max_slippage_ratio,
                pre_send_guard=pre_send_guard,
            )
        except Exception as exc:
            if self._is_ambiguous_submission_error(exc):
                intent = self.journal.update_intent(
                    intent,
                    OrderState.UNKNOWN,
                    last_error_code=type(exc).__name__,
                    last_error_message=str(exc),
                )
                self.journal.set_mode(SystemMode.DEGRADED)
                self.journal.record_event(
                    "order_submission_unknown",
                    severity="critical",
                    correlation_id=intent.intent_id,
                    payload={
                        "error": str(exc),
                        "cl_ord_id": intent.cl_ord_id,
                    },
                )
                self.journal.enqueue_outbox_once(
                    f"order-unknown:{intent.intent_id}",
                    "page.order_submission_unknown",
                    {
                        "intent_id": intent.intent_id,
                        "inst_id": intent.inst_id,
                        "side": intent.side,
                        "cl_ord_id": intent.cl_ord_id,
                        "error": str(exc),
                    },
                )
                return intent
            # 明确的本地校验或 OKX 业务拒绝才允许释放预留。
            intent = self.journal.update_intent(
                intent,
                OrderState.REJECTED,
                last_error_code=type(exc).__name__,
                last_error_message=str(exc),
            )
            self.journal.record_event(
                "order_rejected",
                severity="warning",
                correlation_id=intent.intent_id,
                payload={"error": str(exc)},
            )
            return intent

        exchange_state = getattr(result, "state", "") or ""
        acc_fill = to_decimal(getattr(result, "acc_fill_size", 0))
        state = self._result_state(exchange_state, acc_fill)
        exchange_order = ExchangeOrder(
            inst_id=request.inst_id,
            side=request.side,
            state=state,
            ord_id=result.ord_id,
            cl_ord_id=intent.cl_ord_id,
            requested_qty=request.base_qty,
            acc_fill_qty=acc_fill,
            avg_fill_px=to_decimal(result.fill_price),
            fee=to_decimal(getattr(result, "fee", 0)),
            fee_ccy=getattr(result, "fee_ccy", ""),
            trade_id=getattr(result, "trade_id", ""),
            update_ts=time.time(),
            raw=result.raw,
        )
        try:
            updated, delta = self.journal.apply_exchange_order(exchange_order)
        except Exception as exc:
            # HTTP 已返回后，交易所可能已经成交；本地投影失败是最高等级
            # 账实不一致，不能仍报告 READY 或继续接受 BUY。
            self._projection_healthy.clear()
            logger.critical(
                "交易所订单已响应但 durable 投影失败 %s: %s",
                intent.cl_ord_id,
                exc,
            )
            try:
                self.journal.set_mode(SystemMode.HALTED)
                self.journal.enqueue_outbox(
                    "page.order_projection_failed_after_exchange_response",
                    {
                        "inst_id": request.inst_id,
                        "cl_ord_id": intent.cl_ord_id,
                        "ord_id": result.ord_id,
                        "error": str(exc),
                    },
                )
            except Exception:  # noqa: BLE001
                logger.critical(
                    "订单投影失败后无法持久化 HALTED/Page",
                    exc_info=True,
                )
            raise RuntimeError(
                "交易所已响应但本地订单投影失败；系统已锁停"
            ) from exc
        self._notify_fill(updated, delta)
        return updated

    @property
    def projection_healthy(self) -> bool:
        return self._projection_healthy.is_set()

    @staticmethod
    def _is_ambiguous_submission_error(exc: Exception) -> bool:
        return is_ambiguous_write_error(exc)

    def _capture_entry_guard(self) -> object | None:
        if self.entry_guard is None:
            return None
        ready, token = self.entry_guard()
        if not ready:
            raise RuntimeError("新增风险门禁未 READY")
        return token

    def _assert_entry_guard(self, expected: object | None) -> None:
        if self.entry_guard is None:
            return
        ready, token = self.entry_guard()
        if not ready or token != expected:
            raise RuntimeError("新增风险门禁在风控/提交期间发生变化")

    def process_exchange_update(self, update: ExchangeOrder) -> tuple[OrderIntent, Decimal]:
        with self.operation_lock:
            previous = (
                self.journal.find_intent(exchange_ord_id=update.ord_id)
                if update.ord_id
                else None
            )
            if previous is None and update.cl_ord_id:
                previous = self.journal.find_intent(
                    cl_ord_id=update.cl_ord_id
                )
            intent, delta = self.journal.apply_exchange_order(update)
            base_ccy = update.inst_id.split("-")[0]
            base_fee_changed = (
                previous is not None
                and update.side == "buy"
                and update.fee_ccy == base_ccy
                and update.fee != previous.fee
            )
            self._notify_fill(intent, delta, force=base_fee_changed)
            return intent, delta

    def import_external_update(self, update: ExchangeOrder) -> OrderIntent:
        """导入交易所外部事实，并立即执行与普通成交相同的保护处理器。"""
        with self.operation_lock:
            imported = self.journal.import_external_order(update)
            self._notify_fill(imported, imported.acc_fill_qty)
            return imported

    def _notify_fill(
        self,
        intent: OrderIntent,
        delta: Decimal,
        *,
        force: bool = False,
    ) -> None:
        if delta <= 0 and not force:
            return
        for handler in self._fill_handlers:
            try:
                handler(intent, delta)
            except Exception as exc:  # noqa: BLE001
                logger.exception("成交处理器异常 %s: %s", intent.intent_id, exc)
                self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
                self.journal.record_event(
                    "fill_handler_failed",
                    severity="critical",
                    correlation_id=intent.intent_id,
                    payload={"error": str(exc), "delta": str(delta)},
                )

    @staticmethod
    def _result_state(exchange_state: str, acc_fill: Decimal) -> OrderState:
        normalized = (exchange_state or "").lower()
        if normalized == "filled":
            return OrderState.FILLED
        if normalized == "partially_filled":
            return OrderState.PARTIALLY_FILLED
        if normalized == "live":
            return OrderState.LIVE
        if normalized in {"canceled", "mmp_canceled"}:
            return OrderState.CANCELED
        if acc_fill > 0:
            return OrderState.PARTIALLY_FILLED
        return OrderState.ACKNOWLEDGED
