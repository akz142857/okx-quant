"""启动恢复与交易所事实对账。"""

from __future__ import annotations

import logging
import math
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Protocol

from okx_quant.domain.orders import ExchangeOrder, OrderIntent, OrderState, SystemMode, to_decimal
from okx_quant.exchange import Exchange
from okx_quant.infrastructure.db import JournalRepository

logger = logging.getLogger(__name__)


def fresh_valid_mark_for_dust(
    exchange: Exchange,
    inst_id: str,
    *,
    max_age_s: float,
) -> Decimal | None:
    """返回可用于证明 dust 的新鲜市场事实；不确定时返回 None。"""
    try:
        ticker = exchange.get_ticker(inst_id)
        last = to_decimal(ticker.last)
        bid = to_decimal(ticker.bid)
        ask = to_decimal(ticker.ask)
        timestamp = float(ticker.timestamp)
    except (AttributeError, TypeError, ValueError, ArithmeticError):
        return None
    now = time.time()
    if (
        not last.is_finite()
        or not bid.is_finite()
        or not ask.is_finite()
        or last <= 0
        or bid <= 0
        or ask <= 0
        or ask < bid
        or not math.isfinite(timestamp)
        or timestamp <= 0
        or now - timestamp > max_age_s
        or timestamp - now > max_age_s
    ):
        return None
    return last


class ProtectionReconciler(Protocol):
    """保护管理器的最小对账接口，避免应用服务形成循环依赖。"""

    def reconcile(self, inst_id: str = "") -> list[str]: ...

    def ensure_for_position(
        self,
        inst_id: str,
        qty: Decimal,
        *,
        reference_price: Decimal,
        stop_loss: Decimal = Decimal("0"),
        take_profit: Decimal = Decimal("0"),
        parent_intent_id: str = "",
    ): ...


@dataclass
class ReconciliationResult:
    run_id: str
    mismatch_count: int = 0
    repaired_count: int = 0
    unresolved: list[str] = field(default_factory=list)
    details: list[dict] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return not self.unresolved


class OrderResolver:
    """只查询、不重发地解析 UNKNOWN/未决订单。"""

    def __init__(self, exchange: Exchange, journal: JournalRepository):
        self.exchange = exchange
        self.journal = journal

    def resolve(self, intent: OrderIntent) -> OrderIntent | None:
        try:
            remote = self.exchange.get_order_status(
                intent.inst_id,
                ord_id=intent.exchange_ord_id,
                cl_ord_id=intent.cl_ord_id,
            )
        except Exception:  # noqa: BLE001 — 会继续查历史列表
            remote = self._find_in_recent(intent)
        if remote is None:
            return None
        updated, _ = self.journal.apply_exchange_order(remote)
        return updated

    def _find_in_recent(self, intent: OrderIntent) -> ExchangeOrder | None:
        try:
            orders = self.exchange.get_recent_orders(intent.inst_id)
        except Exception:  # noqa: BLE001
            return None
        for order in orders:
            if intent.exchange_ord_id:
                if order.ord_id == intent.exchange_ord_id:
                    return order
                continue
            if intent.cl_ord_id and order.cl_ord_id == intent.cl_ord_id:
                return order
        return None


class Reconciler:
    """联合普通订单、成交投影与账户余额修复本地状态。"""

    def __init__(
        self,
        exchange: Exchange,
        journal: JournalRepository,
        *,
        quote_ccy: str = "USDT",
        dust_usdt: Decimal = Decimal("1"),
        max_market_data_age_s: float = 5,
        unknown_manual_after_s: float = 300,
        protection_manager: ProtectionReconciler | None = None,
        operation_lock: threading.RLock | None = None,
    ):
        self.exchange = exchange
        self.journal = journal
        self.quote_ccy = quote_ccy
        self.dust_usdt = dust_usdt
        self.max_market_data_age_s = max_market_data_age_s
        self.unknown_manual_after_s = unknown_manual_after_s
        self.resolver = OrderResolver(exchange, journal)
        self.protection_manager = protection_manager
        self.operation_lock = operation_lock or threading.RLock()

    def run(
        self,
        *,
        startup: bool = False,
        manage_mode: bool = True,
        reconcile_protections: bool = True,
    ) -> ReconciliationResult:
        with self.operation_lock:
            return self._run(
                startup=startup,
                manage_mode=manage_mode,
                reconcile_protections=reconcile_protections,
            )

    def _run(
        self,
        *,
        startup: bool = False,
        manage_mode: bool = True,
        reconcile_protections: bool = True,
    ) -> ReconciliationResult:
        hard_modes = {
            SystemMode.HALTED,
            SystemMode.EMERGENCY_EXIT,
            SystemMode.MAINTENANCE,
        }
        latched_mode = (
            self.journal.get_mode()
            if startup and self.journal.get_mode() in hard_modes
            else None
        )
        if startup and latched_mode is None:
            self.journal.set_mode(SystemMode.STARTING)
        run_id = self.journal.start_reconciliation()
        result = ReconciliationResult(run_id=run_id)
        try:
            database_ok = (
                self.journal.integrity_check()
                if startup
                else self.journal.health_check()
            )
            if not database_ok:
                check = "integrity_check" if startup else "health_check"
                raise RuntimeError(f"订单数据库 {check} 失败")
            projection_valid = (
                self._verify_position_projection(result)
                if startup
                else True
            )
            balance = self.exchange.get_balance()
            pending = self.exchange.get_pending_orders()
            fills = self.exchange.get_recent_fills()
            self.journal.record_account_snapshot(
                total_equity_quote=to_decimal(balance.total_equity_quote),
                available_quote=to_decimal(balance.available_quote),
                holdings=[
                    {
                        "ccy": h.ccy,
                        "balance": str(h.balance),
                        "available": str(h.available),
                    }
                    for h in balance.holdings
                ],
                source="startup" if startup else "periodic",
            )

            self._reconcile_fills(fills, result)
            self._reconcile_orders(pending, result)
            self._resolve_local_intents(result)
            if projection_valid:
                self._reconcile_balances(balance, result)
            if reconcile_protections and projection_valid:
                self._reconcile_protections(result)

            if manage_mode:
                current_mode = self.journal.get_mode()
                if latched_mode is not None:
                    self.journal.set_mode(latched_mode)
                elif current_mode not in hard_modes:
                    mode = (
                        SystemMode.READY
                        if result.safe
                        else SystemMode.DEGRADED
                    )
                    self.journal.set_mode(mode)
            status = "ok" if result.safe else "degraded"
            self.journal.finish_reconciliation(
                run_id,
                status=status,
                mismatch_count=result.mismatch_count,
                repaired_count=result.repaired_count,
                details={"unresolved": result.unresolved, "details": result.details},
            )
            self.journal.record_event(
                "reconciliation_completed",
                severity="info" if result.safe else "warning",
                correlation_id=run_id,
                payload={
                    "mismatches": result.mismatch_count,
                    "repaired": result.repaired_count,
                    "unresolved": result.unresolved,
                },
            )
            return result
        except Exception as exc:
            self.journal.set_mode(SystemMode.HALTED)
            self.journal.finish_reconciliation(
                run_id,
                status="failed",
                mismatch_count=result.mismatch_count,
                repaired_count=result.repaired_count,
                details={"error": str(exc), "details": result.details},
            )
            self.journal.record_event(
                "reconciliation_failed",
                severity="critical",
                correlation_id=run_id,
                payload={"error": str(exc)},
            )
            raise

    def _reconcile_orders(
        self, pending: list[ExchangeOrder], result: ReconciliationResult
    ) -> None:
        for remote in pending:
            local = (
                self.journal.find_intent(exchange_ord_id=remote.ord_id)
                if remote.ord_id
                else None
            )
            if local is None and remote.cl_ord_id:
                local = self.journal.find_intent(cl_ord_id=remote.cl_ord_id)
            if local is None:
                result.mismatch_count += 1
                imported = self.journal.import_external_order(
                    remote,
                    reserved_quote=self._external_buy_reserve(remote),
                )
                result.repaired_count += 1
                result.details.append({
                    "type": "external_pending_order",
                    "intent_id": imported.intent_id,
                    "ord_id": remote.ord_id,
                })
                continue
            if (
                remote.ord_id
                and local.exchange_ord_id
                and remote.ord_id != local.exchange_ord_id
            ):
                result.mismatch_count += 1
                result.unresolved.append(
                    f"client_order_id_collision:{remote.inst_id}:{remote.cl_ord_id}"
                )
                result.details.append({
                    "type": "client_order_id_collision",
                    "intent_id": local.intent_id,
                    "local_ord_id": local.exchange_ord_id,
                    "remote_ord_id": remote.ord_id,
                    "cl_ord_id": remote.cl_ord_id,
                })
                self.journal.record_event(
                    "client_order_id_collision",
                    severity="critical",
                    correlation_id=local.intent_id,
                    payload=result.details[-1],
                )
                continue
            try:
                _, delta = self.journal.apply_exchange_order(remote)
                if delta > 0 or local.state != remote.state:
                    result.repaired_count += 1
            except ValueError as exc:
                result.unresolved.append(f"illegal_order_transition:{local.intent_id}")
                result.details.append({"type": "illegal_order_transition", "error": str(exc)})

    def _reconcile_fills(self, fills: list, result: ReconciliationResult) -> None:
        """成交列表只用于发现事实；累计量仍以订单详情为投影依据。"""
        seen_orders: set[tuple[str, str]] = set()
        for fill in fills:
            key = (fill.inst_id, fill.ord_id)
            if key in seen_orders or not fill.ord_id:
                continue
            seen_orders.add(key)
            local = self.journal.find_intent(exchange_ord_id=fill.ord_id)
            if local is None and fill.cl_ord_id:
                local = self.journal.find_intent(cl_ord_id=fill.cl_ord_id)
            try:
                remote = self.exchange.get_order_status(
                    fill.inst_id,
                    ord_id=fill.ord_id,
                    cl_ord_id=fill.cl_ord_id,
                )
            except Exception as exc:  # noqa: BLE001
                result.unresolved.append(
                    f"fill_order_detail_unavailable:{fill.inst_id}:{fill.ord_id}"
                )
                result.details.append({
                    "type": "fill_order_detail_unavailable",
                    "error": str(exc),
                })
                continue
            if local is None:
                result.mismatch_count += 1
                imported = self.journal.import_external_order(remote)
                result.repaired_count += 1
                result.unresolved.append(
                    f"external_fill:{fill.inst_id}:{fill.trade_id}"
                )
                result.details.append({
                    "type": "external_fill",
                    "intent_id": imported.intent_id,
                    "trade_id": fill.trade_id,
                })
                continue
            before = local.acc_fill_qty
            try:
                updated, _ = self.journal.apply_exchange_order(remote)
                if updated.acc_fill_qty > before:
                    result.repaired_count += 1
            except ValueError as exc:
                result.unresolved.append(
                    f"illegal_fill_transition:{local.intent_id}"
                )
                result.details.append({
                    "type": "illegal_fill_transition",
                    "error": str(exc),
                })

    def _resolve_local_intents(self, result: ReconciliationResult) -> None:
        now = time.time()
        for intent in self.journal.list_nonterminal_intents():
            if intent.last_error_code == "EXTERNAL_ORDER":
                resolved = self.resolver.resolve(intent)
                if resolved is not None and resolved.state.is_terminal:
                    result.repaired_count += 1
                    continue
                result.unresolved.append(
                    f"external_pending_order:{intent.inst_id}:"
                    f"{intent.exchange_ord_id or intent.cl_ord_id}"
                )
                continue
            if intent.state is OrderState.PERSISTED:
                # 请求尚未进入 SUBMITTING；根据事务顺序可证明从未发送。
                self.journal.update_intent(
                    intent,
                    OrderState.REJECTED,
                    last_error_code="RECOVERY_NOT_SUBMITTED",
                    last_error_message="进程在发送前退出，恢复时安全终止该意图",
                )
                result.repaired_count += 1
                continue
            if intent.state is OrderState.SUBMITTING:
                intent = self.journal.update_intent(
                    intent,
                    OrderState.UNKNOWN,
                    last_error_code="RECOVERY_AMBIGUOUS",
                    last_error_message="进程可能在发送后、记录 ACK 前退出",
                )
                if intent.side == "buy":
                    self.journal.enqueue_outbox_once(
                        f"order-unknown:{intent.intent_id}",
                        "page.order_submission_unknown",
                        {
                            "intent_id": intent.intent_id,
                            "inst_id": intent.inst_id,
                            "side": intent.side,
                            "cl_ord_id": intent.cl_ord_id,
                            "error": "RECOVERY_AMBIGUOUS",
                        },
                    )
            resolved = self.resolver.resolve(intent)
            if resolved is not None:
                result.repaired_count += 1
                continue
            if intent.state is OrderState.MANUAL_REVIEW:
                result.unresolved.append(f"manual_review:{intent.intent_id}")
                continue
            age = now - intent.updated_at
            if intent.side == "buy" and age >= 30:
                self.journal.enqueue_outbox_once(
                    f"order-unknown:{intent.intent_id}",
                    "page.order_unknown_deadline",
                    {
                        "intent_id": intent.intent_id,
                        "inst_id": intent.inst_id,
                        "side": intent.side,
                        "cl_ord_id": intent.cl_ord_id,
                        "age_seconds": max(age, 0),
                    },
                )
            if age >= self.unknown_manual_after_s:
                if intent.state is not OrderState.UNKNOWN:
                    with suppress(ValueError):
                        intent = self.journal.update_intent(intent, OrderState.UNKNOWN)
                if intent.state is OrderState.UNKNOWN:
                    self.journal.update_intent(
                        intent,
                        OrderState.MANUAL_REVIEW,
                        last_error_code="UNRESOLVED_TIMEOUT",
                        last_error_message="REST/历史订单均无法确认，禁止自动重试",
                    )
                result.unresolved.append(f"manual_review:{intent.intent_id}")
            else:
                result.unresolved.append(f"order_unresolved:{intent.intent_id}")

    def _external_buy_reserve(self, order: ExchangeOrder) -> Decimal:
        if order.side != "buy" or order.state.is_terminal:
            return Decimal("0")
        try:
            ticker = self.exchange.get_ticker(order.inst_id)
            reference = max(
                to_decimal(ticker.last),
                to_decimal(ticker.ask),
            )
        except Exception:  # noqa: BLE001
            reference = Decimal("0")
        # 外部订单缺少本实例风控上下文，按 OKX 允许的最大 5% 滑点预留。
        return order.requested_qty * reference * Decimal("1.05")

    def position_safely_protected(
        self,
        inst_id: str,
        qty: Decimal,
    ) -> bool:
        """允许且仅允许低于 lotSz、同时低于 dust 预算的未覆盖余量。"""
        protections = self.journal.list_protections(
            inst_id,
            active_only=True,
        )
        if len(protections) != 1 or protections[0].state.value != "active":
            return False
        protected = protections[0].protected_qty
        if protected == qty:
            return True
        if protected <= 0 or protected > qty:
            return False
        try:
            lot = to_decimal(
                self.exchange.get_instrument(inst_id).lot_size
            )
        except Exception:  # noqa: BLE001
            return False
        remainder = qty - protected
        if lot <= 0 or remainder >= lot:
            return False
        mark = fresh_valid_mark_for_dust(
            self.exchange,
            inst_id,
            max_age_s=self.max_market_data_age_s,
        )
        return (
            mark is not None
            and remainder * mark < self.dust_usdt
        )

    def _reconcile_balances(self, balance, result: ReconciliationResult) -> None:
        remote_by_inst: dict[str, tuple[Decimal, Decimal]] = {}
        for holding in balance.non_quote_holdings(self.quote_ccy):
            inst_id = f"{holding.ccy}-{self.quote_ccy}"
            remote_by_inst[inst_id] = (
                to_decimal(holding.balance),
                to_decimal(holding.available),
            )
        local_positions = {p["inst_id"]: p for p in self.journal.list_positions()}
        all_instruments = set(remote_by_inst) | set(local_positions)
        for inst_id in sorted(all_instruments):
            remote_qty, remote_available = remote_by_inst.get(
                inst_id, (Decimal("0"), Decimal("0"))
            )
            local_qty = to_decimal(local_positions.get(inst_id, {}).get("base_qty"))
            if remote_qty == local_qty:
                continue

            # 估值只决定是否按 dust 记录，ticker 故障时保守视为重大差异。
            price = fresh_valid_mark_for_dust(
                self.exchange,
                inst_id,
                max_age_s=self.max_market_data_age_s,
            )
            value = (
                abs(remote_qty - local_qty) * price
                if price is not None
                else Decimal("Infinity")
            )
            is_dust = price is not None and value < self.dust_usdt
            reference_price = price if price is not None else Decimal("0")
            result.mismatch_count += 1
            self.journal.reconcile_position(
                inst_id,
                remote_qty,
                available_qty=remote_available,
                reference_price=reference_price,
                reason="exchange_balance_dust" if is_dust else "exchange_balance_authoritative",
                run_id=result.run_id,
            )
            result.repaired_count += 1
            result.details.append({
                "type": "balance_mismatch",
                "inst_id": inst_id,
                "local_qty": str(local_qty),
                "remote_qty": str(remote_qty),
                "dust": is_dust,
            })
            if not is_dust:
                result.details.append({
                    "type": "material_position_adjustment",
                    "inst_id": inst_id,
                })

    def _verify_position_projection(
        self,
        result: ReconciliationResult,
    ) -> bool:
        """Fail closed before READY when durable accounting cannot be replayed."""
        report = self.journal.rebuild_position_projection()
        valid = True
        for position in report["positions"]:
            if position["complete"] and position["matches"]:
                continue
            valid = False
            inst_id = position["inst_id"]
            result.mismatch_count += 1
            issue = (
                f"position_projection_drift:{inst_id}"
                if position["complete"]
                else f"position_projection_history_incomplete:{inst_id}"
            )
            result.unresolved.append(issue)
            result.details.append({
                "type": "position_projection_verification",
                "inst_id": inst_id,
                "complete": position["complete"],
                "matches": position["matches"],
                "source_event_count": position["source_event_count"],
                "current": position["current"],
                "projected": position["projected"],
            })
            self.journal.record_event(
                "position_projection_verification_failed",
                severity="critical",
                correlation_id=result.run_id,
                payload=result.details[-1],
            )
        return valid

    def _reconcile_protections(self, result: ReconciliationResult) -> None:
        """验证所有非 dust 仓位，并在可证明安全时补建交易所保护单。"""
        if self.protection_manager is not None:
            for issue in self.protection_manager.reconcile():
                result.mismatch_count += 1
                result.unresolved.append(issue)

        for position in self.journal.list_positions():
            inst_id = position["inst_id"]
            qty = to_decimal(position["base_qty"])
            if qty <= 0:
                continue
            price = fresh_valid_mark_for_dust(
                self.exchange,
                inst_id,
                max_age_s=self.max_market_data_age_s,
            )
            if price is not None and qty * price < self.dust_usdt:
                continue

            if not self.position_safely_protected(inst_id, qty):
                result.mismatch_count += 1
                if self.protection_manager is not None and price is not None:
                    try:
                        self.protection_manager.ensure_for_position(
                            inst_id,
                            qty,
                            reference_price=to_decimal(position["avg_entry_px"]) or price,
                        )
                        result.repaired_count += 1
                    except Exception as exc:  # noqa: BLE001
                        result.details.append({
                            "type": "protection_repair_failed",
                            "inst_id": inst_id,
                            "error": str(exc),
                        })
                if not self.position_safely_protected(inst_id, qty):
                    result.unresolved.append(
                        f"position_requires_protection:{inst_id}"
                    )


class RecoveryGate:
    """只有完整启动对账安全后才允许系统 READY。"""

    def __init__(self, reconciler: Reconciler):
        self.reconciler = reconciler

    def recover(self) -> ReconciliationResult:
        result = self.reconciler.run(startup=True)
        if not result.safe:
            raise RuntimeError(
                "启动对账存在未解决差异，系统保持 DEGRADED: "
                + ", ".join(result.unresolved)
            )
        return result
