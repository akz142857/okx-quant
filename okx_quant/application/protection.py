"""交易所托管保护单和主动退出协调。"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from decimal import Decimal

from okx_quant.application.execution import (
    ExecutionCoordinator,
    ExecutionRequest,
    is_ambiguous_write_error,
)
from okx_quant.application.reconciliation import (
    OrderResolver,
    fresh_valid_mark_for_dust,
)
from okx_quant.domain.orders import (
    OrderIntent,
    OrderState,
    ProtectionOrder,
    ProtectionState,
    SystemMode,
    generate_client_order_id,
    map_exchange_algo_state,
    to_decimal,
)
from okx_quant.exchange import (
    Exchange,
    price_on_tick,
    tradable_base_quantity,
)
from okx_quant.infrastructure.db import JournalRepository

logger = logging.getLogger(__name__)


class ProtectionManager:
    """确保所有非 dust 现货仓位拥有 ACTIVE 交易所保护单。"""

    def __init__(
        self,
        exchange: Exchange,
        journal: JournalRepository,
        *,
        default_stop_loss_pct: Decimal = Decimal("0.02"),
        default_take_profit_pct: Decimal = Decimal("0.04"),
        min_amend_ticks: int = 1,
        unknown_resolution_timeout_s: float = 5,
        dust_usdt: Decimal = Decimal("1"),
        max_market_data_age_s: float = 5,
    ):
        self.exchange = exchange
        self.journal = journal
        self.default_stop_loss_pct = default_stop_loss_pct
        self.default_take_profit_pct = default_take_profit_pct
        self.min_amend_ticks = max(min_amend_ticks, 1)
        self.unknown_resolution_timeout_s = max(
            unknown_resolution_timeout_s, 0
        )
        self.dust_usdt = dust_usdt
        self.max_market_data_age_s = max_market_data_age_s
        self._execution: ExecutionCoordinator | None = None

    def attach_to(self, coordinator: ExecutionCoordinator) -> None:
        self._execution = coordinator
        coordinator.add_fill_handler(self.on_fill)

    def on_fill(self, intent: OrderIntent, delta: Decimal) -> None:
        position = self.journal.get_position(intent.inst_id)
        qty = to_decimal(position["base_qty"]) if position else Decimal("0")
        if intent.side == "buy" and qty > 0:
            reference = to_decimal(position["avg_entry_px"])
            if reference <= 0:
                reference = to_decimal(self.exchange.get_ticker(intent.inst_id).last)
            stop = intent.requested_stop_loss
            take = intent.requested_take_profit
            try:
                self.ensure_for_position(
                    intent.inst_id,
                    qty,
                    reference_price=reference,
                    stop_loss=stop,
                    take_profit=take,
                    parent_intent_id=intent.intent_id,
                )
            except Exception as exc:
                self._emergency_exit(
                    intent.inst_id,
                    qty,
                    intent.intent_id,
                    f"保护单建立异常: {exc}",
                )
        elif intent.side == "sell":
            if qty <= 0:
                self.cancel_all(intent.inst_id)
                return
            active = self._active(intent.inst_id)
            if active is None:
                return
            try:
                reference = to_decimal(position["avg_entry_px"])
                if reference <= 0:
                    reference = to_decimal(
                        self.exchange.get_ticker(intent.inst_id).last
                    )
                self.ensure_for_position(
                    intent.inst_id,
                    qty,
                    reference_price=reference,
                    stop_loss=active.trigger_px,
                    take_profit=active.take_profit_px,
                    parent_intent_id=intent.intent_id,
                )
            except Exception as exc:
                self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
                self.journal.enqueue_outbox(
                    "page.protection_resize_failed",
                    {
                        "inst_id": intent.inst_id,
                        "qty": str(qty),
                        "error": str(exc),
                    },
                )

    def ensure_for_position(
        self,
        inst_id: str,
        qty: Decimal,
        *,
        reference_price: Decimal,
        stop_loss: Decimal = Decimal("0"),
        take_profit: Decimal = Decimal("0"),
        parent_intent_id: str = "",
    ) -> ProtectionOrder:
        if qty <= 0:
            raise ValueError("保护数量必须大于 0")
        if reference_price <= 0:
            raise ValueError("创建保护单需要有效参考价")
        if stop_loss <= 0:
            stop_loss = reference_price * (Decimal("1") - self.default_stop_loss_pct)
        if take_profit <= 0:
            take_profit = reference_price * (Decimal("1") + self.default_take_profit_pct)
        instrument = self.exchange.get_instrument(inst_id)
        original_qty = qty
        qty, remainder = tradable_base_quantity(qty, instrument)
        if qty <= 0:
            raise ValueError("持仓低于交易所 lotSz/minSz，无法建立保护单")
        stop_loss = price_on_tick(stop_loss, instrument, up=False)
        take_profit = price_on_tick(take_profit, instrument, up=True)
        if remainder > 0:
            mark = fresh_valid_mark_for_dust(
                self.exchange,
                inst_id,
                max_age_s=self.max_market_data_age_s,
            )
            if mark is None or remainder * mark >= self.dust_usdt:
                raise ValueError(
                    "lotSz 量化产生 material 未覆盖余量，拒绝保持仓位"
                )
            self.journal.record_event(
                "position_nontradable_remainder",
                severity="warning",
                payload={
                    "inst_id": inst_id,
                    "position_qty": str(original_qty),
                    "protected_qty": str(qty),
                    "remainder_qty": str(remainder),
                },
            )
        if stop_loss >= reference_price:
            raise ValueError("现货多头止损必须低于参考价")
        if take_profit <= reference_price:
            raise ValueError("现货多头止盈必须高于参考价")

        active = self._active(inst_id)
        if active:
            # 只允许止损上移；保护数量覆盖可交易仓位，低于 dust 的
            # 不可交易余量由运行时单独验证。
            target_stop = max(active.trigger_px, stop_loss)
            try:
                tick = to_decimal(instrument.tick_size)
            except Exception:  # noqa: BLE001
                tick = Decimal("0")
            stop_changed = target_stop > active.trigger_px and (
                tick <= 0
                or target_stop - active.trigger_px >= tick * self.min_amend_ticks
            )
            if active.protected_qty == qty and not stop_changed:
                return active
            return self._amend(
                active,
                qty,
                target_stop if stop_changed else active.trigger_px,
                take_profit,
            )

        # 恢复期间不能在旧 SUBMITTING/UNKNOWN/AMENDING 尚未裁决时补建
        # 第二张保护单；TRIGGERED 也必须先等待其实际退出订单结算。
        for existing in self.journal.list_protections(inst_id):
            if existing.state is ProtectionState.TRIGGERED:
                raise RuntimeError("保护单已触发，等待交易所退出订单结算")
            if existing.state in {
                ProtectionState.REQUIRED,
                ProtectionState.SUBMITTING,
                ProtectionState.AMENDING,
                ProtectionState.UNKNOWN,
            }:
                resolved = self._resolve_unknown(existing)
                if resolved is not None and resolved.state is ProtectionState.ACTIVE:
                    if resolved.protected_qty == qty:
                        return resolved
                    return self._amend(
                        resolved,
                        qty,
                        max(resolved.trigger_px, stop_loss),
                        take_profit,
                    )
                if resolved is not None and resolved.state is ProtectionState.TRIGGERED:
                    raise RuntimeError("保护单已触发，等待交易所退出订单结算")
                raise RuntimeError(
                    f"已有未裁决保护单 {existing.protection_id}，禁止重复创建"
                )

        protection = ProtectionOrder(
            protection_id=uuid.uuid4().hex,
            inst_id=inst_id,
            kind="oco",
            protected_qty=qty,
            trigger_px=stop_loss,
            take_profit_px=take_profit,
            state=ProtectionState.REQUIRED,
            algo_cl_ord_id=generate_client_order_id("sell"),
            parent_intent_id=parent_intent_id,
            created_at=time.time(),
            updated_at=time.time(),
        )
        self.journal.create_protection(protection)
        protection = self.journal.update_protection(
            protection, state=ProtectionState.SUBMITTING
        )
        try:
            remote = self.exchange.place_protection_order(
                inst_id,
                size=qty,
                stop_loss=stop_loss,
                take_profit=take_profit,
                algo_cl_ord_id=protection.algo_cl_ord_id,
            )
        except Exception as exc:
            if is_ambiguous_write_error(exc):
                protection = self.journal.update_protection(
                    protection,
                    state=ProtectionState.UNKNOWN,
                    last_error=str(exc),
                )
                resolved = self._resolve_unknown(
                    protection, self.unknown_resolution_timeout_s
                )
                if resolved is not None:
                    if resolved.state in {
                        ProtectionState.ACTIVE,
                        ProtectionState.TRIGGERED,
                    }:
                        return resolved
                    return self._emergency(
                        resolved,
                        f"保护单已确认未生效: {resolved.state.value}",
                        exit_qty=qty,
                    )
                self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
                self.journal.enqueue_outbox(
                    "page.emergency_exit_blocked",
                    {
                        "inst_id": protection.inst_id,
                        "protection_id": protection.protection_id,
                        "reason": f"保护单提交结果未知: {exc}",
                    },
                )
                return protection
            protection = self.journal.update_protection(
                protection,
                state=ProtectionState.FAILED,
                last_error=str(exc),
            )
            return self._emergency(protection, f"保护单创建失败: {exc}")
        updated = self.journal.update_protection(
            protection,
            state=remote.state,
            exchange_algo_id=remote.algo_id,
            protected_qty=remote.protected_qty or qty,
            trigger_px=remote.trigger_px or stop_loss,
            take_profit_px=remote.take_profit_px or take_profit,
        )
        if updated.state is ProtectionState.ACTIVE:
            return updated
        if updated.state is ProtectionState.TRIGGERED:
            self.journal.set_mode(SystemMode.DEGRADED)
            return updated
        if updated.state is ProtectionState.CANCELED:
            self._emergency_exit(
                updated.inst_id,
                qty,
                updated.parent_intent_id,
                "保护单创建后立即取消",
            )
            return updated
        return self._emergency(
            updated,
            f"保护单创建未进入 ACTIVE: {updated.state.value}",
            exit_qty=qty,
        )

    def _amend(
        self,
        protection: ProtectionOrder,
        qty: Decimal,
        stop_loss: Decimal,
        take_profit: Decimal,
    ) -> ProtectionOrder:
        protection = self.journal.update_protection(
            protection, state=ProtectionState.AMENDING
        )
        try:
            remote = self.exchange.amend_algo_order(
                protection.inst_id,
                protection.exchange_algo_id,
                size=qty,
                stop_loss=stop_loss,
                take_profit=take_profit,
                req_id=uuid.uuid4().hex[:32],
            )
        except Exception as exc:
            if is_ambiguous_write_error(exc):
                unknown = self.journal.update_protection(
                    protection,
                    state=ProtectionState.UNKNOWN,
                    last_error=str(exc),
                )
                resolved = self._resolve_unknown(
                    unknown, self.unknown_resolution_timeout_s
                )
                if resolved and resolved.state is ProtectionState.ACTIVE:
                    if resolved.protected_qty == qty:
                        return resolved
                    return self._abort_amend_and_exit(
                        resolved,
                        qty,
                        f"保护单修改结果可见但数量不足: {exc}",
                    )
                if resolved and resolved.state is ProtectionState.TRIGGERED:
                    self.journal.set_mode(SystemMode.DEGRADED)
                    return resolved
                return self._abort_amend_and_exit(
                    resolved or unknown,
                    qty,
                    f"保护单修改结果未知: {exc}",
                )
            return self._abort_amend_and_exit(
                protection,
                qty,
                f"保护单修改失败: {exc}",
            )
        updated = self.journal.update_protection(
            protection,
            state=remote.state,
            protected_qty=remote.protected_qty,
            trigger_px=remote.trigger_px,
            take_profit_px=remote.take_profit_px,
        )
        if (
            updated.state is ProtectionState.ACTIVE
            and updated.protected_qty == qty
        ):
            return updated
        if updated.state is ProtectionState.TRIGGERED:
            self.journal.set_mode(SystemMode.DEGRADED)
            return updated
        return self._abort_amend_and_exit(
            updated,
            qty,
            f"保护单修改未覆盖目标数量: {updated.state.value}",
        )

    def _abort_amend_and_exit(
        self,
        protection: ProtectionOrder,
        exit_qty: Decimal,
        reason: str,
    ) -> ProtectionOrder:
        """先明确取消旧保护，再按完整 durable 仓位紧急退出。

        旧 OCO 可能冻结余额或已经触发；取消未知时宁可保持硬阻塞，也
        不能并发提交第二个 SELL。
        """
        try:
            remote = self.exchange.cancel_algo_order(
                protection.inst_id,
                protection.exchange_algo_id,
            )
        except Exception as exc:
            try:
                unknown = self.journal.update_protection(
                    protection,
                    state=ProtectionState.UNKNOWN,
                    last_error=f"{reason}; 旧保护取消未确认: {exc}",
                )
            except ValueError:
                unknown = protection
            self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
            self.journal.enqueue_outbox(
                "page.emergency_exit_blocked",
                {
                    "inst_id": protection.inst_id,
                    "protection_id": protection.protection_id,
                    "reason": reason,
                    "cancel_error": str(exc),
                },
            )
            return unknown

        updated = self.journal.update_protection(
            protection,
            state=remote.state,
            exchange_algo_id=remote.algo_id or protection.exchange_algo_id,
            protected_qty=remote.protected_qty or protection.protected_qty,
            trigger_px=remote.trigger_px or protection.trigger_px,
            take_profit_px=(
                remote.take_profit_px or protection.take_profit_px
            ),
            last_error=reason,
        )
        if updated.state is ProtectionState.TRIGGERED:
            self.journal.set_mode(SystemMode.DEGRADED)
            self.journal.enqueue_outbox(
                "page.protection_triggered_during_emergency",
                {
                    "inst_id": protection.inst_id,
                    "protection_id": protection.protection_id,
                },
            )
            return updated
        if updated.state is not ProtectionState.CANCELED:
            self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
            self.journal.enqueue_outbox(
                "page.emergency_exit_blocked",
                {
                    "inst_id": protection.inst_id,
                    "protection_id": protection.protection_id,
                    "reason": f"取消返回 {updated.state.value}",
                },
            )
            return updated
        self._emergency_exit(
            protection.inst_id,
            exit_qty,
            protection.parent_intent_id,
            reason,
        )
        return updated

    def _resolve_unknown(
        self,
        protection: ProtectionOrder,
        timeout_s: float = 0,
    ) -> ProtectionOrder | None:
        deadline = time.monotonic() + max(timeout_s, 0)
        while True:
            try:
                remote = self.exchange.get_algo_order(
                    algo_id=protection.exchange_algo_id,
                    algo_cl_ord_id=protection.algo_cl_ord_id,
                )
                if remote.state is ProtectionState.UNKNOWN:
                    raise RuntimeError("交易所保护状态仍未知")
                return self.journal.update_protection(
                    protection,
                    state=remote.state,
                    exchange_algo_id=remote.algo_id,
                    protected_qty=remote.protected_qty,
                    trigger_px=remote.trigger_px,
                    take_profit_px=remote.take_profit_px,
                )
            except Exception:  # noqa: BLE001
                if time.monotonic() >= deadline:
                    return None
                time.sleep(0.2)

    def process_algo_events(self, rows: list[dict]) -> None:
        for raw in rows:
            algo_id = str(raw.get("algoId", ""))
            client_id = str(raw.get("algoClOrdId", ""))
            local = self.journal.find_protection(
                exchange_algo_id=algo_id,
                algo_cl_ord_id=client_id,
            )
            if local is None:
                self.journal.set_mode(SystemMode.DEGRADED)
                self.journal.record_event(
                    "external_algo_order",
                    severity="critical",
                    payload={"raw": raw},
                )
                continue
            state = map_exchange_algo_state(str(raw.get("state", "")))
            try:
                self.journal.update_protection(
                    local,
                    state=state,
                    exchange_algo_id=algo_id or local.exchange_algo_id,
                    protected_qty=to_decimal(
                        raw.get("sz"), str(local.protected_qty)
                    ),
                    trigger_px=to_decimal(
                        raw.get("slTriggerPx") or raw.get("triggerPx"),
                        str(local.trigger_px),
                    ),
                    take_profit_px=to_decimal(
                        raw.get("tpTriggerPx"),
                        str(local.take_profit_px),
                    ),
                )
            except ValueError as exc:
                self.journal.set_mode(SystemMode.DEGRADED)
                self.journal.record_event(
                    "out_of_order_algo_transition",
                    severity="warning",
                    correlation_id=local.protection_id,
                    payload={"error": str(exc), "raw": raw},
                )

    def reconcile(self, inst_id: str = "") -> list[str]:
        """对账本地和交易所 pending algo，返回未解决问题。"""
        unresolved: list[str] = []
        remote = self.exchange.get_pending_algo_orders(inst_id)
        remote_ids = {p.algo_id for p in remote if p.algo_id}
        remote_by_inst: dict[str, list[str]] = {}
        for item in remote:
            remote_by_inst.setdefault(item.inst_id, []).append(item.algo_id)
        for remote_inst_id, algo_ids in remote_by_inst.items():
            if len(algo_ids) > 1:
                unresolved.append(
                    "multiple_remote_protections:"
                    f"{remote_inst_id}:{','.join(sorted(algo_ids))}"
                )
        for item in remote:
            local = self.journal.find_protection(
                exchange_algo_id=item.algo_id,
                algo_cl_ord_id=item.algo_cl_ord_id,
            )
            position = self.journal.get_position(item.inst_id)
            position_qty = (
                to_decimal(position["base_qty"])
                if position
                else Decimal("0")
            )
            if position_qty <= 0:
                try:
                    canceled = self.exchange.cancel_algo_order(
                        item.inst_id, item.algo_id
                    )
                    if local is not None:
                        self.journal.update_protection(
                            local, state=canceled.state
                        )
                    self.journal.record_event(
                        "orphan_protection_canceled",
                        severity="warning",
                        correlation_id=item.algo_id,
                        payload={"inst_id": item.inst_id},
                    )
                except Exception as exc:  # noqa: BLE001
                    unresolved.append(
                        f"orphan_protection_cancel_failed:"
                        f"{item.inst_id}:{item.algo_id}:{exc}"
                    )
                continue
            if local is None:
                protection = ProtectionOrder(
                    protection_id=uuid.uuid4().hex,
                    inst_id=item.inst_id,
                    kind=item.kind,
                    protected_qty=item.protected_qty,
                    trigger_px=item.trigger_px,
                    take_profit_px=item.take_profit_px,
                    state=item.state,
                    algo_cl_ord_id=item.algo_cl_ord_id or generate_client_order_id("sell"),
                    exchange_algo_id=item.algo_id,
                    created_at=item.update_ts or time.time(),
                    updated_at=time.time(),
                    last_error="交易所保护单由对账导入",
                )
                self.journal.create_protection(protection)
                unresolved.append(f"external_protection:{item.inst_id}:{item.algo_id}")
            else:
                try:
                    if (
                        local.state is not item.state
                        or local.exchange_algo_id != item.algo_id
                        or local.protected_qty != item.protected_qty
                        or local.trigger_px != item.trigger_px
                        or local.take_profit_px != item.take_profit_px
                    ):
                        self.journal.update_protection(
                            local,
                            state=item.state,
                            exchange_algo_id=item.algo_id,
                            protected_qty=item.protected_qty,
                            trigger_px=item.trigger_px,
                            take_profit_px=item.take_profit_px,
                        )
                except ValueError as exc:
                    unresolved.append(
                        f"illegal_protection_transition:"
                        f"{local.protection_id}:{exc}"
                    )
        local_by_inst: dict[str, list[str]] = {}
        for local in self.journal.list_protections(inst_id, active_only=True):
            local_by_inst.setdefault(local.inst_id, []).append(
                local.protection_id
            )
        for local_inst_id, protection_ids in local_by_inst.items():
            if len(protection_ids) > 1:
                unresolved.append(
                    "multiple_local_protections:"
                    f"{local_inst_id}:{','.join(sorted(protection_ids))}"
                )
        for local in self.journal.list_protections(inst_id):
            position = self.journal.get_position(local.inst_id)
            position_qty = (
                to_decimal(position["base_qty"])
                if position
                else Decimal("0")
            )
            if local.state is ProtectionState.REQUIRED:
                self.journal.update_protection(
                    local,
                    state=ProtectionState.FAILED,
                    last_error="恢复发现 REQUIRED：可证明尚未发送到交易所",
                )
                continue
            if local.state is ProtectionState.TRIGGERED:
                if position_qty > 0:
                    unresolved.append(
                        f"triggered_protection_settlement:"
                        f"{local.inst_id}:{local.protection_id}"
                    )
                continue
            if local.state in {
                ProtectionState.FAILED,
                ProtectionState.CANCELED,
                ProtectionState.EMERGENCY_EXIT,
            }:
                continue
            if position_qty <= 0:
                if not local.exchange_algo_id:
                    unresolved.append(
                        f"orphan_local_protection:{local.protection_id}"
                    )
                    continue
                try:
                    canceled = self.exchange.cancel_algo_order(
                        local.inst_id, local.exchange_algo_id
                    )
                    self.journal.update_protection(
                        local, state=canceled.state
                    )
                except Exception as exc:  # noqa: BLE001
                    unresolved.append(
                        f"orphan_protection_cancel_failed:"
                        f"{local.inst_id}:{local.exchange_algo_id}:{exc}"
                    )
                continue
            if local.state in {
                ProtectionState.SUBMITTING,
                ProtectionState.AMENDING,
                ProtectionState.UNKNOWN,
            } and (
                not local.exchange_algo_id
                or local.exchange_algo_id not in remote_ids
            ):
                resolved = self._resolve_unknown(local)
                if resolved is None:
                    unresolved.append(
                        f"missing_remote_protection:{local.inst_id}:{local.protection_id}"
                    )
                elif resolved.state is ProtectionState.TRIGGERED:
                    unresolved.append(
                        f"triggered_protection_settlement:"
                        f"{local.inst_id}:{local.protection_id}"
                    )
                elif resolved.state is not ProtectionState.ACTIVE:
                    unresolved.append(
                        f"unresolved_protection_state:"
                        f"{local.inst_id}:{local.protection_id}:"
                        f"{resolved.state.value}"
                    )
            elif (
                local.state is ProtectionState.ACTIVE
                and local.exchange_algo_id
                and local.exchange_algo_id not in remote_ids
            ):
                resolved = self._resolve_unknown(local)
                if resolved is None or resolved.state is not ProtectionState.ACTIVE:
                    unresolved.append(
                        f"missing_remote_protection:{local.inst_id}:{local.protection_id}"
                    )
        return unresolved

    def cancel_all(self, inst_id: str) -> bool:
        ok = True
        for protection in self.journal.list_protections(inst_id, active_only=True):
            if not protection.exchange_algo_id:
                ok = False
                continue
            try:
                remote = self.exchange.cancel_algo_order(
                    inst_id, protection.exchange_algo_id
                )
                self.journal.update_protection(
                    protection, state=remote.state
                )
                if remote.state is ProtectionState.TRIGGERED:
                    # cancel 与交易所触发竞争时，TRIGGERED 不是“取消成功”。
                    # 调用方必须先结算 actualOrdId，禁止继续普通 SELL。
                    ok = False
            except Exception as exc:  # noqa: BLE001
                unknown = self.journal.update_protection(
                    protection,
                    state=ProtectionState.UNKNOWN,
                    last_error=str(exc),
                )
                if is_ambiguous_write_error(exc):
                    resolved = self._resolve_unknown(
                        unknown, self.unknown_resolution_timeout_s
                    )
                    if (
                        resolved is not None
                        and resolved.state is ProtectionState.CANCELED
                    ):
                        continue
                ok = False
        return ok

    def _active(self, inst_id: str) -> ProtectionOrder | None:
        for protection in self.journal.list_protections(inst_id, active_only=True):
            if protection.state is ProtectionState.ACTIVE:
                return protection
        return None

    def _emergency(
        self,
        protection: ProtectionOrder,
        reason: str,
        *,
        exit_qty: Decimal | None = None,
    ) -> ProtectionOrder:
        protection = self.journal.update_protection(
            protection,
            state=ProtectionState.EMERGENCY_EXIT,
            last_error=reason,
        )
        self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
        self.journal.record_event(
            "position_unprotected",
            severity="critical",
            correlation_id=protection.parent_intent_id,
            payload={
                "inst_id": protection.inst_id,
                "qty": str(protection.protected_qty),
                "reason": reason,
            },
        )
        self.journal.enqueue_outbox(
            "page.position_unprotected",
            {
                "inst_id": protection.inst_id,
                "qty": str(protection.protected_qty),
                "reason": reason,
            },
        )
        self._submit_emergency_sell(
            protection.inst_id,
            exit_qty or protection.protected_qty,
            protection.parent_intent_id,
            reason,
        )
        return protection

    def _emergency_exit(
        self,
        inst_id: str,
        qty: Decimal,
        parent_intent_id: str,
        reason: str,
    ) -> None:
        self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
        self.journal.record_event(
            "position_unprotected",
            severity="critical",
            correlation_id=parent_intent_id,
            payload={"inst_id": inst_id, "qty": str(qty), "reason": reason},
        )
        self.journal.enqueue_outbox(
            "page.position_unprotected",
            {"inst_id": inst_id, "qty": str(qty), "reason": reason},
        )
        self._submit_emergency_sell(inst_id, qty, parent_intent_id, reason)

    def _submit_emergency_sell(
        self,
        inst_id: str,
        qty: Decimal,
        parent_intent_id: str,
        reason: str,
    ) -> None:
        if self._execution is None or qty <= 0:
            return
        try:
            instrument = self.exchange.get_instrument(inst_id)
            sell_qty, remainder = tradable_base_quantity(qty, instrument)
            if sell_qty <= 0:
                raise RuntimeError(
                    "紧急退出数量低于交易所 lotSz/minSz，需人工处置"
                )
            if remainder > 0:
                self.journal.record_event(
                    "emergency_exit_nontradable_remainder",
                    severity="critical",
                    correlation_id=parent_intent_id,
                    payload={
                        "inst_id": inst_id,
                        "requested_qty": str(qty),
                        "sell_qty": str(sell_qty),
                        "remainder_qty": str(remainder),
                    },
                )
            intent = self._execution.submit(ExecutionRequest(
                inst_id=inst_id,
                side="sell",
                base_qty=sell_qty,
            ))
            self.journal.record_event(
                "emergency_exit_submitted",
                severity="critical",
                correlation_id=intent.intent_id,
                payload={
                    "inst_id": inst_id,
                    "state": intent.state.value,
                    "reason": reason,
                },
            )
            if intent.state is not OrderState.FILLED:
                self.journal.enqueue_outbox(
                    "page.emergency_exit_unresolved",
                    {
                        "inst_id": inst_id,
                        "intent_id": intent.intent_id,
                        "state": intent.state.value,
                    },
                )
        except Exception as exc:
            self.journal.record_event(
                "emergency_exit_failed",
                severity="critical",
                correlation_id=parent_intent_id,
                payload={"inst_id": inst_id, "error": str(exc)},
            )
            self.journal.enqueue_outbox(
                "page.emergency_exit_failed",
                {"inst_id": inst_id, "error": str(exc)},
            )


class ExitCoordinator:
    """用 exit lease 串行化策略 SELL、人工 flatten 和保护单触发竞争。"""

    def __init__(
        self,
        exchange: Exchange,
        journal: JournalRepository,
        execution: ExecutionCoordinator,
        protection: ProtectionManager,
        operation_lock: threading.RLock | None = None,
        balance_release_timeout_s: float = 3,
    ):
        self.exchange = exchange
        self.journal = journal
        self.execution = execution
        self.protection = protection
        self.operation_lock = operation_lock or execution.operation_lock
        self.balance_release_timeout_s = balance_release_timeout_s

    def exit_position(self, inst_id: str, reason: str = "") -> OrderIntent | None:
        with self.operation_lock:
            return self._exit_position(inst_id, reason)

    def _exit_position(self, inst_id: str, reason: str = "") -> OrderIntent | None:
        owner = uuid.uuid4().hex
        if not self.journal.acquire_exit_lease(inst_id, owner, ttl_s=30):
            raise RuntimeError(f"{inst_id} 已有退出流程执行中")
        workflow_started = time.monotonic()
        workflow_deadline = (
            workflow_started + self.balance_release_timeout_s
        )
        deadline_timer = threading.Timer(
            self.balance_release_timeout_s,
            self._page_exit_deadline,
            args=(inst_id, owner, workflow_started),
        )
        deadline_timer.daemon = True
        deadline_timer.start()
        release = True
        try:
            # lease 只负责互斥，不能充当订单事实。即使 lease 因进程故障
            # 过期，已有 UNKNOWN/live SELL 仍绝不能重复提交。
            resolver = OrderResolver(self.exchange, self.journal)
            # 必须先冻结/取消仍可能继续增仓的 BUY。否则卖出当前 partial
            # fill 后，原 BUY 继续成交会把“全退”重新变成持仓。
            for pending in self.journal.list_nonterminal_intents(inst_id):
                if pending.side != "buy":
                    continue
                resolved = resolver.resolve(pending)
                if resolved is None:
                    self.journal.set_mode(SystemMode.DEGRADED)
                    release = False
                    return None
                if resolved.state.is_terminal:
                    continue
                if not resolved.exchange_ord_id:
                    self.journal.set_mode(SystemMode.DEGRADED)
                    release = False
                    return None
                try:
                    canceled = self.exchange.cancel_order(
                        inst_id, resolved.exchange_ord_id
                    )
                    resolved, _ = self.execution.process_exchange_update(canceled)
                except Exception as exc:
                    self.journal.set_mode(SystemMode.DEGRADED)
                    self.journal.record_event(
                        "exit_pending_buy_cancel_unresolved",
                        severity="critical",
                        correlation_id=pending.intent_id,
                        payload={"inst_id": inst_id, "error": str(exc)},
                    )
                    release = False
                    return None
                if not resolved.state.is_terminal:
                    self.journal.set_mode(SystemMode.DEGRADED)
                    release = False
                    return None

            for pending in self.journal.list_nonterminal_intents(inst_id):
                if pending.side != "sell":
                    continue
                resolved = resolver.resolve(pending)
                if resolved is None or not resolved.state.is_terminal:
                    self.journal.set_mode(SystemMode.DEGRADED)
                    release = False
                    return pending
                if resolved.state is OrderState.FILLED:
                    return resolved

            # 每次都检查历史 TRIGGERED，而不是只看 active_only。触发后的
            # 结算窗口必须持久阻塞重复 SELL，直到实际普通订单事实可见。
            triggered, linked = self._settle_triggered_protection(inst_id)
            if triggered:
                if linked is None or not linked.state.is_terminal:
                    release = False
                return linked

            canceled = self.protection.cancel_all(inst_id)
            # cancel 请求本身可能与触发原子竞争。无论 cancel_all 返回什么，
            # 都必须重新读取 algo 真相，不能依赖余额 available 的滞后快照。
            triggered, linked = self._settle_triggered_protection(inst_id)
            if triggered:
                if linked is None or not linked.state.is_terminal:
                    release = False
                return linked
            if not canceled:
                self.journal.set_mode(SystemMode.DEGRADED)
                raise RuntimeError("保护单取消状态未知，禁止重复卖出")

            position = self.journal.get_position(inst_id)
            local_qty = to_decimal(position["base_qty"]) if position else Decimal("0")
            if local_qty <= 0:
                return None
            base_ccy = inst_id.split("-")[0]
            available = Decimal("0")
            total = Decimal("0")
            while time.monotonic() < workflow_deadline:
                snap = self.exchange.get_balance()
                holding = snap.holding(base_ccy)
                available = to_decimal(holding.available if holding else 0)
                total = to_decimal(holding.balance if holding else 0)
                if available > 0 or total <= 0:
                    break
                time.sleep(0.1)
            sell_qty = min(local_qty, available)
            if sell_qty <= 0:
                self.journal.set_mode(SystemMode.DEGRADED)
                self.journal.enqueue_outbox(
                    "page.exit_balance_not_released",
                    {
                        "inst_id": inst_id,
                        "local_qty": str(local_qty),
                        "exchange_total": str(total),
                        "exchange_available": str(available),
                    },
                )
                raise RuntimeError("保护单取消后余额仍未释放，禁止盲目卖出")
            instrument = self.exchange.get_instrument(inst_id)
            sell_qty, remainder = tradable_base_quantity(
                sell_qty,
                instrument,
            )
            if sell_qty <= 0:
                self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
                self.journal.enqueue_outbox(
                    "page.exit_nontradable_remainder",
                    {
                        "inst_id": inst_id,
                        "local_qty": str(local_qty),
                        "exchange_available": str(available),
                    },
                )
                raise RuntimeError("退出数量低于交易所 lotSz/minSz，需人工处置")
            material_remainder = False
            if remainder > 0:
                mark = fresh_valid_mark_for_dust(
                    self.exchange,
                    inst_id,
                    max_age_s=self.protection.max_market_data_age_s,
                )
                material_remainder = (
                    mark is None
                    or remainder * mark >= self.protection.dust_usdt
                )
                self.journal.record_event(
                    "exit_nontradable_remainder",
                    severity=(
                        "critical"
                        if material_remainder
                        else "warning"
                    ),
                    payload={
                        "inst_id": inst_id,
                        "sell_qty": str(sell_qty),
                        "remainder_qty": str(remainder),
                        "material": material_remainder,
                    },
                )
                if material_remainder:
                    self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
                    self.journal.enqueue_outbox(
                        "page.exit_material_nontradable_remainder",
                        {
                            "inst_id": inst_id,
                            "remainder_qty": str(remainder),
                            "mark": str(mark or "unknown"),
                        },
                    )
            intent = self.execution.submit(ExecutionRequest(
                inst_id=inst_id,
                side="sell",
                base_qty=sell_qty,
            ))
            if intent.state is OrderState.UNKNOWN:
                release = False
            if intent.state is not OrderState.FILLED:
                self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
                self.journal.enqueue_outbox(
                    "page.exit_not_filled",
                    {
                        "inst_id": inst_id,
                        "intent_id": intent.intent_id,
                        "state": intent.state.value,
                    },
                )
            elif (
                material_remainder
                or not self._exit_postcondition(
                    inst_id,
                    intent,
                    requested_qty=sell_qty,
                )
            ):
                # 可交易部分已退出，但剩余敞口仍超过 dust 且无法按 lot
                # 下单；保持硬应急状态等待累计/人工处置。
                self.journal.set_mode(SystemMode.EMERGENCY_EXIT)
                if not material_remainder:
                    self.journal.enqueue_outbox(
                        "page.exit_postcondition_failed",
                        {
                            "inst_id": inst_id,
                            "intent_id": intent.intent_id,
                            "requested_qty": str(sell_qty),
                            "filled_qty": str(intent.acc_fill_qty),
                        },
                    )
            return intent
        finally:
            if release:
                self.journal.release_exit_lease(inst_id, owner)
                deadline_timer.cancel()

    def _page_exit_deadline(
        self,
        inst_id: str,
        owner: str,
        workflow_started: float,
    ) -> None:
        """Independent deadline observer; network calls cannot delay the Page."""
        try:
            if not self.journal.owns_exit_lease(inst_id, owner):
                return
            self.journal.set_mode(SystemMode.DEGRADED)
            self.journal.enqueue_outbox_once(
                f"exit-deadline:{inst_id}:{owner}",
                "page.exit_workflow_deadline",
                {
                    "inst_id": inst_id,
                    "owner_id": owner,
                    "elapsed_seconds": round(
                        time.monotonic() - workflow_started,
                        6,
                    ),
                    "deadline_seconds": self.balance_release_timeout_s,
                },
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "failed to persist exit workflow deadline page",
                extra={"inst_id": inst_id},
            )

    def _exit_postcondition(
        self,
        inst_id: str,
        intent: OrderIntent,
        *,
        requested_qty: Decimal,
    ) -> bool:
        """FILLED 标签不足以证明全退；本地投影与账户余额都必须只剩 dust。"""
        if intent.acc_fill_qty < requested_qty:
            return False
        position = self.journal.get_position(inst_id)
        local_qty = (
            to_decimal(position["base_qty"])
            if position is not None
            else Decimal("0")
        )
        try:
            snapshot = self.exchange.get_balance()
            holding = snapshot.holding(inst_id.split("-")[0])
            exchange_qty = to_decimal(
                holding.balance if holding is not None else 0
            )
        except Exception:  # noqa: BLE001
            return False
        if local_qty <= 0 and exchange_qty <= 0:
            return True
        mark = fresh_valid_mark_for_dust(
            self.exchange,
            inst_id,
            max_age_s=self.protection.max_market_data_age_s,
        )
        return bool(
            mark is not None
            and local_qty * mark < self.protection.dust_usdt
            and exchange_qty * mark < self.protection.dust_usdt
        )

    def _settle_triggered_protection(
        self, inst_id: str
    ) -> tuple[bool, OrderIntent | None]:
        """返回 (是否必须阻塞普通 SELL, 已关联的实际退出订单)。"""
        for local in self.journal.list_protections(inst_id):
            if (
                local.state is not ProtectionState.TRIGGERED
                and not local.exchange_algo_id
            ):
                continue
            try:
                remote = self.exchange.get_algo_order(
                    algo_id=local.exchange_algo_id,
                    algo_cl_ord_id=local.algo_cl_ord_id,
                )
            except Exception:
                if local.state is ProtectionState.TRIGGERED:
                    self.journal.set_mode(SystemMode.DEGRADED)
                    return True, None
                continue
            if remote.state is not ProtectionState.TRIGGERED:
                continue
            if local.state is not ProtectionState.TRIGGERED:
                self.journal.update_protection(
                    local, state=ProtectionState.TRIGGERED
                )
            self.journal.set_mode(SystemMode.DEGRADED)
            if not remote.actual_order_id:
                return True, None
            try:
                triggered_order = self.exchange.get_order_status(
                    inst_id,
                    ord_id=remote.actual_order_id,
                )
                linked = self.journal.find_intent(
                    exchange_ord_id=remote.actual_order_id
                )
                if linked is None:
                    linked = self.execution.import_external_update(
                        triggered_order
                    )
                else:
                    linked, _ = self.execution.process_exchange_update(
                        triggered_order
                    )
                if linked.state in {
                    OrderState.CANCELED,
                    OrderState.REJECTED,
                }:
                    self.journal.record_event(
                        "triggered_exit_definitively_failed",
                        severity="critical",
                        correlation_id=linked.intent_id,
                        payload={
                            "inst_id": inst_id,
                            "state": linked.state.value,
                        },
                    )
                    continue
                return True, linked
            except Exception as exc:
                self.journal.enqueue_outbox(
                    "page.triggered_exit_unresolved",
                    {
                        "inst_id": inst_id,
                        "algo_id": remote.algo_id,
                        "ord_id": remote.actual_order_id,
                        "error": str(exc),
                    },
                )
                return True, None
        return False, None
