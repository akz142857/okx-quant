"""生产交易领域对象和状态转换不变量。"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any

ZERO = Decimal("0")


def to_decimal(value: Any, default: str = "0") -> Decimal:
    """通过字符串构造 Decimal，避免把二进制 float 误差带入账务。"""
    if value in (None, ""):
        return Decimal(default)
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)


def parse_decimal_fact(
    value: Any,
    field_name: str,
    *,
    default: str | None = None,
    nonnegative: bool = False,
    positive: bool = False,
) -> Decimal:
    """严格解析外部资金事实；缺失、非法或非有限值不得伪装成零。"""
    if value in (None, ""):
        if default is None:
            raise ValueError(f"{field_name} 缺失")
        value = default
    try:
        parsed = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f"{field_name} 不是有效十进制数") from exc
    if not parsed.is_finite():
        raise ValueError(f"{field_name} 必须是有限十进制数")
    if positive and parsed <= 0:
        raise ValueError(f"{field_name} 必须大于 0")
    if nonnegative and parsed < 0:
        raise ValueError(f"{field_name} 不得小于 0")
    return parsed


class OrderState(StrEnum):
    CREATED = "created"
    PERSISTED = "persisted"
    SUBMITTING = "submitting"
    ACKNOWLEDGED = "acknowledged"
    LIVE = "live"
    PARTIALLY_FILLED = "partially_filled"
    FILLED = "filled"
    CANCELED = "canceled"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    MANUAL_REVIEW = "manual_review"

    @property
    def is_terminal(self) -> bool:
        """交易所事实已经结算，风险预留可以安全释放。"""
        return self in {
            OrderState.FILLED,
            OrderState.CANCELED,
            OrderState.REJECTED,
        }


@dataclass(frozen=True)
class IntentRiskGuard:
    """BUY 持久化事务必须再次验证的本地权威风险边界。"""

    mode_epoch: int
    snapshot_id: str
    max_snapshot_age_s: float
    max_open_positions: int
    max_order_intents_per_hour: int


class ProtectionState(StrEnum):
    REQUIRED = "required"
    SUBMITTING = "submitting"
    ACTIVE = "active"
    AMENDING = "amending"
    UNKNOWN = "unknown"
    FAILED = "failed"
    TRIGGERED = "triggered"
    CANCELED = "canceled"
    EMERGENCY_EXIT = "emergency_exit"


class SystemMode(StrEnum):
    STARTING = "starting"
    READY = "ready"
    DEGRADED = "degraded"
    HALTED = "halted"
    EMERGENCY_EXIT = "emergency_exit"
    MAINTENANCE = "maintenance"

    @property
    def allows_new_risk(self) -> bool:
        return self is SystemMode.READY


_ALLOWED_PROTECTION_TRANSITIONS: dict[
    ProtectionState, frozenset[ProtectionState]
] = {
    ProtectionState.REQUIRED: frozenset({
        ProtectionState.SUBMITTING,
        ProtectionState.FAILED,
    }),
    ProtectionState.SUBMITTING: frozenset({
        ProtectionState.ACTIVE,
        ProtectionState.UNKNOWN,
        ProtectionState.FAILED,
        ProtectionState.TRIGGERED,
        ProtectionState.CANCELED,
    }),
    ProtectionState.ACTIVE: frozenset({
        ProtectionState.AMENDING,
        ProtectionState.UNKNOWN,
        ProtectionState.TRIGGERED,
        ProtectionState.CANCELED,
    }),
    ProtectionState.AMENDING: frozenset({
        ProtectionState.ACTIVE,
        ProtectionState.UNKNOWN,
        ProtectionState.FAILED,
        ProtectionState.TRIGGERED,
        ProtectionState.CANCELED,
    }),
    ProtectionState.UNKNOWN: frozenset({
        ProtectionState.ACTIVE,
        ProtectionState.FAILED,
        ProtectionState.TRIGGERED,
        ProtectionState.CANCELED,
        ProtectionState.EMERGENCY_EXIT,
    }),
    ProtectionState.FAILED: frozenset({
        ProtectionState.TRIGGERED,
        ProtectionState.CANCELED,
        ProtectionState.EMERGENCY_EXIT,
    }),
    ProtectionState.TRIGGERED: frozenset(),
    ProtectionState.CANCELED: frozenset(),
    ProtectionState.EMERGENCY_EXIT: frozenset(),
}


_ALLOWED_TRANSITIONS: dict[OrderState, frozenset[OrderState]] = {
    OrderState.CREATED: frozenset({OrderState.PERSISTED}),
    OrderState.PERSISTED: frozenset({OrderState.SUBMITTING, OrderState.REJECTED}),
    OrderState.SUBMITTING: frozenset({
        OrderState.ACKNOWLEDGED,
        OrderState.LIVE,
        OrderState.PARTIALLY_FILLED,
        OrderState.FILLED,
        OrderState.CANCELED,
        OrderState.REJECTED,
        OrderState.UNKNOWN,
    }),
    OrderState.ACKNOWLEDGED: frozenset({
        OrderState.LIVE,
        OrderState.PARTIALLY_FILLED,
        OrderState.FILLED,
        OrderState.CANCELED,
        OrderState.UNKNOWN,
    }),
    OrderState.LIVE: frozenset({
        OrderState.PARTIALLY_FILLED,
        OrderState.FILLED,
        OrderState.CANCELED,
        OrderState.UNKNOWN,
    }),
    OrderState.PARTIALLY_FILLED: frozenset({
        OrderState.PARTIALLY_FILLED,
        OrderState.FILLED,
        OrderState.CANCELED,
        OrderState.UNKNOWN,
    }),
    OrderState.UNKNOWN: frozenset({
        OrderState.ACKNOWLEDGED,
        OrderState.LIVE,
        OrderState.PARTIALLY_FILLED,
        OrderState.FILLED,
        OrderState.CANCELED,
        OrderState.REJECTED,
        OrderState.MANUAL_REVIEW,
    }),
    OrderState.FILLED: frozenset(),
    OrderState.CANCELED: frozenset(),
    OrderState.REJECTED: frozenset(),
    # MANUAL_REVIEW 是持久化硬阻塞，不是交易所终态。后续只能由新的
    # 交易所事实或显式人工裁决推进，并在此之前持续保留风险预留。
    OrderState.MANUAL_REVIEW: frozenset({
        OrderState.ACKNOWLEDGED,
        OrderState.LIVE,
        OrderState.PARTIALLY_FILLED,
        OrderState.FILLED,
        OrderState.CANCELED,
        OrderState.REJECTED,
        OrderState.UNKNOWN,
    }),
}


@dataclass(frozen=True)
class OrderIntent:
    intent_id: str
    cl_ord_id: str
    inst_id: str
    side: str
    requested_base_qty: Decimal
    reserved_quote: Decimal = ZERO
    submission_reference_price: Decimal = ZERO
    requested_stop_loss: Decimal = ZERO
    requested_take_profit: Decimal = ZERO
    state: OrderState = OrderState.CREATED
    decision_id: str = ""
    exchange_ord_id: str = ""
    exchange_state: str = ""
    acc_fill_qty: Decimal = ZERO
    avg_fill_px: Decimal = ZERO
    fee: Decimal = ZERO
    fee_ccy: str = ""
    version: int = 0
    last_error_code: str = ""
    last_error_message: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0

    def transition(self, new_state: OrderState, **changes: Any) -> OrderIntent:
        if new_state != self.state and new_state not in _ALLOWED_TRANSITIONS[self.state]:
            raise ValueError(f"非法订单状态转换: {self.state} -> {new_state}")
        now = time.time()
        return replace(
            self,
            state=new_state,
            version=self.version + 1,
            updated_at=now,
            **changes,
        )


@dataclass(frozen=True)
class ExchangeOrder:
    inst_id: str
    side: str
    state: OrderState
    ord_id: str = ""
    cl_ord_id: str = ""
    requested_qty: Decimal = ZERO
    acc_fill_qty: Decimal = ZERO
    avg_fill_px: Decimal = ZERO
    fee: Decimal = ZERO
    fee_ccy: str = ""
    trade_id: str = ""
    update_ts: float = 0.0
    raw: dict[str, Any] | None = None


@dataclass(frozen=True)
class Fill:
    fill_id: str
    intent_id: str
    exchange_ord_id: str
    inst_id: str
    side: str
    fill_qty: Decimal
    fill_px: Decimal
    fee: Decimal = ZERO
    fee_ccy: str = ""
    trade_id: str = ""
    exchange_ts: float = 0.0
    idempotency_key: str = ""


@dataclass(frozen=True)
class ExchangeFill:
    inst_id: str
    ord_id: str
    trade_id: str
    side: str
    fill_qty: Decimal
    fill_px: Decimal
    fee: Decimal = ZERO
    fee_ccy: str = ""
    cl_ord_id: str = ""
    exchange_ts: float = 0.0
    raw: dict[str, Any] | None = None


@dataclass(frozen=True)
class ProtectionOrder:
    protection_id: str
    inst_id: str
    kind: str
    protected_qty: Decimal
    trigger_px: Decimal
    take_profit_px: Decimal = ZERO
    order_px: Decimal = Decimal("-1")
    state: ProtectionState = ProtectionState.REQUIRED
    algo_cl_ord_id: str = ""
    exchange_algo_id: str = ""
    parent_intent_id: str = ""
    version: int = 0
    created_at: float = 0.0
    updated_at: float = 0.0
    last_error: str = ""

    def transition(
        self, new_state: ProtectionState, **changes: Any
    ) -> ProtectionOrder:
        if (
            new_state != self.state
            and new_state not in _ALLOWED_PROTECTION_TRANSITIONS[self.state]
        ):
            raise ValueError(
                f"非法保护单状态转换: {self.state} -> {new_state}"
            )
        return replace(
            self,
            state=new_state,
            version=self.version + 1,
            updated_at=time.time(),
            **changes,
        )


@dataclass(frozen=True)
class ExchangeAlgoOrder:
    inst_id: str
    kind: str
    state: ProtectionState
    protected_qty: Decimal
    trigger_px: Decimal = ZERO
    take_profit_px: Decimal = ZERO
    order_px: Decimal = Decimal("-1")
    algo_id: str = ""
    algo_cl_ord_id: str = ""
    actual_order_id: str = ""
    update_ts: float = 0.0
    raw: dict[str, Any] | None = None


def map_exchange_algo_state(value: str) -> ProtectionState:
    mapping = {
        "live": ProtectionState.ACTIVE,
        "pause": ProtectionState.ACTIVE,
        "effective": ProtectionState.TRIGGERED,
        "canceled": ProtectionState.CANCELED,
        "order_failed": ProtectionState.FAILED,
        "failed": ProtectionState.FAILED,
    }
    return mapping.get((value or "").lower(), ProtectionState.UNKNOWN)


def generate_client_order_id(side: str) -> str:
    """生成不超过 32 位、仅含字母数字的高熵 clOrdId。

    交易所只约束 pending 唯一；本地数据库会额外永久唯一。
    """
    side_code = "B" if side.lower() == "buy" else "S"
    token = base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
    body = f"Q{token}{side_code}"
    checksum = hashlib.sha256(body.encode("ascii")).hexdigest()[:2].upper()
    value = f"{body}{checksum}"
    if len(value) > 32 or not value.isalnum():
        raise AssertionError("生成的 clOrdId 不符合 OKX 约束")
    return value


def map_exchange_order_state(value: str) -> OrderState:
    """把 OKX 状态映射到领域状态。"""
    mapping = {
        "live": OrderState.LIVE,
        "partially_filled": OrderState.PARTIALLY_FILLED,
        "filled": OrderState.FILLED,
        "canceled": OrderState.CANCELED,
        "mmp_canceled": OrderState.CANCELED,
        "rejected": OrderState.REJECTED,
    }
    return mapping.get((value or "").lower(), OrderState.UNKNOWN)
