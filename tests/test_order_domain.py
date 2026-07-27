"""生产订单领域状态机测试。"""

import random
from decimal import Decimal

import pytest

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


@pytest.mark.unit
def test_client_order_id_meets_okx_constraints_and_is_unique():
    values = {generate_client_order_id("buy") for _ in range(1000)}
    assert len(values) == 1000
    assert all(len(v) <= 32 and v.isalnum() for v in values)


@pytest.mark.unit
def test_order_state_rejects_illegal_terminal_rollback():
    intent = OrderIntent(
        intent_id="i1",
        cl_ord_id="c1",
        inst_id="BTC-USDT",
        side="buy",
        requested_base_qty=Decimal("0.1"),
    )
    intent = intent.transition(OrderState.PERSISTED)
    intent = intent.transition(OrderState.SUBMITTING)
    intent = intent.transition(OrderState.FILLED)
    with pytest.raises(ValueError, match="非法"):
        intent.transition(OrderState.LIVE)


@pytest.mark.unit
def test_unknown_can_be_resolved_to_filled():
    intent = OrderIntent(
        intent_id="i1",
        cl_ord_id="c1",
        inst_id="BTC-USDT",
        side="buy",
        requested_base_qty=Decimal("0.1"),
    )
    intent = intent.transition(OrderState.PERSISTED)
    intent = intent.transition(OrderState.SUBMITTING)
    intent = intent.transition(OrderState.UNKNOWN)
    assert intent.transition(OrderState.FILLED).state is OrderState.FILLED


@pytest.mark.unit
def test_decimal_uses_string_conversion_for_float():
    assert to_decimal(0.1) == Decimal("0.1")


@pytest.mark.unit
def test_only_ready_mode_allows_new_risk():
    assert SystemMode.READY.allows_new_risk
    assert all(
        not mode.allows_new_risk
        for mode in SystemMode
        if mode is not SystemMode.READY
    )


@pytest.mark.unit
def test_decimal_fallback_and_algo_state_mapping():
    assert to_decimal("invalid", "1.25") == Decimal("1.25")
    assert map_exchange_algo_state("live") is ProtectionState.ACTIVE
    assert map_exchange_algo_state("effective") is ProtectionState.TRIGGERED
    assert map_exchange_algo_state("new-state") is ProtectionState.UNKNOWN


@pytest.mark.unit
def test_protection_state_machine_rejects_terminal_regression():
    protection = ProtectionOrder(
        protection_id="p1",
        inst_id="BTC-USDT",
        kind="oco",
        protected_qty=Decimal("0.1"),
        trigger_px=Decimal("49000"),
    )
    protection = protection.transition(ProtectionState.SUBMITTING)
    protection = protection.transition(ProtectionState.ACTIVE)
    protection = protection.transition(ProtectionState.TRIGGERED)
    with pytest.raises(ValueError, match="非法保护单状态转换"):
        protection.transition(ProtectionState.ACTIVE)


@pytest.mark.unit
def test_randomized_order_state_sequences_preserve_transition_contract():
    allowed = {
        OrderState.CREATED: {OrderState.PERSISTED},
        OrderState.PERSISTED: {
            OrderState.SUBMITTING,
            OrderState.REJECTED,
        },
        OrderState.SUBMITTING: {
            OrderState.ACKNOWLEDGED,
            OrderState.LIVE,
            OrderState.PARTIALLY_FILLED,
            OrderState.FILLED,
            OrderState.CANCELED,
            OrderState.REJECTED,
            OrderState.UNKNOWN,
        },
        OrderState.ACKNOWLEDGED: {
            OrderState.LIVE,
            OrderState.PARTIALLY_FILLED,
            OrderState.FILLED,
            OrderState.CANCELED,
            OrderState.UNKNOWN,
        },
        OrderState.LIVE: {
            OrderState.PARTIALLY_FILLED,
            OrderState.FILLED,
            OrderState.CANCELED,
            OrderState.UNKNOWN,
        },
        OrderState.PARTIALLY_FILLED: {
            OrderState.PARTIALLY_FILLED,
            OrderState.FILLED,
            OrderState.CANCELED,
            OrderState.UNKNOWN,
        },
        OrderState.UNKNOWN: {
            OrderState.ACKNOWLEDGED,
            OrderState.LIVE,
            OrderState.PARTIALLY_FILLED,
            OrderState.FILLED,
            OrderState.CANCELED,
            OrderState.REJECTED,
            OrderState.MANUAL_REVIEW,
        },
        OrderState.MANUAL_REVIEW: {
            OrderState.ACKNOWLEDGED,
            OrderState.LIVE,
            OrderState.PARTIALLY_FILLED,
            OrderState.FILLED,
            OrderState.CANCELED,
            OrderState.REJECTED,
            OrderState.UNKNOWN,
        },
        OrderState.FILLED: set(),
        OrderState.CANCELED: set(),
        OrderState.REJECTED: set(),
    }
    candidates = list(OrderState)
    for seed in range(100):
        rng = random.Random(seed)
        intent = OrderIntent(
            intent_id=f"i-{seed}",
            cl_ord_id=f"c-{seed}",
            inst_id="BTC-USDT",
            side="buy",
            requested_base_qty=Decimal("0.1"),
        )
        for _ in range(100):
            proposal = rng.choice(candidates)
            previous = intent
            if proposal is previous.state or proposal in allowed[previous.state]:
                intent = previous.transition(proposal)
                assert intent.state is proposal
                assert intent.version == previous.version + 1
                assert intent.requested_base_qty == previous.requested_base_qty
            else:
                with pytest.raises(ValueError, match="非法订单状态转换"):
                    previous.transition(proposal)
                assert intent is previous


@pytest.mark.unit
def test_randomized_protection_sequences_never_leave_terminal_state():
    terminal = {
        ProtectionState.TRIGGERED,
        ProtectionState.CANCELED,
        ProtectionState.EMERGENCY_EXIT,
    }
    candidates = list(ProtectionState)
    rng = random.Random(20260727)
    for seed in range(100):
        protection = ProtectionOrder(
            protection_id=f"p-{seed}",
            inst_id="BTC-USDT",
            kind="oco",
            protected_qty=Decimal("0.1"),
            trigger_px=Decimal("49000"),
        )
        for _ in range(100):
            proposal = rng.choice(candidates)
            try:
                updated = protection.transition(proposal)
            except ValueError:
                continue
            if protection.state in terminal:
                assert proposal is protection.state
            assert updated.version == protection.version + 1
            protection = updated
