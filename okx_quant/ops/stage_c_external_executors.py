"""Fail-closed OKX Demo actors for four Stage-C external-state scenarios.

The actors in this module mutate only an explicitly confirmed OKX simulated
account.  They do not manufacture Stage-C evidence.  Instead, ``prepare``
returns fixed native-acquisition requests for independently credentialed
source services.  Cleanup is a separate, bounded phase so collectors can
observe the fault before the challenge-owned exchange objects are removed.

Repository capability remains OPEN until the runtime emits the challenge-bound
postcondition events and every source role has a deployed signer unit.  See
``external_scenario_implementation_manifest``.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import asdict, dataclass, field
from decimal import ROUND_DOWN, ROUND_UP, Decimal
from typing import Protocol

STAGE_C_DEMO_CONFIRMATION = "I_UNDERSTAND_STAGE_C_DEMO_TRADES"
EXTERNAL_SCENARIOS = frozenset({
    "external-pending-buy",
    "external-fill",
    "external-protection-cancel",
    "frozen-balance",
})
REPORT_SCHEMA = "okx-quant.stage-c-external-scenario-report/v1"
COLLECTION_REQUEST_SCHEMA = (
    "okx-quant.stage-c-native-acquisition-request/v1"
)
IMPLEMENTATION_MANIFEST_SCHEMA = (
    "okx-quant.stage-c-scenario-implementation-manifest/v1"
)
_CHALLENGE_ID = re.compile(r"[0-9a-f]{32}")
_INST_ID = re.compile(r"[A-Z0-9]{2,15}-USDT")
_TERMINAL_ORDER_STATES = frozenset({"filled", "canceled"})
_LIVE_ORDER_STATES = frozenset({"live", "partially_filled"})
_BALANCE_ATTRIBUTION_TOLERANCE = Decimal("0.00000001")
_CONSUMPTION_ACTION = "attest-stage-c-global-challenge-consumption-v1"


def stable_stage_c_id(
    *,
    scenario: str,
    challenge_id: str,
    purpose: str,
    length: int = 24,
) -> str:
    """Return a stable, non-secret ID derived only from frozen identifiers."""
    if (
        scenario not in EXTERNAL_SCENARIOS
        or not _CHALLENGE_ID.fullmatch(challenge_id)
        or not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", purpose)
        or not 8 <= length <= 32
    ):
        raise ValueError("Stage-C stable ID input 非法")
    return hashlib.sha256(
        f"stage-c:{scenario}:{challenge_id}:{purpose}".encode("ascii")
    ).hexdigest()[:length]


def stable_client_order_id(
    *,
    scenario: str,
    challenge_id: str,
    purpose: str,
) -> str:
    """Return an OKX-compatible <=32 character challenge-owned clOrdId."""
    digest = stable_stage_c_id(
        scenario=scenario,
        challenge_id=challenge_id,
        purpose=purpose,
        length=10,
    )
    # Keep the registrar challenge prefix visible so an independently
    # credentialed collector can recompute ownership from the verified
    # challenge, while retaining a scenario/purpose-bound suffix.  A hash-only
    # value cannot be reconciled with a parser that has only challenge claims.
    return f"SC{challenge_id[:16]}{digest}".upper()


def stable_control_command_id(
    *,
    scenario: str,
    challenge_id: str,
    phase: str,
) -> str:
    return stable_stage_c_id(
        scenario=scenario,
        challenge_id=challenge_id,
        purpose=f"reconcile-{phase}",
        length=32,
    )


@dataclass(frozen=True)
class NativeAcquisitionRequest:
    """A locator/operation request; semantic facts are deliberately absent."""

    schema: str
    source_role: str
    kind: str
    operations: tuple[str, ...]
    parameters: dict
    collect_after_step: int
    same_snapshot_cut: str = ""
    derived_facts_forbidden: bool = True

    def __post_init__(self) -> None:
        if (
            self.schema != COLLECTION_REQUEST_SCHEMA
            or not self.source_role
            or not self.kind
            or not self.operations
            or self.collect_after_step < 1
            or not self.derived_facts_forbidden
            or any(
                key.lower() in {"facts", "payload", "result"}
                for key in self.parameters
            )
        ):
            raise ValueError("Stage-C native acquisition request 非法")


@dataclass
class ExternalScenarioReport:
    schema: str
    scenario: str
    challenge_id: str
    account_uid: str
    inst_id: str
    phase: str
    status: str
    started_at: float
    completed_at: float = 0
    stable_ids: dict[str, str] = field(default_factory=dict)
    steps: list[dict] = field(default_factory=list)
    native_acquisition_requests: list[dict] = field(default_factory=list)
    cleanup_actions: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


class ExternalScenarioActor(Protocol):
    """Narrow actor boundary implemented by the OKX Demo/Journaling adapter."""

    simulated: bool

    def account_uid(self) -> str: ...

    def instrument(self, inst_id: str) -> dict: ...

    def ticker(self, inst_id: str) -> dict: ...

    def balance(self, ccy: str) -> dict: ...

    def open_orders(self, inst_id: str) -> list[dict]: ...

    def pending_algos(self, inst_id: str) -> list[dict]: ...

    def order(self, inst_id: str, cl_ord_id: str) -> dict: ...

    def place_order(
        self,
        *,
        inst_id: str,
        side: str,
        ord_type: str,
        size: str,
        cl_ord_id: str,
        price: str = "",
        target_currency: str = "",
    ) -> dict: ...

    def cancel_order(self, *, inst_id: str, cl_ord_id: str) -> dict: ...

    def cancel_algo(self, *, inst_id: str, algo_id: str) -> dict: ...

    def reconcile(
        self,
        *,
        command_id: str,
        scenario: str,
        challenge_id: str,
        targets: dict[str, str],
        timeout_s: float,
    ) -> dict: ...

    def protection_ownership(
        self,
        *,
        inst_id: str,
        parent_cl_ord_id: str,
        parent_ord_id: str,
    ) -> dict: ...

    def postcondition_event(
        self,
        *,
        event_name: str,
        challenge_id: str,
    ) -> dict | None: ...


def _decimal(
    value: object,
    *,
    label: str,
    positive: bool = False,
) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"{label} 非 decimal") from exc
    if not parsed.is_finite() or (positive and parsed <= 0):
        raise ValueError(f"{label} 非法")
    return parsed


def _on_step(value: Decimal, step: Decimal, *, rounding: str) -> Decimal:
    if step <= 0:
        raise ValueError("instrument step 必须为正")
    return (value / step).to_integral_value(rounding=rounding) * step


def _text(value: Decimal) -> str:
    return format(value.normalize(), "f")


def _balance_detail(balance: dict, ccy: str) -> dict:
    details = balance.get("details", []) if isinstance(balance, dict) else []
    matches = [
        row
        for row in details
        if isinstance(row, dict)
        and str(row.get("ccy", "")).upper() == ccy.upper()
    ]
    if len(matches) != 1:
        raise RuntimeError(f"OKX balance 未返回唯一 {ccy} detail")
    return matches[0]


def _net_base_quantity(order: dict, base_ccy: str) -> Decimal:
    quantity = _decimal(order.get("accFillSz", "0"), label="accFillSz")
    fee = _decimal(order.get("fee", "0"), label="fee")
    if str(order.get("feeCcy", "")).upper() == base_ccy.upper():
        quantity += fee
    return max(quantity, Decimal("0"))


def _owned_order(
    order: dict,
    *,
    cl_ord_id: str,
) -> bool:
    return (
        isinstance(order, dict)
        and str(order.get("clOrdId", "")).upper() == cl_ord_id.upper()
    )


def _assert_order_matches(
    order: dict,
    *,
    inst_id: str,
    side: str,
    ord_type: str,
    size: str,
    cl_ord_id: str,
    price: str,
    target_currency: str,
) -> None:
    """Fail closed if a stable clOrdId resolves to a foreign order."""
    if (
        not _owned_order(order, cl_ord_id=cl_ord_id)
        or str(order.get("instId", "")) != inst_id
        or str(order.get("side", "")).lower() != side
        or str(order.get("ordType", "")).lower() != ord_type
        or str(order.get("tgtCcy", "")).lower()
        != target_currency.lower()
        or _decimal(order.get("sz"), label="existing order sz")
        != _decimal(size, label="requested order sz")
        or (
            bool(price)
            and _decimal(order.get("px"), label="existing order px")
            != _decimal(price, label="requested order px")
        )
        or (not price and str(order.get("px", "")) not in {"", "0"})
    ):
        raise RuntimeError(
            "stable clOrdId 已存在但 order contract 与 challenge action 不同"
        )


class StageCExternalScenarioExecutor:
    """Two-phase, bounded state machines for four OKX Demo scenarios."""

    def __init__(
        self,
        actor: ExternalScenarioActor,
        *,
        timeout_s: float = 30,
        poll_interval_s: float = 0.25,
        minimum_quote_notional: Decimal = Decimal("5.1"),
        monotonic=time.monotonic,
        sleep=time.sleep,
        wall_time=time.time,
    ):
        if (
            timeout_s <= 0
            or timeout_s > 120
            or poll_interval_s <= 0
            or poll_interval_s > 5
            or minimum_quote_notional < Decimal("5")
            or minimum_quote_notional > Decimal("10")
        ):
            raise ValueError("Stage-C executor bounded timing/notional 非法")
        self.actor = actor
        self.timeout_s = timeout_s
        self.poll_interval_s = poll_interval_s
        self.minimum_quote_notional = minimum_quote_notional
        self._monotonic = monotonic
        self._sleep = sleep
        self._wall_time = wall_time

    def prepare(
        self,
        *,
        scenario: str,
        challenge: dict,
        inst_id: str,
        confirmation: str,
    ) -> ExternalScenarioReport:
        challenge_id, account_uid = self._validate_run(
            scenario=scenario,
            challenge=challenge,
            inst_id=inst_id,
            confirmation=confirmation,
        )
        report = ExternalScenarioReport(
            schema=REPORT_SCHEMA,
            scenario=scenario,
            challenge_id=challenge_id,
            account_uid=account_uid,
            inst_id=inst_id,
            phase="prepared",
            status="running",
            started_at=self._wall_time(),
        )
        try:
            handler = {
                "external-pending-buy": self._prepare_pending_buy,
                "external-fill": self._prepare_external_fill,
                "external-protection-cancel": (
                    self._prepare_external_protection_cancel
                ),
                "frozen-balance": self._prepare_frozen_balance,
            }[scenario]
            handler(report)
            report.native_acquisition_requests = [
                asdict(item) for item in self._collection_requests(report)
            ]
            report.status = "awaiting_independent_collection"
        except Exception as exc:  # noqa: BLE001
            report.status = "prepare_failed"
            report.errors.append(
                f"{type(exc).__name__}: {str(exc)[:500]}"
            )
            self._cleanup_owned_objects(report)
        finally:
            report.completed_at = self._wall_time()
        return report

    def cleanup(
        self,
        report: ExternalScenarioReport,
        *,
        confirmation: str,
        challenge: dict,
        consumption_claims: dict,
    ) -> ExternalScenarioReport:
        self._validate_report_for_cleanup(
            report,
            confirmation,
            challenge=challenge,
            consumption_claims=consumption_claims,
        )
        report.phase = "cleanup"
        report.status = "cleanup_running"
        self._cleanup_owned_objects(report)
        report.completed_at = self._wall_time()
        report.status = (
            "cleanup_completed"
            if not report.errors
            else "cleanup_incomplete"
        )
        return report

    def _validate_run(
        self,
        *,
        scenario: str,
        challenge: dict,
        inst_id: str,
        confirmation: str,
    ) -> tuple[str, str]:
        if confirmation != STAGE_C_DEMO_CONFIRMATION:
            raise ValueError("缺少 Stage-C Demo 显式确认")
        if scenario not in EXTERNAL_SCENARIOS:
            raise ValueError("Stage-C external scenario 非法")
        if not _INST_ID.fullmatch(inst_id):
            raise ValueError("Stage-C inst_id 非法")
        if not self.actor.simulated:
            raise ValueError("Stage-C external executor 只允许 OKX simulated")
        if (
            not isinstance(challenge, dict)
            or challenge.get("scenario") != scenario
            or not _CHALLENGE_ID.fullmatch(
                str(challenge.get("challenge_id", ""))
            )
            or not isinstance(challenge.get("identity"), dict)
        ):
            raise ValueError("Stage-C verified challenge claims 非法")
        challenge_id = str(challenge["challenge_id"])
        expected_uid = str(challenge["identity"].get("account_uid", ""))
        actual_uid = self.actor.account_uid()
        if not expected_uid or actual_uid != expected_uid:
            raise ValueError("Stage-C actor account UID 与 challenge 不一致")
        return challenge_id, actual_uid

    def _validate_report_for_cleanup(
        self,
        report: ExternalScenarioReport,
        confirmation: str,
        *,
        challenge: dict,
        consumption_claims: dict,
    ) -> None:
        challenge_id, account_uid = self._validate_run(
            scenario=report.scenario,
            challenge=challenge,
            inst_id=report.inst_id,
            confirmation=confirmation,
        )
        if (
            report.schema != REPORT_SCHEMA
            or report.scenario not in EXTERNAL_SCENARIOS
            or not _CHALLENGE_ID.fullmatch(report.challenge_id)
            or not _INST_ID.fullmatch(report.inst_id)
            or not self.actor.simulated
            or account_uid != report.account_uid
            or challenge_id != report.challenge_id
            or not isinstance(consumption_claims, dict)
            or consumption_claims.get("action") != _CONSUMPTION_ACTION
            or consumption_claims.get("challenge_id") != report.challenge_id
            or consumption_claims.get("scenario") != report.scenario
        ):
            raise ValueError(
                "Stage-C cleanup report/challenge/consumption 非法"
            )
        for purpose, cl_ord_id in report.stable_ids.items():
            if purpose.endswith("cl_ord_id") and cl_ord_id != (
                stable_client_order_id(
                    scenario=report.scenario,
                    challenge_id=report.challenge_id,
                    purpose=purpose.removesuffix("_cl_ord_id"),
                )
            ):
                raise ValueError("Stage-C cleanup clOrdId 非 challenge-owned")
        source_purpose = (
            "source" if report.scenario == "frozen-balance" else "fault"
        )
        expected_sell = {
            "action": "sell_net_base",
            "source_cl_ord_id": stable_client_order_id(
                scenario=report.scenario,
                challenge_id=report.challenge_id,
                purpose=source_purpose,
            ),
        }
        if report.scenario == "external-pending-buy":
            expected_actions = ["cancel_order"]
        elif report.scenario == "external-fill":
            expected_actions = ["sell_net_base"]
            if report.stable_ids.get("fault_algo_id"):
                expected_actions.append("cancel_algo")
        elif report.scenario == "frozen-balance":
            expected_actions = ["sell_net_base", "cancel_order"]
        else:
            expected_actions = ["sell_net_base"]
        action_names = [
            str(action.get("action", ""))
            for action in report.cleanup_actions
            if isinstance(action, dict)
        ]
        if report.status != "prepare_failed":
            if action_names != expected_actions:
                raise ValueError("Stage-C cleanup action inventory 被修改")
        elif (
            len(action_names) != len(report.cleanup_actions)
            or any(action not in expected_actions for action in action_names)
        ):
            raise ValueError("Stage-C failed prepare cleanup action 非法")
        for action in report.cleanup_actions:
            if action["action"] == "cancel_order":
                self._validate_cancel_order_action(report, action)
            elif action["action"] == "sell_net_base":
                if (
                    set(action)
                    != {
                        "action",
                        "source_cl_ord_id",
                        "baseline_base_cash_balance",
                    }
                    or action["source_cl_ord_id"]
                    != expected_sell["source_cl_ord_id"]
                    or _decimal(
                        action["baseline_base_cash_balance"],
                        label="cleanup baseline base cash balance",
                    )
                    < 0
                ):
                    raise ValueError(
                        "Stage-C cleanup sell inventory 非法"
                    )
            elif action["action"] == "cancel_algo":
                if (
                    set(action)
                    != {"action", "algo_id", "algo_cl_ord_id"}
                    or action["algo_id"]
                    != report.stable_ids.get("fault_algo_id")
                    or action["algo_cl_ord_id"]
                    != report.stable_ids.get("fault_algo_client_id")
                ):
                    raise ValueError(
                        "Stage-C cleanup algo inventory 非法"
                    )
            else:
                raise ValueError("Stage-C cleanup action inventory 非法")

    @staticmethod
    def _validate_cancel_order_action(
        report: ExternalScenarioReport,
        action: dict,
    ) -> None:
        if (
            set(action) != {"action", "cl_ord_id", "contract"}
            or action["cl_ord_id"]
            != report.stable_ids.get("fault_cl_ord_id")
            or not isinstance(action["contract"], dict)
            or set(action["contract"])
            != {
                "side",
                "ord_type",
                "size",
                "price",
                "target_currency",
            }
        ):
            raise ValueError("Stage-C cleanup cancel order inventory 非法")
        contract = action["contract"]
        expected_side = (
            "buy"
            if report.scenario == "external-pending-buy"
            else "sell"
        )
        notional = (
            _decimal(contract["size"], label="cleanup order size", positive=True)
            * _decimal(
                contract["price"],
                label="cleanup order price",
                positive=True,
            )
        )
        if (
            report.scenario
            not in {"external-pending-buy", "frozen-balance"}
            or contract["side"] != expected_side
            or contract["ord_type"] != "limit"
            or contract["target_currency"] != "base_ccy"
            or (
                report.scenario == "external-pending-buy"
                and notional > Decimal("10")
            )
        ):
            raise ValueError("Stage-C cleanup cancel order contract 非法")

    def _step(self, report: ExternalScenarioReport, action: str, **ids) -> int:
        step = len(report.steps) + 1
        report.steps.append({
            "step": step,
            "action": action,
            "identifiers": {
                key: str(value)
                for key, value in sorted(ids.items())
                if value not in {None, ""}
            },
        })
        return step

    def _wait_order(
        self,
        *,
        inst_id: str,
        cl_ord_id: str,
        states: frozenset[str],
    ) -> dict:
        return self._poll(
            lambda: self.actor.order(inst_id, cl_ord_id),
            lambda row: (
                _owned_order(row, cl_ord_id=cl_ord_id)
                and str(row.get("state", "")).lower() in states
            ),
            f"order {cl_ord_id} 未进入 {sorted(states)}",
        )

    def _wait_event(
        self,
        *,
        event_name: str,
        challenge_id: str,
    ) -> dict:
        return self._poll(
            lambda: self.actor.postcondition_event(
                event_name=event_name,
                challenge_id=challenge_id,
            ),
            lambda row: (
                isinstance(row, dict)
                and row.get("event_name") == event_name
                and row.get("correlation_id") == challenge_id
            ),
            f"runtime 未生成 challenge-bound {event_name}",
        )

    def _poll(self, acquire, accept, failure: str):
        deadline = self._monotonic() + self.timeout_s
        last = None
        while self._monotonic() <= deadline:
            last = acquire()
            if accept(last):
                return last
            self._sleep(self.poll_interval_s)
        raise TimeoutError(f"{failure}; last={last!r}"[:800])

    def _instrument_values(
        self,
        inst_id: str,
    ) -> tuple[Decimal, Decimal, Decimal, Decimal]:
        instrument = self.actor.instrument(inst_id)
        ticker = self.actor.ticker(inst_id)
        lot = _decimal(instrument.get("lotSz"), label="lotSz", positive=True)
        minimum = _decimal(
            instrument.get("minSz"),
            label="minSz",
            positive=True,
        )
        tick = _decimal(
            instrument.get("tickSz"),
            label="tickSz",
            positive=True,
        )
        last = _decimal(ticker.get("last"), label="last", positive=True)
        return lot, minimum, tick, last

    def _place_or_resolve(
        self,
        *,
        inst_id: str,
        side: str,
        ord_type: str,
        size: str,
        cl_ord_id: str,
        price: str = "",
        target_currency: str = "",
    ) -> dict:
        existing = self.actor.order(inst_id, cl_ord_id)
        if existing:
            _assert_order_matches(
                existing,
                inst_id=inst_id,
                side=side,
                ord_type=ord_type,
                size=size,
                cl_ord_id=cl_ord_id,
                price=price,
                target_currency=target_currency,
            )
            return existing
        try:
            self.actor.place_order(
                inst_id=inst_id,
                side=side,
                ord_type=ord_type,
                size=size,
                cl_ord_id=cl_ord_id,
                price=price,
                target_currency=target_currency,
            )
        except Exception:  # ambiguous write: resolve by stable ID, never replay
            resolved = self.actor.order(inst_id, cl_ord_id)
            _assert_order_matches(
                resolved,
                inst_id=inst_id,
                side=side,
                ord_type=ord_type,
                size=size,
                cl_ord_id=cl_ord_id,
                price=price,
                target_currency=target_currency,
            )
            return resolved
        resolved = self.actor.order(inst_id, cl_ord_id)
        _assert_order_matches(
            resolved,
            inst_id=inst_id,
            side=side,
            ord_type=ord_type,
            size=size,
            cl_ord_id=cl_ord_id,
            price=price,
            target_currency=target_currency,
        )
        return resolved

    def _reconcile(
        self,
        report: ExternalScenarioReport,
        *,
        phase: str,
        targets: dict[str, str],
    ) -> dict:
        command_id = stable_control_command_id(
            scenario=report.scenario,
            challenge_id=report.challenge_id,
            phase=phase,
        )
        report.stable_ids[f"{phase}_command_id"] = command_id
        self._step(
            report,
            "runtime-reconcile-now",
            command_id=command_id,
        )
        result = self.actor.reconcile(
            command_id=command_id,
            scenario=report.scenario,
            challenge_id=report.challenge_id,
            targets=targets,
            timeout_s=self.timeout_s,
        )
        if result.get("status") != "completed":
            raise RuntimeError(
                f"reconcile-now 未完成: {result.get('status')}"
            )
        return result

    def _prepare_pending_buy(self, report: ExternalScenarioReport) -> None:
        lot, minimum, tick, last = self._instrument_values(report.inst_id)
        price = _on_step(last * Decimal("0.5"), tick, rounding=ROUND_DOWN)
        quantity = _on_step(
            max(minimum, self.minimum_quote_notional / price),
            lot,
            rounding=ROUND_UP,
        )
        cl_ord_id = stable_client_order_id(
            scenario=report.scenario,
            challenge_id=report.challenge_id,
            purpose="fault",
        )
        report.stable_ids["fault_cl_ord_id"] = cl_ord_id
        self._place_or_resolve(
            inst_id=report.inst_id,
            side="buy",
            ord_type="limit",
            size=_text(quantity),
            price=_text(price),
            cl_ord_id=cl_ord_id,
            target_currency="base_ccy",
        )
        report.cleanup_actions.append({
            "action": "cancel_order",
            "cl_ord_id": cl_ord_id,
            "contract": {
                "side": "buy",
                "ord_type": "limit",
                "size": _text(quantity),
                "price": _text(price),
                "target_currency": "base_ccy",
            },
        })
        order = self._wait_order(
            inst_id=report.inst_id,
            cl_ord_id=cl_ord_id,
            states=_LIVE_ORDER_STATES,
        )
        self._step(
            report,
            "okx-place-external-limit-buy",
            cl_ord_id=cl_ord_id,
            ord_id=order.get("ordId"),
        )
        self._reconcile(
            report,
            phase="fault",
            targets={
                "cl_ord_id": cl_ord_id,
                "ord_id": str(order.get("ordId", "")),
            },
        )
        self._wait_event(
            event_name="runtime.entry_frozen",
            challenge_id=report.challenge_id,
        )
        self._step(report, "observe-runtime-entry-frozen")

    def _prepare_external_fill(self, report: ExternalScenarioReport) -> None:
        cl_ord_id, order = self._create_external_fill(
            report,
            purpose="fault",
        )
        self._reconcile(
            report,
            phase="fault",
            targets={
                "cl_ord_id": cl_ord_id,
                "ord_id": str(order.get("ordId", "")),
            },
        )
        algo = self._wait_owned_protection(
            report,
            parent_cl_ord_id=cl_ord_id,
            parent_order=order,
        )
        algo_id = str(algo["algoId"])
        report.stable_ids["fault_algo_id"] = algo_id
        report.stable_ids["fault_algo_client_id"] = str(
            algo["algoClOrdId"]
        )
        report.cleanup_actions.append({
            "action": "cancel_algo",
            "algo_id": algo_id,
            "algo_cl_ord_id": str(algo["algoClOrdId"]),
        })
        self._step(
            report,
            "observe-exchange-protection-active",
            algo_id=algo_id,
        )

    def _create_external_fill(
        self,
        report: ExternalScenarioReport,
        *,
        purpose: str,
    ) -> tuple[str, dict]:
        base_ccy = report.inst_id.split("-", 1)[0]
        before_detail = _balance_detail(
            self.actor.balance(base_ccy),
            base_ccy,
        )
        baseline_cash = _decimal(
            before_detail.get("cashBal", "0"),
            label="baseline base cash balance",
        )
        if baseline_cash < 0:
            raise RuntimeError("baseline base cash balance 非法")
        cl_ord_id = stable_client_order_id(
            scenario=report.scenario,
            challenge_id=report.challenge_id,
            purpose=purpose,
        )
        report.stable_ids[f"{purpose}_cl_ord_id"] = cl_ord_id
        self._place_or_resolve(
            inst_id=report.inst_id,
            side="buy",
            ord_type="market",
            size=_text(self.minimum_quote_notional),
            cl_ord_id=cl_ord_id,
            target_currency="quote_ccy",
        )
        report.cleanup_actions.append({
            "action": "sell_net_base",
            "source_cl_ord_id": cl_ord_id,
            "baseline_base_cash_balance": _text(baseline_cash),
        })
        order = self._wait_order(
            inst_id=report.inst_id,
            cl_ord_id=cl_ord_id,
            states=frozenset({"filled"}),
        )
        net_quantity = _net_base_quantity(order, base_ccy)
        if net_quantity <= 0:
            raise RuntimeError("external market fill 未得到正数 net base")
        self._step(
            report,
            "okx-place-external-market-buy",
            cl_ord_id=cl_ord_id,
            ord_id=order.get("ordId"),
        )
        return cl_ord_id, order

    def _prepare_external_protection_cancel(
        self,
        report: ExternalScenarioReport,
    ) -> None:
        cl_ord_id, order = self._create_external_fill(
            report,
            purpose="fault",
        )
        self._reconcile(
            report,
            phase="import",
            targets={
                "cl_ord_id": cl_ord_id,
                "ord_id": str(order.get("ordId", "")),
            },
        )
        algo = self._wait_owned_protection(
            report,
            parent_cl_ord_id=cl_ord_id,
            parent_order=order,
        )
        algo_id = str(algo["algoId"])
        report.stable_ids["fault_algo_id"] = algo_id
        report.stable_ids["fault_algo_client_id"] = str(
            algo["algoClOrdId"]
        )
        self.actor.cancel_algo(inst_id=report.inst_id, algo_id=algo_id)
        self._step(
            report,
            "okx-cancel-live-protection",
            algo_id=algo_id,
        )
        self._reconcile(
            report,
            phase="fault",
            targets={
                "algo_id": algo_id,
                "cl_ord_id": cl_ord_id,
                "ord_id": str(order.get("ordId", "")),
            },
        )
        self._wait_event(
            event_name="runtime.emergency_exit",
            challenge_id=report.challenge_id,
        )
        self._step(report, "observe-runtime-emergency-exit")

    def _wait_owned_protection(
        self,
        report: ExternalScenarioReport,
        *,
        parent_cl_ord_id: str,
        parent_order: dict,
    ) -> dict:
        """Resolve an algo only through the journal parent relationship."""
        parent_ord_id = str(parent_order.get("ordId", ""))
        ownership = self._poll(
            lambda: self.actor.protection_ownership(
                inst_id=report.inst_id,
                parent_cl_ord_id=parent_cl_ord_id,
                parent_ord_id=parent_ord_id,
            ),
            lambda row: (
                isinstance(row, dict)
                and set(row)
                == {
                    "parent_intent_id",
                    "parent_cl_ord_id",
                    "parent_ord_id",
                    "inst_id",
                    "algo_cl_ord_id",
                    "algo_id",
                    "protected_qty",
                }
                and bool(str(row.get("parent_intent_id", "")))
                and row.get("parent_cl_ord_id") == parent_cl_ord_id
                and row.get("parent_ord_id") == parent_ord_id
                and row.get("inst_id") == report.inst_id
                and bool(str(row.get("algo_id", "")))
                and str(row.get("algo_cl_ord_id", "")).isalnum()
                and len(str(row.get("algo_cl_ord_id", ""))) <= 32
                and _decimal(
                    row.get("protected_qty", "0"),
                    label="journal protected qty",
                    positive=True,
                )
                > 0
            ),
            "journal 未生成 challenge parent-bound protection readiness",
        )
        algo_id = str(ownership["algo_id"])
        algo_cl_ord_id = str(ownership["algo_cl_ord_id"])
        protected_qty = _decimal(
            ownership["protected_qty"],
            label="journal protected qty",
            positive=True,
        )
        rows = self._poll(
            lambda: [
                item
                for item in self.actor.pending_algos(report.inst_id)
                if str(item.get("algoId", "")) == algo_id
                and str(item.get("algoClOrdId", "")) == algo_cl_ord_id
            ],
            lambda candidates: (
                len(candidates) == 1
                and str(candidates[0].get("state", "")).lower() == "live"
                and str(candidates[0].get("instId", "")) == report.inst_id
                and str(candidates[0].get("ordType", "")).lower() == "oco"
                and str(candidates[0].get("side", "")).lower() == "sell"
                and str(candidates[0].get("tdMode", "")).lower() == "cash"
                and _decimal(
                    candidates[0].get("sz", "0"),
                    label="exchange protected qty",
                    positive=True,
                )
                == protected_qty
            ),
            "OKX 未返回 journal parent-bound live OCO",
        )
        return rows[0]

    def _prepare_frozen_balance(self, report: ExternalScenarioReport) -> None:
        lot, minimum, tick, last = self._instrument_values(report.inst_id)
        _source_cl_ord_id, source_order = self._create_external_fill(
            report,
            purpose="source",
        )
        base_ccy = report.inst_id.split("-", 1)[0]
        owned_quantity = _net_base_quantity(source_order, base_ccy)
        quantity = _on_step(
            owned_quantity,
            lot,
            rounding=ROUND_DOWN,
        )
        if quantity < minimum:
            raise RuntimeError(
                "challenge-owned base fill 不足以构造 frozen-balance"
            )
        price = _on_step(last * Decimal("2"), tick, rounding=ROUND_UP)
        cl_ord_id = stable_client_order_id(
            scenario=report.scenario,
            challenge_id=report.challenge_id,
            purpose="fault",
        )
        report.stable_ids["fault_cl_ord_id"] = cl_ord_id
        self._place_or_resolve(
            inst_id=report.inst_id,
            side="sell",
            ord_type="limit",
            size=_text(quantity),
            price=_text(price),
            cl_ord_id=cl_ord_id,
            target_currency="base_ccy",
        )
        report.cleanup_actions.append({
            "action": "cancel_order",
            "cl_ord_id": cl_ord_id,
            "contract": {
                "side": "sell",
                "ord_type": "limit",
                "size": _text(quantity),
                "price": _text(price),
                "target_currency": "base_ccy",
            },
        })
        order = self._wait_order(
            inst_id=report.inst_id,
            cl_ord_id=cl_ord_id,
            states=_LIVE_ORDER_STATES,
        )
        self._step(
            report,
            "okx-place-locking-limit-order",
            cl_ord_id=cl_ord_id,
            ord_id=order.get("ordId"),
        )
        self._reconcile(
            report,
            phase="fault",
            targets={
                "cl_ord_id": cl_ord_id,
                "ord_id": str(order.get("ordId", "")),
            },
        )
        self._wait_event(
            event_name="journal.position_preserved",
            challenge_id=report.challenge_id,
        )
        self._step(report, "observe-journal-position-preserved")

    @staticmethod
    def _collection_requests(
        report: ExternalScenarioReport,
    ) -> tuple[NativeAcquisitionRequest, ...]:
        after = len(report.steps)
        common_okx = (
            NativeAcquisitionRequest(
                schema=COLLECTION_REQUEST_SCHEMA,
                source_role="okx_collector",
                kind="exchange.pending_orders",
                operations=("pending-orders", "account-config"),
                parameters={"inst_id": report.inst_id},
                collect_after_step=after,
            ),
            NativeAcquisitionRequest(
                schema=COLLECTION_REQUEST_SCHEMA,
                source_role="okx_collector",
                kind="exchange.pending_algos",
                operations=("pending-algos", "account-config"),
                parameters={"inst_id": report.inst_id},
                collect_after_step=after,
            ),
            NativeAcquisitionRequest(
                schema=COLLECTION_REQUEST_SCHEMA,
                source_role="okx_collector",
                kind="exchange.balances",
                operations=("balance", "account-config"),
                parameters={
                    "ccy": report.inst_id.split("-", 1)[0],
                },
                collect_after_step=after,
            ),
        )
        if report.scenario == "external-pending-buy":
            scenario_request = NativeAcquisitionRequest(
                schema=COLLECTION_REQUEST_SCHEMA,
                source_role="okx_collector",
                kind="exchange.order.external_pending",
                operations=("order", "account-config"),
                parameters={
                    "inst_id": report.inst_id,
                    "cl_ord_id": report.stable_ids["fault_cl_ord_id"],
                },
                collect_after_step=after,
            )
        elif report.scenario == "external-fill":
            scenario_request = NativeAcquisitionRequest(
                schema=COLLECTION_REQUEST_SCHEMA,
                source_role="okx_collector",
                kind="exchange.fill.external",
                operations=("order", "fills-history", "account-config"),
                parameters={
                    "inst_id": report.inst_id,
                    "cl_ord_id": report.stable_ids["fault_cl_ord_id"],
                },
                collect_after_step=after,
            )
        elif report.scenario == "external-protection-cancel":
            scenario_request = NativeAcquisitionRequest(
                schema=COLLECTION_REQUEST_SCHEMA,
                source_role="okx_collector",
                kind="exchange.protection.canceled",
                operations=("algo-order", "order", "account-config"),
                parameters={
                    "inst_id": report.inst_id,
                    "algo_id": report.stable_ids["fault_algo_id"],
                    "algo_cl_ord_id": report.stable_ids[
                        "fault_algo_client_id"
                    ],
                    "cl_ord_id": report.stable_ids["fault_cl_ord_id"],
                },
                collect_after_step=after,
            )
        else:
            scenario_request = NativeAcquisitionRequest(
                schema=COLLECTION_REQUEST_SCHEMA,
                source_role="okx_collector",
                kind="exchange.balance.frozen",
                operations=("balance", "order", "account-config"),
                parameters={
                    "inst_id": report.inst_id,
                    "ccy": report.inst_id.split("-", 1)[0],
                    "cl_ord_id": report.stable_ids["fault_cl_ord_id"],
                },
                collect_after_step=after,
            )
        postcondition = {
            "external-pending-buy": "runtime.entry_frozen",
            "external-protection-cancel": "runtime.emergency_exit",
            "frozen-balance": "journal.position_preserved",
        }.get(report.scenario)
        scenario_extra = (
            (
                NativeAcquisitionRequest(
                    schema=COLLECTION_REQUEST_SCHEMA,
                    source_role="okx_collector",
                    kind="exchange.protection.active",
                    operations=(
                        "algo-order",
                        "order",
                        "instrument",
                        "account-config",
                    ),
                    parameters={
                        "inst_id": report.inst_id,
                        "algo_id": report.stable_ids["fault_algo_id"],
                        "algo_cl_ord_id": report.stable_ids[
                            "fault_algo_client_id"
                        ],
                        "cl_ord_id": report.stable_ids[
                            "fault_cl_ord_id"
                        ],
                    },
                    collect_after_step=after,
                ),
            )
            if report.scenario == "external-fill"
            else ()
        )
        final_cut = (
            f"{report.challenge_id}:final-reconciliation-postcondition"
        )
        journal = (
            *(
                (
                    NativeAcquisitionRequest(
                        schema=COLLECTION_REQUEST_SCHEMA,
                        source_role="journal_collector",
                        kind="journal.protection_ownership",
                        operations=(
                            "snapshot:stage-c-protection-ownership",
                        ),
                        parameters={
                            "parent_cl_ord_id": report.stable_ids[
                                "fault_cl_ord_id"
                            ],
                            "algo_cl_ord_id": report.stable_ids[
                                "fault_algo_client_id"
                            ],
                            "algo_id": report.stable_ids["fault_algo_id"],
                        },
                        collect_after_step=after,
                        same_snapshot_cut=final_cut,
                    ),
                )
                if report.scenario
                in {"external-fill", "external-protection-cancel"}
                else ()
            ),
            *(
                (
                    NativeAcquisitionRequest(
                        schema=COLLECTION_REQUEST_SCHEMA,
                        source_role="journal_collector",
                        kind=postcondition,
                        operations=("snapshot:stage-c-system-event",),
                        parameters={
                            "event_name": postcondition,
                            "challenge_id": report.challenge_id,
                        },
                        collect_after_step=after,
                        same_snapshot_cut=final_cut,
                    ),
                )
                if postcondition is not None
                else ()
            ),
            *(
                NativeAcquisitionRequest(
                    schema=COLLECTION_REQUEST_SCHEMA,
                    source_role="journal_collector",
                    kind=kind,
                    operations=(f"snapshot:{query}",),
                    parameters={
                        "challenge_id": report.challenge_id,
                    },
                    collect_after_step=after,
                    same_snapshot_cut=final_cut,
                )
                for kind, query in (
                    ("reconciliation.completed", "reconciliations"),
                    ("journal.integrity", "integrity"),
                    (
                        "journal.duplicate_buy_audit",
                        "duplicate-buy-audit",
                    ),
                    ("journal.positions", "positions"),
                    ("runtime.mode", "system-mode"),
                )
            ),
        )
        return (
            scenario_request,
            *scenario_extra,
            *common_okx,
            *journal,
        )

    def _cleanup_owned_objects(
        self,
        report: ExternalScenarioReport,
    ) -> None:
        for item in list(reversed(report.cleanup_actions)):
            action = item.get("action")
            try:
                if action == "cancel_order":
                    if set(item) != {
                        "action",
                        "cl_ord_id",
                        "contract",
                    }:
                        raise ValueError(
                            "cleanup cancel order action schema 非法"
                        )
                    cl_ord_id = str(item["cl_ord_id"])
                    if cl_ord_id != report.stable_ids.get(
                        "fault_cl_ord_id"
                    ):
                        raise ValueError("cleanup order 非 challenge-owned")
                    order = self.actor.order(report.inst_id, cl_ord_id)
                    if order:
                        contract = item["contract"]
                        _assert_order_matches(
                            order,
                            inst_id=report.inst_id,
                            side=str(contract["side"]),
                            ord_type=str(contract["ord_type"]),
                            size=str(contract["size"]),
                            cl_ord_id=cl_ord_id,
                            price=str(contract["price"]),
                            target_currency=str(
                                contract["target_currency"]
                            ),
                        )
                    if (
                        order
                        and str(order.get("state", "")).lower()
                        not in _TERMINAL_ORDER_STATES
                    ):
                        self.actor.cancel_order(
                            inst_id=report.inst_id,
                            cl_ord_id=cl_ord_id,
                        )
                    self._step(
                        report,
                        "cleanup-cancel-order",
                        cl_ord_id=cl_ord_id,
                    )
                elif action == "sell_net_base":
                    if set(item) != {
                        "action",
                        "source_cl_ord_id",
                        "baseline_base_cash_balance",
                    }:
                        raise ValueError(
                            "cleanup sell action schema 非法"
                        )
                    source_cl_ord_id = str(item["source_cl_ord_id"])
                    source_purpose = (
                        "source"
                        if report.scenario == "frozen-balance"
                        else "fault"
                    )
                    expected_source = stable_client_order_id(
                        scenario=report.scenario,
                        challenge_id=report.challenge_id,
                        purpose=source_purpose,
                    )
                    if source_cl_ord_id != expected_source:
                        raise ValueError(
                            "cleanup source order 非 challenge-owned"
                        )
                    source_order = self.actor.order(
                        report.inst_id,
                        source_cl_ord_id,
                    )
                    if not source_order:
                        self._step(
                            report,
                            "cleanup-source-order-absent",
                            cl_ord_id=source_cl_ord_id,
                        )
                        continue
                    _assert_order_matches(
                        source_order,
                        inst_id=report.inst_id,
                        side="buy",
                        ord_type="market",
                        size=_text(self.minimum_quote_notional),
                        cl_ord_id=source_cl_ord_id,
                        price="",
                        target_currency="quote_ccy",
                    )
                    state = str(
                        source_order.get("state", "")
                    ).lower()
                    if state in _LIVE_ORDER_STATES:
                        self.actor.cancel_order(
                            inst_id=report.inst_id,
                            cl_ord_id=source_cl_ord_id,
                        )
                        source_order = self.actor.order(
                            report.inst_id,
                            source_cl_ord_id,
                        )
                        state = str(
                            source_order.get("state", "")
                        ).lower()
                    if state not in {"filled", "canceled"}:
                        raise RuntimeError(
                            "cleanup source BUY 终态不确定"
                        )
                    base_ccy = report.inst_id.split("-", 1)[0]
                    quantity = _net_base_quantity(
                        source_order,
                        base_ccy,
                    )
                    if quantity <= 0:
                        self._step(
                            report,
                            "cleanup-source-order-no-fill",
                            cl_ord_id=source_cl_ord_id,
                        )
                        continue
                    average_price = _decimal(
                        source_order.get("avgPx"),
                        label="cleanup source avgPx",
                        positive=True,
                    )
                    if (
                        quantity <= 0
                        or quantity * average_price > Decimal("10")
                    ):
                        raise RuntimeError(
                            "cleanup source fill 超过 Stage-C 10 USDT 硬上限"
                        )
                    baseline_cash = _decimal(
                        item["baseline_base_cash_balance"],
                        label="cleanup baseline base cash balance",
                    )
                    balance = _balance_detail(
                        self.actor.balance(base_ccy),
                        base_ccy,
                    )
                    current_cash = _decimal(
                        balance.get("cashBal", "0"),
                        label="cleanup current base cash balance",
                    )
                    current_available = _decimal(
                        balance.get("availBal", "0"),
                        label="cleanup current available base balance",
                    )
                    expected_cash = baseline_cash + quantity
                    if (
                        abs(current_cash - expected_cash)
                        > _BALANCE_ATTRIBUTION_TOLERANCE
                        or current_available
                        + _BALANCE_ATTRIBUTION_TOLERANCE
                        < expected_cash
                    ):
                        raise RuntimeError(
                            "cleanup challenge-owned base 归属/余额缺口，"
                            "拒绝卖出既有持仓"
                        )
                    lot, minimum, _tick, _last = self._instrument_values(
                        report.inst_id
                    )
                    quantity = _on_step(
                        quantity,
                        lot,
                        rounding=ROUND_DOWN,
                    )
                    if quantity < minimum:
                        continue
                    cl_ord_id = stable_client_order_id(
                        scenario=report.scenario,
                        challenge_id=report.challenge_id,
                        purpose="cleanup",
                    )
                    report.stable_ids["cleanup_cl_ord_id"] = cl_ord_id
                    self._place_or_resolve(
                        inst_id=report.inst_id,
                        side="sell",
                        ord_type="market",
                        size=_text(quantity),
                        cl_ord_id=cl_ord_id,
                        target_currency="base_ccy",
                    )
                    self._wait_order(
                        inst_id=report.inst_id,
                        cl_ord_id=cl_ord_id,
                        states=frozenset({"filled"}),
                    )
                    self._step(
                        report,
                        "cleanup-market-sell",
                        cl_ord_id=cl_ord_id,
                    )
                elif action == "cancel_algo":
                    if set(item) != {
                        "action",
                        "algo_id",
                        "algo_cl_ord_id",
                    }:
                        raise ValueError(
                            "cleanup cancel algo action schema 非法"
                        )
                    algo_id = str(item["algo_id"])
                    if algo_id != report.stable_ids.get("fault_algo_id"):
                        raise ValueError("cleanup algo 非 challenge-owned")
                    algo_cl_ord_id = str(item["algo_cl_ord_id"])
                    if algo_cl_ord_id != report.stable_ids.get(
                        "fault_algo_client_id"
                    ):
                        raise ValueError("cleanup algoClOrdId 非 challenge-owned")
                    matching = [
                        row
                        for row in self.actor.pending_algos(report.inst_id)
                        if str(row.get("algoId", "")) == algo_id
                        and str(row.get("algoClOrdId", ""))
                        == algo_cl_ord_id
                    ]
                    if len(matching) > 1:
                        raise RuntimeError("challenge algo 重复")
                    if matching:
                        self.actor.cancel_algo(
                            inst_id=report.inst_id,
                            algo_id=algo_id,
                        )
                    self._step(
                        report,
                        "cleanup-cancel-algo",
                        algo_id=algo_id,
                    )
                else:
                    raise ValueError("未知 Stage-C cleanup action")
            except Exception as exc:  # noqa: BLE001
                report.errors.append(
                    f"cleanup {action}: {type(exc).__name__}: "
                    f"{str(exc)[:300]}"
                )


def external_scenario_implementation_manifest(
    scenario: str,
) -> dict:
    """Return an explicit per-scenario fail-closed implementation decision."""
    if scenario not in EXTERNAL_SCENARIOS:
        raise ValueError("Stage-C external implementation scenario 非法")
    checks = {
        "fixed_demo_actor_state_machine": True,
        "explicit_simulated_trade_confirmation": True,
        "challenge_derived_stable_ids": True,
        "bounded_two_phase_cleanup": True,
        "mutating_cli_has_durable_pre_intent_checkpoint": True,
        "mutating_cli_globally_consumes_challenge": True,
        "cleanup_reverifies_challenge_and_consumption": True,
        "native_acquisition_requests_without_facts": True,
        "actor_and_source_systemd_users_separated": True,
        "challenge_attests_actor_workload_role": True,
        "raw_acquirer_and_event_signer_workloads_separated": True,
        "all_required_source_signer_units_shipped": True,
        "native_live_bridge_assembled_without_summary_facts": True,
        "runtime_emits_verified_challenge_bound_postcondition": True,
        "okx_source_read_only_api_permission_deployed": False,
        "all_required_source_signer_units_deployed": False,
        "independent_same_snapshot_final_cut_orchestrated": True,
        "real_demo_worm_receipt_verified": False,
    }
    blockers = [
        name for name, passed in checks.items() if passed is not True
    ]
    return {
        "schema": IMPLEMENTATION_MANIFEST_SCHEMA,
        "scenario": scenario,
        "status": "EXTERNAL OPEN",
        "production_capability_implemented": False,
        "checks": checks,
        "blockers": blockers,
    }


def external_scenario_implementation_manifests() -> dict[str, dict]:
    return {
        scenario: external_scenario_implementation_manifest(scenario)
        for scenario in sorted(EXTERNAL_SCENARIOS)
    }


def external_scenario_mutation_self_check(scenario: str) -> dict:
    """Report why the repository CLI must not execute external mutations."""
    manifest = external_scenario_implementation_manifest(scenario)
    return {
        "schema": "okx-quant.stage-c-external-mutation-capability/v1",
        "scenario": scenario,
        "status": manifest["status"],
        "mutation_enabled": False,
        "global_challenge_consumption_closed": True,
        "durable_pre_intent_checkpoint_closed": True,
        "blockers": [
            "okx_source_read_only_api_permission_deployed",
            "all_required_source_signer_units_deployed",
            "real_demo_worm_receipt_verified",
        ],
    }


def validate_prepared_report_for_source(
    report: ExternalScenarioReport,
) -> tuple[NativeAcquisitionRequest, ...]:
    """Recompute and validate the exact source plan from stable identifiers."""
    if (
        report.schema != REPORT_SCHEMA
        or report.scenario not in EXTERNAL_SCENARIOS
        or report.phase != "prepared"
        or report.status != "awaiting_independent_collection"
        or not _CHALLENGE_ID.fullmatch(report.challenge_id)
        or not _INST_ID.fullmatch(report.inst_id)
        or report.completed_at < report.started_at
    ):
        raise ValueError("Stage-C prepared source report identity/state 非法")
    expected_fault_id = stable_client_order_id(
        scenario=report.scenario,
        challenge_id=report.challenge_id,
        purpose="fault",
    )
    if report.stable_ids.get("fault_cl_ord_id") != expected_fault_id:
        raise ValueError("Stage-C prepared source report clOrdId 未绑定 challenge")
    if report.scenario in {"external-fill", "external-protection-cancel"}:
        algo_id = str(report.stable_ids.get("fault_algo_id", ""))
        algo_client_id = str(
            report.stable_ids.get("fault_algo_client_id", "")
        )
        if (
            not algo_id
            or not algo_client_id.isalnum()
            or len(algo_client_id) > 32
        ):
            raise ValueError("Stage-C prepared source report algo locator 非法")
    expected = StageCExternalScenarioExecutor._collection_requests(report)
    if report.native_acquisition_requests != [
        asdict(item) for item in expected
    ]:
        raise ValueError("Stage-C prepared source plan 不是固定重算结果")
    return expected
