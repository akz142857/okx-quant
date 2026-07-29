"""受限 Demo validation probe 的 durable saga。"""

from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from decimal import ROUND_DOWN, ROUND_UP, Decimal
from enum import StrEnum
from pathlib import Path

from okx_quant.application.approval import canonical_bytes
from okx_quant.application.execution import (
    ExecutionCoordinator,
    ExecutionRequest,
)
from okx_quant.application.protection import (
    ExitCoordinator,
    ProtectionManager,
)
from okx_quant.application.reconciliation import OrderResolver
from okx_quant.domain.orders import (
    OrderIntent,
    OrderState,
    ProtectionState,
    SystemMode,
    probe_client_order_ids,
    to_decimal,
)
from okx_quant.exchange import Exchange
from okx_quant.infrastructure.db import JournalRepository

MIN_PROBE_NOTIONAL_USDT = Decimal("5")
# 这是发布源码和数据库 CHECK 共同约束的代码常量，不可由配置放大。
MAX_PROBE_NOTIONAL_USDT = Decimal("10")
PROBE_SOURCE = "demo_validation_probe"
TERMINAL_PROBE_STATES = {"DONE", "REJECTED", "FAILED", "MANUAL_REVIEW"}
BUY_RESOLUTION_TIMEOUT_S = 30
PROTECTION_ACTIVATION_TIMEOUT_S = 10
FORMAL_PROBE_DAYS = 30
FORMAL_SPREAD_BUCKETS = ((0.0, 3.0), (3.0, 10.0))
FORMAL_VOLATILITY_BUCKETS = ((0.0, 15.0), (15.0, 80.0))
_SCHEDULE_KEYS = {
    "version",
    "action",
    "schedule_id",
    "created_at",
    "slots",
}
_SCHEDULE_SLOT_KEYS = {
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


def validate_probe_schedule(value: object) -> dict:
    """Validate an exact, precommitted UTC/liquidity sampling schedule."""
    if not isinstance(value, dict) or set(value) != _SCHEDULE_KEYS:
        raise ValueError("probe schedule schema 非法")
    try:
        created_at = datetime.fromisoformat(str(value["created_at"]))
    except (TypeError, ValueError) as exc:
        raise ValueError("probe schedule created_at 非法") from exc
    slots = value["slots"]
    if (
        value["version"] != 2
        or value["action"] != "precommit-demo-probe-schedule"
        or not str(value["schedule_id"]).strip()
        or created_at.tzinfo is None
        or created_at.utcoffset() is None
        or not isinstance(slots, list)
        or not slots
    ):
        raise ValueError("probe schedule identity 非法")
    identities: set[tuple[str, int]] = set()
    day_counts: dict[str, int] = {}
    for slot in slots:
        if not isinstance(slot, dict) or set(slot) != _SCHEDULE_SLOT_KEYS:
            raise ValueError("probe schedule slot schema 非法")
        try:
            day = datetime.fromisoformat(f"{slot['day']}T00:00:00+00:00")
            started = datetime.fromisoformat(str(slot["window_start"]))
            ended = datetime.fromisoformat(str(slot["window_end"]))
            numeric = [
                float(slot[key])
                for key in (
                    "spread_min_bps",
                    "spread_max_bps",
                    "volatility_min_bps",
                    "volatility_max_bps",
                )
            ]
        except (TypeError, ValueError) as exc:
            raise ValueError("probe schedule slot 时间/数值非法") from exc
        identity = (str(slot["day"]), slot["slot"])
        if (
            type(slot["slot"]) is not int
            or slot["slot"] not in {1, 2}
            or identity in identities
            or not str(slot["inst_id"]).endswith("-USDT")
            or slot["direction"] != "buy_then_exit"
            or started.tzinfo is None
            or ended.tzinfo is None
            or created_at.astimezone(UTC) >= started.astimezone(UTC)
            or started.astimezone(UTC).date() != day.date()
            or ended.astimezone(UTC).date() != day.date()
            or not timedelta(minutes=5)
            <= ended.astimezone(UTC) - started.astimezone(UTC)
            <= timedelta(hours=8)
            or any(not math.isfinite(item) or item < 0 for item in numeric)
            or not numeric[0] < numeric[1]
            or not numeric[2] < numeric[3]
        ):
            raise ValueError("probe schedule slot policy 非法")
        identities.add(identity)
        day_counts[identity[0]] = day_counts.get(identity[0], 0) + 1
    if any(count != 1 for count in day_counts.values()):
        raise ValueError("probe schedule 每日必须精确预注册一个 slot")
    return value


def validate_formal_probe_schedule(value: object) -> dict:
    """Require a 30-day schedule that cannot cherry-pick time/liquidity."""
    schedule = validate_probe_schedule(value)
    slots = sorted(schedule["slots"], key=lambda item: item["day"])
    days = [datetime.fromisoformat(f"{item['day']}T00:00:00+00:00").date() for item in slots]
    if len(days) != FORMAL_PROBE_DAYS or any(
        right - left != timedelta(days=1) for left, right in zip(days, days[1:], strict=False)
    ):
        raise ValueError("formal probe schedule 必须覆盖精确 30 个连续 UTC 日")
    time_bins = Counter(
        datetime.fromisoformat(item["window_start"]).astimezone(UTC).hour // 6 for item in slots
    )
    spread_buckets = Counter(
        (float(item["spread_min_bps"]), float(item["spread_max_bps"])) for item in slots
    )
    volatility_buckets = Counter(
        (
            float(item["volatility_min_bps"]),
            float(item["volatility_max_bps"]),
        )
        for item in slots
    )
    joint_liquidity = Counter(
        (
            (float(item["spread_min_bps"]), float(item["spread_max_bps"])),
            (
                float(item["volatility_min_bps"]),
                float(item["volatility_max_bps"]),
            ),
        )
        for item in slots
    )
    joint_time_liquidity = Counter(
        (
            datetime.fromisoformat(item["window_start"]).astimezone(UTC).hour // 6,
            (float(item["spread_min_bps"]), float(item["spread_max_bps"])),
            (
                float(item["volatility_min_bps"]),
                float(item["volatility_max_bps"]),
            ),
        )
        for item in slots
    )
    instruments = Counter(str(item["inst_id"]) for item in slots)

    def balanced(counts: Counter) -> bool:
        return bool(counts) and max(counts.values()) - min(counts.values()) <= 1

    if (
        set(time_bins) != set(range(4))
        or not balanced(time_bins)
        or set(spread_buckets) != set(FORMAL_SPREAD_BUCKETS)
        or not balanced(spread_buckets)
        or set(volatility_buckets) != set(FORMAL_VOLATILITY_BUCKETS)
        or not balanced(volatility_buckets)
        or set(joint_liquidity)
        != {
            (spread, volatility)
            for spread in FORMAL_SPREAD_BUCKETS
            for volatility in FORMAL_VOLATILITY_BUCKETS
        }
        or not balanced(joint_liquidity)
        or set(joint_time_liquidity)
        != {
            (time_bin, spread, volatility)
            for time_bin in range(4)
            for spread in FORMAL_SPREAD_BUCKETS
            for volatility in FORMAL_VOLATILITY_BUCKETS
        }
        or not balanced(joint_time_liquidity)
        or not balanced(instruments)
    ):
        raise ValueError(
            "formal probe schedule 必须均衡覆盖四个 UTC 时段、规范 "
            "spread/volatility joint strata、time×liquidity cells 和全部交易对"
        )
    return schedule


def probe_schedule_sha256(value: dict) -> str:
    validate_probe_schedule(value)
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def formal_probe_schedule_sha256(value: dict) -> str:
    validate_formal_probe_schedule(value)
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class ProbeState(StrEnum):
    PREPARED = "PREPARED"
    BUY_SUBMITTING = "BUY_SUBMITTING"
    BUY_UNKNOWN = "BUY_UNKNOWN"
    BUY_FILLED = "BUY_FILLED"
    PROTECTING = "PROTECTING"
    PROTECTED = "PROTECTED"
    CLEANING = "CLEANING"
    DONE = "DONE"
    REJECTED = "REJECTED"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    FAILED = "FAILED"


class DemoProbeSaga:
    def __init__(
        self,
        exchange: Exchange,
        journal: JournalRepository,
        execution: ExecutionCoordinator,
        protection: ProtectionManager,
        exit_coordinator: ExitCoordinator,
        *,
        environment: str,
        shadow_mode: bool,
        account_uid: str,
        allowed_instruments: tuple[str, ...],
        probe_schedule_path: str | Path = "",
        require_formal_schedule: bool = False,
        soak_epoch_id: str = "",
        dust_usdt: Decimal = Decimal("1"),
    ):
        if environment != "demo" or shadow_mode:
            raise ValueError("Demo probe 只允许 environment=demo 且 shadow_mode=false")
        if not account_uid.strip():
            raise ValueError("Demo probe account_uid 不能为空")
        self.exchange = exchange
        self.journal = journal
        self.execution = execution
        self.protection = protection
        self.exit = exit_coordinator
        self.account_uid = account_uid
        self.allowed_instruments = tuple(allowed_instruments)
        self.dust_usdt = dust_usdt
        self.require_formal_schedule = require_formal_schedule
        self.soak_epoch_id = soak_epoch_id.strip()
        if require_formal_schedule and not self.soak_epoch_id:
            raise ValueError("formal probe schedule 必须绑定 soak_epoch_id")
        self.probe_schedule: dict | None = None
        self.probe_schedule_hash = ""
        if probe_schedule_path:
            path = Path(probe_schedule_path)
            if not path.is_file() or path.is_symlink():
                raise ValueError("probe schedule 必须是既有非符号链接文件")
            validator = (
                validate_formal_probe_schedule
                if require_formal_schedule
                else validate_probe_schedule
            )
            self.probe_schedule = validator(json.loads(path.read_text(encoding="utf-8")))
            self.probe_schedule_hash = hashlib.sha256(
                canonical_bytes(self.probe_schedule)
            ).hexdigest()
        if require_formal_schedule:
            if self.probe_schedule is None:
                raise ValueError("formal probe schedule 文件不能为空")
            self.journal.bind_formal_probe_schedule(
                account_uid=self.account_uid,
                soak_epoch_id=self.soak_epoch_id,
                schedule=self.probe_schedule,
                schedule_sha256=self.probe_schedule_hash,
            )

    def prepare(
        self,
        *,
        inst_id: str,
        nominal_usdt: Decimal,
        slot: int,
        probe_id: str | None = None,
        now: datetime | None = None,
    ) -> dict:
        nominal_usdt = to_decimal(nominal_usdt)
        if inst_id not in self.allowed_instruments or not inst_id.endswith("-USDT"):
            raise ValueError("probe 交易对不在显式 *-USDT allowlist")
        if not MIN_PROBE_NOTIONAL_USDT <= nominal_usdt <= MAX_PROBE_NOTIONAL_USDT:
            raise ValueError("probe 名义金额必须位于 5..10 USDT")
        if self.journal.get_mode() is not SystemMode.READY:
            raise RuntimeError("probe 只允许在 READY 状态 PREPARED")
        actual_uid = self.exchange.get_account_identity()
        if actual_uid != self.account_uid:
            raise RuntimeError("probe account UID 与配置不匹配")
        if self.exchange.get_pending_orders() or self.exchange.get_pending_algo_orders():
            raise RuntimeError("账户存在交易所 pending 普通单/algo")
        balance = self.exchange.get_balance()
        for holding in balance.non_quote_holdings("USDT"):
            if holding.balance > 0:
                raise RuntimeError(f"账户存在非零基础币 {holding.ccy}，禁止通用 probe")
        probe_id = probe_id or uuid.uuid4().hex
        buy_cl_ord_id, algo_cl_ord_id = probe_client_order_ids(probe_id)
        base_ccy = inst_id.split("-")[0]
        baseline = balance.holding(base_ccy)
        now = now or datetime.now(UTC)
        self._verify_scheduled_slot(
            inst_id=inst_id,
            slot=slot,
            probe_id=probe_id,
            now=now,
        )
        return self.journal.create_probe_run(
            probe_id=probe_id,
            account_uid=self.account_uid,
            utc_day=now.astimezone(UTC).date().isoformat(),
            slot=slot,
            inst_id=inst_id,
            nominal_usdt=nominal_usdt,
            buy_cl_ord_id=buy_cl_ord_id,
            algo_cl_ord_id=algo_cl_ord_id,
            baseline_base_balance=(baseline.balance if baseline is not None else Decimal("0")),
            soak_epoch_id=(
                self.soak_epoch_id if self.require_formal_schedule else ""
            ),
            formal_schedule_sha256=(
                self.probe_schedule_hash
                if self.require_formal_schedule
                else ""
            ),
        )

    def _verify_scheduled_slot(
        self,
        *,
        inst_id: str,
        slot: int,
        probe_id: str,
        now: datetime,
    ) -> None:
        if self.probe_schedule is None:
            return
        current = now.astimezone(UTC)
        day = current.date().isoformat()
        scheduled = next(
            (
                item
                for item in self.probe_schedule["slots"]
                if item["day"] == day and item["slot"] == slot
            ),
            None,
        )
        reason = ""
        observed_spread = 0.0
        observed_volatility = 0.0
        if scheduled is None:
            reason = "slot_not_precommitted"
        elif scheduled["inst_id"] != inst_id:
            reason = "instrument_mismatch"
        else:
            started = datetime.fromisoformat(scheduled["window_start"]).astimezone(UTC)
            ended = datetime.fromisoformat(scheduled["window_end"]).astimezone(UTC)
            if not started <= current < ended:
                reason = "outside_precommitted_utc_window"
            ticker = self.exchange.get_ticker(inst_id)
            if not reason:
                mid = (ticker.bid + ticker.ask) / Decimal("2")
                if ticker.bid <= 0 or ticker.ask < ticker.bid or mid <= 0:
                    reason = "invalid_bbo"
                else:
                    observed_spread = float((ticker.ask - ticker.bid) / mid * Decimal("10000"))
                    if not (
                        float(scheduled["spread_min_bps"])
                        <= observed_spread
                        < float(scheduled["spread_max_bps"])
                    ):
                        reason = "spread_bucket_mismatch"
            if not reason:
                candles = self.exchange.get_candles(
                    inst_id,
                    "1m",
                    30,
                )
                if candles is None or len(candles) < 3 or "close" not in candles.columns:
                    reason = "volatility_sample_missing"
                else:
                    closes = [float(value) for value in candles["close"]]
                    returns = [
                        (current_close / previous_close - 1) * 10000
                        for previous_close, current_close in zip(
                            closes,
                            closes[1:],
                            strict=False,
                        )
                        if previous_close > 0
                    ]
                    if len(returns) != len(closes) - 1 or any(
                        not math.isfinite(value) for value in returns
                    ):
                        reason = "volatility_sample_invalid"
                    else:
                        mean = sum(returns) / len(returns)
                        observed_volatility = math.sqrt(
                            sum((value - mean) ** 2 for value in returns) / (len(returns) - 1)
                        )
                        if not (
                            float(scheduled["volatility_min_bps"])
                            <= observed_volatility
                            < float(scheduled["volatility_max_bps"])
                        ):
                            reason = "volatility_bucket_mismatch"
        self.journal.record_event(
            "probe_schedule_sample",
            severity="warning" if reason else "info",
            payload={
                "schedule_sha256": self.probe_schedule_hash,
                "probe_id": probe_id,
                "day": day,
                "slot": slot,
                "inst_id": inst_id,
                "compliant": not reason,
                "reason": reason,
                "observed_spread_bps": observed_spread,
                "observed_volatility_bps": observed_volatility,
            },
        )
        if reason:
            raise RuntimeError(f"probe 未匹配预注册 schedule: {reason}")

    def advance(
        self,
        probe_id: str,
        *,
        owner: str,
        lease_ttl_s: float = 30,
    ) -> dict:
        acquired = self.journal.acquire_probe_lease(
            probe_id,
            owner,
            ttl_s=lease_ttl_s,
        )
        if acquired is None:
            row = self.journal.get_probe_run(probe_id)
            if row is None:
                raise KeyError(f"probe 不存在: {probe_id}")
            return row
        fencing_token, row = acquired
        try:
            for _ in range(8):
                state = ProbeState(row["state"])
                if state.value in TERMINAL_PROBE_STATES:
                    return row
                previous = row
                row = self._advance_state(
                    row,
                    owner=owner,
                    fencing_token=fencing_token,
                )
                if row["state"] == previous["state"] and row["version"] == previous["version"]:
                    return row
            return row
        finally:
            self.journal.release_probe_lease(
                probe_id,
                owner=owner,
                fencing_token=fencing_token,
            )

    def reclaim_once(
        self,
        *,
        owner: str,
        lease_ttl_s: float = 30,
    ) -> list[dict]:
        """Advance every active saga once under a fresh fenced lease."""
        if not owner.strip():
            raise ValueError("probe reclaimer owner 不能为空")
        results: list[dict] = []
        for candidate in self.journal.list_probe_runs(
            account_uid=self.account_uid,
            unresolved_only=True,
        ):
            if candidate["state"] in TERMINAL_PROBE_STATES:
                continue
            results.append(
                self.advance(
                    candidate["probe_id"],
                    owner=f"{owner}:{uuid.uuid4().hex}",
                    lease_ttl_s=lease_ttl_s,
                )
            )
        return results

    def _transition(
        self,
        row: dict,
        new_state: ProbeState,
        *,
        owner: str,
        fencing_token: int,
        changes: dict | None = None,
    ) -> dict:
        return self.journal.transition_probe_run(
            row["probe_id"],
            owner=owner,
            fencing_token=fencing_token,
            expected_states=(row["state"],),
            new_state=new_state.value,
            changes=changes,
        )

    def _advance_state(
        self,
        row: dict,
        *,
        owner: str,
        fencing_token: int,
    ) -> dict:
        state = ProbeState(row["state"])
        if state is ProbeState.PREPARED:
            return self._submit_buy(
                row,
                owner=owner,
                fencing_token=fencing_token,
            )
        if state in {ProbeState.BUY_SUBMITTING, ProbeState.BUY_UNKNOWN}:
            return self._resolve_buy(
                row,
                owner=owner,
                fencing_token=fencing_token,
            )
        if state is ProbeState.BUY_FILLED:
            return self._transition(
                row,
                ProbeState.PROTECTING,
                owner=owner,
                fencing_token=fencing_token,
            )
        if state is ProbeState.PROTECTING:
            return self._resolve_protection(
                row,
                owner=owner,
                fencing_token=fencing_token,
            )
        if state is ProbeState.PROTECTED:
            return self._transition(
                row,
                ProbeState.CLEANING,
                owner=owner,
                fencing_token=fencing_token,
            )
        if state is ProbeState.CLEANING:
            return self._cleanup(
                row,
                owner=owner,
                fencing_token=fencing_token,
            )
        return row

    def _buy_quantity(self, row: dict) -> Decimal:
        ticker = self.exchange.get_ticker(row["inst_id"])
        price = to_decimal(ticker.ask or ticker.last)
        instrument = self.exchange.get_instrument(row["inst_id"])
        lot = instrument.lot_size
        quantity = (to_decimal(row["nominal_usdt"]) / price / lot).to_integral_value(
            rounding=ROUND_DOWN
        ) * lot
        if quantity < instrument.min_size or quantity * price < 5:
            quantity = (
                max(
                    instrument.min_size,
                    MIN_PROBE_NOTIONAL_USDT / price,
                )
                / lot
            ).to_integral_value(rounding=ROUND_UP) * lot
        notional = quantity * price
        if quantity <= 0 or not 5 <= notional <= MAX_PROBE_NOTIONAL_USDT:
            raise RuntimeError("交易所 lot/minSz 无法在 5..10 USDT 硬边界内形成 probe")
        return quantity

    def _submit_buy(
        self,
        row: dict,
        *,
        owner: str,
        fencing_token: int,
    ) -> dict:
        # BUY_SUBMITTING 必须先 durable，再允许唯一的外部 POST。
        row = self._transition(
            row,
            ProbeState.BUY_SUBMITTING,
            owner=owner,
            fencing_token=fencing_token,
        )
        try:
            intent = self.execution.submit(
                ExecutionRequest(
                    inst_id=row["inst_id"],
                    side="buy",
                    base_qty=self._buy_quantity(row),
                    cl_ord_id=row["buy_cl_ord_id"],
                    source=PROBE_SOURCE,
                    probe_id=row["probe_id"],
                    probe_lease_owner=owner,
                    probe_fencing_token=fencing_token,
                )
            )
        except Exception as exc:
            return self._manual_review(
                row,
                f"BUY submit 本地异常: {exc}",
                owner=owner,
                fencing_token=fencing_token,
            )
        changes = {"buy_intent_id": intent.intent_id}
        if intent.state is OrderState.REJECTED:
            return self._transition(
                row,
                ProbeState.REJECTED,
                owner=owner,
                fencing_token=fencing_token,
                changes={**changes, "last_error": intent.last_error_message},
            )
        if intent.state is OrderState.UNKNOWN:
            return self._transition(
                row,
                ProbeState.BUY_UNKNOWN,
                owner=owner,
                fencing_token=fencing_token,
                changes=changes,
            )
        if intent.state is OrderState.FILLED:
            return self._transition(
                row,
                ProbeState.BUY_FILLED,
                owner=owner,
                fencing_token=fencing_token,
                changes=changes,
            )
        # ACK/LIVE/PARTIAL/CANCELED still need a query-first bounded
        # resolution pass. Persist the intent correlation without changing
        # the saga phase; never call the BUY POST path again.
        return self._transition(
            row,
            ProbeState.BUY_SUBMITTING,
            owner=owner,
            fencing_token=fencing_token,
            changes=changes,
        )

    def _resolve_buy(
        self,
        row: dict,
        *,
        owner: str,
        fencing_token: int,
    ) -> dict:
        intent = self.journal.find_intent(cl_ord_id=row["buy_cl_ord_id"])
        if intent is None:
            # ExecutionCoordinator 持久化 intent 在 POST 之前；没有 intent
            # 可证明崩溃发生在外部副作用之前，不允许“恢复”重放 BUY。
            return self._transition(
                row,
                ProbeState.REJECTED,
                owner=owner,
                fencing_token=fencing_token,
                changes={"last_error": "crash_before_durable_buy_intent"},
            )
        intent = self._query_buy_intent(intent)
        terminal = self._transition_from_buy_fact(
            row,
            intent,
            owner=owner,
            fencing_token=fencing_token,
        )
        if terminal is not None:
            return terminal

        if intent.state in {
            OrderState.ACKNOWLEDGED,
            OrderState.LIVE,
            OrderState.PARTIALLY_FILLED,
        }:
            # A market BUY that remains open is queried first above, then
            # canceled before any partial fill can grow behind cleanup.
            try:
                canceled = self.exchange.cancel_order(
                    row["inst_id"],
                    intent.exchange_ord_id,
                    cl_ord_id=("" if intent.exchange_ord_id else row["buy_cl_ord_id"]),
                )
                intent, _ = self.execution.process_exchange_update(canceled)
            except Exception:  # noqa: BLE001
                intent = self._query_buy_intent(intent)
                intent = self.journal.find_intent(cl_ord_id=row["buy_cl_ord_id"]) or intent
            terminal = self._transition_from_buy_fact(
                row,
                intent,
                owner=owner,
                fencing_token=fencing_token,
            )
            if terminal is not None:
                return terminal
            if self._buy_resolution_age(intent) > BUY_RESOLUTION_TIMEOUT_S:
                return self._manual_review(
                    row,
                    (f"BUY 查询/撤单超过 30 秒仍未终态: {intent.state.value}"),
                    owner=owner,
                    fencing_token=fencing_token,
                )
            return row

        if intent.state in {
            OrderState.PERSISTED,
            OrderState.SUBMITTING,
            OrderState.UNKNOWN,
            OrderState.MANUAL_REVIEW,
        }:
            age = self._buy_resolution_age(intent)
            if age > BUY_RESOLUTION_TIMEOUT_S:
                return self._manual_review(
                    row,
                    "BUY UNKNOWN 超过 30 秒且无法裁决",
                    owner=owner,
                    fencing_token=fencing_token,
                )
            if row["state"] != ProbeState.BUY_UNKNOWN.value:
                return self._transition(
                    row,
                    ProbeState.BUY_UNKNOWN,
                    owner=owner,
                    fencing_token=fencing_token,
                )
        return row

    def _query_buy_intent(self, intent: OrderIntent) -> OrderIntent:
        previous_fill = intent.acc_fill_qty
        resolved = OrderResolver(
            self.exchange,
            self.journal,
        ).resolve(intent)
        current = resolved or intent
        delta = current.acc_fill_qty - previous_fill
        if delta > 0:
            # OrderResolver projects REST facts directly. Re-run the same
            # protection hook used by execution/WS so a newly discovered
            # partial fill is protected before cancellation/cleanup.
            self.protection.on_fill(current, delta)
        return current

    @staticmethod
    def _buy_resolution_age(intent: OrderIntent) -> float:
        # created_at is the durable phase anchor. min(updated_at) also keeps
        # compatibility with imported/legacy rows whose creation timestamp
        # was not the original exchange-submit boundary.
        started_at = min(
            float(intent.created_at),
            float(intent.updated_at),
        )
        return max(time.time() - started_at, 0)

    def _transition_from_buy_fact(
        self,
        row: dict,
        intent: OrderIntent,
        *,
        owner: str,
        fencing_token: int,
    ) -> dict | None:
        changes = {"buy_intent_id": intent.intent_id}
        if intent.acc_fill_qty > 0 and intent.state.is_terminal:
            return self._transition(
                row,
                ProbeState.BUY_FILLED,
                owner=owner,
                fencing_token=fencing_token,
                changes=changes,
            )
        if intent.state is OrderState.FILLED:
            return self._manual_review(
                row,
                "BUY FILLED 但 accFillSz=0",
                owner=owner,
                fencing_token=fencing_token,
            )
        if intent.state in {
            OrderState.CANCELED,
            OrderState.REJECTED,
        }:
            error = intent.last_error_message or f"buy_{intent.state.value}_without_fill"
            return self._transition(
                row,
                ProbeState.REJECTED,
                owner=owner,
                fencing_token=fencing_token,
                changes={**changes, "last_error": error},
            )
        return None

    def _resolve_protection(
        self,
        row: dict,
        *,
        owner: str,
        fencing_token: int,
    ) -> dict:
        intent = self.journal.find_intent(cl_ord_id=row["buy_cl_ord_id"])
        if intent is None or intent.acc_fill_qty <= 0 or not intent.state.is_terminal:
            return self._protection_failure(
                row,
                "BUY_FILLED 与 durable intent 事实冲突",
                intent=intent,
                owner=owner,
                fencing_token=fencing_token,
            )
        protection = self.journal.find_protection(algo_cl_ord_id=row["algo_cl_ord_id"])
        if protection is None:
            position = self.journal.get_position(row["inst_id"])
            qty = to_decimal(position["base_qty"]) if position else Decimal("0")
            if qty <= 0:
                return self._protection_failure(
                    row,
                    "已成交 BUY 没有可保护持仓",
                    intent=intent,
                    owner=owner,
                    fencing_token=fencing_token,
                )
            try:
                protection = self.protection.ensure_for_position(
                    row["inst_id"],
                    qty,
                    reference_price=intent.avg_fill_px,
                    parent_intent_id=intent.intent_id,
                    algo_cl_ord_id=row["algo_cl_ord_id"],
                )
            except Exception as exc:
                return self._protection_failure(
                    row,
                    f"保护建立失败: {exc}",
                    intent=intent,
                    owner=owner,
                    fencing_token=fencing_token,
                )
        if protection.state is ProtectionState.ACTIVE:
            latency = max(protection.updated_at - intent.created_at, 0)
            self.journal.record_event_once(
                f"demo-probe-protection-slo:{row['probe_id']}",
                "protection_activation_slo_sample",
                correlation_id=row["probe_id"],
                payload={
                    "latency_seconds": latency,
                    "success": True,
                    "probe_id": row["probe_id"],
                    "protection_id": protection.protection_id,
                },
            )
            return self._transition(
                row,
                ProbeState.PROTECTED,
                owner=owner,
                fencing_token=fencing_token,
            )
        if protection.state in {
            ProtectionState.FAILED,
            ProtectionState.UNKNOWN,
            ProtectionState.CANCELED,
            ProtectionState.TRIGGERED,
            ProtectionState.EMERGENCY_EXIT,
        } or (time.time() - float(protection.created_at) > PROTECTION_ACTIVATION_TIMEOUT_S):
            return self._protection_failure(
                row,
                f"保护未在 10 秒内 ACTIVE: {protection.state.value}",
                intent=intent,
                owner=owner,
                fencing_token=fencing_token,
            )
        return row

    def _protection_failure(
        self,
        row: dict,
        error: str,
        *,
        intent: OrderIntent | None,
        owner: str,
        fencing_token: int,
    ) -> dict:
        started_at = float(intent.created_at) if intent is not None else float(row["created_at"])
        self.journal.record_event_once(
            f"demo-probe-protection-slo:{row['probe_id']}",
            "protection_activation_slo_sample",
            severity="warning",
            correlation_id=row["probe_id"],
            payload={
                "latency_seconds": max(time.time() - started_at, 0),
                "success": False,
                "probe_id": row["probe_id"],
                "error": error,
            },
        )
        return self._manual_review(
            row,
            error,
            owner=owner,
            fencing_token=fencing_token,
        )

    def _cleanup(
        self,
        row: dict,
        *,
        owner: str,
        fencing_token: int,
    ) -> dict:
        exit_intent = self.exit.exit_position(
            row["inst_id"],
            reason=f"demo-probe:{row['probe_id']}",
            source=PROBE_SOURCE,
            probe_id=row["probe_id"],
            cl_ord_id=f"pe{row['probe_id'][:30]}",
        )
        if exit_intent is not None and exit_intent.state is OrderState.UNKNOWN:
            return self._manual_review(
                row,
                "probe exit UNKNOWN",
                owner=owner,
                fencing_token=fencing_token,
            )
        position = self.journal.get_position(row["inst_id"])
        if position and to_decimal(position["base_qty"]) > 0:
            return row
        balance = self.exchange.get_balance()
        holding = balance.holding(row["inst_id"].split("-")[0])
        final_balance = holding.balance if holding is not None else Decimal("0")
        baseline = to_decimal(row["baseline_base_balance"])
        delta = final_balance - baseline
        lot = self.exchange.get_instrument(row["inst_id"]).lot_size
        if delta < 0 or delta >= lot:
            return self._manual_review(
                row,
                f"cleanup balance delta 不可证明为子 lot 尘埃: {delta}",
                owner=owner,
                fencing_token=fencing_token,
            )
        return self._transition(
            row,
            ProbeState.DONE,
            owner=owner,
            fencing_token=fencing_token,
            changes={
                "exit_intent_id": (exit_intent.intent_id if exit_intent is not None else ""),
                "final_base_balance": final_balance,
                "expected_base_dust": max(delta, Decimal("0")),
            },
        )

    def _manual_review(
        self,
        row: dict,
        error: str,
        *,
        owner: str,
        fencing_token: int,
    ) -> dict:
        self.journal.set_mode(
            SystemMode.HALTED,
            reason="demo_probe_manual_review",
        )
        self.journal.enqueue_outbox_once(
            f"demo-probe-manual:{row['probe_id']}",
            "page.demo_probe_manual_review",
            {
                "probe_id": row["probe_id"],
                "inst_id": row["inst_id"],
                "state": row["state"],
                "error": error,
            },
        )
        return self._transition(
            row,
            ProbeState.MANUAL_REVIEW,
            owner=owner,
            fencing_token=fencing_token,
            changes={"last_error": error},
        )
