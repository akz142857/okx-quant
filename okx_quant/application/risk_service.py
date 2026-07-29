"""组合级生产预交易风控。"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal

from okx_quant.application.execution import ExecutionRequest
from okx_quant.domain.orders import IntentRiskGuard, SystemMode, to_decimal
from okx_quant.exchange import ExchangeReader
from okx_quant.infrastructure.db import JournalRepository


@dataclass(frozen=True)
class ProductionRiskLimits:
    """全部比例使用 0..1，小数金额以 USDT 表示。"""

    max_order_loss_usdt: Decimal = Decimal("100")
    max_position_notional_usdt: Decimal = Decimal("2000")
    max_total_exposure_usdt: Decimal = Decimal("5000")
    max_open_positions: int = 3
    max_daily_loss_usdt: Decimal = Decimal("250")
    max_drawdown_ratio: Decimal = Decimal("0.15")
    max_order_intents_per_hour: int = 20
    max_spread_ratio: Decimal = Decimal("0.005")
    max_slippage_ratio: Decimal = Decimal("0.01")
    max_candle_range_ratio: Decimal = Decimal("0.15")
    min_24h_quote_volume_usdt: Decimal = Decimal("500000")
    max_market_data_age_s: float = 5
    max_account_snapshot_age_s: float = 90
    allowed_instruments: frozenset[str] = frozenset()

    def validate(self) -> None:
        positive = {
            "max_order_loss_usdt": self.max_order_loss_usdt,
            "max_position_notional_usdt": self.max_position_notional_usdt,
            "max_total_exposure_usdt": self.max_total_exposure_usdt,
            "max_daily_loss_usdt": self.max_daily_loss_usdt,
            "max_drawdown_ratio": self.max_drawdown_ratio,
            "max_spread_ratio": self.max_spread_ratio,
            "max_slippage_ratio": self.max_slippage_ratio,
            "max_candle_range_ratio": self.max_candle_range_ratio,
            "min_24h_quote_volume_usdt": self.min_24h_quote_volume_usdt,
        }
        for name, value in positive.items():
            if (
                not isinstance(value, Decimal)
                or not value.is_finite()
                or value <= 0
            ):
                raise ValueError(f"{name} 必须是正有限 Decimal")
        hard_maxima = {
            "max_order_loss_usdt": (
                self.max_order_loss_usdt,
                Decimal("100"),
            ),
            "max_position_notional_usdt": (
                self.max_position_notional_usdt,
                Decimal("2000"),
            ),
            "max_total_exposure_usdt": (
                self.max_total_exposure_usdt,
                Decimal("5000"),
            ),
            "max_daily_loss_usdt": (
                self.max_daily_loss_usdt,
                Decimal("250"),
            ),
            "max_drawdown_ratio": (
                self.max_drawdown_ratio,
                Decimal("0.15"),
            ),
            "max_spread_ratio": (
                self.max_spread_ratio,
                Decimal("0.01"),
            ),
        }
        for name, (value, hard_maximum) in hard_maxima.items():
            if value > hard_maximum:
                raise ValueError(
                    f"{name} 超过编译期硬上限 {hard_maximum}"
                )
        if self.max_drawdown_ratio >= 1:
            raise ValueError("max_drawdown_ratio 必须小于 1")
        if self.max_slippage_ratio > Decimal("0.05"):
            raise ValueError("max_slippage_ratio 不能超过 OKX 的 5% 上限")
        if self.max_candle_range_ratio > Decimal("0.20"):
            raise ValueError("max_candle_range_ratio 不能超过 20% 硬上限")
        if self.max_slippage_ratio.as_tuple().exponent < -4:
            raise ValueError("max_slippage_ratio 最多保留 4 位小数")
        if not 1 <= self.max_open_positions <= 5:
            raise ValueError("max_open_positions 必须在 1..5")
        if not 1 <= self.max_order_intents_per_hour <= 60:
            raise ValueError("max_order_intents_per_hour 必须在 1..60")
        if self.max_position_notional_usdt > self.max_total_exposure_usdt:
            raise ValueError("单交易对仓位上限不能超过账户总敞口上限")
        if (
            not isinstance(self.allowed_instruments, frozenset)
            or len(self.allowed_instruments) > 10
            or any(
                not isinstance(inst_id, str)
                or not re.fullmatch(r"[A-Z0-9]{2,15}-USDT", inst_id)
                for inst_id in self.allowed_instruments
            )
        ):
            raise ValueError("allowed_instruments 格式非法或超过 10 个")
        if (
            isinstance(self.max_market_data_age_s, bool)
            or not isinstance(self.max_market_data_age_s, (int, float))
            or not math.isfinite(self.max_market_data_age_s)
            or not 0 < self.max_market_data_age_s <= 30
        ):
            raise ValueError("max_market_data_age_s 必须在 (0, 30] 秒")
        if (
            isinstance(self.max_account_snapshot_age_s, bool)
            or not isinstance(
                self.max_account_snapshot_age_s,
                (int, float),
            )
            or not math.isfinite(self.max_account_snapshot_age_s)
            or not 0 < self.max_account_snapshot_age_s <= 90
        ):
            raise ValueError(
                "max_account_snapshot_age_s 必须在 (0, 90] 秒"
            )


class ProductionRiskService:
    """由单写者执行器同步调用；SELL/减仓不受 entry-only 限制。"""

    def __init__(
        self,
        exchange: ExchangeReader,
        journal: JournalRepository,
        limits: ProductionRiskLimits,
        metrics=None,
        runtime_ready_check: Callable[[], bool] | None = None,
    ):
        limits.validate()
        self.exchange = exchange
        self.journal = journal
        self.limits = limits
        self.metrics = metrics
        self.runtime_ready_check = runtime_ready_check

    def check(self, request: ExecutionRequest) -> tuple[bool, str]:
        result = self._check(request)
        if not result[0] and self.metrics is not None:
            self.metrics.inc("risk_rejections_total", reason=result[1])
        return result

    def atomic_guard(self, _request: ExecutionRequest) -> IntentRiskGuard:
        """捕获将由 SQLite BEGIN IMMEDIATE 事务重新验证的风险版本。"""
        snapshot = self.journal.latest_account_snapshot()
        if snapshot is None:
            raise RuntimeError("缺少可绑定到 BUY 事务的账户快照")
        mode, mode_epoch = self.journal.get_mode_state()
        if mode is not SystemMode.READY:
            raise RuntimeError("生成 BUY 事务 guard 时系统已离开 READY")
        return IntentRiskGuard(
            mode_epoch=mode_epoch,
            snapshot_id=str(snapshot["snapshot_id"]),
            max_snapshot_age_s=self.limits.max_account_snapshot_age_s,
            max_open_positions=self.limits.max_open_positions,
            max_order_intents_per_hour=(
                self.limits.max_order_intents_per_hour
            ),
        )

    def enforce_account_hard_limits(
        self,
        *,
        now: float | None = None,
    ) -> tuple[bool, str]:
        now = time.time() if now is None else now
        day_start = now - 86400
        daily_realized = to_decimal(
            self.journal.realized_pnl_since(day_start)
        )
        event_name = ""
        payload: dict[str, str] = {}
        reason = ""
        if daily_realized <= -self.limits.max_daily_loss_usdt:
            event_name = "page.daily_realized_loss_limit"
            reason = "单日已实现亏损达到硬限制"
            payload = {
                "daily_realized_pnl": str(daily_realized),
                "limit": str(self.limits.max_daily_loss_usdt),
            }
        else:
            equities = self.journal.account_equities_since(day_start)
            if equities:
                current = equities[-1]
                peak = max(equities)
                drawdown = (
                    (peak - current) / peak
                    if peak > 0
                    else Decimal("0")
                )
                if drawdown >= self.limits.max_drawdown_ratio:
                    event_name = "page.account_drawdown_limit"
                    reason = "账户回撤达到硬限制"
                    payload = {
                        "current_equity": str(current),
                        "peak_equity": str(peak),
                        "drawdown_ratio": str(drawdown),
                        "limit": str(self.limits.max_drawdown_ratio),
                    }
        if not event_name:
            return True, "通过"
        return self._halt_account_limit(event_name, reason, payload)

    def _halt_account_limit(
        self,
        event_name: str,
        reason: str,
        payload: dict[str, str],
    ) -> tuple[bool, str]:
        """锁存已经发生的账户预算越界；候选 BUY 越界只拒单。"""
        current = self.journal.get_mode()
        if current not in {
            SystemMode.EMERGENCY_EXIT,
            SystemMode.MAINTENANCE,
        } and (
            current is not SystemMode.HALTED
            or self.journal.get_mode_reason() != event_name
        ):
            # A new account-limit incident must supersede a Canary startup
            # hold and advance its hard epoch. Repeated sampling of the same
            # incident remains idempotent.
            self.journal.set_mode(SystemMode.HALTED, reason=event_name)
        mode, hard_epoch = self.journal.get_mode_state()
        self.journal.enqueue_outbox_once(
            f"hard-risk:{event_name}:{hard_epoch}",
            event_name,
            {
                **payload,
                "mode": mode.value,
                "hard_epoch": str(hard_epoch),
            },
        )
        return False, reason

    def _current_exposure(
        self,
        positions: dict[str, Decimal],
        *,
        now: float,
    ) -> tuple[bool, str, Decimal]:
        total = Decimal("0")
        for inst_id, qty in positions.items():
            try:
                ticker = self.exchange.get_ticker(inst_id)
                mark = max(
                    to_decimal(ticker.last),
                    to_decimal(ticker.ask),
                )
                captured_at = float(ticker.timestamp)
            except Exception as exc:
                return False, f"无法取得 {inst_id} 风险价格: {exc}", total
            if (
                not mark.is_finite()
                or mark <= 0
                or not math.isfinite(captured_at)
                or captured_at <= 0
                or now - captured_at > self.limits.max_market_data_age_s
                or captured_at - now > self.limits.max_market_data_age_s
            ):
                return False, f"{inst_id} 风险价格无效", total
            position_notional = qty * mark
            if position_notional > self.limits.max_position_notional_usdt:
                allowed, reason = self._halt_account_limit(
                    "page.current_position_notional_limit",
                    "当前单交易对名义仓位已经超过账户硬限制",
                    {
                        "inst_id": inst_id,
                        "current_notional": str(position_notional),
                        "limit": str(
                            self.limits.max_position_notional_usdt
                        ),
                    },
                )
                return allowed, reason, total
            total += position_notional
        pending = self.journal.active_reserved_quote()
        if total + pending > self.limits.max_total_exposure_usdt:
            allowed, reason = self._halt_account_limit(
                "page.current_total_exposure_limit",
                "当前账户总敞口已经超过硬限制",
                {
                    "current_exposure": str(total),
                    "pending_exposure": str(pending),
                    "limit": str(
                        self.limits.max_total_exposure_usdt
                    ),
                },
            )
            return allowed, reason, total
        return True, "通过", total

    def _check(self, request: ExecutionRequest) -> tuple[bool, str]:
        if request.side == "sell":
            return True, "退出路径始终允许"
        if (
            self.limits.allowed_instruments
            and request.inst_id not in self.limits.allowed_instruments
        ):
            return False, "交易对不在生产 allowlist"
        if self.journal.get_mode() is not SystemMode.READY:
            return False, "系统未处于 READY"
        if self.runtime_ready_check is not None and not self.runtime_ready_check():
            return False, "私有事件流/恢复基线未 READY"
        if self.journal.has_nonterminal_intent(request.inst_id):
            return False, "该交易对存在 UNKNOWN/未决订单"
        if self.journal.recent_intent_count(time.time() - 3600) >= (
            self.limits.max_order_intents_per_hour
        ):
            return False, "达到每小时订单意图上限"
        within_hard_limits, hard_limit_reason = (
            self.enforce_account_hard_limits()
        )
        if not within_hard_limits:
            return False, hard_limit_reason

        try:
            account = self.exchange.get_balance()
        except Exception as exc:  # fail closed: stale cash can over-allocate
            return False, f"无法刷新账户快照: {exc}"
        total_equity = to_decimal(account.total_equity_quote)
        available_quote = to_decimal(account.available_quote)
        holding_values = [
            (to_decimal(holding.balance), to_decimal(holding.available))
            for holding in account.holdings
        ]
        if (
            not total_equity.is_finite()
            or not available_quote.is_finite()
            or total_equity < 0
            or available_quote < 0
            or available_quote > total_equity
            or any(
                not balance.is_finite()
                or not available.is_finite()
                or balance < 0
                or available < 0
                or available > balance
                for balance, available in holding_values
            )
        ):
            return False, "账户快照包含非有限、负数或不可用余额"
        self.journal.record_account_snapshot(
            total_equity_quote=total_equity,
            available_quote=available_quote,
            holdings=[
                {
                    "ccy": holding.ccy,
                    "balance": str(holding.balance),
                    "available": str(holding.available),
                }
                for holding in account.holdings
            ],
            source="pre_trade",
        )
        snapshot = self.journal.latest_account_snapshot()
        if snapshot is None:
            return False, "账户快照持久化失败"
        try:
            captured_at = float(snapshot["captured_at"])
        except (KeyError, TypeError, ValueError):
            return False, "账户快照缺少有效采集时间"
        snapshot_age = time.time() - captured_at
        if (
            not math.isfinite(captured_at)
            or snapshot_age < -self.limits.max_market_data_age_s
            or snapshot_age > self.limits.max_account_snapshot_age_s
        ):
            return False, "账户快照过期或时间位于未来"
        authoritative_positions = {
            f"{holding.ccy}-{self.exchange.quote_ccy}": to_decimal(
                holding.balance
            )
            for holding in account.non_quote_holdings(
                self.exchange.quote_ccy
            )
            if to_decimal(holding.balance) > 0
        }
        projected_positions = {
            row["inst_id"]: to_decimal(row["base_qty"])
            for row in self.journal.list_positions()
            if to_decimal(row["base_qty"]) > 0
        }
        if authoritative_positions != projected_positions:
            self.journal.set_mode(SystemMode.DEGRADED)
            return False, "交易所仓位与本地投影不一致，等待联合对账"
        if len(authoritative_positions) > self.limits.max_open_positions:
            return self._halt_account_limit(
                "page.current_position_count_limit",
                "当前持仓数已经超过账户硬限制",
                {
                    "current_positions": str(len(authoritative_positions)),
                    "limit": str(self.limits.max_open_positions),
                },
            )
        now = time.time()
        exposure_ok, exposure_reason, total_exposure = (
            self._current_exposure(authoritative_positions, now=now)
        )
        if not exposure_ok:
            return False, exposure_reason

        ticker = self.exchange.get_ticker(request.inst_id)
        price = to_decimal(ticker.last)
        if not price.is_finite() or price <= 0:
            return False, "行情价格无效"
        try:
            ticker_ts = float(ticker.timestamp)
        except (TypeError, ValueError, OverflowError):
            return False, "行情快照时间缺失、过期或在未来"
        if (
            not math.isfinite(ticker_ts)
            or ticker_ts <= 0
            or now - ticker_ts > self.limits.max_market_data_age_s
            or ticker_ts - now > self.limits.max_market_data_age_s
        ):
            return False, "行情快照时间缺失、过期或在未来"
        quote_volume = to_decimal(ticker.quote_volume_24h)
        if (
            not quote_volume.is_finite()
            or quote_volume < self.limits.min_24h_quote_volume_usdt
        ):
            return False, "24h 计价成交额低于流动性门槛"
        bid = to_decimal(ticker.bid)
        ask = to_decimal(ticker.ask)
        if (
            not bid.is_finite()
            or not ask.is_finite()
            or bid <= 0
            or ask <= 0
            or ask < bid
        ):
            return False, "bid/ask 行情无效"
        spread = (ask - bid) / ((ask + bid) / 2)
        if spread > self.limits.max_spread_ratio:
            return False, f"spread {spread} 超过上限"

        instrument = self.exchange.get_instrument(request.inst_id)
        min_size = to_decimal(instrument.min_size)
        lot_size = to_decimal(instrument.lot_size)
        if min_size > 0 and request.base_qty < min_size:
            return False, "下单数量小于交易所最小数量"
        if lot_size > 0 and request.base_qty % lot_size != 0:
            return False, "下单数量不符合交易所 lot size"

        worst_price = max(price, ask) * (
            Decimal("1") + self.limits.max_slippage_ratio
        )
        request_notional = request.base_qty * worst_price
        if request.reserved_quote < request_notional:
            return False, "风险预留不足以覆盖最新最坏成交名义金额"
        current_mark = max(price, ask)
        existing_notional = (
            authoritative_positions.get(request.inst_id, Decimal("0"))
            * current_mark
        )
        if existing_notional > self.limits.max_position_notional_usdt:
            return self._halt_account_limit(
                "page.current_position_notional_limit",
                "当前单交易对名义仓位已经超过账户硬限制",
                {
                    "inst_id": request.inst_id,
                    "current_notional": str(existing_notional),
                    "limit": str(
                        self.limits.max_position_notional_usdt
                    ),
                },
            )
        if (
            existing_notional
            + request_notional
            > self.limits.max_position_notional_usdt
        ):
            return False, "单交易对请求名义仓位超过上限"
        if request.reserved_quote <= 0:
            return False, "BUY 缺少执行内核计算的权威风险预留"
        if request.reserved_quote > (
            to_decimal(snapshot["available_quote"]) - self.journal.active_reserved_quote()
        ):
            return False, "可用现金扣除风险预留后不足"

        active_instruments = set(authoritative_positions)
        reserved_instruments = self.journal.active_reserved_instruments()
        occupied_instruments = active_instruments | reserved_instruments
        if (
            request.inst_id not in occupied_instruments
            and len(occupied_instruments) >= self.limits.max_open_positions
        ):
            return False, "达到最大同时持仓数"

        pending_exposure = self.journal.active_reserved_quote()
        if (
            total_exposure + pending_exposure + request_notional
            > self.limits.max_total_exposure_usdt
        ):
            return False, "账户总敞口超过上限"

        stop = request.stop_loss
        if stop <= 0 or stop >= price:
            return False, "BUY 必须携带低于当前价的有效止损"
        take = request.take_profit
        if take <= worst_price:
            return False, "BUY 必须携带高于最坏预期成交价的有效止盈"
        expected_loss = request.base_qty * (worst_price - stop)
        if expected_loss > self.limits.max_order_loss_usdt:
            return False, "单笔最大预期损失超过上限"

        # 上面的余额/行情/产品查询都可能阻塞。真实提交前必须重新验证
        # mode、WS baseline、告警与核心线程状态，避免检查期间断线后继续 BUY。
        if self.journal.get_mode() is not SystemMode.READY:
            return False, "风控计算期间系统离开 READY"
        if self.runtime_ready_check is not None and not self.runtime_ready_check():
            return False, "风控计算期间运行时 readiness 失效"
        return True, "通过"
