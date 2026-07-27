"""测试用 FakeExchange —— 内存持久化，无网络依赖"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal

import pandas as pd
import requests

from okx_quant.domain.orders import (
    ExchangeAlgoOrder,
    ExchangeFill,
    ExchangeOrder,
    OrderState,
    ProtectionState,
    parse_decimal_fact,
)
from okx_quant.exchange.base import (
    BalanceSnapshot,
    Exchange,
    Holding,
    InstrumentInfo,
    OrderResult,
    Ticker,
)


@dataclass
class _PlacedOrder:
    inst_id: str
    side: str
    size: Decimal
    tgt_ccy: str
    cl_ord_id: str = ""
    max_slippage: Decimal | None = None


@dataclass
class _OrderOutcome:
    state: str = "filled"
    fill_size: Decimal | None = None
    fill_price: Decimal | None = None
    fee: Decimal = Decimal("0")
    fee_ccy: str = ""
    lose_response: bool = False


@dataclass
class _AlgoOutcome:
    state: ProtectionState = ProtectionState.ACTIVE
    lose_response: bool = False
    reject: bool = False


class FakeExchange(Exchange):
    """内存交易所，供单元测试使用。

    用法::

        ex = FakeExchange(quote_ccy="USDT")
        ex.set_balance(total=10_000, quote_avail=5_000)
        ex.set_holding("BTC", balance=0.1, available=0.1)
        ex.set_candles("BTC-USDT", "1H", df)
        ex.set_ticker("BTC-USDT", last=50000)

        trader = LiveTrader(exchange=ex, ...)
        trader._tick("1H", 100)
        assert ex.orders[-1].side == "buy"
    """

    def __init__(self, quote_ccy: str = "USDT"):
        self._quote = quote_ccy
        self._account_identity = "fake-account"
        self._total_eq = Decimal("0")
        self._avail_quote = Decimal("0")
        self._holdings: dict[str, Holding] = {}
        self._candles: dict[tuple[str, str], pd.DataFrame] = {}
        self._tickers: dict[str, Ticker] = {}
        self._instruments: dict[str, InstrumentInfo] = {}
        self.orders: list[_PlacedOrder] = []
        self._order_counter: int = 0
        self._on_order: Callable[[_PlacedOrder], None] | None = None
        self._fill_price = Decimal("0")  # 模拟市价成交均价，0 表示未知
        self._outcomes: list[_OrderOutcome] = []
        self._exchange_orders: dict[str, ExchangeOrder] = {}
        self._by_cl_ord_id: dict[str, str] = {}
        self._algo_counter: int = 0
        self._algo_outcomes: list[_AlgoOutcome] = []
        self._algo_amend_outcomes: list[_AlgoOutcome] = []
        self._algo_cancel_outcomes: list[_AlgoOutcome] = []
        self._algo_orders: dict[str, ExchangeAlgoOrder] = {}
        self._algo_by_client_id: dict[str, str] = {}

    # ---------- 测试桩点 ----------

    def set_balance(self, total: object, quote_avail: object) -> None:
        self._total_eq = parse_decimal_fact(
            total,
            "fake.total_equity",
            nonnegative=True,
        )
        self._avail_quote = parse_decimal_fact(
            quote_avail,
            "fake.available_quote",
            nonnegative=True,
        )
        # 顺便把 quote 持仓也记入 holdings
        self._holdings[self._quote] = Holding(
            ccy=self._quote, balance=total, available=quote_avail,
        )

    def set_account_identity(self, value: str) -> None:
        self._account_identity = value

    def set_holding(self, ccy: str, balance: object, available: object) -> None:
        self._holdings[ccy] = Holding(ccy=ccy, balance=balance, available=available)

    def set_candles(self, inst_id: str, bar: str, df: pd.DataFrame) -> None:
        self._candles[(inst_id, bar)] = df

    def set_ticker(
        self,
        inst_id: str,
        last: float,
        bid: float = 0.0,
        ask: float = 0.0,
        *,
        quote_volume_24h: float = 1_000_000,
        timestamp: float | None = None,
    ) -> None:
        self._tickers[inst_id] = Ticker(
            inst_id=inst_id,
            last=last,
            bid=bid,
            ask=ask,
            quote_volume_24h=quote_volume_24h,
            timestamp=time.time() if timestamp is None else timestamp,
        )

    def set_instrument(self, info: InstrumentInfo) -> None:
        self._instruments[info.inst_id] = info

    def on_order(self, cb: Callable[[_PlacedOrder], None]) -> None:
        """下单时的回调（测试可在回调里调整余额模拟成交）"""
        self._on_order = cb

    def set_fill_price(self, price: object) -> None:
        """设置后续市价单的模拟成交均价（用于测试滑点/入场价锚定）"""
        self._fill_price = parse_decimal_fact(
            price,
            "fake.fill_price",
            nonnegative=True,
        )

    def queue_order_outcome(
        self,
        *,
        state: str = "filled",
        fill_size: object | None = None,
        fill_price: object | None = None,
        fee: object = Decimal("0"),
        fee_ccy: str = "",
        lose_response: bool = False,
    ) -> None:
        """为下一笔订单编排 ACK/部分成交/响应丢失等故障。"""
        self._outcomes.append(_OrderOutcome(
            state=state,
            fill_size=(
                parse_decimal_fact(
                    fill_size,
                    "fake.fill_size",
                    nonnegative=True,
                )
                if fill_size is not None
                else None
            ),
            fill_price=(
                parse_decimal_fact(
                    fill_price,
                    "fake.fill_price",
                    nonnegative=True,
                )
                if fill_price is not None
                else None
            ),
            fee=parse_decimal_fact(fee, "fake.fee"),
            fee_ccy=fee_ccy,
            lose_response=lose_response,
        ))

    def queue_algo_outcome(
        self,
        *,
        state: ProtectionState = ProtectionState.ACTIVE,
        lose_response: bool = False,
        reject: bool = False,
    ) -> None:
        self._algo_outcomes.append(_AlgoOutcome(
            state=state,
            lose_response=lose_response,
            reject=reject,
        ))

    def queue_algo_amend_outcome(
        self, *, lose_response: bool = False, reject: bool = False
    ) -> None:
        self._algo_amend_outcomes.append(_AlgoOutcome(
            lose_response=lose_response, reject=reject
        ))

    def queue_algo_cancel_outcome(
        self, *, lose_response: bool = False, reject: bool = False
    ) -> None:
        self._algo_cancel_outcomes.append(_AlgoOutcome(
            lose_response=lose_response, reject=reject
        ))

    @property
    def quote_ccy(self) -> str:
        return self._quote

    # ---------- Exchange 接口 ----------

    def get_candles(self, inst_id: str, bar: str, limit: int) -> pd.DataFrame:
        df = self._candles.get((inst_id, bar))
        if df is None:
            return pd.DataFrame(columns=["ts", "open", "high", "low", "close", "vol", "vol_ccy"])
        return df.tail(limit).reset_index(drop=True)

    def get_history_candles(self, inst_id: str, bar: str, total: int) -> pd.DataFrame:
        df = self._candles.get((inst_id, bar))
        if df is None:
            return pd.DataFrame(columns=["ts", "open", "high", "low", "close", "vol", "vol_ccy"])
        return df.tail(total).reset_index(drop=True)

    def get_ticker(self, inst_id: str) -> Ticker:
        return self._tickers.get(inst_id, Ticker(inst_id=inst_id, last=0.0))

    def get_instrument(self, inst_id: str) -> InstrumentInfo:
        if inst_id in self._instruments:
            return self._instruments[inst_id]
        parts = inst_id.split("-")
        return InstrumentInfo(
            inst_id=inst_id,
            base_ccy=parts[0] if parts else inst_id,
            quote_ccy=parts[-1] if len(parts) > 1 else "USDT",
            lot_size=0.0,
            min_size=0.0,
        )

    def get_server_time(self) -> float:
        return time.time()

    def get_balance(self) -> BalanceSnapshot:
        return BalanceSnapshot(
            total_equity_quote=self._total_eq,
            available_quote=self._avail_quote,
            holdings=tuple(self._holdings.values()),
        )

    def get_account_identity(self) -> str:
        return self._account_identity

    def place_market_order(
        self,
        inst_id: str,
        side: str,
        size: Decimal,
        *,
        tgt_ccy: str = "base_ccy",
        cl_ord_id: str = "",
        max_slippage: Decimal | None = None,
    ) -> OrderResult:
        size = parse_decimal_fact(size, "fake.order_size", positive=True)
        if max_slippage is not None:
            max_slippage = parse_decimal_fact(
                max_slippage,
                "fake.max_slippage",
                nonnegative=True,
            )
        self._order_counter += 1
        order = _PlacedOrder(
            inst_id=inst_id,
            side=side,
            size=size,
            tgt_ccy=tgt_ccy,
            cl_ord_id=cl_ord_id,
            max_slippage=max_slippage,
        )
        self.orders.append(order)
        if self._on_order is not None:
            self._on_order(order)
        outcome = self._outcomes.pop(0) if self._outcomes else _OrderOutcome()
        ord_id = f"fake-{self._order_counter}"
        fill_size = (
            outcome.fill_size
            if outcome.fill_size is not None
            else (size if outcome.state == "filled" else Decimal("0"))
        )
        fill_price = (
            outcome.fill_price
            if outcome.fill_price is not None
            else self._fill_price
        )
        state = {
            "filled": OrderState.FILLED,
            "partially_filled": OrderState.PARTIALLY_FILLED,
            "live": OrderState.LIVE,
            "canceled": OrderState.CANCELED,
            "rejected": OrderState.REJECTED,
        }.get(outcome.state, OrderState.UNKNOWN)
        snapshot = ExchangeOrder(
            inst_id=inst_id,
            side=side,
            state=state,
            ord_id=ord_id,
            cl_ord_id=cl_ord_id,
            requested_qty=size,
            acc_fill_qty=fill_size,
            avg_fill_px=fill_price,
            fee=outcome.fee,
            fee_ccy=outcome.fee_ccy,
            trade_id=f"trade-{self._order_counter}" if fill_size > 0 else "",
            update_ts=time.time(),
        )
        self._exchange_orders[ord_id] = snapshot
        if cl_ord_id:
            self._by_cl_ord_id[cl_ord_id] = ord_id
        if state is OrderState.FILLED and side == "sell":
            base_ccy = inst_id.split("-")[0]
            holding = self._holdings.get(base_ccy)
            if holding is not None:
                self._holdings[base_ccy] = Holding(
                    ccy=base_ccy,
                    balance=max(
                        holding.balance - fill_size,
                        Decimal("0"),
                    ),
                    available=max(
                        holding.available - fill_size,
                        Decimal("0"),
                    ),
                )
        if outcome.lose_response:
            raise requests.Timeout("simulated response lost after exchange accepted order")
        return OrderResult(
            inst_id=inst_id,
            side=side,
            ord_id=ord_id,
            size=size,
            fill_price=fill_price,
            state=outcome.state,
            acc_fill_size=fill_size,
            fee=outcome.fee,
            fee_ccy=outcome.fee_ccy,
            trade_id=snapshot.trade_id,
        )

    def get_order_status(
        self, inst_id: str, *, ord_id: str = "", cl_ord_id: str = ""
    ) -> ExchangeOrder:
        if not ord_id and cl_ord_id:
            ord_id = self._by_cl_ord_id.get(cl_ord_id, "")
        order = self._exchange_orders.get(ord_id)
        if order is None or order.inst_id != inst_id:
            raise KeyError(f"order not found: {ord_id or cl_ord_id}")
        return order

    def set_order_status(
        self,
        ord_id: str,
        *,
        state: OrderState,
        acc_fill_size: object,
        fill_price: object = Decimal("0"),
        trade_id: str = "",
    ) -> None:
        previous = self._exchange_orders[ord_id]
        self._exchange_orders[ord_id] = ExchangeOrder(
            inst_id=previous.inst_id,
            side=previous.side,
            state=state,
            ord_id=ord_id,
            cl_ord_id=previous.cl_ord_id,
            requested_qty=previous.requested_qty,
            acc_fill_qty=parse_decimal_fact(
                acc_fill_size,
                "fake.acc_fill_size",
                nonnegative=True,
            ),
            avg_fill_px=parse_decimal_fact(
                fill_price,
                "fake.fill_price",
                nonnegative=True,
            ),
            fee=previous.fee,
            fee_ccy=previous.fee_ccy,
            trade_id=trade_id,
            update_ts=time.time(),
        )

    def get_pending_orders(self, inst_id: str = "") -> list[ExchangeOrder]:
        return [
            order for order in self._exchange_orders.values()
            if (not inst_id or order.inst_id == inst_id)
            and order.state in {OrderState.LIVE, OrderState.PARTIALLY_FILLED}
        ]

    def get_recent_orders(self, inst_id: str = "") -> list[ExchangeOrder]:
        return [
            order for order in self._exchange_orders.values()
            if (not inst_id or order.inst_id == inst_id)
            and order.state.is_terminal
        ]

    def get_recent_fills(self, inst_id: str = "") -> list[ExchangeFill]:
        return [
            ExchangeFill(
                inst_id=order.inst_id,
                ord_id=order.ord_id,
                trade_id=order.trade_id,
                side=order.side,
                fill_qty=order.acc_fill_qty,
                fill_px=order.avg_fill_px,
                fee=order.fee,
                fee_ccy=order.fee_ccy,
                cl_ord_id=order.cl_ord_id,
                exchange_ts=order.update_ts,
            )
            for order in self._exchange_orders.values()
            if order.acc_fill_qty > 0
            and (not inst_id or order.inst_id == inst_id)
        ]

    def cancel_order(
        self,
        inst_id: str,
        ord_id: str = "",
        *,
        cl_ord_id: str = "",
    ) -> ExchangeOrder:
        previous = self.get_order_status(
            inst_id,
            ord_id=ord_id,
            cl_ord_id=cl_ord_id,
        )
        updated = ExchangeOrder(
            **{
                **previous.__dict__,
                "state": OrderState.CANCELED,
                "update_ts": time.time(),
            }
        )
        self._exchange_orders[previous.ord_id] = updated
        return updated

    def amend_order(
        self,
        inst_id: str,
        ord_id: str = "",
        *,
        cl_ord_id: str = "",
        new_size: Decimal | None = None,
        new_price: Decimal | None = None,
    ) -> ExchangeOrder:
        previous = self.get_order_status(
            inst_id,
            ord_id=ord_id,
            cl_ord_id=cl_ord_id,
        )
        requested_qty = (
            parse_decimal_fact(
                new_size,
                "fake.amend.new_size",
                positive=True,
            )
            if new_size is not None
            else previous.requested_qty
        )
        if new_price is not None:
            parse_decimal_fact(
                new_price,
                "fake.amend.new_price",
                positive=True,
            )
        updated = ExchangeOrder(
            **{
                **previous.__dict__,
                "requested_qty": requested_qty,
                "update_ts": time.time(),
            }
        )
        self._exchange_orders[previous.ord_id] = updated
        return updated

    def place_protection_order(
        self,
        inst_id: str,
        *,
        size: Decimal,
        stop_loss: Decimal,
        take_profit: Decimal = Decimal("0"),
        algo_cl_ord_id: str = "",
    ) -> ExchangeAlgoOrder:
        outcome = self._algo_outcomes.pop(0) if self._algo_outcomes else _AlgoOutcome()
        if outcome.reject:
            raise RuntimeError("simulated algo rejection")
        self._algo_counter += 1
        algo_id = f"algo-{self._algo_counter}"
        order = ExchangeAlgoOrder(
            inst_id=inst_id,
            kind="oco" if take_profit > 0 else "conditional",
            state=outcome.state,
            protected_qty=parse_decimal_fact(
                size,
                "fake.protection_size",
                positive=True,
            ),
            trigger_px=parse_decimal_fact(
                stop_loss,
                "fake.stop_loss",
                positive=True,
            ),
            take_profit_px=parse_decimal_fact(
                take_profit,
                "fake.take_profit",
                nonnegative=True,
            ),
            order_px=Decimal("-1"),
            algo_id=algo_id,
            algo_cl_ord_id=algo_cl_ord_id,
            update_ts=time.time(),
        )
        self._algo_orders[algo_id] = order
        if algo_cl_ord_id:
            self._algo_by_client_id[algo_cl_ord_id] = algo_id
        if outcome.lose_response:
            raise requests.Timeout("simulated algo response lost after acceptance")
        return order

    def get_algo_order(
        self, *, algo_id: str = "", algo_cl_ord_id: str = ""
    ) -> ExchangeAlgoOrder:
        if not algo_id and algo_cl_ord_id:
            algo_id = self._algo_by_client_id.get(algo_cl_ord_id, "")
        if algo_id not in self._algo_orders:
            raise KeyError(f"algo not found: {algo_id or algo_cl_ord_id}")
        return self._algo_orders[algo_id]

    def get_pending_algo_orders(self, inst_id: str = "") -> list[ExchangeAlgoOrder]:
        return [
            order for order in self._algo_orders.values()
            if (not inst_id or order.inst_id == inst_id)
            and order.state in {
                ProtectionState.ACTIVE,
                ProtectionState.SUBMITTING,
                ProtectionState.AMENDING,
            }
        ]

    def cancel_algo_order(self, inst_id: str, algo_id: str) -> ExchangeAlgoOrder:
        outcome = (
            self._algo_cancel_outcomes.pop(0)
            if self._algo_cancel_outcomes
            else _AlgoOutcome()
        )
        if outcome.reject:
            raise RuntimeError("simulated algo cancel rejection")
        previous = self.get_algo_order(algo_id=algo_id)
        updated = ExchangeAlgoOrder(
            **{
                **previous.__dict__,
                "state": ProtectionState.CANCELED,
                "update_ts": time.time(),
            }
        )
        self._algo_orders[algo_id] = updated
        if outcome.lose_response:
            raise requests.Timeout(
                "simulated algo cancel response lost after acceptance"
            )
        return updated

    def amend_algo_order(
        self,
        inst_id: str,
        algo_id: str,
        *,
        size: Decimal,
        stop_loss: Decimal,
        take_profit: Decimal = Decimal("0"),
        req_id: str = "",
    ) -> ExchangeAlgoOrder:
        outcome = (
            self._algo_amend_outcomes.pop(0)
            if self._algo_amend_outcomes
            else _AlgoOutcome()
        )
        if outcome.reject:
            raise RuntimeError("simulated algo amend rejection")
        previous = self.get_algo_order(algo_id=algo_id)
        if previous.state is not ProtectionState.ACTIVE:
            raise RuntimeError("algo is not active")
        updated = ExchangeAlgoOrder(
            **{
                **previous.__dict__,
                "protected_qty": parse_decimal_fact(
                    size,
                    "fake.protection_size",
                    positive=True,
                ),
                "trigger_px": parse_decimal_fact(
                    stop_loss,
                    "fake.stop_loss",
                    positive=True,
                ),
                "take_profit_px": parse_decimal_fact(
                    take_profit,
                    "fake.take_profit",
                    nonnegative=True,
                ),
                "update_ts": time.time(),
            }
        )
        self._algo_orders[algo_id] = updated
        if outcome.lose_response:
            raise requests.Timeout(
                "simulated algo amend response lost after acceptance"
            )
        return updated

    def trigger_algo_order(
        self,
        algo_id: str,
        *,
        actual_order_id: str = "",
    ) -> None:
        previous = self.get_algo_order(algo_id=algo_id)
        self._algo_orders[algo_id] = ExchangeAlgoOrder(
            **{
                **previous.__dict__,
                "state": ProtectionState.TRIGGERED,
                "actual_order_id": actual_order_id,
                "update_ts": time.time(),
            }
        )
