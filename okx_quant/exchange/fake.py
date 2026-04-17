"""测试用 FakeExchange —— 内存持久化，无网络依赖"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

import pandas as pd

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
    size: float
    tgt_ccy: str


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
        self._total_eq: float = 0.0
        self._avail_quote: float = 0.0
        self._holdings: dict[str, Holding] = {}
        self._candles: dict[tuple[str, str], pd.DataFrame] = {}
        self._tickers: dict[str, Ticker] = {}
        self._instruments: dict[str, InstrumentInfo] = {}
        self.orders: list[_PlacedOrder] = []
        self._order_counter: int = 0
        self._on_order: Optional[Callable[[_PlacedOrder], None]] = None

    # ---------- 测试桩点 ----------

    def set_balance(self, total: float, quote_avail: float) -> None:
        self._total_eq = total
        self._avail_quote = quote_avail
        # 顺便把 quote 持仓也记入 holdings
        self._holdings[self._quote] = Holding(
            ccy=self._quote, balance=total, available=quote_avail,
        )

    def set_holding(self, ccy: str, balance: float, available: float) -> None:
        self._holdings[ccy] = Holding(ccy=ccy, balance=balance, available=available)

    def set_candles(self, inst_id: str, bar: str, df: pd.DataFrame) -> None:
        self._candles[(inst_id, bar)] = df

    def set_ticker(self, inst_id: str, last: float, bid: float = 0.0, ask: float = 0.0) -> None:
        self._tickers[inst_id] = Ticker(inst_id=inst_id, last=last, bid=bid, ask=ask)

    def set_instrument(self, info: InstrumentInfo) -> None:
        self._instruments[info.inst_id] = info

    def on_order(self, cb: Callable[[_PlacedOrder], None]) -> None:
        """下单时的回调（测试可在回调里调整余额模拟成交）"""
        self._on_order = cb

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

    def get_balance(self) -> BalanceSnapshot:
        return BalanceSnapshot(
            total_equity_quote=self._total_eq,
            available_quote=self._avail_quote,
            holdings=tuple(self._holdings.values()),
        )

    def place_market_order(
        self,
        inst_id: str,
        side: str,
        size: float,
        *,
        tgt_ccy: str = "base_ccy",
    ) -> OrderResult:
        self._order_counter += 1
        order = _PlacedOrder(inst_id=inst_id, side=side, size=size, tgt_ccy=tgt_ccy)
        self.orders.append(order)
        if self._on_order is not None:
            self._on_order(order)
        return OrderResult(
            inst_id=inst_id,
            side=side,
            ord_id=f"fake-{self._order_counter}",
            size=size,
        )
