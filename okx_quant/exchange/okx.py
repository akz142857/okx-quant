"""OKX 交易所 adapter — 把 OKXRestClient 的原始返回归一化为 Exchange Protocol"""

from __future__ import annotations

import logging
from typing import Optional

import pandas as pd

from okx_quant.client.rest import OKXRestClient
from okx_quant.data.market import MarketDataFetcher
from okx_quant.exchange.base import (
    BalanceSnapshot,
    Exchange,
    Holding,
    InstrumentInfo,
    OrderResult,
    Ticker,
)

logger = logging.getLogger(__name__)


class OKXExchange(Exchange):
    """OKX REST 客户端到 Exchange Protocol 的适配器

    所有 OKX 特定字段（totalEq/availEq/cashBal/instId/lotSz/minSz/tickSz）
    在此层解包为归一化 dataclass。
    """

    def __init__(self, client: OKXRestClient, quote_ccy: str = "USDT"):
        self._client = client
        self._fetcher = MarketDataFetcher(client)
        self._quote = quote_ccy

    @property
    def client(self) -> OKXRestClient:
        """对外暴露底层 REST 客户端（仅用于未覆盖的原始操作，应尽量避免）"""
        return self._client

    @property
    def quote_ccy(self) -> str:
        return self._quote

    # ------------------ 行情 ------------------

    def get_candles(self, inst_id: str, bar: str, limit: int) -> pd.DataFrame:
        return self._fetcher.get_candles(inst_id, bar=bar, limit=limit)

    def get_history_candles(self, inst_id: str, bar: str, total: int) -> pd.DataFrame:
        return self._fetcher.get_history_candles(inst_id, bar=bar, total=total)

    def get_ticker(self, inst_id: str) -> Ticker:
        raw = self._client.get_ticker(inst_id) or {}
        return Ticker(
            inst_id=raw.get("instId", inst_id),
            last=_to_float(raw.get("last")),
            bid=_to_float(raw.get("bidPx")),
            ask=_to_float(raw.get("askPx")),
        )

    def get_instrument(self, inst_id: str) -> InstrumentInfo:
        raw = self._client.get_instrument(inst_id) or {}
        base = raw.get("baseCcy") or inst_id.split("-")[0]
        quote = raw.get("quoteCcy") or inst_id.split("-")[-1]
        return InstrumentInfo(
            inst_id=inst_id,
            base_ccy=base,
            quote_ccy=quote,
            lot_size=_to_float(raw.get("lotSz")),
            min_size=_to_float(raw.get("minSz")),
            tick_size=_to_float(raw.get("tickSz")),
        )

    # ------------------ 账户 ------------------

    def get_balance(self) -> BalanceSnapshot:
        """读取全账户余额并归一化

        OKX V5 返回结构为 [{'totalEq': ..., 'details': [{'ccy': ..., 'cashBal': ..., 'availEq': ...}, ...]}]
        """
        raw_list = self._client.get_balance() or []
        total_eq = 0.0
        avail_quote = 0.0
        holdings: list[Holding] = []
        for item in raw_list:
            total_eq = _to_float(item.get("totalEq")) or total_eq
            for detail in item.get("details", []):
                ccy = detail.get("ccy", "")
                if not ccy:
                    continue
                bal = _to_float(detail.get("cashBal"))
                # 现货场景下 availEq 与 availBal 都代表可用，一般都存在
                avail = _to_float(detail.get("availEq")) or _to_float(detail.get("availBal"))
                holdings.append(Holding(ccy=ccy, balance=bal, available=avail))
                if ccy == self._quote:
                    avail_quote = avail
        return BalanceSnapshot(
            total_equity_quote=total_eq,
            available_quote=avail_quote,
            holdings=tuple(holdings),
        )

    # ------------------ 交易 ------------------

    def place_market_order(
        self,
        inst_id: str,
        side: str,
        size: float,
        *,
        tgt_ccy: str = "base_ccy",
    ) -> OrderResult:
        size_str = _fmt_size(size)
        raw = self._client.place_order(
            inst_id=inst_id,
            side=side,
            ord_type="market",
            sz=size_str,
            tgt_ccy=tgt_ccy if side == "buy" else None,
        ) or {}
        return OrderResult(
            inst_id=inst_id,
            side=side,
            ord_id=str(raw.get("ordId", "")),
            size=size,
            raw=dict(raw),
        )


def _to_float(v: Optional[str | float]) -> float:
    try:
        return float(v) if v not in (None, "") else 0.0
    except (TypeError, ValueError):
        return 0.0


def _fmt_size(size: float) -> str:
    """避免科学计数法"""
    return f"{size:.8f}".rstrip("0").rstrip(".")
