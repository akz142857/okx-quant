"""OKX 交易所 adapter — 把 OKXRestClient 的原始返回归一化为 Exchange Protocol"""

from __future__ import annotations

import logging
from decimal import Decimal

import pandas as pd

from okx_quant.client.rest import OKXRestClient
from okx_quant.data.market import MarketDataFetcher
from okx_quant.domain.orders import (
    ExchangeAlgoOrder,
    ExchangeFill,
    ExchangeOrder,
    OrderState,
    map_exchange_algo_state,
    map_exchange_order_state,
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
            last=parse_decimal_fact(
                raw.get("last"),
                "ticker.last",
                positive=True,
            ),
            bid=parse_decimal_fact(
                raw.get("bidPx"),
                "ticker.bid",
                default="0",
                nonnegative=True,
            ),
            ask=parse_decimal_fact(
                raw.get("askPx"),
                "ticker.ask",
                default="0",
                nonnegative=True,
            ),
            quote_volume_24h=parse_decimal_fact(
                raw.get("volCcy24h") or raw.get("volCcyQuote24h"),
                "ticker.quote_volume_24h",
                default="0",
                nonnegative=True,
            ),
            timestamp=_timestamp_seconds(raw.get("ts")),
        )

    def get_instrument(self, inst_id: str) -> InstrumentInfo:
        raw = self._client.get_instrument(inst_id) or {}
        base = raw.get("baseCcy") or inst_id.split("-")[0]
        quote = raw.get("quoteCcy") or inst_id.split("-")[-1]
        return InstrumentInfo(
            inst_id=inst_id,
            base_ccy=base,
            quote_ccy=quote,
            lot_size=parse_decimal_fact(
                raw.get("lotSz"),
                "instrument.lotSz",
                positive=True,
            ),
            min_size=parse_decimal_fact(
                raw.get("minSz"),
                "instrument.minSz",
                positive=True,
            ),
            tick_size=parse_decimal_fact(
                raw.get("tickSz"),
                "instrument.tickSz",
                positive=True,
            ),
        )

    def get_server_time(self) -> float:
        return self._client.get_server_time()

    # ------------------ 账户 ------------------

    def get_balance(self) -> BalanceSnapshot:
        """读取全账户余额并归一化

        OKX V5 返回结构为 [{'totalEq': ..., 'details': [{'ccy': ..., 'cashBal': ..., 'availEq': ...}, ...]}]
        """
        raw_list = self._client.get_balance() or []
        # 空列表代表 API 调用异常（真实账户即使空仓也会返回含 totalEq 的对象）。
        # 抛错而非返回"零余额"，避免上层把临时故障误判为"无持仓"而清掉真实仓位。
        if not raw_list:
            raise RuntimeError("账户余额查询返回空，疑似临时故障")
        total_eq = Decimal("0")
        avail_quote = Decimal("0")
        holdings: list[Holding] = []
        for item in raw_list:
            total_eq = parse_decimal_fact(
                item.get("totalEq"),
                "balance.totalEq",
                nonnegative=True,
            )
            for detail in item.get("details", []):
                ccy = detail.get("ccy", "")
                if not ccy:
                    raise ValueError("balance.details[].ccy 缺失")
                bal = parse_decimal_fact(
                    detail.get("cashBal"),
                    f"balance.{ccy}.cashBal",
                    nonnegative=True,
                )
                # 现货场景下 availEq 与 availBal 都代表可用，一般都存在
                avail_raw = detail.get("availEq")
                if avail_raw in (None, ""):
                    avail_raw = detail.get("availBal")
                avail = parse_decimal_fact(
                    avail_raw,
                    f"balance.{ccy}.available",
                    nonnegative=True,
                )
                if avail > bal:
                    raise ValueError(
                        f"balance.{ccy}.available 不得大于 cashBal"
                    )
                holdings.append(Holding(ccy=ccy, balance=bal, available=avail))
                if ccy == self._quote:
                    avail_quote = avail
        return BalanceSnapshot(
            total_equity_quote=total_eq,
            available_quote=avail_quote,
            holdings=tuple(holdings),
        )

    def get_account_identity(self) -> str:
        uid = str(self._client.get_account_config().get("uid", "")).strip()
        if not uid:
            raise RuntimeError("OKX account config 缺少 uid")
        return uid

    # ------------------ 交易 ------------------

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
        size = parse_decimal_fact(size, "order.size", positive=True)
        size_str = _fmt_decimal(size)
        if max_slippage is not None:
            max_slippage = parse_decimal_fact(
                max_slippage,
                "order.max_slippage",
                nonnegative=True,
            )
        raw = self._client.place_order(
            inst_id=inst_id,
            side=side,
            ord_type="market",
            sz=size_str,
            tgt_ccy=tgt_ccy if side == "buy" else None,
            cl_ord_id=cl_ord_id or None,
            max_slippage=(
                _fmt_decimal(max_slippage)
                if side == "buy" and max_slippage is not None
                else None
            ),
        ) or {}
        ord_id = str(raw.get("ordId", ""))
        if not ord_id:
            raise RuntimeError(f"下单响应缺少 ordId: {raw}")

        # POST ACK 只证明 OKX 接纳请求。不要在共享执行锁内同步 GET：
        # 慢查询会阻塞已经到达的私有 WS fill，直接侵蚀保护单 10s SLO。
        # 成交/费用事实统一由 WS 或 Reconciler 的严格映射推进。
        return OrderResult(
            inst_id=inst_id,
            side=side,
            ord_id=ord_id,
            size=size,
            fill_price=Decimal("0"),
            state="",
            acc_fill_size=Decimal("0"),
            fee=Decimal("0"),
            raw=dict(raw),
        )

    def get_order_status(
        self, inst_id: str, *, ord_id: str = "", cl_ord_id: str = ""
    ) -> ExchangeOrder:
        raw = self._client.get_order(
            inst_id,
            ord_id=ord_id or None,
            cl_ord_id=cl_ord_id or None,
        ) or {}
        return self._map_order(raw, inst_id)

    def get_pending_orders(self, inst_id: str = "") -> list[ExchangeOrder]:
        return [
            self._map_order(raw, str(raw.get("instId", inst_id)))
            for raw in self._client.get_open_orders(inst_id or None)
        ]

    def get_recent_orders(self, inst_id: str = "") -> list[ExchangeOrder]:
        return [
            self._map_order(raw, str(raw.get("instId", inst_id)))
            for raw in self._client.get_order_history(inst_id=inst_id or None)
        ]

    def get_recent_fills(self, inst_id: str = "") -> list[ExchangeFill]:
        return [
            ExchangeFill(
                inst_id=str(raw.get("instId", inst_id)),
                ord_id=str(raw.get("ordId", "")),
                trade_id=str(raw.get("tradeId", "")),
                side=str(raw.get("side", "")),
                fill_qty=parse_decimal_fact(
                    raw.get("fillSz"),
                    "fill.fillSz",
                    positive=True,
                ),
                fill_px=parse_decimal_fact(
                    raw.get("fillPx"),
                    "fill.fillPx",
                    positive=True,
                ),
                fee=parse_decimal_fact(
                    raw.get("fee"),
                    "fill.fee",
                    default="0",
                ),
                fee_ccy=str(raw.get("feeCcy", "")),
                cl_ord_id=str(raw.get("clOrdId", "")),
                exchange_ts=_timestamp_seconds(raw.get("ts")),
                raw=dict(raw),
            )
            for raw in self._client.get_fills(inst_id=inst_id or None, limit=100)
        ]

    def cancel_order(
        self,
        inst_id: str,
        ord_id: str = "",
        *,
        cl_ord_id: str = "",
    ) -> ExchangeOrder:
        self._client.cancel_order(
            inst_id,
            ord_id or None,
            cl_ord_id=cl_ord_id or None,
        )
        return self.get_order_status(
            inst_id,
            ord_id=ord_id,
            cl_ord_id=cl_ord_id,
        )

    def amend_order(
        self,
        inst_id: str,
        ord_id: str = "",
        *,
        cl_ord_id: str = "",
        new_size: Decimal | None = None,
        new_price: Decimal | None = None,
    ) -> ExchangeOrder:
        self._client.amend_order(
            inst_id,
            ord_id or None,
            cl_ord_id=cl_ord_id or None,
            new_size=(
                _fmt_decimal(
                    parse_decimal_fact(
                        new_size,
                        "amend.new_size",
                        positive=True,
                    )
                )
                if new_size is not None
                else None
            ),
            new_price=(
                _fmt_decimal(
                    parse_decimal_fact(
                        new_price,
                        "amend.new_price",
                        positive=True,
                    )
                )
                if new_price is not None
                else None
            ),
        )
        return self.get_order_status(
            inst_id,
            ord_id=ord_id,
            cl_ord_id=cl_ord_id,
        )

    def place_protection_order(
        self,
        inst_id: str,
        *,
        size: Decimal,
        stop_loss: Decimal,
        take_profit: Decimal = Decimal("0"),
        algo_cl_ord_id: str = "",
    ) -> ExchangeAlgoOrder:
        raw = self._client.place_algo_order(
            inst_id=inst_id,
            side="sell",
            ord_type="oco" if take_profit > 0 else "conditional",
            sz=_fmt_decimal(
                parse_decimal_fact(size, "protection.size", positive=True)
            ),
            algo_cl_ord_id=algo_cl_ord_id,
            stop_loss=_fmt_decimal(
                parse_decimal_fact(
                    stop_loss,
                    "protection.stop_loss",
                    positive=True,
                )
            ),
            take_profit=_fmt_decimal(
                parse_decimal_fact(
                    take_profit,
                    "protection.take_profit",
                    positive=True,
                )
            ) if take_profit > 0 else "",
        ) or {}
        algo_id = str(raw.get("algoId", ""))
        if not algo_id:
            raise RuntimeError(f"保护单响应缺少 algoId: {raw}")
        # POST ACK 只证明请求被接收，不能证明保护已 ACTIVE。详情查询
        # 失败必须上抛给 ProtectionManager 的 UNKNOWN resolver。
        return self.get_algo_order(algo_id=algo_id)

    def get_algo_order(
        self, *, algo_id: str = "", algo_cl_ord_id: str = ""
    ) -> ExchangeAlgoOrder:
        raw = self._client.get_algo_order(
            algo_id=algo_id,
            algo_cl_ord_id=algo_cl_ord_id,
        ) or {}
        return self._map_algo(raw)

    def get_pending_algo_orders(self, inst_id: str = "") -> list[ExchangeAlgoOrder]:
        rows = []
        for kind in ("oco", "conditional"):
            rows.extend(self._client.get_pending_algo_orders(
                inst_id=inst_id, ord_type=kind
            ))
        return [self._map_algo(raw) for raw in rows]

    def cancel_algo_order(self, inst_id: str, algo_id: str) -> ExchangeAlgoOrder:
        self._client.cancel_algo_order(inst_id, algo_id)
        # cancel ACK 后仍可能与触发竞态；必须取得 canceled/effective 事实。
        return self.get_algo_order(algo_id=algo_id)

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
        self._client.amend_algo_order(
            inst_id=inst_id,
            algo_id=algo_id,
            size=_fmt_decimal(
                parse_decimal_fact(size, "protection.size", positive=True)
            ),
            stop_loss=_fmt_decimal(
                parse_decimal_fact(
                    stop_loss,
                    "protection.stop_loss",
                    positive=True,
                )
            ),
            take_profit=_fmt_decimal(
                parse_decimal_fact(
                    take_profit,
                    "protection.take_profit",
                    positive=True,
                )
            ) if take_profit > 0 else "",
            req_id=req_id,
        )
        return self.get_algo_order(algo_id=algo_id)

    @staticmethod
    def _map_order(raw: dict, fallback_inst_id: str = "") -> ExchangeOrder:
        raw_state = str(raw.get("state", ""))
        state = map_exchange_order_state(raw_state)
        if state is OrderState.UNKNOWN:
            raise ValueError(f"未知交易所订单状态: {raw_state!r}")
        requested_qty = parse_decimal_fact(
            raw.get("sz"),
            "order.sz",
            positive=True,
        )
        acc_fill_qty = parse_decimal_fact(
            raw.get("accFillSz"),
            "order.accFillSz",
            default="0",
            nonnegative=True,
        )
        avg_fill_px = parse_decimal_fact(
            raw.get("avgPx") or raw.get("fillPx"),
            "order.avgPx",
            default="0",
            nonnegative=True,
        )
        if state in {OrderState.FILLED, OrderState.PARTIALLY_FILLED} and (
            acc_fill_qty <= 0 or avg_fill_px <= 0
        ):
            raise ValueError(
                "已成交订单必须包含正数 accFillSz 和 avgPx"
            )
        return ExchangeOrder(
            inst_id=str(raw.get("instId", fallback_inst_id)),
            side=str(raw.get("side", "")),
            state=state,
            ord_id=str(raw.get("ordId", "")),
            cl_ord_id=str(raw.get("clOrdId", "")),
            requested_qty=requested_qty,
            acc_fill_qty=acc_fill_qty,
            avg_fill_px=avg_fill_px,
            fee=parse_decimal_fact(
                raw.get("fee"),
                "order.fee",
                default="0",
            ),
            fee_ccy=str(raw.get("feeCcy", "")),
            trade_id=str(raw.get("tradeId", "")),
            update_ts=_timestamp_seconds(raw.get("uTime")),
            raw=dict(raw),
        )

    @staticmethod
    def _map_algo(raw: dict) -> ExchangeAlgoOrder:
        sl = raw.get("slTriggerPx") or raw.get("triggerPx")
        tp = raw.get("tpTriggerPx")
        return ExchangeAlgoOrder(
            inst_id=str(raw.get("instId", "")),
            kind=str(raw.get("ordType", "")),
            state=map_exchange_algo_state(str(raw.get("state", ""))),
            protected_qty=parse_decimal_fact(
                raw.get("sz"),
                "algo.sz",
                positive=True,
            ),
            trigger_px=parse_decimal_fact(
                sl or tp,
                "algo.triggerPx",
                positive=True,
            ),
            take_profit_px=parse_decimal_fact(
                tp,
                "algo.takeProfitPx",
                default="0",
                nonnegative=True,
            ),
            order_px=parse_decimal_fact(
                raw.get("slOrdPx") or raw.get("orderPx"),
                "algo.orderPx",
                default="-1",
            ),
            algo_id=str(raw.get("algoId", "")),
            algo_cl_ord_id=str(raw.get("algoClOrdId", "")),
            actual_order_id=str(raw.get("ordId", "")),
            update_ts=_timestamp_seconds(raw.get("uTime") or raw.get("cTime")),
            raw=dict(raw),
        )


def _timestamp_seconds(v: object) -> float:
    try:
        return float(v) / 1000 if v not in (None, "") else 0.0
    except (TypeError, ValueError):
        return 0.0


def _fmt_decimal(value: Decimal) -> str:
    """保留交易所十进制事实的全部有效位，禁止科学计数法和 8 位截断。"""
    parsed = parse_decimal_fact(value, "request.decimal")
    rendered = format(parsed, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"
