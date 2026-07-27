"""交易所 Protocol 与归一化数据类型

所有 dataclass 字段采用交易所中立命名，避免泄漏 OKX/Binance 特定术语。
LiveTrader / Supervisor / RiskManager 等领域代码只依赖这些类型。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from decimal import ROUND_DOWN, ROUND_UP, Decimal, InvalidOperation
from typing import TYPE_CHECKING, Protocol

import pandas as pd

if TYPE_CHECKING:
    from okx_quant.domain.orders import ExchangeAlgoOrder, ExchangeFill, ExchangeOrder


@dataclass(frozen=True)
class InstrumentInfo:
    """交易对精度与下单约束"""

    inst_id: str
    base_ccy: str        # 基础币种，如 BTC
    quote_ccy: str       # 计价币种，如 USDT
    lot_size: Decimal      # 下单数量步长
    min_size: Decimal      # 最小下单数量（以基础币种计）
    tick_size: Decimal = Decimal("0")   # 价格精度（limit 单时用）

    def __post_init__(self) -> None:
        object.__setattr__(self, "lot_size", _decimal_fact(self.lot_size, "lot_size"))
        object.__setattr__(self, "min_size", _decimal_fact(self.min_size, "min_size"))
        object.__setattr__(self, "tick_size", _decimal_fact(self.tick_size, "tick_size"))


def tradable_base_quantity(
    quantity: Decimal,
    instrument: InstrumentInfo,
) -> tuple[Decimal, Decimal]:
    """按 lotSz 向下取得可交易数量，并返回不可交易余量。"""
    lot = instrument.lot_size
    minimum = instrument.min_size
    if lot <= 0:
        return quantity, Decimal("0")
    tradable = (
        quantity / lot
    ).to_integral_value(rounding=ROUND_DOWN) * lot
    if minimum > 0 and tradable < minimum:
        return Decimal("0"), quantity
    return tradable, quantity - tradable


def price_on_tick(
    price: Decimal,
    instrument: InstrumentInfo,
    *,
    up: bool,
) -> Decimal:
    """止损向下、止盈向上量化，避免减弱既定风险边界。"""
    tick = instrument.tick_size
    if tick <= 0:
        return price
    rounding = ROUND_UP if up else ROUND_DOWN
    return (price / tick).to_integral_value(rounding=rounding) * tick


@dataclass(frozen=True)
class Holding:
    """账户持仓快照"""

    ccy: str
    balance: Decimal       # 余额（币种数量，含冻结）
    available: Decimal     # 可用（未冻结部分）

    def __post_init__(self) -> None:
        object.__setattr__(self, "balance", _decimal_fact(self.balance, "balance"))
        object.__setattr__(
            self,
            "available",
            _decimal_fact(self.available, "available"),
        )


@dataclass(frozen=True)
class BalanceSnapshot:
    """账户级余额快照 —— 一次性返回总权益与各币种持仓明细"""

    total_equity_quote: Decimal        # 总权益（计价币种，通常 USDT）
    available_quote: Decimal           # 可用计价币种
    holdings: tuple[Holding, ...]    # 全部币种持仓（含 quote）

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "total_equity_quote",
            _decimal_fact(self.total_equity_quote, "total_equity_quote"),
        )
        object.__setattr__(
            self,
            "available_quote",
            _decimal_fact(self.available_quote, "available_quote"),
        )

    def holding(self, ccy: str) -> Holding | None:
        for h in self.holdings:
            if h.ccy == ccy:
                return h
        return None

    def non_quote_holdings(self, quote: str = "USDT") -> list[Holding]:
        """仅返回基础币种持仓（排除计价货币自身），且余额大于 0"""
        return [h for h in self.holdings if h.ccy != quote and h.balance > 0]


@dataclass(frozen=True)
class Ticker:
    """实时行情快照"""

    inst_id: str
    last: Decimal
    bid: Decimal = Decimal("0")
    ask: Decimal = Decimal("0")
    quote_volume_24h: Decimal = Decimal("0")
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        for name in ("last", "bid", "ask", "quote_volume_24h"):
            object.__setattr__(self, name, _decimal_fact(getattr(self, name), name))


@dataclass(frozen=True)
class Candle:
    """单根 K 线（主要用于类型标注；批量查询返回 DataFrame）"""

    ts: pd.Timestamp
    open: float
    high: float
    low: float
    close: float
    vol: float


@dataclass(frozen=True)
class OrderResult:
    """下单结果归一化"""

    inst_id: str
    side: str            # "buy" | "sell"
    ord_id: str
    size: Decimal          # 实际下单数量（基础币种）
    fill_price: Decimal = Decimal("0")   # 实际成交均价（市价单回查得到，0 表示未知）
    state: str = ""           # live / partially_filled / filled / canceled
    acc_fill_size: Decimal = Decimal("0")
    fee: Decimal = Decimal("0")
    fee_ccy: str = ""
    trade_id: str = ""
    raw: dict = field(default_factory=dict)  # 原始返回，诊断用

    def __post_init__(self) -> None:
        for name in ("size", "fill_price", "acc_fill_size", "fee"):
            object.__setattr__(self, name, _decimal_fact(getattr(self, name), name))


class ExchangeReader(Protocol):
    """只读行情、账户与交易事实端口。"""

    def get_candles(self, inst_id: str, bar: str, limit: int) -> pd.DataFrame:
        """返回最近 limit 根 K 线，升序，含列 ts/open/high/low/close/vol/vol_ccy"""

    def get_history_candles(self, inst_id: str, bar: str, total: int) -> pd.DataFrame:
        """返回至少 total 根历史 K 线，升序（自动翻页）"""

    def get_ticker(self, inst_id: str) -> Ticker: ...

    def get_instrument(self, inst_id: str) -> InstrumentInfo: ...

    def get_server_time(self) -> float:
        """返回交易所 Unix 时间（秒），用于启动时钟偏差门禁。"""

    # ------------------ 账户 ------------------

    def get_balance(self) -> BalanceSnapshot:
        """一次性返回全部币种余额快照"""

    def get_account_identity(self) -> str:
        """返回交易所不可变账户 UID，用于绑定危险操作。"""

    def get_order_status(
        self, inst_id: str, *, ord_id: str = "", cl_ord_id: str = ""
    ) -> ExchangeOrder:
        """查询单个订单的累计成交与最终状态。"""

    def get_pending_orders(self, inst_id: str = "") -> list[ExchangeOrder]:
        """查询普通未完成订单。"""

    def get_recent_orders(self, inst_id: str = "") -> list[ExchangeOrder]:
        """查询近期已完成普通订单。"""

    def get_recent_fills(self, inst_id: str = "") -> list[ExchangeFill]:
        """查询近期真实成交。"""

    def get_algo_order(
        self, *, algo_id: str = "", algo_cl_ord_id: str = ""
    ) -> ExchangeAlgoOrder:
        """查询单个保护单。"""

    def get_pending_algo_orders(self, inst_id: str = "") -> list[ExchangeAlgoOrder]:
        """查询未触发保护单。"""


class ExchangeTrader(Protocol):
    """可能改变交易所状态的最小写端口。"""

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
        """市价下单。size 单位由 tgt_ccy 决定。"""

    def cancel_order(
        self,
        inst_id: str,
        ord_id: str = "",
        *,
        cl_ord_id: str = "",
    ) -> ExchangeOrder:
        """取消普通订单并返回交易所最新事实。"""

    def amend_order(
        self,
        inst_id: str,
        ord_id: str = "",
        *,
        cl_ord_id: str = "",
        new_size: Decimal | None = None,
        new_price: Decimal | None = None,
    ) -> ExchangeOrder:
        """修改普通订单并返回交易所最新事实。"""

    def place_protection_order(
        self,
        inst_id: str,
        *,
        size: Decimal,
        stop_loss: Decimal,
        take_profit: Decimal = Decimal("0"),
        algo_cl_ord_id: str = "",
    ) -> ExchangeAlgoOrder:
        """创建独立的 SPOT conditional/OCO 卖出保护单。"""

    def cancel_algo_order(self, inst_id: str, algo_id: str) -> ExchangeAlgoOrder:
        """取消保护单并返回最新状态。"""

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
        """修改保护数量或触发价。"""


class Exchange(ExchangeReader, ExchangeTrader, Protocol):
    """完整交易所端口；按需依赖 Reader 或 Trader，避免只读服务持写权限。"""


def _decimal_fact(value: object, field_name: str) -> Decimal:
    """把边界输入立即归一化为有限 Decimal；无效事实不得伪装成零。"""
    try:
        parsed = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} 不是有效十进制数") from exc
    if not parsed.is_finite():
        raise ValueError(f"{field_name} 必须是有限十进制数")
    return parsed
