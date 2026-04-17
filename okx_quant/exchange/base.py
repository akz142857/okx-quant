"""交易所 Protocol 与归一化数据类型

所有 dataclass 字段采用交易所中立命名，避免泄漏 OKX/Binance 特定术语。
LiveTrader / Supervisor / RiskManager 等领域代码只依赖这些类型。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol

import pandas as pd


@dataclass(frozen=True)
class InstrumentInfo:
    """交易对精度与下单约束"""

    inst_id: str
    base_ccy: str        # 基础币种，如 BTC
    quote_ccy: str       # 计价币种，如 USDT
    lot_size: float      # 下单数量步长
    min_size: float      # 最小下单数量（以基础币种计）
    tick_size: float = 0.0   # 价格精度（limit 单时用）


@dataclass(frozen=True)
class Holding:
    """账户持仓快照"""

    ccy: str
    balance: float       # 余额（币种数量，含冻结）
    available: float     # 可用（未冻结部分）


@dataclass(frozen=True)
class BalanceSnapshot:
    """账户级余额快照 —— 一次性返回总权益与各币种持仓明细"""

    total_equity_quote: float        # 总权益（计价币种，通常 USDT）
    available_quote: float           # 可用计价币种
    holdings: tuple[Holding, ...]    # 全部币种持仓（含 quote）

    def holding(self, ccy: str) -> Optional[Holding]:
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
    last: float
    bid: float = 0.0
    ask: float = 0.0


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
    size: float          # 实际下单数量（基础币种）
    raw: dict = field(default_factory=dict)  # 原始返回，诊断用


class Exchange(Protocol):
    """交易所抽象

    注意：所有方法应是阻塞 / 同步语义；并发由上层 ThreadPoolExecutor 管理。
    实现可能抛出 RuntimeError（业务错误）或 requests 相关异常；
    调用方应捕获并决定是否重试或降级。
    """

    # ------------------ 行情 ------------------

    def get_candles(self, inst_id: str, bar: str, limit: int) -> pd.DataFrame:
        """返回最近 limit 根 K 线，升序，含列 ts/open/high/low/close/vol/vol_ccy"""

    def get_history_candles(self, inst_id: str, bar: str, total: int) -> pd.DataFrame:
        """返回至少 total 根历史 K 线，升序（自动翻页）"""

    def get_ticker(self, inst_id: str) -> Ticker: ...

    def get_instrument(self, inst_id: str) -> InstrumentInfo: ...

    # ------------------ 账户 ------------------

    def get_balance(self) -> BalanceSnapshot:
        """一次性返回全部币种余额快照"""

    # ------------------ 交易 ------------------

    def place_market_order(
        self,
        inst_id: str,
        side: str,
        size: float,
        *,
        tgt_ccy: str = "base_ccy",
    ) -> OrderResult:
        """市价下单。size 单位由 tgt_ccy 决定：base_ccy 为基础币种数量，
        quote_ccy 为计价币种金额。"""
