"""交易所抽象层

Exchange Protocol 定义了 LiveTrader / Supervisor 对外部行情与账户的所有依赖。
OKX 字段（totalEq/availEq/cashBal/instId 等）只在 adapter 内部存在，
领域代码之后仅依赖归一化后的 BalanceSnapshot / Holding / InstrumentInfo
/ OrderResult / Ticker dataclass。

新增交易所 = 实现一个新 adapter 并通过 factory 注入，无需修改领域代码。
"""

from okx_quant.exchange.base import (
    BalanceSnapshot,
    Candle,
    Exchange,
    Holding,
    InstrumentInfo,
    OrderResult,
    Ticker,
)
from okx_quant.exchange.okx import OKXExchange

__all__ = [
    "BalanceSnapshot",
    "Candle",
    "Exchange",
    "Holding",
    "InstrumentInfo",
    "OKXExchange",
    "OrderResult",
    "Ticker",
]
