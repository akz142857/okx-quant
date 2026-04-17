"""策略基类：定义信号结构和策略接口"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

import pandas as pd

if TYPE_CHECKING:
    from okx_quant.data.news import CryptoNewsFetcher
    from okx_quant.llm.client import LLMClient


@dataclass(frozen=True)
class StrategyContext:
    """策略依赖注入容器

    替代旧的 set_llm_client / set_deep_llm_client / set_news_fetcher 分散调用，
    所有外部依赖在构造时一次性传入，避免"部分装配"中间态。

    ``extra`` 通过 tuple[tuple] 存储以兼顾不可变性；若需字典形式访问，
    使用 ``context.extra_dict()``。
    """

    llm_client: "Optional[LLMClient]" = None           # 廉价模型（单 LLM 策略主用）
    deep_llm_client: "Optional[LLMClient]" = None      # 强力模型（多 Agent 辩论+决策）
    news_fetcher: "Optional[CryptoNewsFetcher]" = None
    extra: tuple[tuple[str, Any], ...] = ()

    def extra_dict(self) -> dict[str, Any]:
        """只读快照：返回 extra 的字典视图"""
        return dict(self.extra)

    @classmethod
    def from_dict_extra(
        cls,
        *,
        llm_client: "Optional[LLMClient]" = None,
        deep_llm_client: "Optional[LLMClient]" = None,
        news_fetcher: "Optional[CryptoNewsFetcher]" = None,
        extra: "Optional[dict[str, Any]]" = None,
    ) -> "StrategyContext":
        return cls(
            llm_client=llm_client,
            deep_llm_client=deep_llm_client,
            news_fetcher=news_fetcher,
            extra=tuple((extra or {}).items()),
        )


class SignalType(Enum):
    BUY = "buy"
    SELL = "sell"
    HOLD = "hold"


@dataclass
class Signal:
    """交易信号"""

    signal: SignalType
    inst_id: str
    price: float               # 建议价格（0 表示市价）
    size_pct: float = 1.0      # 建议仓位比例（0~1），1 表示用全部可用资金
    stop_loss: float = 0.0     # 止损价，0 表示不设
    take_profit: float = 0.0   # 止盈价，0 表示不设
    reason: str = ""           # 信号原因描述
    extra: dict = field(default_factory=dict)

    @property
    def is_buy(self) -> bool:
        return self.signal == SignalType.BUY

    @property
    def is_sell(self) -> bool:
        return self.signal == SignalType.SELL

    @property
    def is_hold(self) -> bool:
        return self.signal == SignalType.HOLD


class BaseStrategy(ABC):
    """策略基类

    子类只需实现 `generate_signal()` 方法。
    策略对象是无状态的（不持有持仓信息），由回测引擎或实盘执行器管理状态。

    示例::

        class MyStrategy(BaseStrategy):
            def generate_signal(self, df, inst_id):
                # df 是最新的 K 线 DataFrame
                # 返回 Signal 对象
                ...
    """

    name: str = "BaseStrategy"

    def __init__(
        self,
        params: Optional[dict] = None,
        context: Optional[StrategyContext] = None,
    ):
        self.params = params or {}
        self._context: StrategyContext = context or StrategyContext()
        self._apply_context()

    @property
    def context(self) -> StrategyContext:
        return self._context

    def _apply_context(self) -> None:
        """子类可覆写以将 StrategyContext 字段分发到自己的内部句柄"""

    @abstractmethod
    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        """根据 K 线数据生成交易信号

        Args:
            df: K 线 DataFrame，含 ts/open/high/low/close/vol 列，按时间升序
            inst_id: 交易对，如 "BTC-USDT"

        Returns:
            Signal 对象
        """

    def get_param(self, key: str, default=None):
        return self.params.get(key, default)

    def __repr__(self) -> str:
        return f"{self.name}({self.params})"
