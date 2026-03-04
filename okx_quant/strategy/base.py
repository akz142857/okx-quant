"""策略基类：定义信号结构和策略接口"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import pandas as pd


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

    def __init__(self, params: Optional[dict] = None):
        self.params = params or {}

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
