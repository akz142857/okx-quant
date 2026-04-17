"""持仓止损/止盈监控

职责：
- 在每个 tick 更新 trailing stop（最高价 - N×ATR）
- 检测 SL/TP 命中并通知卖出回调
- 不触碰 exchange；仅依赖 RiskManager 中的仓位信息
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

import pandas as pd

from okx_quant.indicators import atr as calc_atr
from okx_quant.risk.manager import RiskManager

logger = logging.getLogger(__name__)


class PositionMonitor:
    def __init__(
        self,
        inst_id: str,
        risk: RiskManager,
        sell_fn: Callable[[str], bool],
        *,
        trailing_atr_mult: float = 2.0,
        initial_highest: float = 0.0,
        on_state_change: Optional[Callable[[], None]] = None,
        sell_cooldown_getter: Optional[Callable[[], float]] = None,
    ):
        self.inst_id = inst_id
        self.risk = risk
        self._sell_fn = sell_fn
        self.trailing_atr_mult = trailing_atr_mult
        self._highest: float = initial_highest
        self._on_state_change = on_state_change
        # 外部卖出冷却时间戳（由 OrderExecutor 拥有），仅读
        self._sell_cooldown_getter = sell_cooldown_getter

    @property
    def highest_since_entry(self) -> float:
        return self._highest

    def on_buy(self, entry_price: float) -> None:
        """买入后重置最高价基准"""
        self._highest = entry_price
        self._mark_dirty()

    def on_sell(self) -> None:
        self._highest = 0.0
        self._mark_dirty()

    def check(self, current_price: float, df: Optional[pd.DataFrame] = None) -> bool:
        """返回 True 表示已触发并平仓"""
        pos = self.risk.get_position(self.inst_id)
        if not pos:
            return False

        # 更新 trailing stop
        if df is not None:
            if current_price > self._highest:
                self._highest = current_price
                self._mark_dirty()

            atr_val = calc_atr(df).iloc[-1]
            trailing_stop = self._highest - self.trailing_atr_mult * atr_val
            if trailing_stop > pos.stop_loss:
                pos.stop_loss = trailing_stop
                logger.debug(
                    "[移动止盈] 最高=%.4f ATR=%.4f 新止损=%.4f",
                    self._highest, atr_val, trailing_stop,
                )

        # 卖出冷却期内跳过
        if self._sell_cooldown_getter is not None and time.time() < self._sell_cooldown_getter():
            return False

        if pos.stop_loss > 0 and current_price <= pos.stop_loss:
            logger.warning("[风控] 止损触发 %.4f <= %.4f", current_price, pos.stop_loss)
            reason = "止损触发（移动止盈）" if self._highest > 0 else "止损触发"
            return self._sell_fn(reason)

        if pos.take_profit > 0 and current_price >= pos.take_profit:
            logger.info("[风控] 止盈触发 %.4f >= %.4f", current_price, pos.take_profit)
            return self._sell_fn("止盈触发")

        return False

    def _mark_dirty(self) -> None:
        if self._on_state_change is not None:
            self._on_state_change()
