"""风控管理器：仓位限制、止损检查、最大回撤保护"""

import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class RiskConfig:
    """风控参数配置"""

    max_position_pct: float = 0.50    # 单笔最大仓位占总资产比例
    stop_loss_pct: float = 0.02       # 默认止损比例（入场价的 2%）
    take_profit_pct: float = 0.04     # 默认止盈比例（入场价的 4%）
    max_drawdown_pct: float = 0.15    # 最大回撤阈值（触发后停止交易）
    max_open_positions: int = 1       # 最大同时持仓数（现货策略通常为 1）
    min_order_usdt: float = 1.0       # 最小下单 USDT 价值（低于此值不下单）
    max_daily_loss_pct: float = 0.05  # 当日最大亏损比例（触发后当日停止交易）


@dataclass
class PositionInfo:
    """持仓信息"""

    inst_id: str
    size: float
    entry_price: float
    stop_loss: float = 0.0
    take_profit: float = 0.0
    unrealized_pnl: float = 0.0


class RiskManager:
    """风控管理器

    实盘执行前调用 `check_order()` 进行风控校验。
    每次 K 线结束后调用 `update_equity()` 更新净值，监控回撤。
    """

    def __init__(self, config: Optional[RiskConfig] = None, initial_equity: float = 0.0):
        self.config = config or RiskConfig()
        self.initial_equity = initial_equity
        self.peak_equity = initial_equity
        self.current_equity = initial_equity
        self.daily_start_equity = initial_equity
        self._positions: dict[str, PositionInfo] = {}
        self._trading_halted = False
        self._halt_reason = ""
        self._lock = threading.Lock()

    # -------------------------------------------------------------------------
    # 仓位管理
    # -------------------------------------------------------------------------

    def add_position(self, pos: PositionInfo):
        with self._lock:
            self._positions[pos.inst_id] = pos
        logger.info("[风控] 记录开仓: %s %.6f @ %.4f", pos.inst_id, pos.size, pos.entry_price)

    def remove_position(self, inst_id: str):
        with self._lock:
            if inst_id in self._positions:
                del self._positions[inst_id]
                logger.info("[风控] 移除持仓: %s", inst_id)

    def has_position(self, inst_id: str) -> bool:
        with self._lock:
            return inst_id in self._positions

    def get_position(self, inst_id: str) -> Optional[PositionInfo]:
        with self._lock:
            return self._positions.get(inst_id)

    @property
    def open_count(self) -> int:
        with self._lock:
            return len(self._positions)

    # -------------------------------------------------------------------------
    # 风控检查
    # -------------------------------------------------------------------------

    def check_order(
        self,
        inst_id: str,
        side: str,
        size_usdt: float,
        price: float,
        current_equity: float,
    ) -> tuple[bool, str]:
        """下单前风控检查

        Returns:
            (allowed, reason) — allowed=False 时附带拒绝原因
        """
        with self._lock:
            if self._trading_halted:
                return False, f"交易已暂停: {self._halt_reason}"

            if side == "buy":
                # 最大持仓数检查
                if len(self._positions) >= self.config.max_open_positions:
                    return False, f"持仓数已达上限 ({self.config.max_open_positions})"

                # 最小下单金额
                if size_usdt < self.config.min_order_usdt:
                    return False, f"下单金额 {size_usdt:.2f} USDT 低于最小值 {self.config.min_order_usdt}"

                # 单笔最大仓位
                max_allowed = current_equity * self.config.max_position_pct
                if size_usdt > max_allowed:
                    return False, (
                        f"下单金额 {size_usdt:.2f} USDT 超过最大仓位限制 {max_allowed:.2f} USDT"
                    )

            elif side == "sell":
                if inst_id not in self._positions:
                    return False, f"无持仓，不能卖出 {inst_id}"

            return True, "通过"

    def calc_position_size(
        self,
        available_usdt: float,
        price: float,
        size_pct: float = 1.0,
    ) -> tuple[float, float]:
        """计算建议下单量

        Args:
            available_usdt: 可用 USDT
            price: 当前价格
            size_pct: 策略建议的仓位比例

        Returns:
            (size_coin, cost_usdt) — 建议买入的币种数量和 USDT 花费
        """
        max_pct = min(size_pct, self.config.max_position_pct)
        cost_usdt = available_usdt * max_pct
        cost_usdt = max(0, min(cost_usdt, available_usdt))
        size_coin = cost_usdt / price if price > 0 else 0
        return size_coin, cost_usdt

    def calc_sl_tp(
        self,
        entry_price: float,
        signal_sl: float = 0.0,
        signal_tp: float = 0.0,
    ) -> tuple[float, float]:
        """计算止损/止盈价格，优先使用策略信号值，否则用默认比例"""
        sl = signal_sl if signal_sl > 0 else entry_price * (1 - self.config.stop_loss_pct)
        tp = signal_tp if signal_tp > 0 else entry_price * (1 + self.config.take_profit_pct)
        return round(sl, 8), round(tp, 8)

    # -------------------------------------------------------------------------
    # 净值/回撤监控
    # -------------------------------------------------------------------------

    def update_equity(self, equity: float):
        """更新当前净值，检测最大回撤"""
        if equity <= 0:
            logger.debug("[风控] 忽略无效净值: %.2f", equity)
            return
        with self._lock:
            self.current_equity = equity
            self.peak_equity = max(self.peak_equity, equity)

            drawdown = (self.peak_equity - equity) / self.peak_equity if self.peak_equity > 0 else 0
            if drawdown >= self.config.max_drawdown_pct and not self._trading_halted:
                self._trading_halted = True
                self._halt_reason = f"最大回撤 {drawdown*100:.1f}% 触发保护，停止交易"
                logger.warning("[风控] %s", self._halt_reason)

    def reset_daily(self, equity: float):
        """每日开盘时重置当日亏损统计"""
        self.daily_start_equity = equity
        # 若之前因当日亏损暂停，重置（最大回撤触发不重置）
        if self._trading_halted and "当日" in self._halt_reason:
            self._trading_halted = False
            self._halt_reason = ""

    @property
    def is_halted(self) -> bool:
        return self._trading_halted

    @property
    def current_drawdown_pct(self) -> float:
        if self.peak_equity <= 0:
            return 0.0
        return (self.peak_equity - self.current_equity) / self.peak_equity * 100

    def status(self) -> dict:
        return {
            "peak_equity": self.peak_equity,
            "current_equity": self.current_equity,
            "drawdown_pct": round(self.current_drawdown_pct, 4),
            "open_positions": self.open_count,
            "trading_halted": self._trading_halted,
            "halt_reason": self._halt_reason,
        }
