"""订单执行器

封装：lotSz 取整、市价下单、冷却计时器、异常分类处理（幽灵仓位识别）。
不管 SL/TP 触发（那是 PositionMonitor 的职责）；不管风控规则（那是 RiskManager）。
"""

from __future__ import annotations

import logging
import math
import time
from typing import Callable, Optional

from okx_quant.exchange import Exchange
from okx_quant.risk.manager import PositionInfo, RiskManager

logger = logging.getLogger(__name__)


class OrderExecutor:
    """单个交易对的买卖执行器"""

    # 下单失败后的冷却时间（秒）
    COOLDOWN_SECONDS = 300

    def __init__(
        self,
        exchange: Exchange,
        inst_id: str,
        risk: RiskManager,
        *,
        buy_fail_until: float = 0.0,
        sell_fail_until: float = 0.0,
        on_buy_success: Optional[Callable[[float, float], None]] = None,
        on_sell_success: Optional[Callable[[PositionInfo, float], None]] = None,
        on_state_change: Optional[Callable[[], None]] = None,
    ):
        self.exchange = exchange
        self.inst_id = inst_id
        self.risk = risk
        self._buy_fail_until = buy_fail_until
        self._sell_fail_until = sell_fail_until
        self._on_buy_success = on_buy_success
        self._on_sell_success = on_sell_success
        self._on_state_change = on_state_change

        # 交易对精度（lot_size / min_size），首次触达时查询
        self._lot_sz: float = 0.0
        self._min_sz: float = 0.0
        self._lot_decimals: int = 0
        self._fetch_instrument_info()

    # ------------------ 外部查询/注入 ------------------

    @property
    def buy_fail_until(self) -> float:
        return self._buy_fail_until

    @property
    def sell_fail_until(self) -> float:
        return self._sell_fail_until

    @property
    def min_size(self) -> float:
        return self._min_sz

    def in_buy_cooldown(self) -> bool:
        return time.time() < self._buy_fail_until

    def in_sell_cooldown(self) -> bool:
        return time.time() < self._sell_fail_until

    # ------------------ 内部 ------------------

    def _fetch_instrument_info(self) -> None:
        try:
            info = self.exchange.get_instrument(self.inst_id)
            self._lot_sz = info.lot_size
            self._min_sz = info.min_size
            if self._lot_sz > 0:
                lot_str = f"{self._lot_sz:.10f}".rstrip("0")
                self._lot_decimals = len(lot_str.split(".")[-1]) if "." in lot_str else 0
            logger.info(
                "[精度] %s  lotSz=%s  minSz=%s",
                self.inst_id, self._lot_sz, self._min_sz,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning("[精度] 获取 %s 交易对信息失败: %s，将使用原始数量下单", self.inst_id, e)

    def round_lot_size(self, size: float) -> float:
        if self._lot_sz > 0:
            size = math.floor(size / self._lot_sz) * self._lot_sz
            size = round(size, self._lot_decimals)
        return size

    def _mark_dirty(self) -> None:
        if self._on_state_change is not None:
            self._on_state_change()

    # ------------------ 买 ------------------

    def buy(self, price: float, size_coin: float, sl: float, tp: float, reason: str) -> bool:
        """执行买入；成功返回 True。失败进冷却，避免反复重试。"""
        size_coin = self.round_lot_size(size_coin)
        if self._min_sz > 0 and size_coin < self._min_sz:
            logger.warning("[下单] 数量 %.8f 低于最小下单量 %s，跳过", size_coin, self._min_sz)
            return False

        logger.info(
            "[下单] BUY %s  数量=%.6f  价格=%.4f  止损=%.4f  止盈=%.4f  原因=%s",
            self.inst_id, size_coin, price, sl, tp, reason,
        )
        try:
            result = self.exchange.place_market_order(
                inst_id=self.inst_id,
                side="buy",
                size=size_coin,
                tgt_ccy="base_ccy",
            )
            logger.info("[下单] 买入成功 ordId=%s", result.ord_id)

            # 登记风控仓位
            self.risk.add_position(PositionInfo(
                inst_id=self.inst_id,
                size=size_coin,
                entry_price=price,
                stop_loss=sl,
                take_profit=tp,
            ))

            if self._on_buy_success is not None:
                self._on_buy_success(price, size_coin)
            self._mark_dirty()
            return True
        except Exception as e:  # noqa: BLE001
            logger.error("[下单] 买入失败: %s", e)
            self._buy_fail_until = time.time() + self.COOLDOWN_SECONDS
            self._mark_dirty()
            logger.info("[下单] 买入失败冷却 %ds", self.COOLDOWN_SECONDS)
            return False

    # ------------------ 卖 ------------------

    def sell(self, last_price: float, reason: str) -> bool:
        """全仓卖出；成功返回 True

        关键修复：以交易所**实际可用余额**为准下单，不能用 pos.size。
        原因：买入 market 单以 base_ccy 计时，OKX 会从 base_ccy 扣手续费
        （约 0.1%），实际到账 < 下单数量。直接卖 pos.size 会触发 51008。
        """
        pos = self.risk.get_position(self.inst_id)
        if not pos:
            logger.warning("[下单] 无持仓，跳过卖出")
            return False

        # 查实际可用余额并取 min（通常小于 pos.size，因为手续费扣减）
        base_ccy = self.inst_id.split("-")[0]
        try:
            snap = self.exchange.get_balance()
            holding = snap.holding(base_ccy)
            exchange_available = holding.available if holding else 0.0
        except Exception as e:  # noqa: BLE001
            logger.warning("[下单] 查询实际余额失败: %s；退化为 pos.size", e)
            exchange_available = pos.size

        effective_size = min(pos.size, exchange_available)
        sell_size = self.round_lot_size(effective_size)

        if sell_size <= 0 or (self._min_sz > 0 and sell_size < self._min_sz):
            # 幽灵仓位：实际余额不足最小单量，交易所侧无法成交
            logger.warning(
                "[下单] 实际可用 %.8f / round %.8f 不足 minSz %.8f，清除幽灵仓位 %s",
                exchange_available, sell_size, self._min_sz, self.inst_id,
            )
            self.risk.remove_position(self.inst_id)
            self._mark_dirty()
            return False

        logger.info(
            "[下单] SELL %s  数量=%.6f（pos.size=%.6f, exch_avail=%.6f）  原因=%s",
            self.inst_id, sell_size, pos.size, exchange_available, reason,
        )
        try:
            result = self.exchange.place_market_order(
                inst_id=self.inst_id,
                side="sell",
                size=sell_size,
            )
            logger.info("[下单] 卖出成功 ordId=%s", result.ord_id)
            self.risk.remove_position(self.inst_id)
            if self._on_sell_success is not None:
                self._on_sell_success(pos, last_price)
            self._mark_dirty()
            return True
        except Exception as e:  # noqa: BLE001
            logger.error("[下单] 卖出失败: %s", e)
            if "51008" in str(e):
                logger.warning("[下单] 余额不足，检查实际持仓并清理...")
                self._cleanup_phantom_position()
            else:
                self._sell_fail_until = time.time() + self.COOLDOWN_SECONDS
                logger.info("[下单] 卖出失败冷却 %ds", self.COOLDOWN_SECONDS)
            self._mark_dirty()
            return False

    # ------------------ 异常清理 ------------------

    def _cleanup_phantom_position(self) -> None:
        """实际余额 < 最小下单量 → 清除风控中的幽灵仓位

        所有改变内部状态的路径都必须显式调用 ``_mark_dirty()``，
        不依赖调用方在外层补救。
        """
        base_ccy = self.inst_id.split("-")[0]
        try:
            snap = self.exchange.get_balance()
            holding = snap.holding(base_ccy)
            actual_bal = holding.available if holding else 0.0
            rounded = self.round_lot_size(actual_bal)
            if rounded <= 0 or (self._min_sz > 0 and rounded < self._min_sz):
                logger.warning(
                    "[清理] %s 实际可用余额 %.8f，取整后 %.8f 不足最小下单量，清除幽灵仓位",
                    self.inst_id, actual_bal, rounded,
                )
                self.risk.remove_position(self.inst_id)
                self._mark_dirty()
            else:
                self._sell_fail_until = time.time() + self.COOLDOWN_SECONDS
                logger.info("[下单] 实际余额 %.8f 足够，冷却 %ds 后重试", actual_bal, self.COOLDOWN_SECONDS)
                self._mark_dirty()
        except Exception as ex:  # noqa: BLE001
            logger.error("[清理] 查询 %s 余额失败: %s，冷却 %ds", base_ccy, ex, self.COOLDOWN_SECONDS)
            self._sell_fail_until = time.time() + self.COOLDOWN_SECONDS
            self._mark_dirty()
