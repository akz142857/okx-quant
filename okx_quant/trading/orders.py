"""订单执行器

封装：lotSz 取整、市价下单、冷却计时器、异常分类处理（幽灵仓位识别）。
不管 SL/TP 触发（那是 PositionMonitor 的职责）；不管风控规则（那是 RiskManager）。
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable
from decimal import Decimal
from typing import TYPE_CHECKING

from okx_quant.domain.orders import OrderState, generate_client_order_id, to_decimal
from okx_quant.exchange import Exchange
from okx_quant.risk.manager import PositionInfo, RiskManager

if TYPE_CHECKING:
    from okx_quant.application.runtime import ProductionRuntime

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
        on_buy_success: Callable[[float, float], None] | None = None,
        on_sell_success: Callable[[PositionInfo, float], None] | None = None,
        on_state_change: Callable[[], None] | None = None,
        production_runtime: ProductionRuntime | None = None,
    ):
        self.exchange = exchange
        self.inst_id = inst_id
        self.risk = risk
        self._buy_fail_until = buy_fail_until
        self._sell_fail_until = sell_fail_until
        self._on_buy_success = on_buy_success
        self._on_sell_success = on_sell_success
        self._on_state_change = on_state_change
        self._production = production_runtime
        if self._production is not None:
            self._production.register_risk_manager(self.risk)

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
            # 旧策略层仍以 float 计算信号；交易所权威事实在 adapter/ledger
            # 内保持 Decimal，只有进入该兼容层时显式降精度。
            self._lot_sz = float(info.lot_size)
            self._min_sz = float(info.min_size)
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

    def _assert_legacy_write_is_test_only(self) -> None:
        """无 durable coordinator 时只允许同步成交的内存测试交易所。

        真实 OKX 的 POST 返回仅是 ACK。兼容路径既没有持久化 intent，也没有
        UNKNOWN resolver，无法在响应丢失后安全判断是否应重发，因此必须在
        socket write 前 fail closed。FakeExchange 仅用于本地单元测试，并且
        下方仍会严格验证其返回的累计成交事实。
        """
        from okx_quant.exchange.fake import FakeExchange

        if not isinstance(self.exchange, FakeExchange):
            raise RuntimeError(
                "无 production coordinator 禁止交易写；"
                "该路径缺少 durable clOrdId/UNKNOWN resolver"
            )

    @staticmethod
    def _confirmed_full_fill(result, requested_size: Decimal) -> tuple[Decimal, Decimal]:
        state = str(getattr(result, "state", "") or "").lower()
        filled = to_decimal(getattr(result, "acc_fill_size", 0))
        fill_price = to_decimal(getattr(result, "fill_price", 0))
        if (
            state != OrderState.FILLED.value
            or filled < requested_size
        ):
            raise RuntimeError(
                "兼容测试交易所未返回可验证的完整 FILLED 事实；"
                f"state={state or 'ack'} filled={filled}"
            )
        return filled, fill_price

    # ------------------ 买 ------------------

    def buy(
        self,
        price: float,
        size_coin: float,
        sl: float,
        tp: float,
        reason: str,
        decision_id: str = "",
    ) -> bool:
        """执行买入；成功返回 True。失败进冷却，避免反复重试。"""
        size_coin = self.round_lot_size(size_coin)
        # 取整后可能为 0（如计算金额 < price*lotSz）；独立于 minSz 显式拦截，
        # 避免在 instrument 信息获取失败（_min_sz=0）时把 size=0 的单发给交易所。
        if size_coin <= 0:
            logger.warning("[下单] 取整后数量为 0，跳过买入")
            return False
        if self._min_sz > 0 and size_coin < self._min_sz:
            logger.warning("[下单] 数量 %.8f 低于最小下单量 %s，跳过", size_coin, self._min_sz)
            return False

        logger.info(
            "[下单] BUY %s  数量=%.6f  价格=%.4f  止损=%.4f  止盈=%.4f  原因=%s",
            self.inst_id, size_coin, price, sl, tp, reason,
        )
        try:
            if self._production is not None:
                from okx_quant.application.execution import ExecutionRequest

                intent = self._production.execution.submit(ExecutionRequest(
                    inst_id=self.inst_id,
                    side="buy",
                    base_qty=Decimal(str(size_coin)),
                    reserved_quote=Decimal(str(size_coin * price)),
                    decision_id=decision_id,
                    stop_loss=Decimal(str(sl)),
                    take_profit=Decimal(str(tp)),
                ))
                if (
                    intent.state in {
                        OrderState.REJECTED,
                        OrderState.CANCELED,
                        OrderState.MANUAL_REVIEW,
                    }
                    and intent.acc_fill_qty <= 0
                ):
                    logger.error(
                        "[下单] 买入未接受 state=%s: %s",
                        intent.state.value,
                        intent.last_error_message,
                    )
                    return False
                # UNKNOWN/live 仍占用持久化风险预留，绝不能由调用方释放
                # 后重发。实际成交由 fill bridge 更新旧策略层仓位视图。
                if intent.acc_fill_qty <= 0:
                    logger.warning(
                        "[下单] 买入状态=%s，等待 WS/REST 解析，不重试",
                        intent.state.value,
                    )
                    self._mark_dirty()
                    return True
                fill_price = float(intent.avg_fill_px)
                durable = self._production.journal.get_position(self.inst_id)
                fill_size = (
                    float(Decimal(durable["base_qty"])) if durable else 0.0
                )
                if fill_size <= 0:
                    logger.error(
                        "[下单] 买入成交后仓位已由紧急路径退出，不登记本地仓位"
                    )
                    self._mark_dirty()
                    return False
                ord_id = intent.exchange_ord_id
            else:
                self._assert_legacy_write_is_test_only()
                requested_size = Decimal(str(size_coin))
                result = self.exchange.place_market_order(
                    inst_id=self.inst_id,
                    side="buy",
                    size=requested_size,
                    tgt_ccy="base_ccy",
                    cl_ord_id=generate_client_order_id("buy"),
                )
                confirmed_size, confirmed_price = self._confirmed_full_fill(
                    result,
                    requested_size,
                )
                fill_price = float(confirmed_price)
                fill_size = float(confirmed_size)
                ord_id = result.ord_id
            logger.info("[下单] 买入成功 ordId=%s", ord_id)

            # 优先用真实成交均价做入场价；拿不到则退化为信号价。
            # 成交价与信号价不一致时，按比例平移止损止盈，保持风控配置意图的
            # 百分比缓冲（否则市价滑点会让实际止损幅度偏离设定值）。
            entry_price = fill_price if fill_price > 0 else price
            if entry_price > 0 and price > 0 and entry_price != price:
                ratio = entry_price / price
                sl = round(sl * ratio, 8) if sl > 0 else sl
                tp = round(tp * ratio, 8) if tp > 0 else tp

            if self._production is None:
                # legacy 路径没有 durable fill bridge，需要在这里登记。
                self.risk.add_position(PositionInfo(
                    inst_id=self.inst_id,
                    size=fill_size,
                    entry_price=entry_price,
                    stop_loss=sl,
                    take_profit=tp,
                ))

            if self._on_buy_success is not None:
                self._on_buy_success(entry_price, fill_size)
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

        if self._production is not None:
            try:
                intent = self._production.exit.exit_position(
                    self.inst_id, reason
                )
                if intent is None or intent.state is not OrderState.FILLED:
                    logger.warning(
                        "[下单] 退出尚未形成确定成交，等待交易所事实"
                    )
                    return False
                logger.info(
                    "[下单] 卖出成功 ordId=%s", intent.exchange_ord_id
                )
                self.risk.remove_position(self.inst_id)
                if self._on_sell_success is not None:
                    self._on_sell_success(pos, last_price)
                self._mark_dirty()
                return True
            except Exception as e:  # noqa: BLE001
                logger.error("[下单] 生产退出失败: %s", e)
                self._sell_fail_until = time.time() + self.COOLDOWN_SECONDS
                self._mark_dirty()
                return False

        # 查实际可用余额并取 min（通常小于 pos.size，因为手续费扣减）
        base_ccy = self.inst_id.split("-")[0]
        try:
            snap = self.exchange.get_balance()
            holding = snap.holding(base_ccy)
            exchange_available = float(holding.available) if holding else 0.0
            exchange_balance = float(holding.balance) if holding else 0.0
        except Exception as e:  # noqa: BLE001
            logger.warning("[下单] 查询实际余额失败: %s；退化为 pos.size", e)
            exchange_available = pos.size
            exchange_balance = pos.size

        effective_size = min(pos.size, exchange_available)
        sell_size = self.round_lot_size(effective_size)

        if sell_size <= 0 or (self._min_sz > 0 and sell_size < self._min_sz):
            total_rounded = self.round_lot_size(exchange_balance)
            if total_rounded > 0 and (
                self._min_sz <= 0 or total_rounded >= self._min_sz
            ):
                # 总余额存在但 available 不足，通常表示被未完成订单冻结。
                # 不能把它当作粉尘/幽灵仓位清除，否则会失去真实风险监控。
                self._sell_fail_until = time.time() + self.COOLDOWN_SECONDS
                logger.warning(
                    "[下单] %s 总余额 %.8f 仍存在但可用仅 %.8f，可能被挂单冻结；"
                    "保留仓位并冷却 %ds",
                    self.inst_id,
                    exchange_balance,
                    exchange_available,
                    self.COOLDOWN_SECONDS,
                )
            else:
                # 幽灵仓位：总余额本身也不足最小单量，交易所侧无法成交
                logger.warning(
                    "[下单] 实际余额 %.8f / 可用 %.8f 不足 minSz %.8f，清除幽灵仓位 %s",
                    exchange_balance,
                    exchange_available,
                    self._min_sz,
                    self.inst_id,
                )
                self.risk.remove_position(self.inst_id)
            self._mark_dirty()
            return False

        logger.info(
            "[下单] SELL %s  数量=%.6f（pos.size=%.6f, exch_avail=%.6f）  原因=%s",
            self.inst_id, sell_size, pos.size, exchange_available, reason,
        )
        try:
            self._assert_legacy_write_is_test_only()
            requested_size = Decimal(str(sell_size))
            result = self.exchange.place_market_order(
                inst_id=self.inst_id,
                side="sell",
                size=requested_size,
                cl_ord_id=generate_client_order_id("sell"),
            )
            self._confirmed_full_fill(result, requested_size)
            ord_id = result.ord_id
            logger.info("[下单] 卖出成功 ordId=%s", ord_id)
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
            actual_bal = float(holding.available) if holding else 0.0
            total_bal = float(holding.balance) if holding else 0.0
            rounded = self.round_lot_size(actual_bal)
            if rounded <= 0 or (self._min_sz > 0 and rounded < self._min_sz):
                total_rounded = self.round_lot_size(total_bal)
                if total_rounded > 0 and (
                    self._min_sz <= 0 or total_rounded >= self._min_sz
                ):
                    self._sell_fail_until = time.time() + self.COOLDOWN_SECONDS
                    logger.warning(
                        "[清理] %s 总余额 %.8f 仍存在但可用仅 %.8f，可能被挂单冻结；"
                        "保留仓位并冷却 %ds",
                        self.inst_id,
                        total_bal,
                        actual_bal,
                        self.COOLDOWN_SECONDS,
                    )
                    self._mark_dirty()
                else:
                    logger.warning(
                        "[清理] %s 总余额 %.8f / 可用 %.8f 不足最小下单量，清除幽灵仓位",
                        self.inst_id,
                        total_bal,
                        actual_bal,
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
