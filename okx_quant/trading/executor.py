"""实盘交易执行器：策略信号 → 下单 → 风控 → 监控

LiveTrader 只负责主循环和协调；具体职责拆分到：
- OrderExecutor       下单 + 冷却 + 精度取整
- PositionMonitor     SL/TP + trailing stop
- AccountSnapshot     余额缓存
- DecisionLogger      决策 CSV
- position_restore    账户持仓恢复
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Optional

from okx_quant.client.rest import OKXRestClient
from okx_quant.exchange import Exchange, OKXExchange
from okx_quant.risk.manager import RiskConfig, RiskManager
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from okx_quant.trading.account import AccountSnapshot
from okx_quant.trading.decision_log import DecisionLogger
from okx_quant.trading.orders import OrderExecutor
from okx_quant.trading.position_monitor import PositionMonitor
from okx_quant.trading.position_restore import restore_to_risk
from okx_quant.trading.state import StateStore, TraderState
from okx_quant.utils.timeout import run_with_timeout, TimeoutError as SignalTimeout

logger = logging.getLogger(__name__)


class LiveTrader:
    """实盘交易执行器

    每隔 ``interval_seconds`` 秒拉取最新 K 线，调用策略生成信号，
    经风控校验后委派给 OrderExecutor 执行买卖。
    """

    def __init__(
        self,
        client: Optional[OKXRestClient] = None,
        strategy: Optional[BaseStrategy] = None,
        inst_id: str = "",
        risk_config: Optional[RiskConfig] = None,
        quote_ccy: str = "USDT",
        dashboard: bool = False,
        simulated: bool = True,
        risk_manager: Optional[RiskManager] = None,
        signal_timeout_s: float = 20.0,
        state_store: Optional[StateStore] = None,
        *,
        exchange: Optional[Exchange] = None,
    ):
        if exchange is None and client is None:
            raise ValueError("LiveTrader 需要 exchange 或 client 至少一个")
        if strategy is None:
            raise ValueError("LiveTrader 需要 strategy")
        if not inst_id:
            raise ValueError("LiveTrader 需要 inst_id")

        # Exchange 优先；未提供则把旧 client 包一层 OKXExchange（向后兼容）
        self.exchange: Exchange = exchange if exchange is not None else OKXExchange(
            client, quote_ccy=quote_ccy,
        )
        self.client: Optional[OKXRestClient] = (
            client if client is not None
            else getattr(self.exchange, "client", None)
        )
        self.strategy = strategy
        self.inst_id = inst_id
        self.quote_ccy = quote_ccy
        self.risk = risk_manager if risk_manager is not None else RiskManager(risk_config)
        self._external_risk = risk_manager is not None
        self._running = False
        self._stop_event = threading.Event()
        self._simulated = simulated
        self._signal_timeout_s = signal_timeout_s

        # 状态持久化（跨进程 / 崩溃恢复）
        self._state_store = state_store if state_store is not None else StateStore()
        self._state = self._state_store.load(inst_id) or TraderState(inst_id=inst_id)

        # 决策日志
        self._decision_logger = DecisionLogger(inst_id)

        # Dashboard 相关（部分字段由持久化状态恢复）
        self._use_dashboard = dashboard
        self._dashboard: Optional["Dashboard"] = None
        self._last_price: float = 0.0
        self._last_signal_name: str = self._state.last_signal_name
        self._last_signal_reason: str = self._state.last_signal_reason
        self._last_logged_signal: tuple = self._state.last_logged_signal
        self._last_signal_extra: dict = {}
        self._trade_log: deque = deque(maxlen=20)
        self._tick_count: int = self._state.tick_count
        self._start_time: datetime = datetime.now()
        self._consecutive_errors: int = 0
        self._max_backoff: int = 300  # 最大退避 5 分钟

        # 余额缓存
        self._account = AccountSnapshot(self.exchange, ttl_seconds=300)

        # 订单执行器
        self._orders = OrderExecutor(
            exchange=self.exchange,
            inst_id=inst_id,
            risk=self.risk,
            buy_fail_until=self._state.buy_fail_until,
            sell_fail_until=self._state.sell_fail_until,
            on_buy_success=self._on_buy_success,
            on_sell_success=self._on_sell_success,
            on_state_change=self._mark_state_dirty,
        )

        # 持仓监控
        self._monitor = PositionMonitor(
            inst_id=inst_id,
            risk=self.risk,
            sell_fn=self._sell_for_monitor,
            trailing_atr_mult=2.0,
            initial_highest=self._state.highest_since_entry,
            on_state_change=self._mark_state_dirty,
            sell_cooldown_getter=lambda: self._orders.sell_fail_until,
        )

        # dirty flag：仅在发生变化时落盘
        self._state_dirty: bool = False

    # ------------------------------------------------------------------
    # 账户查询（保留公共 API 供 Supervisor dashboard 使用）
    # ------------------------------------------------------------------

    def get_equity(self, force: bool = False) -> float:
        return self._account.total_equity(force=force)

    def get_available_usdt(self, force: bool = False) -> float:
        return self._account.available_quote(force=force)

    # ------------------------------------------------------------------
    # 回调：由 OrderExecutor / PositionMonitor 触发
    # ------------------------------------------------------------------

    def _on_buy_success(self, price: float, size_coin: float) -> None:
        self._account.invalidate()
        self._monitor.on_buy(price)

        coin = self.inst_id.split("-")[0]
        self._trade_log.append({
            "time": datetime.now().strftime("%m-%d %H:%M"),
            "side": "BUY",
            "price": price,
            "size": size_coin,
            "coin": coin,
            "pnl": "",
        })
        if self._dashboard:
            self._dashboard.log_event(f"BUY {size_coin:.4f} {coin} @ ${price:.4f}")

    def _on_sell_success(self, pos, last_price: float) -> None:
        self._account.invalidate()
        self._monitor.on_sell()

        pnl = (last_price - pos.entry_price) * pos.size if last_price > 0 else 0
        pnl_pct = (last_price / pos.entry_price - 1) * 100 if pos.entry_price > 0 else 0
        pnl_str = f"{pnl:+.2f} ({pnl_pct:+.1f}%)"

        coin = self.inst_id.split("-")[0]
        self._trade_log.append({
            "time": datetime.now().strftime("%m-%d %H:%M"),
            "side": "SELL",
            "price": last_price,
            "size": pos.size,
            "coin": coin,
            "pnl": pnl_str,
        })
        if self._dashboard:
            self._dashboard.log_event(
                f"SELL {pos.size:.4f} {coin} @ ${last_price:.4f}  盈亏: {pnl_str}"
            )

    def _sell_for_monitor(self, reason: str) -> bool:
        """PositionMonitor 触发 SL/TP 时的卖出入口"""
        return self._orders.sell(self._last_price, reason)

    def _mark_state_dirty(self) -> None:
        self._state_dirty = True

    # ------------------------------------------------------------------
    # 状态持久化
    # ------------------------------------------------------------------

    def _persist_state(self, force: bool = False) -> None:
        snapshot = (
            self._monitor.highest_since_entry,
            self._orders.buy_fail_until,
            self._orders.sell_fail_until,
            self._last_signal_name,
            self._last_signal_reason,
            tuple(self._last_logged_signal),
            self._tick_count,
        )
        prev_snapshot = (
            self._state.highest_since_entry,
            self._state.buy_fail_until,
            self._state.sell_fail_until,
            self._state.last_signal_name,
            self._state.last_signal_reason,
            self._state.last_logged_signal,
            self._state.tick_count,
        )
        if not force and snapshot == prev_snapshot and not self._state_dirty:
            return

        (self._state.highest_since_entry,
         self._state.buy_fail_until,
         self._state.sell_fail_until,
         self._state.last_signal_name,
         self._state.last_signal_reason,
         self._state.last_logged_signal,
         self._state.tick_count) = snapshot
        self._state.inst_id = self.inst_id
        self._state.last_update_ts = time.time()
        self._state_store.save(self._state)
        self._state_dirty = False

    # ------------------------------------------------------------------
    # 已有持仓恢复
    # ------------------------------------------------------------------

    def _restore_existing_position(self) -> None:
        restore_to_risk(self.exchange, self.risk, [self.inst_id], quote_ccy=self.quote_ccy)

    # ------------------------------------------------------------------
    # Dashboard 状态构建
    # ------------------------------------------------------------------

    def _build_dashboard_state(
        self, bar: str, equity: float, available: float, interval_seconds: int, countdown: int,
    ):
        from okx_quant.cli.dashboard import DashboardState, TradeRecord

        pos = self.risk.get_position(self.inst_id)
        coin = self.inst_id.split("-")[0]

        position_pnl = 0.0
        position_pnl_pct = 0.0
        if pos and pos.entry_price > 0 and self._last_price > 0:
            position_pnl = (self._last_price - pos.entry_price) * pos.size
            position_pnl_pct = (self._last_price / pos.entry_price - 1) * 100

        account_pnl = equity - self.risk.initial_equity
        account_pnl_pct = (equity / self.risk.initial_equity - 1) * 100 if self.risk.initial_equity > 0 else 0

        trades = [
            TradeRecord(
                time=t["time"], side=t["side"], price=t["price"],
                size=t["size"], coin=t["coin"], pnl=t.get("pnl", ""),
            )
            for t in list(self._trade_log)[-5:]
        ]

        return DashboardState(
            inst_id=self.inst_id,
            strategy_name=self.strategy.name,
            bar=bar,
            simulated=self._simulated,
            start_time=self._start_time,
            equity=equity,
            available=available,
            account_pnl=account_pnl,
            account_pnl_pct=account_pnl_pct,
            position_size=pos.size if pos else 0.0,
            position_coin=coin,
            entry_price=pos.entry_price if pos else 0.0,
            current_price=self._last_price,
            position_pnl=position_pnl,
            position_pnl_pct=position_pnl_pct,
            stop_loss=pos.stop_loss if pos else 0.0,
            take_profit=pos.take_profit if pos else 0.0,
            drawdown_pct=self.risk.current_drawdown_pct,
            max_drawdown_pct=self.risk.config.max_drawdown_pct * 100,
            open_positions=self.risk.open_count,
            max_positions=self.risk.config.max_open_positions,
            risk_halted=self.risk.is_halted,
            signal_name=self._last_signal_name,
            signal_reason=self._last_signal_reason,
            signal_time=datetime.now().strftime("%H:%M:%S"),
            indicators=self._last_signal_extra,
            recent_trades=trades,
            countdown=countdown,
            tick_count=self._tick_count,
            last_update=datetime.now().strftime("%H:%M:%S"),
        )

    def get_worker_state(self) -> dict:
        """返回当前 worker 状态快照，供 MultiDashboard 渲染"""
        pos = self.risk.get_position(self.inst_id)
        coin = self.inst_id.split("-")[0]

        position_pnl_pct = 0.0
        if pos and pos.entry_price > 0 and self._last_price > 0:
            position_pnl_pct = (self._last_price / pos.entry_price - 1) * 100

        return {
            "inst_id": self.inst_id,
            "strategy_name": self.strategy.name,
            "last_price": self._last_price,
            "signal_name": self._last_signal_name,
            "signal_reason": self._last_signal_reason,
            "position": pos,
            "position_coin": coin,
            "position_pnl_pct": position_pnl_pct,
            "recent_trades": list(self._trade_log)[-5:],
            "tick_count": self._tick_count,
            "indicators": dict(self._last_signal_extra),
        }

    # ------------------------------------------------------------------
    # 主循环
    # ------------------------------------------------------------------

    def run(self, bar: str = "1H", lookback: int = 100, interval_seconds: int = 60) -> None:
        self._running = True
        self._start_time = datetime.now()
        logger.info("启动实盘交易: %s  策略=%s  周期=%s", self.inst_id, self.strategy.name, bar)

        # 初始化风控净值（外部共享 risk_manager 由 Supervisor 统一初始化）
        if not self._external_risk:
            equity = self.get_equity(force=True)
            self.risk.initialize(equity)
            logger.info("当前账户权益: %.2f USDT", equity)
            self._restore_existing_position()

        if self._use_dashboard:
            from okx_quant.cli.dashboard import Dashboard
            self._dashboard = Dashboard()
            self._dashboard.log_event(
                f"启动实盘交易 {self.inst_id} {self.strategy.name} {bar}"
            )
            for handler in logging.getLogger().handlers:
                if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                    handler.setLevel(logging.WARNING)

        # 以 context manager 管理决策日志：任何异常都会关闭文件句柄
        with self._decision_logger:
            while self._running:
                try:
                    self._tick_count += 1
                    self._tick(bar, lookback)
                    self._consecutive_errors = 0
                except KeyboardInterrupt:
                    logger.info("收到停止信号，退出...")
                    self._running = False
                    break
                except Exception as e:  # noqa: BLE001
                    self._consecutive_errors += 1
                    backoff = min(
                        interval_seconds * (2 ** self._consecutive_errors),
                        self._max_backoff,
                    )
                    logger.error(
                        "轮询异常 (连续第%d次): %s — %ds 后重试",
                        self._consecutive_errors, e, backoff,
                        exc_info=(self._consecutive_errors == 1),
                    )
                    if self._running:
                        self._stop_event.wait(timeout=backoff)
                    continue

                if self._running:
                    if self._dashboard:
                        self._countdown_with_dashboard(bar, interval_seconds)
                    else:
                        logger.debug("等待 %ds...", interval_seconds)
                        self._stop_event.wait(timeout=interval_seconds)

    def _countdown_with_dashboard(self, bar: str, interval_seconds: int) -> None:
        equity = self.risk.current_equity
        available = self.get_available_usdt()
        for remaining in range(interval_seconds, 0, -1):
            if not self._running or self._stop_event.is_set():
                break
            try:
                state = self._build_dashboard_state(bar, equity, available, interval_seconds, remaining)
                self._dashboard.render(state)
                self._stop_event.wait(timeout=1)
            except KeyboardInterrupt:
                self._running = False
                break

    def _tick(self, bar: str, lookback: int) -> None:
        df = self.exchange.get_candles(self.inst_id, bar=bar, limit=lookback)
        if df.empty:
            logger.warning("K 线数据为空，跳过本次")
            return

        current_price = df["close"].iloc[-1]
        self._last_price = current_price

        equity = self.get_equity()
        self.risk.update_equity(equity)

        if self.risk.is_halted:
            logger.warning("[风控] %s，跳过交易", self.risk.halt_reason)
            return

        # 止损/止盈检查（可能触发 sell）
        if self._monitor.check(current_price, df):
            self._persist_state()
            return

        # 生成策略信号（带硬超时；超时则视为 HOLD，保护主循环）
        try:
            signal = run_with_timeout(
                self.strategy.generate_signal,
                self._signal_timeout_s,
                df,
                self.inst_id,
            )
        except SignalTimeout:
            logger.warning(
                "[信号] %s 策略调用超时 (>%.1fs)，本轮视为 HOLD",
                self.inst_id, self._signal_timeout_s,
            )
            signal = Signal(
                signal=SignalType.HOLD,
                inst_id=self.inst_id,
                price=current_price,
                reason=f"策略调用超时 (>{self._signal_timeout_s:.0f}s)",
            )
        except Exception as e:  # noqa: BLE001
            logger.error("[信号] %s 策略异常: %s", self.inst_id, e, exc_info=True)
            signal = Signal(
                signal=SignalType.HOLD,
                inst_id=self.inst_id,
                price=current_price,
                reason=f"策略异常: {e}",
            )

        self._last_signal_name = signal.signal.value.upper()
        self._last_signal_reason = signal.reason
        self._last_signal_extra = signal.extra or {}

        # 信号 reason 变化时记录日志（所有类型统一去重）
        sig_key = (signal.signal.value, signal.reason)
        if sig_key != self._last_logged_signal:
            logger.info(
                "[信号] %s | %s | %s | 价格=%.4f",
                self.inst_id, signal.signal.value.upper(), signal.reason, current_price,
            )
            self._last_logged_signal = sig_key

        # 记录决策日志
        candle_ts = df["ts"].iloc[-1]
        self._decision_logger.log(signal, candle_ts)

        # 执行信号
        self._dispatch_signal(signal, current_price, equity)

        # 本轮结束后持久化一次状态
        self._persist_state()

    def _dispatch_signal(self, signal: Signal, current_price: float, equity: float) -> None:
        if signal.is_buy and not self.risk.has_position(self.inst_id):
            if self._orders.in_buy_cooldown():
                remaining = int(self._orders.buy_fail_until - time.time())
                logger.debug("[下单] 买入冷却中，剩余 %d 秒", remaining)
                return

            available = self.get_available_usdt()
            size_coin, cost_usdt = self.risk.calc_position_size(
                available, current_price, signal.size_pct,
            )

            allowed, msg = self.risk.check_order(
                self.inst_id, "buy", cost_usdt, current_price, equity,
            )
            if not allowed:
                logger.warning("[风控] 买入被拒: %s", msg)
                return

            sl, tp = self.risk.calc_sl_tp(current_price, signal.stop_loss, signal.take_profit)
            self._orders.buy(current_price, size_coin, sl, tp, signal.reason)

        elif signal.is_sell and not self.risk.has_position(self.inst_id):
            logger.debug("[信号] SELL 忽略: 当前无持仓")

        elif signal.is_sell:
            if self._orders.in_sell_cooldown():
                remaining = int(self._orders.sell_fail_until - time.time())
                logger.debug("[下单] 卖出冷却中，剩余 %d 秒", remaining)
                return

            allowed, msg = self.risk.check_order(
                self.inst_id, "sell", 0, current_price, equity,
            )
            if not allowed:
                logger.warning("[风控] 卖出被拒: %s", msg)
                return
            self._orders.sell(current_price, signal.reason)

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        # run() 内的 with self._decision_logger 会在退出时关闭文件；
        # 此处再显式 close() 幂等，以应对未经 run() 启动就直接 stop() 的场景
        self._decision_logger.close()
        try:
            self._persist_state(force=True)
        except Exception as e:  # noqa: BLE001
            logger.warning("[状态] 停止时保存失败: %s", e)
        logger.info("实盘交易已停止")
