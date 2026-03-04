"""实盘交易执行器：策略信号 → 下单 → 风控 → 监控"""

import csv
import logging
import math
import os
import threading
import time
from datetime import datetime
from typing import Optional

import pandas as pd

from okx_quant.client.rest import OKXRestClient
from okx_quant.data.market import MarketDataFetcher
from okx_quant.risk.manager import RiskManager, RiskConfig, PositionInfo
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType

logger = logging.getLogger(__name__)


class DecisionLogger:
    """CSV 决策日志记录器

    每根 K 线 + 信号类型只记录一次（去重），写入后立即 flush。
    文件路径: logs/decisions_{inst_id}_{date}.csv
    """

    _BASE_COLUMNS = [
        "timestamp", "inst_id", "signal", "price", "reason",
        "stop_loss", "take_profit", "size_pct",
    ]

    def __init__(self, inst_id: str, log_dir: str = "logs"):
        self._inst_id = inst_id
        self._log_dir = log_dir
        self._seen: set[tuple] = set()  # (candle_ts, signal_type)
        self._file = None
        self._writer: Optional[csv.writer] = None
        self._header_written = False
        self._current_columns: list[str] = []

    def _ensure_file(self, extra_keys: list[str]):
        """按需创建/打开 CSV 文件并写表头"""
        columns = self._BASE_COLUMNS + sorted(extra_keys)
        if self._file is not None and columns == self._current_columns:
            return

        # 关闭旧文件（日期切换或列变化时）
        if self._file is not None:
            self._file.close()

        os.makedirs(self._log_dir, exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d")
        safe_id = self._inst_id.replace("/", "-")
        path = os.path.join(self._log_dir, f"decisions_{safe_id}_{date_str}.csv")

        file_exists = os.path.isfile(path) and os.path.getsize(path) > 0
        self._file = open(path, "a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._file)
        self._current_columns = columns

        if not file_exists:
            self._writer.writerow(columns)
            self._file.flush()

    def log(self, signal: Signal, candle_ts) -> bool:
        """记录一条决策日志，返回是否写入（False = 去重跳过）"""
        key = (candle_ts, signal.signal.value)
        if key in self._seen:
            return False
        self._seen.add(key)

        extra = signal.extra or {}
        extra_keys = [k for k in extra if k not in self._BASE_COLUMNS]
        self._ensure_file(extra_keys)

        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            signal.inst_id,
            signal.signal.value.upper(),
            signal.price,
            signal.reason,
            signal.stop_loss,
            signal.take_profit,
            signal.size_pct,
        ]
        for col in sorted(extra_keys):
            row.append(extra.get(col, ""))

        self._writer.writerow(row)
        self._file.flush()
        return True

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None
            self._writer = None


class LiveTrader:
    """实盘交易执行器

    每隔 `interval_seconds` 秒拉取最新 K 线，调用策略生成信号，
    经风控校验后执行买卖。

    用法::

        client = OKXRestClient(api_key=..., secret_key=..., passphrase=..., simulated=True)
        risk_config = RiskConfig(max_position_pct=0.1, stop_loss_pct=0.02)
        trader = LiveTrader(client, strategy, inst_id="BTC-USDT", risk_config=risk_config)
        trader.run(bar="1H", lookback=100, interval_seconds=60)
    """

    def __init__(
        self,
        client: OKXRestClient,
        strategy: BaseStrategy,
        inst_id: str,
        risk_config: Optional[RiskConfig] = None,
        quote_ccy: str = "USDT",
        dashboard: bool = False,
        simulated: bool = True,
        risk_manager: Optional[RiskManager] = None,
    ):
        self.client = client
        self.strategy = strategy
        self.inst_id = inst_id
        self.quote_ccy = quote_ccy
        self.fetcher = MarketDataFetcher(client)
        self.risk = risk_manager if risk_manager is not None else RiskManager(risk_config)
        self._external_risk = risk_manager is not None
        self._running = False
        self._stop_event = threading.Event()
        self._simulated = simulated

        # 决策日志
        self._decision_logger = DecisionLogger(inst_id)

        # Dashboard 相关
        self._use_dashboard = dashboard
        self._dashboard: Optional["Dashboard"] = None
        self._last_price: float = 0.0
        self._last_signal_name: str = "HOLD"
        self._last_signal_reason: str = ""
        self._last_logged_signal: tuple = ("", "")  # (signal_type, reason) 用于日志去重
        self._last_signal_extra: dict = {}  # 策略指标数据
        self._trade_log: list = []
        self._tick_count: int = 0
        self._start_time: datetime = datetime.now()
        self._consecutive_errors: int = 0
        self._max_backoff: int = 300  # 最大退避 5 分钟

        # 余额缓存（减少 API 调用频率）
        self._balance_cache_ttl: int = 300  # 缓存 5 分钟
        self._cached_equity: float = 0.0
        self._cached_equity_ts: float = 0.0
        self._cached_available: float = 0.0
        self._cached_available_ts: float = 0.0

        # 移动止盈 (trailing stop)
        self._highest_since_entry: dict[str, float] = {}  # inst_id -> 最高价
        self.trailing_atr_mult: float = 2.0  # trailing stop = highest - mult * ATR

        # 交易对精度（lotSz / minSz），启动时查询
        self._lot_sz: float = 0.0
        self._min_sz: float = 0.0
        self._fetch_instrument_info()

    # -------------------------------------------------------------------------
    # 账户查询
    # -------------------------------------------------------------------------

    def _fetch_balance(self) -> Optional[dict]:
        """调用 API 获取余额详情，失败返回 None"""
        try:
            balances = self.client.get_balance(self.quote_ccy)
            for item in balances:
                for detail in item.get("details", []):
                    if detail.get("ccy") == self.quote_ccy:
                        return detail
        except Exception as e:
            logger.error("获取账户余额失败: %s", e)
        return None

    def get_equity(self, force: bool = False) -> float:
        """获取账户总权益（USDT），带缓存"""
        now = time.time()
        if not force and (now - self._cached_equity_ts) < self._balance_cache_ttl:
            return self._cached_equity

        detail = self._fetch_balance()
        if detail is not None:
            self._cached_equity = float(detail.get("eq", 0))
            self._cached_equity_ts = now
        return self._cached_equity

    def get_available_usdt(self, force: bool = False) -> float:
        """获取可用 USDT，带缓存"""
        now = time.time()
        if not force and (now - self._cached_available_ts) < self._balance_cache_ttl:
            return self._cached_available

        detail = self._fetch_balance()
        if detail is not None:
            self._cached_available = float(
                detail.get("availEq", 0) or detail.get("availBal", 0) or 0
            )
            self._cached_available_ts = now
        return self._cached_available

    def _invalidate_balance_cache(self):
        """交易后清除余额缓存，下次查询将强制刷新"""
        self._cached_equity_ts = 0.0
        self._cached_available_ts = 0.0

    # -------------------------------------------------------------------------
    # 交易对精度
    # -------------------------------------------------------------------------

    def _fetch_instrument_info(self):
        """查询交易对的 lotSz（下单步长）和 minSz（最小数量）"""
        try:
            info = self.client.get_instrument(self.inst_id)
            self._lot_sz = float(info.get("lotSz", 0))
            self._min_sz = float(info.get("minSz", 0))
            logger.info(
                "[精度] %s  lotSz=%s  minSz=%s",
                self.inst_id, info.get("lotSz"), info.get("minSz"),
            )
        except Exception as e:
            logger.warning("[精度] 获取 %s 交易对信息失败: %s，将使用原始数量下单", self.inst_id, e)

    def _round_lot_size(self, size: float) -> float:
        """按 lotSz 向下取整，确保不低于 minSz"""
        if self._lot_sz > 0:
            size = math.floor(size / self._lot_sz) * self._lot_sz
            # 处理浮点精度：保留与 lotSz 相同的小数位数
            lot_str = f"{self._lot_sz:.10f}".rstrip("0")
            decimals = len(lot_str.split(".")[-1]) if "." in lot_str else 0
            size = round(size, decimals)
        return size

    # -------------------------------------------------------------------------
    # 下单
    # -------------------------------------------------------------------------

    def _buy(self, price: float, size_coin: float, sl: float, tp: float, reason: str) -> bool:
        """执行买入"""
        size_coin = self._round_lot_size(size_coin)
        if self._min_sz > 0 and size_coin < self._min_sz:
            logger.warning("[下单] 数量 %.8f 低于最小下单量 %s，跳过", size_coin, self._min_sz)
            return False
        size_str = self._format_size(size_coin)
        logger.info(
            "[下单] BUY %s  数量=%.6f  价格=%.4f  止损=%.4f  止盈=%.4f  原因=%s",
            self.inst_id, size_coin, price, sl, tp, reason,
        )
        try:
            result = self.client.place_order(
                inst_id=self.inst_id,
                side="buy",
                ord_type="market",
                sz=size_str,
            )
            ord_id = result.get("ordId", "")
            logger.info("[下单] 买入成功 ordId=%s", ord_id)
            self._invalidate_balance_cache()

            # 记录移动止盈基准
            self._highest_since_entry[self.inst_id] = price

            # 记录到风控
            self.risk.add_position(
                PositionInfo(
                    inst_id=self.inst_id,
                    size=size_coin,
                    entry_price=price,
                    stop_loss=sl,
                    take_profit=tp,
                )
            )

            # 交易日志
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
                self._dashboard.log_event(
                    f"BUY {size_coin:.4f} {coin} @ ${price:.4f}  原因: {reason}"
                )
            return True
        except Exception as e:
            logger.error("[下单] 买入失败: %s", e)
            return False

    def _sell(self, reason: str) -> bool:
        """执行卖出（全仓）"""
        pos = self.risk.get_position(self.inst_id)
        if not pos:
            logger.warning("[下单] 无持仓，跳过卖出")
            return False

        sell_size = self._round_lot_size(pos.size)
        if sell_size <= 0:
            logger.warning("[下单] 卖出数量取整后为 0，跳过")
            return False
        size_str = self._format_size(sell_size)
        logger.info(
            "[下单] SELL %s  数量=%.6f  原因=%s",
            self.inst_id, sell_size, reason,
        )
        try:
            result = self.client.place_order(
                inst_id=self.inst_id,
                side="sell",
                ord_type="market",
                sz=size_str,
            )
            ord_id = result.get("ordId", "")
            logger.info("[下单] 卖出成功 ordId=%s", ord_id)
            self._invalidate_balance_cache()

            # 计算盈亏
            pnl = (self._last_price - pos.entry_price) * pos.size if self._last_price > 0 else 0
            pnl_pct = (self._last_price / pos.entry_price - 1) * 100 if pos.entry_price > 0 else 0
            pnl_str = f"{pnl:+.2f} ({pnl_pct:+.1f}%)"

            coin = self.inst_id.split("-")[0]
            self._trade_log.append({
                "time": datetime.now().strftime("%m-%d %H:%M"),
                "side": "SELL",
                "price": self._last_price,
                "size": pos.size,
                "coin": coin,
                "pnl": pnl_str,
            })
            if self._dashboard:
                self._dashboard.log_event(
                    f"SELL {pos.size:.4f} {coin} @ ${self._last_price:.4f}  "
                    f"盈亏: {pnl_str}  原因: {reason}"
                )

            self.risk.remove_position(self.inst_id)
            self._highest_since_entry.pop(self.inst_id, None)
            return True
        except Exception as e:
            logger.error("[下单] 卖出失败: %s", e)
            return False

    @staticmethod
    def _format_size(size: float) -> str:
        """格式化下单数量（避免科学计数法）"""
        return f"{size:.8f}".rstrip("0").rstrip(".")

    # -------------------------------------------------------------------------
    # 止损/止盈轮询检查
    # -------------------------------------------------------------------------

    def _check_sl_tp(self, current_price: float, df: pd.DataFrame | None = None) -> bool:
        """返回 True 表示已触发并平仓"""
        pos = self.risk.get_position(self.inst_id)
        if not pos:
            return False

        # --- 移动止盈 (trailing stop) ---
        if df is not None and self.inst_id in self._highest_since_entry:
            from okx_quant.indicators import atr as calc_atr

            # 更新最高价
            highest = self._highest_since_entry[self.inst_id]
            if current_price > highest:
                highest = current_price
                self._highest_since_entry[self.inst_id] = highest

            # 计算 trailing stop
            atr_val = calc_atr(df).iloc[-1]
            trailing_stop = highest - self.trailing_atr_mult * atr_val

            # 只上移不下移
            if trailing_stop > pos.stop_loss:
                pos.stop_loss = trailing_stop
                logger.debug(
                    "[移动止盈] 最高=%.4f ATR=%.4f 新止损=%.4f",
                    highest, atr_val, trailing_stop,
                )

        if pos.stop_loss > 0 and current_price <= pos.stop_loss:
            logger.warning("[风控] 止损触发 %.4f <= %.4f", current_price, pos.stop_loss)
            return self._sell("止损触发（移动止盈）" if self.inst_id in self._highest_since_entry else "止损触发")

        if pos.take_profit > 0 and current_price >= pos.take_profit:
            logger.info("[风控] 止盈触发 %.4f >= %.4f", current_price, pos.take_profit)
            return self._sell("止盈触发")

        return False

    # -------------------------------------------------------------------------
    # Dashboard 状态构建
    # -------------------------------------------------------------------------

    def _build_dashboard_state(
        self, bar: str, equity: float, available: float, interval_seconds: int, countdown: int
    ):
        """构建仪表盘状态"""
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
            for t in self._trade_log[-5:]
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

    # -------------------------------------------------------------------------
    # Worker 状态（供 Supervisor 收集）
    # -------------------------------------------------------------------------

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
            "recent_trades": list(self._trade_log[-5:]),
            "tick_count": self._tick_count,
            "indicators": dict(self._last_signal_extra),
        }

    # -------------------------------------------------------------------------
    # 主循环
    # -------------------------------------------------------------------------

    def run(
        self,
        bar: str = "1H",
        lookback: int = 100,
        interval_seconds: int = 60,
    ):
        """启动实盘交易主循环

        Args:
            bar: K 线周期
            lookback: 每次获取的历史 K 线数
            interval_seconds: 轮询间隔（秒）
        """
        self._running = True
        self._start_time = datetime.now()
        self._tick_count = 0
        logger.info("启动实盘交易: %s  策略=%s  周期=%s", self.inst_id, self.strategy.name, bar)

        # 初始化风控净值（外部共享 risk_manager 由 Supervisor 统一初始化）
        if not self._external_risk:
            equity = self.get_equity(force=True)
            self.risk.initial_equity = equity
            self.risk.peak_equity = equity
            self.risk.current_equity = equity
            logger.info("当前账户权益: %.2f USDT", equity)

        # 初始化 Dashboard
        if self._use_dashboard:
            from okx_quant.cli.dashboard import Dashboard
            self._dashboard = Dashboard()
            self._dashboard.log_event(
                f"启动实盘交易 {self.inst_id} {self.strategy.name} {bar}"
            )
            # Dashboard 模式下只抑制控制台输出，保留文件日志
            for handler in logging.getLogger().handlers:
                if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                    handler.setLevel(logging.WARNING)

        while self._running:
            try:
                self._tick_count += 1
                self._tick(bar, lookback)
                self._consecutive_errors = 0
            except KeyboardInterrupt:
                logger.info("收到停止信号，退出...")
                self._running = False
                break
            except Exception as e:
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

    def _countdown_with_dashboard(self, bar: str, interval_seconds: int):
        """逐秒倒计时并刷新面板"""
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

    def _tick(self, bar: str, lookback: int):
        """单次轮询处理"""
        # 获取 K 线
        df = self.fetcher.get_candles(self.inst_id, bar=bar, limit=lookback)
        if df.empty:
            logger.warning("K 线数据为空，跳过本次")
            return

        current_price = df["close"].iloc[-1]
        self._last_price = current_price

        # 更新风控净值
        equity = self.get_equity()
        self.risk.update_equity(equity)

        if self.risk.is_halted:
            logger.warning("[风控] %s，跳过交易", self.risk._halt_reason)
            return

        # 止损/止盈检查（传入 df 用于 trailing stop）
        if self._check_sl_tp(current_price, df):
            return

        # 生成策略信号
        signal = self.strategy.generate_signal(df, self.inst_id)
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

        # 记录决策日志（每根 K 线 + 信号类型去重）
        candle_ts = df["ts"].iloc[-1]
        self._decision_logger.log(signal, candle_ts)

        # 执行信号
        if signal.is_buy and not self.risk.has_position(self.inst_id):
            available = self.get_available_usdt()
            size_coin, cost_usdt = self.risk.calc_position_size(
                available, current_price, signal.size_pct
            )

            allowed, msg = self.risk.check_order(
                self.inst_id, "buy", cost_usdt, current_price, equity
            )
            if not allowed:
                logger.warning("[风控] 买入被拒: %s", msg)
                return

            sl, tp = self.risk.calc_sl_tp(current_price, signal.stop_loss, signal.take_profit)
            self._buy(current_price, size_coin, sl, tp, signal.reason)

        elif signal.is_sell and not self.risk.has_position(self.inst_id):
            logger.debug("[信号] SELL 忽略: 当前无持仓")

        elif signal.is_sell:
            allowed, msg = self.risk.check_order(
                self.inst_id, "sell", 0, current_price, equity
            )
            if not allowed:
                logger.warning("[风控] 卖出被拒: %s", msg)
                return
            self._sell(signal.reason)

    def stop(self):
        self._running = False
        self._stop_event.set()
        self._decision_logger.close()
        logger.info("实盘交易已停止")
