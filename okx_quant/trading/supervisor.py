"""多币种交易 Supervisor：每个交易对一个 Worker 线程，主线程协调和渲染"""

import logging
import threading
import time
from datetime import datetime
from typing import Callable

from dataclasses import replace

from okx_quant.client.rest import OKXRestClient
from okx_quant.exchange import Exchange, OKXExchange
from okx_quant.risk.manager import RiskConfig, RiskManager
from okx_quant.trading.executor import LiveTrader
from okx_quant.trading.position_restore import restore_to_risk
from okx_quant.trading.state import StateStore

logger = logging.getLogger(__name__)


class Supervisor:
    """多币种交易协调器

    为每个交易对创建独立的 LiveTrader（dashboard=False），
    共享同一个 RiskManager 和 OKXRestClient。
    主线程负责仪表盘渲染或等待停止信号。

    用法::

        supervisor = Supervisor(
            client=client,
            instruments=["DOGE-USDT", "BTC-USDT"],
            strategy_factory=lambda: make_strategy("ma_cross"),
            risk_config=risk_config,
            bar="1H",
        )
        supervisor.run()
    """

    def __init__(
        self,
        client: "OKXRestClient | None" = None,
        instruments: "list[str] | None" = None,
        strategy_factory: "Callable | None" = None,
        risk_config: "RiskConfig | None" = None,
        bar: str = "1H",
        lookback: int = 100,
        interval_seconds: int = 60,
        dashboard: bool = True,
        simulated: bool = True,
        signal_timeout_s: float = 20.0,
        state_store: "StateStore | None" = None,
        *,
        exchange: "Exchange | None" = None,
    ):
        if exchange is None and client is None:
            raise ValueError("Supervisor 需要 exchange 或 client 至少一个")
        if not instruments or strategy_factory is None or risk_config is None:
            raise ValueError("Supervisor 需要 instruments / strategy_factory / risk_config")

        self.exchange: Exchange = exchange if exchange is not None else OKXExchange(client)
        self.client: "OKXRestClient | None" = (
            client if client is not None else getattr(self.exchange, "client", None)
        )
        self.instruments = instruments
        self.bar = bar
        self.lookback = lookback
        self.interval_seconds = interval_seconds
        self._use_dashboard = dashboard
        self._simulated = simulated
        self._start_time = datetime.now()
        self._signal_timeout_s = signal_timeout_s
        self._state_store = state_store if state_store is not None else StateStore()

        # 共享风控（副本，不修改调用方）
        # max_open_positions 自动设为币种数
        # max_position_pct 均分给每个币种，避免先买的占满资金
        n = len(instruments)
        per_inst_pct = risk_config.max_position_pct / n
        self.risk = RiskManager(replace(
            risk_config,
            max_open_positions=n,
            max_position_pct=per_inst_pct,
        ))

        # 每个 instrument 创建独立策略实例和 LiveTrader；共享同一个 Exchange
        self._workers: list[LiveTrader] = []
        for inst_id in instruments:
            strategy = strategy_factory()
            trader = LiveTrader(
                exchange=self.exchange,
                strategy=strategy,
                inst_id=inst_id,
                dashboard=False,
                simulated=simulated,
                risk_manager=self.risk,
                signal_timeout_s=self._signal_timeout_s,
                state_store=self._state_store,
            )
            self._workers.append(trader)

        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()

    def _init_equity(self):
        """统一初始化账户权益（一次 API 调用）"""
        equity = self._workers[0].get_equity(force=True)
        self.risk.initialize(equity)
        logger.info("账户权益初始化: %.2f USDT（%d 个交易对）", equity, len(self.instruments))

    def _restore_positions(self):
        """检测账户已有持仓，恢复到风控管理器中"""
        quote = getattr(self.exchange, "quote_ccy", "USDT")
        restore_to_risk(self.exchange, self.risk, self.instruments, quote_ccy=quote)

    def collect_states(self) -> list[dict]:
        """收集所有 worker 的状态快照"""
        states = []
        for worker in self._workers:
            try:
                states.append(worker.get_worker_state())
            except Exception:
                states.append({"inst_id": worker.inst_id, "error": True})
        return states

    def run(self):
        """启动所有 worker 线程，主线程负责仪表盘或等待"""
        self._init_equity()
        self._restore_positions()

        # 启动 worker 线程
        for worker in self._workers:
            t = threading.Thread(
                target=self._run_worker,
                args=(worker,),
                name=f"worker-{worker.inst_id}",
                daemon=True,
            )
            self._threads.append(t)
            t.start()
            logger.info("Worker 线程启动: %s", worker.inst_id)

        try:
            if self._use_dashboard:
                self._run_dashboard()
            else:
                logger.info("多币种交易已启动（日志模式），按 Ctrl+C 停止")
                self._stop_event.wait()
        except KeyboardInterrupt:
            logger.info("收到停止信号，正在关闭所有 worker...")
        finally:
            self.stop()

    def _run_worker(self, worker: LiveTrader):
        """在线程中运行单个 worker"""
        try:
            worker.run(
                bar=self.bar,
                lookback=self.lookback,
                interval_seconds=self.interval_seconds,
            )
        except Exception as e:
            logger.error("Worker %s 异常退出: %s", worker.inst_id, e, exc_info=True)

    def _run_dashboard(self):
        """主线程：每秒收集状态并渲染多币种仪表盘"""
        from okx_quant.cli.dashboard import MultiDashboard, MultiDashboardState, TradeRecord

        dashboard = MultiDashboard()

        # Dashboard 模式下抑制控制台日志
        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler
            ):
                handler.setLevel(logging.WARNING)

        while not self._stop_event.is_set():
            try:
                states = self.collect_states()
                equity = self._workers[0].get_equity()
                available = self._workers[0].get_available_usdt()

                # 合并所有 worker 的交易记录
                all_trades = []
                for ws in states:
                    for t in ws.get("recent_trades", []):
                        all_trades.append(
                            TradeRecord(
                                time=t["time"],
                                side=t["side"],
                                price=t["price"],
                                size=t["size"],
                                coin=t["coin"],
                                pnl=t.get("pnl", ""),
                            )
                        )
                # 按时间排序，取最近 5 笔
                all_trades.sort(key=lambda t: t.time)
                all_trades = all_trades[-5:]

                # 找出所有 worker 中最大的 tick_count 作为轮次
                max_tick = max((ws.get("tick_count", 0) for ws in states), default=0)

                account_pnl = equity - self.risk.initial_equity
                account_pnl_pct = (
                    (equity / self.risk.initial_equity - 1) * 100
                    if self.risk.initial_equity > 0
                    else 0
                )

                # 取第一个 worker 的策略名称（多币种共用同一策略）
                strategy_name = states[0].get("strategy_name", "") if states else ""

                dash_state = MultiDashboardState(
                    strategy_name=strategy_name,
                    bar=self.bar,
                    simulated=self._simulated,
                    start_time=self._start_time,
                    equity=equity,
                    available=available,
                    account_pnl=account_pnl,
                    account_pnl_pct=account_pnl_pct,
                    drawdown_pct=self.risk.current_drawdown_pct,
                    max_drawdown_pct=self.risk.config.max_drawdown_pct * 100,
                    open_positions=self.risk.open_count,
                    max_positions=self.risk.config.max_open_positions,
                    risk_halted=self.risk.is_halted,
                    worker_states=states,
                    recent_trades=all_trades,
                    tick_count=max_tick,
                    last_update=datetime.now().strftime("%H:%M:%S"),
                )
                dashboard.render(dash_state)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.debug("Dashboard 渲染异常: %s", e)

            time.sleep(1)

    def stop(self):
        """停止所有 worker 和线程"""
        self._stop_event.set()
        for worker in self._workers:
            worker.stop()
        # 等待线程结束（daemon 线程也给个短暂等待机会）
        for t in self._threads:
            t.join(timeout=3)
        logger.info("所有 worker 已停止")
