"""多币种交易 Supervisor：每个交易对一个 Worker 线程，主线程协调和渲染"""

import logging
import threading
import time
from datetime import datetime
from typing import Callable

from dataclasses import replace

from okx_quant.client.rest import OKXRestClient
from okx_quant.risk.manager import PositionInfo, RiskConfig, RiskManager
from okx_quant.trading.executor import LiveTrader

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
        client: OKXRestClient,
        instruments: list[str],
        strategy_factory: Callable,
        risk_config: RiskConfig,
        bar: str = "1H",
        lookback: int = 100,
        interval_seconds: int = 60,
        dashboard: bool = True,
        simulated: bool = True,
    ):
        self.client = client
        self.instruments = instruments
        self.bar = bar
        self.lookback = lookback
        self.interval_seconds = interval_seconds
        self._use_dashboard = dashboard
        self._simulated = simulated
        self._start_time = datetime.now()

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

        # 每个 instrument 创建独立策略实例和 LiveTrader
        self._workers: list[LiveTrader] = []
        for inst_id in instruments:
            strategy = strategy_factory()
            trader = LiveTrader(
                client=client,
                strategy=strategy,
                inst_id=inst_id,
                dashboard=False,
                simulated=simulated,
                risk_manager=self.risk,
            )
            self._workers.append(trader)

        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()

    def _init_equity(self):
        """统一初始化账户权益（一次 API 调用）"""
        # 使用第一个 worker 获取余额
        equity = self._workers[0].get_equity(force=True)
        self.risk.initial_equity = equity
        self.risk.peak_equity = equity
        self.risk.current_equity = equity
        logger.info("账户权益初始化: %.2f USDT（%d 个交易对）", equity, len(self.instruments))

    def _restore_positions(self):
        """检测账户已有持仓，恢复到风控管理器中"""
        inst_set = set(self.instruments)
        try:
            balances = self.client.get_balance()
            for item in balances:
                for detail in item.get("details", []):
                    ccy = detail.get("ccy", "")
                    bal = float(detail.get("cashBal", 0) or 0)
                    if ccy == "USDT" or bal <= 0:
                        continue
                    inst_id = f"{ccy}-USDT"
                    if inst_id not in inst_set:
                        continue
                    # 获取当前价格作为参考入场价（无法获取真实入场价）
                    try:
                        ticker = self.client.get_ticker(inst_id)
                        price = float(ticker.get("last", 0))
                    except Exception:
                        price = 0
                    if price <= 0:
                        continue
                    # 用当前价格估算止损止盈
                    sl = round(price * (1 - self.risk.config.stop_loss_pct), 8)
                    tp = round(price * (1 + self.risk.config.take_profit_pct), 8)
                    self.risk.add_position(PositionInfo(
                        inst_id=inst_id,
                        size=bal,
                        entry_price=price,
                        stop_loss=sl,
                        take_profit=tp,
                    ))
                    logger.info("恢复已有持仓: %s  数量=%.6f  参考价=%.4f（估算）", inst_id, bal, price)
        except Exception as e:
            logger.warning("检测已有持仓失败: %s", e)

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
