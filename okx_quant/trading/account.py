"""账户余额缓存

把 Exchange.get_balance() 的结果缓存一段时间，避免每次 tick 都打 API。
单次调用会同时刷新 total_equity 与 available_quote，减少重复请求。
"""

from __future__ import annotations

import logging
import threading
import time

from okx_quant.exchange import Exchange
from okx_quant.exchange.base import BalanceSnapshot

logger = logging.getLogger(__name__)


class AccountSnapshot:
    def __init__(self, exchange: Exchange, ttl_seconds: int = 300):
        self._exchange = exchange
        self._ttl = ttl_seconds
        self._snap: BalanceSnapshot | None = None
        self._ts: float = 0.0
        # Supervisor 多 worker 线程 + dashboard 线程会并发访问同一个实例，
        # 用锁保护 _snap/_ts 的读写一致性，并避免重复并发刷新。
        self._lock = threading.Lock()

    def _refresh_locked(self) -> None:
        try:
            fresh = self._exchange.get_balance()
        except Exception as e:  # noqa: BLE001 — 对外部 API 兜底
            if self._snap is None:
                # 启动阶段没有任何可信快照时必须 fail-closed。把错误传播给
                # LiveTrader/Supervisor，避免以 0 权益、0 持仓继续运行。
                raise RuntimeError("无法取得初始账户余额快照，拒绝启动交易") from e
            # 运行中的瞬时故障保留上一份可信快照。不要把故障解释成零余额，
            # 也不要清空真实仓位。
            logger.error("刷新账户余额失败，暂用上一份快照: %s", e)
            return
        self._snap = fresh
        self._ts = time.time()

    def snapshot(self, force: bool = False) -> BalanceSnapshot | None:
        """返回最新快照，默认使用 TTL 缓存"""
        with self._lock:
            if force or self._snap is None or (time.time() - self._ts) >= self._ttl:
                self._refresh_locked()
            return self._snap

    def total_equity(self, force: bool = False) -> float:
        snap = self.snapshot(force=force)
        return float(snap.total_equity_quote) if snap else 0.0

    def available_quote(self, force: bool = False) -> float:
        snap = self.snapshot(force=force)
        return float(snap.available_quote) if snap else 0.0

    def invalidate(self) -> None:
        """交易后清除缓存，下次查询将强制刷新"""
        with self._lock:
            self._ts = 0.0
