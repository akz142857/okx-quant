"""账户余额缓存

把 Exchange.get_balance() 的结果缓存一段时间，避免每次 tick 都打 API。
单次调用会同时刷新 total_equity 与 available_quote，减少重复请求。
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from okx_quant.exchange import Exchange
from okx_quant.exchange.base import BalanceSnapshot

logger = logging.getLogger(__name__)


class AccountSnapshot:
    def __init__(self, exchange: Exchange, ttl_seconds: int = 300):
        self._exchange = exchange
        self._ttl = ttl_seconds
        self._snap: Optional[BalanceSnapshot] = None
        self._ts: float = 0.0

    def _refresh(self) -> None:
        try:
            self._snap = self._exchange.get_balance()
            self._ts = time.time()
        except Exception as e:  # noqa: BLE001 — 对外部 API 兜底
            logger.error("获取账户余额失败: %s", e)

    def snapshot(self, force: bool = False) -> Optional[BalanceSnapshot]:
        """返回最新快照，默认使用 TTL 缓存"""
        if force or self._snap is None or (time.time() - self._ts) >= self._ttl:
            self._refresh()
        return self._snap

    def total_equity(self, force: bool = False) -> float:
        snap = self.snapshot(force=force)
        return snap.total_equity_quote if snap else 0.0

    def available_quote(self, force: bool = False) -> float:
        snap = self.snapshot(force=force)
        return snap.available_quote if snap else 0.0

    def invalidate(self) -> None:
        """交易后清除缓存，下次查询将强制刷新"""
        self._ts = 0.0
