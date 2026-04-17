"""行情数据获取模块：K 线、Ticker、订单簿，统一转为 pandas DataFrame"""

import logging
import time
from typing import Optional
import pandas as pd

from okx_quant.client.rest import OKXRestClient

logger = logging.getLogger(__name__)

# OKX K 线原始字段顺序
_CANDLE_COLS = ["ts", "open", "high", "low", "close", "vol", "vol_ccy", "vol_ccy_quote", "confirm"]

# bar 字符串 → pandas Timedelta
_BAR_MINUTES = {
    "1m": 1, "3m": 3, "5m": 5, "15m": 15, "30m": 30,
    "1H": 60, "2H": 120, "4H": 240, "6H": 360, "12H": 720,
    "1D": 1440, "1W": 10080, "1M": 43200,
}


def _bar_to_timedelta(bar: str) -> Optional[pd.Timedelta]:
    minutes = _BAR_MINUTES.get(bar)
    return pd.Timedelta(minutes=minutes) if minutes else None


class MarketDataFetcher:
    """封装 OKX 行情数据拉取，返回易用的 DataFrame"""

    def __init__(self, client: OKXRestClient):
        self.client = client

    # -------------------------------------------------------------------------
    # K 线
    # -------------------------------------------------------------------------

    def get_candles(
        self,
        inst_id: str,
        bar: str = "1H",
        limit: int = 100,
    ) -> pd.DataFrame:
        """获取最近 N 根 K 线（最新数据在最后）

        Args:
            inst_id: 如 "BTC-USDT"
            bar: K 线周期，1m/5m/15m/30m/1H/4H/1D
            limit: 条数，最大 300

        Returns:
            DataFrame 列: ts(datetime), open, high, low, close, vol, vol_ccy
        """
        raw = self.client.get_candles(inst_id, bar=bar, limit=limit)
        return self._parse_candles(raw)

    def get_history_candles(
        self,
        inst_id: str,
        bar: str = "1H",
        total: int = 500,
    ) -> pd.DataFrame:
        """获取大量历史 K 线（自动翻页）

        OKX 单次最多返回 300 条，此方法自动翻页直到获取 total 条。
        翻页间使用轻量退避防限流；REST 客户端自身也会在 429 / 50011 时重试。
        """
        all_raw: list = []
        after: Optional[str] = None
        seen_after: set[str] = set()
        batch = min(300, total)

        while len(all_raw) < total:
            raw = self.client.get_history_candles(inst_id, bar=bar, limit=batch, after=after)
            if not raw:
                break
            all_raw.extend(raw)

            # 翻页游标：取最早一条的时间戳继续向前
            next_after = str(raw[-1][0])
            if next_after in seen_after:
                # 防止相同游标无限循环
                logger.warning("分页游标重复（%s），提前终止", next_after)
                break
            seen_after.add(next_after)
            after = next_after

            if len(raw) < batch:
                break
            time.sleep(0.3)  # 轻量退避，配合 REST 层限流重试

        df = self._parse_candles(all_raw)
        if df.empty:
            return df

        # 校验时间戳连续性（单位：周期分钟）— 仅告警，不阻断
        self._warn_if_gaps(df, bar)
        return df.tail(total).reset_index(drop=True)

    @staticmethod
    def _warn_if_gaps(df: pd.DataFrame, bar: str) -> None:
        """检测 K 线是否存在时间跳跃（缺失/重叠）"""
        if len(df) < 2:
            return
        period = _bar_to_timedelta(bar)
        if period is None:
            return
        diffs = df["ts"].diff().dropna()
        # 容忍 ±50% 漂移
        gaps = diffs[(diffs > period * 1.5) | (diffs < period * 0.5)]
        if not gaps.empty:
            logger.warning(
                "K 线时间戳存在 %d 处跳跃/重叠（周期=%s），最大间隔=%s",
                len(gaps), bar, gaps.max(),
            )

    def _parse_candles(self, raw: list[list]) -> pd.DataFrame:
        if not raw:
            return pd.DataFrame(columns=_CANDLE_COLS[:7])

        df = pd.DataFrame(raw, columns=_CANDLE_COLS[: len(raw[0])])
        df["ts"] = pd.to_datetime(df["ts"].astype(float), unit="ms", utc=True)
        for col in ["open", "high", "low", "close", "vol", "vol_ccy"]:
            if col in df.columns:
                df[col] = df[col].astype(float)

        # OKX 返回最新在最前，反转使时序递增
        df = df.sort_values("ts").reset_index(drop=True)
        # 过滤未完成的 K 线（confirm != "1"）
        if "confirm" in df.columns:
            df = df[df["confirm"] == "1"].drop(columns=["confirm"])

        return df

    # -------------------------------------------------------------------------
    # Ticker
    # -------------------------------------------------------------------------

    def get_ticker(self, inst_id: str) -> dict:
        """获取单个交易对实时行情"""
        raw = self.client.get_ticker(inst_id)
        if not raw:
            return {}
        return {
            "inst_id": raw.get("instId"),
            "last": float(raw.get("last", 0)),
            "bid": float(raw.get("bidPx", 0)),
            "ask": float(raw.get("askPx", 0)),
            "vol_24h": float(raw.get("vol24h", 0)),
            "open_24h": float(raw.get("open24h", 0)),
            "high_24h": float(raw.get("high24h", 0)),
            "low_24h": float(raw.get("low24h", 0)),
            "change_24h_pct": self._pct(raw.get("open24h"), raw.get("last")),
        }

    def get_all_tickers(self) -> pd.DataFrame:
        """获取所有现货交易对行情"""
        raw_list = self.client.get_tickers("SPOT")
        if not raw_list:
            return pd.DataFrame()
        rows = []
        for r in raw_list:
            rows.append(
                {
                    "inst_id": r.get("instId"),
                    "last": float(r.get("last", 0) or 0),
                    "bid": float(r.get("bidPx", 0) or 0),
                    "ask": float(r.get("askPx", 0) or 0),
                    "vol_24h": float(r.get("vol24h", 0) or 0),
                    "change_24h_pct": self._pct(r.get("open24h"), r.get("last")),
                }
            )
        return pd.DataFrame(rows)

    # -------------------------------------------------------------------------
    # 订单簿
    # -------------------------------------------------------------------------

    def get_orderbook(self, inst_id: str, depth: int = 20) -> dict:
        """获取订单簿，返回结构化字典"""
        raw = self.client.get_orderbook(inst_id, sz=depth)
        if not raw:
            return {"bids": [], "asks": []}

        def parse_side(entries):
            return [
                {"price": float(e[0]), "size": float(e[1]), "orders": int(e[3] if len(e) > 3 else 1)}
                for e in entries
            ]

        return {
            "bids": parse_side(raw.get("bids", [])),
            "asks": parse_side(raw.get("asks", [])),
            "ts": int(raw.get("ts", 0)),
        }

    def get_spread(self, inst_id: str) -> dict:
        """获取买卖价差信息"""
        book = self.get_orderbook(inst_id, depth=1)
        if not book["bids"] or not book["asks"]:
            return {}
        bid = book["bids"][0]["price"]
        ask = book["asks"][0]["price"]
        mid = (bid + ask) / 2
        return {
            "bid": bid,
            "ask": ask,
            "mid": mid,
            "spread": ask - bid,
            "spread_pct": (ask - bid) / mid * 100,
        }

    # -------------------------------------------------------------------------
    # 工具
    # -------------------------------------------------------------------------

    @staticmethod
    def _pct(open_price, last_price) -> float:
        try:
            o, l = float(open_price), float(last_price)
            return round((l - o) / o * 100, 4) if o else 0.0
        except (TypeError, ValueError, ZeroDivisionError):
            return 0.0
