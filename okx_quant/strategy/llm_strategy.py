"""LLM 大模型交易策略 — 调用 AI 分析 K 线 + 技术指标 + 新闻生成交易信号"""

import json
import logging
import re
from typing import Optional

import pandas as pd

from okx_quant.data.news import CryptoNewsFetcher, NewsItem
from okx_quant.indicators import atr, bollinger_bands, ema, macd, rsi
from okx_quant.llm.client import LLMClient, LLMResponse
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a professional cryptocurrency trading analyst.
Analyze the provided market data and return a JSON trading decision.

Rules:
1. Only return valid JSON, no markdown or explanation outside JSON.
2. Be conservative — only signal BUY/SELL when confidence is high.
3. Always provide stop_loss_pct and take_profit_pct as decimals (e.g. 0.02 = 2%).
4. size_pct is the suggested position size as a fraction (0.0–1.0).
5. Reason should be a concise Chinese explanation (1-2 sentences).

Required JSON format:
{"signal":"BUY|SELL|HOLD","confidence":0.0-1.0,"size_pct":0.5,"stop_loss_pct":0.02,"take_profit_pct":0.04,"reason":"中文简述"}
"""


class LLMStrategy(BaseStrategy):
    """LLM 大模型交易策略

    通过调用 LLM 分析 K 线数据、技术指标和新闻情绪来生成交易信号。
    安全机制：置信度 < 0.6 → HOLD | API 失败 → HOLD | JSON 解析失败 → HOLD

    依赖注入：
        set_llm_client(client)   — 必须在使用前注入 LLMClient
        set_news_fetcher(fetcher) — 可选，注入新闻获取器
    """

    name = "LLM"

    def __init__(self, params: dict | None = None):
        defaults = {
            "confidence_threshold": 0.6,
            "candle_count": 20,
            "news_count": 5,
        }
        merged = {**defaults, **(params or {})}
        super().__init__(merged)

        self._llm_client: Optional[LLMClient] = None
        self._news_fetcher: Optional[CryptoNewsFetcher] = None

        # Token 用量累计追踪
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0
        self.total_calls: int = 0

    @property
    def llm_model(self) -> str:
        """当前使用的 LLM 模型名称"""
        if self._llm_client:
            return self._llm_client.config.model
        return ""

    def set_llm_client(self, client: LLMClient) -> None:
        self._llm_client = client

    def set_news_fetcher(self, fetcher: CryptoNewsFetcher) -> None:
        self._news_fetcher = fetcher

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        if self._llm_client is None:
            return Signal(SignalType.HOLD, inst_id, price=0, reason="LLM 客户端未配置")

        if len(df) < 30:
            return Signal(SignalType.HOLD, inst_id, price=0, reason="数据不足")

        curr_price = df["close"].iloc[-1]

        # 构建 Prompt
        user_prompt = self._build_prompt(df, inst_id)

        # 调用 LLM
        response = self._llm_client.chat(_SYSTEM_PROMPT, user_prompt)
        self.total_calls += 1
        self.total_input_tokens += response.input_tokens
        self.total_output_tokens += response.output_tokens

        if not response.ok:
            logger.warning("LLM 调用失败: %s", response.error)
            return Signal(
                SignalType.HOLD, inst_id, price=curr_price,
                reason=f"LLM 调用失败: {response.error}",
            )

        # 解析 JSON
        decision = self._parse_decision(response.content)
        if decision is None:
            return Signal(
                SignalType.HOLD, inst_id, price=curr_price,
                reason="LLM 返回内容无法解析",
            )

        # 置信度检查
        confidence = decision.get("confidence", 0)
        threshold = self.get_param("confidence_threshold")
        if confidence < threshold:
            return Signal(
                SignalType.HOLD, inst_id, price=curr_price,
                reason=f"置信度不足 ({confidence:.2f} < {threshold})",
                extra={"llm_decision": decision},
            )

        # 构建信号
        signal_str = decision.get("signal", "HOLD").upper()
        signal_type = {
            "BUY": SignalType.BUY,
            "SELL": SignalType.SELL,
        }.get(signal_str, SignalType.HOLD)

        size_pct = min(max(decision.get("size_pct", 0.5), 0.0), 1.0)
        sl_pct = decision.get("stop_loss_pct", 0.02)
        tp_pct = decision.get("take_profit_pct", 0.04)

        if signal_type == SignalType.BUY:
            stop_loss = round(curr_price * (1 - sl_pct), 8)
            take_profit = round(curr_price * (1 + tp_pct), 8)
        else:
            # 现货多头系统：SELL 是平仓，HOLD 无操作，均不需要止损止盈
            stop_loss = 0
            take_profit = 0

        return Signal(
            signal=signal_type,
            inst_id=inst_id,
            price=curr_price,
            size_pct=size_pct,
            stop_loss=stop_loss,
            take_profit=take_profit,
            reason=decision.get("reason", "LLM 决策"),
            extra={
                "confidence": confidence,
                "llm_model": self.llm_model,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
            },
        )

    # ------------------------------------------------------------------
    # Prompt 构建
    # ------------------------------------------------------------------

    def _build_prompt(self, df: pd.DataFrame, inst_id: str) -> str:
        sections: list[str] = []
        coin = inst_id.split("-")[0]
        close = df["close"]
        curr_price = close.iloc[-1]

        # 1. Market Summary（基于时间戳精确取 24H 窗口）
        cutoff = df["ts"].iloc[-1] - pd.Timedelta(hours=24)
        df_24h = df[df["ts"] >= cutoff]
        if df_24h.empty:
            df_24h = df
        high_24h = df_24h["high"].max()
        low_24h = df_24h["low"].min()
        open_24h = df_24h["close"].iloc[0]
        change_pct = (curr_price - open_24h) / open_24h * 100

        sections.append(
            f"## Market Summary ({inst_id})\n"
            f"Current Price: {curr_price}\n"
            f"24H Change: {change_pct:+.2f}%\n"
            f"24H High: {high_24h}  |  24H Low: {low_24h}"
        )

        # 2. Technical Indicators
        ema_9 = ema(close, 9).iloc[-1]
        ema_21 = ema(close, 21).iloc[-1]
        macd_df = macd(close)
        rsi_val = rsi(close, 14).iloc[-1]
        bb = bollinger_bands(close, 20, 2.0)
        atr_val = atr(df, 14).iloc[-1]

        sections.append(
            "## Technical Indicators\n"
            f"EMA9: {ema_9:.6f}  |  EMA21: {ema_21:.6f}\n"
            f"MACD: {macd_df['macd'].iloc[-1]:.6f}  |  Signal: {macd_df['signal'].iloc[-1]:.6f}  |  Hist: {macd_df['histogram'].iloc[-1]:.6f}\n"
            f"RSI(14): {rsi_val:.2f}\n"
            f"Bollinger: Upper={bb['upper'].iloc[-1]:.6f}  Mid={bb['middle'].iloc[-1]:.6f}  Lower={bb['lower'].iloc[-1]:.6f}\n"
            f"ATR(14): {atr_val:.6f}"
        )

        # 3. Recent Candles
        candle_count = self.get_param("candle_count")
        recent = df.tail(candle_count)
        candle_lines = ["## Recent Candles (OHLCV)"]
        for row in recent.itertuples():
            candle_lines.append(
                f"{row.ts} | O:{row.open:.6f} H:{row.high:.6f} "
                f"L:{row.low:.6f} C:{row.close:.6f} V:{row.vol:.0f}"
            )
        sections.append("\n".join(candle_lines))

        # 4. News
        if self._news_fetcher:
            news_count = self.get_param("news_count")
            news = self._news_fetcher.get_news(coin, limit=news_count)
            news_text = CryptoNewsFetcher.format_for_prompt(news)
        else:
            news_text = "No news source configured."
        sections.append(f"## Recent News\n{news_text}")

        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # JSON 解析
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_decision(content: str) -> Optional[dict]:
        """尝试从 LLM 返回内容中解析交易决策 JSON"""
        # 直接解析
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # 尝试提取 JSON 块（LLM 有时会包裹在 ```json ... ``` 中）
        # 支持嵌套花括号（如 reason 字段含 {} 的情况）
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        return None

    # ------------------------------------------------------------------
    # 用量统计
    # ------------------------------------------------------------------

    def get_usage_summary(self) -> dict:
        """返回 LLM 调用用量统计"""
        return {
            "total_calls": self.total_calls,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
        }
