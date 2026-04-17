"""多 Agent AI 交易策略 — BaseStrategy 薄封装

调用 agentic.AgenticPipeline 执行完整的多 Agent 流程，
将结果转换为 Signal dataclass。

依赖注入（与现有 LLM 策略接口一致）：
    set_llm_client(client)      — 注入 cheap model（分析师用）
    set_deep_llm_client(client) — 注入 strong model（辩论+决策用）
    set_news_fetcher(fetcher)   — 可选，注入新闻获取器
"""

import logging
from typing import Optional

import pandas as pd

from okx_quant.data.news import CryptoNewsFetcher
from okx_quant.indicators import atr, bollinger_bands, ema, macd, rsi
from okx_quant.llm.client import LLMClient
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType

logger = logging.getLogger(__name__)


class MultiAgentStrategy(BaseStrategy):
    """多 Agent AI 交易策略

    4 个分析师 + 多空辩论 + 交易员 + 风控经理，
    分析师使用廉价模型，辩论和决策使用强力模型。
    """

    name = "MultiAgent"

    def __init__(self, params: dict | None = None):
        defaults = {
            "confidence_threshold": 0.6,
            "candle_count": 20,
            "news_count": 5,
            "debate_rounds": 2,
            # 单次会话 (run) 的 token 预算上限，<=0 表示不限
            "max_total_tokens": 0,
        }
        merged = {**defaults, **(params or {})}
        super().__init__(merged)

        self._llm_client: Optional[LLMClient] = None       # cheap model
        self._deep_llm_client: Optional[LLMClient] = None   # strong model
        self._news_fetcher: Optional[CryptoNewsFetcher] = None
        self._pipeline = None  # 延迟初始化
        self._budget_exceeded_logged: bool = False

    def _over_budget(self) -> bool:
        """检查是否超出 token 预算"""
        cap = int(self.get_param("max_total_tokens") or 0)
        if cap <= 0 or self._pipeline is None:
            return False
        used = self._pipeline.tracker.summary().get("total_tokens", 0)
        return used >= cap

    # ------------------------------------------------------------------
    # 依赖注入（兼容 make_strategy 的调用约定）
    # ------------------------------------------------------------------

    def set_llm_client(self, client: LLMClient) -> None:
        """注入 cheap model（分析师使用）"""
        self._llm_client = client
        self._pipeline = None  # 客户端变更，重建 pipeline

    def set_deep_llm_client(self, client: LLMClient) -> None:
        """注入 strong model（辩论 + 决策使用）"""
        self._deep_llm_client = client
        self._pipeline = None  # 客户端变更，重建 pipeline

    def set_news_fetcher(self, fetcher: CryptoNewsFetcher) -> None:
        self._news_fetcher = fetcher

    @property
    def llm_model(self) -> str:
        """返回主模型名称（用于费用统计显示）"""
        parts = []
        if self._llm_client:
            parts.append(self._llm_client.config.model)
        if self._deep_llm_client:
            parts.append(self._deep_llm_client.config.model)
        return " + ".join(parts) if parts else ""

    def get_usage_summary(self) -> dict:
        """返回 token 用量统计（兼容 _print_llm_usage）"""
        if self._pipeline is None:
            return {"total_calls": 0, "total_input_tokens": 0,
                    "total_output_tokens": 0, "total_tokens": 0}
        summary = self._pipeline.tracker.summary()
        return {
            "total_calls": summary["total_calls"],
            "total_input_tokens": summary["total_input_tokens"],
            "total_output_tokens": summary["total_output_tokens"],
            "total_tokens": summary["total_tokens"],
            "per_agent": summary.get("per_agent", {}),
        }

    # ------------------------------------------------------------------
    # 核心信号生成
    # ------------------------------------------------------------------

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        # 前置检查
        quick = self._llm_client
        deep = self._deep_llm_client or self._llm_client
        if quick is None:
            return Signal(SignalType.HOLD, inst_id, price=0, reason="LLM 客户端未配置")

        if len(df) < 30:
            return Signal(SignalType.HOLD, inst_id, price=0, reason="数据不足")

        # 延迟初始化 pipeline
        if self._pipeline is None:
            from okx_quant.agentic import AgenticConfig, AgenticPipeline

            ag_config = AgenticConfig(
                debate_rounds=self.get_param("debate_rounds"),
                confidence_threshold=self.get_param("confidence_threshold"),
            )
            self._pipeline = AgenticPipeline(
                quick_llm=quick,
                deep_llm=deep,
                config=ag_config,
            )

        curr_price = df["close"].iloc[-1]

        # Token 预算检查（pipeline 已初始化后才可评估）
        if self._over_budget():
            if not self._budget_exceeded_logged:
                logger.warning(
                    "[MultiAgent] 已达 token 预算上限 %s，后续调用将直接 HOLD",
                    self.get_param("max_total_tokens"),
                )
                self._budget_exceeded_logged = True
            return Signal(
                SignalType.HOLD, inst_id, price=curr_price,
                reason="LLM token 预算已达上限",
            )

        # 构建指标上下文
        indicators = self._build_indicators(df, inst_id)
        recent_candles = self._format_candles(df)

        # 获取新闻
        news_text = self._get_news_text(inst_id)

        # 运行 pipeline
        try:
            result = self._pipeline.run(
                indicators=indicators,
                recent_candles=recent_candles,
                inst_id=inst_id,
                news_text=news_text,
            )
        except Exception as e:
            logger.error("[MultiAgent] Pipeline 异常: %s", e)
            return Signal(
                SignalType.HOLD, inst_id, price=curr_price,
                reason=f"多Agent管线异常: {e}",
            )

        # 置信度检查
        confidence = result.get("confidence", 0)
        threshold = self.get_param("confidence_threshold")
        if confidence < threshold:
            return Signal(
                SignalType.HOLD, inst_id, price=curr_price,
                reason=f"置信度不足 ({confidence:.2f} < {threshold})",
                extra={"pipeline_result": result},
            )

        # 构建 Signal
        signal_str = result.get("signal", "HOLD").upper()
        signal_type = {"BUY": SignalType.BUY, "SELL": SignalType.SELL}.get(
            signal_str, SignalType.HOLD
        )

        size_pct = min(max(result.get("size_pct", 0.5), 0.0), 1.0)
        sl_pct = result.get("stop_loss_pct", 0.02)
        tp_pct = result.get("take_profit_pct", 0.04)

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
            reason=result.get("reason", "多Agent决策"),
            extra={
                "confidence": confidence,
                "llm_model": self.llm_model,
                "pipeline_result": result,
            },
        )

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _build_indicators(self, df: pd.DataFrame, inst_id: str) -> dict:
        """从 DataFrame 构建技术指标字典"""
        close = df["close"]
        curr_price = close.iloc[-1]

        # 根据 ts 列计算最近 24 小时的数据窗口
        cutoff = df["ts"].iloc[-1] - pd.Timedelta(hours=24)
        df_24h = df[df["ts"] >= cutoff]
        if df_24h.empty:
            df_24h = df  # fallback: 数据不足 24 小时则用全部

        high_24h = df_24h["high"].max()
        low_24h = df_24h["low"].min()
        open_24h = df_24h["close"].iloc[0]
        change_pct = (curr_price - open_24h) / open_24h * 100

        ema_9 = ema(close, 9).iloc[-1]
        ema_21 = ema(close, 21).iloc[-1]
        macd_df = macd(close)
        rsi_val = rsi(close, 14).iloc[-1]
        bb = bollinger_bands(close, 20, 2.0)
        atr_val = atr(df, 14).iloc[-1]
        bb_width = bb["upper"].iloc[-1] - bb["lower"].iloc[-1]

        # 成交量摘要
        vol = df["vol"]
        vol_avg = vol.tail(20).mean()
        vol_latest = vol.iloc[-1]
        vol_ratio = vol_latest / vol_avg if vol_avg > 0 else 1.0
        vol_summary = (
            f"Latest Volume: {vol_latest:.0f}\n"
            f"20-bar Avg Volume: {vol_avg:.0f}\n"
            f"Volume Ratio: {vol_ratio:.2f}x"
        )

        return {
            "inst_id": inst_id,
            "price": curr_price,
            "change_pct": change_pct,
            "high_24h": high_24h,
            "low_24h": low_24h,
            "ema9": ema_9,
            "ema21": ema_21,
            "macd": macd_df["macd"].iloc[-1],
            "macd_signal": macd_df["signal"].iloc[-1],
            "macd_hist": macd_df["histogram"].iloc[-1],
            "rsi": rsi_val,
            "bb_upper": bb["upper"].iloc[-1],
            "bb_mid": bb["middle"].iloc[-1],
            "bb_lower": bb["lower"].iloc[-1],
            "bb_width": bb_width,
            "atr": atr_val,
            "vol_summary": vol_summary,
        }

    def _format_candles(self, df: pd.DataFrame) -> str:
        """格式化近期 K 线为文本"""
        candle_count = self.get_param("candle_count")
        recent = df.tail(candle_count)
        lines = []
        for row in recent.itertuples():
            lines.append(
                f"{row.ts} | O:{row.open:.6f} H:{row.high:.6f} "
                f"L:{row.low:.6f} C:{row.close:.6f} V:{row.vol:.0f}"
            )
        return "\n".join(lines)

    def _get_news_text(self, inst_id: str) -> str:
        """获取新闻文本"""
        if not self._news_fetcher:
            return "No news source configured."
        coin = inst_id.split("-")[0]
        news_count = self.get_param("news_count")
        news = self._news_fetcher.get_news(coin, limit=news_count)
        return CryptoNewsFetcher.format_for_prompt(news)
