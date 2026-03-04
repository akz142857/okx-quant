from .base import BaseStrategy, Signal, SignalType
from .ma_cross import MACrossStrategy
from .rsi_mean import RSIMeanReversionStrategy
from .bollinger import BollingerBandStrategy
from .llm_strategy import LLMStrategy
from .ensemble import EnsembleStrategy
from .multi_agent_strategy import MultiAgentStrategy
from .adaptive import AdaptiveStrategy
from .trend_momentum import TrendMomentumStrategy

# 策略注册表：key -> (class, 中文名, 描述)
STRATEGY_REGISTRY: dict[str, tuple[type[BaseStrategy], str, str]] = {
    "ma_cross": (MACrossStrategy, "双均线金叉/死叉", "EMA9/21交叉，ATR止损止盈"),
    "rsi_mean": (RSIMeanReversionStrategy, "RSI均值回归", "RSI超买超卖反转"),
    "bollinger": (BollingerBandStrategy, "布林带策略", "布林带上下轨+RSI过滤"),
    "llm": (LLMStrategy, "AI 分析策略", "LLM分析技术指标+新闻"),
    "ensemble": (EnsembleStrategy, "集成策略", "传统策略共识+LLM确认"),
    "multi_agent": (MultiAgentStrategy, "多Agent AI策略", "4分析师+辩论+交易员+风控"),
    "adaptive": (AdaptiveStrategy, "自适应策略", "ADX+布林带宽检测市场状态，自动切换子策略"),
    "trend_momentum": (TrendMomentumStrategy, "趋势动量策略", "多指标趋势确认+移动止盈"),
}

_LLM_STRATEGY_CLASSES = (LLMStrategy, EnsembleStrategy, MultiAgentStrategy)


def is_llm_strategy(key: str) -> bool:
    """判断策略是否为 LLM 策略"""
    entry = STRATEGY_REGISTRY.get(key)
    if not entry:
        return False
    return issubclass(entry[0], _LLM_STRATEGY_CLASSES)


__all__ = [
    "BaseStrategy",
    "Signal",
    "SignalType",
    "MACrossStrategy",
    "RSIMeanReversionStrategy",
    "BollingerBandStrategy",
    "LLMStrategy",
    "EnsembleStrategy",
    "MultiAgentStrategy",
    "AdaptiveStrategy",
    "TrendMomentumStrategy",
    "STRATEGY_REGISTRY",
    "is_llm_strategy",
]
