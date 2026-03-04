"""多 Agent LLM 交易策略模块

灵感来自 TradingAgents 论文（Columbia University），
通过多个专业化 AI Agent 协作辩论来产生更高质量的交易信号。

公共 API:
    AgenticPipeline — 编排 8 个 Agent 的完整管线
    AgenticConfig   — 管线配置参数
"""

from .config import AgenticConfig
from .pipeline import AgenticPipeline
from .token_tracker import TokenTracker

__all__ = ["AgenticPipeline", "AgenticConfig", "TokenTracker"]
