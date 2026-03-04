"""多 Agent 策略配置"""

import dataclasses
from dataclasses import dataclass


@dataclass
class AgenticConfig:
    """AgenticPipeline 配置参数

    Attributes:
        debate_rounds: 多空辩论轮数（每轮 Bull 和 Bear 各发言一次）
        analyst_timeout: 单个分析师超时时间（秒）
        confidence_threshold: 低于此置信度 → HOLD
        max_total_tokens: 单次 pipeline 运行的 token 安全上限
    """

    debate_rounds: int = 2
    analyst_timeout: int = 120
    confidence_threshold: float = 0.6
    max_total_tokens: int = 50000

    @classmethod
    def from_dict(cls, d: dict) -> "AgenticConfig":
        known_fields = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known_fields})
