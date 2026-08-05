"""多 Agent 策略配置"""

import dataclasses
from dataclasses import dataclass


@dataclass
class AgenticConfig:
    """AgenticPipeline 配置参数

    Attributes:
        debate_rounds: 多空辩论轮数（每轮 Bull 和 Bear 各发言一次）
        analyst_timeout: 单个分析师超时时间（秒）
        analyst_max_workers: 分析师并发度，0 = 全部并行（默认）。写死一个小于
            分析师数量的值会让它们分多波跑，墙钟时间成倍增加，并挤占
            as_completed 的共享超时预算。
        debate_timeout: 单个辩论者超时时间（秒）
        confidence_threshold: 低于此置信度 → HOLD
        max_total_tokens: **会话级**（进程生命周期累计）token 上限，0 = 不限。
            注意 config.yaml 里默认写的是 0，也就是开箱即用状态下没有会话级上限；
            真正兜底的是下面这条 per-decision 上限。
        max_decision_tokens: **单次决策**的 token 上限，0 = 不限。与
            max_total_tokens 不同，它每次决策重新计数，因此不会"跑几次之后就
            永久触发、此后每个 tick 都 HOLD"。默认值写在代码里，不依赖 yaml
            是否配置——这是防单次决策失控的最后一道确定性防线。
        min_stop_loss_pct / max_stop_loss_pct: 止损距离的**代码级**上下界。
            LLM 输出的 stop_loss_pct 原先只有 min(交易员, 风控) 取严，没有边界：
            0.5 等于把止损挂在入场价 50% 之下（形同没有止损），0.0005 则进场
            即被扫。size_pct 早就有 clamp，这里把同样的待遇补给止损/止盈。
        min_take_profit_pct / max_take_profit_pct: 止盈距离的代码级上下界。
    """

    debate_rounds: int = 2
    analyst_timeout: int = 120
    analyst_max_workers: int = 0
    debate_timeout: int = 120
    confidence_threshold: float = 0.6
    max_total_tokens: int = 0
    max_decision_tokens: int = 120_000

    min_stop_loss_pct: float = 0.005
    max_stop_loss_pct: float = 0.10
    min_take_profit_pct: float = 0.005
    max_take_profit_pct: float = 0.50

    @classmethod
    def from_dict(cls, d: dict) -> "AgenticConfig":
        known_fields = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known_fields})
