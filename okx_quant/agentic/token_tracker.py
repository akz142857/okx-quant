"""Token 用量追踪器 — 线程安全，跨 Agent 累计统计

两套计数并存，因为它们回答的是不同的问题：

* **lifetime**（``summary()``）—— 进程生命周期累计，供 ``get_usage_summary()`` /
  回测报表 / 会话级预算使用。
* **run-scoped**（``begin_run()`` + ``run_tokens``）—— 单次决策内的用量，供
  **每决策**预算使用。只有 lifetime 计数时，"单次运行上限"这个语义无法实现：
  上限会在跑了几次决策后被永久触发，此后每个 tick 都直接 HOLD。

另外按模型档位（quick / deep）分开计数：strong 模型占 token 的少数、却占**费用的
绝大多数**，只看总 token 数看不见这个 7 倍价差。
"""

import threading
from dataclasses import dataclass

#: 模型档位——quick = 分析师用的廉价模型，deep = 辩论/决策用的强模型
TIER_QUICK = "quick"
TIER_DEEP = "deep"


@dataclass
class _AgentUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    tier: str = TIER_QUICK


class TokenTracker:
    """跨所有 Agent 的 Token 用量追踪器

    线程安全：多个 Analyst 并发调用 record() 时使用锁保护。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._usage: dict[str, _AgentUsage] = {}
        self._lifetime_tokens = 0
        self._run_start_tokens = 0

    def record(
        self,
        agent_name: str,
        input_tokens: int,
        output_tokens: int,
        tier: str = TIER_QUICK,
    ) -> None:
        """记录一次 LLM 调用的 token 用量"""
        with self._lock:
            if agent_name not in self._usage:
                self._usage[agent_name] = _AgentUsage(tier=tier)
            u = self._usage[agent_name]
            u.calls += 1
            u.input_tokens += input_tokens
            u.output_tokens += output_tokens
            u.tier = tier
            self._lifetime_tokens += input_tokens + output_tokens

    # ------------------------------------------------------------------
    # 单次决策（run）作用域
    # ------------------------------------------------------------------

    def begin_run(self) -> None:
        """标记一次新决策的起点；此后 ``run_tokens`` 从 0 重新计算"""
        with self._lock:
            self._run_start_tokens = self._lifetime_tokens

    @property
    def run_tokens(self) -> int:
        """自上次 ``begin_run()`` 以来消耗的 token"""
        with self._lock:
            return self._lifetime_tokens - self._run_start_tokens

    @property
    def lifetime_tokens(self) -> int:
        """进程生命周期累计 token"""
        with self._lock:
            return self._lifetime_tokens

    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """返回用量统计摘要（lifetime 语义）"""
        with self._lock:
            per_agent = {}
            total_calls = 0
            total_input = 0
            total_output = 0
            per_tier = {TIER_QUICK: 0, TIER_DEEP: 0}
            for name, u in self._usage.items():
                per_agent[name] = {
                    "calls": u.calls,
                    "input_tokens": u.input_tokens,
                    "output_tokens": u.output_tokens,
                    "tier": u.tier,
                }
                total_calls += u.calls
                total_input += u.input_tokens
                total_output += u.output_tokens
                per_tier[u.tier] = per_tier.get(u.tier, 0) + u.input_tokens + u.output_tokens

            return {
                "per_agent": per_agent,
                "per_tier_tokens": per_tier,
                "total_calls": total_calls,
                "total_input_tokens": total_input,
                "total_output_tokens": total_output,
                "total_tokens": total_input + total_output,
            }

    def reset(self) -> None:
        """重置所有计数"""
        with self._lock:
            self._usage.clear()
            self._lifetime_tokens = 0
            self._run_start_tokens = 0
