"""Token 用量追踪器 — 线程安全，跨 Agent 累计统计"""

import threading
from dataclasses import dataclass, field


@dataclass
class _AgentUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


class TokenTracker:
    """跨所有 Agent 的 Token 用量追踪器

    线程安全：多个 Analyst 并发调用 record() 时使用锁保护。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._usage: dict[str, _AgentUsage] = {}

    def record(self, agent_name: str, input_tokens: int, output_tokens: int) -> None:
        """记录一次 LLM 调用的 token 用量"""
        with self._lock:
            if agent_name not in self._usage:
                self._usage[agent_name] = _AgentUsage()
            u = self._usage[agent_name]
            u.calls += 1
            u.input_tokens += input_tokens
            u.output_tokens += output_tokens

    def summary(self) -> dict:
        """返回用量统计摘要"""
        with self._lock:
            per_agent = {}
            total_calls = 0
            total_input = 0
            total_output = 0
            for name, u in self._usage.items():
                per_agent[name] = {
                    "calls": u.calls,
                    "input_tokens": u.input_tokens,
                    "output_tokens": u.output_tokens,
                }
                total_calls += u.calls
                total_input += u.input_tokens
                total_output += u.output_tokens

            return {
                "per_agent": per_agent,
                "total_calls": total_calls,
                "total_input_tokens": total_input,
                "total_output_tokens": total_output,
                "total_tokens": total_input + total_output,
            }

    def reset(self) -> None:
        """重置所有计数"""
        with self._lock:
            self._usage.clear()
