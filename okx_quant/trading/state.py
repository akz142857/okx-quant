"""实盘执行器状态持久化

保存/恢复那些 "不在交易所账户里" 但一旦丢失会影响交易决策的本地状态：
- 移动止盈基准（highest_since_entry）
- 买入/卖出失败冷却计时器
- 最近一次信号（用于重启后去重日志）
- 策略指标快照（仅用于 dashboard 连续性）

存储格式为单个 JSON 文件，位于 state_dir/state_{inst_id}.json，使用原子写入
（写到 .tmp 然后 rename）避免崩溃时半写入。
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TraderState:
    """单个 LiveTrader 的可持久化状态"""

    inst_id: str = ""
    highest_since_entry: float = 0.0
    buy_fail_until: float = 0.0
    sell_fail_until: float = 0.0
    last_signal_name: str = "HOLD"
    last_signal_reason: str = ""
    last_logged_signal: tuple[str, str] = ("", "")
    tick_count: int = 0
    last_update_ts: float = 0.0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "TraderState":
        known = {
            "inst_id", "highest_since_entry", "buy_fail_until", "sell_fail_until",
            "last_signal_name", "last_signal_reason", "last_logged_signal",
            "tick_count", "last_update_ts", "extra",
        }
        filtered = {k: v for k, v in d.items() if k in known}
        # JSON 不支持 tuple，恢复为 tuple
        sig = filtered.get("last_logged_signal")
        if isinstance(sig, list) and len(sig) == 2:
            filtered["last_logged_signal"] = tuple(sig)
        return cls(**filtered)


class StateStore:
    """基于本地 JSON 的状态仓库

    线程安全不是必需的（每个 inst_id 单独文件，由其 LiveTrader 独占访问）。
    """

    def __init__(self, state_dir: str = "state"):
        self._dir = state_dir
        os.makedirs(self._dir, exist_ok=True)

    def _path(self, inst_id: str) -> str:
        safe = inst_id.replace("/", "-")
        return os.path.join(self._dir, f"state_{safe}.json")

    def load(self, inst_id: str) -> Optional[TraderState]:
        path = self._path(inst_id)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            state = TraderState.from_dict(data)
            state.inst_id = state.inst_id or inst_id
            return state
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("[状态] 加载 %s 失败: %s", path, e)
            return None

    def save(self, state: TraderState) -> None:
        if not state.inst_id:
            return
        path = self._path(state.inst_id)
        try:
            # 原子写入：tmp → rename
            fd, tmp = tempfile.mkstemp(
                prefix=".state_", suffix=".tmp", dir=self._dir,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state.to_dict(), f, ensure_ascii=False, default=str)
            os.replace(tmp, path)
        except OSError as e:
            logger.warning("[状态] 保存 %s 失败: %s", path, e)

    def clear(self, inst_id: str) -> None:
        path = self._path(inst_id)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass
