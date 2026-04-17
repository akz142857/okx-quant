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
import re
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# inst_id 白名单：字母/数字/连字符/下划线；任何不匹配即拒绝
_SAFE_INST_ID = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


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
        # 解析为绝对路径，便于后续的 "路径必须位于此目录下" 校验
        self._dir = os.path.abspath(state_dir)
        os.makedirs(self._dir, exist_ok=True)

    def _path(self, inst_id: str) -> str:
        """构造状态文件路径；inst_id 必须通过白名单校验且结果路径位于 state_dir 之内"""
        if not _SAFE_INST_ID.match(inst_id):
            raise ValueError(f"非法的 inst_id（仅允许字母数字/-/_）: {inst_id!r}")
        path = os.path.abspath(os.path.join(self._dir, f"state_{inst_id}.json"))
        # 二次防护：规范化后仍必须以 state_dir 为前缀
        if not path.startswith(self._dir + os.sep):
            raise ValueError(f"非法的 inst_id 路径逃逸: {inst_id!r}")
        return path

    def load(self, inst_id: str) -> Optional[TraderState]:
        try:
            path = self._path(inst_id)
        except ValueError as e:
            logger.warning("[状态] %s", e)
            return None
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
        try:
            path = self._path(state.inst_id)
        except ValueError as e:
            logger.warning("[状态] %s", e)
            return
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
        try:
            path = self._path(inst_id)
        except ValueError:
            return
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass
