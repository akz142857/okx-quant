"""决策日志 CSV 记录器

每根 K 线 + 信号类型只记录一次（去重），写入后立即 flush。
文件路径: {log_dir}/decisions_{inst_id}_{YYYYMMDD}.csv

同时支持作为 context manager 使用，确保异常路径文件句柄关闭。
"""

from __future__ import annotations

import csv
import logging
import os
import re
from collections import OrderedDict
from datetime import datetime
from typing import Any, Optional

from okx_quant.strategy.base import Signal

logger = logging.getLogger(__name__)

# 文件名中允许出现的 inst_id 字符；其余一律替换为 '-'，防止路径穿越。
# 与 state.py 的白名单保持一致（防御纵深，不依赖单一校验点）。
_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9_\-]")


class DecisionLogger:
    _BASE_COLUMNS = [
        "timestamp", "inst_id", "signal", "price", "reason",
        "stop_loss", "take_profit", "size_pct",
    ]
    _SEEN_MAX_ENTRIES = 2048  # LRU 上限，防止长时间运行时内存无界增长

    def __init__(self, inst_id: str, log_dir: str = "logs"):
        self._inst_id = inst_id
        self._log_dir = log_dir
        self._seen: "OrderedDict[tuple, None]" = OrderedDict()
        self._file = None
        self._writer: Optional[Any] = None
        self._current_columns: list[str] = []

    def _ensure_file(self, extra_keys: list[str]) -> None:
        columns = self._BASE_COLUMNS + sorted(extra_keys)
        if self._file is not None and columns == self._current_columns:
            return

        if self._file is not None:
            self._file.close()

        log_dir = os.path.abspath(self._log_dir)
        os.makedirs(log_dir, exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d")
        # 全字符白名单清洗（不只是替换 '/'），杜绝 '..'、'\\'、空字节等穿越
        safe_id = _UNSAFE_FILENAME_CHARS.sub("-", self._inst_id) or "unknown"
        path = os.path.abspath(os.path.join(log_dir, f"decisions_{safe_id}_{date_str}.csv"))
        # 二次防护：规范化后仍必须位于 log_dir 之内
        if not path.startswith(log_dir + os.sep):
            raise ValueError(f"非法的决策日志路径: inst_id={self._inst_id!r}")

        file_exists = os.path.isfile(path) and os.path.getsize(path) > 0
        self._file = open(path, "a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._file)
        self._current_columns = columns

        if not file_exists:
            self._writer.writerow(columns)
            self._file.flush()

    def log(self, signal: Signal, candle_ts) -> bool:
        """记录一条决策日志，返回是否写入（False = 去重跳过）"""
        key = (candle_ts, signal.signal.value)
        if key in self._seen:
            self._seen.move_to_end(key)
            return False
        self._seen[key] = None
        while len(self._seen) > self._SEEN_MAX_ENTRIES:
            self._seen.popitem(last=False)

        extra = signal.extra or {}
        extra_keys = [k for k in extra if k not in self._BASE_COLUMNS]
        self._ensure_file(extra_keys)

        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            signal.inst_id,
            signal.signal.value.upper(),
            signal.price,
            signal.reason,
            signal.stop_loss,
            signal.take_profit,
            signal.size_pct,
        ]
        for col in sorted(extra_keys):
            row.append(extra.get(col, ""))

        self._writer.writerow(row)
        self._file.flush()
        return True

    def close(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            except OSError as e:
                logger.warning("[日志] 关闭决策日志失败: %s", e)
            finally:
                self._file = None
                self._writer = None

    def __enter__(self) -> "DecisionLogger":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
