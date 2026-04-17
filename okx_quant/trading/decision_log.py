"""决策日志 CSV 记录器

每根 K 线 + 信号类型只记录一次（去重），写入后立即 flush。
文件路径: {log_dir}/decisions_{inst_id}_{YYYYMMDD}.csv

同时支持作为 context manager 使用，确保异常路径文件句柄关闭。
"""

from __future__ import annotations

import csv
import logging
import os
from collections import OrderedDict
from datetime import datetime
from typing import Any, Optional

from okx_quant.strategy.base import Signal

logger = logging.getLogger(__name__)


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

        os.makedirs(self._log_dir, exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d")
        safe_id = self._inst_id.replace("/", "-")
        path = os.path.join(self._log_dir, f"decisions_{safe_id}_{date_str}.csv")

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
