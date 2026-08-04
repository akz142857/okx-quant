"""投资论点快照 — 对标 AI Berkshire 的 thesis-tracker。

建仓（BUY）时把**完整决策证据**（4 位分析师报告 + 多空辩论 + 交易员/风控理由
+ 数据质量评级）落盘成一份 JSON，平仓复盘时可回放"当初买它的理由现在还成立吗"。

这是把黑箱的 LLM 决策变成可归因、可复盘序列的关键——也是回答"业绩多少来自 alpha、
多少来自 beta"的唯一手段。落盘失败绝不能影响交易主流程（调用方须 try/except）。
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime

logger = logging.getLogger(__name__)

# 与 trading/state.py、trading/decision_log.py 一致的文件名白名单，防路径穿越。
_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9_\-]")

THESIS_SCHEMA = "okx-quant.agentic-thesis/v1"


def build_thesis(
    inst_id: str,
    price: float,
    result: dict,
    evidence: dict | None = None,
    *,
    timestamp: datetime | None = None,
) -> dict:
    """把一次 BUY 决策组装成可持久化的论点快照。"""
    ts = timestamp or datetime.now()
    evidence = evidence or {}
    return {
        "schema": THESIS_SCHEMA,
        "inst_id": inst_id,
        "created_at": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "entry_price": price,
        "decision": {
            "signal": result.get("signal"),
            "confidence": result.get("confidence"),
            "size_pct": result.get("size_pct"),
            "stop_loss_pct": result.get("stop_loss_pct"),
            "take_profit_pct": result.get("take_profit_pct"),
            "reason": result.get("reason"),
        },
        "data_quality": evidence.get("data_quality") or result.get("data_quality"),
        "evidence": {
            "analyst_reports": evidence.get("analyst_reports", {}),
            "debate": evidence.get("debate", ""),
            "trader": evidence.get("trader", {}),
            "risk": evidence.get("risk", {}),
        },
    }


class ThesisStore:
    """把论点快照写入 ``{log_dir}/thesis_{inst_id}_{YYYYMMDD_HHMMSS}.json``。"""

    def __init__(self, log_dir: str = "logs/thesis"):
        self._log_dir = log_dir

    def save(self, thesis: dict) -> str | None:
        """落盘论点快照，返回文件路径；失败返回 None（不抛异常）。"""
        try:
            log_dir = os.path.abspath(self._log_dir)
            os.makedirs(log_dir, exist_ok=True)

            safe_id = _UNSAFE_FILENAME_CHARS.sub("-", str(thesis.get("inst_id", ""))) or "unknown"
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            path = os.path.abspath(os.path.join(log_dir, f"thesis_{safe_id}_{stamp}.json"))
            # 规范化后仍必须位于 log_dir 之内（防御纵深）
            if not path.startswith(log_dir + os.sep):
                raise ValueError(f"非法的论点快照路径: inst_id={thesis.get('inst_id')!r}")

            with open(path, "w", encoding="utf-8") as f:
                json.dump(thesis, f, ensure_ascii=False, indent=2, default=str)
            return path
        except Exception as e:  # noqa: BLE001 — 落盘绝不能影响交易主流程
            logger.warning("[Thesis] 论点快照落盘失败: %s", e)
            return None
