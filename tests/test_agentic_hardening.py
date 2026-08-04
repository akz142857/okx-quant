"""多 Agent 管线加固测试（借鉴 AI Berkshire 的反偏见/防幻觉机制）。

覆盖：
1. 置信度阈值由 pipeline 代码强制（不只靠 wrapper）
2. 风控只能收紧不能放大（仓位/止损）
3. 数据充分度评级 + 置信度天花板
4. 缺失指标渲染为 N/A（而非伪装的 0）
5. 建仓论点快照落盘
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest

from okx_quant.agentic.config import AgenticConfig
from okx_quant.agentic.data_quality import assess_data_sufficiency
from okx_quant.agentic.pipeline import AgenticPipeline
from okx_quant.agentic.prompts import build_technical_prompt
from okx_quant.agentic.thesis import ThesisStore, build_thesis
from okx_quant.llm.client import LLMResponse

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeConfig:
    model = "fake-model"


class FakeLLM:
    """按 system prompt 内容路由：交易员/风控返回指定 JSON，其余返回短文本。"""

    def __init__(self, trader_json: dict, risk_json: dict):
        self._trader = json.dumps(trader_json)
        self._risk = json.dumps(risk_json)
        self.config = _FakeConfig()

    def chat(self, system: str, user: str) -> LLMResponse:
        if "final trading decision" in system:
            content = self._trader
        elif "risk manager reviewing" in system:
            content = self._risk
        else:
            content = "analysis: neutral, confidence 0.5"
        return LLMResponse(content=content, model="fake", input_tokens=1, output_tokens=1)


def _pipeline(trader_json, risk_json, **cfg):
    llm = FakeLLM(trader_json, risk_json)
    config = AgenticConfig(debate_rounds=1, **cfg)
    return AgenticPipeline(quick_llm=llm, deep_llm=llm, config=config)


def _run(pipe, data_quality=None):
    return pipe.run(
        indicators={"inst_id": "DOGE-USDT"},
        recent_candles="ts | O:1 H:1 L:1 C:1 V:1",
        inst_id="DOGE-USDT",
        news_text="",
        data_quality=data_quality,
    )


# ---------------------------------------------------------------------------
# 1. 置信度阈值代码强制
# ---------------------------------------------------------------------------

def test_low_confidence_buy_is_forced_to_hold_by_pipeline():
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
              "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.3, "size_pct": 0.5,
            "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "r"}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6))
    assert result["signal"] == "HOLD"
    assert "阈值" in result["reason"]


def test_high_confidence_buy_passes():
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
              "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.8, "size_pct": 0.5,
            "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "r"}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6))
    assert result["signal"] == "BUY"


# ---------------------------------------------------------------------------
# 2. 风控只能收紧不能放大
# ---------------------------------------------------------------------------

def test_risk_cannot_increase_size_or_widen_stop():
    # 交易员提议保守，风控（错误地）试图放大仓位、放宽止损
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.3,
              "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.9,
            "stop_loss_pct": 0.05, "take_profit_pct": 0.04, "reason": "r"}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6))
    assert result["signal"] == "BUY"
    assert result["size_pct"] == 0.3        # min(0.3, 0.9)
    assert result["stop_loss_pct"] == 0.02  # min(0.02, 0.05) —— 不得放宽


def test_risk_can_still_reduce_size():
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.8,
              "stop_loss_pct": 0.03, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.2,
            "stop_loss_pct": 0.01, "take_profit_pct": 0.04, "reason": "r"}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6))
    assert result["size_pct"] == 0.2        # 收紧生效
    assert result["stop_loss_pct"] == 0.01  # 收紧生效


# ---------------------------------------------------------------------------
# 3. 数据质量置信度天花板
# ---------------------------------------------------------------------------

def test_data_quality_ceiling_caps_confidence():
    trader = {"signal": "BUY", "confidence": 0.95, "size_pct": 0.5,
              "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.95, "size_pct": 0.5,
            "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "r"}
    dq = {"grade": "B", "confidence_ceiling": 0.5}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.3), data_quality=dq)
    assert result["signal"] == "BUY"
    assert result["confidence"] == 0.5  # 被天花板压下来


def test_c_grade_ceiling_below_threshold_forces_hold():
    trader = {"signal": "BUY", "confidence": 0.95, "size_pct": 0.5,
              "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.95, "size_pct": 0.5,
            "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "r"}
    dq = {"grade": "C", "confidence_ceiling": 0.4}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6), data_quality=dq)
    assert result["signal"] == "HOLD"


def _make_df(n, *, flat=False, zero_vol=False, stale=False):
    ts = pd.date_range("2024-01-01", periods=n, freq="1h")
    if stale or flat:
        close = np.full(n, 100.0)
    else:
        close = 100 + np.cumsum(np.random.default_rng(0).normal(0, 1, n))
    if flat:
        high = close.copy()
        low = close.copy()
    else:
        high = close + 1
        low = close - 1
    vol = np.zeros(n) if zero_vol else np.full(n, 1000.0)
    return pd.DataFrame({"ts": ts, "open": close, "high": high,
                         "low": low, "close": close, "vol": vol})


def test_assess_grade_a_for_rich_data():
    dq = assess_data_sufficiency(_make_df(250))
    assert dq.grade == "A"
    assert dq.confidence_ceiling == 1.0


def test_assess_grade_c_for_short_history():
    dq = assess_data_sufficiency(_make_df(50))
    assert dq.grade == "C"
    assert dq.confidence_ceiling == 0.4


def test_assess_grade_c_for_flat_illiquid():
    dq = assess_data_sufficiency(_make_df(250, flat=True, stale=True))
    assert dq.grade == "C"


def test_assess_empty_df():
    dq = assess_data_sufficiency(_make_df(0))
    assert dq.grade == "C"
    assert dq.bars == 0


# ---------------------------------------------------------------------------
# 4. 缺失指标渲染为 N/A
# ---------------------------------------------------------------------------

def test_missing_indicators_render_as_na_not_zero():
    indicators = {
        "inst_id": "DOGE-USDT",
        "price": 0.1,
        # rsi 缺失 -> None；atr 为 NaN
        "rsi": None,
        "atr": float("nan"),
    }
    text = build_technical_prompt(indicators, "candles")
    assert "RSI(14): N/A" in text
    assert "ATR(14): N/A" in text
    # 现价存在则正常显示
    assert "Current Price: 0.1" in text


# ---------------------------------------------------------------------------
# 5. 建仓论点快照落盘
# ---------------------------------------------------------------------------

def test_thesis_save_and_content(tmp_path):
    result = {"signal": "BUY", "confidence": 0.8, "size_pct": 0.3,
              "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "买它",
              "data_quality": {"grade": "A"}}
    evidence = {"analyst_reports": {"Technical Analysis": "bullish"},
                "debate": "bull vs bear", "trader": {"signal": "BUY"},
                "risk": {"signal": "BUY"}, "data_quality": {"grade": "A"}}
    thesis = build_thesis("DOGE-USDT", 0.1, result, evidence)
    path = ThesisStore(str(tmp_path)).save(thesis)
    assert path is not None
    saved = json.loads((tmp_path / path.split("/")[-1]).read_text(encoding="utf-8"))
    assert saved["inst_id"] == "DOGE-USDT"
    assert saved["decision"]["signal"] == "BUY"
    assert saved["evidence"]["debate"] == "bull vs bear"
    assert saved["data_quality"]["grade"] == "A"


def test_thesis_store_rejects_path_traversal(tmp_path):
    # 恶意 inst_id 不得逃出目录；save 内部清洗后仍应落在 tmp_path 内
    thesis = build_thesis("../../etc/DOGE", 0.1, {"signal": "BUY"}, {})
    path = ThesisStore(str(tmp_path)).save(thesis)
    assert path is not None
    assert path.startswith(str(tmp_path.resolve()) if hasattr(tmp_path, "resolve") else str(tmp_path))


def test_pipeline_result_carries_evidence_and_data_quality():
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
              "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
            "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "r"}
    dq = {"grade": "A", "confidence_ceiling": 1.0}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6), data_quality=dq)
    assert result["data_quality"] == dq
    assert "evidence" in result
    assert result["evidence"]["trader"]["signal"] == "BUY"
