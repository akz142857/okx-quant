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


# ---------------------------------------------------------------------------
# 6. 止损/止盈的代码级夹取
#    min(交易员, 风控) 只保证"风控不得放宽"，不构成边界：0.5 等于把止损挂在
#    入场价 50% 之下（形同没有止损），0.0005 则进场即被扫。
# ---------------------------------------------------------------------------

def test_absurdly_wide_stop_loss_is_clamped():
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
              "stop_loss_pct": 0.5, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
            "stop_loss_pct": 0.5, "take_profit_pct": 0.04, "reason": "r"}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6))
    assert result["signal"] == "BUY"
    assert result["stop_loss_pct"] == AgenticConfig().max_stop_loss_pct


def test_absurdly_tight_stop_loss_is_clamped():
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
              "stop_loss_pct": 0.0005, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
            "stop_loss_pct": 0.0005, "take_profit_pct": 0.04, "reason": "r"}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6))
    assert result["stop_loss_pct"] == AgenticConfig().min_stop_loss_pct


def test_take_profit_is_clamped():
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
              "stop_loss_pct": 0.02, "take_profit_pct": 99.0, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
            "stop_loss_pct": 0.02, "take_profit_pct": 99.0, "reason": "r"}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6))
    assert result["take_profit_pct"] == AgenticConfig().max_take_profit_pct


def test_in_range_stop_loss_is_untouched():
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
              "stop_loss_pct": 0.03, "take_profit_pct": 0.06, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
            "stop_loss_pct": 0.03, "take_profit_pct": 0.06, "reason": "r"}
    result = _run(_pipeline(trader, risk, confidence_threshold=0.6))
    assert result["stop_loss_pct"] == 0.03
    assert result["take_profit_pct"] == 0.06


# ---------------------------------------------------------------------------
# 7. Token 预算：per-decision 每次重新计数，会话级在发起调用前拦截
# ---------------------------------------------------------------------------

def _buy_pipeline(**cfg):
    trader = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
              "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "t"}
    risk = {"signal": "BUY", "confidence": 0.9, "size_pct": 0.5,
            "stop_loss_pct": 0.02, "take_profit_pct": 0.04, "reason": "r"}
    return _pipeline(trader, risk, confidence_threshold=0.6, **cfg)


def test_decision_budget_resets_each_run():
    """旧实现用 lifetime 计数做"单次运行上限"，跑几次后会永久触发 HOLD"""
    pipe = _buy_pipeline(max_decision_tokens=1000)
    for _ in range(5):
        assert _run(pipe)["signal"] == "BUY"
    assert pipe.tracker.lifetime_tokens > 0


def test_decision_budget_aborts_within_one_run():
    # FakeLLM 每次调用记 2 token；上限设 1 → 分析师阶段后即超限
    result = _run(_buy_pipeline(max_decision_tokens=1))
    assert result["signal"] == "HOLD"
    assert "预算" in result["reason"]


def test_session_budget_blocks_before_any_call():
    # FakeLLM 每次调用记 2 token；debate_rounds=1 时一次决策 8 次调用 = 16 token
    pipe = _buy_pipeline(max_total_tokens=16, max_decision_tokens=0)
    assert _run(pipe)["signal"] == "BUY"      # 首次跑满，累计 token 恰好达上限
    used = pipe.tracker.lifetime_tokens
    assert used >= 16

    result = _run(pipe)
    assert result["signal"] == "HOLD"
    assert "未发起调用" in result["reason"]
    assert pipe.tracker.lifetime_tokens == used, "会话预算耗尽后不得再发起任何调用"


def test_tracker_separates_quick_and_deep_tiers():
    pipe = _buy_pipeline()
    _run(pipe)
    per_tier = pipe.tracker.summary()["per_tier_tokens"]
    assert per_tier["quick"] > 0
    assert per_tier["deep"] > 0


# ---------------------------------------------------------------------------
# 8. _run_analysts 的并发/命名机制
#    三处硬编码（max_workers=4 / 共享墙钟预算 / fn.__name__ 反查显示名）在
#    分析师数量超过 4 时会造成：并发度不足、后半批被误判超时、失败路径 key 退化。
# ---------------------------------------------------------------------------

def _extra_analyst_pipeline(n_extra: int, delay: float = 0.0, fail: bool = False):
    """在标准 4 分析师之外再挂 n_extra 个假分析师"""
    import time as _time

    pipe = _buy_pipeline()
    base = pipe._build_analyst_tasks

    def patched(indicators, recent_candles, inst_id, news_text):
        tasks = base(indicators, recent_candles, inst_id, news_text)

        def make(i):
            def fn():
                if delay:
                    _time.sleep(delay)
                if fail:
                    raise RuntimeError("boom")
                return f"extra report {i}"
            return fn

        tasks += [(f"Extra Analysis {i}", make(i)) for i in range(n_extra)]
        return tasks

    pipe._build_analyst_tasks = patched
    return pipe


def test_all_analysts_run_in_parallel_regardless_of_count():
    """并发度跟随任务数：8 个分析师不应分两波跑"""
    import time as _time

    pipe = _extra_analyst_pipeline(4, delay=0.1)
    t0 = _time.perf_counter()
    reports = pipe._run_analysts({"inst_id": "DOGE-USDT"}, "c", "DOGE-USDT", "")
    elapsed = _time.perf_counter() - t0

    assert len(reports) == 8
    # 若并发度写死 4，8 个 0.1s 任务要跑两波 ≈ 0.2s
    assert elapsed < 0.18, f"疑似分波执行，耗时 {elapsed:.3f}s"


def test_extra_analysts_are_not_falsely_marked_timeout():
    """共享墙钟预算按波次放大：不得把已完成的响应标成超时丢掉"""
    pipe = _extra_analyst_pipeline(4)
    reports = pipe._run_analysts({"inst_id": "DOGE-USDT"}, "c", "DOGE-USDT", "")
    assert len(reports) == 8
    assert not any("超时" in r for r in reports.values())


def test_failure_path_uses_display_name_not_internal_name():
    """失败路径的 key 必须与成功路径一致，否则 analyst_reports 出现两套 key"""
    pipe = _extra_analyst_pipeline(2, fail=True)
    reports = pipe._run_analysts({"inst_id": "DOGE-USDT"}, "c", "DOGE-USDT", "")

    assert "Extra Analysis 0" in reports
    assert reports["Extra Analysis 0"] == "(分析师调用失败)"
    # 不得出现 lambda / 内部函数名之类的退化 key
    assert all(k[0].isupper() for k in reports), reports.keys()
    assert "<lambda>" not in reports


def test_analyst_max_workers_can_be_pinned():
    pipe = _buy_pipeline(analyst_max_workers=1)
    reports = pipe._run_analysts({"inst_id": "DOGE-USDT"}, "c", "DOGE-USDT", "")
    # 串行执行仍应拿到全部 4 份报告，且不被误判超时
    assert len(reports) == 4
    assert not any("超时" in r for r in reports.values())
