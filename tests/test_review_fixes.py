"""回归测试 —— 覆盖代码审查后修复的关键 bug

每个用例对应审查报告中的一项修复，防止回归。
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from okx_quant.agentic.agents import _parse_json
from okx_quant.backtest.engine import BacktestEngine
from okx_quant.exchange.fake import FakeExchange
from okx_quant.exchange.base import InstrumentInfo
from okx_quant.indicators.momentum import cci, rsi
from okx_quant.llm.client import LLMClient, LLMConfig
from okx_quant.risk.manager import RiskConfig, RiskManager
from okx_quant.strategy.base import BaseStrategy, Signal, SignalType
from okx_quant.trading.orders import OrderExecutor


# ----------------------------------------------------------------------
# RSI 纯上涨返回 100（而非 NaN）
# ----------------------------------------------------------------------

def test_rsi_pure_uptrend_returns_100():
    s = pd.Series(np.arange(1.0, 60.0))  # 严格单调递增 → 无下跌
    r = rsi(s, 14)
    assert not np.isnan(r.iloc[-1])
    assert r.iloc[-1] == pytest.approx(100.0)


def test_rsi_still_within_bounds(synthetic_ohlcv):
    r = rsi(synthetic_ohlcv["close"], 14).dropna()
    assert ((r >= 0) & (r <= 100)).all()


def test_cci_flat_series_is_nan_not_inf():
    s = pd.Series([100.0] * 40)
    df = pd.DataFrame({"high": s, "low": s, "close": s})
    out = cci(df, 20)
    # 平价序列 mean_dev=0 → 显式 NaN，不应是 inf
    assert not np.isinf(out.iloc[-1])
    assert np.isnan(out.iloc[-1])


# ----------------------------------------------------------------------
# RiskManager.try_reserve_buy 原子预留
# ----------------------------------------------------------------------

def test_try_reserve_buy_respects_max_open_positions():
    risk = RiskManager(RiskConfig(max_open_positions=1, max_position_pct=1.0, min_order_usdt=1.0))
    risk.initialize(10_000)

    ok, _ = risk.try_reserve_buy("BTC-USDT", size_usdt=100, price=50_000, current_equity=10_000)
    assert ok
    # 槽位已占用 → 第二个不同币种被拒
    ok2, msg2 = risk.try_reserve_buy("ETH-USDT", size_usdt=100, price=3_000, current_equity=10_000)
    assert not ok2
    assert "上限" in msg2


def test_try_reserve_buy_rejects_duplicate_inst():
    risk = RiskManager(RiskConfig(max_open_positions=5, max_position_pct=1.0, min_order_usdt=1.0))
    risk.initialize(10_000)
    assert risk.try_reserve_buy("BTC-USDT", 100, 50_000, 10_000)[0]
    ok, msg = risk.try_reserve_buy("BTC-USDT", 100, 50_000, 10_000)
    assert not ok and "已有持仓" in msg


def test_try_reserve_buy_release_frees_slot():
    risk = RiskManager(RiskConfig(max_open_positions=1, max_position_pct=1.0, min_order_usdt=1.0))
    risk.initialize(10_000)
    assert risk.try_reserve_buy("BTC-USDT", 100, 50_000, 10_000)[0]
    risk.remove_position("BTC-USDT")  # 模拟下单失败释放
    # 释放后槽位可再次被占用
    assert risk.try_reserve_buy("ETH-USDT", 100, 3_000, 10_000)[0]


def test_try_reserve_buy_enforces_max_position_pct():
    risk = RiskManager(RiskConfig(max_open_positions=1, max_position_pct=0.10, min_order_usdt=1.0))
    risk.initialize(10_000)
    ok, msg = risk.try_reserve_buy("BTC-USDT", size_usdt=5_000, price=50_000, current_equity=10_000)
    assert not ok and "最大仓位" in msg


# ----------------------------------------------------------------------
# OrderExecutor 用真实成交价锚定入场价 + 平移止损止盈
# ----------------------------------------------------------------------

def _make_executor(ex: FakeExchange, risk: RiskManager) -> OrderExecutor:
    ex.set_instrument(InstrumentInfo("BTC-USDT", "BTC", "USDT", lot_size=0.0, min_size=0.0))
    return OrderExecutor(exchange=ex, inst_id="BTC-USDT", risk=risk)


def test_buy_uses_fill_price_and_shifts_sl_tp():
    ex = FakeExchange()
    ex.set_fill_price(50_500)  # 实际成交价高于信号价 50_000（+1% 滑点）
    risk = RiskManager(RiskConfig(max_open_positions=1))
    oe = _make_executor(ex, risk)

    ok = oe.buy(price=50_000, size_coin=0.01, sl=49_000, tp=51_000, reason="t")
    assert ok
    pos = risk.get_position("BTC-USDT")
    assert pos.entry_price == pytest.approx(50_500)
    # sl/tp 按 50_500/50_000 比例平移，保持原始 ±2% 缓冲
    assert pos.stop_loss == pytest.approx(49_000 * 1.01, rel=1e-6)
    assert pos.take_profit == pytest.approx(51_000 * 1.01, rel=1e-6)


def test_buy_without_fill_price_falls_back_to_signal_price():
    ex = FakeExchange()  # fill_price 默认 0
    risk = RiskManager(RiskConfig(max_open_positions=1))
    oe = _make_executor(ex, risk)
    oe.buy(price=50_000, size_coin=0.01, sl=49_000, tp=51_000, reason="t")
    pos = risk.get_position("BTC-USDT")
    assert pos.entry_price == pytest.approx(50_000)
    assert pos.stop_loss == pytest.approx(49_000)


def test_buy_zero_size_rejected():
    ex = FakeExchange()
    risk = RiskManager(RiskConfig(max_open_positions=1))
    oe = _make_executor(ex, risk)
    assert oe.buy(price=50_000, size_coin=0.0, sl=0, tp=0, reason="t") is False
    assert not ex.orders  # 不应发出订单


# ----------------------------------------------------------------------
# agents._parse_json 支持嵌套 JSON 与代码围栏
# ----------------------------------------------------------------------

def test_parse_json_nested_object():
    out = _parse_json('{"signal":"BUY","ctx":{"debug":true,"n":1}}')
    assert out["signal"] == "BUY"
    assert out["ctx"]["n"] == 1


def test_parse_json_with_markdown_fence():
    out = _parse_json('```json\n{"signal":"SELL","confidence":0.7}\n```')
    assert out["signal"] == "SELL"
    assert out["confidence"] == 0.7


def test_parse_json_embedded_in_prose():
    out = _parse_json('分析结论如下：{"signal":"HOLD"} 仅供参考')
    assert out["signal"] == "HOLD"


# ----------------------------------------------------------------------
# LLMClient 不就地修改传入的 config
# ----------------------------------------------------------------------

def test_llm_client_does_not_mutate_config():
    cfg = LLMConfig(provider="openai")  # base_url/model 留空
    assert cfg.base_url == ""
    client = LLMClient(cfg)
    # 调用方的 config 不应被写回默认值
    assert cfg.base_url == ""
    assert cfg.model == ""
    # 但 client 内部应用了默认值
    assert client.config.base_url
    assert client.config.model


# ----------------------------------------------------------------------
# 回测：止损出场计入滑点（亏损更真实）
# ----------------------------------------------------------------------

def _sl_trigger_df() -> pd.DataFrame:
    # 构造：先平稳让策略买入，最后一根 K 线开盘仍在 100（不跳空），
    # 盘中 low 下探至 85 击穿止损 90 → 触发"盘中止损"而非"跳空止损"。
    n = 40
    ts = pd.date_range("2026-01-01", periods=n, freq="1h", tz="UTC")
    open_ = np.full(n, 100.0)
    close = np.concatenate([np.full(n - 1, 100.0), [88.0]])
    high = np.full(n, 101.0)
    low = np.concatenate([np.full(n - 1, 99.0), [85.0]])
    return pd.DataFrame({
        "ts": ts, "open": open_, "high": high, "low": low,
        "close": close, "vol": np.full(n, 100.0), "vol_ccy": np.full(n, 10000.0),
    })


def test_backtest_sl_exit_applies_slippage():
    class BuyThenHold(BaseStrategy):
        name = "BuyOnce"

        def __init__(self):
            super().__init__({})
            self._bought = False

        def generate_signal(self, df, inst_id):
            price = df["close"].iloc[-1]
            if not self._bought and len(df) >= 5:
                self._bought = True
                return Signal(SignalType.BUY, inst_id, price=price, size_pct=1.0,
                              stop_loss=90.0, take_profit=1000.0)
            return Signal(SignalType.HOLD, inst_id, price=price)

    df = _sl_trigger_df()
    slippage = 0.01
    engine = BacktestEngine(initial_capital=10000, fee_rate=0.0, slippage=slippage)
    result = engine.run(df, BuyThenHold(), "BTC-USDT", warmup=3)
    closed = [t for t in result.trades if not t.is_open]
    assert closed, "应至少有一笔平仓交易"
    sl_trade = closed[0]
    assert "止损" in sl_trade.reason_close
    # 出场价应为触发价 90 * (1 - slippage)，而非精确 90
    assert sl_trade.exit_price == pytest.approx(90.0 * (1 - slippage), rel=1e-6)
