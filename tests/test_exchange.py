"""Exchange Protocol / FakeExchange 行为测试"""

import pandas as pd
import pytest

from okx_quant.exchange import BalanceSnapshot, InstrumentInfo
from okx_quant.exchange.fake import FakeExchange


@pytest.mark.unit
def test_fake_exchange_balance_snapshot_structure():
    ex = FakeExchange(quote_ccy="USDT")
    ex.set_balance(total=12000.0, quote_avail=5000.0)
    ex.set_holding("BTC", balance=0.1, available=0.1)
    snap = ex.get_balance()
    assert isinstance(snap, BalanceSnapshot)
    assert snap.total_equity_quote == 12000.0
    assert snap.available_quote == 5000.0
    # 应同时包含 USDT 与 BTC 两个持仓
    tickers = {h.ccy for h in snap.holdings}
    assert tickers == {"USDT", "BTC"}


@pytest.mark.unit
def test_non_quote_holdings_filters_quote_and_zero():
    ex = FakeExchange(quote_ccy="USDT")
    ex.set_balance(total=10000, quote_avail=10000)
    ex.set_holding("ETH", balance=0.5, available=0.5)
    ex.set_holding("DOGE", balance=0.0, available=0.0)  # 零余额
    non_quote = ex.get_balance().non_quote_holdings("USDT")
    assert {h.ccy for h in non_quote} == {"ETH"}


@pytest.mark.unit
def test_fake_exchange_order_records():
    ex = FakeExchange()
    result = ex.place_market_order("BTC-USDT", "buy", 0.001)
    assert result.ord_id == "fake-1"
    assert result.side == "buy"
    assert ex.orders[0].inst_id == "BTC-USDT"


@pytest.mark.unit
def test_fake_exchange_instrument_defaults_from_inst_id():
    ex = FakeExchange()
    info = ex.get_instrument("ETH-USDT")
    assert isinstance(info, InstrumentInfo)
    assert info.base_ccy == "ETH"
    assert info.quote_ccy == "USDT"


@pytest.mark.unit
def test_fake_exchange_candles_empty_when_unset():
    ex = FakeExchange()
    df = ex.get_candles("NONE-USDT", "1H", 100)
    assert df.empty


@pytest.mark.unit
def test_fake_exchange_candles_returns_set_data():
    ex = FakeExchange()
    df = pd.DataFrame({
        "ts": pd.date_range("2026-01-01", periods=5, freq="1h", tz="UTC"),
        "open": [1, 2, 3, 4, 5],
        "high": [2, 3, 4, 5, 6],
        "low": [0, 1, 2, 3, 4],
        "close": [1, 2, 3, 4, 5],
        "vol": [10, 20, 30, 40, 50],
    })
    ex.set_candles("BTC-USDT", "1H", df)
    out = ex.get_candles("BTC-USDT", "1H", 3)
    assert len(out) == 3
    assert out["close"].tolist() == [3, 4, 5]
