"""StateStore 持久化测试"""

import pytest

from okx_quant.trading.state import StateStore, TraderState


@pytest.mark.unit
def test_save_and_load_roundtrip(tmp_path):
    store = StateStore(state_dir=str(tmp_path))
    state = TraderState(
        inst_id="DOGE-USDT",
        highest_since_entry=0.1234,
        buy_fail_until=1700000000.0,
        sell_fail_until=0.0,
        last_signal_name="BUY",
        last_signal_reason="突破上轨",
        last_logged_signal=("buy", "突破上轨"),
        tick_count=42,
    )
    store.save(state)
    loaded = store.load("DOGE-USDT")
    assert loaded is not None
    assert loaded.inst_id == "DOGE-USDT"
    assert loaded.highest_since_entry == pytest.approx(0.1234)
    assert loaded.last_signal_name == "BUY"
    assert loaded.last_logged_signal == ("buy", "突破上轨")
    assert loaded.tick_count == 42


@pytest.mark.unit
def test_load_missing_returns_none(tmp_path):
    store = StateStore(state_dir=str(tmp_path))
    assert store.load("NONEXISTENT-USDT") is None


@pytest.mark.unit
def test_clear_removes_file(tmp_path):
    store = StateStore(state_dir=str(tmp_path))
    store.save(TraderState(inst_id="BTC-USDT", tick_count=1))
    assert store.load("BTC-USDT") is not None
    store.clear("BTC-USDT")
    assert store.load("BTC-USDT") is None


@pytest.mark.unit
def test_corrupt_file_handled_gracefully(tmp_path):
    store = StateStore(state_dir=str(tmp_path))
    path = tmp_path / "state_BAD-USDT.json"
    path.write_text("not valid json {{{", encoding="utf-8")
    assert store.load("BAD-USDT") is None
