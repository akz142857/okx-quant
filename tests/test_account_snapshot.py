"""账户快照安全语义测试。"""

import pytest

from okx_quant.exchange.fake import FakeExchange
from okx_quant.trading.account import AccountSnapshot


@pytest.mark.unit
def test_initial_balance_failure_is_fail_closed():
    class BrokenExchange(FakeExchange):
        def get_balance(self):  # type: ignore[override]
            raise RuntimeError("network down")

    account = AccountSnapshot(BrokenExchange())
    with pytest.raises(RuntimeError, match="拒绝启动"):
        account.total_equity(force=True)


@pytest.mark.unit
def test_refresh_failure_keeps_last_trusted_snapshot():
    class FlakyExchange(FakeExchange):
        broken = False

        def get_balance(self):  # type: ignore[override]
            if self.broken:
                raise RuntimeError("network down")
            return super().get_balance()

    ex = FlakyExchange()
    ex.set_balance(total=10_000, quote_avail=5_000)
    account = AccountSnapshot(ex, ttl_seconds=0)
    assert account.total_equity(force=True) == 10_000

    ex.broken = True
    assert account.total_equity(force=True) == 10_000
