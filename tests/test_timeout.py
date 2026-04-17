"""run_with_timeout 单元测试"""

import time

import pytest

from okx_quant.utils import SignalTimeout, run_with_timeout


@pytest.mark.unit
def test_returns_result_when_fast():
    assert run_with_timeout(lambda x: x * 2, 1.0, 5) == 10


@pytest.mark.unit
def test_raises_on_timeout():
    def slow():
        time.sleep(2.0)
        return "done"

    with pytest.raises(SignalTimeout):
        run_with_timeout(slow, 0.2)


@pytest.mark.unit
def test_propagates_exceptions():
    def boom():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        run_with_timeout(boom, 1.0)


@pytest.mark.unit
def test_zero_timeout_runs_synchronously():
    # timeout_s <= 0 → 直接调用，不开线程
    assert run_with_timeout(lambda: 42, 0) == 42
