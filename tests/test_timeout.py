"""run_with_timeout 单元测试"""

import threading
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


@pytest.mark.unit
def test_never_returning_call_uses_daemon_and_does_not_block_caller():
    release = threading.Event()
    observed_daemon = []

    def blocked():
        observed_daemon.append(threading.current_thread().daemon)
        release.wait()

    started = time.monotonic()
    try:
        with pytest.raises(SignalTimeout):
            run_with_timeout(blocked, 0.02)
        assert time.monotonic() - started < 0.5
        assert observed_daemon == [True]
    finally:
        release.set()
