"""测试公共 fixtures"""

from __future__ import annotations

import os

import numpy as np
import pandas as pd
import pytest

_CRITICAL_SKIPS: set[str] = set()


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Record required platform tests skipped by the CI environment."""
    if (
        os.environ.get("OKX_QUANT_FORBID_CRITICAL_TEST_SKIPS") == "1"
        and report.skipped
        and "linux_ci_required" in report.keywords
    ):
        _CRITICAL_SKIPS.add(report.nodeid)


def pytest_sessionfinish(
    session: pytest.Session,
    exitstatus: int,
) -> None:
    """Fail CI when a required Linux platform test did not execute."""
    if _CRITICAL_SKIPS:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep(
                "=",
                "critical Linux CI tests were skipped",
                red=True,
            )
            for nodeid in sorted(_CRITICAL_SKIPS):
                reporter.write_line(nodeid, red=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture
def synthetic_ohlcv() -> pd.DataFrame:
    """生成 200 根合成 OHLCV，价格呈缓涨 + 随机扰动"""
    rng = np.random.default_rng(42)
    n = 200
    ts = pd.date_range("2026-01-01", periods=n, freq="1h", tz="UTC")
    drift = np.linspace(100.0, 130.0, n)
    noise = rng.normal(0, 1.0, n).cumsum() * 0.3
    close = drift + noise
    open_ = np.concatenate([[close[0]], close[:-1]])
    spread = rng.uniform(0.2, 0.8, n)
    high = np.maximum(open_, close) + spread
    low = np.minimum(open_, close) - spread
    vol = rng.uniform(100, 500, n)
    return pd.DataFrame({
        "ts": ts,
        "open": open_,
        "high": high,
        "low": low,
        "close": close,
        "vol": vol,
        "vol_ccy": vol * close,
    })
