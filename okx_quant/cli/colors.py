"""ANSI 颜色工具 — 纯 stdlib，自动检测 TTY，支持 NO_COLOR 环境变量"""

import os
import sys

_COLOR_ENABLED: bool = (
    hasattr(sys.stdout, "isatty")
    and sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
)


def _wrap(code: str, text: str) -> str:
    if not _COLOR_ENABLED:
        return text
    return f"\033[{code}m{text}\033[0m"


def green(text: str) -> str:
    return _wrap("32", text)


def red(text: str) -> str:
    return _wrap("31", text)


def yellow(text: str) -> str:
    return _wrap("33", text)


def cyan(text: str) -> str:
    return _wrap("36", text)


def gray(text: str) -> str:
    return _wrap("90", text)


def bold(text: str) -> str:
    return _wrap("1", text)


def dim(text: str) -> str:
    return _wrap("2", text)


def colored_pnl(value: float) -> str:
    """正值绿色，负值红色，零灰色"""
    if value > 0:
        return green(f"+{value:.2f}")
    elif value < 0:
        return red(f"{value:.2f}")
    return gray(f"{value:.2f}")


def colored_pnl_pct(value: float) -> str:
    """带百分号的盈亏"""
    if value > 0:
        return green(f"+{value:.1f}%")
    elif value < 0:
        return red(f"{value:.1f}%")
    return gray(f"{value:.1f}%")


def colored_signal(name: str) -> str:
    """BUY 绿，SELL 红，HOLD 灰"""
    upper = name.upper()
    if upper == "BUY":
        return green(upper)
    elif upper == "SELL":
        return red(upper)
    return gray(upper)


def colored_regime(regime: str) -> str:
    """趋势=cyan，震荡高波=yellow，其余=gray"""
    if "趋势" in regime:
        return cyan(regime)
    elif "高波" in regime:
        return yellow(regime)
    return gray(regime)
