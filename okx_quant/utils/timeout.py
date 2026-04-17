"""带硬超时的同步调用封装

用于包裹可能阻塞的同步函数（如 LLM 请求），超时后立即抛错并返回，
避免主循环被长时间阻塞。

注意：被包裹的函数仍会在后台线程继续运行直至结束（Python 无法强制
杀死线程），但主调用方已经恢复，不会影响后续逻辑。
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class TimeoutError(Exception):  # noqa: A001 — 有意与 builtin 同名以便上层捕获
    """同步调用超时"""


# 复用一个守护线程池，避免每次调用都创建/销毁线程
_EXECUTOR = ThreadPoolExecutor(
    max_workers=4,
    thread_name_prefix="okxq-timeout",
)


def run_with_timeout(func: Callable[..., T], timeout_s: float, *args, **kwargs) -> T:
    """在独立线程中执行 func，最多等待 timeout_s 秒。

    Args:
        func: 目标可调用对象
        timeout_s: 超时秒数；<=0 表示不限时（同步直接调用）
        *args/**kwargs: 传递给 func

    Raises:
        TimeoutError: 超时未返回
        Exception: func 内部异常原样抛出
    """
    if timeout_s is None or timeout_s <= 0:
        return func(*args, **kwargs)

    future = _EXECUTOR.submit(func, *args, **kwargs)
    try:
        return future.result(timeout=timeout_s)
    except FutureTimeout as exc:
        # 不能强制终止线程，只能放任后台运行
        future.cancel()
        raise TimeoutError(f"调用超时 {timeout_s}s") from exc
