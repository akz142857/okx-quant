"""带硬超时的同步调用封装

用于包裹可能阻塞的同步函数（如 LLM 请求），超时后立即抛错并返回，
避免主循环被长时间阻塞。

注意：被包裹的函数仍会在后台线程继续运行直至结束（Python 无法强制
杀死线程），但主调用方已经恢复，不会影响后续逻辑。
"""

from __future__ import annotations

import logging
import os
import queue
import threading
from collections.abc import Callable

logger = logging.getLogger(__name__)


class TimeoutError(Exception):  # noqa: A001 — 有意与 builtin 同名以便上层捕获
    """同步调用超时"""


# Python 无法安全杀死线程；用有界守护线程代替 ThreadPoolExecutor。
# 标准 executor 的非守护 worker 会让“永不返回”的第三方调用阻止进程退出。
_MAX_IN_FLIGHT = max(8, min(32, (os.cpu_count() or 4) * 2))
_SLOTS = threading.BoundedSemaphore(_MAX_IN_FLIGHT)


def run_with_timeout[T](
    func: Callable[..., T], timeout_s: float, *args, **kwargs
) -> T:
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

    if not _SLOTS.acquire(blocking=False):
        raise TimeoutError("超时调用槽已耗尽，拒绝排队")
    outcome: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def target() -> None:
        try:
            outcome.put((True, func(*args, **kwargs)))
        except BaseException as exc:
            outcome.put((False, exc))
        finally:
            _SLOTS.release()

    thread = threading.Thread(
        target=target,
        name="okxq-timeout-call",
        daemon=True,
    )
    thread.start()
    try:
        succeeded, value = outcome.get(timeout=timeout_s)
    except queue.Empty as exc:
        raise TimeoutError(f"调用超时 {timeout_s}s") from exc
    if succeeded:
        return value  # type: ignore[return-value]
    raise value  # type: ignore[misc]
