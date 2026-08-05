"""不可信内容哨兵

把来自外部（新闻等）或由外部内容派生（Agent 报告）的文本包进哨兵标记，
并把最明显的 ASCII/Unicode 旁路攻击面压平。

分两类：

* :func:`wrap_untrusted` —— **第一方之外的原始文本**（新闻标题等）。
* :func:`wrap_derived` —— **读过不可信文本的 Agent 写出来的文本**。分析师报告
  属于这一类：新闻分析师的输入有哨兵保护，但它的**输出**会被原样拼进辩论者和
  交易员的 prompt。若不在每一跳重新包裹，任何在摘要中存活下来的指令都会以
  "可信内容"的身份出现在真正产出 ``signal``/``size_pct``/``stop_loss_pct``
  的那个 Agent 面前。

说明：LLM 无硬边界，这里只做输入端加固；真正的纵深防御必须叠加 output 端
（置信度门槛 + size_pct / stop_loss_pct 的代码级 clamp + 风控校验）。
"""

from __future__ import annotations

import re
import unicodedata

_ZERO_WIDTH = dict.fromkeys(map(ord, (
    "​", "‌", "‍", "‎", "‏",
    " ", " ", "‪", "‫", "‬",
    "‭", "‮", "⁠", "⁦", "⁧",
    "⁨", "⁩", "﻿",
)))

#: 单个 untrusted 块硬上限（字符）
UNTRUSTED_MAX_LEN = 4_096
#: 派生内容（Agent 报告）单块上限——报告本身是我们自己的模型写的，比外部原文长，
#: 但仍需要上限，防止某一路 Agent 输出爆量把下游 prompt 撑爆。
DERIVED_MAX_LEN = 8_192

_SENTINEL_PATTERN = re.compile(
    r"\[\s*/?\s*(?:UNTRUSTED_?CONTENT|AGENT_?REPORT)\s*\]",
    flags=re.IGNORECASE,
)


def _sanitize(text: str, max_len: int) -> str:
    """归一化 + 去零宽 + 中和伪哨兵 + 长度截断

    1. NFKC 归一化 —— 全宽括号等同形体等价化为 ASCII
    2. 移除零宽 / 方向控制字符 —— 防止分词旁路
    3. 正则宽松匹配并中和任何伪哨兵变体
    4. 长度硬截断 —— 防御 token 洪水
    """
    safe = unicodedata.normalize("NFKC", text)
    safe = safe.translate(_ZERO_WIDTH)
    safe = _SENTINEL_PATTERN.sub("[UC]", safe)
    if len(safe) > max_len:
        safe = safe[:max_len] + "\n...[truncated]"
    return safe


def wrap_untrusted(text: str, max_len: int = UNTRUSTED_MAX_LEN) -> str:
    """用哨兵包裹来自不可信源的原始内容（新闻等）"""
    if not text:
        return "[UNTRUSTED_CONTENT]\n(empty)\n[/UNTRUSTED_CONTENT]"
    return f"[UNTRUSTED_CONTENT]\n{_sanitize(text, max_len)}\n[/UNTRUSTED_CONTENT]"


def wrap_derived(text: str, max_len: int = DERIVED_MAX_LEN) -> str:
    """用哨兵包裹由不可信输入派生出来的内容（Agent 报告、辩论记录）"""
    if not text:
        return "[AGENT_REPORT]\n(empty)\n[/AGENT_REPORT]"
    return f"[AGENT_REPORT]\n{_sanitize(text, max_len)}\n[/AGENT_REPORT]"
