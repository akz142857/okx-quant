"""多 Agent 策略 — 8 个专业化 Agent

BaseAgent 封装 LLM 调用 + token 追踪。
各子类实现特定的分析/决策方法，通过 prompts 模块构建 prompt。
"""

import json
import logging
import re

from okx_quant.llm.client import LLMClient, LLMResponse

from .prompts import (
    BEAR_RESEARCHER_SYSTEM,
    BULL_RESEARCHER_SYSTEM,
    FUNDAMENTALS_ANALYST_SYSTEM,
    NEWS_ANALYST_SYSTEM,
    RISK_MANAGER_SYSTEM,
    SENTIMENT_ANALYST_SYSTEM,
    TECHNICAL_ANALYST_SYSTEM,
    TRADER_AGENT_SYSTEM,
    build_debate_prompt,
    build_fundamentals_prompt,
    build_news_prompt,
    build_risk_manager_prompt,
    build_sentiment_prompt,
    build_technical_prompt,
    build_trader_prompt,
)
from .token_tracker import TIER_DEEP, TIER_QUICK, TokenTracker

logger = logging.getLogger(__name__)


def _parse_json(content: str) -> dict | None:
    """从 LLM 返回内容中解析 JSON 决策。

    依次尝试：直接解析 → 剥离 markdown 代码围栏 → 括号配对提取第一个
    完整对象。旧实现用 ``\\{[^{}]*\\}`` 正则，遇到嵌套对象会被截断成第一个
    平铺对象（如 ``{"a":1,"b":{...}}`` 解析失败），这里改为深度计数配对。
    """
    if not content:
        return None
    text = content.strip()

    # 剥离 ```json ... ``` 代码围栏
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 括号配对：找到第一个 '{' 及其匹配的 '}'（支持嵌套）
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


class BaseAgent:
    """Agent 基类 — 封装 LLM 调用与 token 追踪

    Args:
        tier: 模型档位（``quick`` / ``deep``）。只用于用量归类——strong 模型占
            token 的少数却占费用的绝大多数，分开计数才看得见这个差距。
    """

    #: 子类可覆盖；辩论/决策类 Agent 走 deep
    tier: str = TIER_QUICK

    def __init__(self, name: str, llm: LLMClient, tracker: TokenTracker):
        self.name = name
        self.llm = llm
        self.tracker = tracker

    def run(self, system: str, user: str) -> str:
        """调用 LLM，记录 token 用量，返回文本内容。失败返回空字符串。"""
        try:
            resp: LLMResponse = self.llm.chat(system, user)
        except Exception as e:
            logger.warning("[%s] LLM 调用异常: %s", self.name, e)
            return ""

        self.tracker.record(self.name, resp.input_tokens, resp.output_tokens, self.tier)

        if not resp.ok:
            logger.warning("[%s] LLM 调用失败: %s", self.name, resp.error)
            return ""
        return resp.content


# =====================================================================
# 4 个分析师 Agent（使用 cheap model）
# =====================================================================

class TechnicalAnalyst(BaseAgent):
    """技术分析师 — 分析技术指标与价格结构"""

    def analyze(self, indicators: dict, recent_candles: str) -> str:
        user_prompt = build_technical_prompt(indicators, recent_candles)
        return self.run(TECHNICAL_ANALYST_SYSTEM, user_prompt)


class SentimentAnalyst(BaseAgent):
    """情绪分析师 — 从价格行为推断市场情绪"""

    def analyze(self, indicators: dict, recent_candles: str) -> str:
        user_prompt = build_sentiment_prompt(indicators, recent_candles)
        return self.run(SENTIMENT_ANALYST_SYSTEM, user_prompt)


class NewsAnalyst(BaseAgent):
    """新闻分析师 — 评估新闻对市场的潜在影响"""

    def analyze(self, news_text: str, inst_id: str) -> str:
        user_prompt = build_news_prompt(news_text, inst_id)
        return self.run(NEWS_ANALYST_SYSTEM, user_prompt)


class FundamentalsAnalyst(BaseAgent):
    """基本面分析师 — 评估市场条件与流动性"""

    def analyze(self, indicators: dict) -> str:
        user_prompt = build_fundamentals_prompt(indicators)
        return self.run(FUNDAMENTALS_ANALYST_SYSTEM, user_prompt)


# =====================================================================
# 2 个辩论 Agent（使用 strong model）
# =====================================================================

class BullResearcher(BaseAgent):
    """多头研究员 — 构建看涨论点"""

    tier = TIER_DEEP

    def argue(self, analyst_reports: dict[str, str],
              opponent_argument: str = "", round_num: int = 1) -> str:
        user_prompt = build_debate_prompt(analyst_reports, opponent_argument, round_num)
        return self.run(BULL_RESEARCHER_SYSTEM, user_prompt)


class BearResearcher(BaseAgent):
    """空头研究员 — 构建看跌/谨慎论点"""

    tier = TIER_DEEP

    def argue(self, analyst_reports: dict[str, str],
              opponent_argument: str = "", round_num: int = 1) -> str:
        user_prompt = build_debate_prompt(analyst_reports, opponent_argument, round_num)
        return self.run(BEAR_RESEARCHER_SYSTEM, user_prompt)


# =====================================================================
# 交易员 + 风控 Agent（使用 strong model）
# =====================================================================

class TraderAgent(BaseAgent):
    """交易员 — 综合所有分析做出交易决策"""

    tier = TIER_DEEP

    def decide(self, analyst_reports: dict[str, str], debate_transcript: str,
               inst_id: str) -> dict | None:
        user_prompt = build_trader_prompt(analyst_reports, debate_transcript, inst_id)
        content = self.run(TRADER_AGENT_SYSTEM, user_prompt)
        if not content:
            return None
        return _parse_json(content)


class RiskManagerAgent(BaseAgent):
    """风控经理 — 审核交易信号，可否决或调整"""

    tier = TIER_DEEP

    def review(self, proposed_signal: dict, portfolio_state: dict) -> dict | None:
        user_prompt = build_risk_manager_prompt(proposed_signal, portfolio_state)
        content = self.run(RISK_MANAGER_SYSTEM, user_prompt)
        if not content:
            return None
        return _parse_json(content)
