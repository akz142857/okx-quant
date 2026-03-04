"""加密货币新闻获取 — CryptoPanic 免费 API，带内存缓存"""

import time
from dataclasses import dataclass

import requests


@dataclass
class NewsItem:
    """单条新闻"""

    title: str = ""
    source: str = ""
    published_at: str = ""
    sentiment: str = ""  # positive / negative / neutral / ""


class CryptoNewsFetcher:
    """CryptoPanic 新闻获取器

    - 5 分钟内存缓存
    - 永不抛异常，出错返回空列表
    """

    BASE_URL = "https://cryptopanic.com/api/free/v1/posts/"
    CACHE_TTL = 300  # 5 分钟

    def __init__(self, auth_token: str = ""):
        self.auth_token = auth_token
        self._session = requests.Session()
        self._cache: dict[str, tuple[float, list[NewsItem]]] = {}

    def get_news(self, coin: str = "BTC", limit: int = 5) -> list[NewsItem]:
        """获取指定币种的最新新闻

        Args:
            coin: 币种符号，如 BTC / ETH / DOGE
            limit: 返回条数上限

        Returns:
            NewsItem 列表，出错返回空列表
        """
        cache_key = coin.upper()
        now = time.time()

        # 命中缓存
        if cache_key in self._cache:
            ts, items = self._cache[cache_key]
            if now - ts < self.CACHE_TTL:
                return items[:limit]

        items = self._fetch(coin)
        self._cache[cache_key] = (now, items)
        return items[:limit]

    def _fetch(self, coin: str) -> list[NewsItem]:
        params: dict[str, str | int] = {
            "currencies": coin.upper(),
            "kind": "news",
            "public": "true",
        }
        if self.auth_token:
            params["auth_token"] = self.auth_token

        try:
            resp = self._session.get(self.BASE_URL, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        results: list[NewsItem] = []
        for post in data.get("results", []):
            votes = post.get("votes", {})
            sentiment = self._detect_sentiment(votes)
            results.append(
                NewsItem(
                    title=post.get("title", ""),
                    source=post.get("source", {}).get("title", ""),
                    published_at=post.get("published_at", ""),
                    sentiment=sentiment,
                )
            )
        return results

    @staticmethod
    def _detect_sentiment(votes: dict) -> str:
        """根据投票判断情绪倾向"""
        positive = votes.get("positive", 0)
        negative = votes.get("negative", 0)
        if positive > negative:
            return "positive"
        if negative > positive:
            return "negative"
        return "neutral"

    @staticmethod
    def format_for_prompt(news: list[NewsItem], max_chars: int = 500) -> str:
        """将新闻格式化为 Prompt 文本

        Args:
            news: NewsItem 列表
            max_chars: 最大字符数

        Returns:
            格式化后的文本，空列表返回 "No recent news available."
        """
        if not news:
            return "No recent news available."

        lines: list[str] = []
        total = 0
        for item in news:
            sentiment_tag = f"[{item.sentiment}]" if item.sentiment else ""
            line = f"- {item.title} ({item.source}) {sentiment_tag}"
            if total + len(line) > max_chars:
                break
            lines.append(line)
            total += len(line)

        return "\n".join(lines) if lines else "No recent news available."
