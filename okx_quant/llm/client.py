"""统一 LLM 客户端 — 支持 OpenAI / DeepSeek / Claude"""

import dataclasses
import threading
from dataclasses import dataclass
from enum import Enum

import requests


class LLMProvider(str, Enum):
    """支持的 LLM 提供商"""

    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    CLAUDE = "claude"


@dataclass
class LLMConfig:
    """LLM 提供商配置"""

    provider: str = LLMProvider.OPENAI
    api_key: str = ""
    model: str = ""          # 留空则使用提供商默认模型
    base_url: str = ""       # 留空则使用提供商默认地址
    temperature: float = 0.3
    max_tokens: int = 1024
    timeout: int = 30

    @classmethod
    def from_dict(cls, d: dict) -> "LLMConfig":
        known_fields = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known_fields})


@dataclass
class LLMResponse:
    """LLM 调用结果"""

    content: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.content)


# 提供商默认配置
_PROVIDER_DEFAULTS: dict[str, dict] = {
    LLMProvider.OPENAI: {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
    },
    LLMProvider.DEEPSEEK: {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
    },
    LLMProvider.CLAUDE: {
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-4-6",
    },
}


class LLMClient:
    """统一 LLM 客户端

    根据 provider 自动分派到 OpenAI 兼容接口或 Claude 接口。
    OpenAI / DeepSeek 共用 /chat/completions，Claude 使用 /v1/messages。
    """

    def __init__(self, config: LLMConfig):
        # 不就地修改调用方传入的 config（旧实现会把默认值写回共享的 LLMConfig，
        # 造成意外副作用）；用 replace 生成私有副本。
        defaults = _PROVIDER_DEFAULTS.get(config.provider, {})
        self.config = dataclasses.replace(
            config,
            base_url=config.base_url or defaults.get("base_url", "https://api.openai.com/v1"),
            model=config.model or defaults.get("model", "gpt-4o-mini"),
        )

        # requests.Session 非线程安全；多 Agent 管线会从 4 个分析师线程并发
        # 调用同一个 LLMClient，故每线程持有独立 Session。
        self._local = threading.local()

    def _session_for_thread(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            self._local.session = s
        return s

    def chat(self, system: str, user: str) -> LLMResponse:
        """发送对话请求，返回 LLMResponse"""
        if self.config.provider == LLMProvider.CLAUDE:
            return self._chat_claude(system, user)
        return self._chat_openai(system, user)

    # ------------------------------------------------------------------
    # OpenAI / DeepSeek 兼容接口
    # ------------------------------------------------------------------

    def _chat_openai(self, system: str, user: str) -> LLMResponse:
        url = f"{self.config.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        try:
            resp = self._session_for_thread().post(
                url, json=payload, headers=headers, timeout=self.config.timeout
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            return LLMResponse(error=f"OpenAI API error: {e}")

        choice = data.get("choices", [{}])[0]
        usage = data.get("usage", {})
        return LLMResponse(
            content=choice.get("message", {}).get("content", ""),
            model=data.get("model", self.config.model),
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )

    # ------------------------------------------------------------------
    # Claude (Anthropic Messages API)
    # ------------------------------------------------------------------

    def _chat_claude(self, system: str, user: str) -> LLMResponse:
        url = f"{self.config.base_url.rstrip('/')}/v1/messages"
        # sk-ant-* 开头为 API Key，其余视为 OAuth token（Claude Max 订阅）
        api_key = self.config.api_key
        if api_key.startswith("sk-ant-"):
            auth_header = {"x-api-key": api_key}
        else:
            auth_header = {"Authorization": f"Bearer {api_key}"}
        headers = {
            **auth_header,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.config.model,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        try:
            resp = self._session_for_thread().post(
                url, json=payload, headers=headers, timeout=self.config.timeout
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            return LLMResponse(error=f"Claude API error: {e}")

        content_blocks = data.get("content", [])
        text = "".join(
            block.get("text", "") for block in content_blocks if block.get("type") == "text"
        )
        usage = data.get("usage", {})
        return LLMResponse(
            content=text,
            model=data.get("model", self.config.model),
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
        )
