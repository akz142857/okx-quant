"""LLM record/replay 缓存测试

覆盖：
1. key 覆盖所有影响输出的入参（含 temperature / max_tokens，不含 api_key）
2. record 后 replay 命中，不再发起真实调用
3. 失败响应不落盘（避免把一次网络抖动固化成"这个输入就是失败的"）
4. replay 严格模式未命中时绝不真实调用
5. 损坏的缓存文件按未命中处理，不抛异常
"""

from __future__ import annotations

import pytest

from okx_quant.llm.cache import LLMCache
from okx_quant.llm.client import LLMConfig, LLMResponse

pytestmark = pytest.mark.unit


class CountingLLM:
    """记录真实调用次数的假客户端"""

    def __init__(self, config: LLMConfig, resp: LLMResponse | None = None):
        self.config = config
        self.calls = 0
        self._resp = resp or LLMResponse(
            content="hello", model="m", input_tokens=10, output_tokens=5
        )

    def chat(self, system: str, user: str) -> LLMResponse:
        self.calls += 1
        return self._resp


def _cfg(**kw) -> LLMConfig:
    base = {
        "provider": "openai", "api_key": "sk-secret", "model": "gpt-4o-mini",
        "base_url": "https://api.openai.com/v1", "temperature": 0.3, "max_tokens": 1024,
    }
    base.update(kw)
    return LLMConfig(**base)


# ---------------------------------------------------------------------------
# key
# ---------------------------------------------------------------------------

def test_key_changes_with_temperature_and_max_tokens():
    """只用 system+user+model 做 key 会把不同采样温度的结果混同"""
    k = LLMCache.make_key(_cfg(), "sys", "usr")
    assert LLMCache.make_key(_cfg(temperature=0.0), "sys", "usr") != k
    assert LLMCache.make_key(_cfg(max_tokens=2048), "sys", "usr") != k
    assert LLMCache.make_key(_cfg(model="other"), "sys", "usr") != k
    assert LLMCache.make_key(_cfg(provider="deepseek"), "sys", "usr") != k
    assert LLMCache.make_key(_cfg(), "sys", "usr2") != k
    assert LLMCache.make_key(_cfg(), "sys2", "usr") != k


def test_key_ignores_api_key():
    """同一份缓存应能跨密钥复用，且密钥绝不参与 key 材料"""
    assert (
        LLMCache.make_key(_cfg(api_key="sk-a"), "s", "u")
        == LLMCache.make_key(_cfg(api_key="sk-b"), "s", "u")
    )


# ---------------------------------------------------------------------------
# record / replay
# ---------------------------------------------------------------------------

def test_record_then_replay_hits_without_real_call(tmp_path):
    cache = LLMCache(tmp_path / "c")
    client = LLMCache.wrap(CountingLLM(_cfg()), cache)

    first = client.chat("sys", "usr")
    assert first.content == "hello"
    assert client._client.calls == 1

    second = client.chat("sys", "usr")
    assert second.content == "hello"
    assert second.input_tokens == 10
    assert client._client.calls == 1, "第二次应命中缓存，不得再发起真实调用"

    stats = cache.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["writes"] == 1


def test_cache_survives_new_instance(tmp_path):
    """缓存是磁盘级的：换进程/换实例仍应命中"""
    cache_dir = tmp_path / "c"
    LLMCache.wrap(CountingLLM(_cfg()), LLMCache(cache_dir)).chat("sys", "usr")

    client2 = LLMCache.wrap(CountingLLM(_cfg()), LLMCache(cache_dir))
    client2.chat("sys", "usr")
    assert client2._client.calls == 0


def test_api_key_never_written_to_disk(tmp_path):
    cache = LLMCache(tmp_path / "c")
    LLMCache.wrap(CountingLLM(_cfg(api_key="sk-super-secret")), cache).chat("s", "u")
    blob = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "c").rglob("*.json"))
    assert blob
    assert "sk-super-secret" not in blob


def test_error_response_not_cached(tmp_path):
    cache = LLMCache(tmp_path / "c")
    failing = CountingLLM(_cfg(), LLMResponse(error="boom"))
    client = LLMCache.wrap(failing, cache)

    client.chat("sys", "usr")
    client.chat("sys", "usr")
    assert failing.calls == 2, "失败响应不得落盘，否则一次抖动被永久固化"
    assert cache.stats()["skipped_errors"] == 2
    assert cache.stats()["writes"] == 0


def test_replay_mode_never_calls_upstream(tmp_path):
    """严格复现模式：未命中直接返回错误响应，绝不偷偷产生真实调用"""
    client = LLMCache.wrap(CountingLLM(_cfg()), LLMCache(tmp_path / "c", mode="replay"))
    resp = client.chat("sys", "usr")
    assert not resp.ok
    assert "replay miss" in resp.error
    assert client._client.calls == 0


def test_off_mode_returns_client_unchanged(tmp_path):
    raw = CountingLLM(_cfg())
    assert LLMCache.wrap(raw, LLMCache(tmp_path / "c", mode="off")) is raw
    assert LLMCache.wrap(raw, None) is raw


def test_corrupt_cache_file_treated_as_miss(tmp_path):
    cache = LLMCache(tmp_path / "c")
    inner = CountingLLM(_cfg())
    client = LLMCache.wrap(inner, cache)
    client.chat("sys", "usr")

    for path in (tmp_path / "c").rglob("*.json"):
        path.write_text("{not json", encoding="utf-8")

    client.chat("sys", "usr")
    assert inner.calls == 2, "损坏的缓存应按未命中处理而非抛异常"


def test_unknown_mode_rejected(tmp_path):
    with pytest.raises(ValueError):
        LLMCache(tmp_path / "c", mode="bogus")  # type: ignore[arg-type]


def test_config_passthrough(tmp_path):
    """包装后仍要能拿到真实模型名（model_name / 报表依赖它）"""
    client = LLMCache.wrap(CountingLLM(_cfg(model="gpt-4o-mini")), LLMCache(tmp_path / "c"))
    assert client.config.model == "gpt-4o-mini"
