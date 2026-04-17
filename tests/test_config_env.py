"""配置环境变量替换测试"""

import os

import pytest

from okx_quant.config import expand_env


@pytest.mark.unit
def test_expand_env_replaces_simple_var(monkeypatch):
    monkeypatch.setenv("FOO_KEY", "secret123")
    out = expand_env({"api_key": "${FOO_KEY}"})
    assert out == {"api_key": "secret123"}


@pytest.mark.unit
def test_expand_env_default_when_missing(monkeypatch):
    monkeypatch.delenv("MISSING_KEY", raising=False)
    out = expand_env({"api_key": "${MISSING_KEY:-fallback}"})
    assert out == {"api_key": "fallback"}


@pytest.mark.unit
def test_expand_env_recurses_into_nested(monkeypatch):
    monkeypatch.setenv("LLM_KEY", "sk-x")
    nested = {"llm": {"api_key": "${LLM_KEY}", "models": ["${LLM_KEY}", "raw"]}}
    out = expand_env(nested)
    assert out["llm"]["api_key"] == "sk-x"
    assert out["llm"]["models"] == ["sk-x", "raw"]


@pytest.mark.unit
def test_expand_env_leaves_non_strings_alone():
    data = {"timeout": 30, "flag": True, "nested": None}
    assert expand_env(data) == data


@pytest.mark.unit
def test_expand_env_missing_no_default(monkeypatch):
    monkeypatch.delenv("UNSET_VAR", raising=False)
    out = expand_env("${UNSET_VAR}")
    assert out == ""
