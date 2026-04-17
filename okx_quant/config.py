"""配置加载与环境变量替换

支持 ${VAR} 或 ${VAR:-default} 语法在 YAML 中引用环境变量：

    okx:
      api_key: ${OKX_API_KEY}
      secret_key: ${OKX_SECRET_KEY:-}
"""

from __future__ import annotations

import os
import re
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(value: Any) -> Any:
    """递归替换字符串中的 ${VAR} / ${VAR:-default} 为环境变量"""
    if isinstance(value, str):
        return _ENV_PATTERN.sub(_replace, value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


def _replace(match: re.Match) -> str:
    var = match.group(1)
    default = match.group(2)
    return os.environ.get(var, default if default is not None else "")


def load_yaml(path: str) -> dict:
    """读取 YAML 并做环境变量替换"""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return expand_env(raw)
