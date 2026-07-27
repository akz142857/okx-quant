"""研究生产者共享的策略身份定义。"""

from __future__ import annotations

from collections.abc import Iterable

from okx_quant.research.costs import canonical_manifest_hash
from okx_quant.strategy.base import BaseStrategy


def strategy_type_name(strategy: BaseStrategy) -> str:
    """返回不受参数面或 walk-forward 调度影响的策略类型身份。"""
    return f"{type(strategy).__module__}.{type(strategy).__qualname__}"


def build_strategy_family_manifest(
    strategies: Iterable[BaseStrategy],
) -> dict:
    """构建跨研究评估可比较的策略家族 manifest。"""
    strategy_types = sorted({
        strategy_type_name(strategy) for strategy in strategies
    })
    if not strategy_types:
        raise ValueError("strategy family 至少需要一个策略实例")
    return {
        "version": 1,
        "strategy_types": strategy_types,
    }


def strategy_family_hash(manifest: dict) -> str:
    """哈希由 :func:`build_strategy_family_manifest` 生成的 manifest。"""
    return canonical_manifest_hash(manifest)
