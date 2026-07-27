"""OKX 生产事件网关。"""

from importlib import import_module

__all__ = ["PrivateStreamService"]


def __getattr__(name: str):
    if name != "PrivateStreamService":
        raise AttributeError(name)
    return getattr(
        import_module("okx_quant.infrastructure.okx.streams"),
        name,
    )
