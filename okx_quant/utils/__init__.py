"""通用工具模块"""

from okx_quant.utils.timeout import run_with_timeout, TimeoutError as SignalTimeout

__all__ = ["run_with_timeout", "SignalTimeout"]
