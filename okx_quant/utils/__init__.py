"""通用工具模块"""

from okx_quant.utils.timeout import TimeoutError as SignalTimeout
from okx_quant.utils.timeout import run_with_timeout

__all__ = ["run_with_timeout", "SignalTimeout"]
