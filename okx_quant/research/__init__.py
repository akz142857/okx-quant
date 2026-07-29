"""生产准入所需的组合、walk-forward、成本和压力研究工具。"""

from okx_quant.research.admission import AdmissionGate, DemoObservationLedger
from okx_quant.research.costs import DynamicCostModel
from okx_quant.research.portfolio import PortfolioBacktester, PortfolioResult
from okx_quant.research.stress import evaluate_portfolio_stress_scenarios
from okx_quant.research.walk_forward import WalkForwardResult, WalkForwardRunner

__all__ = [
    "AdmissionGate",
    "DemoObservationLedger",
    "DemoObservationLedgerV2",
    "DynamicCostModel",
    "PortfolioBacktester",
    "PortfolioResult",
    "evaluate_portfolio_stress_scenarios",
    "WalkForwardRunner",
    "WalkForwardResult",
]


def __getattr__(name: str):
    if name == "DemoObservationLedgerV2":
        from okx_quant.research.demo_soak import DemoObservationLedgerV2

        return DemoObservationLedgerV2
    raise AttributeError(name)
