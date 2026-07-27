"""应用服务：执行、恢复、对账、风险和保护。"""

from importlib import import_module

_EXPORTS = {
    "ExecutionCoordinator": ("execution", "ExecutionCoordinator"),
    "ExecutionRequest": ("execution", "ExecutionRequest"),
    "ExitCoordinator": ("protection", "ExitCoordinator"),
    "ProtectionManager": ("protection", "ProtectionManager"),
    "ProductionRiskLimits": ("risk_service", "ProductionRiskLimits"),
    "ProductionRiskService": ("risk_service", "ProductionRiskService"),
    "ProductionRuntime": ("runtime", "ProductionRuntime"),
    "Reconciler": ("reconciliation", "Reconciler"),
    "RecoveryGate": ("reconciliation", "RecoveryGate"),
}

__all__ = [
    "ExecutionCoordinator",
    "ExecutionRequest",
    "ExitCoordinator",
    "ProtectionManager",
    "ProductionRiskLimits",
    "ProductionRiskService",
    "ProductionRuntime",
    "Reconciler",
    "RecoveryGate",
]


def __getattr__(name: str):
    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    return getattr(
        import_module(f"okx_quant.application.{module_name}"),
        attribute,
    )
