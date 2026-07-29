"""Isolated Stage-C barrier harness.

This package is intentionally outside the ``okx_quant*`` setuptools package
allowlist.  It is shipped only in the separately hashed instrumented artifact.
"""

from .barriers import (
    BARRIER_SCENARIOS,
    BarrierHook,
    BarrierStateStore,
    attest_barrier_reached,
    consume_barrier_phase_globally,
    execute_systemd_kill,
    validate_recovery_bundle,
)
from .pipeline import (
    PipelineBarrierRuntime,
    activate_pipeline_barrier,
    build_pipeline_runtime,
    load_pipeline_proof,
    reach_pipeline_boundary,
)
from .recovery import collect_native_recovery_bundle

__all__ = [
    "BARRIER_SCENARIOS",
    "BarrierHook",
    "BarrierStateStore",
    "attest_barrier_reached",
    "consume_barrier_phase_globally",
    "execute_systemd_kill",
    "validate_recovery_bundle",
    "PipelineBarrierRuntime",
    "activate_pipeline_barrier",
    "build_pipeline_runtime",
    "load_pipeline_proof",
    "reach_pipeline_boundary",
    "collect_native_recovery_bundle",
]
