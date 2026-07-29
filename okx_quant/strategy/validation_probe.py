"""Deterministic no-entry strategy used by the formal Demo Active service."""

from __future__ import annotations

import pandas as pd

from okx_quant.strategy.base import BaseStrategy, Signal, SignalType


class ValidationProbeStrategy(BaseStrategy):
    """Never emits an order; entries are accepted only through DemoProbeSaga."""

    name = "ValidationProbe"

    def generate_signal(self, df: pd.DataFrame, inst_id: str) -> Signal:
        price = float(df["close"].iloc[-1]) if not df.empty else 0.0
        return Signal(
            SignalType.HOLD,
            inst_id,
            price=price,
            reason="formal Demo Active 仅允许 durable validation probe",
        )
