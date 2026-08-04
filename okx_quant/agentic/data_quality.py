"""数据充分度评级 — 对标 AI Berkshire 的 A/B/C 信息丰富度评级。

在跑昂贵的多 Agent 管线前，用**确定性代码**评估标的的行情数据是否撑得起
一个有信心的决策。薄数据（历史短、成交清淡、价格停滞）会压低"置信度天花板"，
避免 LLM 用"合理推测"填补空白、输出一个伪装确定的信号。

设计原则（与整个仓库一致）：约束用代码钉死，而不是写在 prompt 里祈祷模型遵守。
分级只依赖行情本身（bar 数、成交量、K 线形态），纯函数、可测、可复现。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DataQualityThresholds:
    """分级阈值（可按品种/周期覆盖）。

    zero_vol / flat / stale 三个比例都在"最近 window 根 K 线"窗口内统计。
    flat  = 高低价相等（无振幅）的 bar 占比 —— 撮合稀薄的典型特征
    stale = 收盘价与上一根相等（价格停滞）的 bar 占比
    """

    window: int = 100
    # A → B 降级线
    min_bars_a: int = 200
    zero_vol_b: float = 0.05
    flat_b: float = 0.10
    stale_b: float = 0.15
    # B → C 降级线
    min_bars_c: int = 80
    zero_vol_c: float = 0.20
    flat_c: float = 0.30
    stale_c: float = 0.40
    # 各档置信度天花板
    ceiling_a: float = 1.0
    ceiling_b: float = 0.75
    ceiling_c: float = 0.40


@dataclass
class DataQuality:
    """数据充分度评级结果。"""

    grade: str  # "A" / "B" / "C"
    confidence_ceiling: float
    bars: int
    zero_vol_ratio: float
    flat_ratio: float
    stale_ratio: float
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "grade": self.grade,
            "confidence_ceiling": self.confidence_ceiling,
            "bars": self.bars,
            "zero_vol_ratio": round(self.zero_vol_ratio, 4),
            "flat_ratio": round(self.flat_ratio, 4),
            "stale_ratio": round(self.stale_ratio, 4),
            "reasons": list(self.reasons),
        }


def _ratio(series_bool) -> float:
    n = len(series_bool)
    if n == 0:
        return 0.0
    return float(series_bool.sum()) / n


def assess_data_sufficiency(df, thresholds: DataQualityThresholds | None = None) -> DataQuality:
    """评估一个行情 DataFrame 的数据充分度。

    Args:
        df: 至少含 close/high/low 列的 K 线 DataFrame（vol 缺失时按 0 处理，
            即视为"无成交量信息"→ 保守降级）。
        thresholds: 可选阈值覆盖。

    Returns:
        DataQuality —— grade 越差 confidence_ceiling 越低。
    """
    t = thresholds or DataQualityThresholds()
    n = len(df)
    reasons: list[str] = []

    if n == 0:
        return DataQuality("C", t.ceiling_c, 0, 1.0, 1.0, 1.0, ["无任何 K 线数据"])

    window = df.tail(t.window)

    if "vol" in window.columns:
        vol = window["vol"].fillna(0)
        zero_vol_ratio = _ratio(vol <= 0)
    else:
        zero_vol_ratio = 1.0
        reasons.append("缺少成交量列，无法评估流动性")

    high = window["high"]
    low = window["low"]
    flat_ratio = _ratio((high - low).abs() <= 0)

    close = window["close"]
    stale_ratio = _ratio(close.diff().abs().fillna(1) <= 0)

    # --- 定级：从 A 起步，命中 C 线降到 C，否则命中 B 线降到 B ---
    grade = "A"

    hit_c = []
    if n < t.min_bars_c:
        hit_c.append(f"历史仅 {n} 根 K 线 (<{t.min_bars_c})")
    if zero_vol_ratio > t.zero_vol_c:
        hit_c.append(f"零成交量 bar 占比 {zero_vol_ratio:.0%} (>{t.zero_vol_c:.0%})")
    if flat_ratio > t.flat_c:
        hit_c.append(f"无振幅 bar 占比 {flat_ratio:.0%} (>{t.flat_c:.0%})")
    if stale_ratio > t.stale_c:
        hit_c.append(f"价格停滞 bar 占比 {stale_ratio:.0%} (>{t.stale_c:.0%})")

    hit_b = []
    if n < t.min_bars_a:
        hit_b.append(f"历史仅 {n} 根 K 线 (<{t.min_bars_a})")
    if zero_vol_ratio > t.zero_vol_b:
        hit_b.append(f"零成交量 bar 占比 {zero_vol_ratio:.0%} (>{t.zero_vol_b:.0%})")
    if flat_ratio > t.flat_b:
        hit_b.append(f"无振幅 bar 占比 {flat_ratio:.0%} (>{t.flat_b:.0%})")
    if stale_ratio > t.stale_b:
        hit_b.append(f"价格停滞 bar 占比 {stale_ratio:.0%} (>{t.stale_b:.0%})")

    if hit_c:
        grade = "C"
        reasons.extend(hit_c)
    elif hit_b:
        grade = "B"
        reasons.extend(hit_b)
    else:
        reasons.append("历史充足、成交活跃、价格连续")

    ceiling = {"A": t.ceiling_a, "B": t.ceiling_b, "C": t.ceiling_c}[grade]

    # 防御：NaN 兜底为最保守值
    for name, val in (("zero_vol_ratio", zero_vol_ratio),
                      ("flat_ratio", flat_ratio),
                      ("stale_ratio", stale_ratio)):
        if isinstance(val, float) and math.isnan(val):
            reasons.append(f"{name} 计算为 NaN，已保守处理")

    return DataQuality(
        grade=grade,
        confidence_ceiling=ceiling,
        bars=n,
        zero_vol_ratio=0.0 if math.isnan(zero_vol_ratio) else zero_vol_ratio,
        flat_ratio=0.0 if math.isnan(flat_ratio) else flat_ratio,
        stale_ratio=0.0 if math.isnan(stale_ratio) else stale_ratio,
        reasons=reasons,
    )
