"""Phase 1 结果最终分析（HODL-adjusted）

把 `strategy_sharpe` 减去同 inst/bar 的 HODL Sharpe，得到 **alpha_sharpe**。
只有 alpha_sharpe > 阈值且绝对收益为正的组合才是真 edge。

用法:
    uv run python scripts/backtest_analyze_alpha.py \\
        --results /tmp/bt_phase1/results.csv \\
        --candles /tmp/bt_phase1/candles
"""
from __future__ import annotations
import argparse, sys
from pathlib import Path
import numpy as np
import pandas as pd


def calc_hodl(df: pd.DataFrame) -> dict:
    """同样逻辑计算 HODL 指标"""
    if len(df) < 50:
        return {"hodl_return_pct": 0, "hodl7_sharpe": 0, "hodl_mdd": 0, "hodl_days": 0}
    start, end = df["ts"].iloc[0], df["ts"].iloc[-1]
    days = max(1, (end - start).days)
    total = (df["close"].iloc[-1] / df["close"].iloc[0] - 1) * 100
    daily = df.set_index("ts")["close"].resample("1D").last().pct_change().dropna()
    sharpe = float(daily.mean() / daily.std() * np.sqrt(252)) if daily.std() > 0 else 0.0
    mdd = float(((df["close"] / df["close"].cummax()) - 1).min() * 100)
    return {
        "hodl_return_pct": round(total, 2),
        "hodl_sharpe": round(sharpe, 3),
        "hodl_mdd": round(mdd, 2),
        "hodl_days": days,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--candles", required=True)
    parser.add_argument("--min-alpha-sharpe", type=float, default=0.3,
                        help="alpha = strategy_sharpe - hodl_sharpe 下限")
    parser.add_argument("--min-trades", type=int, default=20)
    parser.add_argument("--days", type=int, default=730)
    args = parser.parse_args()

    candles_dir = Path(args.candles)
    df = pd.read_csv(args.results, keep_default_na=False)
    df["error"] = df["error"].fillna("").astype(str)
    df = df[df["error"] == ""].copy()

    # 计算每个 (inst, bar) 的 HODL 基准（从缓存读）
    hodl_cache: dict[tuple[str, str], dict] = {}
    for (inst, bar), _ in df.groupby(["inst_id", "bar"]):
        path = candles_dir / f"{inst}_{bar}_{args.days}d.parquet"
        if path.exists():
            try:
                cdf = pd.read_parquet(path)
                hodl_cache[(inst, bar)] = calc_hodl(cdf)
            except Exception as e:
                print(f"警告: HODL {inst} {bar} 计算失败: {e}", file=sys.stderr)

    # 把 HODL 列 join 到结果表
    for col in ["hodl_return_pct", "hodl_sharpe", "hodl_mdd"]:
        df[col] = df.apply(lambda r: hodl_cache.get((r["inst_id"], r["bar"]), {}).get(col, 0), axis=1)

    df["alpha_sharpe"] = df["sharpe_ratio"] - df["hodl_sharpe"]
    df["alpha_return_pct"] = df["total_return_pct"] - df["hodl_return_pct"]

    total = len(df)
    valid = df[df["n_trades"] >= args.min_trades].copy()
    real_edge = valid[
        (valid["alpha_sharpe"] >= args.min_alpha_sharpe) &
        (valid["total_return_pct"] > 0)
    ].sort_values("alpha_sharpe", ascending=False)

    print(f"\n# 回测网格 HODL-adjusted 分析  {total} 成功组合\n")
    print(f"## 筛选标准")
    print(f"  - n_trades >= {args.min_trades}")
    print(f"  - alpha_sharpe (strategy_sharpe - hodl_sharpe) >= {args.min_alpha_sharpe}")
    print(f"  - total_return_pct > 0（绝对收益为正）")
    print()
    print(f"## 真 edge 候选: {len(real_edge)} / {len(valid)} 个样本量达标的组合\n")

    if len(real_edge):
        cols = ["strategy", "inst_id", "bar", "n_trades",
                "alpha_sharpe", "sharpe_ratio", "hodl_sharpe",
                "total_return_pct", "hodl_return_pct", "alpha_return_pct",
                "max_drawdown_pct"]
        sub = real_edge[cols].copy()
        for c in sub.select_dtypes("number").columns:
            sub[c] = sub[c].round(2)
        print(sub.to_string(index=False))
    else:
        print("  （无组合通过门槛）")

    # 按策略聚合平均 alpha_sharpe
    print("\n\n## 每策略 alpha_sharpe 统计（>=20 笔交易的样本）\n")
    agg = valid.groupby("strategy").agg(
        n_valid=("strategy", "count"),
        avg_alpha_sharpe=("alpha_sharpe", "mean"),
        med_alpha_sharpe=("alpha_sharpe", "median"),
        n_real_edge=("alpha_sharpe", lambda s: int((s >= args.min_alpha_sharpe).sum())),
        best_alpha_sharpe=("alpha_sharpe", "max"),
    ).round(2).sort_values("med_alpha_sharpe", ascending=False)
    print(agg.to_string())

    # 全表 Top 20 by alpha_sharpe
    print("\n\n## Top 20 by alpha_sharpe（含未过门槛）\n")
    top = valid.sort_values("alpha_sharpe", ascending=False).head(20)
    cols = ["strategy", "inst_id", "bar", "n_trades",
            "alpha_sharpe", "sharpe_ratio", "hodl_sharpe",
            "total_return_pct", "hodl_return_pct"]
    sub = top[cols].copy()
    for c in sub.select_dtypes("number").columns:
        sub[c] = sub[c].round(2)
    print(sub.to_string(index=False))

    # 按 bar 的分布
    print("\n\n## 按周期统计\n")
    bar_agg = valid.groupby("bar").agg(
        n=("strategy", "count"),
        avg_alpha=("alpha_sharpe", "mean"),
        med_alpha=("alpha_sharpe", "median"),
        n_real_edge=("alpha_sharpe", lambda s: int((s >= args.min_alpha_sharpe).sum())),
    ).round(2).sort_values("med_alpha", ascending=False)
    print(bar_agg.to_string())

    # 写回带 hodl 列的增强 CSV
    enriched_path = Path(args.results).parent / "results_with_hodl.csv"
    df.to_csv(enriched_path, index=False)
    print(f"\n增强 CSV 写入: {enriched_path}")


if __name__ == "__main__":
    main()
