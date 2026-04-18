"""回测网格结果 → 汇总报告

读取 backtest_results/results.csv，按 Sharpe 排序输出：
  1. 全表 Top 20
  2. 每策略的 Top 5 组合
  3. 每周期的 Top 5 组合
  4. 标记为 "Phase 2 候选" 的组合（post-cost Sharpe > 0.5）
  5. 失败组合（error 非空）

用法：
    uv run python scripts/backtest_report.py
    uv run python scripts/backtest_report.py --input backtest_results/results.csv
    uv run python scripts/backtest_report.py --min-sharpe 0.5
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd


def format_table(df: pd.DataFrame, cols: list[str], n: int = 20) -> str:
    if df.empty:
        return "  (空)"
    sub = df[cols].head(n).copy()
    # 数值列 2 位小数
    for c in sub.columns:
        if sub[c].dtype == "float64":
            sub[c] = sub[c].round(2)
    return sub.to_string(index=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", default="backtest_results/results.csv")
    parser.add_argument("--min-sharpe", type=float, default=0.5,
                        help="Phase 2 候选 Sharpe 下限")
    parser.add_argument("--min-trades", type=int, default=5,
                        help="至少 N 笔交易才进入排名（样本量过滤）")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        print(f"未找到 {path}，先运行 backtest_grid.py")
        return 1

    df = pd.read_csv(path, keep_default_na=False)  # 保留空字符串，避免 NaN 把空 error 变非空
    total = len(df)
    df["error"] = df["error"].fillna("").astype(str)
    errors = df[df["error"].str.len() > 0]
    ok = df[df["error"].str.len() == 0].copy()

    print(f"# 回测网格结果汇总  —  {total} 组合 （{len(ok)} 成功 / {len(errors)} 失败）\n")

    # 基础 QA
    valid = ok[ok["n_trades"] >= args.min_trades].copy()
    print(f"## 过滤后有效: {len(valid)} 组合（至少 {args.min_trades} 笔交易）\n")

    display_cols = [
        "strategy", "inst_id", "bar", "n_trades",
        "sharpe_ratio", "total_return_pct", "annual_return_pct",
        "max_drawdown_pct", "win_rate_pct", "profit_factor",
        "total_fee",
    ]

    # 1. 全表 Top 20
    print("## 1. 按 Sharpe 排序 Top 20\n")
    valid_sorted = valid.sort_values("sharpe_ratio", ascending=False)
    print(format_table(valid_sorted, display_cols, n=20))
    print()

    # 2. 每策略 Top 5
    print("\n## 2. 每策略 Top 5\n")
    for strat in sorted(valid["strategy"].unique()):
        sub = valid[valid["strategy"] == strat].sort_values("sharpe_ratio", ascending=False)
        print(f"\n### {strat}")
        print(format_table(sub, display_cols, n=5))

    # 3. 每周期 Top 5
    print("\n\n## 3. 每周期 Top 5\n")
    for bar in sorted(valid["bar"].unique()):
        sub = valid[valid["bar"] == bar].sort_values("sharpe_ratio", ascending=False)
        print(f"\n### {bar}")
        print(format_table(sub, display_cols, n=5))

    # 4. Phase 2 候选（Sharpe > min_sharpe）
    candidates = valid[valid["sharpe_ratio"] >= args.min_sharpe].sort_values("sharpe_ratio", ascending=False)
    print(f"\n\n## 4. Phase 2 候选 （Sharpe ≥ {args.min_sharpe}）: {len(candidates)} 组合\n")
    if len(candidates):
        print(format_table(candidates, display_cols, n=len(candidates)))
    else:
        print("  (空) —— 没有组合通过门槛。尝试降低 --min-sharpe 或审视策略参数。")

    # 5. 失败组合
    if len(errors):
        print(f"\n\n## 5. 失败组合: {len(errors)}\n")
        err_cols = ["strategy", "inst_id", "bar", "error"]
        err_sub = errors[err_cols].copy()
        err_sub["error"] = err_sub["error"].astype(str).str.slice(0, 100)
        print(err_sub.to_string(index=False))

    # 6. 汇总统计
    print("\n\n## 6. 汇总统计（按策略平均）\n")
    agg = valid.groupby("strategy").agg(
        n_combos=("strategy", "count"),
        avg_sharpe=("sharpe_ratio", "mean"),
        median_sharpe=("sharpe_ratio", "median"),
        avg_return=("total_return_pct", "mean"),
        avg_mdd=("max_drawdown_pct", "mean"),
        avg_trades=("n_trades", "mean"),
    ).round(2).sort_values("median_sharpe", ascending=False)
    print(agg.to_string())

    # LLM 成本（如有）
    if "llm_calls" in valid.columns:
        llm_df = valid[valid["llm_calls"] > 0]
        if not llm_df.empty:
            total_in = llm_df["llm_input_tokens"].sum()
            total_out = llm_df["llm_output_tokens"].sum()
            cost = (total_in * 0.14 + total_out * 0.28) / 1_000_000
            print(f"\n\n## 7. LLM 成本（DeepSeek 定价）\n")
            print(f"  LLM 组合:   {len(llm_df)}")
            print(f"  总调用数:   {llm_df['llm_calls'].sum()}")
            print(f"  input tokens:  {int(total_in):,}")
            print(f"  output tokens: {int(total_out):,}")
            print(f"  总成本:     ~${cost:.4f}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
