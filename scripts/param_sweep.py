"""参数敏感性扫描 —— 区分真 edge vs 过拟合

对 Phase 1 胜出的 (strategy, inst, bar) 组合，one-at-a-time (OAT) 扫描
每个关键参数 ±50%，输出 Sharpe 变化曲线。

判定标准：
  - 真 edge: baseline 高 Sharpe，扫描中大部分变体仍 > 0（平滑曲线）
  - 过拟合: baseline 高 Sharpe，但微调参数后 Sharpe 崩到 <0（陡峭尖刺）

用法：
    # 单个组合全参数扫描
    uv run python scripts/param_sweep.py \\
      --strategy trend_momentum --inst ETH-USDT --bar 4H

    # 自定义单参数
    uv run python scripts/param_sweep.py \\
      --strategy ma_cross --inst BTC-USDT --bar 1H \\
      --param fast_period --values 3,5,7,9,11

    # 批量扫描（从 Phase 1 结果 top N 自动取）
    uv run python scripts/param_sweep.py --from-grid \\
      --grid-input backtest_results/results.csv \\
      --top 5

输出：
    param_sweep_results/
      sweep_{strategy}_{inst}_{bar}.csv    —— 每行一个 (param, value, metrics)
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from okx_quant.backtest import BacktestEngine
from okx_quant.client.rest import OKXRestClient
from okx_quant.config import load_yaml
from okx_quant.data.market import MarketDataFetcher
from okx_quant.strategy import STRATEGY_REGISTRY, StrategyContext


# ============================================================================
# 每策略的扫描维度（保守范围：默认值 ±约 50%）
# 策略默认参数见 okx_quant/strategy/*.py 各 __init__ defaults
# ============================================================================

STRATEGY_SWEEP: dict[str, dict[str, list]] = {
    "ma_cross": {
        "fast_period": [3, 5, 7, 9, 11, 14],       # default 7
        "slow_period": [10, 13, 15, 18, 21, 30],    # default 15
        "atr_sl_mult": [1.0, 1.5, 2.0, 2.5, 3.0],  # default 2.0
        "atr_tp_mult": [1.5, 2.0, 3.0, 4.0, 5.0],  # default 3.0
    },
    "rsi_mean": {
        "rsi_period": [8, 10, 12, 14, 18, 21],     # default 14
        "oversold": [25, 30, 35, 40, 45],           # default 40
        "overbought": [55, 60, 65, 70, 75],         # default 60
        "atr_sl_mult": [1.0, 1.2, 1.5, 2.0, 2.5],  # default 1.5
    },
    "bollinger": {
        "bb_period": [14, 18, 20, 24, 30],         # default 20
        "bb_std": [1.5, 1.8, 2.0, 2.2, 2.5],       # default 2.0
        "pct_b_buy": [10, 20, 30, 40, 50],          # default 30
        "pct_b_sell": [50, 60, 70, 80, 90],         # default 70
        "rsi_filter_low": [35, 40, 45, 50, 55],    # default 45
        "rsi_filter_high": [45, 50, 55, 60, 65],   # default 55
    },
    "adaptive": {
        "adx_trend_thresh": [15, 20, 25, 30, 35],  # default 25
        "adx_range_thresh": [10, 15, 20, 25, 30],  # default 20
        "bw_lookback": [30, 40, 50, 70, 100],       # default 50
        "cooldown_bars": [2, 3, 4, 6, 8],           # default 4
    },
    "trend_momentum": {
        "ema_fast": [12, 15, 20, 25, 30],          # default 20
        "ema_slow": [30, 40, 50, 60, 80],           # default 50
        "adx_thresh": [10, 15, 20, 25, 30],         # default 15
        "macd_fast": [8, 10, 12, 14, 16],           # default 12
        "macd_slow": [20, 22, 26, 30, 34],          # default 26
        "atr_sl_mult": [1.5, 2.0, 2.5, 3.0, 3.5],  # default 2.5
        "pullback_pct": [1.0, 1.5, 2.5, 3.5, 5.0], # default 2.5
    },
    "ensemble": {
        "consensus_threshold": [1, 2, 3],           # default 2（OAT 覆盖所有合法值）
    },
}


# ============================================================================
# 数据获取（复用 Phase 1 缓存）
# ============================================================================

def _bar_to_minutes(bar: str) -> int:
    return {
        "1m": 1, "3m": 3, "5m": 5, "15m": 15, "30m": 30,
        "1H": 60, "2H": 120, "4H": 240, "6H": 360, "12H": 720,
        "1D": 1440,
    }.get(bar, 60)


def get_df(
    inst: str,
    bar: str,
    days: int,
    cache_dirs: list[Path],
    fetcher: MarketDataFetcher,
) -> Optional[pd.DataFrame]:
    """尝试从多个 cache_dirs 找已缓存的 parquet；找不到则拉取"""
    for cache_dir in cache_dirs:
        path = cache_dir / f"{inst}_{bar}_{days}d.parquet"
        if path.exists():
            try:
                df = pd.read_parquet(path)
                if len(df) > 50:
                    return df
            except Exception:
                continue

    # 未命中缓存 → 拉取，写到第一个 cache_dir
    bar_min = _bar_to_minutes(bar)
    total = int(days * 24 * 60 / bar_min) + 50
    df = fetcher.get_history_candles(inst, bar=bar, total=total)
    if df.empty or len(df) < 50:
        return None
    out = cache_dirs[0] / f"{inst}_{bar}_{days}d.parquet"
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    return df


# ============================================================================
# 单参数扫描
# ============================================================================

def build_strategy(name: str, params: dict, llm_cfg: Optional[dict]):
    entry = STRATEGY_REGISTRY[name]
    cls = entry[0]
    ctx = None
    if llm_cfg and llm_cfg.get("api_key") and name in {"llm", "ensemble", "multi_agent"}:
        from okx_quant.llm.client import LLMClient, LLMConfig
        llm_client = LLMClient(LLMConfig.from_dict(llm_cfg))
        ctx = StrategyContext(llm_client=llm_client, deep_llm_client=llm_client)
    if ctx is not None:
        return cls(params, context=ctx)
    return cls(params)


def run_variant(args_tuple) -> dict:
    """单个参数变体的回测 —— ProcessPool worker"""
    (strategy_name, inst, bar, df_path, param_name, param_value,
     llm_cfg, fee_rate, slippage, initial_capital) = args_tuple
    try:
        df = pd.read_parquet(df_path)
        params = {param_name: param_value}
        strategy = build_strategy(strategy_name, params, llm_cfg)
        engine = BacktestEngine(
            initial_capital=initial_capital,
            fee_rate=fee_rate,
            slippage=slippage,
        )
        t0 = time.perf_counter()
        result = engine.run(df, strategy, inst_id=inst)
        elapsed = time.perf_counter() - t0
        m = result.metrics
        return {
            "strategy": strategy_name,
            "inst_id": inst,
            "bar": bar,
            "param": param_name,
            "value": param_value,
            "n_trades": m.get("total_trades", 0),
            "sharpe_ratio": m.get("sharpe_ratio", 0),
            "total_return_pct": m.get("total_return_pct", 0),
            "max_drawdown_pct": m.get("max_drawdown_pct", 0),
            "win_rate_pct": m.get("win_rate_pct", 0),
            "elapsed_s": round(elapsed, 2),
            "error": "",
        }
    except Exception as e:
        return {
            "strategy": strategy_name, "inst_id": inst, "bar": bar,
            "param": param_name, "value": param_value,
            "n_trades": 0, "sharpe_ratio": 0, "total_return_pct": 0,
            "max_drawdown_pct": 0, "win_rate_pct": 0, "elapsed_s": 0,
            "error": f"{type(e).__name__}: {e}",
        }


def append_row(csv_path: Path, row: dict):
    fields = list(row.keys())
    new_file = not csv_path.exists()
    with open(csv_path, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if new_file:
            writer.writeheader()
        writer.writerow(row)


# ============================================================================
# 主流程
# ============================================================================

def sweep(
    strategy: str,
    inst: str,
    bar: str,
    days: int,
    df_path: Path,
    llm_cfg: Optional[dict],
    fee_rate: float,
    slippage: float,
    initial_capital: float,
    outdir: Path,
    parallel: int,
    sweep_params: Optional[list[str]] = None,
    custom_values: Optional[dict[str, list]] = None,
) -> Path:
    """对单个 (strategy, inst, bar) 做 OAT 扫描，返回输出 CSV 路径"""
    sweep_spec = STRATEGY_SWEEP.get(strategy, {})
    if sweep_params:
        sweep_spec = {k: v for k, v in sweep_spec.items() if k in sweep_params}
    if custom_values:
        for k, v in custom_values.items():
            sweep_spec[k] = v
    if not sweep_spec:
        raise ValueError(f"策略 {strategy} 无预定义扫描参数，请用 --param/--values")

    out_csv = outdir / f"sweep_{strategy}_{inst.replace('/', '-')}_{bar}.csv"
    out_csv.unlink(missing_ok=True)

    # 串行不好看，丢给 ProcessPool
    tasks = []
    for param_name, values in sweep_spec.items():
        for v in values:
            tasks.append((
                strategy, inst, bar, str(df_path), param_name, v,
                llm_cfg if strategy in {"llm", "ensemble", "multi_agent"} else None,
                fee_rate, slippage, initial_capital,
            ))

    # LLM 策略降并发避免 rate limit
    effective_parallel = min(parallel, 4) if strategy in {"llm", "ensemble", "multi_agent"} else parallel
    total = len(tasks)
    print(f"\n[{strategy}/{inst}/{bar}] 扫描 {len(sweep_spec)} 参数 × 各自档位 = {total} 变体（{effective_parallel} 并行）")

    done = 0
    t0 = time.perf_counter()
    with ProcessPoolExecutor(max_workers=effective_parallel) as pool:
        futures = {pool.submit(run_variant, t): t for t in tasks}
        for future in as_completed(futures):
            row = future.result()
            append_row(out_csv, row)
            done += 1
            elapsed = time.perf_counter() - t0
            eta = elapsed / done * (total - done) if done else 0
            status = "✓" if not row["error"] else "✗"
            print(
                f"  [{done:>3}/{total}] {status} {row['param']:<20} = {str(row['value']):<6} "
                f"Sharpe={row['sharpe_ratio']:>6.2f}  "
                f"Ret={row['total_return_pct']:>7.2f}%  "
                f"n={row['n_trades']:<4} "
                f"(ETA {eta:.0f}s)"
            )
            if row["error"]:
                print(f"        → {row['error'][:120]}")

    print(f"  ← 完成 ({(time.perf_counter()-t0)/60:.1f} min)，结果: {out_csv}")
    return out_csv


def analyze(csv_path: Path, baseline_sharpe: Optional[float] = None):
    """读 sweep CSV，输出每参数的 Sharpe 曲线 + robustness 评分"""
    df = pd.read_csv(csv_path, keep_default_na=False)
    df["error"] = df["error"].fillna("").astype(str)
    df = df[df["error"] == ""]

    print(f"\n=== 敏感性分析: {csv_path.name} ===\n")

    for param in sorted(df["param"].unique()):
        sub = df[df["param"] == param].sort_values("value")
        if sub.empty:
            continue
        sharpe = sub["sharpe_ratio"].values
        sharpe_mean = sharpe.mean()
        sharpe_std = sharpe.std()
        n_positive = (sharpe > 0).sum()

        label = "robust" if n_positive >= len(sharpe) * 0.6 and sharpe_std < abs(sharpe_mean) + 0.5 else "fragile"
        print(f"  {param:<22}  mean Sharpe={sharpe_mean:+.2f}  std={sharpe_std:.2f}  "
              f"正 Sharpe {n_positive}/{len(sharpe)}  → {label}")
        for _, r in sub.iterrows():
            marker = "  " if r["sharpe_ratio"] > 0 else " ↓"
            print(f"    {marker} {r['value']:<10} Sharpe={r['sharpe_ratio']:+.2f} "
                  f"Ret={r['total_return_pct']:+.2f}%  n={r['n_trades']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--strategy", help="策略名")
    parser.add_argument("--inst", help="交易对，如 BTC-USDT")
    parser.add_argument("--bar", help="K 线周期")
    parser.add_argument("--days", type=int, default=730)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--outdir", default="param_sweep_results")
    parser.add_argument("--cache-dirs", default="backtest_results/candles,/tmp/bt_phase1/candles",
                        help="K 线缓存目录（逗号分隔，优先从前者读）")
    parser.add_argument("--parallel", type=int, default=8)
    parser.add_argument("--fee-rate", type=float, default=0.001)
    parser.add_argument("--slippage", type=float, default=0.0005)
    parser.add_argument("--initial-capital", type=float, default=10_000.0)

    # 单参数模式
    parser.add_argument("--param", help="只扫这一个参数名")
    parser.add_argument("--values", help="逗号分隔值列表，如 3,5,7,9 或 2.0,2.5,3.0")

    # 批量模式
    parser.add_argument("--from-grid", action="store_true",
                        help="从 backtest_grid 结果中自动取 Top-N 组合做扫描")
    parser.add_argument("--grid-input", default="backtest_results/results.csv")
    parser.add_argument("--top", type=int, default=5, help="取前 N 名组合")
    parser.add_argument("--min-sharpe", type=float, default=0.0,
                        help="from-grid 筛选的 Sharpe 下限")

    args = parser.parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(exist_ok=True)
    cache_dirs = [Path(p.strip()) for p in args.cache_dirs.split(",") if p.strip()]
    cfg = load_yaml(args.config) if Path(args.config).exists() else {}
    llm_cfg = cfg.get("llm", {}) or {}

    client = OKXRestClient()
    fetcher = MarketDataFetcher(client)

    # 1. 收集待扫描组合
    targets: list[tuple[str, str, str]] = []
    if args.from_grid:
        grid_path = Path(args.grid_input)
        if not grid_path.exists():
            print(f"错误: {grid_path} 不存在，先运行 backtest_grid.py")
            return 1
        gdf = pd.read_csv(grid_path, keep_default_na=False)
        gdf["error"] = gdf["error"].fillna("").astype(str)
        gdf = gdf[gdf["error"] == ""]
        gdf = gdf[gdf["n_trades"] >= 5]
        gdf = gdf[gdf["sharpe_ratio"] >= args.min_sharpe]
        gdf = gdf.sort_values("sharpe_ratio", ascending=False).head(args.top)
        for _, r in gdf.iterrows():
            targets.append((r["strategy"], r["inst_id"], r["bar"]))
        print(f"从 {grid_path.name} 选出 Top {len(targets)} 组合做扫描")
    elif args.strategy and args.inst and args.bar:
        targets.append((args.strategy, args.inst, args.bar))
    else:
        print("错误: 必须指定 --strategy/--inst/--bar 或 --from-grid")
        return 1

    custom_values = None
    if args.param and args.values:
        vals = [float(v) if "." in v else int(v) for v in args.values.split(",")]
        custom_values = {args.param: vals}
        sweep_params = [args.param]
    else:
        sweep_params = None

    # 2. 为每个组合跑扫描
    for strategy, inst, bar in targets:
        df = get_df(inst, bar, args.days, cache_dirs, fetcher)
        if df is None:
            print(f"跳过 {strategy}/{inst}/{bar}（数据不足）")
            continue
        # 找到实际加载的 df 所在缓存路径
        df_path = None
        for cache_dir in cache_dirs:
            p = cache_dir / f"{inst}_{bar}_{args.days}d.parquet"
            if p.exists():
                df_path = p
                break

        csv_path = sweep(
            strategy, inst, bar, args.days, df_path,
            llm_cfg, args.fee_rate, args.slippage, args.initial_capital,
            outdir, args.parallel, sweep_params, custom_values,
        )
        analyze(csv_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
