"""Phase 1 回测网格 —— 全策略 × 全币种 × 全周期 系统性回测

目的：替换所有策略参数的"拍脑袋默认值"假设，用真实 2+ 年历史数据筛选
出有真正 edge（post-cost Sharpe > 0.5）的策略×币×周期组合。

用法：
    # 默认网格（~360 组合，~1 小时）
    uv run python scripts/backtest_grid.py

    # 自定义
    uv run python scripts/backtest_grid.py \\
      --strategies ma_cross,bollinger,ensemble \\
      --instruments BTC-USDT,ETH-USDT \\
      --bars 1H,4H \\
      --days 730 \\
      --parallel 4

    # 续跑（跳过已完成组合）
    uv run python scripts/backtest_grid.py --resume

    # 只看要跑的组合列表，不实际执行
    uv run python scripts/backtest_grid.py --dry-run

输出：
    backtest_results/
      results.csv           一行一个组合，含 sharpe/cagr/mdd/winrate/n_trades
      candles/              K 线缓存（按 inst-bar-days 分片，避免重复下载）
      summary.md            汇总报告
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import pandas as pd

# 让 scripts/ 可以 import 项目代码
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from okx_quant.backtest import BacktestEngine, BacktestReport
from okx_quant.client.rest import OKXRestClient
from okx_quant.config import load_yaml
from okx_quant.data.market import MarketDataFetcher
from okx_quant.strategy import (
    STRATEGY_REGISTRY,
    BollingerBandStrategy,
    EnsembleStrategy,
    MACrossStrategy,
    RSIMeanReversionStrategy,
    StrategyContext,
    AdaptiveStrategy,
    TrendMomentumStrategy,
)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("backtest_grid")
logger.setLevel(logging.INFO)


# ============================================================================
# 默认网格
# ============================================================================

# 只含传统 + ensemble；llm/multi_agent 回测成本/价值不划算（见 discussion）
DEFAULT_STRATEGIES = [
    "ma_cross",
    "rsi_mean",
    "bollinger",
    "adaptive",
    "trend_momentum",
    "ensemble",
]

# OKX 主流 USDT 现货（按 24H 成交量大致排序，覆盖大/中市值）
DEFAULT_INSTRUMENTS = [
    "BTC-USDT", "ETH-USDT", "SOL-USDT", "XRP-USDT", "DOGE-USDT",
    "ADA-USDT", "AVAX-USDT", "LINK-USDT", "DOT-USDT", "LTC-USDT",
    "UNI-USDT", "ATOM-USDT", "TRX-USDT", "TON-USDT", "NEAR-USDT",
    "APT-USDT", "SUI-USDT", "FIL-USDT", "ALGO-USDT", "BCH-USDT",
]

DEFAULT_BARS = ["15m", "1H", "4H"]
DEFAULT_DAYS = 730   # 2 年
DEFAULT_OUTDIR = "backtest_results"

# 识别需要 LLM 的策略
LLM_STRATEGIES = {"llm", "ensemble", "multi_agent"}


# ============================================================================
# K 线数据获取（带文件缓存）
# ============================================================================

def _bar_to_minutes(bar: str) -> int:
    return {
        "1m": 1, "3m": 3, "5m": 5, "15m": 15, "30m": 30,
        "1H": 60, "2H": 120, "4H": 240, "6H": 360, "12H": 720,
        "1D": 1440,
    }.get(bar, 60)


def candle_cache_path(cache_dir: Path, inst: str, bar: str, days: int) -> Path:
    return cache_dir / f"{inst}_{bar}_{days}d.parquet"


def fetch_candles(
    fetcher: MarketDataFetcher,
    inst: str,
    bar: str,
    days: int,
    cache_dir: Path,
) -> Optional[pd.DataFrame]:
    """优先读本地缓存；过期或缺失则重新拉。"""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = candle_cache_path(cache_dir, inst, bar, days)

    if path.exists():
        try:
            df = pd.read_parquet(path)
            if len(df) > 50:
                return df
            logger.warning(f"缓存过小 {path.name}，重新拉取")
        except Exception as e:
            logger.warning(f"缓存读取失败 {path.name}: {e}，重新拉取")

    bar_min = _bar_to_minutes(bar)
    total = int(days * 24 * 60 / bar_min) + 50
    try:
        logger.info(f"拉取 {inst} {bar} {days}天（约 {total} 根）...")
        df = fetcher.get_history_candles(inst, bar=bar, total=total)
        if df.empty or len(df) < 50:
            logger.warning(f"{inst} {bar} 数据不足，跳过")
            return None
        df.to_parquet(path, index=False)
        logger.info(f"  ← {len(df)} 根，已缓存到 {path.name}")
        return df
    except Exception as e:
        logger.error(f"拉取 {inst} {bar} 失败: {e}")
        return None


# ============================================================================
# 单个回测执行
# ============================================================================

def build_strategy(name: str, llm_cfg: Optional[dict] = None):
    """按策略名实例化；LLM 类策略注入客户端（仅技术面模式，不接入新闻）"""
    entry = STRATEGY_REGISTRY.get(name)
    if not entry:
        raise ValueError(f"未知策略 {name}")
    cls = entry[0]

    ctx = None
    if name in LLM_STRATEGIES:
        if not llm_cfg or not llm_cfg.get("api_key"):
            raise ValueError(f"策略 {name} 需要 LLM key；检查 config.yaml / env")
        from okx_quant.llm.client import LLMClient, LLMConfig
        llm_client = LLMClient(LLMConfig.from_dict(llm_cfg))
        ctx = StrategyContext(llm_client=llm_client, deep_llm_client=llm_client)
        # 回测不接入新闻（历史新闻 API 无法获取）—— 策略 prompt 中会用 "No news" 占位

    return cls(context=ctx) if ctx is not None else cls()


def run_one(
    strategy_name: str,
    inst: str,
    bar: str,
    df: pd.DataFrame,
    llm_cfg: Optional[dict],
    fee_rate: float,
    slippage: float,
    initial_capital: float,
) -> dict:
    """回测单个 (strategy, inst, bar) 组合，返回 metrics 字典。"""
    strategy = build_strategy(strategy_name, llm_cfg)
    engine = BacktestEngine(
        initial_capital=initial_capital,
        fee_rate=fee_rate,
        slippage=slippage,
    )
    t0 = time.perf_counter()
    result = engine.run(df, strategy, inst_id=inst)
    elapsed = time.perf_counter() - t0

    m = result.metrics
    row = {
        "strategy": strategy_name,
        "inst_id": inst,
        "bar": bar,
        "n_bars": len(df),
        "start_ts": str(df["ts"].iloc[0]) if len(df) else "",
        "end_ts": str(df["ts"].iloc[-1]) if len(df) else "",
        "n_trades": m.get("total_trades", 0),
        "win_rate_pct": m.get("win_rate_pct", 0),
        "total_return_pct": m.get("total_return_pct", 0),
        "annual_return_pct": m.get("annual_return_pct", 0),
        "max_drawdown_pct": m.get("max_drawdown_pct", 0),
        "sharpe_ratio": m.get("sharpe_ratio", 0),
        "profit_factor": m.get("profit_factor", 0),
        "total_pnl": m.get("total_pnl", 0),
        "total_fee": m.get("total_fee", 0),
        "final_capital": m.get("final_capital", initial_capital),
        "elapsed_s": round(elapsed, 2),
        "error": "",
    }

    # LLM 策略追加 token 成本
    try:
        usage = strategy.get_usage_summary() if hasattr(strategy, "get_usage_summary") else {}
        row["llm_calls"] = usage.get("total_calls", 0)
        row["llm_input_tokens"] = usage.get("total_input_tokens", 0)
        row["llm_output_tokens"] = usage.get("total_output_tokens", 0)
    except Exception:
        row["llm_calls"] = 0
        row["llm_input_tokens"] = 0
        row["llm_output_tokens"] = 0

    return row


def run_one_safe(args_tuple) -> dict:
    """ProcessPoolExecutor 的 worker 入口，捕获所有异常"""
    strategy_name, inst, bar, df_path, llm_cfg, fee_rate, slippage, initial_capital = args_tuple
    try:
        df = pd.read_parquet(df_path)
        return run_one(strategy_name, inst, bar, df, llm_cfg, fee_rate, slippage, initial_capital)
    except Exception as e:
        tb = traceback.format_exc().splitlines()[-3:]
        return {
            "strategy": strategy_name, "inst_id": inst, "bar": bar,
            "n_bars": 0, "start_ts": "", "end_ts": "",
            "n_trades": 0, "win_rate_pct": 0, "total_return_pct": 0,
            "annual_return_pct": 0, "max_drawdown_pct": 0, "sharpe_ratio": 0,
            "profit_factor": 0, "total_pnl": 0, "total_fee": 0,
            "final_capital": 0, "elapsed_s": 0,
            "error": f"{type(e).__name__}: {e} | {' | '.join(tb)}",
            "llm_calls": 0, "llm_input_tokens": 0, "llm_output_tokens": 0,
        }


# ============================================================================
# 网格编排
# ============================================================================

RESULT_COLUMNS = [
    "strategy", "inst_id", "bar", "n_bars", "start_ts", "end_ts",
    "n_trades", "win_rate_pct", "total_return_pct", "annual_return_pct",
    "max_drawdown_pct", "sharpe_ratio", "profit_factor",
    "total_pnl", "total_fee", "final_capital",
    "llm_calls", "llm_input_tokens", "llm_output_tokens",
    "elapsed_s", "error",
]


def load_completed(csv_path: Path) -> set[tuple[str, str, str]]:
    """resume 用：已完成组合的 set[(strategy, inst, bar)]"""
    if not csv_path.exists():
        return set()
    done = set()
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("error"):
                continue  # 失败的允许重跑
            done.add((row["strategy"], row["inst_id"], row["bar"]))
    return done


def append_row(csv_path: Path, row: dict):
    new_file = not csv_path.exists()
    with open(csv_path, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=RESULT_COLUMNS)
        if new_file:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in RESULT_COLUMNS})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--strategies", default=",".join(DEFAULT_STRATEGIES),
                        help=f"逗号分隔；默认: {','.join(DEFAULT_STRATEGIES)}")
    parser.add_argument("--instruments", default=",".join(DEFAULT_INSTRUMENTS),
                        help=f"逗号分隔；默认 {len(DEFAULT_INSTRUMENTS)} 币")
    parser.add_argument("--bars", default=",".join(DEFAULT_BARS),
                        help=f"逗号分隔；默认: {','.join(DEFAULT_BARS)}")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="回测天数")
    parser.add_argument("--outdir", default=DEFAULT_OUTDIR, help="输出目录")
    parser.add_argument("--config", default="config.yaml", help="配置文件（读取 LLM key + 费率）")
    parser.add_argument("--parallel", type=int, default=4,
                        help="传统策略并行度；LLM 策略始终串行")
    parser.add_argument("--resume", action="store_true", help="跳过 results.csv 已有组合")
    parser.add_argument("--dry-run", action="store_true", help="只打印组合列表，不执行")
    parser.add_argument("--initial-capital", type=float, default=10_000.0)
    parser.add_argument("--fee-rate", type=float, default=0.001, help="往返手续费率")
    parser.add_argument("--slippage", type=float, default=0.0005)
    args = parser.parse_args()

    strategies = [s.strip() for s in args.strategies.split(",") if s.strip()]
    instruments = [i.strip() for i in args.instruments.split(",") if i.strip()]
    bars = [b.strip() for b in args.bars.split(",") if b.strip()]

    for s in strategies:
        if s not in STRATEGY_REGISTRY:
            print(f"错误: 未知策略 '{s}'。可选: {list(STRATEGY_REGISTRY.keys())}")
            return 1

    outdir = Path(args.outdir)
    outdir.mkdir(exist_ok=True)
    cache_dir = outdir / "candles"
    csv_path = outdir / "results.csv"

    # 加载配置（LLM key 等）
    cfg = load_yaml(args.config) if os.path.exists(args.config) else {}
    llm_cfg = cfg.get("llm", {}) or {}

    # 检查是否有 LLM 策略，有就必须要 key
    needs_llm = any(s in LLM_STRATEGIES for s in strategies)
    if needs_llm and not llm_cfg.get("api_key"):
        print("错误: 选中了 LLM 策略但 config.yaml/env 中无 llm.api_key")
        return 1

    combos = [(s, i, b) for s in strategies for i in instruments for b in bars]
    completed = load_completed(csv_path) if args.resume else set()
    todo = [c for c in combos if c not in completed]

    print(f"\n网格规模: {len(strategies)} 策略 × {len(instruments)} 币 × {len(bars)} 周期 = {len(combos)} 组合")
    print(f"已完成:   {len(completed)}")
    print(f"待执行:   {len(todo)}")
    print(f"回测天数: {args.days} ({args.days/365:.1f} 年)")
    print(f"输出:     {csv_path}")

    if args.dry_run:
        print("\n待执行组合:")
        for s, i, b in todo:
            print(f"  {s:<16} {i:<12} {b}")
        return 0

    if not todo:
        print("全部已完成，nothing to do")
        return 0

    # 第 1 步：拉完所有需要的 K 线数据（缓存）
    print("\n=== 第 1 步：预热 K 线数据 ===")
    client = OKXRestClient()  # 公共接口无需 auth
    fetcher = MarketDataFetcher(client)
    data_paths: dict[tuple[str, str], Path] = {}
    missing_data: set[tuple[str, str]] = set()
    for inst in instruments:
        for bar in bars:
            if not any((s, inst, bar) in todo for s in strategies):
                continue
            df = fetch_candles(fetcher, inst, bar, args.days, cache_dir)
            if df is None:
                missing_data.add((inst, bar))
                continue
            data_paths[(inst, bar)] = candle_cache_path(cache_dir, inst, bar, args.days)

    if missing_data:
        print(f"\n警告: {len(missing_data)} 个数据拉取失败，对应组合将跳过")

    # 分组：传统 = 并行，LLM = 串行
    trad_tasks = []
    llm_tasks = []
    for s, inst, bar in todo:
        if (inst, bar) in missing_data:
            continue
        args_tuple = (
            s, inst, bar, str(data_paths[(inst, bar)]),
            llm_cfg if s in LLM_STRATEGIES else None,
            args.fee_rate, args.slippage, args.initial_capital,
        )
        if s in LLM_STRATEGIES:
            llm_tasks.append(args_tuple)
        else:
            trad_tasks.append(args_tuple)

    total = len(trad_tasks) + len(llm_tasks)
    print(f"\n=== 第 2 步：执行 {len(trad_tasks)} 个传统 + {len(llm_tasks)} 个 LLM 组合 ===")

    done_count = 0
    t0 = time.perf_counter()

    # 2a. 传统策略并行
    if trad_tasks:
        with ProcessPoolExecutor(max_workers=args.parallel) as pool:
            futures = {pool.submit(run_one_safe, t): t for t in trad_tasks}
            for future in as_completed(futures):
                row = future.result()
                append_row(csv_path, row)
                done_count += 1
                elapsed = time.perf_counter() - t0
                eta = elapsed / done_count * (total - done_count)
                status = "✓" if not row.get("error") else "✗"
                print(
                    f"[{done_count:>3}/{total}] {status} {row['strategy']:<16} "
                    f"{row['inst_id']:<12} {row['bar']:<4} "
                    f"Sharpe={row['sharpe_ratio']:>6.2f} "
                    f"Ret={row['total_return_pct']:>7.2f}% "
                    f"MDD={row['max_drawdown_pct']:>6.2f}% "
                    f"n={row['n_trades']:<3} "
                    f"({row['elapsed_s']:>5.1f}s, ETA {eta/60:.1f}m)"
                )
                if row.get("error"):
                    print(f"        → {row['error'][:120]}")

    # 2b. LLM 策略 —— 也用进程池并行（并发度比传统低，给 DeepSeek 留余量）
    if llm_tasks:
        llm_parallel = max(1, min(args.parallel, 4))
        print(f"\n  LLM 并发度: {llm_parallel}")
        with ProcessPoolExecutor(max_workers=llm_parallel) as pool:
            futures = {pool.submit(run_one_safe, t): t for t in llm_tasks}
            for future in as_completed(futures):
                row = future.result()
                append_row(csv_path, row)
                done_count += 1
                elapsed = time.perf_counter() - t0
                eta = elapsed / done_count * (total - done_count)
                status = "✓" if not row.get("error") else "✗"
                print(
                    f"[{done_count:>3}/{total}] {status} {row['strategy']:<16} "
                    f"{row['inst_id']:<12} {row['bar']:<4} "
                    f"Sharpe={row['sharpe_ratio']:>6.2f} "
                    f"Ret={row['total_return_pct']:>7.2f}% "
                    f"MDD={row['max_drawdown_pct']:>6.2f}% "
                    f"n={row['n_trades']:<3} "
                    f"llm_calls={row.get('llm_calls', 0)} "
                    f"({row['elapsed_s']:>5.1f}s, ETA {eta/60:.1f}m)"
                )
                if row.get("error"):
                    print(f"        → {row['error'][:120]}")

    elapsed_min = (time.perf_counter() - t0) / 60
    print(f"\n=== 完成 {done_count} 组合，用时 {elapsed_min:.1f} 分钟 ===")
    print(f"结果: {csv_path}")
    print(f"下一步: uv run python scripts/backtest_report.py  # 生成汇总")
    return 0


if __name__ == "__main__":
    sys.exit(main())
