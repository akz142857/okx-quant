"""回测示例：对比三个策略在 BTC-USDT 4H 上的表现"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from okx_quant.client.rest import OKXRestClient
from okx_quant.data.market import MarketDataFetcher
from okx_quant.backtest import BacktestEngine, BacktestReport
from okx_quant.strategy import MACrossStrategy, RSIMeanReversionStrategy, BollingerBandStrategy


def run_backtest(df, strategy, inst_id, initial_capital=10000):
    engine = BacktestEngine(initial_capital=initial_capital, fee_rate=0.001, slippage=0.0005)
    result = engine.run(df, strategy, inst_id)
    return result


def main():
    # 公共接口无需 API Key
    client = OKXRestClient()
    fetcher = MarketDataFetcher(client)
    inst_id = "BTC-USDT"
    bar = "4H"

    print(f"正在获取 {inst_id} {bar} 历史 K 线（约 180 天）...")
    df = fetcher.get_history_candles(inst_id, bar=bar, total=1080)
    print(f"获取完成: {len(df)} 根 K 线\n")

    strategies = [
        ("双均线金叉/死叉", MACrossStrategy({"fast_period": 9, "slow_period": 21})),
        ("RSI 均值回归", RSIMeanReversionStrategy({"rsi_period": 14, "oversold": 30, "overbought": 70})),
        ("布林带策略", BollingerBandStrategy({"bb_period": 20, "bb_std": 2.0})),
    ]

    results = []
    for name, strategy in strategies:
        print(f"=== 回测: {name} ===")
        result = run_backtest(df, strategy, inst_id)
        report = BacktestReport(result)
        report.print_summary()
        results.append((name, result.metrics))
        print()

    # 对比摘要
    print("\n" + "=" * 70)
    print(f"  策略对比摘要 ({inst_id} {bar})")
    print("=" * 70)
    print(f"{'策略':<20} {'总收益%':>10} {'最大回撤%':>12} {'Sharpe':>10} {'胜率%':>10} {'交易次数':>10}")
    print("-" * 70)
    for name, m in results:
        if m.get("total_trades", 0) > 0:
            print(
                f"{name:<20} {m['total_return_pct']:>10.2f} {m['max_drawdown_pct']:>12.2f} "
                f"{m['sharpe_ratio']:>10.4f} {m['win_rate_pct']:>10.2f} {m['total_trades']:>10}"
            )
        else:
            print(f"{name:<20} {'无交易':>10}")
    print("=" * 70)


if __name__ == "__main__":
    main()
