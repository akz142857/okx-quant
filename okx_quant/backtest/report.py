"""回测结果报告展示"""

import pandas as pd
from tabulate import tabulate

from okx_quant.backtest.engine import BacktestResult


class BacktestReport:
    """回测结果打印与分析"""

    def __init__(self, result: BacktestResult):
        self.result = result

    def print_summary(self):
        """打印绩效摘要"""
        m = self.result.metrics
        if not m or m.get("total_trades", 0) == 0:
            print("回测完成，无交易记录")
            return

        rows = [
            ["初始资金", f"${m['initial_capital']:,.2f}"],
            ["最终资金", f"${m['final_capital']:,.2f}"],
            ["总收益率", f"{m['total_return_pct']:.2f}%"],
            ["年化收益率", f"{m['annual_return_pct']:.2f}%"],
            ["最大回撤", f"{m['max_drawdown_pct']:.2f}%"],
            ["Sharpe 比率", f"{m['sharpe_ratio']:.4f}"],
            ["", ""],
            ["总交易次数", m["total_trades"]],
            ["盈利次数", m["win_trades"]],
            ["亏损次数", m["loss_trades"]],
            ["胜率", f"{m['win_rate_pct']:.2f}%"],
            ["平均盈利", f"${m['avg_win']:.4f}"],
            ["平均亏损", f"${m['avg_loss']:.4f}"],
            ["盈亏比", f"{m['profit_factor']:.4f}"],
            ["总盈亏", f"${m['total_pnl']:.4f}"],
            ["总手续费", f"${m['total_fee']:.4f}"],
        ]
        print("\n" + "=" * 50)
        print("  回测绩效报告")
        print("=" * 50)
        print(tabulate(rows, tablefmt="simple"))
        print("=" * 50)

    def print_trades(self, max_rows: int = 20):
        """打印交易明细"""
        trades = self.result.trades
        if not trades:
            print("无交易记录")
            return

        rows = []
        for t in trades[-max_rows:]:
            rows.append(
                [
                    str(t.open_ts)[:16],
                    str(t.close_ts)[:16] if t.close_ts else "-",
                    t.inst_id,
                    t.direction,
                    f"{t.entry_price:.4f}",
                    f"{t.exit_price:.4f}",
                    f"{t.size:.6f}",
                    f"${t.pnl:.4f}",
                    f"{t.pnl_pct:.2f}%",
                    t.reason_close,
                ]
            )

        headers = ["开仓时间", "平仓时间", "品种", "方向", "入场价", "出场价", "数量", "盈亏", "盈亏%", "平仓原因"]
        print(f"\n--- 最近 {len(rows)} 笔交易 ---")
        print(tabulate(rows, headers=headers, tablefmt="simple"))

    def equity_to_csv(self, path: str):
        """导出权益曲线到 CSV"""
        self.result.equity_curve.to_csv(path, header=True)
        print(f"权益曲线已保存至: {path}")

    def trades_to_dataframe(self) -> pd.DataFrame:
        """将交易记录转换为 DataFrame"""
        return pd.DataFrame(
            [
                {
                    "open_ts": t.open_ts,
                    "close_ts": t.close_ts,
                    "inst_id": t.inst_id,
                    "direction": t.direction,
                    "entry_price": t.entry_price,
                    "exit_price": t.exit_price,
                    "size": t.size,
                    "pnl": t.pnl,
                    "pnl_pct": t.pnl_pct,
                    "fee": t.fee,
                    "reason_open": t.reason_open,
                    "reason_close": t.reason_close,
                }
                for t in self.result.trades
            ]
        )
