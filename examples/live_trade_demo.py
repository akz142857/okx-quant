"""实盘/模拟盘交易示例（需要 API Key）"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import yaml
from okx_quant.client.rest import OKXRestClient
from okx_quant.trading.executor import LiveTrader
from okx_quant.risk.manager import RiskConfig
from okx_quant.strategy import MACrossStrategy


def main():
    # 加载配置
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
    if not os.path.exists(config_path):
        print("请先复制 config.yaml.example 为 config.yaml 并填写 API Key")
        return

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    okx_cfg = cfg.get("okx", {})
    client = OKXRestClient(
        api_key=okx_cfg["api_key"],
        secret_key=okx_cfg["secret_key"],
        passphrase=okx_cfg["passphrase"],
        simulated=okx_cfg.get("simulated", True),  # 默认模拟盘
    )

    # 策略配置
    strategy = MACrossStrategy({"fast_period": 9, "slow_period": 21})

    # 风控配置
    risk_config = RiskConfig(
        max_position_pct=0.10,   # 单次最多用 10% 仓位
        stop_loss_pct=0.02,      # 2% 止损
        take_profit_pct=0.04,    # 4% 止盈
        max_drawdown_pct=0.15,   # 最大回撤 15% 停止交易
        min_order_usdt=10.0,
    )

    mode = "【模拟盘】" if okx_cfg.get("simulated") else "【实盘】"
    print(f"\n{mode} 启动交易 BTC-USDT | 策略: {strategy} | 周期: 1H")
    print("按 Ctrl+C 停止\n")

    trader = LiveTrader(
        client=client,
        strategy=strategy,
        inst_id="BTC-USDT",
        risk_config=risk_config,
    )

    trader.run(
        bar="1H",
        lookback=100,
        interval_seconds=60,  # 每分钟检查一次（1H 策略不必要太频繁）
    )


if __name__ == "__main__":
    main()
