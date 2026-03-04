"""行情数据示例：获取 K 线和实时行情（无需 API Key）"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from okx_quant.client.rest import OKXRestClient
from okx_quant.data.market import MarketDataFetcher
from okx_quant.indicators import ema, macd, rsi, bollinger_bands


def main():
    client = OKXRestClient()  # 公共行情无需鉴权
    fetcher = MarketDataFetcher(client)

    inst_id = "BTC-USDT"

    # 实时行情
    print(f"=== {inst_id} 实时行情 ===")
    ticker = fetcher.get_ticker(inst_id)
    for k, v in ticker.items():
        print(f"  {k}: {v}")

    # K 线 + 技术指标
    print(f"\n=== {inst_id} 1H K 线 (最近 5 根) + 技术指标 ===")
    df = fetcher.get_candles(inst_id, bar="1H", limit=50)

    df["ema9"] = ema(df["close"], 9)
    df["ema21"] = ema(df["close"], 21)
    df["rsi14"] = rsi(df["close"], 14)

    macd_df = macd(df["close"])
    df["macd"] = macd_df["macd"]
    df["macd_signal"] = macd_df["signal"]
    df["macd_hist"] = macd_df["histogram"]

    bb = bollinger_bands(df["close"])
    df["bb_upper"] = bb["upper"]
    df["bb_lower"] = bb["lower"]

    cols = ["ts", "close", "ema9", "ema21", "rsi14", "macd", "macd_hist", "bb_upper", "bb_lower"]
    print(df[cols].tail(5).to_string(index=False))

    # 订单簿
    print(f"\n=== {inst_id} 订单簿 (买卖各 3 档) ===")
    book = fetcher.get_orderbook(inst_id, depth=3)
    print("卖单 (Asks):")
    for ask in reversed(book["asks"]):
        print(f"  价格: {ask['price']:,.2f}  数量: {ask['size']:.6f}")
    print("买单 (Bids):")
    for bid in book["bids"]:
        print(f"  价格: {bid['price']:,.2f}  数量: {bid['size']:.6f}")


if __name__ == "__main__":
    main()
