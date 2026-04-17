"""OKX WebSocket 客户端，支持公共/私有频道订阅

NOTE: 此模块已完整实现但尚未集成到实盘执行器（当前使用 REST 轮询）。
保留供未来切换到实时行情推送；如需移除请同步更新 ``client/__init__.py`` 的导出。
"""

import asyncio
import hashlib
import hmac
import base64
import json
import logging
import time
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)

PUBLIC_WS_URL = "wss://ws.okx.com:8443/ws/v5/public"
PRIVATE_WS_URL = "wss://ws.okx.com:8443/ws/v5/private"
BUSINESS_WS_URL = "wss://ws.okx.com:8443/ws/v5/business"  # 历史 K 线订阅


class OKXWebSocketClient:
    """OKX WebSocket 订阅客户端

    用法示例::

        client = OKXWebSocketClient(api_key=..., secret_key=..., passphrase=...)

        async def on_ticker(data):
            print(data)

        await client.subscribe_ticker("BTC-USDT", on_ticker)
        await client.run()
    """

    def __init__(
        self,
        api_key: str = "",
        secret_key: str = "",
        passphrase: str = "",
        simulated: bool = False,
    ):
        self.api_key = api_key
        self.secret_key = secret_key
        self.passphrase = passphrase
        self.simulated = simulated
        self._handlers: dict[str, list[Callable]] = {}  # channel -> [callback]
        self._public_channels: list[dict] = []
        self._private_channels: list[dict] = []
        self._running = False

    # -------------------------------------------------------------------------
    # 内部签名
    # -------------------------------------------------------------------------

    def _sign_login(self) -> dict:
        ts = str(int(time.time()))
        message = ts + "GET" + "/users/self/verify"
        mac = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256,
        )
        sign = base64.b64encode(mac.digest()).decode()
        return {
            "op": "login",
            "args": [
                {
                    "apiKey": self.api_key,
                    "passphrase": self.passphrase,
                    "timestamp": ts,
                    "sign": sign,
                }
            ],
        }

    # -------------------------------------------------------------------------
    # 订阅注册
    # -------------------------------------------------------------------------

    def _add_handler(self, channel_key: str, callback: Callable):
        self._handlers.setdefault(channel_key, []).append(callback)

    def subscribe_ticker(self, inst_id: str, callback: Callable):
        """订阅实时 Ticker"""
        arg = {"channel": "tickers", "instId": inst_id}
        self._public_channels.append(arg)
        self._add_handler(f"tickers:{inst_id}", callback)

    def subscribe_candle(self, inst_id: str, bar: str, callback: Callable):
        """订阅 K 线推送（如 candle1m, candle1H）"""
        channel = f"candle{bar}"
        arg = {"channel": channel, "instId": inst_id}
        self._public_channels.append(arg)
        self._add_handler(f"{channel}:{inst_id}", callback)

    def subscribe_orderbook(self, inst_id: str, callback: Callable, depth: str = "books5"):
        """订阅订单簿（books/books5/books-l2-tbt）"""
        arg = {"channel": depth, "instId": inst_id}
        self._public_channels.append(arg)
        self._add_handler(f"{depth}:{inst_id}", callback)

    def subscribe_account(self, callback: Callable, ccy: str = ""):
        """订阅账户余额推送（私有）"""
        arg = {"channel": "account"}
        if ccy:
            arg["ccy"] = ccy
        self._private_channels.append(arg)
        key = f"account:{ccy}" if ccy else "account"
        self._add_handler(key, callback)

    def subscribe_orders(self, inst_type: str, inst_id: str, callback: Callable):
        """订阅订单推送（私有）"""
        arg = {"channel": "orders", "instType": inst_type, "instId": inst_id}
        self._private_channels.append(arg)
        self._add_handler(f"orders:{inst_id}", callback)

    # -------------------------------------------------------------------------
    # 消息分发
    # -------------------------------------------------------------------------

    def _dispatch(self, message: dict):
        arg = message.get("arg", {})
        channel = arg.get("channel", "")
        inst_id = arg.get("instId", "")
        ccy = arg.get("ccy", "")

        # 构建频道 key
        if inst_id:
            key = f"{channel}:{inst_id}"
        elif ccy:
            key = f"{channel}:{ccy}"
        else:
            key = channel

        data = message.get("data", [])
        for handler in self._handlers.get(key, []):
            try:
                handler(data)
            except Exception as e:
                logger.error("消息处理器异常 [%s]: %s", key, e)

    # -------------------------------------------------------------------------
    # 异步运行
    # -------------------------------------------------------------------------

    async def _run_public(self):
        import websockets

        while self._running:
            try:
                async with websockets.connect(PUBLIC_WS_URL, ping_interval=20) as ws:
                    if self._public_channels:
                        sub_msg = {"op": "subscribe", "args": self._public_channels}
                        await ws.send(json.dumps(sub_msg))
                        logger.info("已订阅公共频道: %s", self._public_channels)

                    async for raw in ws:
                        if not self._running:
                            break
                        try:
                            msg = json.loads(raw)
                            if "data" in msg:
                                self._dispatch(msg)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                if self._running:
                    logger.warning("公共 WS 断线，5s 后重连: %s", e)
                    await asyncio.sleep(5)

    async def _run_private(self):
        if not self._private_channels:
            return
        if not self.api_key:
            raise ValueError("私有频道需要 API Key")

        import websockets

        while self._running:
            try:
                async with websockets.connect(PRIVATE_WS_URL, ping_interval=20) as ws:
                    # 登录
                    await ws.send(json.dumps(self._sign_login()))
                    resp = json.loads(await ws.recv())
                    if resp.get("event") != "login" or resp.get("code") != "0":
                        raise RuntimeError(f"WS 登录失败: {resp}")

                    # 订阅私有频道
                    sub_msg = {"op": "subscribe", "args": self._private_channels}
                    await ws.send(json.dumps(sub_msg))
                    logger.info("已订阅私有频道: %s", self._private_channels)

                    async for raw in ws:
                        if not self._running:
                            break
                        try:
                            msg = json.loads(raw)
                            if "data" in msg:
                                self._dispatch(msg)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                if self._running:
                    logger.warning("私有 WS 断线，5s 后重连: %s", e)
                    await asyncio.sleep(5)

    async def run(self):
        """启动 WebSocket 连接（阻塞直到调用 stop()）"""
        self._running = True
        tasks = [asyncio.create_task(self._run_public())]
        if self._private_channels:
            tasks.append(asyncio.create_task(self._run_private()))
        await asyncio.gather(*tasks)

    def stop(self):
        self._running = False
