"""OKX WebSocket 客户端，支持公共/私有/业务频道订阅。"""

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import logging
import threading
import time
from collections.abc import Callable
from enum import StrEnum

logger = logging.getLogger(__name__)

PUBLIC_WS_URL = "wss://ws.okx.com:8443/ws/v5/public"
PRIVATE_WS_URL = "wss://ws.okx.com:8443/ws/v5/private"
BUSINESS_WS_URL = "wss://ws.okx.com:8443/ws/v5/business"  # 历史 K 线订阅
DEMO_PRIVATE_WS_URL = "wss://wspap.okx.com:8443/ws/v5/private"
DEMO_BUSINESS_WS_URL = "wss://wspap.okx.com:8443/ws/v5/business"
DEMO_PUBLIC_WS_URL = "wss://wspap.okx.com:8443/ws/v5/public"
WS_PING_INTERVAL_SECONDS = 10
WS_PING_TIMEOUT_SECONDS = 5
WS_DISCONNECT_DETECTION_BOUND_SECONDS = (
    WS_PING_INTERVAL_SECONDS + WS_PING_TIMEOUT_SECONDS
)


class ConnectionState(StrEnum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    SUBSCRIBING = "subscribing"
    READY = "ready"
    STALE = "stale"
    BACKOFF = "backoff"


class OKXWebSocketClient:
    """OKX WebSocket 订阅客户端

    用法示例::

        client = OKXWebSocketClient(api_key=..., secret_key=..., passphrase=...)

        async def on_ticker(data):
            logger.info("ticker: %s", data)

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
        self._business_channels: list[dict] = []
        self._running = False
        self._states: dict[str, ConnectionState] = {
            "public": ConnectionState.DISCONNECTED,
            "private": ConnectionState.DISCONNECTED,
            "business": ConnectionState.DISCONNECTED,
        }
        self._last_message_at: dict[str, float] = {
            "public": 0.0,
            "private": 0.0,
            "business": 0.0,
        }
        self._state_handlers: list[Callable[[str, ConnectionState], None]] = []
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connections: dict[str, object] = {}

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
        arg = {"channel": "orders", "instType": inst_type}
        if inst_id:
            arg["instId"] = inst_id
        self._private_channels.append(arg)
        self._add_handler(f"orders:{inst_id}" if inst_id else "orders", callback)

    def subscribe_balance_and_position(self, callback: Callable):
        """订阅余额和持仓变化（私有）。"""
        self._private_channels.append({"channel": "balance_and_position"})
        self._add_handler("balance_and_position", callback)

    def subscribe_algo_orders(self, callback: Callable, inst_type: str = "ANY"):
        """订阅普通 algo order 更新（business WS）。"""
        self._business_channels.append({
            "channel": "orders-algo",
            "instType": inst_type,
        })
        self._add_handler("orders-algo", callback)

    def add_state_handler(self, callback: Callable[[str, ConnectionState], None]) -> None:
        self._state_handlers.append(callback)

    def connection_state(self, name: str) -> ConnectionState:
        return self._states[name]

    def last_message_age(self, name: str) -> float:
        ts = self._last_message_at.get(name, 0.0)
        return time.time() - ts if ts > 0 else float("inf")

    @property
    def private_ready(self) -> bool:
        required = []
        if self._private_channels:
            required.append(self._states["private"] is ConnectionState.READY)
        if self._business_channels:
            required.append(self._states["business"] is ConnectionState.READY)
        return bool(required) and all(required)

    @property
    def public_required(self) -> bool:
        return bool(self._public_channels)

    @property
    def public_ready(self) -> bool:
        return (
            not self.public_required
            or self._states["public"] is ConnectionState.READY
        )

    def _set_state(self, name: str, state: ConnectionState) -> None:
        if self._states.get(name) is state:
            return
        self._states[name] = state
        for handler in self._state_handlers:
            try:
                handler(name, state)
            except Exception as exc:  # noqa: BLE001
                logger.error("WS 状态处理器异常 [%s]: %s", name, exc)

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
        handlers = list(self._handlers.get(key, []))
        # ANY 订阅注册在纯 channel key，下发消息通常带 instId。
        if inst_id:
            handlers.extend(self._handlers.get(channel, []))
        for handler in handlers:
            try:
                handler(data)
            except Exception as e:
                logger.error("消息处理器异常 [%s]: %s", key, e)

    # -------------------------------------------------------------------------
    # 异步运行
    # -------------------------------------------------------------------------

    async def _run_connection(
        self,
        *,
        name: str,
        url: str,
        channels: list[dict],
        authenticated: bool,
    ):
        import websockets

        while self._running:
            try:
                self._set_state(name, ConnectionState.CONNECTING)
                async with websockets.connect(
                    url,
                    ping_interval=WS_PING_INTERVAL_SECONDS,
                    ping_timeout=WS_PING_TIMEOUT_SECONDS,
                    close_timeout=5,
                ) as ws:
                    self._connections[name] = ws
                    if authenticated:
                        self._set_state(name, ConnectionState.AUTHENTICATING)
                        await ws.send(json.dumps(self._sign_login()))
                        response = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                        if response.get("event") != "login" or response.get("code") != "0":
                            raise RuntimeError(f"WS 登录失败: {response}")
                    if channels:
                        self._set_state(name, ConnectionState.SUBSCRIBING)
                        sub_msg = {"op": "subscribe", "args": channels}
                        await ws.send(json.dumps(sub_msg))
                        pending_subscriptions = {
                            json.dumps(arg, sort_keys=True, separators=(",", ":"))
                            for arg in channels
                        }
                        logger.info("已订阅 %s 频道: %s", name, channels)
                    else:
                        pending_subscriptions = set()
                        self._set_state(name, ConnectionState.READY)

                    async for raw in ws:
                        if not self._running:
                            break
                        self._last_message_at[name] = time.time()
                        try:
                            msg = json.loads(raw)
                            if msg.get("event") == "subscribe":
                                acknowledged = json.dumps(
                                    msg.get("arg", {}),
                                    sort_keys=True,
                                    separators=(",", ":"),
                                )
                                pending_subscriptions.discard(acknowledged)
                                if not pending_subscriptions:
                                    self._set_state(name, ConnectionState.READY)
                                continue
                            if msg.get("event") == "error":
                                raise RuntimeError(f"WS 订阅错误: {msg}")
                            if "data" in msg:
                                if not pending_subscriptions:
                                    self._set_state(name, ConnectionState.READY)
                                self._dispatch(msg)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                if self._running:
                    self._set_state(name, ConnectionState.BACKOFF)
                    logger.warning("%s WS 断线，5s 后重连: %s", name, e)
                    await asyncio.sleep(5)
            finally:
                self._connections.pop(name, None)
        self._set_state(name, ConnectionState.DISCONNECTED)

    async def run(self):
        """启动 WebSocket 连接（阻塞直到调用 stop()）"""
        if (self._private_channels or self._business_channels) and not self.api_key:
            raise ValueError("私有频道需要 API Key")
        if not self._running:
            self._running = True
        self._loop = asyncio.get_running_loop()
        tasks = []
        if self._public_channels:
            tasks.append(asyncio.create_task(self._run_connection(
                name="public",
                url=DEMO_PUBLIC_WS_URL if self.simulated else PUBLIC_WS_URL,
                channels=self._public_channels,
                authenticated=False,
            )))
        if self._private_channels:
            tasks.append(asyncio.create_task(self._run_connection(
                name="private",
                url=DEMO_PRIVATE_WS_URL if self.simulated else PRIVATE_WS_URL,
                channels=self._private_channels,
                authenticated=True,
            )))
        if self._business_channels:
            tasks.append(asyncio.create_task(self._run_connection(
                name="business",
                url=DEMO_BUSINESS_WS_URL if self.simulated else BUSINESS_WS_URL,
                channels=self._business_channels,
                authenticated=True,
            )))
        if not tasks:
            raise ValueError("未注册任何 WebSocket 订阅")
        await asyncio.gather(*tasks)

    def run_in_thread(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running = True

        def target() -> None:
            asyncio.run(self.run())

        self._thread = threading.Thread(
            target=target,
            name="okx-websocket",
            daemon=False,
        )
        self._thread.start()

    def stop(self, timeout: float = 10):
        self._running = False
        loop = self._loop
        if loop and loop.is_running():
            async def close_connections():
                await asyncio.gather(
                    *[
                        connection.close()
                        for connection in list(self._connections.values())
                    ],
                    return_exceptions=True,
                )

            with contextlib.suppress(Exception):
                asyncio.run_coroutine_threadsafe(
                    close_connections(), loop
                ).result(timeout=min(timeout, 5))
        for name in self._states:
            self._set_state(name, ConnectionState.DISCONNECTED)
        if (
            self._thread
            and self._thread.is_alive()
            and self._thread is not threading.current_thread()
        ):
            self._thread.join(timeout=timeout)
        self._loop = None
