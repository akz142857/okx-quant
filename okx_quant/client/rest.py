"""OKX REST API 客户端，支持鉴权和模拟盘"""

import base64
import contextlib
import hashlib
import hmac
import json
import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import requests

# OKX V5 业务数据返回类型：公共接口通常是 list[dict]，部分返回单个 dict，也可能为 None
OKXData = list | dict | None

logger = logging.getLogger(__name__)


class OKXRestClient:
    """OKX V5 REST API 客户端

    公共接口无需鉴权，私有接口（账户/下单）需要 API Key。
    设置 simulated=True 可切换到模拟盘（Sandbox）。
    """

    BASE_URL = "https://openapi.okx.com"

    # OKX V5 错误码：触发速率限制（需退避重试）
    # 参考: https://www.okx.com/docs-v5/zh/#error-code
    _RATE_LIMIT_CODES: frozenset[str] = frozenset({
        "50011",  # User/IP 限速
        "50013",  # 系统繁忙
        "50061",  # 批量下单过快
    })
    _GLOBAL_RATE_LOCK = threading.Lock()
    _GLOBAL_NOT_BEFORE = 0.0
    _MAX_WRITE_TIMEOUT_SECONDS = 3

    def __init__(
        self,
        api_key: str = "",
        secret_key: str = "",
        passphrase: str = "",
        simulated: bool = False,
        timeout: int = 15,
        max_retries: int = 3,
        proxy: str = "",
        base_url: str = "",
        request_observer: Callable[[str, str, float], None] | None = None,
    ):
        self.api_key = api_key
        self.secret_key = secret_key
        self.passphrase = passphrase
        self.simulated = simulated
        self.timeout = timeout
        self.max_retries = max_retries
        self.base_url = (base_url or self.BASE_URL).rstrip("/")
        self.request_observer = request_observer
        self._proxy = proxy
        # requests.Session 非线程安全；Supervisor 多 worker 线程共享同一个
        # OKXRestClient，故每线程持有独立 Session。连接出错时只重建本线程的
        # session，不影响其它线程的在途请求。
        self._local = threading.local()

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"Content-Type": "application/json"})
        if self._proxy:
            s.proxies = {"http": self._proxy, "https": self._proxy}
        return s

    @property
    def _session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = self._make_session()
            self._local.session = s
        return s

    def _reset_session(self) -> None:
        """关闭并重建当前线程的 session（连接/SSL 错误后调用）"""
        s = getattr(self._local, "session", None)
        if s is not None:
            with contextlib.suppress(Exception):
                s.close()
        self._local.session = self._make_session()

    # -------------------------------------------------------------------------
    # 内部签名方法
    # -------------------------------------------------------------------------

    def _timestamp(self) -> str:
        """生成 ISO8601 UTC 时间戳"""
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _sign(self, timestamp: str, method: str, path: str, body: str = "") -> str:
        """HMAC-SHA256 签名"""
        message = f"{timestamp}{method.upper()}{path}{body}"
        mac = hmac.new(
            self.secret_key.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        )
        return base64.b64encode(mac.digest()).decode("utf-8")

    def _auth_headers(self, method: str, path: str, body: str = "") -> dict:
        ts = self._timestamp()
        # x-simulated-trading 由 _request 统一注入（auth/非 auth 路径都覆盖），
        # 此处不再重复添加，避免两处维护。
        return {
            "OK-ACCESS-KEY": self.api_key,
            "OK-ACCESS-SIGN": self._sign(ts, method, path, body),
            "OK-ACCESS-TIMESTAMP": ts,
            "OK-ACCESS-PASSPHRASE": self.passphrase,
        }

    # -------------------------------------------------------------------------
    # 底层请求
    # -------------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        body: dict | None = None,
        auth: bool = False,
        *,
        max_attempts: int | None = None,
        timeout_override: float | None = None,
    ) -> OKXData:
        url = self.base_url + path
        body_str = json.dumps(body) if body else ""
        headers: dict[str, str] = {}

        if auth:
            if not self.api_key:
                raise ValueError("私有接口需要 API Key，请在配置中填写鉴权信息")
            # OKX 签名要求 GET path 包含 query string
            sign_path = path
            if params:
                sign_path = f"{path}?{urlencode(params)}"
            headers = self._auth_headers(method, sign_path, body_str)

        if self.simulated:
            headers["x-simulated-trading"] = "1"

        data: Any = None
        last_exc: Exception | None = None
        attempt_limit = (
            self.max_retries
            if max_attempts is None
            else max(1, min(max_attempts, self.max_retries))
        )
        for attempt in range(1, attempt_limit + 1):
            self._wait_for_global_rate_limit()
            request_started = time.monotonic()
            request_observed = False
            try:
                resp = self._session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=body_str if body_str else None,
                    timeout=(
                        min(self.timeout, timeout_override)
                        if timeout_override is not None
                        else (
                            self.timeout
                            if method.upper() == "GET"
                            else min(
                                self.timeout,
                                self._MAX_WRITE_TIMEOUT_SECONDS,
                            )
                        )
                    ),
                )
                if not 200 <= resp.status_code < 400:
                    self._observe_request(
                        path,
                        str(resp.status_code),
                        time.monotonic() - request_started,
                    )
                    request_observed = True
                # GET 的 429 可以显式退避。写请求的 429 无法证明请求未被
                # 交易所接受，必须原样交给上层 UNKNOWN resolver，绝不能
                # 在 REST 层重放 POST。
                if resp.status_code == 429 and method.upper() == "GET":
                    wait = self._backoff_delay(attempt, resp.headers.get("Retry-After"))
                    self._defer_global_requests(wait)
                    logger.warning(
                        "HTTP 429 限速 (%d/%d)，%.1fs 后重试: %s %s",
                        attempt, attempt_limit, wait, method, url,
                    )
                    if attempt < attempt_limit:
                        if auth:
                            headers.update(self._refresh_auth(method, path, params, body_str))
                        continue
                elif resp.status_code == 429:
                    self._defer_global_requests(
                        self._backoff_delay(
                            attempt,
                            resp.headers.get("Retry-After"),
                        )
                    )
                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, dict):
                    self._observe_request(
                        path,
                        "OKX:malformed",
                        time.monotonic() - request_started,
                    )
                    request_observed = True
                    raise RuntimeError("OKX API 响应必须是 JSON 对象")
                # HTTP 200 仍可能携带 OKX 业务/基础设施错误码。若先把 200
                # 记为成功，每次错误都会重置连续错误预算，永远无法 HALT。
                business_code = str(data.get("code", "missing"))
                self._observe_request(
                    path,
                    f"OKX:{business_code}",
                    time.monotonic() - request_started,
                )
                request_observed = True
            except (requests.ConnectionError, requests.Timeout) as e:
                if not request_observed:
                    self._observe_request(
                        path,
                        type(e).__name__,
                        time.monotonic() - request_started,
                    )
                last_exc = e
                # SSL/连接错误后清理本线程连接池，避免复用损坏的连接
                self._reset_session()
                # 交易类 POST 的请求是否已被 OKX 接受不可知。这里必须把
                # 歧义交给上层 UNKNOWN resolver，绝不能在 REST 层盲重试。
                if method.upper() != "GET":
                    logger.error(
                        "POST 响应丢失，禁止自动重试: %s %s -> %s",
                        method,
                        url,
                        e,
                    )
                    raise
                if attempt < attempt_limit:
                    wait = self._backoff_delay(attempt)
                    logger.warning(
                        "HTTP 请求超时/连接失败 (%d/%d)，%.1fs 后重试: %s %s",
                        attempt, attempt_limit, wait, method, url,
                    )
                    time.sleep(wait)
                    if auth:
                        headers.update(self._refresh_auth(method, path, params, body_str))
                    continue
                logger.error("HTTP 请求失败 (已重试 %d 次): %s %s -> %s", attempt_limit, method, url, e)
                raise
            except requests.RequestException as e:
                if not request_observed:
                    self._observe_request(
                        path,
                        type(e).__name__,
                        time.monotonic() - request_started,
                    )
                logger.error("HTTP 请求失败: %s %s -> %s", method, url, e)
                raise

            # 解析 OKX 业务错误码
            code = data.get("code")
            if code == "0":
                return data.get("data")

            # 只有 GET 的业务限速码可以安全重试。交易写收到业务限速码时，
            # 服务端是否在限速判定前接纳请求并不由客户端掌握，因此按歧义
            # 写失败交给 clOrdId/algoClOrdId 查询解析。
            if (
                code in self._RATE_LIMIT_CODES
                and method.upper() == "GET"
                and attempt < attempt_limit
            ):
                wait = self._backoff_delay(attempt)
                logger.warning(
                    "OKX 限速 [%s] (%d/%d)，%.1fs 后重试: %s %s",
                    code, attempt, attempt_limit, wait, method, url,
                )
                self._defer_global_requests(wait)
                if auth:
                    headers.update(self._refresh_auth(method, path, params, body_str))
                continue
            if code in self._RATE_LIMIT_CODES and method.upper() == "GET":
                self._defer_global_requests(self._backoff_delay(attempt))
            if code in self._RATE_LIMIT_CODES and method.upper() != "GET":
                self._defer_global_requests(self._backoff_delay(attempt))
                msg = data.get("msg", "交易写请求被限速")
                raise requests.RequestException(
                    f"ambiguous OKX write rate limit [{code}]: {msg}"
                )

            # 其它业务错误直接抛出
            msg = data.get("msg", "未知错误")
            details = ""
            items = data.get("data")
            if isinstance(items, list):
                parts = [f"sCode={it.get('sCode')} sMsg={it.get('sMsg')}" for it in items if it.get("sCode")]
                if parts:
                    details = " | 详情: " + "; ".join(parts)
            logger.error("OKX API 错误 [%s]: %s%s", code, msg, details)
            raise RuntimeError(f"OKX API Error [{code}]: {msg}{details}")

        # 重试耗尽仍未成功
        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"OKX API 请求失败（已重试 {attempt_limit} 次）: {method} {url}")

    def _observe_request(self, endpoint: str, code: str, latency_s: float) -> None:
        observer = self.request_observer
        if observer is None:
            return
        try:
            observer(endpoint, code, latency_s)
        except Exception:  # metrics must never break trading
            logger.debug("请求指标回调失败", exc_info=True)

    @classmethod
    def _defer_global_requests(cls, delay_s: float) -> None:
        """把限速退避发布到进程内所有 client/线程。"""
        with cls._GLOBAL_RATE_LOCK:
            cls._GLOBAL_NOT_BEFORE = max(
                cls._GLOBAL_NOT_BEFORE,
                time.monotonic() + max(delay_s, 0),
            )

    @classmethod
    def _wait_for_global_rate_limit(cls) -> None:
        with cls._GLOBAL_RATE_LOCK:
            deadline = cls._GLOBAL_NOT_BEFORE
        delay = deadline - time.monotonic()
        if delay <= 0:
            return
        time.sleep(delay)
        with cls._GLOBAL_RATE_LOCK:
            if deadline >= cls._GLOBAL_NOT_BEFORE:
                cls._GLOBAL_NOT_BEFORE = 0.0

    @staticmethod
    def _backoff_delay(attempt: int, retry_after: str | None = None) -> float:
        """指数退避延迟，支持服务端 Retry-After 头部"""
        if retry_after:
            try:
                return max(float(retry_after), 0.5)
            except (TypeError, ValueError):
                pass
        # 2s, 4s, 8s, 16s ... 上限 30s
        return min(2 ** attempt, 30.0)

    def _refresh_auth(
        self,
        method: str,
        path: str,
        params: dict | None,
        body_str: str,
    ) -> dict:
        """重试前刷新签名（时间戳必须更新）"""
        sign_path = path
        if params:
            sign_path = f"{path}?{urlencode(params)}"
        return self._auth_headers(method, sign_path, body_str)

    def get(self, path: str, params: dict | None = None, auth: bool = False) -> Any:
        return self._request("GET", path, params=params, auth=auth)

    def post(self, path: str, body: Any = None, auth: bool = True) -> Any:
        return self._request("POST", path, body=body, auth=auth)

    # -------------------------------------------------------------------------
    # 公共行情接口
    # -------------------------------------------------------------------------

    def get_ticker(self, inst_id: str) -> dict:
        """获取单个品种实时 Ticker"""
        result = self.get("/api/v5/market/ticker", {"instId": inst_id})
        return result[0] if result else {}

    def get_server_time(self) -> float:
        """返回 OKX 服务器 Unix 时间（秒）。"""
        result = self.get("/api/v5/public/time") or []
        if not result or not result[0].get("ts"):
            raise RuntimeError("OKX server time 响应为空")
        return float(result[0]["ts"]) / 1000

    def get_tickers(self, inst_type: str = "SPOT") -> list[dict]:
        """获取所有现货 Ticker"""
        return self.get("/api/v5/market/tickers", {"instType": inst_type}) or []

    def get_candles(
        self,
        inst_id: str,
        bar: str = "1H",
        limit: int = 100,
        after: str | None = None,
        before: str | None = None,
    ) -> list[list]:
        """获取历史 K 线数据

        Args:
            inst_id: 交易对，如 "BTC-USDT"
            bar: K 线周期，1m/3m/5m/15m/30m/1H/2H/4H/6H/12H/1D/1W/1M
            limit: 返回条数，最大 300
            after: 分页游标（时间戳毫秒），取此时间之前的数据
            before: 分页游标，取此时间之后的数据

        Returns:
            列表元素: [ts, open, high, low, close, vol, volCcy, volCcyQuote, confirm]
        """
        params: dict = {"instId": inst_id, "bar": bar, "limit": str(limit)}
        if after:
            params["after"] = after
        if before:
            params["before"] = before
        return self.get("/api/v5/market/candles", params) or []

    def get_history_candles(
        self,
        inst_id: str,
        bar: str = "1H",
        limit: int = 100,
        after: str | None = None,
    ) -> list[list]:
        """获取更长历史 K 线（最多 1440 条）"""
        params: dict = {"instId": inst_id, "bar": bar, "limit": str(limit)}
        if after:
            params["after"] = after
        return self.get("/api/v5/market/history-candles", params) or []

    def get_orderbook(self, inst_id: str, sz: int = 20) -> dict:
        """获取订单簿"""
        result = self.get("/api/v5/market/books", {"instId": inst_id, "sz": str(sz)})
        return result[0] if result else {}

    def get_instruments(self, inst_type: str = "SPOT") -> list[dict]:
        """获取交易品种列表"""
        return self.get("/api/v5/public/instruments", {"instType": inst_type}) or []

    def get_instrument(self, inst_id: str, inst_type: str = "SPOT") -> dict:
        """获取单个交易品种信息（含 lotSz / minSz / tickSz 等）"""
        result = self.get("/api/v5/public/instruments", {"instType": inst_type, "instId": inst_id})
        return result[0] if result else {}

    # -------------------------------------------------------------------------
    # 账户接口（需鉴权）
    # -------------------------------------------------------------------------

    def get_balance(self, ccy: str | None = None) -> list[dict]:
        """查询账户余额"""
        params = {"ccy": ccy} if ccy else {}
        return self.get("/api/v5/account/balance", params, auth=True) or []

    def get_account_config(self) -> dict:
        """查询当前 API key 实际绑定的账户配置。"""
        rows = self.get("/api/v5/account/config", auth=True) or []
        if not isinstance(rows, list) or not rows:
            raise RuntimeError("账户配置查询返回空")
        return dict(rows[0])

    def get_positions(self, inst_type: str = "SPOT") -> list[dict]:
        """查询持仓"""
        return self.get("/api/v5/account/positions", {"instType": inst_type}, auth=True) or []

    # -------------------------------------------------------------------------
    # 交易接口（需鉴权）
    # -------------------------------------------------------------------------

    def place_order(
        self,
        inst_id: str,
        side: str,
        ord_type: str,
        sz: str,
        px: str | None = None,
        td_mode: str = "cash",
        tgt_ccy: str | None = None,
        cl_ord_id: str | None = None,
        max_slippage: str | None = None,
        attach_algo_orders: list[dict] | None = None,
    ) -> dict:
        """下单

        Args:
            inst_id: 交易对，如 "BTC-USDT"
            side: "buy" | "sell"
            ord_type: "market" | "limit" | "post_only" | "fok" | "ioc"
            sz: 委托数量（现货按币种数量）
            px: 委托价格（市价单不需要）
            td_mode: "cash"（现货）| "cross"（全仓）| "isolated"（逐仓）
            tgt_ccy: "base_ccy"（sz为币数量）| "quote_ccy"（sz为USDT金额）
                     现货市价买单默认 quote_ccy，需显式传 base_ccy
            cl_ord_id: 客户自定义订单 ID
            max_slippage: 市价单允许的最大滑点比例，由 OKX 执行层强制
            attach_algo_orders: OKX attachAlgoOrds 契约验证/兼容入口
        """
        body: dict = {
            "instId": inst_id,
            "tdMode": td_mode,
            "side": side,
            "ordType": ord_type,
            "sz": sz,
        }
        if px:
            body["px"] = px
        if tgt_ccy:
            body["tgtCcy"] = tgt_ccy
        if cl_ord_id:
            body["clOrdId"] = cl_ord_id
        if max_slippage:
            body["slippagePct"] = max_slippage
        if attach_algo_orders:
            body["attachAlgoOrds"] = attach_algo_orders

        result = self.post("/api/v5/trade/order", body)
        return self._business_result(result, "place order")

    def cancel_order(
        self,
        inst_id: str,
        ord_id: str | None = None,
        *,
        cl_ord_id: str | None = None,
    ) -> dict:
        """按 ordId 或 clOrdId 撤单；写请求仍只尝试一次。"""
        body = self._ordinary_order_identifier(
            inst_id,
            ord_id=ord_id,
            cl_ord_id=cl_ord_id,
        )
        result = self.post("/api/v5/trade/cancel-order", body)
        return self._business_result(result, "cancel order")

    def amend_order(
        self,
        inst_id: str,
        ord_id: str | None = None,
        *,
        cl_ord_id: str | None = None,
        new_size: str | None = None,
        new_price: str | None = None,
        request_id: str | None = None,
        cancel_on_fail: bool = True,
    ) -> dict:
        """按稳定订单标识改单；至少修改价格或数量之一。"""
        if not new_size and not new_price:
            raise ValueError("new_size / new_price 至少需要一个")
        body = self._ordinary_order_identifier(
            inst_id,
            ord_id=ord_id,
            cl_ord_id=cl_ord_id,
        )
        if new_size:
            body["newSz"] = new_size
        if new_price:
            body["newPx"] = new_price
        if request_id:
            body["reqId"] = request_id
        body["cxlOnFail"] = "true" if cancel_on_fail else "false"
        result = self.post("/api/v5/trade/amend-order", body)
        return self._business_result(result, "amend order")

    @staticmethod
    def _ordinary_order_identifier(
        inst_id: str,
        *,
        ord_id: str | None,
        cl_ord_id: str | None,
    ) -> dict:
        if bool(ord_id) == bool(cl_ord_id):
            raise ValueError("ord_id / cl_ord_id 必须且只能提供一个")
        body = {"instId": inst_id}
        if ord_id:
            body["ordId"] = ord_id
        else:
            body["clOrdId"] = str(cl_ord_id)
        return body

    def get_order(
        self,
        inst_id: str,
        ord_id: str | None = None,
        cl_ord_id: str | None = None,
    ) -> dict:
        """查询订单状态"""
        if not ord_id and not cl_ord_id:
            raise ValueError("ord_id / cl_ord_id 至少需要一个")
        params = {"instId": inst_id}
        if ord_id:
            params["ordId"] = ord_id
        elif cl_ord_id:
            params["clOrdId"] = cl_ord_id
        result = self.get(
            "/api/v5/trade/order", params, auth=True
        )
        return result[0] if result else {}

    def get_open_orders(self, inst_id: str | None = None) -> list[dict]:
        """查询未成交订单"""
        params = {}
        if inst_id:
            params["instId"] = inst_id
        return self.get("/api/v5/trade/orders-pending", params, auth=True) or []

    def get_order_history(
        self,
        inst_id: str | None = None,
        inst_type: str = "SPOT",
        limit: int = 100,
    ) -> list[dict]:
        """查询最近 7 天已完成订单。"""
        params: dict = {"instType": inst_type, "limit": str(min(max(limit, 1), 100))}
        if inst_id:
            params["instId"] = inst_id
        return self.get("/api/v5/trade/orders-history", params, auth=True) or []

    def get_fills(self, inst_id: str | None = None, limit: int = 20) -> list[dict]:
        """查询成交历史"""
        params: dict = {"limit": str(limit)}
        if inst_id:
            params["instId"] = inst_id
        return self.get("/api/v5/trade/fills", params, auth=True) or []

    def place_algo_order(
        self,
        *,
        inst_id: str,
        side: str,
        ord_type: str,
        sz: str,
        algo_cl_ord_id: str = "",
        stop_loss: str = "",
        take_profit: str = "",
    ) -> dict:
        body: dict = {
            "instId": inst_id,
            "tdMode": "cash",
            "side": side,
            "ordType": ord_type,
            "sz": sz,
        }
        if algo_cl_ord_id:
            body["algoClOrdId"] = algo_cl_ord_id
        if stop_loss:
            body["slTriggerPx"] = stop_loss
            body["slOrdPx"] = "-1"
            body["slTriggerPxType"] = "last"
        if take_profit:
            body["tpTriggerPx"] = take_profit
            body["tpOrdPx"] = "-1"
            body["tpTriggerPxType"] = "last"
        result = self.post("/api/v5/trade/order-algo", body)
        return self._business_result(result, "place algo")

    def get_algo_order(
        self,
        *,
        algo_id: str = "",
        algo_cl_ord_id: str = "",
    ) -> dict:
        if not algo_id and not algo_cl_ord_id:
            raise ValueError("algo_id / algo_cl_ord_id 至少需要一个")
        params = (
            {"algoId": algo_id}
            if algo_id
            else {"algoClOrdId": algo_cl_ord_id}
        )
        # 保护建立确认位于 fill→ACTIVE 的硬 SLO 路径：单次快速查询，
        # 失败由 ProtectionManager 的有界 resolver 接管，不能在 REST 内
        # 隐式重试几十秒。
        result = self._request(
            "GET",
            "/api/v5/trade/order-algo",
            params=params,
            auth=True,
            max_attempts=1,
            timeout_override=2,
        )
        return result[0] if result else {}

    def get_pending_algo_orders(
        self,
        *,
        inst_id: str = "",
        ord_type: str = "oco",
    ) -> list[dict]:
        params = {"ordType": ord_type}
        if inst_id:
            params["instId"] = inst_id
        return self.get("/api/v5/trade/orders-algo-pending", params, auth=True) or []

    def get_algo_order_history(
        self,
        *,
        inst_id: str = "",
        ord_type: str = "oco",
        state: str = "effective",
    ) -> list[dict]:
        params = {"ordType": ord_type, "state": state}
        if inst_id:
            params["instId"] = inst_id
        return self.get("/api/v5/trade/orders-algo-history", params, auth=True) or []

    def cancel_algo_order(self, inst_id: str, algo_id: str) -> dict:
        result = self.post(
            "/api/v5/trade/cancel-algos",
            [{"instId": inst_id, "algoId": algo_id}],
        )
        return self._business_result(result, "cancel algo")

    def amend_algo_order(
        self,
        *,
        inst_id: str,
        algo_id: str,
        size: str,
        stop_loss: str,
        take_profit: str = "",
        req_id: str = "",
    ) -> dict:
        body: dict = {
            "instId": inst_id,
            "algoId": algo_id,
            "newSz": size,
            "newSlTriggerPx": stop_loss,
            "newSlOrdPx": "-1",
        }
        if take_profit:
            body["newTpTriggerPx"] = take_profit
            body["newTpOrdPx"] = "-1"
        if req_id:
            body["reqId"] = req_id
        result = self.post("/api/v5/trade/amend-algos", body)
        return self._business_result(result, "amend algo")

    @staticmethod
    def _business_result(result: Any, operation: str) -> dict:
        item = result[0] if isinstance(result, list) and result else {}
        if not item:
            raise RuntimeError(f"OKX {operation} 响应为空")
        code = str(item.get("sCode", "0"))
        if code not in {"", "0"}:
            raise RuntimeError(
                f"OKX {operation} rejected [{code}]: "
                f"{item.get('sMsg', 'unknown error')}"
            )
        return item

    def cancel_all_orders(self, inst_id: str) -> list[dict]:
        """撤销某交易对的所有未成交订单"""
        open_orders = self.get_open_orders(inst_id)
        results = []
        for order in open_orders:
            try:
                results.append(self.cancel_order(inst_id, order["ordId"]))
            except RuntimeError as e:
                logger.warning("撤单失败: %s", e)
        return results
