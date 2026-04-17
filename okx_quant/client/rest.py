"""OKX REST API 客户端，支持鉴权和模拟盘"""

import hashlib
import hmac
import base64
import time
import logging
from datetime import datetime, timezone
from typing import Any, Optional
import requests

logger = logging.getLogger(__name__)


class OKXRestClient:
    """OKX V5 REST API 客户端

    公共接口无需鉴权，私有接口（账户/下单）需要 API Key。
    设置 simulated=True 可切换到模拟盘（Sandbox）。
    """

    BASE_URL = "https://www.okx.com"

    # OKX V5 错误码：触发速率限制（需退避重试）
    # 参考: https://www.okx.com/docs-v5/zh/#error-code
    _RATE_LIMIT_CODES: frozenset[str] = frozenset({
        "50011",  # User/IP 限速
        "50013",  # 系统繁忙
        "50061",  # 批量下单过快
    })

    def __init__(
        self,
        api_key: str = "",
        secret_key: str = "",
        passphrase: str = "",
        simulated: bool = False,
        timeout: int = 15,
        max_retries: int = 3,
        proxy: str = "",
    ):
        self.api_key = api_key
        self.secret_key = secret_key
        self.passphrase = passphrase
        self.simulated = simulated
        self.timeout = timeout
        self.max_retries = max_retries
        self._proxy = proxy
        self._session = self._make_session()

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"Content-Type": "application/json"})
        if self._proxy:
            s.proxies = {"http": self._proxy, "https": self._proxy}
        return s

    # -------------------------------------------------------------------------
    # 内部签名方法
    # -------------------------------------------------------------------------

    def _timestamp(self) -> str:
        """生成 ISO8601 UTC 时间戳"""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

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
        return {
            "OK-ACCESS-KEY": self.api_key,
            "OK-ACCESS-SIGN": self._sign(ts, method, path, body),
            "OK-ACCESS-TIMESTAMP": ts,
            "OK-ACCESS-PASSPHRASE": self.passphrase,
            **({"x-simulated-trading": "1"} if self.simulated else {}),
        }

    # -------------------------------------------------------------------------
    # 底层请求
    # -------------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        body: Optional[dict] = None,
        auth: bool = False,
    ) -> Any:
        import json

        url = self.BASE_URL + path
        body_str = json.dumps(body) if body else ""
        headers = {}

        if auth:
            if not self.api_key:
                raise ValueError("私有接口需要 API Key，请在配置中填写鉴权信息")
            # OKX 签名要求 GET path 包含 query string
            sign_path = path
            if params:
                from urllib.parse import urlencode
                sign_path = f"{path}?{urlencode(params)}"
            headers = self._auth_headers(method, sign_path, body_str)

        if self.simulated:
            headers["x-simulated-trading"] = "1"

        data: Any = None
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=body_str if body_str else None,
                    timeout=self.timeout,
                )
                # HTTP 429 显式退避
                if resp.status_code == 429:
                    wait = self._backoff_delay(attempt, resp.headers.get("Retry-After"))
                    logger.warning(
                        "HTTP 429 限速 (%d/%d)，%.1fs 后重试: %s %s",
                        attempt, self.max_retries, wait, method, url,
                    )
                    if attempt < self.max_retries:
                        time.sleep(wait)
                        if auth:
                            headers.update(self._refresh_auth(method, path, params, body_str))
                        continue
                resp.raise_for_status()
                data = resp.json()
            except (requests.ConnectionError, requests.Timeout) as e:
                last_exc = e
                # SSL/连接错误后清理连接池，避免复用损坏的连接
                self._session.close()
                self._session = self._make_session()
                if attempt < self.max_retries:
                    wait = self._backoff_delay(attempt)
                    logger.warning(
                        "HTTP 请求超时/连接失败 (%d/%d)，%.1fs 后重试: %s %s",
                        attempt, self.max_retries, wait, method, url,
                    )
                    time.sleep(wait)
                    if auth:
                        headers.update(self._refresh_auth(method, path, params, body_str))
                    continue
                logger.error("HTTP 请求失败 (已重试 %d 次): %s %s -> %s", self.max_retries, method, url, e)
                raise
            except requests.RequestException as e:
                logger.error("HTTP 请求失败: %s %s -> %s", method, url, e)
                raise

            # 解析 OKX 业务错误码
            code = data.get("code")
            if code == "0":
                return data.get("data")

            # 命中速率限制码 → 退避后重试
            if code in self._RATE_LIMIT_CODES and attempt < self.max_retries:
                wait = self._backoff_delay(attempt)
                logger.warning(
                    "OKX 限速 [%s] (%d/%d)，%.1fs 后重试: %s %s",
                    code, attempt, self.max_retries, wait, method, url,
                )
                time.sleep(wait)
                if auth:
                    headers.update(self._refresh_auth(method, path, params, body_str))
                continue

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
        raise RuntimeError(f"OKX API 请求失败（已重试 {self.max_retries} 次）: {method} {url}")

    @staticmethod
    def _backoff_delay(attempt: int, retry_after: Optional[str] = None) -> float:
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
        params: Optional[dict],
        body_str: str,
    ) -> dict:
        """重试前刷新签名（时间戳必须更新）"""
        sign_path = path
        if params:
            from urllib.parse import urlencode
            sign_path = f"{path}?{urlencode(params)}"
        return self._auth_headers(method, sign_path, body_str)

    def get(self, path: str, params: dict | None = None, auth: bool = False) -> Any:
        return self._request("GET", path, params=params, auth=auth)

    def post(self, path: str, body: dict | None = None, auth: bool = True) -> Any:
        return self._request("POST", path, body=body, auth=auth)

    # -------------------------------------------------------------------------
    # 公共行情接口
    # -------------------------------------------------------------------------

    def get_ticker(self, inst_id: str) -> dict:
        """获取单个品种实时 Ticker"""
        result = self.get("/api/v5/market/ticker", {"instId": inst_id})
        return result[0] if result else {}

    def get_tickers(self, inst_type: str = "SPOT") -> list[dict]:
        """获取所有现货 Ticker"""
        return self.get("/api/v5/market/tickers", {"instType": inst_type}) or []

    def get_candles(
        self,
        inst_id: str,
        bar: str = "1H",
        limit: int = 100,
        after: Optional[str] = None,
        before: Optional[str] = None,
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
        after: Optional[str] = None,
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

    def get_balance(self, ccy: Optional[str] = None) -> list[dict]:
        """查询账户余额"""
        params = {"ccy": ccy} if ccy else {}
        return self.get("/api/v5/account/balance", params, auth=True) or []

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
        px: Optional[str] = None,
        td_mode: str = "cash",
        tgt_ccy: Optional[str] = None,
        cl_ord_id: Optional[str] = None,
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

        result = self.post("/api/v5/trade/order", body)
        return result[0] if result else {}

    def cancel_order(self, inst_id: str, ord_id: str) -> dict:
        """撤单"""
        result = self.post("/api/v5/trade/cancel-order", {"instId": inst_id, "ordId": ord_id})
        return result[0] if result else {}

    def get_order(self, inst_id: str, ord_id: str) -> dict:
        """查询订单状态"""
        result = self.get(
            "/api/v5/trade/order", {"instId": inst_id, "ordId": ord_id}, auth=True
        )
        return result[0] if result else {}

    def get_open_orders(self, inst_id: Optional[str] = None) -> list[dict]:
        """查询未成交订单"""
        params = {}
        if inst_id:
            params["instId"] = inst_id
        return self.get("/api/v5/trade/orders-pending", params, auth=True) or []

    def get_fills(self, inst_id: Optional[str] = None, limit: int = 20) -> list[dict]:
        """查询成交历史"""
        params: dict = {"limit": str(limit)}
        if inst_id:
            params["instId"] = inst_id
        return self.get("/api/v5/trade/fills", params, auth=True) or []

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
