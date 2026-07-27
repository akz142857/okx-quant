"""REST GET 可重试、交易 POST 响应丢失绝不盲重试。"""

import pytest
import requests

from okx_quant.client.rest import OKXRestClient


class _Session:
    def __init__(self):
        self.calls = 0

    def request(self, *args, **kwargs):
        self.calls += 1
        raise requests.Timeout("lost")

    def close(self):
        return None


class _Response:
    def __init__(self, code: str, status_code: int = 200):
        self.code = code
        self.status_code = status_code
        self.headers = {}

    def raise_for_status(self):
        if self.status_code >= 400:
            response = requests.Response()
            response.status_code = self.status_code
            raise requests.HTTPError(
                f"HTTP {self.status_code}",
                response=response,
            )
        return None

    def json(self):
        return {"code": self.code, "msg": "fixture", "data": []}


class _BusinessCodeSession:
    def __init__(self, codes):
        self.codes = iter(codes)

    def request(self, *_args, **_kwargs):
        return _Response(next(self.codes))

    def close(self):
        return None


class _ResponseSession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = 0

    def request(self, *_args, **_kwargs):
        self.calls += 1
        return next(self.responses)

    def close(self):
        return None


@pytest.mark.unit
def test_ambiguous_post_is_attempted_only_once(monkeypatch):
    client = OKXRestClient(
        api_key="k",
        secret_key="s",
        passphrase="p",
        max_retries=5,
    )
    sessions: list[_Session] = []

    def make_session():
        session = _Session()
        sessions.append(session)
        return session

    monkeypatch.setattr(client, "_make_session", make_session)
    with pytest.raises(requests.Timeout):
        client.post("/api/v5/trade/order", {"instId": "BTC-USDT"})
    assert sum(session.calls for session in sessions) == 1


@pytest.mark.unit
@pytest.mark.parametrize(
    "response",
    [
        _Response("50011"),
        _Response("0", status_code=429),
    ],
)
def test_rate_limited_post_is_never_replayed(monkeypatch, response):
    client = OKXRestClient(
        api_key="k",
        secret_key="s",
        passphrase="p",
        max_retries=5,
    )
    session = _ResponseSession([response])
    monkeypatch.setattr(client, "_make_session", lambda: session)
    with pytest.raises(requests.RequestException):
        client.post("/api/v5/trade/order", {"instId": "BTC-USDT"})
    assert session.calls == 1


@pytest.mark.unit
def test_rate_limited_get_remains_retryable(monkeypatch):
    client = OKXRestClient(max_retries=2)
    session = _ResponseSession([
        _Response("50011"),
        _Response("0"),
    ])
    monkeypatch.setattr(client, "_make_session", lambda: session)
    monkeypatch.setattr("okx_quant.client.rest.time.sleep", lambda _delay: None)
    assert client.get("/api/v5/public/time") == []
    assert session.calls == 2


@pytest.mark.unit
def test_rate_limit_backoff_is_shared_across_client_instances(monkeypatch):
    sleeps = []
    clock = iter([100.0, 100.0])
    monkeypatch.setattr("okx_quant.client.rest.time.monotonic", lambda: next(clock))
    monkeypatch.setattr(
        "okx_quant.client.rest.time.sleep",
        lambda delay: sleeps.append(delay),
    )
    OKXRestClient._GLOBAL_NOT_BEFORE = 0.0
    first = OKXRestClient()
    second = OKXRestClient()
    first._defer_global_requests(2.0)
    second._wait_for_global_rate_limit()
    assert sleeps == [2.0]
    assert OKXRestClient._GLOBAL_NOT_BEFORE == 0.0


@pytest.mark.unit
def test_write_timeout_is_capped_below_protection_slo(monkeypatch):
    captured = {}

    class Session:
        def request(self, *_args, **kwargs):
            captured["timeout"] = kwargs["timeout"]
            return _Response("0")

        def close(self):
            return None

    client = OKXRestClient(
        api_key="k",
        secret_key="s",
        passphrase="p",
        timeout=15,
    )
    monkeypatch.setattr(client, "_make_session", Session)
    assert client.post("/api/v5/trade/order", {"instId": "BTC-USDT"}) == []
    assert captured["timeout"] == 3


@pytest.mark.unit
def test_observer_sees_okx_business_code_instead_of_http_200(monkeypatch):
    observed = []
    client = OKXRestClient(
        max_retries=1,
        request_observer=lambda endpoint, code, _latency: observed.append(
            (endpoint, code)
        ),
    )
    monkeypatch.setattr(
        client,
        "_make_session",
        lambda: _BusinessCodeSession(["50011"]),
    )
    with pytest.raises(RuntimeError, match="50011"):
        client.get("/api/v5/account/balance")
    assert observed == [
        ("/api/v5/account/balance", "OKX:50011")
    ]


@pytest.mark.unit
def test_observer_records_okx_zero_as_success(monkeypatch):
    observed = []
    client = OKXRestClient(
        max_retries=1,
        request_observer=lambda endpoint, code, _latency: observed.append(
            (endpoint, code)
        ),
    )
    monkeypatch.setattr(
        client,
        "_make_session",
        lambda: _BusinessCodeSession(["0"]),
    )
    assert client.get("/api/v5/public/time") == []
    assert observed == [("/api/v5/public/time", "OKX:0")]


@pytest.mark.unit
def test_market_order_contract_includes_slippage_and_attached_algo(monkeypatch):
    client = OKXRestClient()
    captured = {}

    def post(path, body=None, auth=True):
        captured.update({"path": path, "body": body, "auth": auth})
        return [{"sCode": "0", "ordId": "demo-1"}]

    monkeypatch.setattr(client, "post", post)
    result = client.place_order(
        "BTC-USDT",
        "buy",
        "market",
        "0.001",
        tgt_ccy="base_ccy",
        cl_ord_id="contract1",
        max_slippage="0.01",
        attach_algo_orders=[{
            "attachAlgoClOrdId": "contract-sl",
            "slTriggerPx": "49000",
            "slOrdPx": "-1",
        }],
    )
    assert result["ordId"] == "demo-1"
    assert captured["body"]["slippagePct"] == "0.01"
    assert captured["body"]["attachAlgoOrds"][0]["slOrdPx"] == "-1"


@pytest.mark.unit
def test_cancel_and_amend_accept_exactly_one_stable_identifier(monkeypatch):
    client = OKXRestClient()
    calls = []

    def post(path, body=None, auth=True):
        calls.append((path, body, auth))
        return [{"sCode": "0", "ordId": "demo-1"}]

    monkeypatch.setattr(client, "post", post)
    client.cancel_order("BTC-USDT", cl_ord_id="QSTABLE01")
    client.amend_order(
        "BTC-USDT",
        "demo-1",
        new_size="0.002",
        new_price="50000.1",
        request_id="amend-1",
    )
    assert calls[0][1] == {
        "instId": "BTC-USDT",
        "clOrdId": "QSTABLE01",
    }
    assert calls[1][1] == {
        "instId": "BTC-USDT",
        "ordId": "demo-1",
        "newSz": "0.002",
        "newPx": "50000.1",
        "reqId": "amend-1",
        "cxlOnFail": "true",
    }
    with pytest.raises(ValueError, match="必须且只能"):
        client.cancel_order("BTC-USDT")
    with pytest.raises(ValueError, match="必须且只能"):
        client.cancel_order(
            "BTC-USDT",
            "demo-1",
            cl_ord_id="QSTABLE01",
        )
    with pytest.raises(ValueError, match="至少需要一个"):
        client.amend_order("BTC-USDT", "demo-1")
