"""REST 客户端配置契约测试。"""

import pytest

from main import make_client
from okx_quant.client.rest import OKXRestClient


@pytest.mark.unit
def test_rest_client_normalizes_custom_base_url():
    client = OKXRestClient(base_url="https://example.test/")
    assert client.base_url == "https://example.test"


@pytest.mark.unit
def test_make_client_applies_transport_config():
    client = make_client({
        "okx": {
            "base_url": "https://example.test/",
            "timeout": 7,
            "max_retries": 5,
            "simulated": True,
        }
    })
    assert client.base_url == "https://example.test"
    assert client.timeout == 7
    assert client.max_retries == 5
