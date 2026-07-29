"""OKX demo contract 编排测试（不访问网络）。"""

import json
import sys
from decimal import Decimal

from okx_quant.client.rest import OKXAPIError
from okx_quant.infrastructure.okx.contract_fixture import (
    build_redacted_contract_fixture,
    validate_contract_fixture,
)
from scripts import demo_contract
from scripts.demo_contract import run_contract


class DemoClient:
    def __init__(self):
        self.orders = {}
        self.algos = {}
        self.next_order = 0
        self.placed_orders = []
        self.base_balance = Decimal("0")
        self.attached_error_code = ""
        self.reject_off_tick_prices = False

    def get_instrument(self, _inst_id):
        return {
            "baseCcy": "BTC",
            "lotSz": "0.001",
            "minSz": "0.001",
            "tickSz": "0.1",
        }

    def get_ticker(self, _inst_id):
        return {"last": "50000"}

    def place_order(
        self,
        _inst_id,
        side,
        _ord_type,
        sz,
        **kwargs,
    ):
        self.placed_orders.append({
            "side": side,
            "sz": sz,
            "tgt_ccy": kwargs.get("tgt_ccy"),
        })
        cl_ord_id = kwargs["cl_ord_id"]
        attached = kwargs.get("attach_algo_orders")
        if side == "buy" and attached and self.attached_error_code:
            raise RuntimeError(
                f"OKX API Error [{self.attached_error_code}]: "
                "attached route unsupported"
            )
        self.next_order += 1
        filled_size = "0.001" if attached else sz
        order = {
            "ordId": f"o{self.next_order}",
            "clOrdId": cl_ord_id,
            "state": "filled",
            "accFillSz": filled_size,
            "avgPx": "50123.4",
            "fee": "0",
            "feeCcy": "USDT",
        }
        self.orders[cl_ord_id] = order
        if attached:
            spec = attached[0]
            if self.reject_off_tick_prices:
                tick = Decimal("0.1")
                assert Decimal(spec["slTriggerPx"]) % tick == 0
                assert Decimal(spec["tpTriggerPx"]) % tick == 0
            algo_id = f"a{len(self.algos) + 1}"
            self.algos[algo_id] = {
                "algoId": algo_id,
                "algoClOrdId": spec["attachAlgoClOrdId"],
                "instId": _inst_id,
                "side": "sell",
                "ordType": "oco",
                "state": "live",
                "sz": filled_size,
                "slTriggerPx": spec["slTriggerPx"],
                "tpTriggerPx": spec["tpTriggerPx"],
            }
        if side == "buy":
            self.base_balance += Decimal(filled_size)
        else:
            self.base_balance -= Decimal(sz)
        return order

    def get_order(self, _inst_id, *, cl_ord_id):
        return self.orders.get(cl_ord_id, {})

    def place_algo_order(self, **kwargs):
        row = {
            "algoId": "a1",
            "algoClOrdId": kwargs["algo_cl_ord_id"],
            "instId": kwargs["inst_id"],
            "side": kwargs["side"],
            "ordType": kwargs["ord_type"],
            "state": "live",
            "sz": kwargs["sz"],
            "slTriggerPx": kwargs["stop_loss"],
            "tpTriggerPx": kwargs["take_profit"],
        }
        self.algos[row["algoId"]] = row
        return row

    def get_algo_order(self, *, algo_cl_ord_id):
        return next(
            (
                row
                for row in self.algos.values()
                if row["algoClOrdId"] == algo_cl_ord_id
            ),
            {},
        )

    def get_pending_algo_orders(self, *, inst_id, ord_type):
        del inst_id, ord_type
        return list(self.algos.values())

    def cancel_algo_order(self, _inst_id, algo_id):
        return self.algos.pop(algo_id)

    def get_balance(self, _ccy=None):
        return [{
            "details": [{
                "ccy": "BTC",
                "cashBal": str(self.base_balance),
            }],
        }]

    def get_open_orders(self, _inst_id):
        return []


def test_demo_contract_gates_on_independent_oco_and_conclusive_probe():
    evidence, ok = run_contract(
        DemoClient(),
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )

    assert ok
    assert evidence["selected_route"] == "independent_oco_after_fill"
    assert evidence["independent_oco"]["ok"]
    assert evidence["attached_probe"]["supported"]
    assert evidence["attached_probe"]["conclusive"]
    assert evidence["cleanup_errors"] == []
    fixture = build_redacted_contract_fixture(evidence)
    validate_contract_fixture(fixture)
    assert fixture["capture_origin"] == "okx_demo_live"
    assert fixture["redaction"]["redacted_identifier_count"] > 0
    assert "<ORDER_ID_" in json.dumps(fixture)


class TinyInstrumentClient(DemoClient):
    def get_instrument(self, _inst_id):
        return {
            "baseCcy": "BTC",
            "quoteCcy": "USDT",
            "lotSz": "0.00000001",
            "minSz": "0.00001",
            "tickSz": "0.1",
        }


def test_demo_contract_sizes_above_quote_notional_floor():
    client = TinyInstrumentClient()
    evidence, ok = run_contract(
        client,
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )

    assert ok, evidence
    assert Decimal(evidence["estimated_quote_notional"]) >= Decimal("5")
    first_buy = client.placed_orders[0]
    assert first_buy["tgt_ccy"] == "base_ccy"
    assert Decimal(first_buy["sz"]) == Decimal("0.0001")


class DefinitiveRejectionClient(DemoClient):
    def __init__(self):
        super().__init__()
        self.get_order_calls = 0

    def place_order(self, *_args, **_kwargs):
        raise OKXAPIError(
            "51020",
            "OKX place order rejected [51020]: minimum amount",
        )

    def get_order(self, _inst_id, *, cl_ord_id):
        del cl_ord_id
        self.get_order_calls += 1
        return {}


def test_demo_contract_does_not_poll_definitively_rejected_order():
    client = DefinitiveRejectionClient()
    evidence, ok = run_contract(
        client,
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )

    assert not ok
    assert client.get_order_calls == 0
    assert "51020" in evidence["error"]


def test_demo_contract_main_creates_output_directories(
    monkeypatch,
    tmp_path,
):
    output = tmp_path / "nested" / "demo-contract.json"
    fixture = tmp_path / "fixtures" / "demo-contract.v1.json"
    evidence = {
        "ok": True,
        "started_at": 1,
        "completed_at": 2,
    }
    monkeypatch.setattr(
        demo_contract,
        "load_yaml",
        lambda _path: {"okx": {"simulated": True}},
    )
    monkeypatch.setattr(
        demo_contract,
        "make_client",
        lambda _config: type(
            "IdentityClient",
            (),
            {"get_account_config": lambda self: {"uid": "demo-account"}},
        )(),
    )
    monkeypatch.setattr(
        demo_contract,
        "build_release_identity",
        lambda _root: {
            "git_commit": "1" * 40,
            "git_tree_hash": "2" * 40,
            "workspace_clean": True,
            "source_manifest_sha256": "3" * 64,
        },
    )
    monkeypatch.setattr(
        demo_contract,
        "build_deployment_identity",
        lambda **_kwargs: {
            "account_uid": "demo-account",
            "api_domain": "https://www.okx.com",
            "simulated": True,
            "config_sha256": "4" * 64,
            "key_fingerprint": "5" * 64,
        },
    )
    monkeypatch.setattr(
        demo_contract,
        "run_contract",
        lambda _client, _inst: (evidence, True),
    )
    monkeypatch.setattr(
        demo_contract,
        "build_redacted_contract_fixture",
        lambda _evidence: {"fixture": True},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "demo_contract.py",
            "--confirm",
            demo_contract.CONFIRMATION,
            "--output",
            str(output),
            "--fixture-output",
            str(fixture),
        ],
    )

    assert demo_contract.main() == 0
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["version"] == 2
    assert written["contract"] == evidence
    assert written["release_identity"]["workspace_clean"] is True
    assert json.loads(fixture.read_text(encoding="utf-8")) == {
        "fixture": True,
    }
    manifest = json.loads(
        output.with_suffix(
            output.suffix + ".manifest-request.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["action"] == "attest-demo-contract-v2"
    assert manifest["components"]["evidence"]["bytes"] > 0


class AckOnlyAlgoClient(DemoClient):
    def place_algo_order(self, **_kwargs):
        return {"algoId": "ack-only"}

    def cancel_algo_order(self, _inst_id, _algo_id):
        return {}


def test_demo_contract_rejects_algo_ack_without_active_exchange_fact():
    evidence, ok = run_contract(
        AckOnlyAlgoClient(),
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )
    assert not ok
    assert not evidence["route_b_ok"]


class StickyAlgoClient(DemoClient):
    def cancel_algo_order(self, _inst_id, algo_id):
        return self.algos[algo_id]


def test_demo_contract_rejects_cleanup_when_algo_remains_live():
    evidence, ok = run_contract(
        StickyAlgoClient(),
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )
    assert not ok
    assert any("仍为 ACTIVE" in error for error in evidence["cleanup_errors"])


def test_demo_contract_does_not_treat_transient_error_as_unsupported():
    client = DemoClient()
    client.attached_error_code = "50000"
    evidence, ok = run_contract(
        client,
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )
    assert not ok
    assert not evidence["attached_probe"]["explicitly_rejected"]
    assert not evidence["attached_probe"]["conclusive"]


def test_demo_contract_does_not_treat_generic_parameter_error_as_unsupported():
    client = DemoClient()
    client.attached_error_code = "51000"
    evidence, ok = run_contract(
        client,
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )
    assert not ok
    assert not evidence["attached_probe"]["explicitly_rejected"]
    assert not evidence["attached_probe"]["conclusive"]


def test_demo_contract_quantizes_all_trigger_prices_to_tick():
    client = DemoClient()
    client.reject_off_tick_prices = True
    evidence, ok = run_contract(
        client,
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )
    assert ok, evidence
    for key in ("slTriggerPx", "tpTriggerPx"):
        assert Decimal(evidence["independent_oco"][key]) % Decimal("0.1") == 0


class OversellCleanupClient(DemoClient):
    def __init__(self):
        super().__init__()
        self.base_balance = Decimal("0.010")

    def place_order(self, inst_id, side, ord_type, sz, **kwargs):
        result = super().place_order(
            inst_id,
            side,
            ord_type,
            sz,
            **kwargs,
        )
        if side == "sell":
            self.base_balance -= Decimal("0.001")
        return result


def test_demo_contract_rejects_cleanup_that_erodes_baseline_holding():
    evidence, ok = run_contract(
        OversellCleanupClient(),
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )
    assert not ok
    assert Decimal(evidence["final_base_balance"]) < Decimal(
        evidence["baseline_base_balance"]
    )
    assert any(
        "侵蚀" in error for error in evidence["cleanup_errors"]
    )


class BaseFeeDustClient(TinyInstrumentClient):
    def get_ticker(self, _inst_id):
        return {"last": "63438"}

    def place_order(self, inst_id, side, ord_type, sz, **kwargs):
        result = super().place_order(
            inst_id,
            side,
            ord_type,
            sz,
            **kwargs,
        )
        if side == "buy" and not kwargs.get("attach_algo_orders"):
            fee = -Decimal(result["accFillSz"]) * Decimal("0.001")
            result["fee"] = str(fee)
            result["feeCcy"] = "BTC"
            self.base_balance += fee
        return result


def test_demo_contract_accepts_only_proven_sub_lot_fee_dust():
    evidence, ok = run_contract(
        BaseFeeDustClient(),
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )

    assert ok, evidence
    delta = Decimal(evidence["final_base_balance_delta"])
    expected_dust = Decimal(evidence["expected_base_dust"])
    tolerance = Decimal(evidence["balance_measurement_tolerance"])
    assert Decimal("0") < delta <= expected_dust + tolerance
    assert expected_dust < Decimal("0.00000001")


class UndersellCleanupClient(DemoClient):
    def place_order(self, inst_id, side, ord_type, sz, **kwargs):
        result = super().place_order(
            inst_id,
            side,
            ord_type,
            sz,
            **kwargs,
        )
        if side == "sell":
            self.base_balance += Decimal("0.001")
        return result


def test_demo_contract_rejects_unexplained_positive_residual():
    evidence, ok = run_contract(
        UndersellCleanupClient(),
        "BTC-USDT",
        poll_timeout_s=0.01,
        poll_interval_s=0,
    )

    assert not ok
    assert any(
        "残留持仓" in error for error in evidence["cleanup_errors"]
    )
