import subprocess
from decimal import Decimal

import pytest

from okx_quant.application.runtime import ProductionRuntime
from okx_quant.domain.orders import SystemMode
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.ops.account_lease import (
    AccountLeaseConflict,
    AccountLeaseStore,
    SignedAccountLeaseClient,
)


def _keys(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", private],
        check=True,
        capture_output=True,
    )
    private.chmod(0o600)
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            private,
            "-pubout",
            "-out",
            public,
        ],
        check=True,
        capture_output=True,
    )
    return private, public


def test_account_lease_store_fences_cross_host_second_writer(tmp_path):
    store = AccountLeaseStore(tmp_path / "leases.db")
    first = store.acquire(
        account_uid="account-a",
        holder_id="a" * 32,
        ttl_s=30,
        broker_id="broker-v1",
        now=100,
    )
    with pytest.raises(AccountLeaseConflict):
        store.acquire(
            account_uid="account-a",
            holder_id="b" * 32,
            ttl_s=30,
            broker_id="broker-v1",
            now=101,
        )

    second = store.acquire(
        account_uid="account-a",
        holder_id="b" * 32,
        ttl_s=30,
        broker_id="broker-v1",
        now=131,
    )

    assert second["fencing_token"] == first["fencing_token"] + 1
    with pytest.raises(AccountLeaseConflict):
        store.renew(
            account_uid="account-a",
            holder_id=first["holder_id"],
            lease_id=first["lease_id"],
            fencing_token=first["fencing_token"],
            ttl_s=30,
            broker_id="broker-v1",
            now=132,
        )
    with pytest.raises(ValueError, match="renew"):
        store.renew(
            account_uid="account-a",
            holder_id=second["holder_id"],
            lease_id=second["lease_id"],
            fencing_token=True,
            ttl_s=30,
            broker_id="broker-v1",
            now=132,
        )
    with pytest.raises(ValueError, match="release"):
        store.release(
            account_uid="account-a",
            holder_id=second["holder_id"],
            lease_id="not-a-lease-id",
            fencing_token=second["fencing_token"],
            broker_id="broker-v1",
            now=132,
        )


def test_signed_account_lease_client_rejects_unsigned_state(
    tmp_path,
    monkeypatch,
):
    private, public = _keys(tmp_path)
    holder_id = "a" * 32
    lease_id = "b" * 32

    class Response:
        status_code = 200

        def __init__(self, artifact):
            self.artifact = artifact

        def raise_for_status(self):
            return None

        def json(self):
            return self.artifact

    def fake_post(url, *, json, **_kwargs):
        released = url.endswith("/release")
        claims = {
            "version": 1,
            "action": "grant-account-writer-lease",
            "broker_id": "broker-v1",
            "account_uid": "account-a",
            "holder_id": holder_id,
            "lease_id": lease_id,
            "fencing_token": 7,
            "issued_at": 100,
            "expires_at": 105 if released else 130,
        }
        assert json["account_uid"] == "account-a"
        return Response(sign_ed25519_payload(claims, private))

    monkeypatch.setenv("LEASE_TOKEN", "secret-token")
    monkeypatch.setattr(
        "okx_quant.ops.account_lease.requests.post",
        fake_post,
    )
    client = SignedAccountLeaseClient(
        base_url="https://lease.example",
        public_key=public,
        token_env="LEASE_TOKEN",
        account_uid="account-a",
        broker_id="broker-v1",
        ttl_s=30,
        clock=lambda: 100,
    )

    claims = client.start(holder_id=holder_id)
    assert claims["fencing_token"] == 7
    assert client.valid()
    assert client.fencing_identity() == (lease_id, 7)
    client.stop()
    assert not client.valid()


def test_runtime_halts_when_external_account_lease_is_lost(tmp_path):
    class LostLease:
        last_error = "renew timeout"

        @staticmethod
        def valid():
            return False

        @staticmethod
        def fencing_identity():
            return ("c" * 32, 9)

    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.READY)
    runtime = ProductionRuntime(
        FakeExchange(),
        journal,
        expected_account_id="account-a",
        account_lease=LostLease(),
    )

    runtime._enforce_account_writer_lease()

    assert journal.get_mode() is SystemMode.HALTED
    assert journal.latest_event("account_writer_lease_lost") is not None
    assert any(
        row["event_name"] == "page.account_writer_lease_lost"
        for row in journal.get_unpublished_outbox()
    )
    journal.close()


def test_runtime_account_lease_guards_every_exchange_write(tmp_path):
    class ToggleLease:
        last_error = ""

        def __init__(self):
            self.is_valid = True

        def valid(self):
            return self.is_valid

        @staticmethod
        def fencing_identity():
            return ("c" * 32, 9)

    lease = ToggleLease()
    exchange = FakeExchange()
    journal = SQLiteJournal(tmp_path / "trading.db")
    ProductionRuntime(
        exchange,
        journal,
        expected_account_id="account-a",
        account_lease=lease,
    )
    ordinary = exchange.place_market_order(
        "BTC-USDT",
        "sell",
        Decimal("0.01"),
        cl_ord_id="LEASEWRITE01",
    )
    protection = exchange.place_protection_order(
        "BTC-USDT",
        size=Decimal("0.01"),
        stop_loss=Decimal("49000"),
        algo_cl_ord_id="LEASEALGO01",
    )
    lease.is_valid = False

    write_attempts = (
        lambda: exchange.place_market_order(
            "BTC-USDT",
            "sell",
            Decimal("0.01"),
        ),
        lambda: exchange.cancel_order("BTC-USDT", ordinary.ord_id),
        lambda: exchange.amend_order(
            "BTC-USDT",
            ordinary.ord_id,
            new_size=Decimal("0.02"),
        ),
        lambda: exchange.place_protection_order(
            "BTC-USDT",
            size=Decimal("0.01"),
            stop_loss=Decimal("49000"),
        ),
        lambda: exchange.cancel_algo_order(
            "BTC-USDT",
            protection.algo_id,
        ),
        lambda: exchange.amend_algo_order(
            "BTC-USDT",
            protection.algo_id,
            size=Decimal("0.01"),
            stop_loss=Decimal("48000"),
        ),
    )
    for attempt in write_attempts:
        with pytest.raises(RuntimeError, match="coordination lease"):
            attempt()

    assert len(exchange.orders) == 1
    assert exchange.get_order_status(
        "BTC-USDT",
        ord_id=ordinary.ord_id,
    ).state.value == "filled"
    assert exchange.get_algo_order(
        algo_id=protection.algo_id,
    ).state.value == "active"
    journal.close()
