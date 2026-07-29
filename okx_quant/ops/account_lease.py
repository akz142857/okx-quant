"""Signed, account-UID scoped writer leases for cross-host fencing."""

from __future__ import annotations

import contextlib
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import requests

from okx_quant.application.approval import verify_ed25519_artifact

_LEASE_KEYS = {
    "version",
    "action",
    "broker_id",
    "account_uid",
    "holder_id",
    "lease_id",
    "fencing_token",
    "issued_at",
    "expires_at",
}
_HOLDER = re.compile(r"[0-9a-f]{32}")


class AccountLeaseConflict(RuntimeError):
    """Another non-expired holder owns the account writer lease."""


def validate_lease_claims(
    value: object,
    *,
    expected_account_uid: str,
    expected_holder_id: str,
    expected_broker_id: str,
    now: float,
    maximum_ttl_s: int,
) -> dict:
    if not isinstance(value, dict) or set(value) != _LEASE_KEYS:
        raise ValueError("account writer lease schema 非法")
    numeric = (
        value["issued_at"],
        value["expires_at"],
    )
    if (
        value["version"] != 1
        or value["action"] != "grant-account-writer-lease"
        or value["broker_id"] != expected_broker_id
        or value["account_uid"] != expected_account_uid
        or value["holder_id"] != expected_holder_id
        or not _HOLDER.fullmatch(str(value["holder_id"]))
        or not _HOLDER.fullmatch(str(value["lease_id"]))
        or type(value["fencing_token"]) is not int
        or value["fencing_token"] <= 0
        or any(
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
            for item in numeric
        )
        or not float(value["issued_at"]) - 5 <= now <= float(value["expires_at"])
        or not 5 <= float(value["expires_at"]) - float(value["issued_at"]) <= maximum_ttl_s
    ):
        raise ValueError("account writer lease identity/time/fence 非法")
    return value


class SignedAccountLeaseClient:
    """Acquire and renew a lease signed by a separate HTTPS broker."""

    def __init__(
        self,
        *,
        base_url: str,
        public_key: str | Path,
        token_env: str,
        account_uid: str,
        broker_id: str,
        ttl_s: int = 30,
        timeout_s: float = 3,
        clock=time.time,
    ):
        parsed = urlparse(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("account lease broker 必须是不含凭据的 HTTPS URL")
        if (
            not account_uid.strip()
            or not broker_id.strip()
            or not token_env.strip()
            or not 15 <= ttl_s <= 60
            or not 0 < timeout_s <= 5
        ):
            raise ValueError("account lease client identity/TTL/timeout 非法")
        self.base_url = base_url.rstrip("/")
        self.public_key = Path(public_key)
        self.token_env = token_env
        self.account_uid = account_uid
        self.broker_id = broker_id
        self.ttl_s = ttl_s
        self.timeout_s = timeout_s
        self._clock = clock
        self._lock = threading.Lock()
        self._claims: dict | None = None
        self._holder_id = ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error = ""

    def _request(self, action: str, payload: dict) -> dict:
        token = os.environ.get(self.token_env, "")
        if not token:
            raise RuntimeError(f"account lease 缺少 bearer token 环境变量: {self.token_env}")
        response = requests.post(
            f"{self.base_url}/v1/leases/{action}",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout_s,
            allow_redirects=False,
        )
        if response.status_code == 409:
            raise AccountLeaseConflict(f"account UID {self.account_uid} 已由另一运行时持有")
        response.raise_for_status()
        try:
            artifact = response.json()
        except ValueError as exc:
            raise RuntimeError("account lease broker 返回非 JSON") from exc
        claims = verify_ed25519_artifact(
            artifact,
            self.public_key,
            label="account writer lease",
        )
        return validate_lease_claims(
            claims,
            expected_account_uid=self.account_uid,
            expected_holder_id=self._holder_id,
            expected_broker_id=self.broker_id,
            now=self._clock(),
            maximum_ttl_s=self.ttl_s,
        )

    def start(self, *, holder_id: str) -> dict:
        if not _HOLDER.fullmatch(holder_id):
            raise ValueError("account lease holder_id 必须是 32 位小写 hex")
        if self._thread and self._thread.is_alive():
            raise RuntimeError("account lease client 已启动")
        self._holder_id = holder_id
        claims = self._request(
            "acquire",
            {
                "account_uid": self.account_uid,
                "holder_id": holder_id,
                "ttl_seconds": self.ttl_s,
            },
        )
        with self._lock:
            self._claims = claims
            self.last_error = ""
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._renew_loop,
            name="account-writer-lease-renewer",
            daemon=True,
        )
        self._thread.start()
        return claims

    def _renew_loop(self) -> None:
        interval = max(self.ttl_s / 3, 1)
        while not self._stop.wait(interval):
            with self._lock:
                current = dict(self._claims or {})
            if not current:
                return
            try:
                renewed = self._request(
                    "renew",
                    {
                        "account_uid": self.account_uid,
                        "holder_id": self._holder_id,
                        "lease_id": current["lease_id"],
                        "fencing_token": current["fencing_token"],
                        "ttl_seconds": self.ttl_s,
                    },
                )
                if (
                    renewed["lease_id"] != current["lease_id"]
                    or renewed["fencing_token"] != current["fencing_token"]
                ):
                    raise RuntimeError("account lease renew 改变 lease/fencing identity")
                with self._lock:
                    self._claims = renewed
                    self.last_error = ""
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self.last_error = f"{type(exc).__name__}: {exc}"

    def valid(self, *, safety_margin_s: float = 5) -> bool:
        with self._lock:
            claims = dict(self._claims or {})
        return bool(claims and self._clock() + safety_margin_s < float(claims["expires_at"]))

    def fencing_identity(self) -> tuple[str, int] | None:
        with self._lock:
            claims = dict(self._claims or {})
        if not claims:
            return None
        return claims["lease_id"], claims["fencing_token"]

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        with self._lock:
            claims = dict(self._claims or {})
        if claims:
            with contextlib.suppress(Exception):
                self._request(
                    "release",
                    {
                        "account_uid": self.account_uid,
                        "holder_id": self._holder_id,
                        "lease_id": claims["lease_id"],
                        "fencing_token": claims["fencing_token"],
                        "ttl_seconds": self.ttl_s,
                    },
                )
        with self._lock:
            self._claims = None


class AccountLeaseStore:
    """SQLite state machine used by the reference independent broker."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS account_writer_leases (
                    account_uid TEXT PRIMARY KEY,
                    holder_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
                    expires_at REAL NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def acquire(
        self,
        *,
        account_uid: str,
        holder_id: str,
        ttl_s: int,
        broker_id: str,
        now: float,
    ) -> dict:
        if (
            not account_uid.strip()
            or not _HOLDER.fullmatch(holder_id)
            or not 15 <= ttl_s <= 60
            or not broker_id.strip()
        ):
            raise ValueError("broker lease acquire 参数非法")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT holder_id, lease_id, fencing_token, expires_at
                FROM account_writer_leases WHERE account_uid=?
                """,
                (account_uid,),
            ).fetchone()
            if row and float(row[3]) > now and row[0] != holder_id:
                raise AccountLeaseConflict(f"account UID {account_uid} 已被持有")
            if row and float(row[3]) > now and row[0] == holder_id:
                lease_id = str(row[1])
                fencing_token = int(row[2])
            else:
                lease_id = uuid.uuid4().hex
                fencing_token = int(row[2]) + 1 if row else 1
            expires_at = now + ttl_s
            connection.execute(
                """
                INSERT INTO account_writer_leases(
                    account_uid, holder_id, lease_id,
                    fencing_token, expires_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(account_uid) DO UPDATE SET
                    holder_id=excluded.holder_id,
                    lease_id=excluded.lease_id,
                    fencing_token=excluded.fencing_token,
                    expires_at=excluded.expires_at
                """,
                (
                    account_uid,
                    holder_id,
                    lease_id,
                    fencing_token,
                    expires_at,
                ),
            )
        return {
            "version": 1,
            "action": "grant-account-writer-lease",
            "broker_id": broker_id,
            "account_uid": account_uid,
            "holder_id": holder_id,
            "lease_id": lease_id,
            "fencing_token": fencing_token,
            "issued_at": now,
            "expires_at": expires_at,
        }

    def renew(
        self,
        *,
        account_uid: str,
        holder_id: str,
        lease_id: str,
        fencing_token: int,
        ttl_s: int,
        broker_id: str,
        now: float,
    ) -> dict:
        if (
            not account_uid.strip()
            or not _HOLDER.fullmatch(holder_id)
            or not _HOLDER.fullmatch(lease_id)
            or type(fencing_token) is not int
            or fencing_token <= 0
            or not 15 <= ttl_s <= 60
            or not broker_id.strip()
        ):
            raise ValueError("broker lease renew 参数非法")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT holder_id, lease_id, fencing_token, expires_at
                FROM account_writer_leases WHERE account_uid=?
                """,
                (account_uid,),
            ).fetchone()
            if (
                row is None
                or row[0] != holder_id
                or row[1] != lease_id
                or int(row[2]) != fencing_token
                or float(row[3]) <= now
            ):
                raise AccountLeaseConflict("account lease 已丢失或过期")
            expires_at = now + ttl_s
            connection.execute(
                """
                UPDATE account_writer_leases
                SET expires_at=?
                WHERE account_uid=? AND lease_id=? AND fencing_token=?
                """,
                (expires_at, account_uid, lease_id, fencing_token),
            )
        return {
            "version": 1,
            "action": "grant-account-writer-lease",
            "broker_id": broker_id,
            "account_uid": account_uid,
            "holder_id": holder_id,
            "lease_id": lease_id,
            "fencing_token": fencing_token,
            "issued_at": now,
            "expires_at": expires_at,
        }

    def release(
        self,
        *,
        account_uid: str,
        holder_id: str,
        lease_id: str,
        fencing_token: int,
        broker_id: str,
        now: float,
    ) -> dict:
        if (
            not account_uid.strip()
            or not _HOLDER.fullmatch(holder_id)
            or not _HOLDER.fullmatch(lease_id)
            or type(fencing_token) is not int
            or fencing_token <= 0
            or not broker_id.strip()
        ):
            raise ValueError("broker lease release 参数非法")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT holder_id, lease_id, fencing_token
                FROM account_writer_leases WHERE account_uid=?
                """,
                (account_uid,),
            ).fetchone()
            if (
                row is None
                or row[0] != holder_id
                or row[1] != lease_id
                or int(row[2]) != fencing_token
            ):
                raise AccountLeaseConflict("account lease release identity 非法")
            connection.execute(
                """
                UPDATE account_writer_leases SET expires_at=?
                WHERE account_uid=? AND lease_id=? AND fencing_token=?
                """,
                (now, account_uid, lease_id, fencing_token),
            )
        return {
            "version": 1,
            "action": "grant-account-writer-lease",
            "broker_id": broker_id,
            "account_uid": account_uid,
            "holder_id": holder_id,
            "lease_id": lease_id,
            "fencing_token": fencing_token,
            "issued_at": now,
            "expires_at": now + 5,
        }
