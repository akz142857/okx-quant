#!/usr/bin/env python3
"""Reference HTTPS broker for account-UID scoped writer leases."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import ssl
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.ops.account_lease import AccountLeaseConflict, AccountLeaseStore


def _private_file(path: Path, label: str) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size <= 0
    ):
        raise RuntimeError(f"{label} 必须是 owner-only 0600 普通文件")


class LeaseBrokerHandler(BaseHTTPRequestHandler):
    server_version = "okx-quant-account-lease/1"

    def log_message(self, format, *args):  # noqa: A002
        # Never include Authorization or request bodies in access logs.
        super().log_message(format, *args)

    def _json(self, status: int, value: object) -> None:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802
        configured_hash = self.server.token_sha256  # type: ignore[attr-defined]
        authorization = self.headers.get("Authorization", "")
        prefix = "Bearer "
        supplied = authorization[len(prefix) :] if authorization.startswith(prefix) else ""
        supplied_hash = hashlib.sha256(supplied.encode()).hexdigest()
        if not supplied or not hmac.compare_digest(
            supplied_hash,
            configured_hash,
        ):
            self._json(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= 16_384:
            self._json(400, {"error": "invalid content length"})
            return
        try:
            request = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "invalid json"})
            return
        action = self.path.removeprefix("/v1/leases/")
        account_uid = request.get("account_uid") if isinstance(request, dict) else None
        if account_uid not in self.server.allowed_account_uids:  # type: ignore[attr-defined]
            self._json(403, {"error": "account not allowed"})
            return
        store = self.server.store  # type: ignore[attr-defined]
        broker_id = self.server.broker_id  # type: ignore[attr-defined]
        clock = self.server.clock  # type: ignore[attr-defined]
        try:
            if (
                action == "acquire"
                and isinstance(request, dict)
                and set(request) == {"account_uid", "holder_id", "ttl_seconds"}
            ):
                claims = store.acquire(
                    account_uid=request["account_uid"],
                    holder_id=request["holder_id"],
                    ttl_s=request["ttl_seconds"],
                    broker_id=broker_id,
                    now=clock(),
                )
            elif (
                action in {"renew", "release"}
                and isinstance(request, dict)
                and set(request)
                == {
                    "account_uid",
                    "holder_id",
                    "lease_id",
                    "fencing_token",
                    "ttl_seconds",
                }
            ):
                common = {
                    "account_uid": request["account_uid"],
                    "holder_id": request["holder_id"],
                    "lease_id": request["lease_id"],
                    "fencing_token": request["fencing_token"],
                    "broker_id": broker_id,
                    "now": clock(),
                }
                claims = (
                    store.renew(
                        **common,
                        ttl_s=request["ttl_seconds"],
                    )
                    if action == "renew"
                    else store.release(**common)
                )
            else:
                self._json(404, {"error": "unsupported route/schema"})
                return
            artifact = sign_ed25519_payload(
                claims,
                self.server.signing_private_key,  # type: ignore[attr-defined]
            )
            self._json(200, artifact)
        except AccountLeaseConflict as exc:
            self._json(409, {"error": str(exc)})
        except (TypeError, ValueError) as exc:
            self._json(400, {"error": str(exc)})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--signing-private-key", required=True, type=Path)
    parser.add_argument("--tls-cert", required=True, type=Path)
    parser.add_argument("--tls-private-key", required=True, type=Path)
    parser.add_argument("--token-sha256", required=True)
    parser.add_argument("--broker-id", required=True)
    parser.add_argument(
        "--allowed-account-uid",
        required=True,
        action="append",
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=9443)
    args = parser.parse_args()
    _private_file(args.signing_private_key, "broker signing private key")
    _private_file(args.tls_private_key, "broker TLS private key")
    if (
        len(args.token_sha256) != 64
        or any(item not in "0123456789abcdef" for item in args.token_sha256)
        or not args.broker_id.strip()
        or any(not item.strip() for item in args.allowed_account_uid)
        or len(set(args.allowed_account_uid)) != len(args.allowed_account_uid)
        or not 1 <= args.listen_port <= 65535
    ):
        raise ValueError("broker token hash/id/port 非法")
    server = ThreadingHTTPServer(
        (args.listen_host, args.listen_port),
        LeaseBrokerHandler,
    )
    server.store = AccountLeaseStore(args.database)
    server.signing_private_key = args.signing_private_key
    server.token_sha256 = args.token_sha256
    server.broker_id = args.broker_id
    server.allowed_account_uids = frozenset(args.allowed_account_uid)
    server.clock = __import__("time").time
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(
        certfile=args.tls_cert,
        keyfile=args.tls_private_key,
    )
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
