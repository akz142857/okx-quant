"""Isolated TLS reverse proxy for the POST-before-ACK Stage-C barrier."""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import threading
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

from okx_quant.application.approval import canonical_bytes
from okx_quant.ops.stage_c_chaos_protocol import _opaque_bytes_descriptor
from stage_c_test_harness.barriers import BarrierHook, _atomic_new
from stage_c_test_harness.pipeline import PIPELINE_PROOF_SCHEMA

ORDER_PATH = "/api/v5/trade/order"
_ALLOWED_UPSTREAM_HOSTS = {
    "openapi.okx.com",
    "www.okx.com",
    "127.0.0.1",
    "localhost",
    "::1",
}
_PRODUCTION_UPSTREAM_HOSTS = {"openapi.okx.com", "www.okx.com"}
_SECURITY_HEADERS = {
    "content-length",
    "host",
    "ok-access-key",
    "ok-access-passphrase",
    "ok-access-sign",
    "ok-access-timestamp",
    "x-simulated-trading",
}


def _strict_json_object(raw: bytes) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("Stage-C TLS proxy JSON key 重复")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except json.JSONDecodeError as exc:
        raise ValueError("Stage-C TLS proxy body 非法 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("Stage-C TLS proxy body 必须是 object")
    return value


class TLSAckHoldingProxyController:
    """Read a complete BUY POST, forward it once, then withhold its ACK."""

    def __init__(
        self,
        *,
        challenge: dict,
        hook: BarrierHook,
        proof_output: Path,
        upstream_base_url: str,
        target_pid: int,
        verify_upstream: bool | str = True,
        session_factory: Callable[[], requests.Session] = requests.Session,
        wait_for_kill: Callable[[], None] = BarrierHook.wait_for_systemd_kill,
    ):
        parsed = urllib.parse.urlsplit(upstream_base_url)
        if (
            challenge.get("scenario") != "barrier-post-before-ack"
            or hook.challenge != challenge
            or hook.pid != target_pid
            or target_pid <= 1
            or parsed.scheme != "https"
            or parsed.hostname not in _ALLOWED_UPSTREAM_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or proof_output.exists()
            or proof_output.is_symlink()
            or (
                session_factory is requests.Session
                and parsed.hostname not in _PRODUCTION_UPSTREAM_HOSTS
            )
            or (
                session_factory is requests.Session
                and verify_upstream is not True
            )
        ):
            raise ValueError("Stage-C TLS proxy 未绑定 test-only challenge")
        self.challenge = challenge
        self.hook = hook
        self.proof_output = proof_output
        self.upstream_base_url = upstream_base_url.rstrip("/")
        self.target_pid = target_pid
        self.verify_upstream = verify_upstream
        self.session_factory = session_factory
        self.wait_for_kill = wait_for_kill
        self._lock = threading.Lock()
        self._reached = False

    def receive_and_hold(
        self,
        *,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> None:
        """Forward exactly once and never deliver ACK before external kill."""
        with self._lock:
            if self._reached:
                raise RuntimeError("Stage-C TLS proxy 已消费唯一 POST")
            if (
                path != ORDER_PATH
                or not 0 < len(body) <= 64 * 1024
                or any(key.lower() == "transfer-encoding" for key, _ in headers)
            ):
                raise ValueError("Stage-C TLS proxy request 非固定 OKX POST")
            lowered: dict[str, list[str]] = {}
            for key, value in headers:
                lowered.setdefault(key.lower(), []).append(value)
            if any(
                len(lowered.get(key, [])) > 1
                for key in _SECURITY_HEADERS
            ):
                raise ValueError("Stage-C TLS proxy security header 重复")
            if lowered.get("x-simulated-trading") != ["1"]:
                raise ValueError("Stage-C TLS proxy 仅允许 OKX 模拟盘")
            payload = _strict_json_object(body)
            try:
                size = Decimal(str(payload.get("sz", "")))
            except InvalidOperation as exc:
                raise ValueError("Stage-C TLS proxy size 非法") from exc
            if (
                set(payload)
                != {
                    "instId",
                    "tdMode",
                    "side",
                    "ordType",
                    "sz",
                    "tgtCcy",
                    "clOrdId",
                }
                or payload["instId"] != "BTC-USDT"
                or payload["tdMode"] != "cash"
                or payload["side"] != "buy"
                or payload.get("ordType") != "market"
                or payload["tgtCcy"] != "base_ccy"
                or not re.fullmatch(
                    r"[A-Za-z0-9]{1,32}",
                    str(payload["clOrdId"]),
                )
                or not size.is_finite()
                or not Decimal("0.00001") <= size <= Decimal("0.0002")
            ):
                raise ValueError(
                    "Stage-C TLS proxy 仅允许小额 BTC demo probe BUY"
                )
            forward_headers = {
                key: value
                for key, value in headers
                if key.lower() not in {
                    "connection",
                    "content-length",
                    "host",
                    "proxy-connection",
                }
            }
            with self.session_factory() as session:
                response = session.post(
                    self.upstream_base_url + path,
                    headers=forward_headers,
                    data=body,
                    timeout=10,
                    verify=self.verify_upstream,
                )
                upstream_body = response.content
                upstream_status = response.status_code
                upstream_headers = {
                    str(key).lower(): str(value)
                    for key, value in response.headers.items()
                }
            write_completed_at = datetime.now(UTC).isoformat()
            request_material = canonical_bytes({
                "method": "POST",
                "path": path,
                "headers_present": sorted(
                    key.lower() for key, _ in headers
                ),
                "body_sha256": hashlib.sha256(body).hexdigest(),
            })
            proof = {
                "schema": PIPELINE_PROOF_SCHEMA,
                "scenario": self.challenge["scenario"],
                "challenge_id": self.challenge["challenge_id"],
                "barrier_nonce": self.challenge["barrier_nonce"],
                "artifact_sha256": self.challenge["identity"][
                    "artifact_sha256"
                ],
                "boundary": "post-before-ack",
                "pid": self.target_pid,
                "facts": {
                    "cl_ord_id": str(payload["clOrdId"]),
                    "request_sha256": hashlib.sha256(
                        request_material
                    ).hexdigest(),
                    "request_body": _opaque_bytes_descriptor(body),
                    "bytes_received": len(body),
                    "request_fully_received": True,
                    "write_completed_at": write_completed_at,
                    "order_params_sha256": hashlib.sha256(
                        canonical_bytes(payload)
                    ).hexdigest(),
                    "upstream_status": upstream_status,
                    "upstream_headers_sha256": hashlib.sha256(
                        canonical_bytes(upstream_headers)
                    ).hexdigest(),
                    "upstream_response": _opaque_bytes_descriptor(
                        upstream_body
                    ),
                    "upstream_ack_observed_by_proxy": True,
                    "ack_delivery_started_to_trader": False,
                },
            }
            proof_sha256 = hashlib.sha256(
                canonical_bytes(proof)
            ).hexdigest()
            _atomic_new(self.proof_output, proof, mode=0o640)
            self.hook.reach(
                "post-before-ack",
                boundary_proof_sha256=proof_sha256,
            )
            self._reached = True
        self.wait_for_kill()
        raise RuntimeError("Stage-C TLS proxy kill waiter 非法返回")


class TLSDemoPassthroughController:
    """Recovery-only Demo proxy; it contains no barrier or ACK hold path."""

    def __init__(
        self,
        *,
        upstream_base_url: str = "https://openapi.okx.com",
        session_factory: Callable[[], requests.Session] = requests.Session,
        verify_upstream: bool = True,
    ):
        parsed = urllib.parse.urlsplit(upstream_base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _PRODUCTION_UPSTREAM_HOSTS
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or verify_upstream is not True
        ):
            raise ValueError("Stage-C recovery passthrough upstream 非法")
        self.upstream_base_url = upstream_base_url.rstrip("/")
        self.session_factory = session_factory
        self.verify_upstream = verify_upstream

    def forward(
        self,
        *,
        method: str,
        target: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> tuple[int, dict[str, str], bytes]:
        parsed = urllib.parse.urlsplit(target)
        lowered: dict[str, list[str]] = {}
        for key, value in headers:
            lowered.setdefault(key.lower(), []).append(value)
        if (
            method not in {"GET", "POST"}
            or not parsed.path.startswith("/api/v5/")
            or parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or len(body) > 64 * 1024
            or lowered.get("x-simulated-trading") != ["1"]
            or any(len(values) != 1 for values in lowered.values())
            or any(
                token in parsed.path.lower()
                for token in ("withdraw", "transfer", "/asset/")
            )
        ):
            raise ValueError("Stage-C recovery passthrough request 非法")
        forward_headers = {
            key: value
            for key, value in headers
            if key.lower()
            not in {
                "connection",
                "content-length",
                "host",
                "proxy-connection",
                "transfer-encoding",
            }
        }
        with self.session_factory() as session:
            response = session.request(
                method,
                self.upstream_base_url + target,
                headers=forward_headers,
                data=body or None,
                timeout=10,
                verify=self.verify_upstream,
            )
            response_body = response.content
            response_headers = {
                str(key): str(value)
                for key, value in response.headers.items()
                if str(key).lower()
                not in {
                    "connection",
                    "content-length",
                    "transfer-encoding",
                }
            }
            return response.status_code, response_headers, response_body


class _ProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, controller):
        super().__init__(address, _ProxyHandler)
        self.controller = controller


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_error(400)
            return
        if not 0 < content_length <= 64 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(content_length)
        if len(body) != content_length:
            self.send_error(400)
            return
        # Success deliberately has no HTTP response: the controller blocks
        # after durable proof until the trader is killed.
        self.server.controller.receive_and_hold(  # type: ignore[attr-defined]
            path=urllib.parse.urlsplit(self.path).path,
            headers=[
                (str(key), str(value))
                for key, value in self.headers.raw_items()
            ],
            body=body,
        )

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _PassthroughHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self._forward(b"")

    def do_POST(self) -> None:  # noqa: N802
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if not 0 <= content_length <= 64 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(content_length)
        if len(body) != content_length:
            self.send_error(400)
            return
        self._forward(body)

    def _forward(self, body: bytes) -> None:
        try:
            status, headers, response = self.server.controller.forward(  # type: ignore[attr-defined]
                method=self.command,
                target=self.path,
                headers=[
                    (str(key), str(value))
                    for key, value in self.headers.raw_items()
                ],
                body=body,
            )
        except Exception:  # noqa: BLE001
            self.send_error(502)
            return
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def build_tls_ack_holding_server(
    *,
    host: str,
    port: int,
    certificate: Path,
    private_key: Path,
    controller: TLSAckHoldingProxyController,
) -> ThreadingHTTPServer:
    """Create a loopback-only TLS server; caller controls its lifecycle."""
    if (
        host not in {"127.0.0.1", "::1", "localhost"}
        or not 0 <= port <= 65535
        or not certificate.is_file()
        or certificate.is_symlink()
        or not private_key.is_file()
        or private_key.is_symlink()
    ):
        raise ValueError("Stage-C TLS proxy listen/certificate 非法")
    server = _ProxyServer((host, port), controller)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def build_tls_demo_passthrough_server(
    *,
    host: str,
    port: int,
    certificate: Path,
    private_key: Path,
    controller: TLSDemoPassthroughController,
) -> ThreadingHTTPServer:
    if (
        host not in {"127.0.0.1", "::1", "localhost"}
        or not 0 <= port <= 65535
        or not certificate.is_file()
        or certificate.is_symlink()
        or not private_key.is_file()
        or private_key.is_symlink()
    ):
        raise ValueError("Stage-C TLS recovery proxy listen/certificate 非法")
    server = ThreadingHTTPServer((host, port), _PassthroughHandler)
    server.controller = controller  # type: ignore[attr-defined]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server
