"""Local-only HTTP server for the read-only trading Dashboard."""

from __future__ import annotations

import argparse
import json
import mimetypes
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .read_model import DashboardReadModel

_STATIC_ROOT = Path(__file__).with_name("static")
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


class DashboardServer:
    def __init__(
        self,
        read_model: DashboardReadModel,
        *,
        host: str = "127.0.0.1",
        port: int = 9180,
    ):
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError(
                "Dashboard 没有内置身份认证，只允许绑定本机回环地址"
            )
        self.read_model = read_model
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def _handler(self):
        read_model = self.read_model

        class Handler(BaseHTTPRequestHandler):
            server_version = "OKXQuantDashboard/1"

            def _headers(
                self,
                *,
                status: HTTPStatus,
                content_type: str,
                length: int,
                cache: str = "no-store",
            ) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(length))
                self.send_header("Cache-Control", cache)
                for key, value in _SECURITY_HEADERS.items():
                    self.send_header(key, value)
                self.end_headers()

            def _json(
                self,
                payload: object,
                *,
                status: HTTPStatus = HTTPStatus.OK,
            ) -> None:
                body = json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                self._headers(
                    status=status,
                    content_type="application/json; charset=utf-8",
                    length=len(body),
                )
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _error(self, status: HTTPStatus, message: str) -> None:
                self._json(
                    {"error": status.phrase, "message": message},
                    status=status,
                )

            def _static(self, relative: str) -> None:
                target = (_STATIC_ROOT / relative).resolve()
                try:
                    target.relative_to(_STATIC_ROOT.resolve())
                except ValueError:
                    self._error(HTTPStatus.NOT_FOUND, "资源不存在")
                    return
                if not target.is_file():
                    self._error(HTTPStatus.NOT_FOUND, "资源不存在")
                    return
                body = target.read_bytes()
                content_type = (
                    mimetypes.guess_type(target.name)[0]
                    or "application/octet-stream"
                )
                self._headers(
                    status=HTTPStatus.OK,
                    content_type=content_type,
                    length=len(body),
                    cache="public, max-age=300",
                )
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _route(self) -> None:
                parsed = urlparse(self.path)
                try:
                    if parsed.path in {"/", "/index.html"}:
                        self._static("index.html")
                    elif parsed.path == "/assets/app.css":
                        self._static("app.css")
                    elif parsed.path == "/assets/app.js":
                        self._static("app.js")
                    elif parsed.path == "/healthz":
                        self._json(
                            {
                                "ok": True,
                                "schema_version": read_model.validate_schema(),
                                "access": "read-only",
                            }
                        )
                    elif parsed.path == "/api/v1/overview":
                        self._json(read_model.overview())
                    elif parsed.path == "/api/v1/positions":
                        self._json({"items": read_model.positions()})
                    elif parsed.path == "/api/v1/orders":
                        query = parse_qs(parsed.query)
                        limit = int(query.get("limit", ["100"])[0])
                        self._json({"items": read_model.orders(limit)})
                    elif parsed.path == "/api/v1/events":
                        query = parse_qs(parsed.query)
                        limit = int(query.get("limit", ["100"])[0])
                        self._json({"items": read_model.events(limit)})
                    else:
                        self._error(HTTPStatus.NOT_FOUND, "页面不存在")
                except (TypeError, ValueError):
                    self._error(HTTPStatus.BAD_REQUEST, "请求参数非法")
                except Exception:
                    self._error(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "只读数据源暂时不可用",
                    )

            def do_GET(self):  # noqa: N802
                self._route()

            def do_HEAD(self):  # noqa: N802
                self._route()

            def do_POST(self):  # noqa: N802
                self._error(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    "Dashboard 第一版严格只读",
                )

            def log_message(self, _format, *_args):
                return

        return Handler

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.read_model.validate_schema()
        self._server = ThreadingHTTPServer(
            (self.host, self.port),
            self._handler(),
        )
        self._server.daemon_threads = True
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="dashboard-http",
            daemon=True,
        )
        self._thread.start()

    def serve_forever(self) -> None:
        self.read_model.validate_schema()
        self._server = ThreadingHTTPServer(
            (self.host, self.port),
            self._handler(),
        )
        self._server.daemon_threads = True
        self.port = int(self._server.server_address[1])
        print(
            f"OKX Quant Dashboard: http://{self.host}:{self.port} "
            f"(只读数据源: {self.read_model.database})"
        )
        try:
            self._server.serve_forever()
        finally:
            self._server.server_close()
            self._server = None

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="启动本机只读 OKX Quant Web Dashboard"
    )
    parser.add_argument(
        "--database",
        required=True,
        help="SQLite trading.db 路径",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9180)
    args = parser.parse_args()
    DashboardServer(
        DashboardReadModel(args.database),
        host=args.host,
        port=args.port,
    ).serve_forever()


if __name__ == "__main__":
    main()
