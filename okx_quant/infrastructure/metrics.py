"""无额外依赖的 Prometheus 文本指标与健康端点。"""

from __future__ import annotations

import math
import threading
from collections import defaultdict
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    def escape(value: object) -> str:
        return (
            str(value)
            .replace("\\", "\\\\")
            .replace("\n", "\\n")
            .replace('"', '\\"')
        )

    body = ",".join(
        f'{key}="{escape(value)}"'
        for key, value in sorted(labels.items())
    )
    return "{" + body + "}"


class MetricRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._values: dict[tuple[str, tuple], float] = defaultdict(float)
        self._types: dict[str, str] = {}

    def inc(self, name: str, amount: float = 1, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._types[name] = "counter"
            self._values[key] += amount

    def set(self, name: str, value: float, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._types[name] = "gauge"
            self._values[key] = value

    def observe(
        self,
        name: str,
        value: float,
        *,
        buckets: tuple[float, ...],
        **labels: str,
    ) -> None:
        """记录 Prometheus 累积直方图，用于在监控端计算 p95/p99。"""
        if not math.isfinite(value) or value < 0:
            raise ValueError("histogram observation 必须是有限非负数")
        ordered = tuple(sorted(set(buckets)))
        label_items = tuple(sorted(labels.items()))
        with self._lock:
            self._types[name] = "histogram"
            self._values[(f"{name}_count", label_items)] += 1
            self._values[(f"{name}_sum", label_items)] += value
            for bound in (*ordered, float("inf")):
                bound_text = (
                    "+Inf" if math.isinf(bound) else format(bound, "g")
                )
                bucket_labels = tuple(
                    sorted((*labels.items(), ("le", bound_text)))
                )
                key = (f"{name}_bucket", bucket_labels)
                self._values[key] += 0
                if value <= bound:
                    self._values[key] += 1

    def render(self) -> str:
        with self._lock:
            values = dict(self._values)
            types = dict(self._types)
        lines: list[str] = []
        for name in sorted(types):
            lines.append(f"# TYPE {name} {types[name]}")
            for (metric, label_items), value in sorted(values.items()):
                if (
                    metric == name
                    or (
                        types[name] == "histogram"
                        and metric in {
                            f"{name}_bucket",
                            f"{name}_count",
                            f"{name}_sum",
                        }
                    )
                ):
                    rendered = (
                        "+Inf"
                        if math.isinf(value) and value > 0
                        else "-Inf"
                        if math.isinf(value)
                        else "NaN"
                        if math.isnan(value)
                        else str(value)
                    )
                    lines.append(
                        f"{metric}{_labels(dict(label_items))} {rendered}"
                    )
        return "\n".join(lines) + "\n"


class MetricsServer:
    def __init__(
        self,
        registry: MetricRegistry,
        *,
        host: str,
        port: int,
        health: Callable[[], tuple[bool, dict]],
        liveness: Callable[[], tuple[bool, dict]] | None = None,
    ):
        self.registry = registry
        self.host = host
        self.port = port
        self.health = health
        self.liveness = liveness or health
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        registry = self.registry
        readiness = self.health
        liveness = self.liveness

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/metrics":
                    body = registry.render().encode()
                    status = 200
                    content_type = "text/plain; version=0.0.4"
                elif self.path in {"/healthz", "/readyz"}:
                    import json

                    probe = (
                        liveness
                        if self.path == "/healthz"
                        else readiness
                    )
                    ok, detail = probe()
                    body = json.dumps(detail, ensure_ascii=False).encode()
                    status = 200 if ok else 503
                    content_type = "application/json"
                else:
                    body = b"not found\n"
                    status = 404
                    content_type = "text/plain"
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                return

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="metrics-http",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
