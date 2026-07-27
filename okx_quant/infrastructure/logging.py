"""结构化 JSON 日志和密钥脱敏。"""

from __future__ import annotations

import json
import logging
import traceback
from datetime import UTC, datetime


class SecretRedactionFilter(logging.Filter):
    def __init__(self, secrets: list[str]):
        super().__init__()
        self.secrets = [secret for secret in secrets if secret]

    def filter(self, record: logging.LogRecord) -> bool:
        message = self._redact(record.getMessage())
        record.msg = message
        record.args = ()
        for key, value in list(record.__dict__.items()):
            if key not in {"msg", "args", "exc_info"}:
                record.__dict__[key] = self._redact(value)
        if record.exc_info:
            rendered = "".join(traceback.format_exception(*record.exc_info))
            record._redacted_exception = self._redact(rendered)
        return True

    def _redact(self, value):
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            return {key: self._redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._redact(item) for item in value)
        if value is None or isinstance(value, (int, float, bool)):
            return value
        # 自定义对象随后会被 JSON default=str；必须先对其字符串表示脱敏。
        return self._redact(str(value))


class JsonFormatter(logging.Formatter):
    STANDARD_FIELDS = {
        "name", "msg", "args", "levelname", "levelno", "pathname",
        "filename", "module", "exc_info", "exc_text", "stack_info",
        "lineno", "funcName", "created", "msecs", "relativeCreated",
        "thread", "threadName", "processName", "process",
    }
    CONTEXT_FIELDS = (
        "intent_id",
        "cl_ord_id",
        "ord_id",
        "algo_id",
        "inst_id",
        "system_mode",
        "state_from",
        "state_to",
        "exchange_code",
        "latency_ms",
        "correlation_id",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=UTC
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event_name": getattr(record, "event_name", record.getMessage()),
            "message": record.getMessage(),
        }
        for field in self.CONTEXT_FIELDS:
            payload[field] = getattr(
                record,
                field,
                None if field == "latency_ms" else "",
            )
        for key, value in record.__dict__.items():
            if key not in self.STANDARD_FIELDS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            redacted = getattr(record, "_redacted_exception", None)
            payload["exception"] = (
                redacted
                if redacted is not None
                else self.formatException(record.exc_info)
            )
        return json.dumps(payload, ensure_ascii=False, default=str)
