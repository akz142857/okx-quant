"""Versioned redaction and validation for OKX demo contract captures."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

_IDENTIFIER_KEYS = {
    "ordId": "ORDER_ID",
    "parent_ord_id": "ORDER_ID",
    "exit_ord_id": "ORDER_ID",
    "clOrdId": "CLIENT_ORDER_ID",
    "algoId": "ALGO_ID",
    "algo_id": "ALGO_ID",
    "algoClOrdId": "ALGO_CLIENT_ID",
    "cancel_algo_id": "ALGO_ID",
    "tradeId": "TRADE_ID",
    "uid": "ACCOUNT_ID",
    "account_id": "ACCOUNT_ID",
}
_SECRET_PATTERN = re.compile(
    r"(?i)(api[-_ ]?key|secret|passphrase|signature|authorization)"
)


def build_redacted_contract_fixture(evidence: Mapping) -> dict:
    """Redact stable identifiers while retaining relationship and value shape."""
    if (
        not isinstance(evidence, Mapping)
        or evidence.get("environment") != "OKX demo"
        or not evidence.get("inst_id")
    ):
        raise ValueError("只接受 OKX demo contract evidence")
    source_bytes = json.dumps(
        evidence,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    aliases: dict[tuple[str, str], str] = {}

    def redact(value, key: str = ""):
        if _SECRET_PATTERN.search(key):
            return "<REDACTED_SECRET>"
        if isinstance(value, Mapping):
            return {
                str(child_key): redact(child_value, str(child_key))
                for child_key, child_value in sorted(value.items())
            }
        if isinstance(value, list):
            return [redact(item, key) for item in value]
        label = _IDENTIFIER_KEYS.get(key)
        if label and value not in (None, ""):
            identity = (label, str(value))
            if identity not in aliases:
                aliases[identity] = f"<{label}_{len(aliases) + 1}>"
            return aliases[identity]
        return value

    fixture = {
        "version": 1,
        "capture_origin": "okx_demo_live",
        "captured_at": evidence.get("completed_at"),
        "inst_id": evidence["inst_id"],
        "source_evidence_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "redaction": {
            "version": 1,
            "stable_relationship_tokens": True,
            "redacted_identifier_count": len(aliases),
        },
        "evidence": redact(evidence),
    }
    # Redaction runs lazily, so capture the final count after traversing evidence.
    fixture["redaction"]["redacted_identifier_count"] = len(aliases)
    validate_contract_fixture(fixture)
    return fixture


def validate_contract_fixture(fixture: object) -> None:
    required = {
        "version",
        "capture_origin",
        "captured_at",
        "inst_id",
        "source_evidence_sha256",
        "redaction",
        "evidence",
    }
    if not isinstance(fixture, dict) or set(fixture) != required:
        raise ValueError("OKX contract fixture 字段不完整或含未知字段")
    if fixture["version"] != 1 or fixture["capture_origin"] != "okx_demo_live":
        raise ValueError("OKX contract fixture 版本或来源非法")
    redaction = fixture["redaction"]
    if (
        not isinstance(redaction, dict)
        or set(redaction)
        != {
            "version",
            "stable_relationship_tokens",
            "redacted_identifier_count",
        }
        or redaction["version"] != 1
        or redaction["stable_relationship_tokens"] is not True
        or type(redaction["redacted_identifier_count"]) is not int
        or redaction["redacted_identifier_count"] < 1
    ):
        raise ValueError("OKX contract fixture redaction manifest 非法")
    if not re.fullmatch(
        r"[0-9a-f]{64}",
        str(fixture["source_evidence_sha256"]),
    ):
        raise ValueError("OKX contract fixture source hash 非法")
    evidence = fixture["evidence"]
    if (
        not isinstance(evidence, dict)
        or evidence.get("environment") != "OKX demo"
        or evidence.get("inst_id") != fixture["inst_id"]
        or evidence.get("ok") is not True
        or evidence.get("route_b_ok") is not True
        or evidence.get("cleanup_errors") != []
    ):
        raise ValueError("OKX contract fixture 未证明安全完成 demo contract")

    def inspect(value, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                if (
                    _SECRET_PATTERN.search(str(child_key))
                    and child_value != "<REDACTED_SECRET>"
                ):
                    raise ValueError("OKX contract fixture 泄露敏感字段")
                inspect(child_value, str(child_key))
            return
        if isinstance(value, list):
            for item in value:
                inspect(item, key)
            return
        if (
            key in _IDENTIFIER_KEYS
            and value not in (None, "")
            and not re.fullmatch(r"<[A-Z_]+_[0-9]+>", str(value))
        ):
            raise ValueError("OKX contract fixture 含未脱敏稳定标识")

    inspect(evidence)
