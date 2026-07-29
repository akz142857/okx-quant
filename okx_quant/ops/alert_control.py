"""Single-writer ingestion of external alert challenge/receipt requests."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import time
from pathlib import Path

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.db import JournalRepository

_SHA256 = re.compile(r"[0-9a-f]{64}")


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError(f"{label} 必须是正有限 Unix timestamp")
    return float(value)


def build_challenge_request(
    *,
    account_id: str,
    role: str,
    day: str,
) -> dict:
    if (
        not account_id.strip()
        or role not in {"shadow", "active", "chaos"}
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day)
    ):
        raise ValueError("alert challenge request identity 非法")
    return {
        "version": 1,
        "action": "request-synthetic-alert-challenge",
        "account_id": account_id,
        "role": role,
        "day": day,
    }


def build_receipt_request(
    *,
    account_id: str,
    kind: str,
    artifact_bytes: bytes,
) -> dict:
    if (
        not account_id.strip()
        or kind not in {"provider", "human-ack", "escalation"}
        or not artifact_bytes
        or len(artifact_bytes) > 524_288
    ):
        raise ValueError("alert receipt request identity/size 非法")
    return {
        "version": 1,
        "action": "import-signed-alert-receipt",
        "account_id": account_id,
        "kind": kind,
        "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "artifact_bytes_base64": base64.b64encode(artifact_bytes).decode(
            "ascii"
        ),
    }


def _receipt_claims(
    artifact_bytes: bytes,
    public_key: Path,
    *,
    action: str,
    keys: set[str],
) -> dict:
    claims = verify_ed25519_artifact(
        json.loads(artifact_bytes),
        public_key,
        label=f"alert {action}",
    )
    if (
        not isinstance(claims, dict)
        or set(claims) != keys
        or claims["version"] != 1
        or claims["action"] != action
        or not str(claims["event_id"]).strip()
        or type(claims["issued_at"]) is not int
        or abs(time.time() - claims["issued_at"]) > 86400
    ):
        raise ValueError(f"alert {action} claims 非法")
    return claims


def apply_alert_control_request(
    request: object,
    *,
    journal: JournalRepository,
    expected_account_id: str,
    receipt_public_keys: dict[str, Path],
) -> dict:
    if not isinstance(request, dict):
        raise ValueError("alert control request 必须是对象")
    if request.get("account_id") != expected_account_id:
        raise ValueError("alert control request account identity 不匹配")
    action = request.get("action")
    if action == "request-synthetic-alert-challenge":
        if set(request) != {
            "version",
            "action",
            "account_id",
            "role",
            "day",
        }:
            raise ValueError("alert challenge request schema 非法")
        if request["version"] != 1:
            raise ValueError("alert challenge request version 非法")
        build_challenge_request(
            account_id=request["account_id"],
            role=request["role"],
            day=request["day"],
        )
        challenge_id = (
            f"synthetic-alert:{expected_account_id}:{request['day']}"
        )
        event_id = journal.enqueue_outbox_once(
            challenge_id,
            "warning.synthetic_alert_delivery_challenge",
            {
                "version": 1,
                "challenge_id": challenge_id,
                "day": request["day"],
                "role": request["role"],
                "account_id": expected_account_id,
                "requires_signed_provider_receipt": True,
            },
        )
        return {"event_id": event_id, "challenge_id": challenge_id}
    if action != "import-signed-alert-receipt" or set(request) != {
        "version",
        "action",
        "account_id",
        "kind",
        "artifact_sha256",
        "artifact_bytes_base64",
    }:
        raise ValueError("alert receipt request schema 非法")
    if request["version"] != 1 or not _SHA256.fullmatch(
        str(request["artifact_sha256"])
    ):
        raise ValueError("alert receipt request version/hash 非法")
    try:
        artifact_bytes = base64.b64decode(
            request["artifact_bytes_base64"],
            validate=True,
        )
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ValueError("alert receipt request base64 非法") from exc
    if (
        not artifact_bytes
        or len(artifact_bytes) > 524_288
        or hashlib.sha256(artifact_bytes).hexdigest()
        != request["artifact_sha256"]
    ):
        raise ValueError("alert receipt request bytes/hash 不匹配")
    common = {"version", "action", "event_id", "issued_at"}
    kind = request["kind"]
    if set(receipt_public_keys) != {
        "provider",
        "human-ack",
        "escalation",
    }:
        raise ValueError("alert receipt role public keys 配置不完整")
    receipt_public_key = receipt_public_keys.get(kind)
    if receipt_public_key is None:
        raise ValueError("alert receipt kind 非法")
    digest = request["artifact_sha256"]
    if kind == "provider":
        claims = _receipt_claims(
            artifact_bytes,
            receipt_public_key,
            action="confirm-alert-provider-received",
            keys=common | {"provider_event_id", "provider_received_at"},
        )
        return journal.record_alert_provider_received(
            claims["event_id"],
            provider_received_at=_timestamp(
                claims["provider_received_at"],
                "provider_received_at",
            ),
            provider_event_id=str(claims["provider_event_id"]),
            artifact_sha256=digest,
        )
    if kind == "human-ack":
        claims = _receipt_claims(
            artifact_bytes,
            receipt_public_key,
            action="confirm-alert-human-ack",
            keys=common
            | {"provider_event_id", "actor", "human_ack_at"},
        )
        match = next(
            (
                row
                for row in journal.list_alert_deliveries()
                if row["event_id"] == claims["event_id"]
            ),
            None,
        )
        if (
            match is None
            or match["provider_event_id"] != claims["provider_event_id"]
        ):
            raise RuntimeError("human ack 未绑定已验证 provider event")
        return journal.record_alert_human_ack(
            claims["event_id"],
            human_ack_at=_timestamp(
                claims["human_ack_at"],
                "human_ack_at",
            ),
            actor=str(claims["actor"]),
            artifact_sha256=digest,
        )
    if kind == "escalation":
        claims = _receipt_claims(
            artifact_bytes,
            receipt_public_key,
            action="confirm-alert-escalation",
            keys=common | {"escalation_at", "reason"},
        )
        if not str(claims["reason"]).strip():
            raise ValueError("escalation reason 不能为空")
        return journal.record_alert_escalation(
            claims["event_id"],
            escalation_at=_timestamp(
                claims["escalation_at"],
                "escalation_at",
            ),
        )
    raise ValueError("alert receipt kind 非法")
