"""Strict, signed attestation for the external Stage-C deployment boundary.

This module deliberately validates *claims about* a Linux/cloud deployment;
it does not manufacture those claims.  The inputs must be exact bytes (or
exact-version object locators) collected by the independent roles.  A valid
artifact therefore makes the missing external work explicit instead of
turning a local fixture into a production capability.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.evidence import (
    ed25519_public_key_fingerprint,
    sha256_bytes,
    sign_ed25519_payload,
)

SCHEMA = "okx-quant.external-deployment-attestation/v1"
ACTION = "attest-external-demo-deployment-v1"
ACCOUNT_ROLES = frozenset({"demo-shadow", "demo-active", "demo-chaos"})
RESPONSIBILITY_ROLES = frozenset({
    "bundle_publisher",
    "raw_observer",
    "deployment_verifier",
    "fleet_admission_gate",
    "worm_readback_verifier",
})
EVIDENCE_ROLES = frozenset({
    "iam_sts",
    "worm_manifest",
    "exact_version_readback",
    "second_fault_domain",
})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_URI_SCHEMES = frozenset({"s3"})
_ROOT_KEYS = {
    "version",
    "schema",
    "action",
    "candidate_sha256",
    "environment",
    "accounts",
    "failure_domains",
    "responsibilities",
    "evidence",
    "issued_at",
    "expires_at",
    "verifier_key_fingerprint",
}
_ACCOUNT_KEYS = {
    "role",
    "account_uid",
    "api_domain",
    "simulated",
    "key_fingerprint",
    "permission_profile",
}
_DOMAIN_KEYS = {
    "role",
    "host_id",
    "network_namespace_sha256",
    "cgroup_policy_sha256",
    "credential_namespace_sha256",
}
_RESPONSIBILITY_KEYS = {
    "role",
    "principal_arn",
    "sts_session_id",
    "key_fingerprint",
}
_EVIDENCE_KEYS = {
    "sha256",
    "bytes",
    "object_uri",
    "version_id",
    "retention_mode",
    "retain_until",
    "kms_key_id",
    "verifier_key_fingerprint",
    "verified_at",
}


def _hash(value: object, label: str) -> str:
    text = str(value).lower()
    if not _SHA256.fullmatch(text):
        raise ValueError(f"{label} 必须是 64 位小写 SHA-256")
    return text


def _time(value: object, label: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise ValueError(f"{label} 必须是带时区 ISO-8601") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError(f"{label} 必须包含时区")
    return result.astimezone(UTC)


def _fingerprint(value: object, label: str) -> str:
    return _hash(value, label)


def _uri(value: object, label: str) -> str:
    parsed = urlparse(str(value))
    if parsed.scheme not in _URI_SCHEMES or not parsed.netloc or not parsed.path.strip("/"):
        raise ValueError(f"{label} 必须是带路径的 s3:// URI")
    return str(value)


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} 不能为空")
    return value


def validate_external_deployment_attestation(value: object) -> dict:
    """Validate one unsigned payload; reject unknown keys and role reuse."""
    if not isinstance(value, dict) or set(value) != _ROOT_KEYS:
        raise ValueError("external deployment attestation schema 非法")
    if (
        value["version"] != 1
        or value["schema"] != SCHEMA
        or value["action"] != ACTION
        or value["environment"] != "OKX demo"
    ):
        raise ValueError("external deployment attestation version/action 非法")
    _hash(value["candidate_sha256"], "candidate_sha256")
    issued = _time(value["issued_at"], "issued_at")
    expires = _time(value["expires_at"], "expires_at")
    if expires <= issued:
        raise ValueError("attestation expires_at 必须晚于 issued_at")
    _fingerprint(value["verifier_key_fingerprint"], "verifier key fingerprint")

    accounts = value["accounts"]
    if not isinstance(accounts, list) or len(accounts) != len(ACCOUNT_ROLES) or {item.get("role") for item in accounts if isinstance(item, dict)} != ACCOUNT_ROLES:
        raise ValueError("Demo 账户角色必须精确覆盖三种隔离账户")
    account_uids: set[str] = set()
    account_keys: set[str] = set()
    for item in accounts:
        if not isinstance(item, dict) or set(item) != _ACCOUNT_KEYS:
            raise ValueError("Demo 账户 attestation 字段非法")
        role = _nonempty(item["role"], "account role")
        uid = _nonempty(item["account_uid"], "account_uid")
        if role not in ACCOUNT_ROLES or uid in account_uids:
            raise ValueError("Demo 账户 UID/role 重复")
        account_uids.add(uid)
        domain = str(item["api_domain"])
        if not domain.startswith("https://") or domain.rstrip("/") not in {
            "https://www.okx.com",
            "https://openapi.okx.com",
        }:
            raise ValueError("Demo 账户 API domain 必须是 OKX HTTPS")
        if item["simulated"] is not True:
            raise ValueError("external deployment 只允许 OKX Demo")
        account_keys.add(_fingerprint(item["key_fingerprint"], "account key fingerprint"))
        _nonempty(item["permission_profile"], "permission_profile")
    if len(account_keys) != len(accounts):
        raise ValueError("Demo 账户不得复用 API key fingerprint")

    domains = value["failure_domains"]
    if not isinstance(domains, list) or len(domains) != len(ACCOUNT_ROLES) or {item.get("role") for item in domains if isinstance(item, dict)} != ACCOUNT_ROLES:
        raise ValueError("故障域必须精确覆盖三种 Demo 角色")
    domain_values: set[tuple[str, str, str, str]] = set()
    host_ids: set[str] = set()
    for item in domains:
        if not isinstance(item, dict) or set(item) != _DOMAIN_KEYS:
            raise ValueError("故障域 attestation 字段非法")
        role = _nonempty(item["role"], "failure domain role")
        if role not in ACCOUNT_ROLES:
            raise ValueError("故障域 role 非法")
        row = (
            _nonempty(item["host_id"], "host_id"),
            _hash(item["network_namespace_sha256"], "network namespace"),
            _hash(item["cgroup_policy_sha256"], "cgroup policy"),
            _hash(item["credential_namespace_sha256"], "credential namespace"),
        )
        if row[0] in host_ids:
            raise ValueError("故障域 host_id 被复用")
        host_ids.add(row[0])
        domain_values.add(row)
    if len(domain_values) != len(domains):
        raise ValueError("故障域 host/network/cgroup/credential identity 被复用")

    responsibilities = value["responsibilities"]
    if not isinstance(responsibilities, list) or len(responsibilities) != len(RESPONSIBILITY_ROLES) or {item.get("role") for item in responsibilities if isinstance(item, dict)} != RESPONSIBILITY_ROLES:
        raise ValueError("职责分离必须精确覆盖五个职责")
    principals: set[str] = set()
    sessions: set[str] = set()
    role_keys: set[str] = set()
    for item in responsibilities:
        if not isinstance(item, dict) or set(item) != _RESPONSIBILITY_KEYS:
            raise ValueError("职责 attestation 字段非法")
        role = _nonempty(item["role"], "responsibility role")
        principal = _nonempty(item["principal_arn"], "IAM principal")
        session = _nonempty(item["sts_session_id"], "STS session")
        if role not in RESPONSIBILITY_ROLES or principal in principals or session in sessions:
            raise ValueError("IAM principal/STS session/role 重复")
        principals.add(principal)
        sessions.add(session)
        role_keys.add(_fingerprint(item["key_fingerprint"], "responsibility key fingerprint"))
    if len(role_keys) != len(responsibilities):
        raise ValueError("五个职责必须使用独立 key")
    verifier = _fingerprint(value["verifier_key_fingerprint"], "verifier key fingerprint")
    if verifier not in role_keys:
        raise ValueError("attestation verifier 必须是预注册职责身份")

    evidence = value["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_ROLES:
        raise ValueError("external evidence 必须覆盖 IAM/WORM/回读/第二故障域")
    for role, item in evidence.items():
        if not isinstance(item, dict) or set(item) != _EVIDENCE_KEYS:
            raise ValueError(f"{role} evidence schema 非法")
        _hash(item["sha256"], f"{role} evidence SHA-256")
        if type(item["bytes"]) is not int or item["bytes"] <= 0:
            raise ValueError(f"{role} evidence bytes 非法")
        _uri(item["object_uri"], f"{role} evidence object_uri")
        _nonempty(item["version_id"], f"{role} evidence version_id")
        _fingerprint(item["verifier_key_fingerprint"], f"{role} evidence verifier")
        _time(item["verified_at"], f"{role} evidence verified_at")
        if role == "worm_manifest":
            if item["retention_mode"] != "COMPLIANCE":
                raise ValueError("WORM evidence 必须是 Object Lock COMPLIANCE")
            retain = _time(item["retain_until"], "WORM retain_until")
            if retain <= expires:
                raise ValueError("WORM retention 必须覆盖 attestation expiry")
            _nonempty(item["kms_key_id"], "WORM kms_key_id")
        elif item["retention_mode"] not in {"", None}:
            raise ValueError(f"{role} 不得伪造 WORM retention")
    return value


def verify_signed_external_deployment_attestation(
    artifact: object,
    public_key: str | Path,
    *,
    now: datetime | None = None,
) -> dict:
    claims = verify_ed25519_artifact(
        artifact,
        public_key,
        label="external deployment attestation",
    )
    validate_external_deployment_attestation(claims)
    fingerprint = ed25519_public_key_fingerprint(public_key)
    if claims["verifier_key_fingerprint"] != fingerprint:
        raise ValueError("external deployment verifier key fingerprint 不匹配")
    if now is not None:
        instant = now.astimezone(UTC) if now.tzinfo else None
        if instant is None:
            raise ValueError("now 必须带时区")
        if not _time(claims["issued_at"], "issued_at") <= instant <= _time(claims["expires_at"], "expires_at"):
            raise ValueError("external deployment attestation 已过期/尚未生效")
    return claims


def build_external_deployment_attestation(
    payload: dict,
    *,
    verifier_private_key: Path,
) -> dict:
    """Validate then sign externally collected claims; never fills facts in."""
    validate_external_deployment_attestation(payload)
    fingerprint = ed25519_public_key_fingerprint(verifier_private_key, private_key=True)
    if payload["verifier_key_fingerprint"] != fingerprint:
        raise ValueError("verifier private key 与 payload fingerprint 不匹配")
    return sign_ed25519_payload(payload, verifier_private_key)


def evidence_descriptor(raw: bytes, *, object_uri: str, version_id: str, verifier_key_fingerprint: str, verified_at: str, retention_mode: str = "", retain_until: str = "", kms_key_id: str = "") -> dict:
    """Build only a byte descriptor; callers must supply exact external locators."""
    return {
        "sha256": sha256_bytes(raw),
        "bytes": len(raw),
        "object_uri": object_uri,
        "version_id": version_id,
        "retention_mode": retention_mode,
        "retain_until": retain_until,
        "kms_key_id": kms_key_id,
        "verifier_key_fingerprint": verifier_key_fingerprint,
        "verified_at": verified_at,
    }
