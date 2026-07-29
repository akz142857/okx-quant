"""发布级证据的规范化、身份绑定和 detached manifest 支持。"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from okx_quant.application.approval import (
    canonical_bytes,
    verify_ed25519_artifact,
)

_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SECRET_KEYS = {
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "secretkey",
    "passphrase",
    "password",
    "private_key",
    "privatekey",
    "token",
}

DEMO_CONTRACT_MANIFEST_KEYS = {
    "version",
    "action",
    "contract_run_id",
    "created_at",
    "release_identity",
    "deployment_identity",
    "components",
    "retention",
    "kms_key_id",
    "signing_key_id",
}
DEMO_CONTRACT_EVIDENCE_KEYS = {
    "version",
    "artifact_type",
    "contract_run_id",
    "script_version",
    "started_at",
    "completed_at",
    "release_identity",
    "deployment_identity",
    "fixture_sha256",
    "contract",
}


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _normalized_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def redact_secrets(value: Any) -> Any:
    """递归移除 secret 值，但保留字段存在性以稳定绑定配置结构。"""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if _normalized_key(key) in {
                _normalized_key(name) for name in _SECRET_KEYS
            }:
                redacted[str(key)] = "<redacted-present>" if item else ""
            else:
                redacted[str(key)] = redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [redact_secrets(item) for item in value]
    return value


def redacted_config_hash(config: dict) -> str:
    if not isinstance(config, dict):
        raise ValueError("配置必须是对象")
    return sha256_bytes(canonical_bytes(redact_secrets(config)))


def credential_fingerprint(api_key: str) -> str:
    """返回不可反推出 API key 的域分离指纹。"""
    if not api_key:
        raise ValueError("API key 不能为空")
    return sha256_bytes(b"okx-quant/api-key/v1\0" + api_key.encode())


def ed25519_public_key_fingerprint(
    key_path: str | Path,
    *,
    private_key: bool = False,
) -> str:
    """Fingerprint canonical public DER, independent of PEM formatting/path."""
    path = Path(key_path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size <= 0:
        raise ValueError("Ed25519 key 必须是非空普通文件且不能为符号链接")
    command = ["openssl", "pkey"]
    if not private_key:
        command.append("-pubin")
    command.extend([
        "-in",
        str(path),
        "-pubout",
        "-outform",
        "DER",
    ])
    result = subprocess.run(
        command,
        capture_output=True,
        timeout=5,
        check=False,
    )
    ed25519_subject_public_key_prefix = bytes.fromhex(
        "302a300506032b6570032100"
    )
    if (
        result.returncode != 0
        or len(result.stdout) != 44
        or not result.stdout.startswith(ed25519_subject_public_key_prefix)
    ):
        raise ValueError("Ed25519 key 无法派生规范公钥")
    return sha256_bytes(
        b"okx-quant/ed25519-public/v1\0" + result.stdout
    )


def utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def _git(
    release_root: Path,
    *args: str,
    text: bool = True,
) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(release_root), *args],
        capture_output=True,
        check=False,
        timeout=10,
        text=text,
    )
    if result.returncode != 0:
        stderr = result.stderr if text else result.stderr.decode(errors="replace")
        raise RuntimeError(f"Git identity 查询失败: {stderr.strip()}")
    return result.stdout


def source_manifest_hash(release_root: str | Path) -> str:
    """哈希 Git 索引内的发布树文件及其当前 bytes。"""
    root = Path(release_root).resolve()
    raw = _git(root, "ls-files", "-z", text=False)
    assert isinstance(raw, bytes)
    labels = sorted(
        item.decode("utf-8")
        for item in raw.split(b"\0")
        if item
    )
    if not labels:
        raise RuntimeError("发布目录没有 Git tracked files")
    digest = hashlib.sha256()
    for label in labels:
        path = root / label
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"发布 manifest 文件非法或缺失: {label}")
        digest.update(label.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def build_release_identity(release_root: str | Path) -> dict:
    root = Path(release_root).resolve()
    commit = str(_git(root, "rev-parse", "HEAD")).strip().lower()
    tree = str(_git(root, "rev-parse", "HEAD^{tree}")).strip().lower()
    status = str(
        _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    )
    if not _SHA1.fullmatch(commit) or not _SHA1.fullmatch(tree):
        raise RuntimeError("Git commit/tree identity 非法")
    return {
        "git_commit": commit,
        "git_tree_hash": tree,
        "workspace_clean": not bool(status.strip()),
        "source_manifest_sha256": source_manifest_hash(root),
    }


def build_deployment_identity(
    *,
    config: dict,
    account_config: dict,
) -> dict:
    okx = config.get("okx", {})
    if not isinstance(okx, dict):
        raise ValueError("okx 配置必须是对象")
    account_uid = str(account_config.get("uid", "")).strip()
    if not account_uid:
        raise ValueError("OKX account config 未返回 uid")
    base_url = str(okx.get("base_url", "")).rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("OKX API domain 必须是有效 HTTPS URL")
    simulated = okx.get("simulated")
    if simulated is not True:
        raise ValueError("Demo contract 只允许 simulated=true")
    return {
        "account_uid": account_uid,
        "api_domain": base_url,
        "simulated": True,
        "config_sha256": redacted_config_hash(config),
        "key_fingerprint": credential_fingerprint(
            str(okx.get("api_key", ""))
        ),
    }


def component_descriptor(
    *,
    name: str,
    payload: bytes,
    object_uri: str = "",
    version_id: str = "",
) -> dict:
    return {
        "name": name,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
        "object_uri": object_uri,
        "version_id": version_id,
    }


def build_demo_contract_manifest_request(
    *,
    contract_run_id: str,
    release_identity: dict,
    deployment_identity: dict,
    evidence_name: str,
    evidence_bytes: bytes,
    fixture_name: str,
    fixture_bytes: bytes,
    created_at: str,
) -> dict:
    return {
        "version": 2,
        "action": "attest-demo-contract-v2",
        "contract_run_id": contract_run_id,
        "created_at": created_at,
        "release_identity": release_identity,
        "deployment_identity": deployment_identity,
        "components": {
            "evidence": component_descriptor(
                name=evidence_name,
                payload=evidence_bytes,
            ),
            "fixture": component_descriptor(
                name=fixture_name,
                payload=fixture_bytes,
            ),
        },
        "retention": {
            "mode": "",
            "retain_until": "",
        },
        "kms_key_id": "",
        "signing_key_id": "",
    }


def complete_demo_contract_manifest(
    request: dict,
    *,
    evidence_uri: str,
    evidence_version_id: str,
    fixture_uri: str,
    fixture_version_id: str,
    retain_until: str,
    kms_key_id: str,
    signing_key_id: str,
) -> dict:
    """由独立签名步骤补齐 immutable object identity。"""
    payload = json.loads(json.dumps(request))
    if set(payload) != DEMO_CONTRACT_MANIFEST_KEYS:
        raise ValueError("Demo contract manifest request schema 非法")
    for name, uri, version_id in (
        ("evidence", evidence_uri, evidence_version_id),
        ("fixture", fixture_uri, fixture_version_id),
    ):
        parsed = urlparse(uri)
        if (
            parsed.scheme != "s3"
            or not parsed.netloc
            or not parsed.path.strip("/")
            or not version_id.strip()
        ):
            raise ValueError(f"{name} 必须绑定 S3 URI 和 exact version ID")
        payload["components"][name]["object_uri"] = uri
        payload["components"][name]["version_id"] = version_id
    retention = datetime.fromisoformat(retain_until)
    if retention.tzinfo is None or retention.utcoffset() is None:
        raise ValueError("retain_until 必须带时区")
    payload["retention"] = {
        "mode": "COMPLIANCE",
        "retain_until": retention.astimezone(UTC).isoformat(),
    }
    if not kms_key_id.strip():
        raise ValueError("kms_key_id 不能为空")
    payload["kms_key_id"] = kms_key_id
    if not signing_key_id.strip():
        raise ValueError("signing_key_id 不能为空")
    payload["signing_key_id"] = signing_key_id
    validate_demo_contract_manifest_payload(payload)
    return payload


def _validate_component(component: object, label: str) -> dict:
    if not isinstance(component, dict) or set(component) != {
        "name",
        "sha256",
        "bytes",
        "object_uri",
        "version_id",
    }:
        raise ValueError(f"{label} component schema 非法")
    if (
        not str(component["name"]).strip()
        or not _SHA256.fullmatch(str(component["sha256"]).lower())
        or type(component["bytes"]) is not int
        or component["bytes"] <= 0
    ):
        raise ValueError(f"{label} component identity 非法")
    return component


def validate_demo_contract_manifest_payload(
    payload: object,
    *,
    require_immutable: bool = True,
) -> dict:
    if not isinstance(payload, dict) or set(payload) != DEMO_CONTRACT_MANIFEST_KEYS:
        raise ValueError("Demo contract manifest schema 非法")
    if payload["version"] != 2 or payload["action"] != "attest-demo-contract-v2":
        raise ValueError("Demo contract manifest 版本/action 非法")
    if not re.fullmatch(r"[0-9a-f]{32}", str(payload["contract_run_id"])):
        raise ValueError("contract_run_id 非法")
    created = datetime.fromisoformat(str(payload["created_at"]))
    if created.tzinfo is None or created.utcoffset() is None:
        raise ValueError("manifest created_at 必须带时区")
    release = payload["release_identity"]
    if (
        not isinstance(release, dict)
        or set(release)
        != {
            "git_commit",
            "git_tree_hash",
            "workspace_clean",
            "source_manifest_sha256",
        }
        or not _SHA1.fullmatch(str(release["git_commit"]))
        or not _SHA1.fullmatch(str(release["git_tree_hash"]))
        or type(release["workspace_clean"]) is not bool
        or not _SHA256.fullmatch(str(release["source_manifest_sha256"]))
    ):
        raise ValueError("release identity 非法")
    deployment = payload["deployment_identity"]
    if (
        not isinstance(deployment, dict)
        or set(deployment)
        != {
            "account_uid",
            "api_domain",
            "simulated",
            "config_sha256",
            "key_fingerprint",
        }
        or not str(deployment["account_uid"]).strip()
        or deployment["simulated"] is not True
        or not _SHA256.fullmatch(str(deployment["config_sha256"]))
        or not _SHA256.fullmatch(str(deployment["key_fingerprint"]))
    ):
        raise ValueError("deployment identity 非法")
    components = payload["components"]
    if not isinstance(components, dict) or set(components) != {
        "evidence",
        "fixture",
    }:
        raise ValueError("manifest components 非法")
    for label in ("evidence", "fixture"):
        component = _validate_component(components[label], label)
        if require_immutable:
            parsed = urlparse(str(component["object_uri"]))
            if (
                parsed.scheme != "s3"
                or not parsed.netloc
                or not parsed.path.strip("/")
                or not str(component["version_id"]).strip()
            ):
                raise ValueError(f"{label} 未绑定 exact immutable object")
    retention = payload["retention"]
    if not isinstance(retention, dict) or set(retention) != {
        "mode",
        "retain_until",
    }:
        raise ValueError("retention schema 非法")
    if require_immutable:
        if retention["mode"] != "COMPLIANCE":
            raise ValueError("Object Lock 必须为 COMPLIANCE")
        retain_until = datetime.fromisoformat(str(retention["retain_until"]))
        if retain_until.tzinfo is None or retain_until.utcoffset() is None:
            raise ValueError("retention 时间必须带时区")
        if not str(payload["signing_key_id"]).strip():
            raise ValueError("manifest signing_key_id 不能为空")
        if not str(payload["kms_key_id"]).strip():
            raise ValueError("manifest kms_key_id 不能为空")
    return payload


def verify_component_bytes(component: dict, payload: bytes) -> None:
    if len(payload) != component["bytes"]:
        raise ValueError(f"{component['name']} bytes 不匹配")
    if sha256_bytes(payload) != component["sha256"]:
        raise ValueError(f"{component['name']} SHA-256 不匹配")


def validate_demo_contract_evidence(
    evidence: object,
    *,
    fixture_bytes: bytes,
) -> dict:
    if (
        not isinstance(evidence, dict)
        or set(evidence) != DEMO_CONTRACT_EVIDENCE_KEYS
    ):
        raise ValueError("Demo contract evidence v2 schema 非法")
    if (
        evidence["version"] != 2
        or evidence["artifact_type"] != "okx-demo-contract"
        or evidence["script_version"] != 2
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(evidence["contract_run_id"]),
        )
    ):
        raise ValueError("Demo contract evidence version/identity 非法")
    started = datetime.fromisoformat(str(evidence["started_at"]))
    completed = datetime.fromisoformat(str(evidence["completed_at"]))
    if (
        started.tzinfo is None
        or started.utcoffset() is None
        or completed.tzinfo is None
        or completed.utcoffset() is None
        or completed < started
    ):
        raise ValueError("Demo contract evidence UTC 时间链非法")
    fixture_hash = sha256_bytes(fixture_bytes)
    if (
        not _SHA256.fullmatch(str(evidence["fixture_sha256"]))
        or fixture_hash != evidence["fixture_sha256"]
    ):
        raise ValueError("Demo contract fixture SHA-256 不匹配")
    contract = evidence["contract"]
    if (
        not isinstance(contract, dict)
        or contract.get("ok") is not True
        or contract.get("route_b_ok") is not True
        or contract.get("attached_probe_conclusive") is not True
        or contract.get("cleanup_errors") != []
    ):
        raise ValueError("Demo contract 交易/保护/清理契约未通过")
    fixture = json.loads(fixture_bytes)
    if (
        not isinstance(fixture, dict)
        or fixture.get("version") != 1
        or fixture.get("source_evidence_sha256")
        != sha256_bytes(canonical_bytes(contract))
    ):
        raise ValueError("Demo contract fixture 未绑定 contract payload")
    validate_demo_contract_manifest_payload(
        {
            "version": 2,
            "action": "attest-demo-contract-v2",
            "contract_run_id": evidence["contract_run_id"],
            "created_at": evidence["completed_at"],
            "release_identity": evidence["release_identity"],
            "deployment_identity": evidence["deployment_identity"],
            "components": {
                "evidence": component_descriptor(
                    name="evidence",
                    payload=b"x",
                ),
                "fixture": component_descriptor(
                    name="fixture",
                    payload=b"x",
                ),
            },
            "retention": {"mode": "", "retain_until": ""},
            "kms_key_id": "",
            "signing_key_id": "",
        },
        require_immutable=False,
    )
    return evidence


def sign_ed25519_payload(payload: dict, private_key: Path) -> dict:
    """使用 OpenSSL 生成与项目其它准入制品一致的 detached Ed25519 签名。"""
    import tempfile

    with tempfile.NamedTemporaryFile() as message:
        message.write(canonical_bytes(payload))
        message.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                message.name,
            ],
            capture_output=True,
            timeout=5,
            check=False,
        )
    if result.returncode != 0 or len(result.stdout) != 64:
        raise RuntimeError("Demo contract manifest Ed25519 签名失败")
    return {
        "payload": payload,
        "signature": base64.b64encode(result.stdout).decode("ascii"),
    }


def verify_signed_demo_contract_manifest(
    artifact: object,
    public_key: str | Path,
) -> dict:
    payload = verify_ed25519_artifact(
        artifact,
        public_key,
        label="Demo contract manifest",
    )
    return validate_demo_contract_manifest_payload(payload)
