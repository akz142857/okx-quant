"""Isolated Canary source collection and signing primitives.

Collectors only acquire exact bytes from a declared file, HTTPS endpoint, or
exact-version object interface.  Signers re-parse those bytes and bind them to
the running systemd invocation; neither side accepts a Boolean "passed" input.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pwd
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

from okx_quant.infrastructure.evidence import (
    credential_fingerprint,
    ed25519_public_key_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.research.canary import (
    _POST_START_EVIDENCE_KINDS,
    _PRE_START_EVIDENCE_KINDS,
    CANARY_PRODUCER_ADAPTERS,
    TARGET_CREDENTIAL_AUTHORITIES,
    build_source_evidence,
    canary_readiness_id,
    derive_post_start_facts,
    derive_pre_start_facts,
    identity_sha256,
    pre_start_evidence_observed_at,
    validate_collection_receipt,
    validate_post_start_source_claims,
    validate_pre_start_source_claims,
    validate_target_deployment_identity,
)
from okx_quant.research.demo_soak import (
    canary_source_producer_inventory_sha256,
    validate_canary_source_producer_inventory,
)

MAX_RAW_BYTES = 16 * 1024 * 1024
MAX_CONTROL_BYTES = 2 * 1024 * 1024
_REQUEST_KEYS = {
    "version",
    "producer_name",
    "adapter",
    "method",
    "source_uri",
    "source_object_uri",
    "source_version_id",
    "secondary_source_uri",
    "secondary_source_object_uri",
    "secondary_source_version_id",
    "target_credential_fingerprint",
    "auth_mode",
    "okx_auth_credentials",
    "headers_from_credentials",
    "required_response_headers",
    "secondary_required_response_headers",
    "timeout_seconds",
}
_CONTEXT_KEYS = {
    "version",
    "phase",
    "producer_name",
    "demo_soak_epoch_id",
    "target_deployment_identity",
    "release_identity",
    "pre_start_challenge",
    "transition_sha256",
    "policy_sha256",
    "runtime_instance_id",
    "boot_id",
    "startup_nonce",
    "expected_startup_hard_epoch",
    "pre_start_source_artifact_sha256",
    "capability_expires_at",
}
def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _secure_read(
    path: Path,
    *,
    label: str,
    maximum: int,
    owner_only: bool = False,
) -> bytes:
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_size <= 0
        or info.st_size > maximum
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (
            owner_only
            and (
                not info.st_mode & stat.S_IRUSR
                or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            )
        )
    ):
        raise ValueError(f"{label} 必须是受控、有界普通文件")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
            or opened.st_size != info.st_size
        ):
            raise ValueError(f"{label} 在打开期间发生替换")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if not raw or len(raw) > maximum:
            raise ValueError(f"{label} 大小非法")
        return raw
    finally:
        os.close(descriptor)


def _load_json(path: Path, *, label: str) -> dict:
    raw = _secure_read(
        path,
        label=label,
        maximum=MAX_CONTROL_BYTES,
    )
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是 JSON 对象")
    return value


def _atomic_replace(path: Path, raw: bytes, *, mode: int) -> None:
    if path.is_symlink():
        raise ValueError(f"拒绝写入符号链接: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, mode)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Canary atomic write 无进展")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _current_execution(expected_user: str, expected_unit: str) -> dict:
    actual_user = pwd.getpwuid(os.getuid()).pw_name
    invocation = os.environ.get("INVOCATION_ID", "").lower()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    mount_namespace = os.readlink("/proc/self/ns/mnt")
    cgroup_rows = Path("/proc/self/cgroup").read_text().splitlines()
    cgroup = next(
        (
            row.partition("::")[2]
            for row in cgroup_rows
            if "::" in row and row.partition("::")[2].endswith(f"/{expected_unit}")
        ),
        "",
    )
    if (
        actual_user != expected_user
        or not re.fullmatch(r"[0-9a-f]{32}", invocation)
        or not cgroup
        or not re.fullmatch(r"[0-9a-fA-F-]{16,64}", boot_id)
        or not re.fullmatch(r"mnt:\[[1-9][0-9]*\]", mount_namespace)
    ):
        raise RuntimeError(
            "Canary producer 必须由 inventory 指定的 systemd unit/user 启动"
        )
    return {
        "unix_user": actual_user,
        "uid": os.getuid(),
        "systemd_unit": expected_unit,
        "invocation_id": invocation,
        "cgroup": cgroup,
        "boot_id": boot_id,
        "mount_namespace_id": mount_namespace,
    }


def _credential_headers(mapping: object) -> dict[str, str]:
    if not isinstance(mapping, dict):
        raise ValueError("headers_from_credentials 必须是对象")
    credential_directory = Path(
        os.environ.get("CREDENTIALS_DIRECTORY", "/run/credentials")
    )
    headers: dict[str, str] = {}
    for header, credential_name in mapping.items():
        if (
            not re.fullmatch(r"[A-Za-z0-9-]{1,64}", str(header))
            or not re.fullmatch(
                r"[A-Za-z0-9_.-]{1,128}",
                str(credential_name),
            )
        ):
            raise ValueError("credential header/name 非法")
        raw = _secure_read(
            credential_directory / str(credential_name),
            label=f"systemd credential {credential_name}",
            maximum=16 * 1024,
            owner_only=True,
        )
        headers[str(header)] = raw.decode().strip()
    return headers


def _credential_value(name: object, *, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", str(name)):
        raise ValueError(f"{label} systemd credential name 非法")
    directory = Path(
        os.environ.get("CREDENTIALS_DIRECTORY", "/run/credentials")
    )
    value = _secure_read(
        directory / str(name),
        label=label,
        maximum=16 * 1024,
        owner_only=True,
    ).decode().strip()
    if not value:
        raise ValueError(f"{label} 不能为空")
    return value


def _okx_auth_headers(request: dict) -> tuple[dict[str, str], str, str]:
    credentials = request["okx_auth_credentials"]
    if set(credentials) != {"api_key", "secret_key", "passphrase"}:
        raise ValueError("OKX auth credential contract 非法")
    api_key = _credential_value(
        credentials["api_key"],
        label="OKX API key",
    )
    actual_fingerprint = credential_fingerprint(api_key)
    if actual_fingerprint != request["target_credential_fingerprint"]:
        raise ValueError("实际 OKX API key 与目标 credential fingerprint 不匹配")
    secret = _credential_value(
        credentials["secret_key"],
        label="OKX API secret",
    )
    passphrase = _credential_value(
        credentials["passphrase"],
        label="OKX API passphrase",
    )
    timestamp = datetime.now(UTC).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    parsed = urllib.parse.urlparse(str(request["source_uri"]))
    request_target = parsed.path + (
        f"?{parsed.query}" if parsed.query else ""
    )
    prehash = f"{timestamp}GET{request_target}".encode()
    signature = base64.b64encode(
        hmac.new(
            secret.encode(),
            prehash,
            hashlib.sha256,
        ).digest()
    ).decode("ascii")
    return (
        {
            "OK-ACCESS-KEY": api_key,
            "OK-ACCESS-SIGN": signature,
            "OK-ACCESS-TIMESTAMP": timestamp,
            "OK-ACCESS-PASSPHRASE": passphrase,
        },
        actual_fingerprint,
        timestamp,
    )


def _response_headers(response) -> dict[str, str]:
    return {
        str(key).lower(): str(value)
        for key, value in response.headers.items()
    }


def _collect_https(
    request: dict,
) -> tuple[bytes, dict[str, str], str, str]:
    parsed = urllib.parse.urlparse(str(request["source_uri"]))
    timeout = request["timeout_seconds"]
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or type(timeout) is not int
        or not 1 <= timeout <= 30
    ):
        raise ValueError("Canary HTTPS source URI/timeout 非法")
    if request["auth_mode"] == "okx-v5":
        headers, actual_fingerprint, auth_timestamp = (
            _okx_auth_headers(request)
        )
        if request["headers_from_credentials"]:
            raise ValueError("OKX v5 auth 禁止静态认证 headers")
    else:
        headers = _credential_headers(
            request["headers_from_credentials"]
        )
        actual_fingerprint = ""
        auth_timestamp = ""
    http_request = urllib.request.Request(
        request["source_uri"],
        method="GET",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(
            http_request,
            timeout=timeout,
        ) as response:
            if (
                response.status != 200
                or response.geturl() != request["source_uri"]
            ):
                raise ValueError(
                    "Canary external endpoint status/redirect 非法"
                )
            raw = response.read(MAX_RAW_BYTES + 1)
            response_headers = _response_headers(response)
    except urllib.error.URLError as exc:
        raise RuntimeError("Canary external endpoint 获取失败") from exc
    if not raw or len(raw) > MAX_RAW_BYTES:
        raise ValueError("Canary external response 大小非法")
    return raw, response_headers, actual_fingerprint, auth_timestamp


def _collect_s3_version(
    request: dict,
) -> tuple[bytes, dict[str, str]]:
    parsed = urllib.parse.urlparse(str(request["source_uri"]))
    query = urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True,
    )
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or query.get("versionId") != [request["source_version_id"]]
    ):
        raise ValueError("S3 exact-version URI 未绑定唯一 versionId")
    headers = _credential_headers(
        request["headers_from_credentials"]
    )
    http_request = urllib.request.Request(
        request["source_uri"],
        method="GET",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(
            http_request,
            timeout=request["timeout_seconds"],
        ) as response:
            if (
                response.status != 200
                or response.geturl() != request["source_uri"]
                or response.headers.get("x-amz-version-id")
                != request["source_version_id"]
            ):
                raise ValueError("S3 exact-version response/redirect 非法")
            raw = response.read(MAX_RAW_BYTES + 1)
            response_headers = _response_headers(response)
    except urllib.error.URLError as exc:
        raise RuntimeError("S3 exact-version readback 获取失败") from exc
    if not raw or len(raw) > MAX_RAW_BYTES:
        raise ValueError("S3 exact-version readback 大小非法")
    return raw, response_headers


def _collect_file(request: dict) -> tuple[bytes, os.stat_result, str]:
    parsed = urllib.parse.urlparse(str(request["source_uri"]))
    if (
        parsed.scheme != "file"
        or parsed.netloc
        or not Path(parsed.path).is_absolute()
        or request["headers_from_credentials"] != {}
        or request["auth_mode"] != "none"
        or request["okx_auth_credentials"] != {}
    ):
        raise ValueError("该 producer 不允许 file source")
    path = Path(urllib.parse.unquote(parsed.path))
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_size <= 0
        or info.st_size > MAX_RAW_BYTES
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError(
            "Canary file source 必须是 root-owned、有界、不可委托写入的普通文件"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        fd_target = os.readlink(f"/proc/self/fd/{descriptor}")
        if (
            opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
            or fd_target != str(path)
        ):
            raise ValueError("Canary file source open-fd identity 不匹配")
        chunks: list[bytes] = []
        remaining = MAX_RAW_BYTES + 1
        while remaining:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, remaining),
            )
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if not raw or len(raw) != opened.st_size:
            raise ValueError("Canary file source 短读或大小非法")
        return raw, opened, fd_target
    finally:
        os.close(descriptor)


def collect_source(
    *,
    inventory_path: Path,
    request_path: Path,
    collection_receipt_path: Path,
    now: int | None = None,
) -> dict:
    """Collect exact producer bytes and atomically publish a provenance receipt."""
    inventory = validate_canary_source_producer_inventory(
        _load_json(inventory_path, label="Canary producer inventory")
    )
    request = _load_json(
        request_path,
        label="Canary collector request",
    )
    if (
        set(request) != _REQUEST_KEYS
        or request["version"] != 1
        or request["producer_name"] not in inventory
        or request["adapter"] not in {
            "file",
            "https",
            "s3-version",
        }
        or not isinstance(request["source_version_id"], str)
        or not request["source_version_id"].strip()
        or not isinstance(request["headers_from_credentials"], dict)
        or not isinstance(request["okx_auth_credentials"], dict)
        or request["auth_mode"] not in {"none", "static", "okx-v5"}
        or not isinstance(request["required_response_headers"], dict)
        or not isinstance(
            request["secondary_required_response_headers"],
            dict,
        )
        or any(
            not isinstance(key, str)
            or key != key.lower()
            or not isinstance(value, str)
            for key, value in request[
                "required_response_headers"
            ].items()
        )
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(request["target_credential_fingerprint"]),
        )
        or type(request["timeout_seconds"]) is not int
        or not 1 <= request["timeout_seconds"] <= 30
    ):
        raise ValueError("Canary collector request schema 非法")
    name = request["producer_name"]
    item = inventory[name]
    authority = item["source_authority"]
    request_sha256 = hashlib.sha256(
        _canonical(request)
    ).hexdigest()
    if request_sha256 != item["source_request_sha256"]:
        raise ValueError(
            f"Canary producer {name} request 未绑定 epoch inventory"
        )
    if request["adapter"] not in CANARY_PRODUCER_ADAPTERS[name]:
        raise ValueError(
            f"Canary producer {name} 不允许 adapter "
            f"{request['adapter']}"
        )
    if (
        request["method"]
        != ("READ" if request["adapter"] == "file" else "GET")
        or (
            request["adapter"] == "s3-version"
            and (
                not {
                    "x-amz-version-id",
                    "x-amz-server-side-encryption",
                    "x-amz-server-side-encryption-aws-kms-key-id",
                    "x-amz-object-lock-mode",
                    "x-amz-object-lock-retain-until-date",
                }.issubset(request["required_response_headers"])
                or not request["source_object_uri"].startswith("s3://")
                or not request[
                    "secondary_source_object_uri"
                ].startswith("s3://")
            )
        )
        or (
            request["adapter"] != "s3-version"
            and (
                request["source_object_uri"] != ""
                or request["secondary_source_object_uri"] != ""
            )
        )
        or (
            authority in TARGET_CREDENTIAL_AUTHORITIES
            and request["auth_mode"] != "okx-v5"
        )
        or (
            authority not in TARGET_CREDENTIAL_AUTHORITIES
            and request["auth_mode"] == "okx-v5"
        )
    ):
        raise ValueError(
            f"Canary producer {name} method/WORM header contract 非法"
        )
    source_info = None
    fd_target = ""
    requested_at = int(time.time() if now is None else now)
    if request["adapter"] == "file":
        raw, source_info, fd_target = _collect_file(request)
        response_headers: dict[str, str] = {}
        response_status = 0
        actual_target_fingerprint = ""
        request_auth_timestamp = ""
    elif request["adapter"] == "https":
        (
            raw,
            response_headers,
            actual_target_fingerprint,
            request_auth_timestamp,
        ) = _collect_https(request)
        response_status = 200
    else:
        archive, response_headers = _collect_s3_version(request)
        secondary_request = {
            **request,
            "source_uri": request["secondary_source_uri"],
            "source_version_id": request[
                "secondary_source_version_id"
            ],
            "required_response_headers": request[
                "secondary_required_response_headers"
            ],
        }
        manifest, secondary_response_headers = _collect_s3_version(
            secondary_request
        )
        manifest_value = json.loads(manifest)
        if (
            not isinstance(manifest_value, dict)
            or set(manifest_value)
            != {
                "archive_request_uri",
                "archive_object_uri",
                "archive_version_id",
                "archive_sha256",
                "archive_bytes",
                "manifest_request_uri",
                "manifest_object_uri",
                "manifest_version_id",
                "backup_completed_at",
            }
            or manifest_value["archive_request_uri"]
            != request["source_uri"]
            or manifest_value["archive_object_uri"]
            != request["source_object_uri"]
            or manifest_value["archive_version_id"]
            != request["source_version_id"]
            or manifest_value["archive_sha256"]
            != hashlib.sha256(archive).hexdigest()
            or manifest_value["archive_bytes"] != len(archive)
            or manifest_value["manifest_request_uri"]
            != request["secondary_source_uri"]
            or manifest_value["manifest_object_uri"]
            != request["secondary_source_object_uri"]
            or manifest_value["manifest_version_id"]
            != request["secondary_source_version_id"]
        ):
            raise ValueError("backup archive/manifest exact GET binding 非法")
        received_at = int(time.time() if now is None else now)
        raw = _canonical(
            {
                "archive_get": {
                    "request_uri": request["source_uri"],
                    "version_id": request["source_version_id"],
                    "response_headers": response_headers,
                    "payload_sha256": hashlib.sha256(archive).hexdigest(),
                    "payload_bytes": len(archive),
                    "payload_base64": base64.b64encode(archive).decode(),
                },
                "manifest_get": {
                    "request_uri": request["secondary_source_uri"],
                    "version_id": request[
                        "secondary_source_version_id"
                    ],
                    "response_headers": secondary_response_headers,
                    "payload_sha256": hashlib.sha256(manifest).hexdigest(),
                    "payload_bytes": len(manifest),
                    "payload_base64": base64.b64encode(manifest).decode(),
                },
                "restore_requested_at": int(
                    time.time() if now is None else now
                ),
            }
        )
        response_status = 200
        actual_target_fingerprint = ""
        request_auth_timestamp = ""
    if request["adapter"] != "s3-version":
        secondary_response_headers = {}
    if request["required_response_headers"] != {
        key: response_headers.get(key)
        for key in request["required_response_headers"]
    }:
        raise ValueError("Canary response headers 未满足冻结 request")
    received_at = int(time.time() if now is None else now)
    # Parsing is mandatory before publication. It proves schema and exact-byte
    # recomputability, but never turns an invalid external fact into success.
    if name in _PRE_START_EVIDENCE_KINDS:
        if name in {
            "account_uid_verified",
            "api_key_read_trade_only",
            "api_key_withdraw_disabled",
            "ip_allowlist_verified",
        }:
            json.loads(raw)
    else:
        json.loads(raw)
    execution = _current_execution(
        item["collector_unix_user"],
        item["collector_systemd_unit"],
    )
    collected_at = int(time.time() if now is None else now)
    raw_path = Path(item["raw_source_path"])
    _atomic_replace(raw_path, raw, mode=0o640)
    receipt = {
        "version": 1,
        "action": "collect-canary-native-source",
        "producer_name": name,
        "source_authority": authority,
        "source_request_sha256": request_sha256,
        "collector_request": request,
        "adapter": request["adapter"],
        "source_uri": request["source_uri"],
        "source_version_id": request["source_version_id"],
        "request_method": request["method"],
        "request_auth_timestamp": request_auth_timestamp,
        "actual_target_credential_fingerprint": (
            actual_target_fingerprint
        ),
        "requested_at": requested_at,
        "response_status": response_status,
        "response_headers": response_headers,
        "received_at": received_at,
        "secondary_source_uri": request["secondary_source_uri"],
        "secondary_source_version_id": request[
            "secondary_source_version_id"
        ],
        "secondary_response_status": (
            200 if request["adapter"] == "s3-version" else 0
        ),
        "secondary_response_headers": secondary_response_headers,
        "secondary_received_at": (
            received_at if request["adapter"] == "s3-version" else 0
        ),
        "source_device": (
            source_info.st_dev if source_info is not None else 0
        ),
        "source_inode": (
            source_info.st_ino if source_info is not None else 0
        ),
        "source_mode": (
            source_info.st_mode if source_info is not None else 0
        ),
        "source_uid": (
            source_info.st_uid if source_info is not None else 0
        ),
        "source_mount_id": (
            f"{os.major(source_info.st_dev)}:"
            f"{os.minor(source_info.st_dev)}"
            if source_info is not None
            else ""
        ),
        "proc_fd_target": fd_target,
        "raw_path": str(raw_path),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes": len(raw),
        "collected_at": collected_at,
        "collector_unix_user": execution["unix_user"],
        "collector_uid": execution["uid"],
        "collector_systemd_unit": execution["systemd_unit"],
        "collector_invocation_id": execution["invocation_id"],
        "collector_cgroup": execution["cgroup"],
        "boot_id": execution["boot_id"],
        "mount_namespace_id": execution["mount_namespace_id"],
    }
    _atomic_replace(
        collection_receipt_path,
        _canonical(receipt) + b"\n",
        mode=0o640,
    )
    validate_collection_receipt(
        receipt,
        producer_name=name,
        inventory=inventory,
        raw=raw,
        target_key_fingerprint=request[
            "target_credential_fingerprint"
        ],
        now=collected_at,
    )
    return receipt


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(
        _secure_read(
            path,
            label=f"executable/parser {path}",
            maximum=MAX_RAW_BYTES,
        )
    ).hexdigest()


def sign_source(
    *,
    inventory_path: Path,
    context_path: Path,
    collection_receipt_path: Path,
    iam_sts_receipt_path: Path,
    iam_receipt_output_path: Path | None = None,
    private_key_path: Path,
    collector_executable_path: Path,
    signer_executable_path: Path,
    parser_path: Path,
    host_image_sha256_path: Path,
    output_path: Path,
    now: int | None = None,
) -> dict:
    """Recompute one fact and sign it from the isolated signer identity."""
    current = int(time.time() if now is None else now)
    inventory = validate_canary_source_producer_inventory(
        _load_json(inventory_path, label="Canary producer inventory")
    )
    context = _load_json(context_path, label="Canary signing context")
    if (
        set(context) != _CONTEXT_KEYS
        or context["version"] != 1
        or context["phase"]
        not in {"pre-start", "post-start", "capability"}
        or context["producer_name"] not in inventory
    ):
        raise ValueError("Canary signing context schema 非法")
    name = context["producer_name"]
    item = inventory[name]
    raw_path = Path(item["raw_source_path"])
    raw_info = raw_path.lstat()
    raw = _secure_read(
        raw_path,
        label="Canary collected raw",
        maximum=MAX_RAW_BYTES,
    )
    signer = _current_execution(
        item["signer_unix_user"],
        item["signer_systemd_unit"],
    )
    if (
        raw_info.st_uid == signer["uid"]
        or raw_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("Canary signer 不得拥有或可写 raw source")
    target = validate_target_deployment_identity(
        context["target_deployment_identity"]
    )
    receipt = validate_collection_receipt(
        _load_json(
            collection_receipt_path,
            label="Canary collection receipt",
        ),
        producer_name=name,
        inventory=inventory,
        raw=raw,
        target_key_fingerprint=target["key_fingerprint"],
        now=current,
    )
    if signer["boot_id"] != receipt["boot_id"]:
        raise ValueError("Canary collector/signer 不在同一 host boot")
    private_key = _secure_read(
        private_key_path,
        label="Canary source private key",
        maximum=64 * 1024,
        owner_only=True,
    )
    del private_key
    source_fingerprint = ed25519_public_key_fingerprint(
        private_key_path,
        private_key=True,
    )
    if source_fingerprint != item["source_key_fingerprint"]:
        raise ValueError("Canary source private key 与 inventory 不匹配")
    iam_raw = _secure_read(
        iam_sts_receipt_path,
        label="Canary IAM/STS receipt",
        maximum=MAX_CONTROL_BYTES,
    )
    host_image_sha256 = (
        _secure_read(
            host_image_sha256_path,
            label="host image SHA",
            maximum=256,
        )
        .decode()
        .strip()
    )
    readiness = canary_readiness_id(
        demo_soak_epoch_id=context["demo_soak_epoch_id"],
        target_deployment_identity_sha256=identity_sha256(target),
        source_producer_inventory_sha256=(
            canary_source_producer_inventory_sha256(inventory)
        ),
    )
    execution = {
        "version": 1,
        "producer_name": name,
        "readiness_id": readiness,
        "inventory_sha256": (
            canary_source_producer_inventory_sha256(inventory)
        ),
        "source_key_fingerprint": source_fingerprint,
        "collector_unix_user": receipt["collector_unix_user"],
        "collector_uid": receipt["collector_uid"],
        "collector_systemd_unit": receipt["collector_systemd_unit"],
        "collector_invocation_id": receipt["collector_invocation_id"],
        "collector_cgroup": receipt["collector_cgroup"],
        "signer_unix_user": signer["unix_user"],
        "signer_uid": signer["uid"],
        "signer_systemd_unit": signer["systemd_unit"],
        "signer_invocation_id": signer["invocation_id"],
        "signer_cgroup": signer["cgroup"],
        "boot_id": signer["boot_id"],
        "host_image_sha256": host_image_sha256,
        "collector_mount_namespace_id": receipt[
            "mount_namespace_id"
        ],
        "signer_mount_namespace_id": signer["mount_namespace_id"],
        "iam_principal": item["iam_principal"],
        "iam_sts_receipt_sha256": hashlib.sha256(iam_raw).hexdigest(),
        "collector_executable_sha256": _file_sha256(
            collector_executable_path
        ),
        "signer_executable_sha256": _file_sha256(
            signer_executable_path
        ),
        "parser_sha256": _file_sha256(parser_path),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes": len(raw),
        "collected_at": receipt["collected_at"],
        "signed_at": current,
        "nonce": uuid.uuid4().hex,
    }
    if context["phase"] == "capability":
        expires_at = context["capability_expires_at"]
        pre_start_artifact_sha256 = context[
            "pre_start_source_artifact_sha256"
        ]
        if (
            type(expires_at) is not int
            or not 60 <= expires_at - current <= 300
            or (
                name in _PRE_START_EVIDENCE_KINDS
                and not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(pre_start_artifact_sha256),
                )
            )
            or (
                name in _POST_START_EVIDENCE_KINDS
                and pre_start_artifact_sha256 != ""
            )
        ):
            raise ValueError("Canary capability expiry/pre-start hash 非法")
        claims = {
            "version": 1,
            "action": "attest-canary-external-producer-ready",
            "producer_name": name,
            "observed_at": current,
            "expires_at": expires_at,
            "release_identity_sha256": identity_sha256(
                context["release_identity"]
            ),
            "config_sha256": target["config_sha256"],
            "account_uid": target["account_uid"],
            "demo_soak_epoch_id": context["demo_soak_epoch_id"],
            "target_deployment_identity_sha256": identity_sha256(target),
            "transition_sha256": context["transition_sha256"],
            "source_producer_inventory_sha256": (
                canary_source_producer_inventory_sha256(inventory)
            ),
            "readiness_id": readiness,
            "producer_execution": execution,
            "collection_receipt": receipt,
            "capability_probe_bytes_base64": base64.b64encode(
                raw
            ).decode("ascii"),
            "capability_probe_sha256": hashlib.sha256(raw).hexdigest(),
            "pre_start_source_artifact_sha256": (
                pre_start_artifact_sha256
            ),
        }
    elif context["phase"] == "pre-start":
        if name not in _PRE_START_EVIDENCE_KINDS:
            raise ValueError("post-start producer 不能签发 pre-start source")
        evidence = build_source_evidence(
            _PRE_START_EVIDENCE_KINDS[name],
            raw,
        )
        facts = derive_pre_start_facts(
            name,
            evidence,
            target=target,
            release_identity=context["release_identity"],
        )
        observed_at = pre_start_evidence_observed_at(
            name,
            evidence,
            fallback=current,
            target_key_fingerprint=target["key_fingerprint"],
            collection_receipt=receipt,
        )
        claims = {
            "version": 1,
            "action": "attest-canary-pre-start-source",
            "check": name,
            "observed_at": observed_at,
            "account_uid": target["account_uid"],
            "deployment_unit": target["unit"],
            "demo_soak_epoch_id": context["demo_soak_epoch_id"],
            "release_identity_sha256": identity_sha256(
                context["release_identity"]
            ),
            "release_commit": target["release_commit"],
            "deployed_source_sha256": target["deployed_source_sha256"],
            "config_sha256": target["config_sha256"],
            "target_deployment_identity_sha256": identity_sha256(target),
            "pre_start_challenge": context["pre_start_challenge"],
            "producer_execution": execution,
            "collection_receipt": receipt,
            "source_evidence": evidence,
            "facts": facts,
        }
        validate_pre_start_source_claims(
            claims,
            check=name,
            target=target,
            release_identity=context["release_identity"],
            demo_soak_epoch_id=context["demo_soak_epoch_id"],
            producer_inventory=inventory,
            pre_start_challenge=context["pre_start_challenge"],
            now=current,
        )
    else:
        if name not in _POST_START_EVIDENCE_KINDS:
            raise ValueError("pre-start producer 不能签发 post-start source")
        evidence_raw = raw
        if name != "runtime_safety_kernel_live_within_60s":
            evidence_raw = _canonical(
                {
                    "runtime_binding": {
                        "runtime_instance_id": context[
                            "runtime_instance_id"
                        ],
                        "boot_id": context["boot_id"],
                        "deployment_unit": target["unit"],
                        "startup_nonce": context["startup_nonce"],
                        "startup_hard_epoch": context[
                            "expected_startup_hard_epoch"
                        ],
                    },
                    "native_payload_base64": base64.b64encode(raw).decode(),
                    "native_sha256": hashlib.sha256(raw).hexdigest(),
                    "native_bytes": len(raw),
                }
            )
        evidence = build_source_evidence(
            _POST_START_EVIDENCE_KINDS[name],
            evidence_raw,
        )
        claims = {
            "version": 1,
            "action": "attest-canary-post-start-source",
            "check": name,
            "observed_at": current,
            "runtime_instance_id": context["runtime_instance_id"],
            "boot_id": context["boot_id"],
            "account_uid": target["account_uid"],
            "deployment_unit": target["unit"],
            "demo_soak_epoch_id": context["demo_soak_epoch_id"],
            "transition_sha256": context["transition_sha256"],
            "policy_sha256": context["policy_sha256"],
            "target_deployment_identity_sha256": identity_sha256(target),
            "startup_nonce": context["startup_nonce"],
            "expected_startup_hard_epoch": context[
                "expected_startup_hard_epoch"
            ],
            "producer_execution": execution,
            "collection_receipt": receipt,
            "source_evidence": evidence,
            "facts": derive_post_start_facts(name, evidence),
        }
        validate_post_start_source_claims(
            claims,
            check=name,
            runtime_instance_id=context["runtime_instance_id"],
            boot_id=context["boot_id"],
            account_uid=target["account_uid"],
            deployment_unit=target["unit"],
            demo_soak_epoch_id=context["demo_soak_epoch_id"],
            transition_sha256=context["transition_sha256"],
            policy_sha256=context["policy_sha256"],
            target_deployment_identity_sha256=identity_sha256(target),
            startup_nonce=context["startup_nonce"],
            expected_startup_hard_epoch=context[
                "expected_startup_hard_epoch"
            ],
            producer_inventory=inventory,
            target_key_fingerprint=target["key_fingerprint"],
            now=current,
        )
    artifact = sign_ed25519_payload(claims, private_key_path)
    if iam_receipt_output_path is not None:
        _atomic_replace(
            iam_receipt_output_path,
            iam_raw,
            mode=0o640,
        )
    _atomic_replace(
        output_path,
        _canonical(artifact) + b"\n",
        mode=0o640,
    )
    return artifact


def default_collection_receipt(raw_path: Path) -> Path:
    return raw_path.with_name(f"{raw_path.name}.collection.json")
