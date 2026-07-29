#!/usr/bin/env python3
"""Perform and independently sign one exact-version WORM GET."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import pwd
import re
import stat
import time
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from okx_quant.application.approval import canonical_bytes
from okx_quant.infrastructure.evidence import (
    credential_fingerprint,
    sign_ed25519_payload,
)
from okx_quant.research.canary import (
    _canonical_worm_request_uri,
    canary_readiness_id,
    identity_sha256,
    verify_transition,
)
from okx_quant.research.demo_soak import (
    CANARY_SOURCE_PRODUCER_NAMES,
    canary_source_producer_inventory_sha256,
)

MAX_BYTES = 16 * 1024 * 1024


def _secure_bytes(path: Path, maximum: int = MAX_BYTES) -> bytes:
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_size <= 0
        or info.st_size > maximum
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError(f"不安全或超限文件: {path}")
    return path.read_bytes()


def _execution(expected_unit: str) -> dict:
    invocation = os.environ.get("INVOCATION_ID", "").lower()
    cgroup = next(
        (
            row.partition("::")[2]
            for row in Path("/proc/self/cgroup").read_text().splitlines()
            if "::" in row
            and row.partition("::")[2].endswith(f"/{expected_unit}")
        ),
        "",
    )
    mount_namespace = os.readlink("/proc/self/ns/mnt")
    if (
        not re.fullmatch(r"[0-9a-f]{32}", invocation)
        or not cgroup.startswith("/system.slice/")
        or not re.fullmatch(
            r"mnt:\[[1-9][0-9]*\]",
            mount_namespace,
        )
    ):
        raise RuntimeError("WORM verifier 必须由预期 systemd unit 启动")
    return {
        "verifier_unix_user": pwd.getpwuid(os.getuid()).pw_name,
        "verifier_uid": os.getuid(),
        "verifier_systemd_unit": expected_unit,
        "verifier_invocation_id": invocation,
        "verifier_cgroup": cgroup,
        "boot_id": Path(
            "/proc/sys/kernel/random/boot_id"
        ).read_text().strip(),
        "mount_namespace_id": mount_namespace,
    }


def _aws_sigv4_headers(
    *,
    request_uri: str,
    access_key_id: str,
    secret_access_key: str,
    session_token: str,
    region: str,
    timestamp: datetime,
    expected_access_key_fingerprint: str,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, str]:
    parsed = urllib.parse.urlparse(request_uri)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not re.fullmatch(r"[A-Z0-9]{16,128}", access_key_id)
        or not secret_access_key
        or not re.fullmatch(
            r"[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*",
            region,
        )
        or credential_fingerprint(access_key_id)
        != expected_access_key_fingerprint
    ):
        raise ValueError("WORM AWS SigV4 identity/region 非法")
    instant = timestamp.astimezone(UTC)
    amz_date = instant.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = instant.strftime("%Y%m%d")
    payload_sha256 = hashlib.sha256(b"").hexdigest()
    headers = {
        "host": parsed.netloc.lower(),
        "x-amz-content-sha256": payload_sha256,
        "x-amz-date": amz_date,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token
    for name, value in (extra_headers or {}).items():
        lowered = name.strip().lower()
        if (
            not re.fullmatch(r"[a-z0-9-]{1,64}", lowered)
            or lowered == "authorization"
        ):
            raise ValueError("WORM AWS SigV4 extra header 非法")
        headers[lowered] = value
    canonical_uri = urllib.parse.quote(
        urllib.parse.unquote(parsed.path or "/"),
        safe="/-_.~",
    )
    canonical_query = "&".join(
        f"{urllib.parse.quote(name, safe='-_.~')}="
        f"{urllib.parse.quote(value, safe='-_.~')}"
        for name, value in sorted(
            urllib.parse.parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
            )
        )
    )
    canonical_headers = "".join(
        f"{name}:{' '.join(value.strip().split())}\n"
        for name, value in sorted(headers.items())
    )
    signed_headers = ";".join(sorted(headers))
    canonical_request = "\n".join(
        (
            "GET",
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_sha256,
        )
    )
    scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        (
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        )
    )

    def sign(key: bytes, value: str) -> bytes:
        return hmac.new(key, value.encode(), hashlib.sha256).digest()

    signing_key = sign(
        sign(
            sign(
                sign(
                    f"AWS4{secret_access_key}".encode(),
                    date_stamp,
                ),
                region,
            ),
            "s3",
        ),
        "aws4_request",
    )
    signature = hmac.new(
        signing_key,
        string_to_sign.encode(),
        hashlib.sha256,
    ).hexdigest()
    result = {
        name: value
        for name, value in headers.items()
        if name != "host"
    }
    result["Authorization"] = (
        "AWS4-HMAC-SHA256 "
        f"Credential={access_key_id}/{scope},"
        f"SignedHeaders={signed_headers},"
        f"Signature={signature}"
    )
    return result


def _atomic_new(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"拒绝覆盖 WORM receipt: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o640,
    )
    try:
        try:
            raw = (
                json.dumps(value, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode()
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("WORM receipt write 无进展")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        # link(2) has create-if-absent semantics.  Unlike replace(2), it
        # cannot overwrite an output created after the initial pre-check.
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY,
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            directory_descriptor = os.open(
                path.parent,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--producer-name", required=True)
    parser.add_argument("--transition", required=True, type=Path)
    parser.add_argument("--operator-public-key", required=True, type=Path)
    parser.add_argument("--risk-public-key", required=True, type=Path)
    parser.add_argument("--readiness-artifact", required=True, type=Path)
    parser.add_argument("--object-uri", required=True)
    parser.add_argument("--request-uri", required=True)
    parser.add_argument("--version-id", required=True)
    parser.add_argument("--kms-key-id", required=True)
    parser.add_argument("--host-image-sha256", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.producer_name not in CANARY_SOURCE_PRODUCER_NAMES:
        raise ValueError("未知 Canary producer")
    transition = verify_transition(
        json.loads(_secure_bytes(args.transition)),
        operator_public_key=args.operator_public_key,
        risk_public_key=args.risk_public_key,
    )
    inventory = transition["source_producer_inventory"]
    index = sorted(CANARY_SOURCE_PRODUCER_NAMES).index(
        args.producer_name
    )
    execution = _execution(
        f"okx-quant-canary-worm-readback@{index:02d}.service"
    )
    expected = _secure_bytes(args.readiness_artifact)
    policy = inventory[args.producer_name]
    if (
        args.object_uri != policy["worm_object_uri"]
        or args.kms_key_id != policy["worm_kms_key_id"]
        or args.request_uri
        != _canonical_worm_request_uri(
            object_uri=policy["worm_object_uri"],
            request_origin=policy["worm_request_origin"],
            version_id=args.version_id,
        )
    ):
        raise ValueError("WORM exact GET 未绑定冻结 locator/KMS policy")
    credential_directory = Path(os.environ["CREDENTIALS_DIRECTORY"])
    access_key_id = _secure_bytes(
        credential_directory / "aws-access-key-id",
        16 * 1024,
    ).decode().strip()
    secret_access_key = _secure_bytes(
        credential_directory / "aws-secret-access-key",
        16 * 1024,
    ).decode().strip()
    session_token = _secure_bytes(
        credential_directory / "aws-session-token",
        64 * 1024,
    ).decode().strip()
    request_headers = _aws_sigv4_headers(
        request_uri=args.request_uri,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
        region=policy["worm_aws_region"],
        timestamp=datetime.now(tz=UTC),
        expected_access_key_fingerprint=policy[
            "worm_reader_access_key_fingerprint"
        ],
    )
    requested_at = int(time.time())
    request = urllib.request.Request(
        args.request_uri,
        method="GET",
        headers=request_headers,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if (
            response.status != 200
            or response.geturl() != args.request_uri
        ):
            raise ValueError("WORM GET status/redirect 非法")
        readback = response.read(MAX_BYTES + 1)
        selected_headers = {
            name: str(response.headers.get(name, ""))
            for name in (
                "x-amz-version-id",
                "x-amz-server-side-encryption",
                "x-amz-server-side-encryption-aws-kms-key-id",
                "x-amz-object-lock-mode",
                "x-amz-object-lock-retain-until-date",
            )
        }
    retrieved_at = int(time.time())
    try:
        retain_until = datetime.fromisoformat(
            selected_headers[
                "x-amz-object-lock-retain-until-date"
            ].replace("Z", "+00:00")
        )
    except (ValueError, AttributeError) as exc:
        raise ValueError("WORM Object Lock retain-until 非法") from exc
    if (
        readback != expected
        or selected_headers["x-amz-version-id"] != args.version_id
        or selected_headers["x-amz-server-side-encryption"] != "aws:kms"
        or selected_headers[
            "x-amz-server-side-encryption-aws-kms-key-id"
        ]
        != args.kms_key_id
        or selected_headers["x-amz-object-lock-mode"] != "COMPLIANCE"
        or retain_until.tzinfo is None
        or retain_until.astimezone(UTC)
        < datetime.fromtimestamp(retrieved_at, tz=UTC)
        + timedelta(days=35)
    ):
        raise ValueError("WORM exact GET bytes/KMS/ObjectLock 不匹配")
    target = transition["target_deployment_identity"]
    inventory_sha256 = canary_source_producer_inventory_sha256(
        inventory
    )
    claims = {
        "version": 1,
        "action": "attest-canary-worm-exact-get",
        "receipt_id": uuid.uuid4().hex,
        "producer_name": args.producer_name,
        "readiness_id": canary_readiness_id(
            demo_soak_epoch_id=transition["demo_soak_epoch_id"],
            target_deployment_identity_sha256=identity_sha256(target),
            source_producer_inventory_sha256=inventory_sha256,
        ),
        "demo_soak_epoch_id": transition["demo_soak_epoch_id"],
        "target_deployment_identity_sha256": identity_sha256(target),
        "transition_sha256": identity_sha256(transition),
        "requested_at": requested_at,
        "retrieved_at": retrieved_at,
        "request_method": "GET",
        "object_uri": args.object_uri,
        "request_uri": args.request_uri,
        "version_id": args.version_id,
        "expected_kms_key_id": args.kms_key_id,
        "aws_region": policy["worm_aws_region"],
        "reader_access_key_fingerprint": credential_fingerprint(
            access_key_id
        ),
        "request_header_names": sorted(
            name.lower() for name in request_headers
        ),
        "request_headers_sha256": hashlib.sha256(
            canonical_bytes(
                {
                    name.lower(): value
                    for name, value in request_headers.items()
                }
            )
        ).hexdigest(),
        "response_status": 200,
        "response_headers": selected_headers,
        "readback_sha256": hashlib.sha256(readback).hexdigest(),
        "readback_bytes": len(readback),
        "readback_bytes_base64": base64.b64encode(readback).decode(),
        **execution,
        "host_image_sha256": _secure_bytes(
            args.host_image_sha256,
            256,
        ).decode().strip(),
        "verifier_executable_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "nonce": uuid.uuid4().hex,
    }
    _secure_bytes(args.private_key, 64 * 1024)
    _atomic_new(
        args.output,
        sign_ed25519_payload(claims, args.private_key),
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
