#!/usr/bin/env python3
"""独立复验 Demo contract v2、detached signature 和 exact S3 versions。"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

from okx_quant.infrastructure.evidence import (
    sha256_bytes,
    validate_demo_contract_evidence,
    verify_component_bytes,
    verify_signed_demo_contract_manifest,
)


def _read_regular(path: Path, label: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} 必须是非符号链接普通文件")
    return path.read_bytes()


def _s3_identity(uri: str) -> tuple[str, str]:
    parsed = urlparse(uri)
    if (
        parsed.scheme != "s3"
        or not parsed.netloc
        or not parsed.path.strip("/")
    ):
        raise ValueError("immutable object URI 必须是 s3://bucket/key")
    return parsed.netloc, unquote(parsed.path.lstrip("/"))


def _aws_json(args: list[str]) -> dict:
    result = subprocess.run(
        ["aws", *args, "--output", "json", "--no-cli-pager"],
        capture_output=True,
        check=False,
        timeout=60,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"AWS exact-version 查询失败: {result.stderr.strip()}")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("AWS 返回非对象 JSON")
    return value


def exact_version_get(
    component: dict,
    *,
    retain_until: str,
    expected_kms_key_id: str,
) -> bytes:
    """使用调用者自身只读凭据检查并下载一个 exact version。"""
    bucket, key = _s3_identity(component["object_uri"])
    version_id = component["version_id"]
    head = _aws_json([
        "s3api",
        "head-object",
        "--bucket",
        bucket,
        "--key",
        key,
        "--version-id",
        version_id,
    ])
    if (
        str(head.get("VersionId", "")) != version_id
        or head.get("ObjectLockMode") != "COMPLIANCE"
    ):
        raise ValueError("对象 version identity 或 Object Lock mode 不匹配")
    if (
        head.get("ServerSideEncryption") != "aws:kms"
        or str(head.get("SSEKMSKeyId", "")) != expected_kms_key_id
    ):
        raise ValueError("对象未使用 signed manifest 指定的 KMS key")
    expected_retention = datetime.fromisoformat(retain_until).astimezone(UTC)
    actual_retention = datetime.fromisoformat(
        str(head.get("ObjectLockRetainUntilDate", ""))
    ).astimezone(UTC)
    if actual_retention < expected_retention:
        raise ValueError("对象 retention 短于 signed manifest")
    if int(head.get("ContentLength", -1)) != component["bytes"]:
        raise ValueError("对象 ContentLength 不匹配")
    with tempfile.TemporaryDirectory() as temporary:
        destination = Path(temporary) / "component.bin"
        result = subprocess.run(
            [
                "aws",
                "s3api",
                "get-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--version-id",
                version_id,
                str(destination),
                "--no-cli-pager",
            ],
            capture_output=True,
            check=False,
            timeout=120,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"AWS exact-version GET 失败: {result.stderr.strip()}"
            )
        response = json.loads(result.stdout or "{}")
        if response.get("VersionId") != version_id:
            raise ValueError("GET 响应未绑定请求的 exact version")
        payload = destination.read_bytes()
    verify_component_bytes(component, payload)
    return payload


def verify_contract_bundle(
    *,
    artifact: object,
    public_key: Path,
    evidence_bytes: bytes,
    fixture_bytes: bytes,
    expected_commit: str = "",
    expected_config_sha256: str = "",
    expected_account_uid: str = "",
) -> dict:
    payload = verify_signed_demo_contract_manifest(artifact, public_key)
    components = payload["components"]
    verify_component_bytes(components["evidence"], evidence_bytes)
    verify_component_bytes(components["fixture"], fixture_bytes)
    evidence = json.loads(evidence_bytes)
    validate_demo_contract_evidence(
        evidence,
        fixture_bytes=fixture_bytes,
    )
    if evidence["contract_run_id"] != payload["contract_run_id"]:
        raise ValueError("evidence 与 manifest contract_run_id 不匹配")
    for identity_name in ("release_identity", "deployment_identity"):
        if evidence[identity_name] != payload[identity_name]:
            raise ValueError(f"evidence 与 manifest {identity_name} 不匹配")
    release = payload["release_identity"]
    deployment = payload["deployment_identity"]
    if release["workspace_clean"] is not True:
        raise ValueError("发布级 contract 必须来自干净工作树")
    expected = {
        "git_commit": expected_commit.lower(),
        "config_sha256": expected_config_sha256.lower(),
        "account_uid": expected_account_uid,
    }
    actual = {
        "git_commit": release["git_commit"],
        "config_sha256": deployment["config_sha256"],
        "account_uid": deployment["account_uid"],
    }
    for key, value in expected.items():
        if value and actual[key] != value:
            raise ValueError(f"Demo contract 未绑定预期 {key}")
    return {
        "verified": True,
        "immutable_verified": True,
        "contract_run_id": payload["contract_run_id"],
        "git_commit": release["git_commit"],
        "config_sha256": deployment["config_sha256"],
        "account_uid": deployment["account_uid"],
        "evidence_sha256": sha256_bytes(evidence_bytes),
        "fixture_sha256": sha256_bytes(fixture_bytes),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--expected-commit", default="")
    parser.add_argument("--expected-config-sha256", default="")
    parser.add_argument("--expected-account-uid", default="")
    args = parser.parse_args()
    if not args.offline and not all(
        (
            args.expected_commit,
            args.expected_config_sha256,
            args.expected_account_uid,
        )
    ):
        raise SystemExit(
            "immutable verifier 必须同时提供 --expected-commit、"
            "--expected-config-sha256 和 --expected-account-uid"
        )
    artifact = json.loads(
        _read_regular(args.manifest, "signed manifest").decode()
    )
    payload = verify_signed_demo_contract_manifest(
        artifact,
        args.public_key,
    )
    if args.offline:
        if args.evidence is None or args.fixture is None:
            raise SystemExit("--offline 必须同时提供 --evidence 和 --fixture")
        evidence_bytes = _read_regular(args.evidence, "evidence")
        fixture_bytes = _read_regular(args.fixture, "fixture")
    else:
        evidence_bytes = exact_version_get(
            payload["components"]["evidence"],
            retain_until=payload["retention"]["retain_until"],
            expected_kms_key_id=payload["kms_key_id"],
        )
        fixture_bytes = exact_version_get(
            payload["components"]["fixture"],
            retain_until=payload["retention"]["retain_until"],
            expected_kms_key_id=payload["kms_key_id"],
        )
    result = verify_contract_bundle(
        artifact=artifact,
        public_key=args.public_key,
        evidence_bytes=evidence_bytes,
        fixture_bytes=fixture_bytes,
        expected_commit=args.expected_commit,
        expected_config_sha256=args.expected_config_sha256,
        expected_account_uid=args.expected_account_uid,
    )
    result["immutable_verified"] = not args.offline
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
