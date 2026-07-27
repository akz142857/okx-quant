#!/usr/bin/env python3
"""由独立风险审批人离线签署生产准入根请求。"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from okx_quant.application.approval import canonical_bytes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--approver", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        not args.request.is_file()
        or args.request.is_symlink()
        or not args.private_key.is_file()
        or args.private_key.is_symlink()
    ):
        raise SystemExit("request/private-key 必须是既有普通文件且不能是符号链接")
    if args.private_key.stat().st_mode & 0o077:
        raise SystemExit("风险审批私钥权限过宽；必须仅 owner 可读写")
    claims = json.loads(args.request.read_text(encoding="utf-8"))
    if (
        not isinstance(claims, dict)
        or claims.get("action") != "admit-production"
        or claims.get("risk_approver") != ""
    ):
        raise SystemExit("request 不是未签名生产准入请求")
    approver = args.approver.strip()
    operator = str(claims.get("operator", "")).strip()
    if not approver or approver == operator:
        raise SystemExit("approver 必须与 operator 不同且不能为空")
    claims["risk_approver"] = approver
    with tempfile.NamedTemporaryFile() as message_file:
        message_file.write(canonical_bytes(claims))
        message_file.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(args.private_key),
                "-in",
                message_file.name,
            ],
            capture_output=True,
            timeout=5,
            check=False,
        )
    if result.returncode != 0 or len(result.stdout) != 64:
        sys.stderr.buffer.write(result.stderr)
        raise SystemExit("Ed25519 签名失败")
    if args.output.exists():
        raise SystemExit(f"拒绝覆盖既有批准文件: {args.output}")
    artifact = {
        "payload": claims,
        "signature": base64.b64encode(result.stdout).decode("ascii"),
    }
    args.output.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
