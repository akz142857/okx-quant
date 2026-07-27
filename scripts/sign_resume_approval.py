#!/usr/bin/env python3
"""由独立风险审批人使用离线 Ed25519 私钥签署高风险控制请求。"""

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
    parser.add_argument("--request", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--approver", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    request_path = Path(args.request)
    key_path = Path(args.private_key)
    output_path = Path(args.output)
    if (
        not request_path.is_file()
        or request_path.is_symlink()
        or not key_path.is_file()
        or key_path.is_symlink()
    ):
        raise SystemExit("request/private-key 必须是既有普通文件且不能是符号链接")
    if key_path.stat().st_mode & 0o077:
        raise SystemExit("风险审批私钥权限过宽；必须仅 owner 可读写")
    claims = json.loads(request_path.read_text(encoding="utf-8"))
    if not isinstance(claims, dict) or claims.get("risk_approver") != "":
        raise SystemExit("request 不是未签名控制请求")
    actor = str(claims.get("actor", ""))
    approver = args.approver.strip()
    if not approver or approver == actor:
        raise SystemExit("approver 必须与 actor 不同且不能为空")
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
                str(key_path),
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
    artifact = {
        "payload": claims,
        "signature": base64.b64encode(result.stdout).decode("ascii"),
    }
    if output_path.exists():
        raise SystemExit(f"拒绝覆盖既有批准文件: {output_path}")
    output_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    output_path.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
