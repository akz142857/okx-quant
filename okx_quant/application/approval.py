"""短效、一次性、Ed25519 签名的恢复交易批准凭证。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict
from pathlib import Path

from okx_quant.config import ProductionSettings

_COMMAND_ID = re.compile(r"[0-9a-f]{32}")
_HASH = re.compile(r"[0-9a-f]{64}")
_CLAIM_KEYS = {
    "version",
    "action",
    "command_id",
    "account_id",
    "config_hash",
    "confirmation",
    "actor",
    "risk_approver",
    "instruments",
    "issued_at",
    "expires_at",
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def production_config_hash(settings: ProductionSettings, cfg: dict) -> str:
    """绑定所有生产设置和非秘密 OKX 端点/模式，不把密钥写入批准文件。"""
    material = {
        "production": {
            key: str(value) if hasattr(value, "as_tuple") else value
            for key, value in asdict(settings).items()
        },
        "okx": {
            "base_url": cfg.get("okx", {}).get("base_url"),
            "simulated": cfg.get("okx", {}).get("simulated"),
        },
    }
    return hashlib.sha256(canonical_bytes(material)).hexdigest()


def verify_ed25519_artifact(
    artifact: object,
    public_key_path: str | Path,
    *,
    label: str,
) -> dict:
    """验证严格二字段签名制品，并拒绝可被同 UID 篡改的生产公钥。"""
    if not isinstance(artifact, dict) or set(artifact) != {
        "payload",
        "signature",
    }:
        raise ValueError(f"{label}文件结构非法")
    claims = artifact["payload"]
    if not isinstance(claims, dict):
        raise ValueError(f"{label} payload 必须是对象")
    key = Path(public_key_path)
    try:
        key_stat = key.lstat()
    except OSError as exc:
        raise ValueError(f"{label}公钥不存在") from exc
    if (
        not stat.S_ISREG(key_stat.st_mode)
        or stat.S_ISLNK(key_stat.st_mode)
        or key_stat.st_size <= 0
        or key_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError(
            f"{label}公钥必须是非空普通文件且不能由 group/other 写入"
        )
    production_root = Path("/etc/okx-quant")
    try:
        in_production_root = key.is_relative_to(production_root)
    except ValueError:
        in_production_root = False
    if in_production_root:
        if key_stat.st_uid != 0:
            raise ValueError(f"{label}生产公钥必须由 root 持有")
        candidate = key.parent
        while True:
            try:
                candidate_stat = candidate.lstat()
            except OSError as exc:
                raise ValueError(f"{label}公钥目录链不可验证") from exc
            if (
                candidate_stat.st_uid != 0
                or stat.S_ISLNK(candidate_stat.st_mode)
                or candidate_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise ValueError(
                    f"{label}生产公钥及目录必须 root-owned 且不可被非 root 写入"
                )
            if candidate == production_root:
                break
            if production_root not in candidate.parents:
                raise ValueError(f"{label}公钥不在受控生产目录内")
            candidate = candidate.parent
    encoded_signature = artifact["signature"]
    if not isinstance(encoded_signature, str):
        raise ValueError(f"{label}签名必须是 base64 字符串")
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label}签名不是合法 base64") from exc
    if len(signature) != 64:
        raise ValueError(f"{label}必须使用 Ed25519 签名")
    with (
        tempfile.NamedTemporaryFile() as message_file,
        tempfile.NamedTemporaryFile() as signature_file,
    ):
        message_file.write(canonical_bytes(claims))
        message_file.flush()
        signature_file.write(signature)
        signature_file.flush()
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
        }
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(key),
                    "-in",
                    message_file.name,
                    "-sigfile",
                    signature_file.name,
                ],
                capture_output=True,
                timeout=5,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(f"无法执行{label}签名验证") from exc
    if result.returncode != 0:
        raise ValueError(f"{label}签名验证失败")
    return dict(claims)


def build_resume_request(
    settings: ProductionSettings,
    cfg: dict,
    *,
    actor: str,
    lifetime_s: int = 300,
    now: int | None = None,
) -> dict:
    return build_control_request(
        settings,
        cfg,
        action="resume-entries",
        actor=actor,
        lifetime_s=lifetime_s,
        now=now,
    )


def build_control_request(
    settings: ProductionSettings,
    cfg: dict,
    *,
    action: str,
    actor: str,
    instruments: list[str] | tuple[str, ...] = (),
    lifetime_s: int = 300,
    now: int | None = None,
) -> dict:
    if action not in {"resume-entries", "flatten-and-cancel"}:
        raise ValueError("不支持的批准 action")
    if not actor.strip():
        raise ValueError("actor 不能为空")
    if type(lifetime_s) is not int or not 30 <= lifetime_s <= 600:
        raise ValueError("批准有效期必须是 30..600 秒整数")
    issued_at = int(time.time() if now is None else now)
    normalized_instruments = sorted(set(instruments))
    if any(
        not isinstance(item, str)
        or not re.fullmatch(r"[A-Z0-9]{2,15}-[A-Z0-9]{2,15}", item)
        for item in normalized_instruments
    ):
        raise ValueError("instruments 包含非法交易对")
    if action == "resume-entries" and normalized_instruments:
        raise ValueError("resume-entries 不允许携带 instruments")
    account_id = settings.account_id or settings.environment
    verb = "RESUME" if action == "resume-entries" else "FLATTEN"
    return {
        "version": 1,
        "action": action,
        "command_id": uuid.uuid4().hex,
        "account_id": account_id,
        "config_hash": production_config_hash(settings, cfg),
        "confirmation": f"{verb} {account_id}",
        "actor": actor.strip(),
        "risk_approver": "",
        "instruments": normalized_instruments,
        "issued_at": issued_at,
        "expires_at": issued_at + lifetime_s,
    }


class ControlApprovalVerifier:
    """运行时只持有风险审批公钥，无法自行伪造第二人批准。"""

    def __init__(self, public_key_path: str | Path, *, clock=time.time):
        self.public_key_path = Path(public_key_path)
        self._clock = clock

    def verify(
        self,
        artifact: object,
        *,
        command_id: str,
        expected_account_id: str,
        expected_config_hash: str,
        expected_action: str = "resume-entries",
        expected_instruments: list[str] | tuple[str, ...] = (),
    ) -> dict:
        if not isinstance(artifact, dict) or set(artifact) != {
            "payload",
            "signature",
        }:
            raise ValueError("控制批准文件结构非法")
        claims = artifact["payload"]
        if not isinstance(claims, dict) or set(claims) != _CLAIM_KEYS:
            raise ValueError("控制批准 claims 不完整或包含未知字段")
        if claims["version"] != 1 or claims["action"] != expected_action:
            raise ValueError("控制批准版本或 action 非法")
        if not isinstance(claims["command_id"], str) or not _COMMAND_ID.fullmatch(
            claims["command_id"]
        ):
            raise ValueError("控制批准 command_id 非法")
        if claims["command_id"] != command_id:
            raise ValueError("控制批准未绑定当前控制命令")
        if claims["account_id"] != expected_account_id:
            raise ValueError("控制批准未绑定当前 OKX 账户")
        verb = "RESUME" if expected_action == "resume-entries" else "FLATTEN"
        if claims["confirmation"] != f"{verb} {expected_account_id}":
            raise ValueError("控制批准缺少精确账户确认文本")
        instruments = claims["instruments"]
        if (
            not isinstance(instruments, list)
            or instruments != sorted(set(expected_instruments))
            or any(not isinstance(item, str) for item in instruments)
        ):
            raise ValueError("控制批准未绑定当前交易对集合")
        if (
            not isinstance(claims["config_hash"], str)
            or not _HASH.fullmatch(claims["config_hash"])
            or claims["config_hash"] != expected_config_hash
        ):
            raise ValueError("控制批准未绑定当前生产配置")
        actor = claims["actor"]
        approver = claims["risk_approver"]
        if (
            not isinstance(actor, str)
            or not isinstance(approver, str)
            or not actor.strip()
            or not approver.strip()
            or actor == approver
        ):
            raise ValueError("控制批准必须包含两个不同身份")
        issued_at = claims["issued_at"]
        expires_at = claims["expires_at"]
        if (
            type(issued_at) is not int
            or type(expires_at) is not int
            or not 30 <= expires_at - issued_at <= 600
        ):
            raise ValueError("控制批准有效期非法")
        now = int(self._clock())
        if now < issued_at - 30 or now > expires_at:
            raise ValueError("控制批准尚未生效或已过期")
        self._verify_signature(claims, artifact["signature"])
        return dict(claims)

    def _verify_signature(self, claims: dict, encoded_signature: object) -> None:
        verify_ed25519_artifact(
            {
                "payload": claims,
                "signature": encoded_signature,
            },
            self.public_key_path,
            label="控制批准",
        )


# 向后兼容现有调用；验证器本身支持 resume 与 flatten 两种高风险 action。
ResumeApprovalVerifier = ControlApprovalVerifier
