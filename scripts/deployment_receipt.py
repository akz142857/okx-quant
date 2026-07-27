"""Durable proof that an immutable production identity was activated in-window."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

from okx_quant.application.approval import verify_ed25519_artifact

_RECEIPT_KEYS = {
    "version",
    "action",
    "activated_at",
    "commit_sha",
    "config_hash",
    "account_id",
    "environment",
    "deployed_source_sha256",
    "evidence_sha256",
    "ledger_head_hash",
    "approval_sha256",
}
_APPROVAL_KEYS = {
    "version",
    "action",
    "evidence_sha256",
    "ledger_head_hash",
    "commit_sha",
    "config_hash",
    "account_id",
    "environment",
    "approved_max_slippage_ratio",
    "approved_max_stress_loss_usdt",
    "monitor_key_fingerprint",
    "operator",
    "risk_approver",
    "issued_at",
    "expires_at",
}


def build_deployment_receipt(
    *,
    identity: dict,
    approval_claims: dict,
    approval_bytes: bytes,
    evidence_sha256: str,
    ledger_head_hash: str,
    activated_at: int,
) -> dict:
    if not approval_claims["issued_at"] <= activated_at <= approval_claims["expires_at"]:
        raise ValueError("deployment receipt 激活时间不在批准窗口内")
    return {
        "version": 1,
        "action": "activate-immutable-production-release",
        "activated_at": activated_at,
        "commit_sha": identity["commit_sha"],
        "config_hash": identity["config_hash"],
        "account_id": identity["account_id"],
        "environment": identity["environment"],
        "deployed_source_sha256": identity["deployed_source_sha256"],
        "evidence_sha256": evidence_sha256,
        "ledger_head_hash": ledger_head_hash,
        "approval_sha256": hashlib.sha256(approval_bytes).hexdigest(),
    }


def _secure_receipt(path: Path) -> None:
    path_stat = path.lstat()
    if (
        not stat.S_ISREG(path_stat.st_mode)
        or path.is_symlink()
        or path_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("deployment receipt 必须是不可由 group/other 写入的普通文件")
    production_root = Path("/var/lib/okx-quant/admission")
    if path.is_relative_to(production_root):
        if path_stat.st_uid != 0:
            raise ValueError("生产 deployment receipt 必须由 root 持有")
        candidate = path.parent
        while True:
            candidate_stat = candidate.lstat()
            if (
                candidate_stat.st_uid != 0
                or stat.S_ISLNK(candidate_stat.st_mode)
                or candidate_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise ValueError("生产 deployment receipt 目录链不安全")
            if candidate == production_root:
                break
            candidate = candidate.parent


def validate_deployment_receipt(
    receipt_path: Path,
    *,
    identity: dict,
    approval_path: Path,
    approval_public_key: Path,
    evidence_path: Path,
) -> dict:
    _secure_receipt(receipt_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS:
        raise ValueError("deployment receipt 字段不完整或包含未知字段")
    if (
        receipt["version"] != 1
        or receipt["action"] != "activate-immutable-production-release"
    ):
        raise ValueError("deployment receipt 版本或 action 非法")
    approval_bytes = approval_path.read_bytes()
    approval = json.loads(approval_bytes)
    claims = verify_ed25519_artifact(
        approval,
        approval_public_key,
        label="生产准入批准",
    )
    if (
        set(claims) != _APPROVAL_KEYS
        or claims["version"] != 1
        or claims["action"] != "admit-production"
    ):
        raise ValueError("deployment receipt 引用的生产批准结构非法")
    evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    expected = {
        "commit_sha": identity["commit_sha"],
        "config_hash": identity["config_hash"],
        "account_id": identity["account_id"],
        "environment": identity["environment"],
        "deployed_source_sha256": identity["deployed_source_sha256"],
        "evidence_sha256": evidence_sha256,
        "ledger_head_hash": claims.get("ledger_head_hash"),
        "approval_sha256": hashlib.sha256(approval_bytes).hexdigest(),
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError(f"deployment receipt 未绑定当前 {key}")
    for key in (
        "commit_sha",
        "config_hash",
        "account_id",
        "environment",
        "evidence_sha256",
        "ledger_head_hash",
    ):
        if claims.get(key) != receipt.get(key):
            raise ValueError(f"生产批准与 deployment receipt 的 {key} 不一致")
    activated_at = receipt["activated_at"]
    if (
        type(activated_at) is not int
        or type(claims.get("issued_at")) is not int
        or type(claims.get("expires_at")) is not int
        or not claims["issued_at"] <= activated_at <= claims["expires_at"]
    ):
        raise ValueError("deployment receipt 激活时间不在签名批准窗口")
    return receipt
