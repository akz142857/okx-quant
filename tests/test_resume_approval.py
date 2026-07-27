"""恢复交易的独立签名批准、一次性消费与告警 challenge。"""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from okx_quant.application.approval import (
    ResumeApprovalVerifier,
    build_control_request,
    build_resume_request,
    production_config_hash,
)
from okx_quant.application.runtime import ProductionRuntime
from okx_quant.cli.operations import enqueue_and_wait
from okx_quant.config import ProductionSettings
from okx_quant.domain.orders import SystemMode
from okx_quant.exchange.fake import FakeExchange
from okx_quant.infrastructure.db import SQLiteJournal


def _signed_approval(
    tmp_path,
    *,
    action="resume-entries",
    instruments=(),
):
    private_key = tmp_path / "risk-private.pem"
    public_key = tmp_path / "risk-public.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )
    settings = ProductionSettings(
        environment="production",
        account_id="production-uid",
        resume_approval_public_key=str(public_key),
    )
    cfg = {
        "okx": {
            "base_url": "https://www.okx.com",
            "simulated": False,
        }
    }
    request = (
        build_resume_request(
            settings,
            cfg,
            actor="operator-a",
        )
        if action == "resume-entries"
        else build_control_request(
            settings,
            cfg,
            action=action,
            actor="operator-a",
            instruments=instruments,
        )
    )
    request_path = tmp_path / "resume-request.json"
    approval_path = tmp_path / "resume-approval.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    subprocess.run(
        [
            sys.executable,
            "scripts/sign_resume_approval.py",
            "--request",
            str(request_path),
            "--private-key",
            str(private_key),
            "--approver",
            "risk-b",
            "--output",
            str(approval_path),
        ],
        check=True,
        capture_output=True,
        cwd=Path(__file__).parents[1],
    )
    return (
        settings,
        cfg,
        public_key,
        json.loads(approval_path.read_text(encoding="utf-8")),
    )


@pytest.mark.unit
def test_resume_approval_is_signed_and_bound_to_command_account_config(tmp_path):
    settings, cfg, public_key, artifact = _signed_approval(tmp_path)
    claims = artifact["payload"]
    verifier = ResumeApprovalVerifier(public_key)
    verified = verifier.verify(
        artifact,
        command_id=claims["command_id"],
        expected_account_id=settings.account_id,
        expected_config_hash=production_config_hash(settings, cfg),
    )
    assert verified["risk_approver"] == "risk-b"

    artifact["payload"]["account_id"] = "attacker"
    with pytest.raises(ValueError, match="账户"):
        verifier.verify(
            artifact,
            command_id=claims["command_id"],
            expected_account_id=settings.account_id,
            expected_config_hash=production_config_hash(settings, cfg),
        )


@pytest.mark.unit
def test_flatten_approval_binds_action_and_exact_instruments(tmp_path):
    settings, cfg, public_key, artifact = _signed_approval(
        tmp_path,
        action="flatten-and-cancel",
        instruments=("BTC-USDT", "ETH-USDT"),
    )
    claims = artifact["payload"]
    verifier = ResumeApprovalVerifier(public_key)
    verifier.verify(
        artifact,
        command_id=claims["command_id"],
        expected_account_id=settings.account_id,
        expected_config_hash=production_config_hash(settings, cfg),
        expected_action="flatten-and-cancel",
        expected_instruments=["ETH-USDT", "BTC-USDT"],
    )
    with pytest.raises(ValueError, match="交易对"):
        verifier.verify(
            artifact,
            command_id=claims["command_id"],
            expected_account_id=settings.account_id,
            expected_config_hash=production_config_hash(settings, cfg),
            expected_action="flatten-and-cancel",
            expected_instruments=["BTC-USDT"],
        )


@pytest.mark.unit
def test_signed_resume_is_one_time_and_requires_page_challenge(
    tmp_path,
    monkeypatch,
):
    settings, cfg, public_key, artifact = _signed_approval(tmp_path)
    claims = artifact["payload"]
    exchange = FakeExchange()
    exchange.set_account_identity(settings.account_id)
    exchange.set_balance(total=10_000, quote_avail=10_000)
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.HALTED)
    runtime = ProductionRuntime(
        exchange,
        journal,
        lock_path=tmp_path / "trading.lock",
        expected_account_id=settings.account_id,
        approval_public_key=public_key,
        production_config_hash=production_config_hash(settings, cfg),
        alert_webhook_url="https://alerts.example",
    )
    calls = []

    def acknowledge(url, **kwargs):
        calls.append((url, kwargs["json"]["event_name"]))
        return SimpleNamespace(raise_for_status=lambda: None)

    monkeypatch.setattr(
        "okx_quant.infrastructure.operations.requests.post",
        acknowledge,
    )
    runtime.start()
    try:
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"approval": artifact},
            timeout_s=2,
            command_id=claims["command_id"],
        )
        assert command["status"] == "completed"
        assert journal.get_mode() is SystemMode.READY
        assert ("https://alerts.example", "resume_delivery_challenge") in calls
        with pytest.raises(sqlite3.IntegrityError):
            journal.enqueue_control_command(
                "resume-entries",
                {"approval": artifact},
                command_id=claims["command_id"],
            )
    finally:
        runtime.stop()


@pytest.mark.unit
def test_failed_page_challenge_keeps_hard_halt(tmp_path, monkeypatch):
    settings, cfg, public_key, artifact = _signed_approval(tmp_path)
    claims = artifact["payload"]
    exchange = FakeExchange()
    exchange.set_account_identity(settings.account_id)
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.set_mode(SystemMode.HALTED)
    runtime = ProductionRuntime(
        exchange,
        journal,
        lock_path=tmp_path / "trading.lock",
        expected_account_id=settings.account_id,
        approval_public_key=public_key,
        production_config_hash=production_config_hash(settings, cfg),
        alert_webhook_url="https://alerts.invalid",
    )

    def reject(*_args, **_kwargs):
        raise OSError("unreachable")

    monkeypatch.setattr(
        "okx_quant.infrastructure.operations.requests.post",
        reject,
    )
    runtime.start()
    try:
        command = enqueue_and_wait(
            journal,
            "resume-entries",
            {"approval": artifact},
            timeout_s=2,
            command_id=claims["command_id"],
        )
        assert command["status"] == "failed"
        assert journal.get_mode() is SystemMode.HALTED
    finally:
        runtime.stop()
