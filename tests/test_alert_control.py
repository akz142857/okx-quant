import json
import subprocess
import time

import pytest

from okx_quant.infrastructure.db import SQLiteJournal
from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.ops.alert_control import (
    apply_alert_control_request,
    build_challenge_request,
    build_receipt_request,
)


def _keys(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", private],
        check=True,
        capture_output=True,
    )
    private.chmod(0o600)
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            private,
            "-pubout",
            "-out",
            public,
        ],
        check=True,
        capture_output=True,
    )
    return private, public


def _role_keys(public):
    return {
        "provider": public,
        "human-ack": public,
        "escalation": public,
    }


@pytest.mark.unit
def test_alert_file_drop_is_applied_by_single_journal_writer(tmp_path):
    private, public = _keys(tmp_path)
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.initialize_identity(
        account_id="demo-account",
        initial_config_hash="a" * 64,
        actor="test",
    )
    challenge = build_challenge_request(
        account_id="demo-account",
        role="active",
        day="2026-07-28",
    )
    result = apply_alert_control_request(
        challenge,
        journal=journal,
        expected_account_id="demo-account",
        receipt_public_keys=_role_keys(public),
    )
    now = time.time()
    artifact = (
        json.dumps(sign_ed25519_payload(
            {
                "version": 1,
                "action": "confirm-alert-provider-received",
                "event_id": result["event_id"],
                "issued_at": int(now),
                "provider_event_id": "provider-1",
                "provider_received_at": now,
            },
            private,
        ))
        + "\n"
    ).encode()
    receipt = build_receipt_request(
        account_id="demo-account",
        kind="provider",
        artifact_bytes=artifact,
    )
    applied = apply_alert_control_request(
        receipt,
        journal=journal,
        expected_account_id="demo-account",
        receipt_public_keys=_role_keys(public),
    )
    assert applied["state"] == "provider_received"
    assert applied["provider_artifact_sha256"] == (
        receipt["artifact_sha256"]
    )
    journal.close()


@pytest.mark.unit
def test_alert_file_drop_rejects_account_or_signature_substitution(tmp_path):
    private, public = _keys(tmp_path)
    other_private, _other_public = _keys(tmp_path / "other")
    journal = SQLiteJournal(tmp_path / "trading.db")
    journal.initialize_identity(
        account_id="demo-account",
        initial_config_hash="a" * 64,
        actor="test",
    )
    with pytest.raises(ValueError, match="account identity"):
        apply_alert_control_request(
            build_challenge_request(
                account_id="other-account",
                role="active",
                day="2026-07-28",
            ),
            journal=journal,
            expected_account_id="demo-account",
            receipt_public_keys=_role_keys(public),
        )
    event_id = journal.enqueue_outbox(
        "warning.fixture",
        {"fixture": True},
    )
    artifact = json.dumps(sign_ed25519_payload(
        {
            "version": 1,
            "action": "confirm-alert-provider-received",
            "event_id": event_id,
            "issued_at": int(time.time()),
            "provider_event_id": "provider-1",
            "provider_received_at": time.time(),
        },
        other_private,
    )).encode()
    with pytest.raises(ValueError, match="签名"):
        apply_alert_control_request(
            build_receipt_request(
                account_id="demo-account",
                kind="provider",
                artifact_bytes=artifact,
            ),
            journal=journal,
            expected_account_id="demo-account",
            receipt_public_keys=_role_keys(public),
        )
    journal.close()
