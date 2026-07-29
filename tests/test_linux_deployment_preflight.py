from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from scripts.linux_deployment_preflight import PreflightError, build_report

PROJECT = Path(__file__).resolve().parents[1]


def _args(**overrides):
    values = {
        "root": PROJECT,
        "mode": "static",
        "installed_unit": [],
        "attestation": None,
        "public_key": None,
        "expected_candidate_sha256": "",
        "require_attestation": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_static_preflight_is_explicitly_not_deployment_attestation():
    report = build_report(_args())
    assert report["passed"] is True
    assert report["preflight_only"] is True
    assert report["checks"]["external_deployment_attestation"]["verified"] is False


def test_required_external_attestation_cannot_be_skipped():
    with pytest.raises(PreflightError, match="必须同时提供"):
        build_report(_args(require_attestation=True))

    with pytest.raises(PreflightError, match="expected-candidate"):
        build_report(
            _args(
                require_attestation=True,
                attestation=PROJECT / "missing-attestation.json",
                public_key=PROJECT / "missing-public.pem",
            )
        )


def test_live_mode_rejects_non_linux_before_claiming_host_facts(monkeypatch):
    monkeypatch.setattr("scripts.linux_deployment_preflight.platform.system", lambda: "Darwin")
    with pytest.raises(PreflightError, match="只能在 Linux"):
        build_report(_args(mode="live"))
