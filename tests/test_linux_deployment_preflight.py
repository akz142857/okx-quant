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
        "role": None,
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
    assert report["roles"] == ["shadow", "active"]
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


def test_live_gate_a_defaults_to_shadow_and_active(monkeypatch):
    captured = {}

    def fake_host(units, roles):
        captured["units"] = units
        captured["roles"] = roles
        return {"network_namespaces": {}, "installed_units": []}

    monkeypatch.setattr("scripts.linux_deployment_preflight._check_live_host", fake_host)
    monkeypatch.setattr(
        "scripts.linux_deployment_preflight._check_systemd_units",
        lambda _root, *, live: {"live": live},
    )

    report = build_report(_args(mode="live"))

    assert report["roles"] == ["shadow", "active"]
    assert captured == {
        "units": [
            "okx-quant-demo-shadow.service",
            "okx-quant-demo-active.service",
        ],
        "roles": ("shadow", "active"),
    }


def test_live_gate_a_can_explicitly_include_chaos(monkeypatch):
    captured = {}

    def fake_host(units, roles):
        captured["units"] = units
        captured["roles"] = roles
        return {"network_namespaces": {}, "installed_units": []}

    monkeypatch.setattr("scripts.linux_deployment_preflight._check_live_host", fake_host)
    monkeypatch.setattr(
        "scripts.linux_deployment_preflight._check_systemd_units",
        lambda _root, *, live: {"live": live},
    )

    report = build_report(_args(mode="live", role=["shadow", "active", "chaos"]))

    assert report["roles"] == ["shadow", "active", "chaos"]
    assert captured["units"][-1] == "okx-quant-demo-chaos.service"
    assert captured["roles"] == ("shadow", "active", "chaos")


@pytest.mark.parametrize(
    "roles",
    [
        ["shadow"],
        ["active"],
        ["shadow", "active", "active"],
    ],
)
def test_gate_a_roles_fail_closed_when_incomplete_or_duplicated(roles):
    with pytest.raises(PreflightError):
        build_report(_args(role=roles))


def test_live_installed_units_must_match_selected_roles():
    with pytest.raises(PreflightError, match="精确一致"):
        build_report(
            _args(
                mode="live",
                installed_unit=[
                    "okx-quant-demo-shadow.service",
                    "okx-quant-demo-active.service",
                    "okx-quant-demo-chaos.service",
                ],
            )
        )
