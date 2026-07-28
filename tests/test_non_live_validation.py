"""非实盘验证证据必须完整，同时永远不能冒充生产准入。"""

from __future__ import annotations

import json

import pytest

from scripts import non_live_validation as validation


def _suite_result(suite):
    stdout = f"{suite['id']}: passed\n"
    stderr = ""
    return {
        "id": suite["id"],
        "description": suite["description"],
        "tests": list(suite["tests"]),
        "command": ["python", "-m", "pytest", *suite["tests"]],
        "duration_seconds": 1.0,
        "exit_code": 0,
        "passed": True,
        "stdout_sha256": validation._sha256_text(stdout),
        "stderr_sha256": validation._sha256_text(stderr),
        "stdout": stdout,
        "stderr": stderr,
    }


@pytest.mark.unit
def test_non_live_suite_inventory_covers_every_test_file_once():
    discovered = validation._validate_suite_inventory()
    selected = validation._suite_tests()
    assert sorted(selected) == discovered
    assert len(selected) == len(set(selected))


@pytest.mark.unit
def test_non_live_report_never_claims_production_admission(monkeypatch):
    monkeypatch.setattr(
        validation,
        "_git_identity",
        lambda: ("a" * 40, "b" * 40, True),
    )
    monkeypatch.setattr(validation, "_run_suite", _suite_result)
    evidence = validation.build_evidence()
    assert evidence["overall_passed"] is True
    assert evidence["release_candidate_eligible"] is True
    assert evidence["production_admissible"] is False
    assert evidence["assurance_scope"] == "offline_deterministic_only"


@pytest.mark.unit
def test_non_live_release_evidence_verifies_and_rejects_tampering(tmp_path):
    revision = "a" * 40
    revision_file = tmp_path / "REVISION"
    revision_file.write_text(revision + "\n", encoding="ascii")
    evidence = {
        "schema_version": 1,
        "evidence_type": "okx_quant_non_live_validation",
        "assurance_scope": "offline_deterministic_only",
        "production_admissible": False,
        "started_at": 100.0,
        "completed_at": 110.0,
        "git_commit": revision,
        "git_tree_hash": "b" * 40,
        "workspace_clean": True,
        "source_manifest_sha256": validation._source_manifest_hash(),
        "test_inventory_sha256": validation._test_inventory_hash(),
        "complete_test_inventory": True,
        "suites": [
            _suite_result(suite) for suite in validation.SUITES
        ],
        "limitations": list(validation.LIMITATIONS),
        "overall_passed": True,
        "release_candidate_eligible": True,
    }
    evidence_path = tmp_path / "non-live.json"
    evidence_path.write_text(
        json.dumps(evidence),
        encoding="utf-8",
    )

    verified = validation.verify_evidence_artifact(
        evidence_path,
        revision_file,
    )
    assert verified["git_commit"] == revision

    evidence["suites"][0]["stdout"] = "forged"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(RuntimeError, match="suite 非法"):
        validation.verify_evidence_artifact(
            evidence_path,
            revision_file,
        )


@pytest.mark.unit
def test_non_live_evidence_is_write_once(tmp_path):
    output = tmp_path / "non-live.json"
    validation._write_once(output, {"value": 1})
    with pytest.raises(RuntimeError, match="拒绝覆盖"):
        validation._write_once(output, {"value": 2})
