from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from okx_quant.application.approval import canonical_bytes
from okx_quant.ops import stage_c_implementation_inventory as inventory
from okx_quant.ops.stage_c_build_provenance import (
    INVENTORY_BUILD_PROVENANCE_SCHEMA,
)
from okx_quant.ops.stage_c_chaos_protocol import (
    IMPLEMENTATION_INVENTORY_SHA256,
    PARSER_MANIFEST,
    PARSER_PROTOCOL,
    RAW_EVENT_SCHEMA,
    SCENARIO_PROTOCOLS,
    driver_contract_document,
    implemented_stage_c_scenarios,
    production_instrumented_stage_c_scenarios,
    required_source_roles,
)


def _expected_classes() -> dict[str, str]:
    return {
        scenario: spec.artifact_class
        for scenario, spec in SCENARIO_PROTOCOLS.items()
    }


def _expected_roles() -> dict[str, frozenset[str]]:
    return {
        scenario: required_source_roles(scenario)
        for scenario in SCENARIO_PROTOCOLS
    }


def _expected_adapters() -> dict[str, str]:
    return {
        scenario: hashlib.sha256(
            canonical_bytes(driver_contract_document(scenario))
        ).hexdigest()
        for scenario in SCENARIO_PROTOCOLS
    }


def _expected_native_schema() -> str:
    return hashlib.sha256(
        canonical_bytes({
            "native_event_schema": RAW_EVENT_SCHEMA,
            "parser_protocol": PARSER_PROTOCOL,
        })
    ).hexdigest()


def _copy_parser_sources(target: Path) -> None:
    package_root = Path(inventory.__file__).resolve().parents[1]
    for relative in inventory.PARSER_SOURCE_FILES:
        source = package_root / relative
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _write_bound(
    root: Path,
    group: str,
    role: str,
    raw: bytes,
) -> inventory.BoundArtifact:
    path = f"stage_c_artifacts/{group}/{role}"
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return inventory.BoundArtifact(
        role=role,
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _future_implementation(
    root: Path,
    scenario: str,
    *,
    production_raw_acquisition: bool = True,
) -> inventory.ShippedImplementation:
    artifact_class = _expected_classes()[scenario]
    driver_path = f"stage_c_artifacts/bin/{scenario}"
    driver_raw = f"driver:{scenario}".encode()
    driver = root / driver_path
    driver.parent.mkdir(parents=True, exist_ok=True)
    driver.write_bytes(driver_raw)
    driver_sha256 = hashlib.sha256(driver_raw).hexdigest()

    def bindings(group: str, roles) -> tuple[inventory.BoundArtifact, ...]:
        return tuple(
            _write_bound(
                root,
                group,
                role,
                f"{scenario}:{group}:{role}".encode(),
            )
            for role in sorted(roles)
        )

    runtime_identity = bindings(
        "runtime",
        inventory.REQUIRED_RUNTIME_IDENTITY_ROLES,
    )
    runtime = {item.role: item for item in runtime_identity}
    exact_release_sha256 = driver_sha256
    build_artifacts: list[inventory.BoundArtifact] = []
    if artifact_class == "instrumented_test_only":
        counterpart = _write_bound(
            root,
            "build",
            "exact_release_counterpart",
            f"exact-release:{scenario}".encode(),
        )
        build_artifacts.append(counterpart)
        exact_release_sha256 = counterpart.sha256
    provenance = canonical_bytes({
        "schema": INVENTORY_BUILD_PROVENANCE_SCHEMA,
        "artifact_class": artifact_class,
        "artifact_build_id": (
            f"test-only:{scenario}"
            if artifact_class == "instrumented_test_only"
            else f"exact-release:{scenario}"
        ),
        "driver_artifact_sha256": driver_sha256,
        "exact_release_artifact_sha256": exact_release_sha256,
        "parser_bundle_sha256": runtime["parser_bundle"].sha256,
        "dependency_lock_sha256": runtime["dependency_lock"].sha256,
        "interpreter_sha256": runtime["interpreter"].sha256,
        "source_manifest_sha256": "a" * 64,
        "test_hooks_present": artifact_class == "instrumented_test_only",
        "exact_release_excludes_test_harness": (
            artifact_class == "exact_release_black_box"
        ),
    })
    build_artifacts.append(
        _write_bound(
            root,
            "build",
            "build_provenance",
            provenance,
        )
    )
    test_source = b"\n".join(
        f"def test_attack_{index}():\n    assert True\n".encode()
        for index in range(4)
    )
    test_source_path = (
        f"stage_c_artifacts/test-sources/tests/{scenario}.py"
    )
    source_target = root / test_source_path
    source_target.parent.mkdir(parents=True, exist_ok=True)
    source_target.write_bytes(test_source)
    source_sha256 = hashlib.sha256(test_source).hexdigest()
    security_tests = []
    for index in range(4):
        test_id = f"tests/{scenario}.py::test_attack_{index}"
        result = canonical_bytes({
            "schema": inventory.SECURITY_TEST_RESULT_SCHEMA,
            "test_id": test_id,
            "source_sha256": source_sha256,
            "driver_artifact_sha256": driver_sha256,
            "parser_bundle_sha256": runtime["parser_bundle"].sha256,
            "dependency_lock_sha256": runtime["dependency_lock"].sha256,
            "interpreter_sha256": runtime["interpreter"].sha256,
            "runner_artifact_sha256": runtime["parser_bundle"].sha256,
            "outcome": "passed",
            "completed_at": f"2026-07-29T00:00:0{index}Z",
        })
        result_path = (
            f"stage_c_artifacts/test-results/{scenario}-{index}.json"
        )
        result_target = root / result_path
        result_target.parent.mkdir(parents=True, exist_ok=True)
        result_target.write_bytes(result)
        security_tests.append(inventory.SecurityTestBinding(
            test_id=test_id,
            source_path=test_source_path,
            source_sha256=source_sha256,
            result_path=result_path,
            result_sha256=hashlib.sha256(result).hexdigest(),
        ))
    return inventory.ShippedImplementation(
        schema=inventory.IMPLEMENTATION_ARTIFACT_SCHEMA,
        driver_entrypoint=driver_path,
        driver_artifact_sha256=driver_sha256,
        adapter_manifest_sha256=_expected_adapters()[scenario],
        native_frame_schema_sha256=_expected_native_schema(),
        collector_artifacts=bindings("collector", _expected_roles()[scenario]),
        systemd_unit_artifacts=bindings("systemd", _expected_roles()[scenario]),
        iam_policy_artifacts=bindings("iam", _expected_roles()[scenario]),
        worm_admission_artifacts=bindings(
            "worm",
            inventory.REQUIRED_WORM_ADMISSION_ROLES,
        ),
        build_provenance_artifacts=tuple(build_artifacts),
        runtime_identity_artifacts=runtime_identity,
        trust_root_artifacts=bindings(
            "trust",
            inventory.REQUIRED_TRUST_ROOT_ROLES,
        ),
        focused_security_tests=tuple(security_tests),
        production_raw_acquisition=production_raw_acquisition,
    )


def test_parser_manifest_binds_exact_parser_and_collector_source_bytes():
    source_manifest = PARSER_MANIFEST["parser_source_manifest"]
    paths = [item["path"] for item in source_manifest["files"]]

    assert paths == list(inventory.PARSER_SOURCE_FILES)
    assert paths == sorted(paths)
    assert {
        "ops/stage_c_chaos_protocol.py",
        "ops/stage_c_exact_release_drivers.py",
        "ops/stage_c_native_collectors.py",
        "ops/stage_c_implementation_inventory.py",
    } <= set(paths)

    package_root = Path(inventory.__file__).resolve().parents[1]
    for item in source_manifest["files"]:
        raw = (package_root / item["path"]).read_bytes()
        assert item["bytes"] == len(raw)
        assert item["sha256"] == hashlib.sha256(raw).hexdigest()


def test_parser_source_tamper_changes_manifest_identity(tmp_path):
    _copy_parser_sources(tmp_path)
    original = inventory.build_parser_source_manifest(tmp_path)
    target = tmp_path / "ops/stage_c_native_collectors.py"
    target.write_bytes(target.read_bytes() + b"\n# tampered\n")
    changed = inventory.build_parser_source_manifest(tmp_path)

    assert changed != original
    assert hashlib.sha256(canonical_bytes(changed)).hexdigest() != (
        hashlib.sha256(canonical_bytes(original)).hexdigest()
    )


def test_parser_source_manifest_rejects_symlink(tmp_path):
    _copy_parser_sources(tmp_path)
    target = tmp_path / "ops/stage_c_native_collectors.py"
    real = tmp_path / "ops/native-real.py"
    target.rename(real)
    target.symlink_to(real)

    with pytest.raises(RuntimeError, match="符号链接"):
        inventory.build_parser_source_manifest(tmp_path)


def test_inventory_is_exact_open_and_digest_bound():
    document = inventory.implementation_inventory_document(
        _expected_classes(),
        _expected_roles(),
        _expected_adapters(),
        _expected_native_schema(),
    )

    assert len(document["records"]) == 13
    assert document["semantic_verifiers"] == []
    assert document["semantic_results"] == []
    assert document["semantic_verifier_registry_sha256"] == hashlib.sha256(
        canonical_bytes([])
    ).hexdigest()
    assert all(record["parser_ready"] for record in document["records"])
    assert not any(
        record["executor_shipped"] for record in document["records"]
    )
    assert implemented_stage_c_scenarios() == frozenset()
    assert production_instrumented_stage_c_scenarios() == frozenset()
    assert hashlib.sha256(
        canonical_bytes(document)
    ).hexdigest() == IMPLEMENTATION_INVENTORY_SHA256


def test_full_inventory_records_all_18_without_capability_promotion():
    document = inventory.full_stage_c_inventory_document(
        _expected_classes(),
        _expected_roles(),
        _expected_adapters(),
        _expected_native_schema(),
    )
    assert document["scenario_count"] == 18
    assert len(document["records"]) == 18
    assert document["executor_shipped_scenarios"] == []
    assert document["production_instrumented_scenarios"] == []
    assert {
        row["scenario"]
        for row in document["records"]
        if row["capability_state"].startswith("REPOSITORY_PRODUCER")
    } == set(inventory.LEGACY_REPOSITORY_PRODUCER_SCENARIOS)
    assert all(
        row["executor_shipped"] is False for row in document["records"]
    )


def test_inventory_rejects_semantic_verifier_registry_rebinding(monkeypatch):
    monkeypatch.setattr(
        inventory,
        "SEMANTIC_IMPLEMENTATION_VERIFIERS",
        {"backup-db-corruption": lambda *_args: True},
    )

    with pytest.raises(RuntimeError, match="verifier registry 运行时漂移"):
        inventory.implementation_inventory_document(
            _expected_classes(),
            _expected_roles(),
            _expected_adapters(),
            _expected_native_schema(),
        )


def test_inventory_cannot_upgrade_from_boolean_without_artifact_bindings(
    monkeypatch,
):
    records = list(inventory.IMPLEMENTATION_RECORDS)
    records[0] = replace(records[0], executor_shipped=True)
    monkeypatch.setattr(
        inventory,
        "IMPLEMENTATION_RECORDS",
        tuple(records),
    )

    with pytest.raises(RuntimeError, match="不能无 artifact binding"):
        inventory.shipped_scenarios(
            _expected_classes(),
            _expected_roles(),
        )


def test_shipped_record_requires_all_artifact_classes_and_security_tests(
    monkeypatch,
):
    records = list(inventory.IMPLEMENTATION_RECORDS)
    records[0] = replace(
        records[0],
        executor_shipped=True,
        implementation=inventory.ShippedImplementation(
            schema=inventory.IMPLEMENTATION_ARTIFACT_SCHEMA,
            driver_entrypoint="scripts/stage-c-driver",
            driver_artifact_sha256="1" * 64,
            adapter_manifest_sha256=_expected_adapters()[
                "backup-db-corruption"
            ],
            native_frame_schema_sha256=_expected_native_schema(),
            collector_artifacts=(),
            systemd_unit_artifacts=(),
            iam_policy_artifacts=(),
            worm_admission_artifacts=(),
            build_provenance_artifacts=(),
            runtime_identity_artifacts=(),
            trust_root_artifacts=(),
            focused_security_tests=(),
            production_raw_acquisition=False,
        ),
    )
    monkeypatch.setattr(
        inventory,
        "IMPLEMENTATION_RECORDS",
        tuple(records),
    )

    with pytest.raises(RuntimeError, match="collector artifact"):
        inventory.shipped_scenarios(
            _expected_classes(),
            _expected_roles(),
            _expected_adapters(),
            _expected_native_schema(),
        )


def test_barrier_cannot_ship_without_production_raw_acquisition(
    tmp_path,
    monkeypatch,
):
    records = list(inventory.IMPLEMENTATION_RECORDS)
    index = next(
        index
        for index, record in enumerate(records)
        if record.scenario == "barrier-buy-intent-before-post"
    )
    scenario = records[index].scenario
    records[index] = replace(
        records[index],
        executor_shipped=True,
        implementation=_future_implementation(
            tmp_path,
            scenario,
            production_raw_acquisition=False,
        ),
    )
    monkeypatch.setattr(
        inventory,
        "IMPLEMENTATION_RECORDS",
        tuple(records),
    )

    with pytest.raises(RuntimeError, match="production raw acquisition"):
        inventory.production_instrumented_scenarios(
            _expected_classes(),
            _expected_roles(),
            _expected_adapters(),
            _expected_native_schema(),
            tmp_path,
        )


def test_structural_artifacts_are_recomputed_but_cannot_self_upgrade(
    tmp_path,
    monkeypatch,
):
    scenario = "backup-db-corruption"
    implementation = _future_implementation(tmp_path, scenario)
    records = list(inventory.IMPLEMENTATION_RECORDS)
    index = next(
        index
        for index, record in enumerate(records)
        if record.scenario == scenario
    )
    records[index] = replace(
        records[index],
        executor_shipped=True,
        implementation=implementation,
    )
    monkeypatch.setattr(
        inventory,
        "IMPLEMENTATION_RECORDS",
        tuple(records),
    )

    missing_controls = list(records)
    missing_controls[index] = replace(
        records[index],
        implementation=replace(
            implementation,
            worm_admission_artifacts=(),
        ),
    )
    monkeypatch.setattr(
        inventory,
        "IMPLEMENTATION_RECORDS",
        tuple(missing_controls),
    )
    with pytest.raises(RuntimeError, match="worm_admission roles"):
        inventory.shipped_scenarios(
            _expected_classes(),
            _expected_roles(),
            _expected_adapters(),
            _expected_native_schema(),
            tmp_path,
        )

    monkeypatch.setattr(
        inventory,
        "IMPLEMENTATION_RECORDS",
        tuple(records),
    )
    with pytest.raises(RuntimeError, match="registry 必须与 shipped"):
        inventory.shipped_scenarios(
            _expected_classes(),
            _expected_roles(),
            _expected_adapters(),
            _expected_native_schema(),
            tmp_path,
        )
    implementation.validate(
        scenario=scenario,
        artifact_class=records[index].artifact_class,
        required_source_roles=_expected_roles()[scenario],
        expected_adapter_manifest_sha256=_expected_adapters()[scenario],
        expected_native_frame_schema_sha256=_expected_native_schema(),
        artifact_root=tmp_path,
    )
    (tmp_path / implementation.collector_artifacts[0].path).write_bytes(
        b"tampered"
    )
    with pytest.raises(RuntimeError, match="hash 漂移"):
        implementation.validate(
            scenario=scenario,
            artifact_class=records[index].artifact_class,
            required_source_roles=_expected_roles()[scenario],
            expected_adapter_manifest_sha256=(
                _expected_adapters()[scenario]
            ),
            expected_native_frame_schema_sha256=(
                _expected_native_schema()
            ),
            artifact_root=tmp_path,
        )


@pytest.mark.parametrize(
    "scenario",
    ["backup-db-corruption", "barrier-post-before-ack"],
)
def test_future_shipped_structure_binds_build_runtime_trust_and_test_bytes(
    tmp_path,
    scenario,
):
    implementation = _future_implementation(tmp_path, scenario)

    implementation.validate(
        scenario=scenario,
        artifact_class=_expected_classes()[scenario],
        required_source_roles=_expected_roles()[scenario],
        expected_adapter_manifest_sha256=_expected_adapters()[scenario],
        expected_native_frame_schema_sha256=_expected_native_schema(),
        artifact_root=tmp_path,
    )

    with pytest.raises(RuntimeError, match="trust_root roles"):
        replace(implementation, trust_root_artifacts=()).validate(
            scenario=scenario,
            artifact_class=_expected_classes()[scenario],
            required_source_roles=_expected_roles()[scenario],
            expected_adapter_manifest_sha256=_expected_adapters()[scenario],
            expected_native_frame_schema_sha256=_expected_native_schema(),
            artifact_root=tmp_path,
        )

    test = implementation.focused_security_tests[0]
    (tmp_path / test.result_path).write_bytes(b'{"outcome":"passed"}')
    with pytest.raises(RuntimeError, match="bytes/hash 漂移"):
        implementation.validate(
            scenario=scenario,
            artifact_class=_expected_classes()[scenario],
            required_source_roles=_expected_roles()[scenario],
            expected_adapter_manifest_sha256=_expected_adapters()[scenario],
            expected_native_frame_schema_sha256=_expected_native_schema(),
            artifact_root=tmp_path,
        )


def test_future_shipped_structure_rejects_build_class_and_role_byte_reuse(
    tmp_path,
):
    scenario = "backup-db-corruption"
    implementation = _future_implementation(tmp_path, scenario)
    provenance = implementation.build_provenance_artifacts[0]
    claims = json.loads((tmp_path / provenance.path).read_bytes())
    claims["test_hooks_present"] = True
    raw = canonical_bytes(claims)
    (tmp_path / provenance.path).write_bytes(raw)
    bad_provenance = replace(
        provenance,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    with pytest.raises(RuntimeError, match="artifact class/build provenance"):
        replace(
            implementation,
            build_provenance_artifacts=(bad_provenance,),
        ).validate(
            scenario=scenario,
            artifact_class=_expected_classes()[scenario],
            required_source_roles=_expected_roles()[scenario],
            expected_adapter_manifest_sha256=_expected_adapters()[scenario],
            expected_native_frame_schema_sha256=_expected_native_schema(),
            artifact_root=tmp_path,
        )

    implementation = _future_implementation(tmp_path, scenario)
    runtime = list(implementation.runtime_identity_artifacts)
    parser_bundle = next(
        item for item in runtime if item.role == "parser_bundle"
    )
    interpreter_index = next(
        index for index, item in enumerate(runtime)
        if item.role == "interpreter"
    )
    runtime[interpreter_index] = inventory.BoundArtifact(
        role="interpreter",
        path=parser_bundle.path,
        sha256=parser_bundle.sha256,
    )
    with pytest.raises(RuntimeError, match="artifact bytes 禁止复用"):
        replace(
            implementation,
            runtime_identity_artifacts=tuple(runtime),
        ).validate(
            scenario=scenario,
            artifact_class=_expected_classes()[scenario],
            required_source_roles=_expected_roles()[scenario],
            expected_adapter_manifest_sha256=_expected_adapters()[scenario],
            expected_native_frame_schema_sha256=_expected_native_schema(),
            artifact_root=tmp_path,
        )


def test_semantic_verifier_result_is_strict_and_inventory_bound(tmp_path):
    scenario = "backup-db-corruption"
    implementation = _future_implementation(tmp_path, scenario)

    def verify(_implementation, _root):
        raise AssertionError("not called")

    spec = inventory.SemanticVerifierSpec(
        scenario=scenario,
        verifier_id="stage-c-backup-db-corruption-semantic-v1",
        source_path="ops/stage_c_implementation_inventory.py",
        source_sha256="1" * 64,
        callable_name="verify",
        verifier=verify,
    )
    result = {
        "schema": inventory.SEMANTIC_VERIFIER_RESULT_SCHEMA,
        "scenario": scenario,
        "verifier_id": spec.verifier_id,
        "implementation_sha256": hashlib.sha256(
            canonical_bytes(implementation.document())
        ).hexdigest(),
        "checks": {
            check: True for check in inventory.REQUIRED_SEMANTIC_CHECKS
        },
        "passed": True,
    }
    assert inventory._validate_semantic_verifier_result(
        result,
        scenario=scenario,
        verifier=spec,
        implementation=implementation,
    ) == result
    result["checks"]["native_raw_acquisition_bridge"] = False
    with pytest.raises(RuntimeError, match="result schema/closure"):
        inventory._validate_semantic_verifier_result(
            result,
            scenario=scenario,
            verifier=spec,
            implementation=implementation,
        )
