"""Fail-closed implementation inventory for Stage-C scenarios.

Parser support, a repository-side actor, and a production-deployed executor
are three different capabilities.  This module deliberately keeps those
states separate.  A scenario can become ``EXECUTOR_SHIPPED`` only through an
explicit record that binds every executable, collector, service unit, IAM
policy, native-frame schema, and focused security test by digest.

The records are append-only review data.  No callable discovery, import
success, filename convention, or caller-supplied flag can upgrade a scenario.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from okx_quant.application.approval import canonical_bytes
from okx_quant.ops.stage_c_build_provenance import (
    EXACT_ARTIFACT_CLASS,
    verify_inventory_build_provenance,
)

PARSER_SOURCE_MANIFEST_SCHEMA = (
    "okx-quant.stage-c-parser-source-manifest/v1"
)
IMPLEMENTATION_INVENTORY_SCHEMA = (
    "okx-quant.stage-c-implementation-inventory/v2"
)
IMPLEMENTATION_ARTIFACT_SCHEMA = (
    "okx-quant.stage-c-implementation-artifacts/v2"
)
SECURITY_TEST_RESULT_SCHEMA = "okx-quant.stage-c-security-test-result/v1"
SEMANTIC_VERIFIER_RESULT_SCHEMA = (
    "okx-quant.stage-c-semantic-verifier-result/v1"
)

# These paths are relative to the installed ``okx_quant`` package.  They are
# the production admission/parser surface, not documentation or tests.
PARSER_SOURCE_FILES = (
    "application/demo_probe.py",
    "infrastructure/okx/streams.py",
    "ops/demo_chaos_evidence.py",
    "ops/stage_c_build_provenance.py",
    "ops/stage_c_chaos_protocol.py",
    "ops/stage_c_deployment_identity.py",
    "ops/stage_c_exact_release_drivers.py",
    "ops/stage_c_external_bridge.py",
    "ops/stage_c_external_executors.py",
    "ops/stage_c_implementation_inventory.py",
    "ops/stage_c_native_collectors.py",
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ARTIFACT_PATH = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_./@+-]{0,255}")
_TEST_ID = re.compile(r"tests/[a-zA-Z0-9_./-]+::test_[a-zA-Z0-9_]+")
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_ZIPAPP_BYTES = 16 * 1024 * 1024
REQUIRED_WORM_ADMISSION_ROLES = frozenset({
    "bundle_publisher",
    "deployment_verifier",
    "fleet_admission_gate",
    "raw_observer",
    "worm_readback_verifier",
})
REQUIRED_RUNTIME_IDENTITY_ROLES = frozenset({
    "dependency_lock",
    "interpreter",
    "parser_bundle",
})
REQUIRED_TRUST_ROOT_ROLES = frozenset({
    "capability_authority_policy",
    "capability_authority_public_key",
    "registrar_policy",
    "registrar_public_key",
})
REQUIRED_SEMANTIC_CHECKS = frozenset({
    "artifact_class_build_provenance",
    "driver_fault_contract",
    "iam_least_privilege",
    "native_raw_acquisition_bridge",
    "security_test_results",
    "source_role_independence",
    "systemd_workload_isolation",
    "trust_root_separation",
    "worm_deployment_fleet_enforcement",
})


def _safe_artifact_path(root: Path, relative: str, *, label: str) -> Path:
    candidate = Path(relative)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or candidate.parts[0] != "stage_c_artifacts"
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise RuntimeError(
            f"{label} 必须位于 package stage_c_artifacts/"
        )
    path = root.joinpath(candidate)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError(f"{label} artifact 不存在: {relative}") from exc
    if resolved != path:
        raise RuntimeError(f"{label} artifact 路径链禁止符号链接")
    return path


def _read_regular_file_once(
    path: Path,
    *,
    label: str,
    maximum: int = _MAX_SOURCE_BYTES,
) -> bytes:
    """Read a non-symlink regular file through one stable descriptor."""
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} 无法安全打开: {path}") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise RuntimeError(f"{label} 必须是非空普通文件: {path}")
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        if (
            len(raw) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise RuntimeError(f"{label} 读取期间发生变化: {path}")
        return raw
    finally:
        os.close(fd)


def _zipapp_source_files() -> dict[str, bytes] | None:
    """Read this module's zipapp once when imported through zipimport."""
    archive_value = getattr(globals().get("__loader__"), "archive", None)
    if not isinstance(archive_value, str) or not archive_value:
        return None
    archive = Path(archive_value)
    if archive.is_symlink():
        raise RuntimeError("Stage-C parser zipapp 禁止符号链接")
    archive_raw = _read_regular_file_once(
        archive,
        label="Stage-C parser zipapp",
        maximum=_MAX_ZIPAPP_BYTES,
    )
    try:
        with zipfile.ZipFile(io.BytesIO(archive_raw)) as bundle:
            names = [
                info.filename
                for info in bundle.infolist()
                if not info.is_dir()
            ]
            if len(names) != len(set(names)):
                raise RuntimeError("Stage-C parser zipapp 含重复 member")
            result = {}
            for relative in PARSER_SOURCE_FILES:
                member = f"okx_quant/{relative}"
                try:
                    info = bundle.getinfo(member)
                except KeyError as exc:
                    raise RuntimeError(
                        f"Stage-C parser zipapp 缺少 member: {member}"
                    ) from exc
                if (
                    info.file_size <= 0
                    or info.file_size > _MAX_SOURCE_BYTES
                    or info.flag_bits & 0x1
                ):
                    raise RuntimeError(
                        f"Stage-C parser zipapp member 非法: {member}"
                    )
                result[relative] = bundle.read(info)
            return result
    except zipfile.BadZipFile as exc:
        raise RuntimeError("Stage-C parser zipapp 非法") from exc


def build_parser_source_manifest(
    package_root: Path | None = None,
    *,
    source_files: Iterable[str] = PARSER_SOURCE_FILES,
) -> dict:
    """Hash the exact production parser/collector source bytes.

    Absolute paths are intentionally excluded so the same wheel has the same
    identity on every host.  Paths must be a fixed, duplicate-free relative
    set under the installed package root.
    """
    normalized = tuple(source_files)
    if (
        not normalized
        or len(set(normalized)) != len(normalized)
        or normalized != tuple(sorted(normalized))
    ):
        raise ValueError("Stage-C parser source file 清单必须非空、唯一、有序")
    zip_sources = (
        _zipapp_source_files()
        if package_root is None
        and normalized == PARSER_SOURCE_FILES
        else None
    )
    root = (
        None
        if zip_sources is not None
        else (
            Path(__file__).resolve().parents[1]
            if package_root is None
            else package_root.resolve()
        )
    )
    entries: list[dict[str, object]] = []
    for relative in normalized:
        candidate = Path(relative)
        if (
            candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or candidate.suffix != ".py"
        ):
            raise ValueError(f"Stage-C parser source path 非法: {relative!r}")
        if zip_sources is None:
            if root is None:  # pragma: no cover - invariant guard
                raise RuntimeError("Stage-C parser source root 缺失")
            path = root.joinpath(candidate)
            try:
                path.relative_to(root)
            except ValueError as exc:
                raise ValueError(
                    f"Stage-C parser source 逃逸 package root: {relative!r}"
                ) from exc
            try:
                resolved_path = path.resolve(strict=True)
            except OSError as exc:
                raise RuntimeError(
                    f"Stage-C parser source 不存在: {relative}"
                ) from exc
            if resolved_path != path:
                raise RuntimeError(
                    f"Stage-C parser source 路径链禁止符号链接: {relative}"
                )
            raw = _read_regular_file_once(
                path,
                label=f"Stage-C parser source {relative}",
            )
        else:
            raw = zip_sources[relative]
        entries.append({
            "path": candidate.as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        })
    return {
        "schema": PARSER_SOURCE_MANIFEST_SCHEMA,
        "files": entries,
    }


@dataclass(frozen=True)
class BoundArtifact:
    role: str
    path: str
    sha256: str

    def validate(self, *, label: str) -> None:
        if (
            not re.fullmatch(r"[a-z][a-z0-9_-]{1,63}", self.role)
            or not _ARTIFACT_PATH.fullmatch(self.path)
            or ".." in Path(self.path).parts
            or not _SHA256.fullmatch(self.sha256)
        ):
            raise RuntimeError(f"{label} artifact binding 非法")

    def document(self) -> dict[str, str]:
        return {
            "role": self.role,
            "path": self.path,
            "sha256": self.sha256,
        }


def _canonical_json_artifact(raw: bytes, *, label: str) -> dict:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} 非法 JSON") from exc
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise RuntimeError(f"{label} 必须是 canonical JSON object")
    return value


@dataclass(frozen=True)
class SecurityTestBinding:
    test_id: str
    source_path: str
    source_sha256: str
    result_path: str
    result_sha256: str

    def validate(
        self,
        *,
        artifact_root: Path,
        driver_artifact_sha256: str,
        parser_bundle_sha256: str,
        dependency_lock_sha256: str,
        interpreter_sha256: str,
    ) -> None:
        expected_source_path = (
            "stage_c_artifacts/test-sources/"
            + self.test_id.split("::", 1)[0]
        )
        if (
            not _TEST_ID.fullmatch(self.test_id)
            or self.source_path != expected_source_path
            or not _SHA256.fullmatch(self.source_sha256)
            or not _SHA256.fullmatch(self.result_sha256)
        ):
            raise RuntimeError("Stage-C security test binding 非法")
        source = _read_regular_file_once(
            _safe_artifact_path(
                artifact_root,
                self.source_path,
                label=f"Stage-C security test source {self.test_id}",
            ),
            label=f"Stage-C security test source {self.test_id}",
        )
        result = _read_regular_file_once(
            _safe_artifact_path(
                artifact_root,
                self.result_path,
                label=f"Stage-C security test result {self.test_id}",
            ),
            label=f"Stage-C security test result {self.test_id}",
        )
        if (
            hashlib.sha256(source).hexdigest() != self.source_sha256
            or hashlib.sha256(result).hexdigest() != self.result_sha256
        ):
            raise RuntimeError(
                f"Stage-C security test {self.test_id} bytes/hash 漂移"
            )
        try:
            tree = ast.parse(source, filename=self.source_path)
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise RuntimeError(
                f"Stage-C security test {self.test_id} source 非法"
            ) from exc
        function_name = self.test_id.rsplit("::", 1)[1]
        if not any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
            for node in tree.body
        ):
            raise RuntimeError(
                f"Stage-C security test {self.test_id} 不存在于绑定 source"
            )
        claims = _canonical_json_artifact(
            result,
            label=f"Stage-C security test result {self.test_id}",
        )
        expected_keys = {
            "schema",
            "test_id",
            "source_sha256",
            "driver_artifact_sha256",
            "parser_bundle_sha256",
            "dependency_lock_sha256",
            "interpreter_sha256",
            "runner_artifact_sha256",
            "outcome",
            "completed_at",
        }
        if (
            set(claims) != expected_keys
            or claims["schema"] != SECURITY_TEST_RESULT_SCHEMA
            or claims["test_id"] != self.test_id
            or claims["source_sha256"] != self.source_sha256
            or claims["driver_artifact_sha256"]
            != driver_artifact_sha256
            or claims["parser_bundle_sha256"] != parser_bundle_sha256
            or claims["dependency_lock_sha256"] != dependency_lock_sha256
            or claims["interpreter_sha256"] != interpreter_sha256
            or claims["runner_artifact_sha256"] != parser_bundle_sha256
            or claims["outcome"] != "passed"
            or not isinstance(claims["completed_at"], str)
            or not claims["completed_at"].strip()
        ):
            raise RuntimeError(
                f"Stage-C security test {self.test_id} result 未绑定 release"
            )

    def document(self) -> dict[str, str]:
        return {
            "test_id": self.test_id,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "result_path": self.result_path,
            "result_sha256": self.result_sha256,
        }


@dataclass(frozen=True)
class SemanticVerifierSpec:
    scenario: str
    verifier_id: str
    source_path: str
    source_sha256: str
    callable_name: str
    verifier: Callable[[object, Path], object]

    def validate(self, *, artifact_root: Path) -> None:
        if (
            not re.fullmatch(r"stage-c-[a-z0-9-]+-semantic-v[0-9]+", self.verifier_id)
            or self.source_path not in PARSER_SOURCE_FILES
            or not _SHA256.fullmatch(self.source_sha256)
            or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", self.callable_name)
            or not callable(self.verifier)
            or getattr(self.verifier, "__name__", None) != self.callable_name
        ):
            raise RuntimeError(
                f"Stage-C {self.scenario} semantic verifier spec 非法"
            )
        path = artifact_root.joinpath(self.source_path)
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError(
                f"Stage-C {self.scenario} semantic verifier source 缺失"
            ) from exc
        if resolved != path:
            raise RuntimeError(
                f"Stage-C {self.scenario} semantic verifier source 禁止符号链接"
            )
        source = _read_regular_file_once(
            path,
            label=f"Stage-C {self.scenario} semantic verifier source",
        )
        if hashlib.sha256(source).hexdigest() != self.source_sha256:
            raise RuntimeError(
                f"Stage-C {self.scenario} semantic verifier source 漂移"
            )
        expected_module = "okx_quant." + self.source_path.removesuffix(
            ".py"
        ).replace("/", ".")
        if getattr(self.verifier, "__module__", None) != expected_module:
            raise RuntimeError(
                f"Stage-C {self.scenario} semantic verifier module 串线"
            )

    def document(self) -> dict[str, object]:
        return {
            "scenario": self.scenario,
            "verifier_id": self.verifier_id,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "callable_name": self.callable_name,
            "result_schema": SEMANTIC_VERIFIER_RESULT_SCHEMA,
            "required_checks": sorted(REQUIRED_SEMANTIC_CHECKS),
        }


@dataclass(frozen=True)
class ShippedImplementation:
    schema: str
    driver_entrypoint: str
    driver_artifact_sha256: str
    adapter_manifest_sha256: str
    native_frame_schema_sha256: str
    collector_artifacts: tuple[BoundArtifact, ...]
    systemd_unit_artifacts: tuple[BoundArtifact, ...]
    iam_policy_artifacts: tuple[BoundArtifact, ...]
    worm_admission_artifacts: tuple[BoundArtifact, ...]
    build_provenance_artifacts: tuple[BoundArtifact, ...]
    runtime_identity_artifacts: tuple[BoundArtifact, ...]
    trust_root_artifacts: tuple[BoundArtifact, ...]
    focused_security_tests: tuple[SecurityTestBinding, ...]
    production_raw_acquisition: bool

    def validate(
        self,
        *,
        scenario: str,
        artifact_class: str,
        required_source_roles: frozenset[str],
        expected_adapter_manifest_sha256: str,
        expected_native_frame_schema_sha256: str,
        artifact_root: Path,
    ) -> None:
        if (
            self.schema != IMPLEMENTATION_ARTIFACT_SCHEMA
            or not _ARTIFACT_PATH.fullmatch(self.driver_entrypoint)
            or not _SHA256.fullmatch(self.driver_artifact_sha256)
            or not _SHA256.fullmatch(self.adapter_manifest_sha256)
            or not _SHA256.fullmatch(self.native_frame_schema_sha256)
        ):
            raise RuntimeError(
                f"Stage-C {scenario} shipped implementation 基础绑定非法"
            )
        if (
            self.adapter_manifest_sha256
            != expected_adapter_manifest_sha256
            or self.native_frame_schema_sha256
            != expected_native_frame_schema_sha256
        ):
            raise RuntimeError(
                f"Stage-C {scenario} adapter/native schema 未绑定当前协议"
            )
        source_collections = (
            ("collector", self.collector_artifacts),
            ("systemd", self.systemd_unit_artifacts),
            ("iam", self.iam_policy_artifacts),
        )
        all_bindings: list[tuple[str, BoundArtifact]] = []
        for label, artifacts in source_collections:
            if not artifacts:
                raise RuntimeError(
                    f"Stage-C {scenario} 缺少 {label} artifact binding"
                )
            roles = [item.role for item in artifacts]
            if len(set(roles)) != len(roles):
                raise RuntimeError(
                    f"Stage-C {scenario} {label} artifact role 重复"
                )
            for artifact in artifacts:
                artifact.validate(label=f"Stage-C {scenario} {label}")
                all_bindings.append((label, artifact))
            if set(roles) != set(required_source_roles):
                raise RuntimeError(
                    f"Stage-C {scenario} {label} roles 未精确绑定协议 source roles"
                )
        expected_build_roles = (
            {"build_provenance"}
            if artifact_class == EXACT_ARTIFACT_CLASS
            else {"build_provenance", "exact_release_counterpart"}
        )
        fixed_collections = (
            (
                "worm_admission",
                self.worm_admission_artifacts,
                REQUIRED_WORM_ADMISSION_ROLES,
            ),
            (
                "build_provenance",
                self.build_provenance_artifacts,
                expected_build_roles,
            ),
            (
                "runtime_identity",
                self.runtime_identity_artifacts,
                REQUIRED_RUNTIME_IDENTITY_ROLES,
            ),
            (
                "trust_root",
                self.trust_root_artifacts,
                REQUIRED_TRUST_ROOT_ROLES,
            ),
        )
        for label, artifacts, expected_roles in fixed_collections:
            roles = [item.role for item in artifacts]
            if (
                not artifacts
                or len(set(roles)) != len(roles)
                or set(roles) != set(expected_roles)
            ):
                raise RuntimeError(
                    f"Stage-C {scenario} {label} roles 未精确绑定"
                )
            for artifact in artifacts:
                artifact.validate(label=f"Stage-C {scenario} {label}")
                all_bindings.append((label, artifact))
        identities = [
            self.driver_artifact_sha256,
            *(artifact.sha256 for _label, artifact in all_bindings),
        ]
        if len(set(identities)) != len(identities):
            raise RuntimeError(
                f"Stage-C {scenario} driver/role artifact bytes 禁止复用"
            )
        if (
            len(self.focused_security_tests) < 4
            or len({item.test_id for item in self.focused_security_tests})
            != len(self.focused_security_tests)
            or len({item.result_sha256 for item in self.focused_security_tests})
            != len(self.focused_security_tests)
        ):
            raise RuntimeError(
                f"Stage-C {scenario} 至少需要 4 个唯一攻击回归测试 bytes/result"
            )
        if not self.production_raw_acquisition:
            raise RuntimeError(
                f"Stage-C {scenario} 缺少 production raw acquisition"
            )
        driver_path = _safe_artifact_path(
            artifact_root,
            self.driver_entrypoint,
            label=f"Stage-C {scenario} driver",
        )
        driver_raw = _read_regular_file_once(
            driver_path,
            label=f"Stage-C {scenario} driver",
        )
        if hashlib.sha256(driver_raw).hexdigest() != self.driver_artifact_sha256:
            raise RuntimeError(f"Stage-C {scenario} driver artifact hash 漂移")
        bound_raw: dict[tuple[str, str], bytes] = {}
        for label, artifact in all_bindings:
            artifact_path = _safe_artifact_path(
                artifact_root,
                artifact.path,
                label=f"Stage-C {scenario} {label} {artifact.role}",
            )
            raw = _read_regular_file_once(
                artifact_path,
                label=f"Stage-C {scenario} {label} {artifact.role}",
            )
            if hashlib.sha256(raw).hexdigest() != artifact.sha256:
                raise RuntimeError(
                    f"Stage-C {scenario} {label} {artifact.role} hash 漂移"
                )
            bound_raw[(label, artifact.role)] = raw
        runtime = {
            item.role: item for item in self.runtime_identity_artifacts
        }
        build = {item.role: item for item in self.build_provenance_artifacts}
        exact_release_sha256 = (
            self.driver_artifact_sha256
            if artifact_class == EXACT_ARTIFACT_CLASS
            else build["exact_release_counterpart"].sha256
        )
        try:
            verify_inventory_build_provenance(
                bound_raw[("build_provenance", "build_provenance")],
                artifact_class=artifact_class,
                driver_artifact_sha256=self.driver_artifact_sha256,
                exact_release_artifact_sha256=exact_release_sha256,
                parser_bundle_sha256=runtime["parser_bundle"].sha256,
                dependency_lock_sha256=runtime["dependency_lock"].sha256,
                interpreter_sha256=runtime["interpreter"].sha256,
            )
        except ValueError as exc:
            raise RuntimeError(
                f"Stage-C {scenario} artifact class/build provenance 非法"
            ) from exc
        for test in self.focused_security_tests:
            test.validate(
                artifact_root=artifact_root,
                driver_artifact_sha256=self.driver_artifact_sha256,
                parser_bundle_sha256=runtime["parser_bundle"].sha256,
                dependency_lock_sha256=runtime["dependency_lock"].sha256,
                interpreter_sha256=runtime["interpreter"].sha256,
            )

    def document(self) -> dict:
        return {
            "schema": self.schema,
            "driver_entrypoint": self.driver_entrypoint,
            "driver_artifact_sha256": self.driver_artifact_sha256,
            "adapter_manifest_sha256": self.adapter_manifest_sha256,
            "native_frame_schema_sha256": self.native_frame_schema_sha256,
            "collector_artifacts": [
                item.document() for item in self.collector_artifacts
            ],
            "systemd_unit_artifacts": [
                item.document() for item in self.systemd_unit_artifacts
            ],
            "iam_policy_artifacts": [
                item.document() for item in self.iam_policy_artifacts
            ],
            "worm_admission_artifacts": [
                item.document() for item in self.worm_admission_artifacts
            ],
            "build_provenance_artifacts": [
                item.document() for item in self.build_provenance_artifacts
            ],
            "runtime_identity_artifacts": [
                item.document() for item in self.runtime_identity_artifacts
            ],
            "trust_root_artifacts": [
                item.document() for item in self.trust_root_artifacts
            ],
            "focused_security_tests": [
                item.document() for item in self.focused_security_tests
            ],
            "production_raw_acquisition": self.production_raw_acquisition,
        }


@dataclass(frozen=True)
class ScenarioImplementationRecord:
    scenario: str
    artifact_class: str
    parser_ready: bool
    executor_shipped: bool
    implementation: ShippedImplementation | None = None

    def validate(
        self,
        *,
        required_source_roles: frozenset[str],
        expected_adapter_manifest_sha256: str,
        expected_native_frame_schema_sha256: str,
        artifact_root: Path,
    ) -> None:
        if (
            self.artifact_class
            not in {"exact_release_black_box", "instrumented_test_only"}
            or not self.parser_ready
        ):
            raise RuntimeError(
                f"Stage-C {self.scenario} inventory record 非法"
            )
        if self.executor_shipped:
            if self.implementation is None:
                raise RuntimeError(
                    f"Stage-C {self.scenario} 不能无 artifact binding 升级"
                )
            self.implementation.validate(
                scenario=self.scenario,
                artifact_class=self.artifact_class,
                required_source_roles=required_source_roles,
                expected_adapter_manifest_sha256=(
                    expected_adapter_manifest_sha256
                ),
                expected_native_frame_schema_sha256=(
                    expected_native_frame_schema_sha256
                ),
                artifact_root=artifact_root,
            )
        elif self.implementation is not None:
            raise RuntimeError(
                f"Stage-C {self.scenario} OPEN record 禁止携带假实现"
            )

    def document(self) -> dict:
        return {
            "scenario": self.scenario,
            "artifact_class": self.artifact_class,
            "parser_ready": self.parser_ready,
            "executor_shipped": self.executor_shipped,
            "implementation": (
                None
                if self.implementation is None
                else self.implementation.document()
            ),
        }


def _open(
    scenario: str,
    artifact_class: str,
) -> ScenarioImplementationRecord:
    return ScenarioImplementationRecord(
        scenario=scenario,
        artifact_class=artifact_class,
        parser_ready=True,
        executor_shipped=False,
    )


# Explicit entries prevent a parser registration or newly importable callable
# from silently changing production admissibility.
IMPLEMENTATION_RECORDS = (
    _open("backup-db-corruption", "exact_release_black_box"),
    _open("barrier-buy-intent-before-post", "instrumented_test_only"),
    _open("barrier-fill-before-projection", "instrumented_test_only"),
    _open("barrier-post-before-ack", "instrumented_test_only"),
    _open("clordid-conflict", "exact_release_black_box"),
    _open("external-fill", "exact_release_black_box"),
    _open("external-pending-buy", "exact_release_black_box"),
    _open("external-protection-cancel", "exact_release_black_box"),
    _open("frozen-balance", "exact_release_black_box"),
    _open("oco-active-process-death", "exact_release_black_box"),
    _open("rest-5xx-429-unknown", "exact_release_black_box"),
    _open("restart-while-ws-down", "exact_release_black_box"),
    _open("ws-partial-fill-recovery", "exact_release_black_box"),
)

# Five WP4/WP5 producers predate the native Stage-C protocol catalogue.  They
# are still first-class inventory entries: a repository producer is not a
# production executor, and keeping these entries outside the parser hash
# would make a nominal "18 scenarios" claim impossible to audit.  Their
# separate catalogue is intentionally not consumed by ``implemented_*`` or
# ``production_instrumented_*`` capability queries.
LEGACY_REPOSITORY_PRODUCER_SCENARIOS = (
    "restart-sigkill",
    "restart-sigterm",
    "ws-business",
    "ws-private",
    "ws-public",
)


def full_stage_c_inventory_document(
    expected_artifact_classes: dict[str, str],
    expected_source_roles: dict[str, frozenset[str]] | None = None,
    expected_adapter_manifest_sha256: dict[str, str] | None = None,
    expected_native_frame_schema_sha256: str = "",
    artifact_root: Path | None = None,
) -> dict:
    """Return the auditable 18-scenario inventory without promotion.

    The protocol inventory remains the parser/capability hash for the 13
    shipped-parser scenarios.  This view adds five legacy records, each bound
    to an explicit native contract and bridge schema, so review tooling can
    prove that all 18 named scenarios have an auditable record.  Legacy
    records have no shipped implementation binding and can never affect
    production capability decisions.
    """
    native = implementation_inventory_document(
        expected_artifact_classes,
        expected_source_roles,
        expected_adapter_manifest_sha256,
        expected_native_frame_schema_sha256,
        artifact_root,
    )
    # Resolve the legacy contracts lazily to avoid the protocol -> inventory
    # import cycle.  These bindings document the native bridge surface while
    # leaving executor_shipped false and outside the parser inventory digest.
    from okx_quant.ops.stage_c_chaos_protocol import (
        LEGACY_NATIVE_PROTOCOLS,
        driver_contract_document,
        required_source_roles,
    )

    legacy = [
        {
            "scenario": scenario,
            "artifact_class": "exact_release_black_box",
            "parser_ready": True,
            "executor_shipped": False,
            "implementation": None,
            "native_contract_sha256": hashlib.sha256(
                canonical_bytes(driver_contract_document(scenario))
            ).hexdigest(),
            "native_source_roles": sorted(required_source_roles(scenario)),
            "live_bridge": {
                "raw_collection_schema": (
                    "okx-quant.stage-c-external-raw-collection/v2"
                ),
                "signed_fragment_schema": (
                    "okx-quant.stage-c-external-signed-fragment/v1"
                ),
                "production_evidence": False,
            },
            "capability_state": "REPOSITORY_PRODUCER / EXTERNAL OPEN",
            "promotion_blockers": [
                "native_stage_c_protocol_not_registered",
                "production_executor_not_deployed",
                "deployment_attestation_missing",
            ],
        }
        for scenario in LEGACY_REPOSITORY_PRODUCER_SCENARIOS
        if scenario in LEGACY_NATIVE_PROTOCOLS
    ]
    records = [
        {**record, "capability_state": "PARSER_READY / EXTERNAL OPEN"}
        for record in native["records"]
    ] + legacy
    records.sort(key=lambda item: item["scenario"])
    expected = set(expected_artifact_classes) | set(
        LEGACY_REPOSITORY_PRODUCER_SCENARIOS
    )
    if {item["scenario"] for item in records} != expected:
        raise RuntimeError("Stage-C full inventory 未覆盖精确 18 场景")
    return {
        "schema": "okx-quant.stage-c-full-implementation-inventory/v1",
        "native_parser_inventory_sha256": hashlib.sha256(
            canonical_bytes(native)
        ).hexdigest(),
        "records": records,
        "scenario_count": len(records),
        "executor_shipped_scenarios": [],
        "production_instrumented_scenarios": [],
    }


def full_stage_c_inventory_sha256(
    expected_artifact_classes: dict[str, str],
    expected_source_roles: dict[str, frozenset[str]] | None = None,
    expected_adapter_manifest_sha256: dict[str, str] | None = None,
    expected_native_frame_schema_sha256: str = "",
    artifact_root: Path | None = None,
) -> str:
    return hashlib.sha256(
        canonical_bytes(
            full_stage_c_inventory_document(
                expected_artifact_classes,
                expected_source_roles,
                expected_adapter_manifest_sha256,
                expected_native_frame_schema_sha256,
                artifact_root,
            )
        )
    ).hexdigest()

# A complete artifact record is still only structural evidence.  Each future
# production executor additionally needs a scenario-specific semantic
# verifier that parses its driver/unit/IAM/test receipt and proves the actual
# fault contract.  The registry is intentionally empty while every scenario
# is OPEN.  Presence of files or syntactically valid 64-hex hashes can never
# populate this registry automatically.
_FROZEN_SEMANTIC_IMPLEMENTATION_VERIFIERS: Mapping[
    str,
    SemanticVerifierSpec,
] = MappingProxyType({})
SEMANTIC_IMPLEMENTATION_VERIFIERS = (
    _FROZEN_SEMANTIC_IMPLEMENTATION_VERIFIERS
)


def _semantic_implementation_verifiers(
    _registry: Mapping[str, SemanticVerifierSpec] = (
        _FROZEN_SEMANTIC_IMPLEMENTATION_VERIFIERS
    ),
) -> Mapping[str, SemanticVerifierSpec]:
    """Reject module-level registry replacement before any admission work."""
    if (
        SEMANTIC_IMPLEMENTATION_VERIFIERS is not _registry
        or _FROZEN_SEMANTIC_IMPLEMENTATION_VERIFIERS is not _registry
    ):
        raise RuntimeError("Stage-C semantic verifier registry 运行时漂移")
    return _registry


def _validate_semantic_verifier_result(
    value: object,
    *,
    scenario: str,
    verifier: SemanticVerifierSpec,
    implementation: ShippedImplementation,
) -> dict[str, object]:
    expected_keys = {
        "schema",
        "scenario",
        "verifier_id",
        "implementation_sha256",
        "checks",
        "passed",
    }
    implementation_sha256 = hashlib.sha256(
        canonical_bytes(implementation.document())
    ).hexdigest()
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value["schema"] != SEMANTIC_VERIFIER_RESULT_SCHEMA
        or value["scenario"] != scenario
        or value["verifier_id"] != verifier.verifier_id
        or value["implementation_sha256"] != implementation_sha256
        or value["passed"] is not True
        or not isinstance(value["checks"], dict)
        or set(value["checks"]) != set(REQUIRED_SEMANTIC_CHECKS)
        or any(check is not True for check in value["checks"].values())
    ):
        raise RuntimeError(
            f"Stage-C {scenario} semantic verifier result schema/closure 非法"
        )
    return value


def implementation_inventory_document(
    expected_artifact_classes: dict[str, str],
    expected_source_roles: dict[str, frozenset[str]] | None = None,
    expected_adapter_manifest_sha256: dict[str, str] | None = None,
    expected_native_frame_schema_sha256: str = "",
    artifact_root: Path | None = None,
) -> dict:
    semantic_verifiers = _semantic_implementation_verifiers()
    expected_names = set(expected_artifact_classes)
    if (
        expected_source_roles is not None
        and set(expected_source_roles) != expected_names
    ):
        raise RuntimeError(
            "Stage-C source role inventory 必须与协议场景精确一致"
        )
    if (
        expected_adapter_manifest_sha256 is not None
        and set(expected_adapter_manifest_sha256) != expected_names
    ):
        raise RuntimeError(
            "Stage-C adapter manifest inventory 必须与协议场景精确一致"
        )
    resolved_artifact_root = (
        Path(__file__).resolve().parents[1]
        if artifact_root is None
        else artifact_root.resolve()
    )
    records = tuple(IMPLEMENTATION_RECORDS)
    names = [record.scenario for record in records]
    if (
        names != sorted(names)
        or len(set(names)) != len(names)
        or set(names) != expected_names
    ):
        raise RuntimeError(
            "Stage-C implementation inventory 必须与协议场景精确一致"
        )
    for record in records:
        if (
            expected_artifact_classes[record.scenario]
            != record.artifact_class
        ):
            raise RuntimeError(
                f"Stage-C {record.scenario} artifact class 漂移"
            )
        record.validate(
            required_source_roles=(
                frozenset()
                if expected_source_roles is None
                else expected_source_roles[record.scenario]
            ),
            expected_adapter_manifest_sha256=(
                ""
                if expected_adapter_manifest_sha256 is None
                else expected_adapter_manifest_sha256[record.scenario]
            ),
            expected_native_frame_schema_sha256=(
                expected_native_frame_schema_sha256
            ),
            artifact_root=resolved_artifact_root,
        )
    shipped_names = {
        record.scenario for record in records if record.executor_shipped
    }
    if set(semantic_verifiers) != shipped_names:
        raise RuntimeError(
            "Stage-C semantic verifier registry 必须与 shipped 场景精确一致"
        )
    verifier_documents: list[dict[str, object]] = []
    for scenario in sorted(semantic_verifiers):
        verifier = semantic_verifiers[scenario]
        if verifier.scenario != scenario:
            raise RuntimeError("Stage-C semantic verifier scenario 串线")
        verifier.validate(artifact_root=resolved_artifact_root)
        verifier_documents.append(verifier.document())
    semantic_results: list[dict[str, object]] = []
    for record in records:
        if record.executor_shipped:
            verifier = semantic_verifiers.get(
                record.scenario
            )
            if verifier is None:
                raise RuntimeError(
                    f"Stage-C {record.scenario} 缺少场景语义 verifier，"
                    "禁止仅凭 blob/hash/test-id 晋级"
                )
            implementation = record.implementation
            if implementation is None:  # pragma: no cover - validated above
                raise RuntimeError("Stage-C shipped implementation 缺失")
            semantic_results.append(
                _validate_semantic_verifier_result(
                    verifier.verifier(
                        implementation,
                        resolved_artifact_root,
                    ),
                    scenario=record.scenario,
                    verifier=verifier,
                    implementation=implementation,
                )
            )
    verifier_registry_sha256 = hashlib.sha256(
        canonical_bytes(verifier_documents)
    ).hexdigest()
    return {
        "schema": IMPLEMENTATION_INVENTORY_SCHEMA,
        "semantic_verifier_registry_sha256": verifier_registry_sha256,
        "semantic_verifiers": verifier_documents,
        "semantic_results": semantic_results,
        "records": [record.document() for record in records],
    }


def implementation_inventory_sha256(
    expected_artifact_classes: dict[str, str],
    expected_source_roles: dict[str, frozenset[str]] | None = None,
    expected_adapter_manifest_sha256: dict[str, str] | None = None,
    expected_native_frame_schema_sha256: str = "",
    artifact_root: Path | None = None,
) -> str:
    return hashlib.sha256(
        canonical_bytes(
            implementation_inventory_document(
                expected_artifact_classes,
                expected_source_roles,
                expected_adapter_manifest_sha256,
                expected_native_frame_schema_sha256,
                artifact_root,
            )
        )
    ).hexdigest()


def shipped_scenarios(
    expected_artifact_classes: dict[str, str],
    expected_source_roles: dict[str, frozenset[str]] | None = None,
    expected_adapter_manifest_sha256: dict[str, str] | None = None,
    expected_native_frame_schema_sha256: str = "",
    artifact_root: Path | None = None,
) -> frozenset[str]:
    implementation_inventory_document(
        expected_artifact_classes,
        expected_source_roles,
        expected_adapter_manifest_sha256,
        expected_native_frame_schema_sha256,
        artifact_root,
    )
    return frozenset(
        record.scenario
        for record in IMPLEMENTATION_RECORDS
        if record.executor_shipped
    )


def production_instrumented_scenarios(
    expected_artifact_classes: dict[str, str],
    expected_source_roles: dict[str, frozenset[str]] | None = None,
    expected_adapter_manifest_sha256: dict[str, str] | None = None,
    expected_native_frame_schema_sha256: str = "",
    artifact_root: Path | None = None,
) -> frozenset[str]:
    implementation_inventory_document(
        expected_artifact_classes,
        expected_source_roles,
        expected_adapter_manifest_sha256,
        expected_native_frame_schema_sha256,
        artifact_root,
    )
    return frozenset(
        record.scenario
        for record in IMPLEMENTATION_RECORDS
        if (
            record.executor_shipped
            and record.artifact_class == "instrumented_test_only"
            and record.implementation is not None
            and record.implementation.production_raw_acquisition
        )
    )
