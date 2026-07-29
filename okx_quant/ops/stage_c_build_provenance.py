"""Recomputable provenance for Stage-C instrumented barrier artifacts.

The build attestor is not trusted to summarize whether a hook is present.
Instead, the Stage-C parser receives the exact instrumented and production
archives, expands their complete file indexes, recomputes both SBOMs and
manifests, and inspects the production Python AST for test-harness imports or
activation symbols.
"""

from __future__ import annotations

import ast
import base64
import csv
import hashlib
import io
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

from okx_quant.application.approval import canonical_bytes

BUILD_MANIFEST_SCHEMA = "okx-quant.stage-c-build-manifest/v1"
SBOM_SCHEMA = "okx-quant.stage-c-file-sbom/v1"
INSTRUMENTED_ARTIFACT_CLASS = "instrumented_test_only"
EXACT_ARTIFACT_CLASS = "exact_release_black_box"
TEST_HARNESS_PREFIX = "stage_c_test_harness/"
TEST_HARNESS_MODULE = "stage_c_test_harness"
INSTRUMENTED_ENTRYPOINT = "__main__.py"
INSTRUMENTED_HOOK_MODULE = "stage_c_test_harness/barriers.py"
INSTRUMENTED_PIPELINE_MODULE = "stage_c_test_harness/pipeline.py"
INSTRUMENTED_RECOVERY_MODULE = "stage_c_test_harness/recovery.py"
INSTRUMENTED_TLS_PROXY_MODULE = "stage_c_test_harness/tls_ack_proxy.py"
INSTRUMENTED_TRANSFORM_MEMBERS = frozenset({
    "okx_quant/application/demo_probe.py",
    "okx_quant/infrastructure/okx/streams.py",
})
INSTRUMENTED_ONLY_MEMBERS = frozenset({
    "__main__.py",
    "stage_c_test_harness/__init__.py",
    "stage_c_test_harness/barriers.py",
    "stage_c_test_harness/cli.py",
    "stage_c_test_harness/native_events.py",
    INSTRUMENTED_PIPELINE_MODULE,
    INSTRUMENTED_RECOVERY_MODULE,
    INSTRUMENTED_TLS_PROXY_MODULE,
})
INSTRUMENTED_MAIN = (
    b"from stage_c_test_harness.cli import main\n"
    b"raise SystemExit(main())\n"
)
REQUIRED_EXACT_MEMBERS = frozenset({
    "main.py",
    "okx_quant/__init__.py",
    "okx_quant/config.py",
    *INSTRUMENTED_TRANSFORM_MEMBERS,
})
PRODUCTION_FORBIDDEN_SYMBOLS = frozenset({
    "BarrierReached",
    "BarrierStore",
    "arm_barrier",
    "reach_barrier",
})
PRODUCTION_FORBIDDEN_ENABLE_KEYS = frozenset({
    "OKX_QUANT_STAGE_C_BARRIER",
    "stage_c_barrier_hook",
})
BUILD_RECEIPT_SCHEMA = "okx-quant.hermetic-wheel-build/v1"
DEPENDENCY_LOCK_SCHEMA = "okx-quant.wheel-lock/v1"
INVENTORY_BUILD_PROVENANCE_SCHEMA = (
    "okx-quant.stage-c-inventory-build-provenance/v1"
)
BUILD_RECEIPT_PATH = "okx_quant_build/build-receipt.json"
DEPENDENCY_LOCK_PATH = "okx_quant_build/dependency-lock.json"
_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_WHEEL_HASH = re.compile(r"sha256=[A-Za-z0-9_-]{43}")
_MANIFEST_KEYS = {
    "schema",
    "artifact_class",
    "artifact_build_id",
    "artifact_sha256",
    "source_manifest_sha256",
    "file_index_sha256",
    "instrumented_delta_sha256",
    "sbom_sha256",
    "entrypoint",
    "hook_module",
    "hook_sha256",
    "exact_release_excludes_test_harness",
}
_INVENTORY_BUILD_PROVENANCE_KEYS = {
    "schema",
    "artifact_class",
    "artifact_build_id",
    "driver_artifact_sha256",
    "exact_release_artifact_sha256",
    "parser_bundle_sha256",
    "dependency_lock_sha256",
    "interpreter_sha256",
    "source_manifest_sha256",
    "test_hooks_present",
    "exact_release_excludes_test_harness",
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_inventory_build_provenance(
    raw: bytes,
    *,
    artifact_class: str,
    driver_artifact_sha256: str,
    exact_release_artifact_sha256: str,
    parser_bundle_sha256: str,
    dependency_lock_sha256: str,
    interpreter_sha256: str,
) -> dict[str, object]:
    """Validate the immutable build identity used by implementation inventory.

    This receipt is deliberately narrower than the live barrier provenance
    proof.  It freezes the complete parser bundle, dependency lock and Python
    interpreter identities and prevents an exact-release executor from being
    represented by a test-hook build (or vice versa).  Scenario semantic
    verifiers must additionally inspect the bound driver/unit/IAM bytes.
    """
    value = _canonical_json(raw, label="Stage-C inventory build provenance")
    if (
        set(value) != _INVENTORY_BUILD_PROVENANCE_KEYS
        or value["schema"] != INVENTORY_BUILD_PROVENANCE_SCHEMA
        or value["artifact_class"] != artifact_class
        or value["driver_artifact_sha256"] != driver_artifact_sha256
        or value["exact_release_artifact_sha256"]
        != exact_release_artifact_sha256
        or value["parser_bundle_sha256"] != parser_bundle_sha256
        or value["dependency_lock_sha256"] != dependency_lock_sha256
        or value["interpreter_sha256"] != interpreter_sha256
        or any(
            not _SHA256.fullmatch(str(value[key]))
            for key in (
                "driver_artifact_sha256",
                "exact_release_artifact_sha256",
                "parser_bundle_sha256",
                "dependency_lock_sha256",
                "interpreter_sha256",
                "source_manifest_sha256",
            )
        )
        or not isinstance(value["artifact_build_id"], str)
    ):
        raise ValueError("Stage-C inventory build provenance 身份绑定非法")
    if artifact_class == EXACT_ARTIFACT_CLASS:
        valid_class = (
            value["artifact_build_id"].startswith("exact-release:")
            and value["test_hooks_present"] is False
            and value["exact_release_excludes_test_harness"] is True
            and exact_release_artifact_sha256 == driver_artifact_sha256
        )
    elif artifact_class == INSTRUMENTED_ARTIFACT_CLASS:
        valid_class = (
            value["artifact_build_id"].startswith("test-only:")
            and value["test_hooks_present"] is True
            and value["exact_release_excludes_test_harness"] is False
            and exact_release_artifact_sha256 != driver_artifact_sha256
        )
    else:
        valid_class = False
    if not valid_class:
        raise ValueError("Stage-C inventory artifact class/build provenance 非法")
    return value


def instrument_stage_c_member(name: str, raw: bytes) -> bytes:
    """Apply one reviewed source transform to an exact production member.

    The transform is intentionally byte based and rejects missing, duplicate,
    or already-instrumented anchors.  Admission recomputes this function from
    the exact-release archive, so a build signer cannot substitute a broader
    monkeypatch or an arbitrary replacement module.
    """
    if name not in INSTRUMENTED_TRANSFORM_MEMBERS:
        raise ValueError(f"Stage-C member 不在 transform allowlist: {name}")
    if b"stage_c_test_harness" in raw:
        raise ValueError("exact-release source 已含 Stage-C harness")
    if name == "okx_quant/application/demo_probe.py":
        import_anchor = (
            b"from okx_quant.infrastructure.db import JournalRepository\n"
        )
        import_delta = (
            import_anchor
            + b"from stage_c_test_harness.pipeline import "
            + b"reach_pipeline_boundary\n"
        )
        boundary_anchor = (
            b"        row = self._transition(\n"
            b"            row,\n"
            b"            ProbeState.BUY_SUBMITTING,\n"
            b"            owner=owner,\n"
            b"            fencing_token=fencing_token,\n"
            b"        )\n"
            b"        try:\n"
        )
        boundary_delta = (
            boundary_anchor.removesuffix(b"        try:\n")
            + b"        reach_pipeline_boundary(\n"
            + b'            "buy-intent-before-post",\n'
            + b"            journal=self.journal,\n"
            + b"            probe_row=row,\n"
            + b"        )\n"
            + b"        try:\n"
        )
    else:
        import_anchor = (
            b"from okx_quant.infrastructure.db import JournalRepository\n"
        )
        import_delta = (
            import_anchor
            + b"from stage_c_test_harness.pipeline import "
            + b"reach_pipeline_boundary\n"
        )
        boundary_anchor = (
            b"                update = map_order_event(row)\n"
            b"            except Exception as exc:\n"
        )
        boundary_delta = (
            b"                update = map_order_event(row)\n"
            b"                reach_pipeline_boundary(\n"
            b'                    "fill-before-projection",\n'
            b"                    journal=self.journal,\n"
            b"                    exchange_order=update,\n"
            b"                    raw_event=row,\n"
            b"                )\n"
            b"            except Exception as exc:\n"
        )
    for anchor, label in (
        (import_anchor, "import"),
        (boundary_anchor, "boundary"),
    ):
        if raw.count(anchor) != 1:
            raise ValueError(
                f"Stage-C {name} {label} anchor 必须精确出现一次"
            )
    transformed = raw.replace(import_anchor, import_delta, 1)
    transformed = transformed.replace(boundary_anchor, boundary_delta, 1)
    if transformed == raw:
        raise ValueError("Stage-C source transform 未产生差异")
    ast.parse(transformed, filename=name)
    return transformed


def _safe_member_name(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"Stage-C archive member path 非法: {name!r}")
    return path.as_posix()


def _archive_files(raw: bytes, *, label: str) -> dict[str, bytes]:
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise ValueError(f"{label} 必须是 1..2MiB zip archive")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"{label} 不是合法 zip archive") from exc
    files: dict[str, bytes] = {}
    total = 0
    with archive:
        if len(archive.infolist()) > 2_000:
            raise ValueError(f"{label} member 数过多")
        for info in archive.infolist():
            name = _safe_member_name(info.filename)
            if info.is_dir():
                continue
            mode = info.external_attr >> 16
            if mode and not stat.S_ISREG(mode):
                raise ValueError(f"{label} 含非普通文件: {name}")
            if name in files:
                raise ValueError(f"{label} 含重复 member: {name}")
            if info.file_size > 512 * 1024:
                raise ValueError(f"{label} 单个 member 过大: {name}")
            total += info.file_size
            if total > 6 * 1024 * 1024:
                raise ValueError(f"{label} 解压后超过 6MiB")
            files[name] = archive.read(info)
    if not files:
        raise ValueError(f"{label} 为空")
    return files


def _file_index(files: dict[str, bytes]) -> list[dict[str, object]]:
    return [
        {"path": name, "sha256": _sha(files[name]), "bytes": len(files[name])}
        for name in sorted(files)
    ]


def _is_allowed_exact_member(name: str, *, record_path: str) -> bool:
    if name == "main.py":
        return True
    if name.startswith("okx_quant/") and name.endswith(".py"):
        return True
    if name in {BUILD_RECEIPT_PATH, DEPENDENCY_LOCK_PATH}:
        return True
    dist_info = record_path.removesuffix("/RECORD")
    if not name.startswith(f"{dist_info}/"):
        return False
    leaf = name.removeprefix(f"{dist_info}/")
    return (
        leaf in {
            "METADATA",
            "WHEEL",
            "RECORD",
            "entry_points.txt",
            "top_level.txt",
        }
        or leaf.startswith("licenses/")
    )


def _record_hash(raw: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return "sha256=" + digest.rstrip(b"=").decode("ascii")


def _verify_wheel_record(files: dict[str, bytes]) -> None:
    record_paths = [
        name for name in files if name.endswith(".dist-info/RECORD")
    ]
    if len(record_paths) != 1:
        raise ValueError("exact-release wheel 必须含唯一 RECORD")
    record_path = record_paths[0]
    if any(
        not _is_allowed_exact_member(name, record_path=record_path)
        for name in files
    ):
        raise ValueError("exact-release wheel member 不在严格 allowlist")
    try:
        rows = list(csv.reader(io.StringIO(files[record_path].decode())))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ValueError("exact-release RECORD 非法") from exc
    if any(len(row) != 3 for row in rows):
        raise ValueError("exact-release RECORD row schema 非法")
    recorded: dict[str, tuple[str, str]] = {}
    for raw_name, digest, size in rows:
        name = _safe_member_name(raw_name)
        if name in recorded:
            raise ValueError("exact-release RECORD member 重复")
        recorded[name] = (digest, size)
    if set(recorded) != set(files):
        raise ValueError("exact-release RECORD 未覆盖全部成员")
    for name, raw in files.items():
        digest, size = recorded[name]
        if name == record_path:
            if digest or size:
                raise ValueError("RECORD 自身 row 必须为空 hash/size")
            continue
        if (
            not _WHEEL_HASH.fullmatch(digest)
            or digest != _record_hash(raw)
            or size != str(len(raw))
        ):
            raise ValueError(f"exact-release RECORD hash/size 不匹配: {name}")


def _verify_dependency_lock(raw: bytes) -> str:
    value = _canonical_json(raw, label="dependency wheel lock")
    if (
        set(value) != {"schema", "lock_sha256", "wheels"}
        or value["schema"] != DEPENDENCY_LOCK_SCHEMA
        or not isinstance(value["wheels"], list)
        or not value["wheels"]
    ):
        raise ValueError("dependency wheel lock schema 非法")
    names: set[str] = set()
    normalized: list[dict] = []
    for wheel in value["wheels"]:
        if (
            not isinstance(wheel, dict)
            or set(wheel) != {"name", "version", "filename", "sha256"}
            or not str(wheel["name"]).strip()
            or not str(wheel["version"]).strip()
            or not str(wheel["filename"]).endswith(".whl")
            or not _SHA256.fullmatch(str(wheel["sha256"]))
            or str(wheel["name"]).lower() in names
        ):
            raise ValueError("dependency wheel lock entry 非法/重复")
        names.add(str(wheel["name"]).lower())
        normalized.append(wheel)
    expected_lock = _sha(canonical_bytes(normalized))
    if value["lock_sha256"] != expected_lock:
        raise ValueError("dependency wheel lock digest 不可重算")
    return expected_lock


def _verify_build_receipt(
    raw: bytes,
    *,
    identity: dict,
    dependency_lock_sha256: str,
) -> None:
    value = _canonical_json(raw, label="hermetic build receipt")
    if (
        set(value)
        != {
            "schema",
            "git_commit",
            "git_tree_hash",
            "builder_image_digest",
            "dependency_lock_sha256",
            "build_command",
            "source_date_epoch",
        }
        or value["schema"] != BUILD_RECEIPT_SCHEMA
        or not _SHA1.fullmatch(str(value["git_commit"]))
        or not _SHA1.fullmatch(str(value["git_tree_hash"]))
        or not re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            str(value["builder_image_digest"]),
        )
        or value["dependency_lock_sha256"] != dependency_lock_sha256
        or value["build_command"]
        != ["python", "-m", "build", "--wheel", "--no-isolation"]
        or type(value["source_date_epoch"]) is not int
        or value["source_date_epoch"] <= 0
        or value["git_commit"] != identity["git_commit"]
        or value["git_tree_hash"] != identity["git_tree_hash"]
    ):
        raise ValueError("hermetic build signer receipt 非法/未绑定 release")


def build_sbom_bytes(
    files: dict[str, bytes],
    *,
    artifact_class: str,
) -> bytes:
    return canonical_bytes({
        "schema": SBOM_SCHEMA,
        "artifact_class": artifact_class,
        "files": _file_index(files),
    })


def build_manifest_bytes(
    archive_raw: bytes,
    *,
    artifact_class: str,
    artifact_build_id: str,
    entrypoint: str,
    hook_module: str | None,
    shared_production_files: dict[str, bytes] | None = None,
) -> tuple[bytes, bytes]:
    """Build canonical manifest and SBOM from exact archive bytes."""
    files = _archive_files(archive_raw, label=artifact_class)
    file_index = _file_index(files)
    production_files = (
        files if shared_production_files is None else shared_production_files
    )
    production_index = _file_index(production_files)
    delta_index = [
        item
        for item in file_index
        if (
            item["path"] not in production_files
            or files[item["path"]] != production_files[item["path"]]
        )
    ]
    sbom = build_sbom_bytes(files, artifact_class=artifact_class)
    hook_sha = _sha(files[hook_module]) if hook_module is not None else None
    manifest = {
        "schema": BUILD_MANIFEST_SCHEMA,
        "artifact_class": artifact_class,
        "artifact_build_id": artifact_build_id,
        "artifact_sha256": _sha(archive_raw),
        "source_manifest_sha256": _sha(canonical_bytes(production_index)),
        "file_index_sha256": _sha(canonical_bytes(file_index)),
        "instrumented_delta_sha256": (
            _sha(canonical_bytes(delta_index))
            if shared_production_files is not None
            else None
        ),
        "sbom_sha256": _sha(sbom),
        "entrypoint": entrypoint,
        "hook_module": hook_module,
        "hook_sha256": hook_sha,
        "exact_release_excludes_test_harness": (
            artifact_class == EXACT_ARTIFACT_CLASS
        ),
    }
    return canonical_bytes(manifest), sbom


def _canonical_json(raw: bytes, *, label: str) -> dict:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} 非法 JSON") from exc
    if (
        not isinstance(value, dict)
        or canonical_bytes(value) != raw
    ):
        raise ValueError(f"{label} 必须是 canonical JSON object")
    return value


def _assert_no_production_hook(files: dict[str, bytes]) -> None:
    _verify_wheel_record(files)
    if any(
        name.startswith(TEST_HARNESS_PREFIX)
        or name.startswith("scripts/stage_c_barrier")
        or name.endswith((".so", ".pth", ".dylib", ".dll"))
        or PurePosixPath(name).name
        in {"sitecustomize.py", "usercustomize.py"}
        or "plugin" in PurePosixPath(name).name.lower()
        for name in files
    ):
        raise ValueError("exact-release archive 偷渡 hook/native/plugin")
    for name, raw in files.items():
        if not name.endswith(".py"):
            continue
        try:
            tree = ast.parse(raw, filename=name)
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise ValueError(f"exact-release Python AST 非法: {name}") from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
                if any(
                    module == TEST_HARNESS_MODULE
                    or module.startswith(f"{TEST_HARNESS_MODULE}.")
                    for module in modules
                ):
                    raise ValueError("exact-release import test harness")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if (
                    module == TEST_HARNESS_MODULE
                    or module.startswith(f"{TEST_HARNESS_MODULE}.")
                ):
                    raise ValueError("exact-release import test harness")
            elif isinstance(node, ast.Name):
                if node.id in PRODUCTION_FORBIDDEN_SYMBOLS:
                    raise ValueError("exact-release 含 barrier hook symbol")
            elif isinstance(node, ast.Attribute):
                if node.attr in PRODUCTION_FORBIDDEN_SYMBOLS:
                    raise ValueError("exact-release 含 barrier hook attribute")
            elif isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "builtins"
                ):
                    call_name = node.func.attr
                if call_name in {"eval", "exec", "compile"}:
                    raise ValueError("exact-release 含动态 code execution")
                if (
                    call_name in {"getenv", "get"}
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value
                    in PRODUCTION_FORBIDDEN_ENABLE_KEYS
                ):
                    raise ValueError("exact-release 读取 production hook enable key")
                if call_name in {"import_module", "__import__"}:
                    if not node.args:
                        raise ValueError("exact-release dynamic import 无目标")
                    target = node.args[0]
                    allowed = (
                        isinstance(target, ast.Constant)
                        and isinstance(target.value, str)
                        and (
                            target.value.startswith("okx_quant.")
                            or target.value
                            in {
                                "os",
                                "time",
                            }
                        )
                    )
                    if isinstance(target, ast.JoinedStr):
                        prefix = "".join(
                            value.value
                            for value in target.values
                            if isinstance(value, ast.Constant)
                            and isinstance(value.value, str)
                        )
                        allowed = prefix.startswith("okx_quant.")
                    if not allowed:
                        raise ValueError(
                            "exact-release 含非 allowlist dynamic import"
                        )
            elif (
                isinstance(node, ast.Subscript)
                and isinstance(node.slice, ast.Constant)
                and node.slice.value in PRODUCTION_FORBIDDEN_ENABLE_KEYS
            ):
                raise ValueError("exact-release 索引 production hook enable key")


def _assert_instrumented_delta(
    instrumented: dict[str, bytes],
    exact: dict[str, bytes],
) -> None:
    extras = set(instrumented) - set(exact)
    missing = set(exact) - set(instrumented)
    if extras != set(INSTRUMENTED_ONLY_MEMBERS) or missing:
        raise ValueError(
            "instrumented/exact-release 仅允许固定 harness member 差异"
        )
    for name, raw in exact.items():
        expected = (
            instrument_stage_c_member(name, raw)
            if name in INSTRUMENTED_TRANSFORM_MEMBERS
            else raw
        )
        if instrumented[name] != expected:
            raise ValueError(
                f"instrumented archive member 超出固定 transform: {name}"
            )
    if instrumented[INSTRUMENTED_ENTRYPOINT] != INSTRUMENTED_MAIN:
        raise ValueError("instrumented zipapp entrypoint 非固定 CLI")
    for name in INSTRUMENTED_ONLY_MEMBERS:
        raw = instrumented[name]
        if name.endswith(".py"):
            try:
                tree = ast.parse(raw, filename=name)
            except (SyntaxError, UnicodeDecodeError) as exc:
                raise ValueError(f"instrumented Python AST 非法: {name}") from exc
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_name = ""
                    if isinstance(node.func, ast.Name):
                        call_name = node.func.id
                    elif (
                        isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "builtins"
                    ):
                        call_name = node.func.attr
                    if call_name in {
                        "eval",
                        "exec",
                        "compile",
                        "__import__",
                    }:
                        raise ValueError(
                            "instrumented harness 含通用 Python 旁路"
                        )
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and node.value == "PYTHONPATH"
                ):
                    raise ValueError("instrumented harness 允许 PYTHONPATH 注入")


def verify_build_provenance(
    *,
    instrumented_archive: bytes,
    instrumented_manifest: bytes,
    instrumented_sbom: bytes,
    exact_release_archive: bytes,
    exact_release_manifest: bytes,
    exact_release_sbom: bytes,
    identity: dict,
    executable_sha256: str,
) -> dict[str, str | bool]:
    """Recompute both builds and prove the production artifact has no hook."""
    if instrumented_archive == exact_release_archive:
        raise ValueError("instrumented/exact-release artifact 不得相同")
    instrumented_files = _archive_files(
        instrumented_archive,
        label="instrumented artifact",
    )
    exact_files = _archive_files(
        exact_release_archive,
        label="exact-release artifact",
    )
    if (
        INSTRUMENTED_ENTRYPOINT not in instrumented_files
        or INSTRUMENTED_HOOK_MODULE not in instrumented_files
    ):
        raise ValueError("instrumented artifact 缺少固定 entrypoint/hook")
    if not REQUIRED_EXACT_MEMBERS.issubset(exact_files):
        raise ValueError("exact-release artifact 缺少生产入口/配置")
    _assert_no_production_hook(exact_files)
    _assert_instrumented_delta(instrumented_files, exact_files)
    dependency_lock_sha256 = _verify_dependency_lock(
        exact_files[DEPENDENCY_LOCK_PATH]
    )
    _verify_build_receipt(
        exact_files[BUILD_RECEIPT_PATH],
        identity=identity,
        dependency_lock_sha256=dependency_lock_sha256,
    )

    expected_instrumented_manifest, expected_instrumented_sbom = (
        build_manifest_bytes(
            instrumented_archive,
            artifact_class=INSTRUMENTED_ARTIFACT_CLASS,
            artifact_build_id=str(identity["artifact_build_id"]),
            entrypoint=INSTRUMENTED_ENTRYPOINT,
            hook_module=INSTRUMENTED_HOOK_MODULE,
            shared_production_files=exact_files,
        )
    )
    exact_claims = _canonical_json(
        exact_release_manifest,
        label="exact-release manifest",
    )
    if set(exact_claims) != _MANIFEST_KEYS:
        raise ValueError("exact-release manifest schema 非法")
    expected_exact_manifest, expected_exact_sbom = build_manifest_bytes(
        exact_release_archive,
        artifact_class=EXACT_ARTIFACT_CLASS,
        artifact_build_id=str(exact_claims["artifact_build_id"]),
        entrypoint="main.py",
        hook_module=None,
    )
    if (
        instrumented_manifest != expected_instrumented_manifest
        or instrumented_sbom != expected_instrumented_sbom
        or exact_release_manifest != expected_exact_manifest
        or exact_release_sbom != expected_exact_sbom
    ):
        raise ValueError("Stage-C build manifest/SBOM 无法从 archive 重算")

    instrumented_claims = _canonical_json(
        instrumented_manifest,
        label="instrumented manifest",
    )
    if (
        set(instrumented_claims) != _MANIFEST_KEYS
        or instrumented_claims["artifact_class"]
        != INSTRUMENTED_ARTIFACT_CLASS
        or exact_claims["artifact_class"] != EXACT_ARTIFACT_CLASS
        or instrumented_claims["source_manifest_sha256"]
        != exact_claims["source_manifest_sha256"]
        or not _SHA256.fullmatch(
            str(instrumented_claims["instrumented_delta_sha256"])
        )
        or exact_claims["instrumented_delta_sha256"] is not None
        or instrumented_claims["exact_release_excludes_test_harness"]
        is not False
        or exact_claims["exact_release_excludes_test_harness"] is not True
        or identity["test_hooks_present"] is not True
        or not str(identity["artifact_build_id"]).startswith("test-only:")
        or identity["artifact_sha256"] != _sha(instrumented_archive)
        or identity["source_manifest_sha256"]
        != instrumented_claims["source_manifest_sha256"]
        or executable_sha256 != _sha(instrumented_archive)
    ):
        raise ValueError("instrumented build identity/executable 未绑定原始 artifact")
    return {
        "instrumented_artifact_sha256": _sha(instrumented_archive),
        "exact_release_artifact_sha256": _sha(exact_release_archive),
        "source_manifest_sha256": str(
            instrumented_claims["source_manifest_sha256"]
        ),
        "sbom_sha256": _sha(instrumented_sbom),
        "hook_sha256": _sha(
            instrumented_files[INSTRUMENTED_HOOK_MODULE]
        ),
        "production_hook_absent": True,
        "dependency_lock_sha256": dependency_lock_sha256,
    }


def deterministic_zip(files: dict[str, bytes]) -> bytes:
    """Create a byte-stable zip used by the isolated build pipeline/tests."""
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name in sorted(files):
            safe_name = _safe_member_name(name)
            info = zipfile.ZipInfo(safe_name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, files[name])
    return output.getvalue()


def exact_release_wheel(
    files: dict[str, bytes],
    *,
    dist_info: str = "okx_quant-1.0.0.dist-info",
) -> bytes:
    """Add a complete RECORD and return a deterministic exact-release wheel."""
    if any(name.endswith(".dist-info/RECORD") for name in files):
        raise ValueError("caller 不得预置 RECORD")
    rows = [
        [name, _record_hash(raw), str(len(raw))]
        for name, raw in sorted(files.items())
    ]
    record_path = f"{dist_info}/RECORD"
    rows.append([record_path, "", ""])
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerows(rows)
    return deterministic_zip({
        **files,
        record_path: buffer.getvalue().encode(),
    })


def archive_tree(
    root: Path,
    *,
    members: list[Path],
) -> bytes:
    files: dict[str, bytes] = {}
    root = root.resolve()
    for path in members:
        resolved = path.resolve()
        try:
            name = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("build member 必须位于 source root") from exc
        if not resolved.is_file() or resolved.is_symlink():
            raise ValueError(f"build member 非普通文件: {name}")
        files[name] = resolved.read_bytes()
    return deterministic_zip(files)
