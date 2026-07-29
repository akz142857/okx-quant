#!/usr/bin/env python3
"""Build the isolated Stage-C instrumented zipapp and recomputable manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from okx_quant.application.approval import canonical_bytes
from okx_quant.ops.stage_c_build_provenance import (
    BUILD_RECEIPT_PATH,
    BUILD_RECEIPT_SCHEMA,
    DEPENDENCY_LOCK_PATH,
    EXACT_ARTIFACT_CLASS,
    INSTRUMENTED_ARTIFACT_CLASS,
    INSTRUMENTED_ENTRYPOINT,
    INSTRUMENTED_HOOK_MODULE,
    INSTRUMENTED_MAIN,
    INSTRUMENTED_TRANSFORM_MEMBERS,
    build_manifest_bytes,
    deterministic_zip,
    exact_release_wheel,
    instrument_stage_c_member,
    verify_build_provenance,
)

_HARNESS_MEMBERS = (
    Path("stage_c_test_harness/__init__.py"),
    Path("stage_c_test_harness/barriers.py"),
    Path("stage_c_test_harness/cli.py"),
    Path("stage_c_test_harness/native_events.py"),
    Path("stage_c_test_harness/pipeline.py"),
    Path("stage_c_test_harness/recovery.py"),
    Path("stage_c_test_harness/tls_ack_proxy.py"),
)


def _write_new(path: Path, raw: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_file(path: Path, *, label: str) -> bytes:
    if (
        not path.is_file()
        or path.is_symlink()
        or not 0 < path.stat().st_size <= 2 * 1024 * 1024
    ):
        raise ValueError(f"{label} 非安全普通文件")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise ValueError(f"{label} 必须是 canonical JSON object")
    return raw


def _production_files(
    source_root: Path,
    *,
    dependency_lock: bytes,
    build_receipt: bytes,
) -> dict[str, bytes]:
    package_root = source_root / "okx_quant"
    if (
        not package_root.is_dir()
        or package_root.is_symlink()
        or not (source_root / "main.py").is_file()
        or (source_root / "main.py").is_symlink()
    ):
        raise ValueError("production source root/main.py 类型非法")
    members = [
        source_root / "main.py",
        *sorted(package_root.rglob("*.py")),
    ]
    if not members or any(
        not path.is_file() or path.is_symlink()
        for path in members
    ):
        raise ValueError("production source 含缺失/symlink Python member")
    files = {
        path.relative_to(source_root).as_posix(): path.read_bytes()
        for path in members
    }
    files.update({
        DEPENDENCY_LOCK_PATH: dependency_lock,
        BUILD_RECEIPT_PATH: build_receipt,
        "okx_quant-1.0.0.dist-info/METADATA": (
            b"Metadata-Version: 2.4\nName: okx-quant\nVersion: 1.0.0\n"
        ),
        "okx_quant-1.0.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: stage-c-hermetic-builder\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "okx_quant-1.0.0.dist-info/entry_points.txt": (
            b"[console_scripts]\nokx-quant = main:main\n"
        ),
        "okx_quant-1.0.0.dist-info/top_level.txt": b"okx_quant\n",
    })
    return files


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--git-commit", required=True)
    parser.add_argument("--git-tree-hash", required=True)
    parser.add_argument("--builder-image-digest", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--dependency-lock", type=Path, required=True)
    parser.add_argument("--artifact-build-id", required=True)
    parser.add_argument("--exact-output", type=Path, required=True)
    parser.add_argument("--instrumented-output", type=Path, required=True)
    parser.add_argument("--exact-manifest-output", type=Path, required=True)
    parser.add_argument(
        "--instrumented-manifest-output",
        type=Path,
        required=True,
    )
    parser.add_argument("--exact-sbom-output", type=Path, required=True)
    parser.add_argument(
        "--instrumented-sbom-output",
        type=Path,
        required=True,
    )
    parser.add_argument("--identity-output", type=Path, required=True)
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    dependency_lock = _canonical_file(
        args.dependency_lock,
        label="dependency lock",
    )
    dependency_value = json.loads(dependency_lock)
    build_receipt = canonical_bytes({
        "schema": BUILD_RECEIPT_SCHEMA,
        "git_commit": args.git_commit,
        "git_tree_hash": args.git_tree_hash,
        "builder_image_digest": args.builder_image_digest,
        "dependency_lock_sha256": dependency_value["lock_sha256"],
        "build_command": [
            "python",
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
        ],
        "source_date_epoch": args.source_date_epoch,
    })
    production_files = _production_files(
        source_root,
        dependency_lock=dependency_lock,
        build_receipt=build_receipt,
    )
    exact = exact_release_wheel(production_files)
    exact_files = dict(production_files)
    # Re-open through the verifier-friendly archive helper by using RECORD
    # from the completed wheel, then add only the fixed harness delta.
    import zipfile
    from io import BytesIO

    with zipfile.ZipFile(BytesIO(exact)) as archive:
        exact_files = {
            info.filename: archive.read(info)
            for info in archive.infolist()
            if not info.is_dir()
        }
    instrumented_files = dict(exact_files)
    for name in INSTRUMENTED_TRANSFORM_MEMBERS:
        instrumented_files[name] = instrument_stage_c_member(
            name,
            exact_files[name],
        )
    instrumented_files["__main__.py"] = INSTRUMENTED_MAIN
    for relative in _HARNESS_MEMBERS:
        source = source_root / relative
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"缺少 harness member: {relative}")
        instrumented_files[relative.as_posix()] = source.read_bytes()
    instrumented = deterministic_zip(instrumented_files)

    exact_manifest, exact_sbom = build_manifest_bytes(
        exact,
        artifact_class=EXACT_ARTIFACT_CLASS,
        artifact_build_id="exact-release:stage-c-base",
        entrypoint="main.py",
        hook_module=None,
    )
    instrumented_manifest, instrumented_sbom = build_manifest_bytes(
        instrumented,
        artifact_class=INSTRUMENTED_ARTIFACT_CLASS,
        artifact_build_id=args.artifact_build_id,
        entrypoint=INSTRUMENTED_ENTRYPOINT,
        hook_module=INSTRUMENTED_HOOK_MODULE,
        shared_production_files=exact_files,
    )
    instrumented_claims = json.loads(instrumented_manifest)
    identity = {
        "git_commit": args.git_commit,
        "git_tree_hash": args.git_tree_hash,
        "source_manifest_sha256": instrumented_claims[
            "source_manifest_sha256"
        ],
        "artifact_sha256": hashlib.sha256(instrumented).hexdigest(),
        "artifact_build_id": args.artifact_build_id,
        "test_hooks_present": True,
    }
    verify_build_provenance(
        instrumented_archive=instrumented,
        instrumented_manifest=instrumented_manifest,
        instrumented_sbom=instrumented_sbom,
        exact_release_archive=exact,
        exact_release_manifest=exact_manifest,
        exact_release_sbom=exact_sbom,
        identity=identity,
        executable_sha256=identity["artifact_sha256"],
    )
    outputs = (
        (args.exact_output, exact, 0o640),
        (args.instrumented_output, instrumented, 0o750),
        (args.exact_manifest_output, exact_manifest, 0o640),
        (
            args.instrumented_manifest_output,
            instrumented_manifest,
            0o640,
        ),
        (args.exact_sbom_output, exact_sbom, 0o640),
        (args.instrumented_sbom_output, instrumented_sbom, 0o640),
        (args.identity_output, canonical_bytes(identity) + b"\n", 0o640),
    )
    for path, raw, mode in outputs:
        _write_new(path, raw, mode=mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
