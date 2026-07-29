#!/usr/bin/env python3
# ruff: noqa: E402
"""Recompute the local Stage-C freeze identities.

This command is deliberately an evidence *builder*, not an admission switch.
It hashes the parser source, protocol inventory, deployment units, lock file
and interpreter that are present in the checkout.  A dirty checkout is
reported as ``candidate=false`` (and causes a non-zero exit unless
``--allow-dirty`` is used), so a hand-written JSON file cannot masquerade as a
release freeze.  Linux/systemd/IAM/WORM facts are intentionally not inferred.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

# When invoked as ``python scripts/recompute_stage_c_evidence.py``, Python
# puts only ``scripts/`` on sys.path.  Add the repository root before loading
# package modules so the documented CLI works without requiring PYTHONPATH.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from okx_quant.application.approval import canonical_bytes
from okx_quant.ops import stage_c_chaos_protocol as protocol

SCHEMA = "okx-quant.stage-c-freeze-report/v1"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def _file_digest(root: Path, relative: str) -> dict[str, object]:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"拒绝对非普通文件/符号链接计算 provenance: {relative}")
    raw = path.read_bytes()
    return {"path": relative, "bytes": len(raw), "sha256": _sha(raw)}


def _interpreter_digest() -> dict[str, object]:
    """Bind the report to the interpreter bytes actually executing it."""
    path = Path(sys.executable).resolve(strict=True)
    if not path.is_file():
        raise RuntimeError(f"解释器不是普通文件: {path}")
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": _sha(raw)}


def build_report(root: Path) -> dict[str, object]:
    root = root.resolve()
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    parser_manifest = protocol.PARSER_SOURCE_MANIFEST
    inventory = protocol.IMPLEMENTATION_INVENTORY
    inventory_sha = protocol.IMPLEMENTATION_INVENTORY_SHA256
    parser_manifest_sha = protocol.PARSER_MANIFEST_SHA256
    units = [
        _file_digest(root, path.as_posix())
        for path in sorted((root / "deploy").rglob("*.service"))
    ] + [
        _file_digest(root, path.as_posix())
        for path in sorted((root / "deploy").rglob("*.timer"))
    ]
    lock = _file_digest(root, "uv.lock")
    interpreter = _interpreter_digest()
    revision = _git(root, "rev-parse", "HEAD")
    source_identity = {
        "revision": revision,
        "parser_manifest_sha256": parser_manifest_sha,
        "implementation_inventory_sha256": inventory_sha,
        "uv_lock_sha256": lock["sha256"],
        "interpreter_sha256": interpreter["sha256"],
        "systemd_units_sha256": _sha(canonical_bytes(units)),
    }
    return {
        "schema": SCHEMA,
        "candidate": not bool(status),
        "git": {
            "revision": revision,
            "status_porcelain": status,
            "clean": not bool(status),
        },
        "runtime": {
            "python": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "interpreter": interpreter,
        },
        "parser": {
            "manifest": parser_manifest,
            "manifest_sha256": parser_manifest_sha,
            "implemented_stage_c_scenarios": sorted(
                protocol.implemented_stage_c_scenarios()
            ),
            "production_instrumented_stage_c_scenarios": sorted(
                protocol.production_instrumented_stage_c_scenarios()
            ),
        },
        "implementation_inventory": {
            "document": inventory,
            "sha256": inventory_sha,
            "executor_shipped": sorted(
                record["scenario"]
                for record in inventory["records"]
                if record["executor_shipped"]
            ),
        },
        "provenance": {
            "source_identity": source_identity,
            "uv_lock": lock,
            "systemd_units": units,
            "note": (
                "Source/lock/unit identities are recomputed locally. "
                "This report is not Linux deployment, IAM, WORM, or OKX evidence."
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="write a non-admitting report for a dirty checkout",
    )
    args = parser.parse_args()
    report = build_report(args.root)
    if not report["git"]["clean"] and not args.allow_dirty:
        raise SystemExit(
            "refusing freeze evidence from dirty checkout; use --allow-dirty "
            "only for a diagnostic report"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_bytes(report))
    print(json.dumps({
        "candidate": report["candidate"],
        "revision": report["git"]["revision"],
        "parser_manifest_sha256": report["parser"]["manifest_sha256"],
        "implementation_inventory_sha256": report["implementation_inventory"]["sha256"],
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
