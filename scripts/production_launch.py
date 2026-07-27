#!/usr/bin/env python3
"""Validate one root-controlled launch manifest, then exec that exact live argv."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from okx_quant.config import ProductionSettings, load_yaml

if __package__:
    from scripts.deployment_receipt import validate_deployment_receipt
    from scripts.launch_manifest import load_launch_manifest
    from scripts.production_gate import (
        _actual_runtime_identity,
        _runtime_python_executable,
    )
else:
    from deployment_receipt import validate_deployment_receipt
    from launch_manifest import load_launch_manifest
    from production_gate import (
        _actual_runtime_identity,
        _runtime_python_executable,
    )

_load_launch_manifest = load_launch_manifest


def _live_argv(
    executable: Path,
    config: Path,
    launch: dict,
    *,
    safety_only: bool = False,
) -> list[str]:
    argv = [
        str(executable),
        str(Path(__file__).resolve().parents[1] / "main.py"),
        "--config",
        str(config),
        "live",
        "--inst",
        ",".join(launch["instruments"]),
        "--strategy",
        launch["strategy"],
        "--bar",
        launch["bar"],
        "--interval",
        str(int(launch["interval_seconds"])),
        "--no-dashboard",
        "--yes",
    ]
    if safety_only:
        argv.append("--safety-only")
    return argv


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--release-commit-file", required=True, type=Path)
    parser.add_argument("--launch-manifest", required=True, type=Path)
    parser.add_argument("--identity-only", action="store_true")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--approval-public-key", type=Path)
    args = parser.parse_args()
    safety_only = False
    try:
        launch = _load_launch_manifest(args.launch_manifest)
        identity = _actual_runtime_identity(
            config_path=args.config,
            release_commit_file=args.release_commit_file,
            strategy=launch["strategy"],
            bar=launch["bar"],
            instruments=launch["instruments"],
            interval=float(launch["interval_seconds"]),
        )
    except Exception as exc:
        if args.identity_only:
            raise
        settings = ProductionSettings.from_config(
            load_yaml(str(args.config)),
            require_credentials=False,
            require_external_controls=False,
        )
        launch = {
            "strategy": "ma_cross",
            "bar": "1H",
            "instruments": list(settings.allowed_instruments[:1]),
            "interval_seconds": 60,
        }
        if not launch["instruments"]:
            raise RuntimeError("safety-only 启动也缺少 allowed instrument") from exc
        identity = {}
        safety_only = True
        print(
            f"launch identity 不可验证，降级 safety-only: {exc}",
            file=sys.stderr,
        )
    if args.identity_only:
        print(json.dumps(identity, ensure_ascii=False, indent=2))
        return 0
    required = (
        args.receipt,
        args.evidence,
        args.approval,
        args.approval_public_key,
    )
    if any(value is None for value in required):
        raise ValueError("生产启动缺少 durable deployment receipt 参数")
    if not safety_only:
        try:
            validate_deployment_receipt(
                args.receipt,
                identity=identity,
                approval_path=args.approval,
                approval_public_key=args.approval_public_key,
                evidence_path=args.evidence,
            )
        except Exception as exc:
            safety_only = True
            print(
                f"deployment receipt 不可验证，降级 safety-only: {exc}",
                file=sys.stderr,
            )
    executable, _, _ = _runtime_python_executable()
    main_entry = Path(__file__).resolve().parents[1] / "main.py"
    main_stat = main_entry.lstat()
    if (
        not stat.S_ISREG(main_stat.st_mode)
        or main_entry.is_symlink()
        or main_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise RuntimeError("受控 production main.py 缺失或权限不安全")
    argv = _live_argv(
        executable,
        args.config,
        launch,
        safety_only=safety_only,
    )
    os.execv(executable, argv)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
