#!/usr/bin/env python3
"""Sign independent Stage-C source fragments and assemble native JSONL."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from okx_quant.ops.stage_c_chaos_protocol import (
    verify_stage_c_challenge,
)
from okx_quant.ops.stage_c_external_bridge import (
    assemble_external_raw_jsonl,
    build_external_signed_fragment,
)
from okx_quant.ops.stage_c_native_collectors import (
    assert_current_process_matches_workload,
)


def _safe_bytes(path: Path, *, label: str, limit: int = 8 * 1024 * 1024) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= limit
        ):
            raise ValueError(f"{label} 必须是安全普通文件")
        raw = b""
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"{label} 短读")
            raw += chunk
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"{label} 读取期间增长")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError(f"{label} 读取期间被替换/修改")
        return raw
    finally:
        os.close(descriptor)


def _json(path: Path, *, label: str) -> dict:
    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label} JSON key 重复: {key}")
            value[key] = item
        return value

    value = json.loads(
        _safe_bytes(path, label=label),
        object_pairs_hook=reject_duplicates,
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是 JSON object")
    return value


def _assignments(values: list[str], *, label: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for raw in values:
        role, separator, path = raw.partition("=")
        if (
            not separator
            or not role.strip()
            or not path.strip()
            or role in result
        ):
            raise ValueError(f"{label} assignment 非法/重复: {raw}")
        result[role] = Path(path)
    return result


def _wait_paths(paths: list[Path], *, seconds: float, label: str) -> None:
    if not 0 <= seconds <= 600:
        raise ValueError("Stage-C signer input wait 必须位于 0..600 秒")
    deadline = time.monotonic() + seconds
    while not all(path.is_file() and not path.is_symlink() for path in paths):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Stage-C signer 等待 {label} 超时")
        time.sleep(0.1)


def _exclusive(path: Path, raw: bytes, *, mode: int = 0o640) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"拒绝覆盖 Stage-C signer output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
            dir_fd=parent,
        )
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Stage-C signer output 短写")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


def _add_common_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--challenge", required=True, type=Path)
    parser.add_argument("--registrar-public-key", required=True, type=Path)
    parser.add_argument(
        "--collection",
        action="append",
        default=[],
        metavar="SOURCE_ROLE=PATH",
    )
    parser.add_argument(
        "--acquirer-public-key",
        action="append",
        default=[],
        metavar="ACQUIRER_ROLE=PATH",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--input-wait-seconds", type=float, default=0)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    sign = sub.add_parser("sign-fragment")
    _add_common_inputs(sign)
    sign.add_argument("--source-role", required=True)
    sign.add_argument("--source-private-key", required=True, type=Path)

    assemble = sub.add_parser("assemble")
    _add_common_inputs(assemble)
    assemble.add_argument("--consumption-receipt", required=True, type=Path)
    assemble.add_argument("--consumer-public-key", required=True, type=Path)
    assemble.add_argument(
        "--capability-authority-public-key",
        required=True,
        type=Path,
    )
    assemble.add_argument(
        "--fragment",
        action="append",
        default=[],
        metavar="SOURCE_ROLE=PATH",
    )
    assemble.add_argument(
        "--source-public-key",
        action="append",
        default=[],
        metavar="ROLE=PATH",
    )
    args = parser.parse_args()

    collection_paths = _assignments(
        args.collection,
        label="raw collection",
    )
    fragment_paths = (
        _assignments(args.fragment, label="signed fragment")
        if args.command == "assemble"
        else {}
    )
    wait_paths = [args.challenge, *collection_paths.values()]
    if args.command == "assemble":
        wait_paths.extend([
            args.consumption_receipt,
            *fragment_paths.values(),
        ])
    _wait_paths(
        wait_paths,
        seconds=args.input_wait_seconds,
        label="challenge/collection/fragment",
    )
    challenge_artifact = _json(args.challenge, label="registrar challenge")
    scenario = str(challenge_artifact.get("payload", {}).get("scenario", ""))
    challenge = verify_stage_c_challenge(
        challenge_artifact,
        registrar_public_key=args.registrar_public_key,
        scenario=scenario,
        now=None,
        enforce_current_window=(args.command == "sign-fragment"),
    )
    collections = {
        role: _json(path, label=f"raw collection {role}")
        for role, path in collection_paths.items()
    }
    acquirer_public_keys = _assignments(
        args.acquirer_public_key,
        label="acquirer public key",
    )
    if args.command == "sign-fragment":
        assert_current_process_matches_workload(
            challenge["workloads"][args.source_role]
        )
        fragment = build_external_signed_fragment(
            source_role=args.source_role,
            collections=collections,
            challenge=challenge,
            acquirer_public_keys=acquirer_public_keys,
            source_private_key=args.source_private_key,
        )
        _exclusive(
            args.output,
            (
                json.dumps(
                    fragment,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                    allow_nan=False,
                )
                + "\n"
            ).encode(),
        )
        return 0

    assert_current_process_matches_workload(
        challenge["workloads"]["parser_signer"]
    )
    raw = assemble_external_raw_jsonl(
        challenge_artifact=challenge_artifact,
        consumption_receipt=_json(
            args.consumption_receipt,
            label="consumption receipt",
        ),
        registrar_public_key=args.registrar_public_key,
        consumer_public_key=args.consumer_public_key,
        capability_authority_public_key=(
            args.capability_authority_public_key
        ),
        collections=collections,
        fragments={
            role: _json(path, label=f"signed fragment {role}")
            for role, path in fragment_paths.items()
        },
        source_public_keys=_assignments(
            args.source_public_key,
            label="source public key",
        ),
        acquirer_public_keys=acquirer_public_keys,
    )
    _exclusive(args.output, raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
