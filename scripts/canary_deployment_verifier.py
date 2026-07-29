#!/usr/bin/env python3
"""Independently inspect and sign the exact Canary systemd deployment."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import time
import uuid
from pathlib import Path

from okx_quant.infrastructure.evidence import sign_ed25519_payload
from okx_quant.research.canary import (
    canary_readiness_id,
    identity_sha256,
    verify_transition,
)
from okx_quant.research.demo_soak import (
    canary_source_producer_inventory_sha256,
)

MAX_BYTES = 16 * 1024 * 1024


def _secure_bytes(path: Path, maximum: int = MAX_BYTES) -> bytes:
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_size <= 0
        or info.st_size > maximum
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError(f"不安全或超限文件: {path}")
    return path.read_bytes()


def _sha256(path: Path) -> str:
    return hashlib.sha256(_secure_bytes(path)).hexdigest()


def _systemd_property(unit: str, name: str) -> str:
    return subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            f"--property={name}",
            "--value",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip()


def _groups(user: str) -> tuple[int, set[int]]:
    account = pwd.getpwnam(user)
    gids = {account.pw_gid}
    gids.update(
        row.gr_gid
        for row in grp.getgrall()
        if user in row.gr_mem
    )
    return account.pw_uid, gids


def _allowed(
    info: os.stat_result,
    *,
    uid: int,
    gids: set[int],
    operation: str,
) -> bool:
    shift = 6 if uid == info.st_uid else 3 if info.st_gid in gids else 0
    mask = {"read": 4, "write": 2}[operation] << shift
    return bool(stat.S_IMODE(info.st_mode) & mask)


def _execution() -> dict:
    unit = "okx-quant-canary-deployment-verifier.service"
    invocation = os.environ.get("INVOCATION_ID", "").lower()
    cgroup = next(
        (
            row.partition("::")[2]
            for row in Path("/proc/self/cgroup").read_text().splitlines()
            if "::" in row
            and row.partition("::")[2].endswith(f"/{unit}")
        ),
        "",
    )
    mount_namespace = os.readlink("/proc/self/ns/mnt")
    if (
        not re.fullmatch(r"[0-9a-f]{32}", invocation)
        or not cgroup.startswith("/system.slice/")
        or not re.fullmatch(
            r"mnt:\[[1-9][0-9]*\]",
            mount_namespace,
        )
    ):
        raise RuntimeError("deployment verifier 必须由预期 systemd unit 启动")
    return {
        "verifier_unix_user": pwd.getpwuid(os.getuid()).pw_name,
        "verifier_uid": os.getuid(),
        "verifier_systemd_unit": unit,
        "verifier_invocation_id": invocation,
        "verifier_cgroup": cgroup,
        "boot_id": Path(
            "/proc/sys/kernel/random/boot_id"
        ).read_text().strip(),
        "mount_namespace_id": mount_namespace,
    }


def _producer_unit_claim(
    name: str,
    item: dict,
    *,
    collector_executable: Path,
    signer_executable: Path,
    parser_path: Path,
    capability_user: str,
) -> dict:
    collector_fragment = Path(
        _systemd_property(item["collector_systemd_unit"], "FragmentPath")
    )
    signer_fragment = Path(
        _systemd_property(item["signer_systemd_unit"], "FragmentPath")
    )
    collector_exec = _systemd_property(
        item["collector_systemd_unit"],
        "ExecStart",
    )
    signer_exec = _systemd_property(
        item["signer_systemd_unit"],
        "ExecStart",
    )
    collector_user = _systemd_property(
        item["collector_systemd_unit"],
        "User",
    )
    signer_user = _systemd_property(
        item["signer_systemd_unit"],
        "User",
    )
    if (
        str(collector_executable) not in collector_exec
        or str(signer_executable) not in signer_exec
        or str(parser_path) not in signer_exec
        or collector_user != item["collector_unix_user"]
        or signer_user != item["signer_unix_user"]
    ):
        raise ValueError(f"{name} systemd ExecStart/User 未绑定冻结 inventory")
    collector_hash = _sha256(collector_executable)
    signer_hash = _sha256(signer_executable)
    parser_hash = _sha256(parser_path)
    if (
        collector_hash != item["collector_executable_sha256"]
        or signer_hash != item["signer_executable_sha256"]
        or parser_hash != item["parser_sha256"]
    ):
        raise ValueError(f"{name} executable/parser hash 未绑定冻结 release")
    raw_file = Path(item["raw_source_path"])
    signed_file = Path(item["artifact_output_path"])
    raw_directory = raw_file.parent
    signed_directory = signed_file.parent
    raw_dir_info = raw_directory.stat()
    raw_info = raw_file.stat()
    signed_dir_info = signed_directory.stat()
    signed_info = signed_file.stat()
    collector_uid, collector_gids = _groups(collector_user)
    signer_uid, signer_gids = _groups(signer_user)
    capability_uid, capability_gids = _groups(capability_user)
    probe = {
        "collector_can_write_raw_directory": _allowed(
            raw_dir_info,
            uid=collector_uid,
            gids=collector_gids,
            operation="write",
        ),
        "signer_can_read_raw_artifact": _allowed(
            raw_info,
            uid=signer_uid,
            gids=signer_gids,
            operation="read",
        ),
        "signer_can_write_raw_artifact": _allowed(
            raw_info,
            uid=signer_uid,
            gids=signer_gids,
            operation="write",
        ),
        "signer_can_write_signed_directory": _allowed(
            signed_dir_info,
            uid=signer_uid,
            gids=signer_gids,
            operation="write",
        ),
        "capability_can_read_signed_artifact": _allowed(
            signed_info,
            uid=capability_uid,
            gids=capability_gids,
            operation="read",
        ),
        "capability_can_write_signed_artifact": _allowed(
            signed_info,
            uid=capability_uid,
            gids=capability_gids,
            operation="write",
        ),
        "raw_directory_mode": f"{stat.S_IMODE(raw_dir_info.st_mode):04o}",
        "raw_artifact_mode": f"{stat.S_IMODE(raw_info.st_mode):04o}",
        "signed_directory_mode": (
            f"{stat.S_IMODE(signed_dir_info.st_mode):04o}"
        ),
        "signed_artifact_mode": (
            f"{stat.S_IMODE(signed_info.st_mode):04o}"
        ),
    }
    expected_probe = {
        "collector_can_write_raw_directory": True,
        "signer_can_read_raw_artifact": True,
        "signer_can_write_raw_artifact": False,
        "signer_can_write_signed_directory": True,
        "capability_can_read_signed_artifact": True,
        "capability_can_write_signed_artifact": False,
        "raw_directory_mode": "0750",
        "raw_artifact_mode": "0640",
        "signed_directory_mode": "0750",
        "signed_artifact_mode": "0640",
    }
    if probe != expected_probe:
        raise ValueError(f"{name} Unix permission probe 未达到隔离契约")
    return {
        "producer_name": name,
        "collector_systemd_unit": item["collector_systemd_unit"],
        "collector_fragment_path": str(collector_fragment),
        "collector_fragment_sha256": _sha256(collector_fragment),
        "collector_exec_start_sha256": hashlib.sha256(
            collector_exec.encode()
        ).hexdigest(),
        "collector_executable_sha256": collector_hash,
        "collector_user": collector_user,
        "signer_systemd_unit": item["signer_systemd_unit"],
        "signer_fragment_path": str(signer_fragment),
        "signer_fragment_sha256": _sha256(signer_fragment),
        "signer_exec_start_sha256": hashlib.sha256(
            signer_exec.encode()
        ).hexdigest(),
        "signer_executable_sha256": signer_hash,
        "signer_user": signer_user,
        "parser_sha256": parser_hash,
        "permission_probe": probe,
    }


def _atomic_new(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"拒绝覆盖: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o640,
    )
    try:
        try:
            raw = (
                json.dumps(value, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode()
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError(
                        "deployment verifier write 无进展"
                    )
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY,
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            directory_descriptor = os.open(
                path.parent,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transition", required=True, type=Path)
    parser.add_argument("--operator-public-key", required=True, type=Path)
    parser.add_argument("--risk-public-key", required=True, type=Path)
    parser.add_argument("--host-image-sha256", required=True, type=Path)
    parser.add_argument("--collector-executable", required=True, type=Path)
    parser.add_argument("--signer-executable", required=True, type=Path)
    parser.add_argument("--parser", required=True, type=Path)
    parser.add_argument(
        "--capability-user",
        default="oqc-capability",
    )
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    transition = verify_transition(
        json.loads(_secure_bytes(args.transition)),
        operator_public_key=args.operator_public_key,
        risk_public_key=args.risk_public_key,
    )
    inventory = transition["source_producer_inventory"]
    target = transition["target_deployment_identity"]
    inventory_sha256 = canary_source_producer_inventory_sha256(
        inventory
    )
    host_image = _secure_bytes(
        args.host_image_sha256,
        256,
    ).decode().strip()
    if host_image != target["host_image_sha256"]:
        raise ValueError("deployment verifier host image 未绑定 target")
    units = {
        name: _producer_unit_claim(
            name,
            item,
            collector_executable=args.collector_executable,
            signer_executable=args.signer_executable,
            parser_path=args.parser,
            capability_user=args.capability_user,
        )
        for name, item in inventory.items()
    }
    systemd_version = subprocess.run(
        ["/usr/bin/systemctl", "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.splitlines()[0]
    claims = {
        "version": 1,
        "action": "attest-canary-deployment-units",
        "verifier_id": f"deployment-{uuid.uuid4().hex}",
        "readiness_id": canary_readiness_id(
            demo_soak_epoch_id=transition["demo_soak_epoch_id"],
            target_deployment_identity_sha256=identity_sha256(target),
            source_producer_inventory_sha256=inventory_sha256,
        ),
        "release_identity_sha256": identity_sha256(
            transition["release_identity"]
        ),
        "config_sha256": target["config_sha256"],
        "account_uid": target["account_uid"],
        "demo_soak_epoch_id": transition["demo_soak_epoch_id"],
        "target_deployment_identity_sha256": identity_sha256(target),
        "transition_sha256": identity_sha256(transition),
        "source_producer_inventory_sha256": inventory_sha256,
        **_execution(),
        "host_image_sha256": host_image,
        "systemd_version": systemd_version,
        "verifier_executable_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "producer_units": units,
        "observed_at": int(time.time()),
        "nonce": uuid.uuid4().hex,
    }
    _secure_bytes(args.private_key, 64 * 1024)
    _atomic_new(
        args.output,
        sign_ed25519_payload(claims, args.private_key),
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
