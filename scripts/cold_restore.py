#!/usr/bin/env python3
"""验证加密备份后原子安装交易库，并强制锁存 MAINTENANCE。"""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

if __package__:
    from scripts.restore_drill import decrypt, verify, verify_manifest
else:
    from restore_drill import decrypt, verify, verify_manifest


def _assert_trader_stopped() -> None:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", "okx-quant.service"],
        check=False,
        timeout=10,
    )
    if result.returncode == 0:
        raise RuntimeError(
            "okx-quant.service 仍在运行，拒绝替换交易数据库"
        )


def _latch_maintenance(database: Path, actor: str, source: Path) -> None:
    connection = sqlite3.connect(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT value FROM system_state WHERE key='mode_epoch'"
        ).fetchone()
        epoch = int(row[0]) if row else 0
        now = time.time()
        connection.execute(
            """
            INSERT INTO system_state(key, value, updated_at)
            VALUES('mode', 'maintenance', ?)
            ON CONFLICT(key) DO UPDATE SET
                value='maintenance', updated_at=excluded.updated_at
            """,
            (now,),
        )
        connection.execute(
            """
            INSERT INTO system_state(key, value, updated_at)
            VALUES('mode_epoch', ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value=excluded.value, updated_at=excluded.updated_at
            """,
            (str(epoch + 1), now),
        )
        connection.execute(
            """
            INSERT INTO system_events(
                event_id, event_name, severity, correlation_id,
                payload_json, created_at
            ) VALUES(?, 'cold_restore_installed', 'critical', '', ?, ?)
            """,
            (
                uuid.uuid4().hex,
                json.dumps({
                    "actor": actor,
                    "source": str(source),
                    "forced_mode": "maintenance",
                }, ensure_ascii=False),
                now,
            ),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _durable_copy(source: Path, destination: Path) -> None:
    source_stat = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(source_stat.st_mode):
        raise RuntimeError(f"cold restore 拒绝复制非普通文件: {source}")
    if destination.exists() or destination.is_symlink():
        raise RuntimeError(f"cold restore 旧库保留路径已存在: {destination}")
    shutil.copy2(source, destination)
    with destination.open("rb") as handle:
        os.fsync(handle.fileno())


def _checkpoint_database(database: Path, *, label: str) -> None:
    """Make a database self-contained before its inode is copied or moved."""
    connection = sqlite3.connect(
        f"{database.absolute().as_uri()}?mode=rw",
        uri=True,
    )
    try:
        row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if row is not None and int(row[0]) != 0:
            raise RuntimeError(f"{label}数据库 WAL checkpoint 被占用")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"{label}数据库在原子切换前完整性检查失败")
    finally:
        connection.close()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(database) + suffix)
        if sidecar.is_symlink():
            raise RuntimeError(f"cold restore 拒绝符号链接 sidecar: {sidecar}")
        if sidecar.exists():
            sidecar_stat = sidecar.lstat()
            if not stat.S_ISREG(sidecar_stat.st_mode):
                raise RuntimeError(
                    f"cold restore 拒绝非普通文件 sidecar: {sidecar}"
                )
            sidecar.unlink()
    _fsync_directory(database.parent)


def install_verified_database(
    candidate: Path,
    target: Path,
    *,
    actor: str,
    source: Path,
    replace_existing: bool,
    confirmation: str,
    expected_account_id: str,
    expected_schema_version: int,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> dict:
    if not actor.strip():
        raise ValueError("cold restore actor 不能为空")
    if (owner_uid is None) != (owner_gid is None):
        raise ValueError("owner_uid/owner_gid 必须同时提供")
    if owner_uid is not None and (owner_uid < 0 or owner_gid < 0):
        raise ValueError("owner uid/gid 不能为负")
    target = target.absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.is_symlink() or not target.parent.is_dir():
        raise RuntimeError("cold restore 拒绝符号链接或非目录目标父路径")
    if target.is_symlink() or candidate.is_symlink():
        raise RuntimeError("cold restore 拒绝符号链接数据库")
    if owner_uid is not None and owner_gid is not None:
        os.chown(target.parent, owner_uid, owner_gid)
        os.chmod(target.parent, 0o2750)
    existed = target.exists()
    expected_confirmation = (
        f"REPLACE {target} WITH ACCOUNT {expected_account_id}"
    )
    if existed and (
        not replace_existing or confirmation != expected_confirmation
    ):
        raise RuntimeError(
            "目标已存在；必须 --replace-existing 并输入精确确认词: "
            f"{expected_confirmation}"
        )
    _latch_maintenance(candidate, actor, source)
    verification = verify(
        candidate,
        expected_account_id=expected_account_id,
        expected_schema_version=expected_schema_version,
    )
    if not verification["database_ok"]:
        raise RuntimeError("候选数据库在 MAINTENANCE 锁存后复验失败")
    _checkpoint_database(candidate, label="候选")
    if owner_uid is not None and owner_gid is not None:
        os.chown(candidate, owner_uid, owner_gid)
    os.chmod(candidate, 0o640)
    with candidate.open("rb") as handle:
        os.fsync(handle.fileno())
    replaced_backup = ""
    if existed:
        _checkpoint_database(target, label="旧交易")
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        previous = target.with_name(
            f"{target.name}.pre-cold-restore-{stamp}-{uuid.uuid4().hex[:8]}"
        )
        # Preserve the old database while its canonical pathname remains live.
        # The only namespace switch is candidate -> target below, so any failure
        # before that point leaves the service's canonical database untouched.
        _durable_copy(target, previous)
        replaced_backup = str(previous)
        _fsync_directory(target.parent)
    os.replace(candidate, target)
    _fsync_directory(target.parent)
    installed = verify(
        target,
        expected_account_id=expected_account_id,
        expected_schema_version=expected_schema_version,
    )
    connection = sqlite3.connect(f"{target.as_uri()}?mode=ro", uri=True)
    try:
        mode = connection.execute(
            "SELECT value FROM system_state WHERE key='mode'"
        ).fetchone()[0]
    finally:
        connection.close()
    if not installed["database_ok"] or mode != "maintenance":
        raise RuntimeError("原子安装后验证失败或未保持 MAINTENANCE")
    target_stat = target.stat()
    if (
        target_stat.st_mode & 0o777 != 0o640
        or (
            owner_uid is not None
            and (
                target_stat.st_uid != owner_uid
                or target_stat.st_gid != owner_gid
            )
        )
    ):
        raise RuntimeError("原子安装后数据库 owner/mode 不符合要求")
    return {
        **installed,
        "installed": True,
        "target": str(target),
        "mode": mode,
        "replaced_backup": replaced_backup,
        "requires_read_only_reconciliation": True,
        "requires_signed_resume": True,
        "owner_uid": target_stat.st_uid,
        "owner_gid": target_stat.st_gid,
        "mode_bits": "0640",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("backup", type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-schema-version", type=int, default=9)
    parser.add_argument("--manifest-public-key", required=True, type=Path)
    parser.add_argument("--expected-signing-key-id", required=True)
    parser.add_argument("--expected-encryption-key-id", required=True)
    parser.add_argument(
        "--passphrase-env",
        default="OKX_QUANT_BACKUP_PASSPHRASE",
    )
    parser.add_argument("--actor", required=True)
    parser.add_argument("--owner-user", default="okxquant-trader")
    parser.add_argument("--owner-group", default="okxquant-data")
    parser.add_argument("--replace-existing", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    _assert_trader_stopped()
    owner_uid = pwd.getpwnam(args.owner_user).pw_uid
    owner_gid = grp.getgrnam(args.owner_group).gr_gid
    manifest = verify_manifest(
        args.backup,
        args.manifest_public_key,
    )
    if (
        manifest["account_id"] != args.expected_account_id
        or manifest["schema_version"] != args.expected_schema_version
        or manifest["signing_key_id"]
        != args.expected_signing_key_id
        or manifest["encryption_key_id"]
        != args.expected_encryption_key_id
    ):
        raise RuntimeError("备份 manifest 身份与 cold restore 目标不匹配")
    args.target.parent.mkdir(parents=True, exist_ok=True)
    if args.target.parent.is_symlink() or not args.target.parent.is_dir():
        raise RuntimeError("cold restore 拒绝符号链接或非目录目标父路径")
    temporary_dir = Path(tempfile.mkdtemp(
        prefix=".cold-restore-",
        dir=args.target.parent,
    ))
    try:
        candidate = temporary_dir / "candidate.db"
        decrypt(args.backup, candidate, args.passphrase_env)
        preflight = verify(
            candidate,
            expected_account_id=args.expected_account_id,
            expected_schema_version=args.expected_schema_version,
        )
        if not preflight["database_ok"]:
            raise RuntimeError("cold restore 候选数据库预检失败")
        result = install_verified_database(
            candidate,
            args.target,
            actor=args.actor,
            source=args.backup,
            replace_existing=args.replace_existing,
            confirmation=args.confirm,
            expected_account_id=args.expected_account_id,
            expected_schema_version=args.expected_schema_version,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
    finally:
        shutil.rmtree(temporary_dir)
    result["manifest_sha256"] = manifest["sha256"]
    result["completed_at"] = time.time()
    if args.output.exists():
        raise RuntimeError(f"拒绝覆盖 cold restore receipt: {args.output}")
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
