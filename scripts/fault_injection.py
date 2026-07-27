#!/usr/bin/env python3
"""运行生产方案规定的自动化故障注入并生成审计证据。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CASES = [
    "tests/test_execution_coordinator.py",
    "tests/test_sqlite_journal.py",
    "tests/test_reconciliation.py",
    "tests/test_private_streams.py",
    "tests/test_protection.py",
    "tests/test_production_runtime.py",
    "tests/test_rest_retry_safety.py",
    "tests/test_timeout.py",
    "tests/test_failure_injection.py",
    "tests/test_operations.py",
]
PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def process_kill_during_transaction() -> dict:
    with tempfile.TemporaryDirectory(prefix="okx-fi-kill-") as directory:
        database = Path(directory) / "kill.db"
        connection = sqlite3.connect(database)
        connection.executescript(
            "CREATE TABLE facts(value TEXT);"
            "INSERT INTO facts(value) VALUES('committed');"
        )
        connection.commit()
        connection.close()
        code = (
            "import sqlite3,sys,time;"
            "c=sqlite3.connect(sys.argv[1]);"
            "c.execute('BEGIN IMMEDIATE');"
            "c.execute(\"UPDATE facts SET value='uncommitted'\");"
            "print('TRANSACTION_OPEN',flush=True);"
            "time.sleep(30)"
        )
        process = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", code, str(database)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready = process.stdout.readline().strip() if process.stdout else ""
        if ready != "TRANSACTION_OPEN":
            process.kill()
            raise RuntimeError("kill fixture 未进入开放事务")
        process.kill()
        process.wait(timeout=5)
        connection = sqlite3.connect(database)
        try:
            value = connection.execute(
                "SELECT value FROM facts"
            ).fetchone()[0]
            integrity = connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
        finally:
            connection.close()
        if value != "committed" or integrity != "ok":
            raise RuntimeError("SIGKILL 后事务原子性或完整性失败")
        return {
            "level": "os_process",
            "mechanism": "SIGKILL with open SQLite write transaction",
            "passed": True,
        }


def readonly_database_write() -> dict:
    with tempfile.TemporaryDirectory(prefix="okx-fi-readonly-") as directory:
        database = Path(directory) / "readonly.db"
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE facts(value TEXT)")
        connection.commit()
        connection.close()
        readonly = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
        try:
            try:
                readonly.execute("INSERT INTO facts VALUES('forbidden')")
            except sqlite3.OperationalError as exc:
                if "readonly" not in str(exc).lower():
                    raise
            else:
                raise RuntimeError("只读 SQLite URI 意外允许写入")
        finally:
            readonly.close()
        return {
            "level": "os_filesystem",
            "mechanism": "SQLite read-only file descriptor",
            "passed": True,
        }


def sqlite_full_write() -> dict:
    with tempfile.TemporaryDirectory(prefix="okx-fi-full-") as directory:
        database = Path(directory) / "full.db"
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA page_size=512")
            connection.execute("VACUUM")
            connection.execute("CREATE TABLE payload(value BLOB)")
            current_pages = int(
                connection.execute("PRAGMA page_count").fetchone()[0]
            )
            connection.execute(
                f"PRAGMA max_page_count={current_pages + 4}"
            )
            saw_full = False
            for _ in range(100):
                try:
                    connection.execute(
                        "INSERT INTO payload VALUES(randomblob(1024))"
                    )
                    connection.commit()
                except sqlite3.OperationalError as exc:
                    if "full" not in str(exc).lower():
                        raise
                    saw_full = True
                    connection.rollback()
                    break
            if not saw_full:
                raise RuntimeError("未触发真实 SQLITE_FULL")
            integrity = connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
            if integrity != "ok":
                raise RuntimeError("SQLITE_FULL 后数据库完整性失败")
        finally:
            connection.close()
        return {
            "level": "storage_engine",
            "mechanism": "SQLite max_page_count / SQLITE_FULL",
            "passed": True,
        }


def socket_response_blackhole() -> dict:
    client, blackhole = socket.socketpair()
    try:
        client.settimeout(0.05)
        client.sendall(b"POST /trade HTTP/1.1\r\n\r\n")
        try:
            client.recv(1)
        except TimeoutError:
            pass
        else:
            raise RuntimeError("socket 黑洞未触发读取超时")
    finally:
        client.close()
        blackhole.close()
    return {
        "level": "os_network",
        "mechanism": "kernel socket peer accepts bytes but never responds",
        "passed": True,
    }


def run_system_faults() -> list[dict]:
    return [
        process_kill_during_transaction(),
        readonly_database_write(),
        sqlite_full_write(),
        socket_response_blackhole(),
    ]


def _source_manifest_files() -> list[Path]:
    files = [
        PROJECT_ROOT / "main.py",
        PROJECT_ROOT / "pyproject.toml",
        PROJECT_ROOT / "uv.lock",
        PROJECT_ROOT / ".coveragerc-core",
    ]
    for relative_root in (
        ".github/workflows",
        "deploy",
        "okx_quant",
        "scripts",
        "tests",
    ):
        root = PROJECT_ROOT / relative_root
        files.extend(
            path
            for path in root.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    unique = {path.relative_to(PROJECT_ROOT).as_posix(): path for path in files}
    return [unique[label] for label in sorted(unique)]


def _source_manifest_hash() -> str:
    digest = hashlib.sha256()
    for path in _source_manifest_files():
        label = path.relative_to(PROJECT_ROOT).as_posix()
        digest.update(label.encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def verify_evidence_artifact(evidence_path: Path, revision_file: Path) -> dict:
    if (
        not evidence_path.is_file()
        or evidence_path.is_symlink()
        or not revision_file.is_file()
        or revision_file.is_symlink()
    ):
        raise RuntimeError("故障注入 evidence/REVISION 必须是非符号链接普通文件")
    revision = revision_file.read_text(encoding="ascii").strip().lower()
    if not _SHA1.fullmatch(revision):
        raise RuntimeError("REVISION 必须是完整 40 位提交 SHA")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    required = {
        "started_at",
        "completed_at",
        "git_commit",
        "git_tree_hash",
        "workspace_clean",
        "source_manifest_sha256",
        "system_fault_cases",
        "semantic_fault_cases",
        "exit_code",
    }
    if not isinstance(evidence, dict) or not required <= set(evidence):
        raise RuntimeError("故障注入 evidence 结构不完整")
    system_cases = evidence["system_fault_cases"]
    if (
        evidence["exit_code"] != 0
        or evidence["workspace_clean"] is not True
        or str(evidence["git_commit"]).lower() != revision
        or not _SHA1.fullmatch(str(evidence["git_tree_hash"]).lower())
        or evidence["semantic_fault_cases"] != CASES
        or not isinstance(system_cases, list)
        or {item.get("level") for item in system_cases}
        != {"os_process", "os_filesystem", "storage_engine", "os_network"}
        or not all(item.get("passed") is True for item in system_cases)
    ):
        raise RuntimeError("故障注入 evidence 未通过或未绑定当前发布提交")
    expected_manifest = _source_manifest_hash()
    recorded_manifest = str(evidence["source_manifest_sha256"]).lower()
    if (
        not _SHA256.fullmatch(recorded_manifest)
        or recorded_manifest != expected_manifest
    ):
        raise RuntimeError("故障注入 evidence 未绑定当前发布源码/测试 manifest")
    started_at = evidence["started_at"]
    completed_at = evidence["completed_at"]
    if (
        isinstance(started_at, bool)
        or isinstance(completed_at, bool)
        or not isinstance(started_at, (int, float))
        or not isinstance(completed_at, (int, float))
        or completed_at < started_at
    ):
        raise RuntimeError("故障注入 evidence 时间链非法")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("fault-injection.json"))
    parser.add_argument("--verify-evidence", type=Path)
    parser.add_argument("--revision-file", type=Path, default=Path("REVISION"))
    args = parser.parse_args()
    if args.verify_evidence is not None:
        evidence = verify_evidence_artifact(
            args.verify_evidence,
            args.revision_file,
        )
        print(json.dumps({
            "verified": True,
            "git_commit": evidence["git_commit"],
            "git_tree_hash": evidence["git_tree_hash"],
            "source_manifest_sha256": evidence["source_manifest_sha256"],
        }, ensure_ascii=False))
        return 0
    if args.output.exists():
        raise RuntimeError(f"拒绝覆盖既有故障注入证据: {args.output}")
    started = time.time()
    system_cases = run_system_faults()
    process = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *CASES],
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        tree_hash = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        workspace_clean = not subprocess.run(
            ["git", "status", "--porcelain"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
    except Exception:
        commit = "unknown"
        tree_hash = "unknown"
        workspace_clean = False
    evidence = {
        "started_at": started,
        "completed_at": time.time(),
        "git_commit": commit,
        "git_tree_hash": tree_hash,
        "workspace_clean": workspace_clean,
        "source_manifest_sha256": _source_manifest_hash(),
        "system_fault_cases": system_cases,
        "semantic_fault_cases": CASES,
        "cases": CASES,
        "exit_code": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if not workspace_clean:
        return 3
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
