#!/usr/bin/env python3
"""Download the just-published immutable S3 versions and restore-verify them."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

from main import load_env_file


def _version_id(bucket: str, key: str) -> str:
    result = subprocess.run(
        [
            "aws",
            "s3api",
            "head-object",
            "--bucket",
            bucket,
            "--key",
            key,
            "--output",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    version_id = str(json.loads(result.stdout).get("VersionId", ""))
    if not version_id or version_id == "null":
        raise RuntimeError("S3 bucket 必须启用 versioning 并返回 VersionId")
    return version_id


def _download_version(
    bucket: str,
    key: str,
    version_id: str,
    destination: Path,
) -> None:
    subprocess.run(
        [
            "aws",
            "s3api",
            "get-object",
            "--bucket",
            bucket,
            "--key",
            key,
            "--version-id",
            version_id,
            str(destination),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup-env", required=True, type=Path)
    parser.add_argument("--local-backup-dir", required=True, type=Path)
    parser.add_argument("--manifest-public-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    load_env_file(str(args.backup_env))
    stale_temporary_cutoff = time.time() - 3600
    for temporary in args.local_backup_dir.glob(".offsite-restore-*"):
        if temporary.stat().st_mtime < stale_temporary_cutoff:
            if temporary.is_dir() and not temporary.is_symlink():
                shutil.rmtree(temporary)
            else:
                temporary.unlink(missing_ok=True)
    required_env = {
        key: os.environ.get(key, "")
        for key in (
            "OKX_QUANT_ACCOUNT_ID",
            "OKX_QUANT_OFFSITE_BACKUP_URI",
            "OKX_QUANT_BACKUP_PASSPHRASE",
            "OKX_QUANT_BACKUP_SIGNING_KEY_ID",
            "OKX_QUANT_BACKUP_ENCRYPTION_KEY_ID",
        )
    }
    missing = [key for key, value in required_env.items() if not value]
    if missing:
        raise RuntimeError(f"offsite restore check 缺少环境变量: {missing}")
    ready = sorted(
        args.local_backup_dir.glob("trading-*.db.enc.manifest.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not ready:
        raise RuntimeError("没有刚发布的本地 signed backup manifest")
    manifest_path = ready[0]
    archive_name = manifest_path.name.removesuffix(".manifest.json")
    parsed = urlparse(required_env["OKX_QUANT_OFFSITE_BACKUP_URI"])
    if parsed.scheme != "s3" or not parsed.netloc:
        raise RuntimeError("OKX_QUANT_OFFSITE_BACKUP_URI 必须是 s3:// URI")
    prefix = parsed.path.strip("/")
    archive_key = "/".join(part for part in (prefix, archive_name) if part)
    manifest_key = archive_key + ".manifest.json"
    started = time.time()
    archive_version = _version_id(parsed.netloc, archive_key)
    manifest_version = _version_id(parsed.netloc, manifest_key)
    with tempfile.TemporaryDirectory(
        prefix=".offsite-restore-",
        dir=args.local_backup_dir,
    ) as directory:
        temporary = Path(directory)
        archive = temporary / archive_name
        manifest = temporary / (archive_name + ".manifest.json")
        _download_version(
            parsed.netloc,
            archive_key,
            archive_version,
            archive,
        )
        _download_version(
            parsed.netloc,
            manifest_key,
            manifest_version,
            manifest,
        )
        component_output = temporary / "component-restore.json"
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("restore_drill.py")),
                str(archive),
                "--expected-account-id",
                required_env["OKX_QUANT_ACCOUNT_ID"],
                "--manifest-public-key",
                str(args.manifest_public_key),
                "--expected-signing-key-id",
                required_env["OKX_QUANT_BACKUP_SIGNING_KEY_ID"],
                "--expected-encryption-key-id",
                required_env["OKX_QUANT_BACKUP_ENCRYPTION_KEY_ID"],
                "--output",
                str(component_output),
            ],
            check=True,
            timeout=300,
        )
        evidence = json.loads(component_output.read_text(encoding="utf-8"))
    evidence.update({
        "offsite_roundtrip_ok": True,
        "offsite_uri": (
            f"s3://{parsed.netloc}/{archive_key}"
        ),
        "archive_version_id": archive_version,
        "manifest_version_id": manifest_version,
        "roundtrip_started_at": started,
        "roundtrip_completed_at": time.time(),
    })
    args.output.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
