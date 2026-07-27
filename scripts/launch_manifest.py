"""Strict loader for the single root-controlled production launch manifest."""

from __future__ import annotations

import json
import math
import stat
from pathlib import Path

_LAUNCH_KEYS = {
    "version",
    "strategy",
    "bar",
    "instruments",
    "interval_seconds",
}


def load_launch_manifest(path: Path) -> dict:
    path_stat = path.lstat()
    if (
        not stat.S_ISREG(path_stat.st_mode)
        or path.is_symlink()
        or path_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("launch manifest 必须是不可由 group/other 写入的普通文件")
    if path.is_relative_to("/etc/okx-quant") and path_stat.st_uid != 0:
        raise ValueError("生产 launch manifest 必须由 root 持有")
    if path.is_relative_to("/etc/okx-quant"):
        production_root = Path("/etc/okx-quant")
        candidate = path.parent
        while True:
            candidate_stat = candidate.lstat()
            if (
                candidate_stat.st_uid != 0
                or stat.S_ISLNK(candidate_stat.st_mode)
                or candidate_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise ValueError("生产 launch manifest 目录链不安全")
            if candidate == production_root:
                break
            candidate = candidate.parent
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != _LAUNCH_KEYS:
        raise ValueError("launch manifest 字段不完整或包含未知字段")
    if manifest["version"] != 1:
        raise ValueError("launch manifest 版本不支持")
    if (
        not isinstance(manifest["strategy"], str)
        or not isinstance(manifest["bar"], str)
        or not isinstance(manifest["instruments"], list)
        or any(not isinstance(item, str) for item in manifest["instruments"])
    ):
        raise ValueError("launch manifest 策略、bar 或 instruments 类型非法")
    interval = manifest["interval_seconds"]
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not math.isfinite(float(interval))
        or int(interval) != interval
        or interval <= 0
    ):
        raise ValueError("launch manifest interval_seconds 必须是正整数")
    return manifest
