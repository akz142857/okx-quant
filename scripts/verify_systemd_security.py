#!/usr/bin/env python3
"""Static, fail-closed check of the deployable systemd hardening baseline.

``systemd-analyze verify`` checks syntax and dependency resolution; it does
not make a policy decision about sandboxing.  This checker complements it by
examining the version-controlled unit bytes.  Test-only barrier units are
excluded because they are deliberately separate harnesses and are never a
production admission source.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SCHEMA = "okx-quant.systemd-security-report/v1"
TRUTHY = {"true", "yes", "1"}
REQUIRED = {
    "NoNewPrivileges": TRUTHY,
    "PrivateTmp": TRUTHY,
    "ProtectSystem": {"strict"},
    "ProtectHome": TRUTHY,
    "CapabilityBoundingSet": {""},
    "RestrictSUIDSGID": TRUTHY,
    "RestrictRealtime": TRUTHY,
    "SystemCallArchitectures": {"native"},
}


def _service_properties(raw: str) -> dict[str, list[str]]:
    section = ""
    properties: dict[str, list[str]] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section != "Service" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        properties.setdefault(key, []).append(value.strip())
    return properties


def check_units(root: Path) -> dict:
    paths = sorted(root.glob("deploy/**/*.service"))
    if not paths:
        raise RuntimeError("没有找到 systemd service unit")
    checked: list[dict] = []
    failures: list[str] = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if "/stage-c-barriers/" in relative and "test-only" in relative:
            continue
        props = _service_properties(path.read_text(encoding="utf-8"))
        if not props.get("User") or props["User"][-1] == "root":
            failures.append(f"{relative}: Service.User 必须是非 root 身份")
        unit_failures: list[str] = []
        for key, allowed in REQUIRED.items():
            values = props.get(key, [])
            if not values or values[-1].lower() not in {v.lower() for v in allowed}:
                actual = "<missing>" if not values else repr(values[-1])
                unit_failures.append(f"{key}={actual}")
        # An empty capability bounding set is only useful if ambient
        # capabilities are not reintroduced through a later assignment.
        for value in props.get("AmbientCapabilities", []):
            if value:
                unit_failures.append(f"AmbientCapabilities={value!r}")
        if unit_failures:
            failures.extend(f"{relative}: {item}" for item in unit_failures)
        checked.append({"path": relative, "ok": not unit_failures})
    report = {"schema": SCHEMA, "checked": checked, "failures": failures}
    if failures:
        raise RuntimeError(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = check_units(args.root.resolve())
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
