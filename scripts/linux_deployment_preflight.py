#!/usr/bin/env python3
# ruff: noqa: E402
"""Read-only acceptance preflight for a real Linux Demo deployment.

The command intentionally produces a *preflight report*, not a deployment
attestation.  In ``--live`` mode every host fact is obtained from the running
host (systemd, iproute and procfs); when ``--require-attestation`` is set, a
signed attestation from the independent verifier is mandatory.  Missing
commands, missing units, or unavailable external evidence fail closed.

This is kept separate from the admission gate so that operators can run it
before a service is started without accidentally upgrading Stage-C state.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

# Running ``python scripts/foo.py`` puts only ``scripts/`` on sys.path.  Add
# the repository root before importing the package and sibling checker; this
# does not change imports when the module is executed by pytest.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from okx_quant.ops.external_deployment_attestation import (
    verify_signed_external_deployment_attestation,
)
from scripts.verify_systemd_security import check_units

SCHEMA = "okx-quant.linux-deployment-preflight/v1"
ROLES = ("shadow", "active", "chaos")
REQUIRED_GATE_A_ROLES = frozenset({"shadow", "active"})
DEFAULT_GATE_A_ROLES = ("shadow", "active")


class PreflightError(RuntimeError):
    """A required preflight check failed."""


def _run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError(f"command failed: {' '.join(argv)}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise PreflightError(f"command exited {result.returncode}: {' '.join(argv)}{suffix}")
    return result


def _check_systemd_units(root: Path, *, live: bool) -> dict:
    report = check_units(root)
    result = {"static_security": report}
    if not live:
        return result
    if shutil.which("systemd-analyze") is None:
        raise PreflightError("live Linux preflight 需要 systemd-analyze")
    paths = sorted(root.glob("deploy/**/*.service")) + sorted(root.glob("deploy/**/*.timer"))
    verify = []
    for path in paths:
        completed = _run(["systemd-analyze", "verify", str(path)], check=False)
        verify.append({"path": path.relative_to(root).as_posix(), "returncode": completed.returncode})
        if completed.returncode:
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            raise PreflightError(
                f"systemd-analyze verify 失败: {path}: {detail[-1] if detail else 'unknown error'}"
            )
    result["systemd_analyze"] = verify
    return result


def _netns_inode(namespace: str) -> str:
    completed = _run(
        ["ip", "netns", "exec", namespace, "stat", "-Lc", "%i", "/proc/self/ns/net"]
    )
    inode = completed.stdout.strip()
    if not inode.isdigit():
        raise PreflightError(f"namespace {namespace} 返回无效 netns inode")
    return inode


def _validated_roles(values: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    roles = tuple(values or DEFAULT_GATE_A_ROLES)
    if len(set(roles)) != len(roles):
        raise PreflightError("Demo role 不得重复")
    unknown = set(roles) - set(ROLES)
    if unknown:
        raise PreflightError(f"未知 Demo role: {', '.join(sorted(unknown))}")
    missing = REQUIRED_GATE_A_ROLES - set(roles)
    if missing:
        raise PreflightError(
            f"Gate A 必须包含 shadow 和 active；缺少: {', '.join(sorted(missing))}"
        )
    return tuple(role for role in ROLES if role in roles)


def _expected_demo_units(roles: tuple[str, ...]) -> list[str]:
    return [f"okx-quant-demo-{role}.service" for role in roles]


def _check_live_host(installed_units: list[str], roles: tuple[str, ...]) -> dict:
    if platform.system() != "Linux":
        raise PreflightError("--live 只能在 Linux 主机执行")
    if os.geteuid() != 0:
        raise PreflightError("--live preflight 必须由 root 执行")
    for command in ("systemctl", "ip", "stat"):
        if shutil.which(command) is None:
            raise PreflightError(f"live Linux preflight 缺少命令: {command}")

    netns = {}
    names = _run(["ip", "netns", "list"]).stdout.splitlines()
    available = {line.split()[0] for line in names if line.split()}
    for role in roles:
        name = f"okx-quant-demo-{role}"
        if name not in available:
            raise PreflightError(f"缺少隔离 network namespace: {name}")
        netns[name] = _netns_inode(name)
    if len(set(netns.values())) != len(netns):
        raise PreflightError("启用的 Demo network namespace inode 被复用")

    units = []
    for unit in installed_units:
        _run(["systemctl", "cat", unit])
        user = _run(["systemctl", "show", "--value", "-p", "User", unit]).stdout.strip()
        if not user or user == "root":
            raise PreflightError(f"unit {unit} 的 User 必须是非 root: {user or '<empty>'}")
        units.append({"unit": unit, "user": user})
    return {"network_namespaces": netns, "installed_units": units}


def _verify_attestation(args: argparse.Namespace) -> dict:
    if args.attestation is None or args.public_key is None:
        if args.require_attestation:
            raise PreflightError("--require-attestation 必须同时提供 --attestation 和 --public-key")
        return {"required": False, "verified": False}
    if args.require_attestation and not args.expected_candidate_sha256:
        raise PreflightError("--require-attestation 必须提供 --expected-candidate-sha256")
    if not args.attestation.is_file() or args.attestation.is_symlink():
        raise PreflightError("attestation 必须是非符号链接普通文件")
    if not args.public_key.is_file() or args.public_key.is_symlink():
        raise PreflightError("attestation public key 必须是非符号链接普通文件")
    try:
        artifact = json.loads(args.attestation.read_text(encoding="utf-8"))
        claims = verify_signed_external_deployment_attestation(
            artifact,
            args.public_key,
            now=datetime.now(UTC),
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise PreflightError(f"拒绝 external deployment attestation: {exc}") from exc
    expected = args.expected_candidate_sha256.lower()
    if expected and claims["candidate_sha256"] != expected:
        raise PreflightError("candidate deployment identity SHA-256 不匹配")
    return {
        "required": args.require_attestation,
        "verified": True,
        "schema": claims["schema"],
        "candidate_sha256": claims["candidate_sha256"],
        "account_roles": sorted(item["role"] for item in claims["accounts"]),
        "failure_domain_roles": sorted(item["role"] for item in claims["failure_domains"]),
        "evidence_roles": sorted(claims["evidence"]),
    }


def build_report(args: argparse.Namespace) -> dict:
    live = args.mode == "live"
    roles = _validated_roles(getattr(args, "role", None))
    installed_units = list(args.installed_unit)
    expected_units = _expected_demo_units(roles)
    if live:
        if not installed_units:
            installed_units = expected_units
        if set(installed_units) != set(expected_units) or len(installed_units) != len(expected_units):
            raise PreflightError("installed-unit 必须与启用的 Demo role 精确一致")
    report = {
        "schema": SCHEMA,
        "preflight_only": True,
        "mode": args.mode,
        "roles": list(roles),
        "started_at": datetime.now(UTC).isoformat(),
        "checks": {},
    }
    if live:
        report["checks"]["host"] = _check_live_host(installed_units, roles)
    report["checks"]["units"] = _check_systemd_units(args.root.resolve(), live=live)
    report["checks"]["external_deployment_attestation"] = _verify_attestation(args)
    report["passed"] = True
    report["completed_at"] = datetime.now(UTC).isoformat()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("static", "live"), default="static")
    parser.add_argument(
        "--role",
        action="append",
        choices=ROLES,
        help="启用的 Demo role；默认 shadow+active，可重复指定并可选加入 chaos",
    )
    parser.add_argument("--installed-unit", action="append", default=[])
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--expected-candidate-sha256", default="")
    parser.add_argument("--require-attestation", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = build_report(args)
    except (PreflightError, RuntimeError) as exc:
        print(f"deployment preflight rejected: {exc}", file=sys.stderr)
        return 1
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
