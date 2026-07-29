#!/usr/bin/env python3
"""Fail-closed structural validation for checked-in monitoring assets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

REQUIRED_ALERTS = {
    "OkxQuantDemoTargetDown",
    "OkxQuantDemoNotReady",
    "OkxQuantDemoWebSocketUnavailable",
    "OkxQuantDemoUnknownBuy",
    "OkxQuantDemoUnprotectedPosition",
    "OkxQuantDemoAlertDeliveryBroken",
    "OkxQuantDemoBackupRpoExceeded",
    "OkxQuantDemoClockUnsafe",
    "OkxQuantDemoResourceHardBreach",
    "OkxQuantDemoWalCheckpointStale",
    "OkxQuantDemoApiErrorRate",
    "OkxQuantDemoAccountSnapshotNearStale",
    "OkxQuantDemoMarketDataNearStale",
    "OkxQuantDemoSlippageNearLimit",
}
REQUIRED_DASHBOARD_EXPRESSIONS = {
    "system_mode",
    "ws_connected",
    "backup_recovery_point_age_seconds",
    "unknown_buy_oldest_age_seconds",
    "unprotected_position_seconds",
    "wal_checkpoint_age_seconds",
    "account_snapshot_age_seconds / account_snapshot_max_age_seconds",
    "market_data_age_seconds / market_data_max_age_seconds",
    "execution_slippage_ratio / execution_slippage_limit_ratio",
}


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是 mapping")
    return value


def validate_rules(path: Path) -> None:
    root = _mapping(yaml.safe_load(path.read_text(encoding="utf-8")), "rules")
    if set(root) != {"groups"} or not isinstance(root["groups"], list):
        raise ValueError("Prometheus rules 顶层 schema 非法")
    alert_names: list[str] = []
    for group in root["groups"]:
        group = _mapping(group, "rule group")
        if set(group) != {"name", "interval", "rules"}:
            raise ValueError("Prometheus rule group schema 非法")
        if (
            not isinstance(group["name"], str)
            or not group["name"].strip()
            or not isinstance(group["interval"], str)
            or not isinstance(group["rules"], list)
            or not group["rules"]
        ):
            raise ValueError("Prometheus rule group 内容非法")
        for rule in group["rules"]:
            rule = _mapping(rule, "alert rule")
            if set(rule) != {
                "alert",
                "expr",
                "for",
                "labels",
                "annotations",
            }:
                raise ValueError("Prometheus alert rule schema 非法")
            labels = _mapping(rule["labels"], "alert labels")
            annotations = _mapping(rule["annotations"], "alert annotations")
            if (
                not isinstance(rule["alert"], str)
                or not rule["alert"].strip()
                or not isinstance(rule["expr"], str)
                or not rule["expr"].strip()
                or labels.get("priority") not in {"P0", "P1"}
                or labels.get("severity") not in {"page", "warning"}
                or labels["priority"] == "P0"
                and labels["severity"] != "page"
                or labels["priority"] == "P1"
                and labels["severity"] != "warning"
                or not isinstance(annotations.get("summary"), str)
                or not annotations["summary"].strip()
            ):
                raise ValueError("Prometheus alert rule 语义非法")
            alert_names.append(rule["alert"])
    if len(alert_names) != len(set(alert_names)):
        raise ValueError("Prometheus alert 名称重复")
    missing = REQUIRED_ALERTS - set(alert_names)
    if missing:
        raise ValueError(f"Prometheus critical alerts 缺失: {sorted(missing)}")


def validate_alertmanager(path: Path) -> None:
    root = _mapping(
        yaml.safe_load(path.read_text(encoding="utf-8")),
        "Alertmanager config",
    )
    if set(root) != {"route", "receivers"}:
        raise ValueError("Alertmanager 顶层 schema 非法")
    route = _mapping(root["route"], "Alertmanager route")
    receivers = root["receivers"]
    if not isinstance(receivers, list):
        raise ValueError("Alertmanager receivers 必须是 list")
    receiver_names = {
        _mapping(receiver, "Alertmanager receiver").get("name")
        for receiver in receivers
    }
    expected_receivers = {"p0-primary", "p0-independent", "p1-primary"}
    if receiver_names != expected_receivers:
        raise ValueError("Alertmanager receiver 集合非法")
    routes = route.get("routes")
    if not isinstance(routes, list) or len(routes) != 2:
        raise ValueError("Alertmanager 必须有两个独立 P0 route")
    p0_receivers = {
        _mapping(child, "Alertmanager child route").get("receiver")
        for child in routes
    }
    if p0_receivers != {"p0-primary", "p0-independent"}:
        raise ValueError("Alertmanager P0 双路由缺失")
    for receiver in receivers:
        receiver = _mapping(receiver, "Alertmanager receiver")
        configs = receiver.get("webhook_configs")
        if not isinstance(configs, list) or len(configs) != 1:
            raise ValueError("Alertmanager receiver webhook 非法")
        webhook = _mapping(configs[0], "Alertmanager webhook")
        if set(webhook) != {"url_file", "send_resolved"}:
            raise ValueError("Alertmanager webhook 禁止内联 secret")
        if webhook["send_resolved"] is not True:
            raise ValueError("Alertmanager 必须发送 resolved")


def validate_dashboard(path: Path) -> None:
    dashboard = _mapping(
        json.loads(path.read_text(encoding="utf-8")),
        "Grafana dashboard",
    )
    panels = dashboard.get("panels")
    if (
        dashboard.get("editable") is not False
        or not isinstance(dashboard.get("uid"), str)
        or not isinstance(panels, list)
        or not panels
    ):
        raise ValueError("Grafana dashboard schema 非法")
    expressions = {
        target.get("expr")
        for panel in panels
        if isinstance(panel, dict)
        for target in panel.get("targets", [])
        if isinstance(target, dict)
    }
    missing = REQUIRED_DASHBOARD_EXPRESSIONS - expressions
    if missing:
        raise ValueError(f"Grafana critical panels 缺失: {sorted(missing)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rules",
        type=Path,
        default=Path("deploy/monitoring/prometheus-rules.yaml"),
    )
    parser.add_argument(
        "--alertmanager",
        type=Path,
        default=Path("deploy/monitoring/alertmanager.yaml.example"),
    )
    parser.add_argument(
        "--dashboard",
        type=Path,
        default=Path("deploy/monitoring/grafana-dashboard.json"),
    )
    args = parser.parse_args()
    validate_rules(args.rules)
    validate_alertmanager(args.alertmanager)
    validate_dashboard(args.dashboard)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
