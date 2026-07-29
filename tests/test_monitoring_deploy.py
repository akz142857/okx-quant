from pathlib import Path

import yaml

from scripts.validate_monitoring_config import (
    validate_alertmanager,
    validate_dashboard,
    validate_rules,
)

PROJECT = Path(__file__).resolve().parents[1]


def test_checked_in_monitoring_assets_are_fail_closed():
    validate_rules(PROJECT / "deploy/monitoring/prometheus-rules.yaml")
    validate_alertmanager(
        PROJECT / "deploy/monitoring/alertmanager.yaml.example"
    )
    validate_dashboard(
        PROJECT / "deploy/monitoring/grafana-dashboard.json"
    )


def test_metrics_agent_scrapes_inside_role_netns_and_remote_writes_mtls():
    unit = (
        PROJECT
        / "deploy/systemd/okx-quant-demo-metrics-agent@.service"
    ).read_text(encoding="utf-8")
    config = yaml.safe_load(
        (
            PROJECT
            / "deploy/monitoring/prometheus-agent.yaml.example"
        ).read_text(encoding="utf-8")
    )

    assert "NetworkNamespacePath=/run/netns/okx-quant-demo-%i" in unit
    assert "--enable-feature=agent" in unit
    assert "--storage.agent.path=" in unit
    assert "ReadWritePaths=/var/lib/okx-quant-metrics-agent/demo-%i" in unit
    remote_write = config["remote_write"]
    assert len(remote_write) == 1
    tls = remote_write[0]["tls_config"]
    assert tls["ca_file"].endswith("/ca.pem")
    assert tls["cert_file"].endswith("/client.pem")
    assert tls["key_file"].endswith("/client-key.pem")
    assert tls["insecure_skip_verify"] is False
    assert config["scrape_configs"][0]["static_configs"][0]["targets"] == [
        "127.0.0.1:REPLACE_WITH_ROLE_METRICS_PORT"
    ]


def test_demo_journal_is_persistent_bounded_and_sealed():
    config = (
        PROJECT / "deploy/journald/99-okx-quant-demo.conf"
    ).read_text(encoding="utf-8")
    assert "Storage=persistent" in config
    assert "Seal=yes" in config
    assert "SystemMaxUse=" in config
    assert "SystemKeepFree=" in config
    assert "MaxRetentionSec=" in config
