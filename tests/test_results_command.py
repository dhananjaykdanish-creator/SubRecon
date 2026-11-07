"""Tests for the SubRecon results command."""

from datetime import datetime, timezone

import pytest

from typer.testing import CliRunner

from subrecon.cli import app
from subrecon.config import AppConfig
from subrecon.core.models import (
    DNSObservation,
    DiscoveredSubdomain,
    Scan,
    ScanStatus,
)
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.dns import add_dns_observation
from subrecon.storage.repositories.scans import (
    add_discovered_subdomain,
    create_scan,
)


runner = CliRunner()


@pytest.fixture
def app_config(tmp_path):
    results_dir = tmp_path / "results"

    return AppConfig(
        project_root=tmp_path,
        results_dir=results_dir,
        database_path=results_dir / "subrecon.db",
        log_level="INFO",
    )


def test_results_command_handles_missing_database(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.results.load_config",
        lambda: app_config,
    )

    result = runner.invoke(
        app,
        ["results", "missing-scan"],
    )

    assert result.exit_code == 1
    assert "No database found" in result.stdout


def test_results_command_rejects_unknown_scan(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.results.load_config",
        lambda: app_config,
    )

    initialize_database(app_config.database_path)

    result = runner.invoke(
        app,
        ["results", "unknown-scan"],
    )

    assert result.exit_code == 1
    assert "Scan not found" in result.stdout


def test_results_command_displays_hostnames_and_dns(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.results.load_config",
        lambda: app_config,
    )

    initialize_database(app_config.database_path)

    connection = connect_database(app_config.database_path)

    try:
        create_scan(
            connection,
            Scan(
                scan_id="results-test-001",
                root_domain="example.com",
                status=ScanStatus.COMPLETED,
                started_at=datetime.now(timezone.utc),
            ),
        )

        add_discovered_subdomain(
            connection,
            "results-test-001",
            DiscoveredSubdomain(
                hostname="api.example.com",
                sources=("subfinder", "amass"),
            ),
        )

        add_dns_observation(
            connection,
            "results-test-001",
            DNSObservation(
                hostname="api.example.com",
                record_type="A",
                value="192.0.2.10",
                ttl=300,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    result = runner.invoke(
        app,
        ["results", "results-test-001"],
    )

    assert result.exit_code == 0
    assert "Scan Information" in result.stdout
    assert "Discovered Hostnames" in result.stdout
    assert "DNS Observations" in result.stdout
    assert "api.example.com" in result.stdout
    assert "subfinder" in result.stdout
    assert "amass" in result.stdout
    assert "192.0.2.10" in result.stdout
    assert "300" in result.stdout


def test_results_command_handles_empty_scan(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.results.load_config",
        lambda: app_config,
    )

    initialize_database(app_config.database_path)

    connection = connect_database(app_config.database_path)

    try:
        create_scan(
            connection,
            Scan(
                scan_id="empty-results-001",
                root_domain="example.com",
            ),
        )

        connection.commit()

    finally:
        connection.close()

    result = runner.invoke(
        app,
        ["results", "empty-results-001"],
    )

    assert result.exit_code == 0
    assert "No discovered hostnames were recorded" in result.stdout
    assert "No DNS observations were recorded" in result.stdout


def test_results_command_requires_scan_id():
    result = runner.invoke(app, ["results"])

    assert result.exit_code != 0
    assert "Missing argument 'scan_id'." in result.output
