"""Tests for the SubRecon export CLI command."""

import csv
import json

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


@pytest.fixture
def prepared_database(monkeypatch, app_config):
    monkeypatch.setattr(
        "subrecon.commands.export.load_config",
        lambda: app_config,
    )

    initialize_database(app_config.database_path)

    connection = connect_database(app_config.database_path)

    try:
        create_scan(
            connection,
            Scan(
                scan_id="export-test-001",
                root_domain="example.com",
                status=ScanStatus.COMPLETED,
            ),
        )

        add_discovered_subdomain(
            connection,
            "export-test-001",
            DiscoveredSubdomain(
                hostname="api.example.com",
                sources=("subfinder", "amass"),
            ),
        )

        add_dns_observation(
            connection,
            "export-test-001",
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

    return app_config


def test_default_export_creates_json(prepared_database):
    result = runner.invoke(
        app,
        ["export", "export-test-001"],
    )

    output = (
        prepared_database.results_dir
        / "reports"
        / "export-test-001.json"
    )

    assert result.exit_code == 0
    assert output.is_file()
    assert "JSON" in result.output
    assert "exported successfully" in result.output.lower()

    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["scan"]["root_domain"] == "example.com"
    assert report["dns_observations"][0]["value"] == "192.0.2.10"


@pytest.mark.parametrize(
    ("file_format", "extension"),
    [
        ("json", ".json"),
        ("csv", ".csv"),
        ("txt", ".txt"),
        ("html", ".html"),
    ],
)
def test_all_export_formats(
    prepared_database,
    file_format,
    extension,
):
    result = runner.invoke(
        app,
        [
            "export",
            "export-test-001",
            "--format",
            file_format,
        ],
    )

    output = (
        prepared_database.results_dir
        / "reports"
        / f"export-test-001{extension}"
    )

    assert result.exit_code == 0
    assert output.is_file()
    assert "exported successfully" in result.output.lower()


def test_csv_output_contains_discovered_hostname(prepared_database):
    result = runner.invoke(
        app,
        [
            "export",
            "export-test-001",
            "--format",
            "csv",
        ],
    )

    output = (
        prepared_database.results_dir
        / "reports"
        / "export-test-001.csv"
    )

    assert result.exit_code == 0

    with output.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        rows = list(csv.DictReader(file))

    assert any(
        row["record_type"] == "subdomain"
        and row["hostname"] == "api.example.com"
        for row in rows
    )


def test_custom_output_path(prepared_database, tmp_path):
    output = tmp_path / "custom" / "my-report.html"

    result = runner.invoke(
        app,
        [
            "export",
            "export-test-001",
            "--format",
            "html",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.is_file()
    assert "api.example.com" in output.read_text(encoding="utf-8")


def test_unsupported_format_rejected(prepared_database):
    result = runner.invoke(
        app,
        [
            "export",
            "export-test-001",
            "--format",
            "pdf",
        ],
    )

    assert result.exit_code == 2
    assert "Unsupported export format" in result.output


def test_unknown_scan_rejected(prepared_database):
    result = runner.invoke(
        app,
        [
            "export",
            "missing-scan",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    assert "Scan not found" in result.output


def test_missing_database_rejected(monkeypatch, tmp_path):
    results_dir = tmp_path / "results"

    config = AppConfig(
        project_root=tmp_path,
        results_dir=results_dir,
        database_path=results_dir / "missing.db",
        log_level="INFO",
    )

    monkeypatch.setattr(
        "subrecon.commands.export.load_config",
        lambda: config,
    )

    result = runner.invoke(
        app,
        ["export", "missing-scan"],
    )

    assert result.exit_code == 1
    assert "Database not found" in result.output


def test_export_requires_scan_id():
    result = runner.invoke(app, ["export"])

    assert result.exit_code != 0
    assert "Missing argument" in result.output
