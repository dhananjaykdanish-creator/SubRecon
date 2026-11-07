"""Tests for the unified SubRecon scan command."""

from types import SimpleNamespace

import pytest

from typer.testing import CliRunner

from subrecon.config import AppConfig
from subrecon.core.models import (
    ScanStatus,
    ToolRunStatus,
)
from subrecon.integrations.base import ToolExecutionResult
from subrecon.cli import app
from subrecon.storage.database import connect_database
from subrecon.storage.repositories.scans import get_scan


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


def make_tool_result(name, status):
    return SimpleNamespace(
        execution=ToolExecutionResult(
            tool_name=name,
            status=status,
            exit_code=0 if status == ToolRunStatus.COMPLETED else None,
        )
    )


def make_passive_result(
    subfinder_status=ToolRunStatus.COMPLETED,
    amass_status=ToolRunStatus.COMPLETED,
):
    return SimpleNamespace(
        subfinder=make_tool_result("subfinder", subfinder_status),
        amass=make_tool_result("amass", amass_status),
        unique_hostname_count=3,
    )


def make_dns_result(
    status=ToolRunStatus.COMPLETED,
):
    return SimpleNamespace(
        execution=ToolExecutionResult(
            tool_name="dnsx",
            status=status,
            exit_code=0 if status == ToolRunStatus.COMPLETED else None,
        ),
        observation_count=4,
    )


def test_authorization_confirmation_is_required(monkeypatch):
    """The command must refuse execution without confirmation."""

    def unexpected_config_call():
        pytest.fail("Configuration must not load before authorization.")

    monkeypatch.setattr(
        "subrecon.commands.scan.load_config",
        unexpected_config_call,
    )

    result = runner.invoke(
        app,
        ["scan", "example.com"],
    )

    assert result.exit_code == 2
    assert "Authorization confirmation required" in result.stdout


def test_invalid_domain_rejected():
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--confirm-authorization",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid target domain" in result.stdout


def test_successful_scan_creates_completed_record(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.scan.load_config",
        lambda: app_config,
    )

    monkeypatch.setattr(
        "subrecon.commands.scan.run_passive_discovery",
        lambda **kwargs: make_passive_result(),
    )

    monkeypatch.setattr(
        "subrecon.commands.scan.run_dnsx_for_scan",
        lambda **kwargs: make_dns_result(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--confirm-authorization",
        ],
    )

    assert result.exit_code == 0
    assert "Scan workflow completed" in result.stdout
    assert "example.com" in result.stdout
    assert "COMPLETED" in result.stdout
    assert "3" in result.stdout
    assert "4" in result.stdout

    connection = connect_database(app_config.database_path)

    try:
        row = connection.execute(
            "SELECT scan_id FROM scans"
        ).fetchone()

        assert row is not None

        scan = get_scan(connection, row["scan_id"])

        assert scan is not None
        assert scan.root_domain == "example.com"
        assert scan.status == ScanStatus.COMPLETED
        assert scan.completed_at is not None

    finally:
        connection.close()


def test_failed_discovery_marks_scan_failed(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.scan.load_config",
        lambda: app_config,
    )

    monkeypatch.setattr(
        "subrecon.commands.scan.run_passive_discovery",
        lambda **kwargs: make_passive_result(
            ToolRunStatus.FAILED,
            ToolRunStatus.SKIPPED,
        ),
    )

    monkeypatch.setattr(
        "subrecon.commands.scan.run_dnsx_for_scan",
        lambda **kwargs: make_dns_result(
            ToolRunStatus.SKIPPED,
        ),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--confirm-authorization",
        ],
    )

    assert result.exit_code == 1

    connection = connect_database(app_config.database_path)

    try:
        row = connection.execute(
            "SELECT scan_id FROM scans"
        ).fetchone()

        scan = get_scan(connection, row["scan_id"])

        assert scan.status == ScanStatus.FAILED

    finally:
        connection.close()


def test_unexpected_error_marks_scan_failed(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.scan.load_config",
        lambda: app_config,
    )

    def failing_pipeline(**kwargs):
        raise RuntimeError("Simulated pipeline failure")

    monkeypatch.setattr(
        "subrecon.commands.scan.run_passive_discovery",
        failing_pipeline,
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--confirm-authorization",
        ],
    )

    assert result.exit_code == 1
    assert "Simulated pipeline failure" in result.stdout

    connection = connect_database(app_config.database_path)

    try:
        row = connection.execute(
            "SELECT scan_id FROM scans"
        ).fetchone()

        scan = get_scan(connection, row["scan_id"])

        assert scan.status == ScanStatus.FAILED
        assert scan.completed_at is not None

    finally:
        connection.close()


def test_dns_failure_does_not_erase_successful_discovery(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.scan.load_config",
        lambda: app_config,
    )

    monkeypatch.setattr(
        "subrecon.commands.scan.run_passive_discovery",
        lambda **kwargs: make_passive_result(),
    )

    monkeypatch.setattr(
        "subrecon.commands.scan.run_dnsx_for_scan",
        lambda **kwargs: make_dns_result(
            ToolRunStatus.FAILED,
        ),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--confirm-authorization",
        ],
    )

    assert result.exit_code == 0
    assert "Scan workflow completed" in result.stdout
    assert "DNS resolution did not complete" in result.stdout
