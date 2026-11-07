"""Tests for SubRecon scan history."""

from datetime import datetime, timedelta, timezone

import pytest

from typer.testing import CliRunner

from subrecon.cli import app
from subrecon.config import AppConfig
from subrecon.core.models import Scan, ScanStatus
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.scans import (
    create_scan,
    list_scans,
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


def test_list_scans_empty_database(tmp_path):
    database_path = tmp_path / "empty.db"

    initialize_database(database_path)
    connection = connect_database(database_path)

    try:
        assert list_scans(connection) == []
    finally:
        connection.close()


def test_list_scans_newest_first(tmp_path):
    database_path = tmp_path / "history.db"

    initialize_database(database_path)
    connection = connect_database(database_path)

    now = datetime.now(timezone.utc)

    try:
        create_scan(
            connection,
            Scan(
                scan_id="older",
                root_domain="older.example.com",
                started_at=now - timedelta(hours=2),
            ),
        )

        create_scan(
            connection,
            Scan(
                scan_id="newer",
                root_domain="newer.example.com",
                started_at=now,
            ),
        )

        connection.commit()

        scans = list_scans(connection)

        assert len(scans) == 2
        assert scans[0].scan_id == "newer"
        assert scans[1].scan_id == "older"

    finally:
        connection.close()


def test_list_scans_limit(tmp_path):
    database_path = tmp_path / "history.db"

    initialize_database(database_path)
    connection = connect_database(database_path)

    now = datetime.now(timezone.utc)

    try:
        for index in range(3):
            create_scan(
                connection,
                Scan(
                    scan_id=f"scan-{index}",
                    root_domain=f"site{index}.example.com",
                    started_at=now + timedelta(minutes=index),
                ),
            )

        connection.commit()

        scans = list_scans(connection, limit=1)

        assert len(scans) == 1
        assert scans[0].scan_id == "scan-2"

    finally:
        connection.close()


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_history_limit_rejected(tmp_path, limit):
    database_path = tmp_path / "history.db"

    initialize_database(database_path)
    connection = connect_database(database_path)

    try:
        with pytest.raises(ValueError, match="positive integer"):
            list_scans(connection, limit)

    finally:
        connection.close()


def test_history_command_handles_missing_database(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.history.load_config",
        lambda: app_config,
    )

    result = runner.invoke(app, ["history"])

    assert result.exit_code == 0
    assert "No scan history found" in result.stdout


def test_history_command_displays_scans(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.history.load_config",
        lambda: app_config,
    )

    initialize_database(app_config.database_path)
    connection = connect_database(app_config.database_path)

    try:
        create_scan(
            connection,
            Scan(
                scan_id="history-test-001",
                root_domain="example.com",
                status=ScanStatus.COMPLETED,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    result = runner.invoke(app, ["history"])

    assert result.exit_code == 0
    assert "Scan History" in result.stdout
    assert "history-test-001" in result.stdout
    assert "example.com" in result.stdout
    assert "COMPLETED" in result.stdout


def test_history_command_respects_limit(
    monkeypatch,
    app_config,
):
    monkeypatch.setattr(
        "subrecon.commands.history.load_config",
        lambda: app_config,
    )

    initialize_database(app_config.database_path)
    connection = connect_database(app_config.database_path)

    now = datetime.now(timezone.utc)

    try:
        for index in range(3):
            create_scan(
                connection,
                Scan(
                    scan_id=f"history-{index}",
                    root_domain=f"site{index}.example.com",
                    started_at=now + timedelta(minutes=index),
                ),
            )

        connection.commit()

    finally:
        connection.close()

    result = runner.invoke(
        app,
        ["history", "--limit", "1"],
    )

    assert result.exit_code == 0
    assert "history-2" in result.stdout
    assert "history-0" not in result.stdout
    assert "Showing 1 scan(s)" in result.stdout
