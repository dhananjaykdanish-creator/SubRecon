"""Tests for SubRecon SQLite storage."""

import sqlite3

import pytest

from subrecon.storage.database import (
    connect_database,
    initialize_database,
)


@pytest.fixture
def db_connection(tmp_path):
    """Create a temporary initialized database."""

    path = tmp_path / "data" / "subrecon.db"
    initialize_database(path)

    connection = connect_database(path)

    yield connection

    connection.close()


def test_database_tables_created(db_connection):
    """All expected database tables should exist."""

    tables = {
        row["name"]
        for row in db_connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }

    expected = {
        "schema_migrations",
        "scans",
        "discovered_subdomains",
        "subdomain_sources",
        "dns_observations",
        "http_observations",
        "technology_observations",
        "tool_runs",
    }

    assert expected.issubset(tables)


def test_migrations_are_idempotent(tmp_path):
    """Running initialization twice must not duplicate migrations."""

    path = tmp_path / "subrecon.db"

    initialize_database(path)
    initialize_database(path)

    connection = connect_database(path)

    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0]

        assert count == 1
    finally:
        connection.close()


def test_duplicate_hostname_rejected(db_connection):
    """A hostname should appear only once per scan."""

    db_connection.execute(
        "INSERT INTO scans (scan_id, root_domain, started_at) "
        "VALUES (?, ?, ?)",
        ("scan-001", "example.com", "2026-11-07T00:00:00Z"),
    )

    values = (
        "scan-001",
        "api.example.com",
        "2026-11-07T00:00:00Z",
    )

    db_connection.execute(
        "INSERT INTO discovered_subdomains "
        "(scan_id, hostname, discovered_at) VALUES (?, ?, ?)",
        values,
    )

    with pytest.raises(sqlite3.IntegrityError):
        db_connection.execute(
            "INSERT INTO discovered_subdomains "
            "(scan_id, hostname, discovered_at) VALUES (?, ?, ?)",
            ("scan-001", "API.EXAMPLE.COM", "2026-11-07T01:00:00Z"),
        )


def test_http_403_is_valid_observation(db_connection):
    """HTTP 403 must be stored as a valid HTTP response."""

    db_connection.execute(
        "INSERT INTO scans (scan_id, root_domain, started_at) "
        "VALUES (?, ?, ?)",
        ("scan-002", "example.com", "2026-11-07T00:00:00Z"),
    )

    cursor = db_connection.execute(
        "INSERT INTO discovered_subdomains "
        "(scan_id, hostname, discovered_at) VALUES (?, ?, ?)",
        ("scan-002", "api.example.com", "2026-11-07T00:00:00Z"),
    )

    db_connection.execute(
        """
        INSERT INTO http_observations
        (subdomain_id, url, status_code, observed_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            cursor.lastrowid,
            "https://api.example.com",
            403,
            "2026-11-07T00:00:00Z",
        ),
    )

    result = db_connection.execute(
        "SELECT status_code FROM http_observations"
    ).fetchone()

    assert result["status_code"] == 403


def test_foreign_key_enforcement(db_connection):
    """Observations cannot reference nonexistent scans or assets."""

    assert db_connection.execute(
        "PRAGMA foreign_keys"
    ).fetchone()[0] == 1

    with pytest.raises(sqlite3.IntegrityError):
        db_connection.execute(
            """
            INSERT INTO discovered_subdomains
            (scan_id, hostname, discovered_at)
            VALUES (?, ?, ?)
            """,
            (
                "missing-scan",
                "api.example.com",
                "2026-11-07T00:00:00Z",
            ),
        )
