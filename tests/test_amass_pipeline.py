"""Tests for the Amass discovery pipeline."""

import subprocess

import pytest

from subrecon.core.models import (
    DiscoveredSubdomain,
    Scan,
    ToolRunStatus,
)
from subrecon.core.scope import ScopePolicy, ScopeValidationError
from subrecon.integrations.amass import AmassAdapter
from subrecon.modules.amass_discovery import run_amass_for_scan
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.scans import (
    add_discovered_subdomain,
    create_scan,
    list_discovered_subdomains,
)
from subrecon.storage.repositories.tool_runs import list_tool_runs


@pytest.fixture
def connection(tmp_path):
    path = tmp_path / "subrecon.db"
    initialize_database(path)

    db = connect_database(path)

    create_scan(
        db,
        Scan(
            scan_id="scan-amass-001",
            root_domain="example.com",
        ),
    )

    db.commit()

    yield db

    db.close()


@pytest.fixture
def scope():
    return ScopePolicy(("example.com",))


def make_adapter(output="", return_code=0):
    calls = []

    def fake_runner(command, **kwargs):
        calls.append(command)

        if command[1] == "enum":
            return subprocess.CompletedProcess(
                command,
                return_code,
                stdout="",
                stderr=(
                    "Simulated Amass failure"
                    if return_code else ""
                ),
            )

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=output,
            stderr="",
        )

    adapter = AmassAdapter(
        executable="/fake/amass",
        runner=fake_runner,
    )

    return adapter, calls


def test_successful_discovery_is_saved(
    connection,
    scope,
    tmp_path,
):
    adapter, calls = make_adapter(
        "api.example.com\nwww.example.com\n"
    )

    result = run_amass_for_scan(
        connection,
        "scan-amass-001",
        scope,
        tmp_path / "amass",
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.COMPLETED
    assert result.discovered_count == 2
    assert len(calls) == 2

    discoveries = list_discovered_subdomains(
        connection,
        "scan-amass-001",
    )

    assert len(discoveries) == 2
    assert discoveries[0].sources == ("amass",)

    runs = list_tool_runs(connection, "scan-amass-001")

    assert len(runs) == 1
    assert runs[0].status == ToolRunStatus.COMPLETED


def test_failed_execution_is_recorded(
    connection,
    scope,
    tmp_path,
):
    adapter, _ = make_adapter(return_code=1)

    result = run_amass_for_scan(
        connection,
        "scan-amass-001",
        scope,
        tmp_path / "amass",
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.FAILED

    runs = list_tool_runs(connection, "scan-amass-001")

    assert runs[0].status == ToolRunStatus.FAILED


def test_timeout_is_recorded(connection, scope, tmp_path):
    def timeout_runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, timeout=10)

    adapter = AmassAdapter(
        executable="/fake/amass",
        runner=timeout_runner,
    )

    result = run_amass_for_scan(
        connection,
        "scan-amass-001",
        scope,
        tmp_path / "amass",
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.TIMED_OUT

    runs = list_tool_runs(connection, "scan-amass-001")

    assert runs[0].status == ToolRunStatus.TIMED_OUT


def test_out_of_scope_scan_rejected(connection, tmp_path):
    with pytest.raises(ScopeValidationError):
        run_amass_for_scan(
            connection,
            "scan-amass-001",
            ScopePolicy(("other.org",)),
            tmp_path / "amass",
            make_adapter()[0],
        )

    assert list_tool_runs(connection, "scan-amass-001") == []


def test_missing_scan_rejected(connection, scope, tmp_path):
    with pytest.raises(LookupError, match="Scan not found"):
        run_amass_for_scan(
            connection,
            "missing",
            scope,
            tmp_path / "amass",
            make_adapter()[0],
        )


def test_duplicate_discovery_merges_sources(
    connection,
    scope,
    tmp_path,
):
    add_discovered_subdomain(
        connection,
        "scan-amass-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("subfinder",),
        ),
    )

    adapter, _ = make_adapter("api.example.com\n")

    result = run_amass_for_scan(
        connection,
        "scan-amass-001",
        scope,
        tmp_path / "amass",
        adapter,
    )

    connection.commit()

    discoveries = list_discovered_subdomains(
        connection,
        "scan-amass-001",
    )

    assert result.discovered_count == 1
    assert len(discoveries) == 1
    assert discoveries[0].sources == ("amass", "subfinder")


def test_out_of_scope_result_is_not_saved(
    connection,
    scope,
    tmp_path,
):
    adapter, _ = make_adapter("attacker.org\n")

    result = run_amass_for_scan(
        connection,
        "scan-amass-001",
        scope,
        tmp_path / "amass",
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.FAILED
    assert result.discovered_count == 0

    assert list_discovered_subdomains(
        connection,
        "scan-amass-001",
    ) == []
