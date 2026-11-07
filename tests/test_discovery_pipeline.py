"""Tests for the Subfinder discovery pipeline."""

import json
import subprocess

import pytest

from subrecon.core.models import (
    DiscoveredSubdomain,
    Scan,
    ToolRunStatus,
)
from subrecon.core.scope import ScopePolicy, ScopeValidationError
from subrecon.integrations.subfinder import SubfinderAdapter
from subrecon.modules.subdomain_discovery import run_subfinder_for_scan
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
            scan_id="scan-pipeline-001",
            root_domain="example.com",
        ),
    )

    db.commit()

    yield db

    db.close()


@pytest.fixture
def scope():
    return ScopePolicy(("example.com",))


def make_adapter(output, return_code=0):
    def fake_runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            return_code,
            stdout=output,
            stderr="",
        )

    return SubfinderAdapter(
        executable="/fake/subfinder",
        runner=fake_runner,
    )


def test_successful_discovery_is_saved(connection, scope):
    output = json.dumps({
        "host": "api.example.com",
        "source": "crtsh",
    })

    result = run_subfinder_for_scan(
        connection,
        "scan-pipeline-001",
        scope,
        make_adapter(output),
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.COMPLETED
    assert result.discovered_count == 1

    discoveries = list_discovered_subdomains(
        connection,
        "scan-pipeline-001",
    )

    assert len(discoveries) == 1
    assert discoveries[0].hostname == "api.example.com"
    assert discoveries[0].sources == ("crtsh",)

    runs = list_tool_runs(connection, "scan-pipeline-001")

    assert len(runs) == 1
    assert runs[0].status == ToolRunStatus.COMPLETED


def test_failed_execution_is_recorded(connection, scope):
    adapter = make_adapter("", return_code=1)

    result = run_subfinder_for_scan(
        connection,
        "scan-pipeline-001",
        scope,
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.FAILED

    runs = list_tool_runs(connection, "scan-pipeline-001")

    assert runs[0].status == ToolRunStatus.FAILED


def test_out_of_scope_scan_is_rejected(connection):
    with pytest.raises(ScopeValidationError):
        run_subfinder_for_scan(
            connection,
            "scan-pipeline-001",
            ScopePolicy(("other.org",)),
            make_adapter(""),
        )

    assert list_tool_runs(connection, "scan-pipeline-001") == []


def test_missing_scan_is_rejected(connection, scope):
    with pytest.raises(LookupError, match="Scan not found"):
        run_subfinder_for_scan(
            connection,
            "missing",
            scope,
            make_adapter(""),
        )


def test_duplicate_discovery_merges_sources(connection, scope):
    add_discovered_subdomain(
        connection,
        "scan-pipeline-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("crtsh",),
        ),
    )

    output = json.dumps({
        "host": "api.example.com",
        "source": "hackertarget",
    })

    result = run_subfinder_for_scan(
        connection,
        "scan-pipeline-001",
        scope,
        make_adapter(output),
    )

    connection.commit()

    discoveries = list_discovered_subdomains(
        connection,
        "scan-pipeline-001",
    )

    assert result.discovered_count == 1
    assert len(discoveries) == 1
    assert discoveries[0].sources == ("crtsh", "hackertarget")


def test_timeout_is_recorded(connection, scope):
    def timeout_runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, timeout=10)

    adapter = SubfinderAdapter(
        executable="/fake/subfinder",
        runner=timeout_runner,
    )

    result = run_subfinder_for_scan(
        connection,
        "scan-pipeline-001",
        scope,
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.TIMED_OUT

    runs = list_tool_runs(connection, "scan-pipeline-001")

    assert runs[0].status == ToolRunStatus.TIMED_OUT
