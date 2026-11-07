"""Tests for the DNSx discovery pipeline."""

import pytest

from subrecon.core.models import (
    DNSObservation,
    DiscoveredSubdomain,
    Scan,
    ToolRunStatus,
)
from subrecon.core.scope import ScopePolicy, ScopeValidationError
from subrecon.integrations.base import ToolExecutionResult
from subrecon.integrations.dnsx import DNSxRunResult
from subrecon.modules.dns_discovery import run_dnsx_for_scan
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.dns import list_dns_observations
from subrecon.storage.repositories.scans import (
    add_discovered_subdomain,
    create_scan,
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
            scan_id="scan-dnsx-001",
            root_domain="example.com",
        ),
    )

    db.commit()

    yield db

    db.close()


@pytest.fixture
def scope():
    return ScopePolicy(("example.com",))


class FakeDNSxAdapter:
    """Mock DNSx adapter for pipeline tests."""

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.hostnames = None

    def run(self, hostnames, scope):
        self.hostnames = tuple(hostnames)

        if self.error is not None:
            raise self.error

        return self.result


def make_result(
    status=ToolRunStatus.COMPLETED,
    observations=(),
    exit_code=0,
    stderr="",
):
    execution = ToolExecutionResult(
        tool_name="dnsx",
        status=status,
        exit_code=exit_code,
        stderr=stderr,
    )

    return DNSxRunResult(
        execution=execution,
        observations=tuple(observations),
    )


def add_test_hostnames(connection):
    add_discovered_subdomain(
        connection,
        "scan-dnsx-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("subfinder",),
        ),
    )

    add_discovered_subdomain(
        connection,
        "scan-dnsx-001",
        DiscoveredSubdomain(
            hostname="www.example.com",
            sources=("amass",),
        ),
    )


def test_successful_dns_observations_are_saved(connection, scope):
    add_test_hostnames(connection)

    observations = (
        DNSObservation(
            hostname="api.example.com",
            record_type="A",
            value="192.0.2.10",
            ttl=300,
        ),
        DNSObservation(
            hostname="www.example.com",
            record_type="AAAA",
            value="2001:db8::10",
            ttl=180,
        ),
    )

    adapter = FakeDNSxAdapter(
        result=make_result(observations=observations),
    )

    result = run_dnsx_for_scan(
        connection,
        "scan-dnsx-001",
        scope,
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.COMPLETED
    assert result.observation_count == 2

    assert adapter.hostnames == (
        "api.example.com",
        "www.example.com",
    )

    saved = list_dns_observations(
        connection,
        "scan-dnsx-001",
    )

    assert len(saved) == 2
    assert saved[0].record_type == "A"
    assert saved[0].value == "192.0.2.10"
    assert saved[0].ttl == 300
    assert saved[1].record_type == "AAAA"
    assert saved[1].value == "2001:db8::10"

    runs = list_tool_runs(connection, "scan-dnsx-001")

    assert len(runs) == 1
    assert runs[0].tool_name == "dnsx"
    assert runs[0].status == ToolRunStatus.COMPLETED


def test_failed_execution_is_recorded(connection, scope):
    add_test_hostnames(connection)

    adapter = FakeDNSxAdapter(
        result=make_result(
            status=ToolRunStatus.FAILED,
            exit_code=1,
            stderr="Simulated DNSx failure",
        ),
    )

    result = run_dnsx_for_scan(
        connection,
        "scan-dnsx-001",
        scope,
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.FAILED
    assert result.observation_count == 0

    runs = list_tool_runs(connection, "scan-dnsx-001")

    assert runs[0].status == ToolRunStatus.FAILED


def test_timeout_is_recorded(connection, scope):
    add_test_hostnames(connection)

    adapter = FakeDNSxAdapter(
        result=make_result(
            status=ToolRunStatus.TIMED_OUT,
            stderr="DNSx execution timed out.",
        ),
    )

    result = run_dnsx_for_scan(
        connection,
        "scan-dnsx-001",
        scope,
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.TIMED_OUT

    runs = list_tool_runs(connection, "scan-dnsx-001")

    assert runs[0].status == ToolRunStatus.TIMED_OUT


def test_adapter_exception_is_recorded(connection, scope):
    add_test_hostnames(connection)

    adapter = FakeDNSxAdapter(
        error=RuntimeError("Simulated adapter error"),
    )

    result = run_dnsx_for_scan(
        connection,
        "scan-dnsx-001",
        scope,
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.FAILED
    assert "Simulated adapter error" in result.execution.stderr

    runs = list_tool_runs(connection, "scan-dnsx-001")

    assert runs[0].status == ToolRunStatus.FAILED


def test_no_discovered_hostnames_skips_dnsx(connection, scope):
    adapter = FakeDNSxAdapter(
        error=RuntimeError("DNSx should not execute"),
    )

    result = run_dnsx_for_scan(
        connection,
        "scan-dnsx-001",
        scope,
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.SKIPPED
    assert result.observation_count == 0
    assert adapter.hostnames is None

    runs = list_tool_runs(connection, "scan-dnsx-001")

    assert len(runs) == 1
    assert runs[0].status == ToolRunStatus.SKIPPED


def test_out_of_scope_scan_rejected(connection):
    with pytest.raises(ScopeValidationError):
        run_dnsx_for_scan(
            connection,
            "scan-dnsx-001",
            ScopePolicy(("other.org",)),
        )

    assert list_tool_runs(connection, "scan-dnsx-001") == []


def test_missing_scan_rejected(connection, scope):
    with pytest.raises(LookupError, match="Scan not found"):
        run_dnsx_for_scan(
            connection,
            "missing",
            scope,
        )


def test_failed_persistence_rolls_back_all_observations(
    connection,
    scope,
):
    add_discovered_subdomain(
        connection,
        "scan-dnsx-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("subfinder",),
        ),
    )

    observations = (
        DNSObservation(
            hostname="api.example.com",
            record_type="A",
            value="192.0.2.10",
            ttl=300,
        ),
        DNSObservation(
            hostname="other.org",
            record_type="A",
            value="192.0.2.20",
            ttl=300,
        ),
    )

    adapter = FakeDNSxAdapter(
        result=make_result(observations=observations),
    )

    result = run_dnsx_for_scan(
        connection,
        "scan-dnsx-001",
        scope,
        adapter,
    )

    connection.commit()

    assert result.execution.status == ToolRunStatus.FAILED
    assert result.observation_count == 0
    assert "Failed to persist DNSx results" in result.execution.stderr

    # The first observation must also be rolled back.
    assert list_dns_observations(
        connection,
        "scan-dnsx-001",
    ) == []

    runs = list_tool_runs(connection, "scan-dnsx-001")

    assert runs[0].status == ToolRunStatus.FAILED
