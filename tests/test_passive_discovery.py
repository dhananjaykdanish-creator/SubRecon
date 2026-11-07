"""Tests for the unified passive discovery engine."""

import json
import subprocess

import pytest

from subrecon.core.models import Scan, ToolRunStatus
from subrecon.core.scope import ScopePolicy, ScopeValidationError
from subrecon.integrations.amass import AmassAdapter
from subrecon.integrations.base import IntegrationError
from subrecon.integrations.subfinder import SubfinderAdapter
from subrecon.modules.passive_discovery import run_passive_discovery
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.scans import (
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
            scan_id="scan-unified-001",
            root_domain="example.com",
        ),
    )

    db.commit()

    yield db
    db.close()


@pytest.fixture
def scope():
    return ScopePolicy(("example.com",))


def make_subfinder(output="", return_code=0):
    def fake_runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            return_code,
            stdout=output,
            stderr="Simulated Subfinder output",
        )

    return SubfinderAdapter(
        executable="/fake/subfinder",
        runner=fake_runner,
    )


def make_amass(output="", return_code=0):
    def fake_runner(command, **kwargs):
        if command[1] == "enum":
            return subprocess.CompletedProcess(
                command,
                return_code,
                stdout="",
                stderr="Simulated Amass output",
            )

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=output,
            stderr="",
        )

    return AmassAdapter(
        executable="/fake/amass",
        runner=fake_runner,
    )


def test_both_tools_success_and_merge_sources(
    connection,
    scope,
    tmp_path,
):
    subfinder_output = json.dumps({
        "host": "api.example.com",
        "source": "crtsh",
    })

    amass_output = (
        "api.example.com\n"
        "www.example.com\n"
    )

    result = run_passive_discovery(
        connection,
        "scan-unified-001",
        scope,
        tmp_path,
        make_subfinder(subfinder_output),
        make_amass(amass_output),
    )

    connection.commit()

    assert result.subfinder.execution.status == ToolRunStatus.COMPLETED
    assert result.amass.execution.status == ToolRunStatus.COMPLETED

    assert result.unique_hostname_count == 2

    api = next(
        item for item in result.discoveries
        if item.hostname == "api.example.com"
    )

    assert api.sources == ("amass", "crtsh")

    runs = list_tool_runs(connection, "scan-unified-001")

    assert len(runs) == 2
    assert all(run.status == ToolRunStatus.COMPLETED for run in runs)


def test_amass_runs_when_subfinder_fails(
    connection,
    scope,
    tmp_path,
):
    result = run_passive_discovery(
        connection,
        "scan-unified-001",
        scope,
        tmp_path,
        make_subfinder(return_code=1),
        make_amass("api.example.com\n"),
    )

    connection.commit()

    assert result.subfinder.execution.status == ToolRunStatus.FAILED
    assert result.amass.execution.status == ToolRunStatus.COMPLETED
    assert result.unique_hostname_count == 1


def test_subfinder_results_survive_amass_failure(
    connection,
    scope,
    tmp_path,
):
    output = json.dumps({
        "host": "api.example.com",
        "source": "crtsh",
    })

    result = run_passive_discovery(
        connection,
        "scan-unified-001",
        scope,
        tmp_path,
        make_subfinder(output),
        make_amass(return_code=1),
    )

    connection.commit()

    assert result.subfinder.execution.status == ToolRunStatus.COMPLETED
    assert result.amass.execution.status == ToolRunStatus.FAILED
    assert result.unique_hostname_count == 1


def test_missing_subfinder_does_not_block_amass(
    connection,
    scope,
    tmp_path,
    monkeypatch,
):
    import subrecon.modules.passive_discovery as module

    def missing_subfinder():
        raise IntegrationError("Subfinder is not installed.")

    monkeypatch.setattr(
        module,
        "SubfinderAdapter",
        missing_subfinder,
    )

    result = run_passive_discovery(
        connection,
        "scan-unified-001",
        scope,
        tmp_path,
        amass_adapter=make_amass("api.example.com\n"),
    )

    connection.commit()

    assert result.subfinder.execution.status == ToolRunStatus.SKIPPED
    assert result.amass.execution.status == ToolRunStatus.COMPLETED


def test_missing_amass_does_not_block_subfinder(
    connection,
    scope,
    tmp_path,
    monkeypatch,
):
    import subrecon.modules.passive_discovery as module

    def missing_amass():
        raise IntegrationError("Amass is not installed.")

    output = json.dumps({
        "host": "api.example.com",
        "source": "crtsh",
    })

    monkeypatch.setattr(
        module,
        "AmassAdapter",
        missing_amass,
    )

    result = run_passive_discovery(
        connection,
        "scan-unified-001",
        scope,
        tmp_path,
        subfinder_adapter=make_subfinder(output),
    )

    connection.commit()

    assert result.subfinder.execution.status == ToolRunStatus.COMPLETED
    assert result.amass.execution.status == ToolRunStatus.SKIPPED


def test_scope_mismatch_rejected_before_execution(
    connection,
    tmp_path,
):
    with pytest.raises(ScopeValidationError):
        run_passive_discovery(
            connection,
            "scan-unified-001",
            ScopePolicy(("other.org",)),
            tmp_path,
            make_subfinder(),
            make_amass(),
        )

    assert list_tool_runs(connection, "scan-unified-001") == []


def test_missing_scan_rejected(connection, scope, tmp_path):
    with pytest.raises(LookupError, match="Scan not found"):
        run_passive_discovery(
            connection,
            "missing",
            scope,
            tmp_path,
            make_subfinder(),
            make_amass(),
        )


def test_existing_discoveries_are_included_in_unique_count(
    connection,
    scope,
    tmp_path,
):
    from subrecon.core.models import DiscoveredSubdomain
    from subrecon.storage.repositories.scans import add_discovered_subdomain

    add_discovered_subdomain(
        connection,
        "scan-unified-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("manual",),
        ),
    )

    result = run_passive_discovery(
        connection,
        "scan-unified-001",
        scope,
        tmp_path,
        make_subfinder(),
        make_amass(),
    )

    connection.commit()

    assert result.unique_hostname_count == 1
    assert result.discoveries[0].sources == ("manual",)


def test_skipped_tool_is_recorded_in_database(
    connection,
    scope,
    tmp_path,
    monkeypatch,
):
    import subrecon.modules.passive_discovery as module

    def missing_subfinder():
        raise IntegrationError("Subfinder unavailable.")

    monkeypatch.setattr(
        module,
        "SubfinderAdapter",
        missing_subfinder,
    )

    run_passive_discovery(
        connection,
        "scan-unified-001",
        scope,
        tmp_path,
        amass_adapter=make_amass(),
    )

    connection.commit()

    runs = list_tool_runs(connection, "scan-unified-001")

    assert len(runs) == 2
    assert any(run.status == ToolRunStatus.SKIPPED for run in runs)
