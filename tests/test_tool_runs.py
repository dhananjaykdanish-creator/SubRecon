"""Tests for external tool execution tracking."""

import pytest

from datetime import datetime, timezone

from subrecon.core.models import (
    Scan,
    ToolRun,
    ToolRunStatus,
)
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.scans import create_scan
from subrecon.storage.repositories.tool_runs import (
    add_tool_run,
    list_tool_runs,
    update_tool_run,
)


@pytest.fixture
def connection(tmp_path):
    """Create a temporary database with one scan."""

    path = tmp_path / "subrecon.db"
    initialize_database(path)

    db = connect_database(path)

    create_scan(
        db,
        Scan(
            scan_id="scan-tools-001",
            root_domain="example.com",
        ),
    )

    db.commit()

    yield db

    db.close()


def test_add_and_retrieve_tool_run(connection):
    run = ToolRun(
        tool_name="subfinder",
        status=ToolRunStatus.COMPLETED,
        exit_code=0,
    )

    run_id = add_tool_run(
        connection,
        "scan-tools-001",
        run,
    )

    connection.commit()

    assert run_id > 0

    results = list_tool_runs(
        connection,
        "scan-tools-001",
    )

    assert len(results) == 1
    assert results[0].tool_name == "subfinder"
    assert results[0].status == ToolRunStatus.COMPLETED
    assert results[0].exit_code == 0


def test_update_running_tool_to_completed(connection):
    run_id = add_tool_run(
        connection,
        "scan-tools-001",
        ToolRun(
            tool_name="amass",
            status=ToolRunStatus.RUNNING,
        ),
    )

    finish_time = datetime.now(timezone.utc)

    update_tool_run(
        connection,
        run_id,
        status=ToolRunStatus.COMPLETED,
        finished_at=finish_time,
        exit_code=0,
    )

    connection.commit()

    result = list_tool_runs(
        connection,
        "scan-tools-001",
    )[0]

    assert result.status == ToolRunStatus.COMPLETED
    assert result.exit_code == 0
    assert result.finished_at == finish_time


def test_failed_tool_error_is_preserved(connection):
    add_tool_run(
        connection,
        "scan-tools-001",
        ToolRun(
            tool_name="amass",
            status=ToolRunStatus.FAILED,
            exit_code=1,
            error_message="Execution failed.",
        ),
    )

    connection.commit()

    result = list_tool_runs(
        connection,
        "scan-tools-001",
    )[0]

    assert result.status == ToolRunStatus.FAILED
    assert result.error_message == "Execution failed."


def test_tool_history_is_preserved(connection):
    add_tool_run(
        connection,
        "scan-tools-001",
        ToolRun(
            tool_name="subfinder",
            status=ToolRunStatus.COMPLETED,
        ),
    )

    add_tool_run(
        connection,
        "scan-tools-001",
        ToolRun(
            tool_name="subfinder",
            status=ToolRunStatus.FAILED,
        ),
    )

    connection.commit()

    results = list_tool_runs(
        connection,
        "scan-tools-001",
    )

    assert len(results) == 2


def test_missing_scan_rejected(connection):
    with pytest.raises(LookupError, match="Scan not found"):
        add_tool_run(
            connection,
            "missing",
            ToolRun(tool_name="subfinder"),
        )


def test_empty_tool_name_rejected(connection):
    with pytest.raises(ValueError, match="Tool name"):
        add_tool_run(
            connection,
            "scan-tools-001",
            ToolRun(tool_name="   "),
        )


def test_missing_tool_run_update_rejected(connection):
    with pytest.raises(LookupError, match="Tool run not found"):
        update_tool_run(
            connection,
            999,
            status=ToolRunStatus.FAILED,
        )


def test_invalid_exit_code_rejected(connection):
    with pytest.raises(ValueError, match="exit code"):
        add_tool_run(
            connection,
            "scan-tools-001",
            ToolRun(
                tool_name="subfinder",
                exit_code=True,
            ),
        )


def test_empty_scan_tool_history(connection):
    results = list_tool_runs(
        connection,
        "scan-tools-001",
    )

    assert results == []
