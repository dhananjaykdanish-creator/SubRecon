"""Orchestration of passive Amass discovery."""

import sqlite3

from dataclasses import dataclass
from pathlib import Path

from subrecon.core.models import ToolRun, ToolRunStatus, utc_now
from subrecon.core.scope import ScopePolicy
from subrecon.integrations.amass import AmassAdapter
from subrecon.integrations.base import ToolExecutionResult
from subrecon.storage.repositories.scans import (
    add_discovered_subdomain,
    get_scan,
)
from subrecon.storage.repositories.tool_runs import (
    add_tool_run,
    update_tool_run,
)


@dataclass(frozen=True, slots=True)
class AmassDiscoveryResult:
    """Result of Amass execution and database persistence."""

    tool_run_id: int
    execution: ToolExecutionResult
    discovered_count: int


def run_amass_for_scan(
    connection: sqlite3.Connection,
    scan_id: str,
    scope: ScopePolicy,
    workspace: str | Path,
    adapter: AmassAdapter | None = None,
) -> AmassDiscoveryResult:
    """Run passive Amass for an authorized scan and store its results."""

    scan = get_scan(connection, scan_id)

    if scan is None:
        raise LookupError(f"Scan not found: {scan_id}")

    # Validate the scan's root domain before executing Amass.
    scope.require_allowed(scan.root_domain)

    tool_run_id = add_tool_run(
        connection,
        scan_id,
        ToolRun(
            tool_name="amass",
            status=ToolRunStatus.RUNNING,
        ),
    )

    try:
        adapter = adapter or AmassAdapter()

        result = adapter.run(
            scan.root_domain,
            scope,
            workspace,
        )

        execution = result.execution

    except Exception as exc:
        error = str(exc)

        execution = ToolExecutionResult(
            tool_name="amass",
            status=ToolRunStatus.FAILED,
            stderr=error,
        )

        update_tool_run(
            connection,
            tool_run_id,
            status=ToolRunStatus.FAILED,
            finished_at=utc_now(),
            error_message=error,
        )

        return AmassDiscoveryResult(
            tool_run_id=tool_run_id,
            execution=execution,
            discovered_count=0,
        )

    if execution.status != ToolRunStatus.COMPLETED:
        update_tool_run(
            connection,
            tool_run_id,
            status=execution.status,
            finished_at=utc_now(),
            exit_code=execution.exit_code,
            error_message=execution.stderr or None,
        )

        return AmassDiscoveryResult(
            tool_run_id=tool_run_id,
            execution=execution,
            discovered_count=0,
        )

    # Persist discoveries atomically.
    connection.execute("SAVEPOINT amass_persistence")

    try:
        for subdomain in result.discovered:
            add_discovered_subdomain(
                connection,
                scan_id,
                subdomain,
            )

        update_tool_run(
            connection,
            tool_run_id,
            status=ToolRunStatus.COMPLETED,
            finished_at=utc_now(),
            exit_code=execution.exit_code,
        )

        connection.execute("RELEASE SAVEPOINT amass_persistence")

    except Exception as exc:
        connection.execute(
            "ROLLBACK TO SAVEPOINT amass_persistence"
        )
        connection.execute(
            "RELEASE SAVEPOINT amass_persistence"
        )

        error = f"Failed to persist Amass results: {exc}"

        update_tool_run(
            connection,
            tool_run_id,
            status=ToolRunStatus.FAILED,
            finished_at=utc_now(),
            exit_code=execution.exit_code,
            error_message=error,
        )

        return AmassDiscoveryResult(
            tool_run_id=tool_run_id,
            execution=ToolExecutionResult(
                tool_name="amass",
                status=ToolRunStatus.FAILED,
                exit_code=execution.exit_code,
                stderr=error,
                duration_seconds=execution.duration_seconds,
            ),
            discovered_count=0,
        )

    return AmassDiscoveryResult(
        tool_run_id=tool_run_id,
        execution=execution,
        discovered_count=len(result.discovered),
    )
