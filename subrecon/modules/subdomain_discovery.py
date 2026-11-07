"""Orchestration of passive subdomain discovery."""

import sqlite3

from dataclasses import dataclass

from subrecon.core.models import ToolRun, ToolRunStatus, utc_now
from subrecon.core.scope import ScopePolicy
from subrecon.integrations.base import ToolExecutionResult
from subrecon.integrations.subfinder import SubfinderAdapter
from subrecon.storage.repositories.scans import (
    add_discovered_subdomain,
    get_scan,
)
from subrecon.storage.repositories.tool_runs import (
    add_tool_run,
    update_tool_run,
)


@dataclass(frozen=True, slots=True)
class DiscoveryPipelineResult:
    """Result of a Subfinder execution and database persistence."""

    tool_run_id: int
    execution: ToolExecutionResult
    discovered_count: int


def run_subfinder_for_scan(
    connection: sqlite3.Connection,
    scan_id: str,
    scope: ScopePolicy,
    adapter: SubfinderAdapter | None = None,
) -> DiscoveryPipelineResult:
    """Run passive Subfinder for an authorized scan and store its results."""

    scan = get_scan(connection, scan_id)

    if scan is None:
        raise LookupError(f"Scan not found: {scan_id}")

    # Validate the scan's root domain before recording or executing anything.
    scope.require_allowed(scan.root_domain)

    adapter = adapter or SubfinderAdapter()

    tool_run_id = add_tool_run(
        connection,
        scan_id,
        ToolRun(
            tool_name="subfinder",
            status=ToolRunStatus.RUNNING,
        ),
    )

    try:
        result = adapter.run(scan.root_domain, scope)
        execution = result.execution

    except Exception as exc:
        execution = ToolExecutionResult(
            tool_name="subfinder",
            status=ToolRunStatus.FAILED,
            stderr=str(exc),
        )

        update_tool_run(
            connection,
            tool_run_id,
            status=ToolRunStatus.FAILED,
            finished_at=utc_now(),
            error_message=str(exc),
        )

        return DiscoveryPipelineResult(
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

        return DiscoveryPipelineResult(
            tool_run_id=tool_run_id,
            execution=execution,
            discovered_count=0,
        )

    # Persist discoveries atomically using a savepoint.
    connection.execute("SAVEPOINT subfinder_persistence")

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

        connection.execute("RELEASE SAVEPOINT subfinder_persistence")

    except Exception as exc:
        connection.execute(
            "ROLLBACK TO SAVEPOINT subfinder_persistence"
        )
        connection.execute(
            "RELEASE SAVEPOINT subfinder_persistence"
        )

        error = f"Failed to persist Subfinder results: {exc}"

        update_tool_run(
            connection,
            tool_run_id,
            status=ToolRunStatus.FAILED,
            finished_at=utc_now(),
            exit_code=execution.exit_code,
            error_message=error,
        )

        return DiscoveryPipelineResult(
            tool_run_id=tool_run_id,
            execution=ToolExecutionResult(
                tool_name="subfinder",
                status=ToolRunStatus.FAILED,
                exit_code=execution.exit_code,
                stderr=error,
                duration_seconds=execution.duration_seconds,
            ),
            discovered_count=0,
        )

    return DiscoveryPipelineResult(
        tool_run_id=tool_run_id,
        execution=execution,
        discovered_count=len(result.discovered),
    )
