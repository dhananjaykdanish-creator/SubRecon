"""Orchestration of DNSx resolution and DNS observation storage."""

import sqlite3

from dataclasses import dataclass

from subrecon.core.models import (
    ToolRun,
    ToolRunStatus,
    utc_now,
)
from subrecon.core.scope import ScopePolicy
from subrecon.integrations.base import (
    ToolExecutionResult,
)
from subrecon.integrations.dnsx import DNSxAdapter
from subrecon.storage.repositories.dns import add_dns_observation
from subrecon.storage.repositories.scans import (
    get_scan,
    list_discovered_subdomains,
)
from subrecon.storage.repositories.tool_runs import (
    add_tool_run,
    update_tool_run,
)


@dataclass(frozen=True, slots=True)
class DNSDiscoveryResult:
    """Result of DNSx execution and database persistence."""

    tool_run_id: int
    execution: ToolExecutionResult
    observation_count: int


def run_dnsx_for_scan(
    connection: sqlite3.Connection,
    scan_id: str,
    scope: ScopePolicy,
    adapter: DNSxAdapter | None = None,
) -> DNSDiscoveryResult:
    """Resolve discovered hostnames and save DNS observations."""

    scan = get_scan(connection, scan_id)

    if scan is None:
        raise LookupError(f"Scan not found: {scan_id}")

    # Verify authorization before executing DNSx.
    scope.require_allowed(scan.root_domain)

    # DNSx receives only hostnames discovered in this scan.
    discoveries = list_discovered_subdomains(
        connection,
        scan_id,
    )

    hostnames = tuple(
        discovery.hostname
        for discovery in discoveries
    )

    # Do not execute DNSx when there are no discovered hostnames.
    if not hostnames:
        reason = "No discovered hostnames are available for DNS resolution."

        tool_run_id = add_tool_run(
            connection,
            scan_id,
            ToolRun(
                tool_name="dnsx",
                status=ToolRunStatus.SKIPPED,
                finished_at=utc_now(),
                error_message=reason,
            ),
        )

        return DNSDiscoveryResult(
            tool_run_id=tool_run_id,
            execution=ToolExecutionResult(
                tool_name="dnsx",
                status=ToolRunStatus.SKIPPED,
                stderr=reason,
            ),
            observation_count=0,
        )

    # Record the execution before starting DNSx.
    tool_run_id = add_tool_run(
        connection,
        scan_id,
        ToolRun(
            tool_name="dnsx",
            status=ToolRunStatus.RUNNING,
        ),
    )

    try:
        adapter = adapter or DNSxAdapter()

        result = adapter.run(
            hostnames,
            scope,
        )

        execution = result.execution

    except Exception as exc:
        error = str(exc)

        execution = ToolExecutionResult(
            tool_name="dnsx",
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

        return DNSDiscoveryResult(
            tool_run_id=tool_run_id,
            execution=execution,
            observation_count=0,
        )

    # Record failed, skipped or timed-out executions.
    if execution.status != ToolRunStatus.COMPLETED:
        update_tool_run(
            connection,
            tool_run_id,
            status=execution.status,
            finished_at=utc_now(),
            exit_code=execution.exit_code,
            error_message=execution.stderr or None,
        )

        return DNSDiscoveryResult(
            tool_run_id=tool_run_id,
            execution=execution,
            observation_count=0,
        )

    # Persist every DNS observation atomically.
    connection.execute("SAVEPOINT dnsx_persistence")

    try:
        for observation in result.observations:
            add_dns_observation(
                connection,
                scan_id,
                observation,
            )

        update_tool_run(
            connection,
            tool_run_id,
            status=ToolRunStatus.COMPLETED,
            finished_at=utc_now(),
            exit_code=execution.exit_code,
        )

        connection.execute(
            "RELEASE SAVEPOINT dnsx_persistence"
        )

    except Exception as exc:
        connection.execute(
            "ROLLBACK TO SAVEPOINT dnsx_persistence"
        )

        connection.execute(
            "RELEASE SAVEPOINT dnsx_persistence"
        )

        error = f"Failed to persist DNSx results: {exc}"

        update_tool_run(
            connection,
            tool_run_id,
            status=ToolRunStatus.FAILED,
            finished_at=utc_now(),
            exit_code=execution.exit_code,
            error_message=error,
        )

        return DNSDiscoveryResult(
            tool_run_id=tool_run_id,
            execution=ToolExecutionResult(
                tool_name="dnsx",
                status=ToolRunStatus.FAILED,
                exit_code=execution.exit_code,
                stderr=error,
                duration_seconds=execution.duration_seconds,
            ),
            observation_count=0,
        )

    return DNSDiscoveryResult(
        tool_run_id=tool_run_id,
        execution=execution,
        observation_count=len(result.observations),
    )
