"""Unified orchestration for passive subdomain discovery."""

import hashlib
import sqlite3

from dataclasses import dataclass
from pathlib import Path

from subrecon.core.models import (
    DiscoveredSubdomain,
    ToolRun,
    ToolRunStatus,
    utc_now,
)
from subrecon.core.scope import ScopePolicy
from subrecon.integrations.amass import AmassAdapter
from subrecon.integrations.base import (
    IntegrationError,
    ToolExecutionResult,
)
from subrecon.integrations.subfinder import SubfinderAdapter
from subrecon.modules.amass_discovery import (
    AmassDiscoveryResult,
    run_amass_for_scan,
)
from subrecon.modules.subdomain_discovery import (
    DiscoveryPipelineResult,
    run_subfinder_for_scan,
)
from subrecon.storage.repositories.scans import (
    get_scan,
    list_discovered_subdomains,
)
from subrecon.storage.repositories.tool_runs import add_tool_run


@dataclass(frozen=True, slots=True)
class PassiveDiscoveryResult:
    """Combined results from Subfinder and Amass."""

    subfinder: DiscoveryPipelineResult
    amass: AmassDiscoveryResult
    discoveries: tuple[DiscoveredSubdomain, ...]

    @property
    def unique_hostname_count(self) -> int:
        """Total unique hostnames stored for this scan."""
        return len(self.discoveries)


def _record_skipped_tool(
    connection: sqlite3.Connection,
    scan_id: str,
    tool_name: str,
    reason: str,
):
    """Record a tool that could not be initialized."""

    run_id = add_tool_run(
        connection,
        scan_id,
        ToolRun(
            tool_name=tool_name,
            status=ToolRunStatus.SKIPPED,
            finished_at=utc_now(),
            error_message=reason,
        ),
    )

    return run_id


def run_passive_discovery(
    connection: sqlite3.Connection,
    scan_id: str,
    scope: ScopePolicy,
    workspace: str | Path,
    subfinder_adapter: SubfinderAdapter | None = None,
    amass_adapter: AmassAdapter | None = None,
) -> PassiveDiscoveryResult:
    """Run Subfinder and Amass independently and combine their results.

    Missing tool installations are recorded as skipped.
    A failure in one tool does not prevent the other from running.
    Database changes remain under the caller's transaction control.
    """

    scan = get_scan(connection, scan_id)

    if scan is None:
        raise LookupError(f"Scan not found: {scan_id}")

    # Validate authorization before initializing either tool.
    scope.require_allowed(scan.root_domain)

    # Each scan receives an isolated Amass workspace.
    workspace_key = hashlib.sha256(
        scan_id.encode("utf-8")
    ).hexdigest()[:16]

    amass_workspace = (
        Path(workspace).expanduser()
        / workspace_key
        / "amass"
    )

    amass_workspace.mkdir(parents=True, exist_ok=True)

    # ---------------- SUBFINDER ----------------

    try:
        if subfinder_adapter is None:
            subfinder_adapter = SubfinderAdapter()

        subfinder_result = run_subfinder_for_scan(
            connection,
            scan_id,
            scope,
            subfinder_adapter,
        )

    except IntegrationError as exc:
        run_id = _record_skipped_tool(
            connection,
            scan_id,
            "subfinder",
            str(exc),
        )

        subfinder_result = DiscoveryPipelineResult(
            tool_run_id=run_id,
            execution=ToolExecutionResult(
                tool_name="subfinder",
                status=ToolRunStatus.SKIPPED,
                stderr=str(exc),
            ),
            discovered_count=0,
        )

    # ---------------- AMASS ----------------

    try:
        if amass_adapter is None:
            amass_adapter = AmassAdapter()

        amass_result = run_amass_for_scan(
            connection,
            scan_id,
            scope,
            amass_workspace,
            amass_adapter,
        )

    except IntegrationError as exc:
        run_id = _record_skipped_tool(
            connection,
            scan_id,
            "amass",
            str(exc),
        )

        amass_result = AmassDiscoveryResult(
            tool_run_id=run_id,
            execution=ToolExecutionResult(
                tool_name="amass",
                status=ToolRunStatus.SKIPPED,
                stderr=str(exc),
            ),
            discovered_count=0,
        )

    # Both repositories consolidate duplicate hostnames.
    discoveries = tuple(
        list_discovered_subdomains(connection, scan_id)
    )

    return PassiveDiscoveryResult(
        subfinder=subfinder_result,
        amass=amass_result,
        discoveries=discoveries,
    )
