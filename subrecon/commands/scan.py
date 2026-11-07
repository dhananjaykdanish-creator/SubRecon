"""Unified authorized reconnaissance scan command."""

from uuid import uuid4

import typer

from rich.console import Console
from rich.table import Table

from subrecon.config import load_config
from subrecon.core.models import (
    Scan,
    ScanStatus,
    ToolRunStatus,
)
from subrecon.core.normalization import normalize_hostname
from subrecon.core.scope import ScopePolicy
from subrecon.core.models import utc_now
from subrecon.modules.passive_discovery import run_passive_discovery
from subrecon.modules.dns_discovery import run_dnsx_for_scan
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.scans import (
    create_scan,
    update_scan_status,
)


console = Console()


def run_scan_command(
    domain: str,
    confirm_authorization: bool = False,
) -> None:
    """Run passive discovery and DNS resolution for an authorized domain."""

    if not confirm_authorization:
        console.print(
            "[bold red]Authorization confirmation required.[/]\n"
            "Use --confirm-authorization only when you own "
            "the domain or have explicit permission to assess it."
        )
        raise typer.Exit(code=2)

    try:
        root_domain = normalize_hostname(domain)
        scope = ScopePolicy((root_domain,))
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Invalid target domain: {exc}[/]")
        raise typer.Exit(code=2) from exc

    connection = None
    scan_id = uuid4().hex
    scan_created = False

    try:
        config = load_config()

        config.results_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        initialize_database(config.database_path)

        connection = connect_database(config.database_path)

        # Create and persist the scan before external tools start.
        create_scan(
            connection,
            Scan(
                scan_id=scan_id,
                root_domain=root_domain,
                status=ScanStatus.RUNNING,
            ),
        )

        connection.commit()
        scan_created = True

        # Stage 1: Passive subdomain discovery.
        passive_result = run_passive_discovery(
            connection=connection,
            scan_id=scan_id,
            scope=scope,
            workspace=config.results_dir / "workspaces",
        )

        # Stage 2: Resolve only discovered, in-scope hostnames.
        dns_result = run_dnsx_for_scan(
            connection=connection,
            scan_id=scan_id,
            scope=scope,
        )

        discovery_statuses = (
            passive_result.subfinder.execution.status,
            passive_result.amass.execution.status,
        )

        # A scan is successful when at least one discovery provider
        # completes. Individual tool failures remain in tool_runs.
        discovery_succeeded = any(
            status == ToolRunStatus.COMPLETED
            for status in discovery_statuses
        )

        final_status = (
            ScanStatus.COMPLETED
            if discovery_succeeded
            else ScanStatus.FAILED
        )

        update_scan_status(
            connection,
            scan_id,
            final_status,
            utc_now(),
        )

        connection.commit()

    except Exception as exc:
        if connection is not None and scan_created:
            try:
                # Remove incomplete pipeline changes but preserve
                # the initial scan record.
                connection.rollback()

                update_scan_status(
                    connection,
                    scan_id,
                    ScanStatus.FAILED,
                    utc_now(),
                )

                connection.commit()

            except Exception:
                connection.rollback()

        console.print(
            f"\n[bold red]Scan execution failed:[/] {exc}"
        )

        raise typer.Exit(code=1) from exc

    finally:
        if connection is not None:
            connection.close()

    # Display the final scan report.
    table = Table(
        title="SubRecon - Scan Summary",
        show_lines=True,
    )

    table.add_column("Property", style="cyan")
    table.add_column("Result")

    table.add_row("Scan ID", scan_id)
    table.add_row("Domain", root_domain)
    table.add_row("Scan status", final_status.value.upper())

    table.add_row(
        "Discovered hostnames",
        str(passive_result.unique_hostname_count),
    )

    table.add_row(
        "DNS observations",
        str(dns_result.observation_count),
    )

    table.add_row(
        "Subfinder",
        passive_result.subfinder.execution.status.value.upper(),
    )

    table.add_row(
        "Amass",
        passive_result.amass.execution.status.value.upper(),
    )

    table.add_row(
        "DNSx",
        dns_result.execution.status.value.upper(),
    )

    console.print()
    console.print(table)

    if final_status == ScanStatus.FAILED:
        console.print(
            "\n[bold red]No discovery provider completed successfully.[/]"
        )
        raise typer.Exit(code=1)

    if dns_result.execution.status != ToolRunStatus.COMPLETED:
        console.print(
            "\n[yellow]Warning: DNS resolution did not complete. "
            "Check the recorded tool status.[/]"
        )

    console.print(
        "\n[bold green]Scan workflow completed.[/]"
    )
