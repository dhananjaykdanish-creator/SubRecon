"""Display reconnaissance results from SQLite."""

import typer

from pathlib import Path

from rich.console import Console
from rich.table import Table

from subrecon.config import load_config
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.dns import list_dns_observations
from subrecon.storage.repositories.scans import (
    get_scan,
    list_discovered_subdomains,
)


console = Console()


def run_results_command(scan_id: str) -> None:
    """Display discovered hostnames and DNS observations."""

    try:
        config = load_config()
        database_path = Path(config.database_path)

        if not database_path.is_file():
            console.print(
                "[yellow]No database found. Run a scan first.[/]"
            )
            raise typer.Exit(code=1)

        initialize_database(database_path)
        connection = connect_database(database_path)

        try:
            scan = get_scan(connection, scan_id)

            if scan is None:
                console.print(
                    f"[red]Scan not found: {scan_id}[/]"
                )
                raise typer.Exit(code=1)

            discoveries = list_discovered_subdomains(
                connection,
                scan_id,
            )

            observations = list_dns_observations(
                connection,
                scan_id,
            )

        finally:
            connection.close()

    except typer.Exit:
        raise

    except Exception as exc:
        console.print(
            f"[red]Unable to retrieve scan results: {exc}[/]"
        )
        raise typer.Exit(code=1) from exc

    console.print()
    console.print("[bold cyan]SubRecon - Scan Results[/]")
    console.print()

    details = Table(
        title="Scan Information",
        show_lines=True,
    )

    details.add_column("Property", style="cyan")
    details.add_column("Value")

    details.add_row("Scan ID", scan.scan_id)
    details.add_row("Domain", scan.root_domain)
    details.add_row("Status", scan.status.value.upper())
    details.add_row(
        "Started",
        scan.started_at.astimezone().strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        ),
    )

    details.add_row(
        "Completed",
        (
            scan.completed_at.astimezone().strftime(
                "%Y-%m-%d %H:%M:%S %Z"
            )
            if scan.completed_at
            else "-"
        ),
    )

    console.print(details)
    console.print()

    hostname_table = Table(
        title="Discovered Hostnames",
        show_lines=True,
    )

    hostname_table.add_column("Hostname", style="cyan")
    hostname_table.add_column("Discovery Sources")

    for discovery in discoveries:
        sources = (
            ", ".join(discovery.sources)
            if discovery.sources
            else "-"
        )

        hostname_table.add_row(
            discovery.hostname,
            sources,
        )

    if discoveries:
        console.print(hostname_table)
    else:
        console.print(
            "[yellow]No discovered hostnames were recorded.[/]"
        )

    console.print()

    dns_table = Table(
        title="DNS Observations",
        show_lines=True,
    )

    dns_table.add_column("Hostname", style="cyan")
    dns_table.add_column("Record Type")
    dns_table.add_column("Value")
    dns_table.add_column("TTL")

    for observation in observations:
        dns_table.add_row(
            observation.hostname,
            observation.record_type,
            observation.value,
            (
                str(observation.ttl)
                if observation.ttl is not None
                else "-"
            ),
        )

    if observations:
        console.print(dns_table)
    else:
        console.print(
            "[yellow]No DNS observations were recorded.[/]"
        )

    console.print()
    console.print(
        f"Hostnames: {len(discoveries)} | "
        f"DNS observations: {len(observations)}"
    )


def results(
    scan_id: str = typer.Argument(
        ...,
        help="ID of the scan whose results should be displayed.",
    ),
) -> None:
    """View discovered hostnames and DNS observations."""

    run_results_command(scan_id)
