"""Display previous SubRecon scans."""

import typer

from pathlib import Path

from rich.console import Console
from rich.table import Table

from subrecon.config import load_config
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.scans import list_scans


console = Console()


def run_history_command(limit: int = 20) -> None:
    """Display recent scans from the SubRecon database."""

    try:
        config = load_config()
        database_path = Path(config.database_path)

        if not database_path.is_file():
            console.print(
                "[yellow]No scan history found. "
                "Run a scan to create your first history record.[/]"
            )
            return

        initialize_database(database_path)
        connection = connect_database(database_path)

        try:
            scans = list_scans(connection, limit)
        finally:
            connection.close()

    except Exception as exc:
        console.print(f"[red]Unable to read scan history: {exc}[/]")
        raise typer.Exit(code=1) from exc

    if not scans:
        console.print("[yellow]No scan history found.[/]")
        return

    table = Table(
        title="SubRecon - Scan History",
        show_lines=True,
    )

    table.add_column("Scan ID", style="cyan")
    table.add_column("Domain")
    table.add_column("Status")
    table.add_column("Started")

    for scan in scans:
        status = scan.status.value.upper()

        if status == "COMPLETED":
            status_display = f"[green]{status}[/]"
        elif status == "FAILED":
            status_display = f"[red]{status}[/]"
        else:
            status_display = f"[yellow]{status}[/]"

        started = scan.started_at.astimezone().strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        )

        table.add_row(
            scan.scan_id,
            scan.root_domain,
            status_display,
            started,
        )

    console.print()
    console.print(table)
    console.print(f"\nShowing {len(scans)} scan(s).")


def history(
    limit: int = typer.Option(
        20,
        "--limit",
        min=1,
        help="Maximum number of recent scans to display.",
    ),
) -> None:
    """View previous reconnaissance scans."""

    run_history_command(limit)
