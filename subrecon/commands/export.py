"""Export stored reconnaissance results into report files."""

import typer

from pathlib import Path

from rich.console import Console

from subrecon.config import load_config
from subrecon.reporting.data import build_scan_report
from subrecon.reporting.json_export import export_json
from subrecon.reporting.csv_export import export_csv
from subrecon.reporting.txt_export import export_txt
from subrecon.reporting.html_export import export_html
from subrecon.storage.database import connect_database


console = Console()

EXPORTERS = {
    "json": export_json,
    "csv": export_csv,
    "txt": export_txt,
    "html": export_html,
}


def run_export_command(
    scan_id: str,
    output_format: str = "json",
    output_path: Path | None = None,
) -> Path:
    """Build and export a report for an existing scan."""

    output_format = output_format.lower().strip()

    if output_format not in EXPORTERS:
        console.print(
            "[red]Unsupported export format.[/] "
            "Choose json, csv, txt or html."
        )
        raise typer.Exit(code=2)

    try:
        config = load_config()
        database_path = Path(config.database_path)

        if not database_path.is_file():
            console.print(
                "[red]Database not found. Run a scan first.[/]"
            )
            raise typer.Exit(code=1)

        connection = connect_database(database_path)

        try:
            report = build_scan_report(
                connection,
                scan_id,
            )
        finally:
            connection.close()

        if output_path is None:
            safe_scan_id = "".join(
                character
                for character in scan_id
                if character.isalnum() or character in "-_"
            )

            if not safe_scan_id:
                raise ValueError("Invalid scan ID for output filename.")

            destination = (
                config.results_dir
                / "reports"
                / f"{safe_scan_id}.{output_format}"
            )
        else:
            destination = Path(output_path).expanduser()

        exporter = EXPORTERS[output_format]

        exported_path = exporter(
            report,
            destination,
        )

    except typer.Exit:
        raise

    except (OSError, ValueError, LookupError) as exc:
        console.print(
            f"\n[bold red]Export failed:[/] {exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print()
    console.print(
        "[bold green]Report exported successfully![/]"
    )
    console.print(f"[cyan]Format:[/] {output_format.upper()}")
    console.print(f"[cyan]File:[/] {exported_path}")

    return exported_path


def export(
    scan_id: str = typer.Argument(
        ...,
        help="ID of the scan to export.",
    ),
    output_format: str = typer.Option(
        "json",
        "--format",
        help="Export format: json, csv, txt or html.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Optional destination file path.",
    ),
) -> None:
    """Export scan results into JSON, CSV, TXT or HTML."""

    run_export_command(
        scan_id=scan_id,
        output_format=output_format,
        output_path=output,
    )
