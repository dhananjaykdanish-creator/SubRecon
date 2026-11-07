"""Check availability of external reconnaissance tools."""

from rich.console import Console
from rich.table import Table
from rich.text import Text

from subrecon.integrations.manager import ToolManager


def run_check() -> None:
    """Display installed tools and their availability."""

    manager = ToolManager()
    results = manager.check_all()

    console = Console()

    table = Table(
        title="SubRecon - Tool Availability",
        show_lines=True,
    )

    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Executable")
    table.add_column("Details")

    available_count = 0

    for name, result in results.items():
        if result.available:
            available_count += 1
            status = Text("AVAILABLE", style="bold green")
        else:
            status = Text("MISSING / FAILED", style="bold red")

        table.add_row(
            name,
            status,
            result.version or "-",
            result.executable or "-",
            result.detail or "-",
        )

    console.print()
    console.print(table)
    console.print(
        f"\nAvailable tools: {available_count}/{len(results)}"
    )
