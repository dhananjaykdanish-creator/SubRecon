"""SubRecon command-line interface."""

import typer

from subrecon import __version__
from subrecon.commands.check import run_check
from subrecon.commands.export import export
from subrecon.commands.history import history
from subrecon.commands.results import results
from subrecon.commands.scan import run_scan_command


app = typer.Typer(
    name="subrecon",
    help="Advanced Subdomain Reconnaissance & Website Asset Discovery Tool.",
    no_args_is_help=True,
)


def version_callback(value: bool) -> None:
    """Display the application version."""

    if value:
        typer.echo(f"SubRecon {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Display the SubRecon version.",
    ),
) -> None:
    """SubRecon - Authorized reconnaissance framework."""


@app.command()
def check() -> None:
    """Check installed reconnaissance tools and versions."""

    run_check()


@app.command()
def scan(
    domain: str = typer.Argument(
        ...,
        help="Authorized root domain to assess.",
    ),
    confirm_authorization: bool = typer.Option(
        False,
        "--confirm-authorization",
        help="Confirm ownership or explicit authorization.",
    ),
) -> None:
    """Run passive subdomain discovery and DNS resolution."""

    run_scan_command(
        domain=domain,
        confirm_authorization=confirm_authorization,
    )


app.command()(history)
app.command()(results)
app.command()(export)


if __name__ == "__main__":
    app()
