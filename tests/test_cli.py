"""Tests for the SubRecon command-line interface."""

from typer.testing import CliRunner

from subrecon import __version__
from subrecon.cli import app

runner = CliRunner()


def test_version_option():
    """The version option should display the current version."""
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert f"SubRecon {__version__}" in result.stdout


def test_help_option():
    """The help option should display CLI information."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Advanced Subdomain Reconnaissance" in result.stdout
    assert "--version" in result.stdout
