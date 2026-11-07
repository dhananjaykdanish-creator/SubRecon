"""Tests for the SubRecon check command."""

from typer.testing import CliRunner

from subrecon.cli import app
from subrecon.integrations.base import ToolCheckResult


runner = CliRunner()


def test_check_displays_tool_status(monkeypatch):
    """Check command displays available and missing tools."""

    class FakeToolManager:
        def check_all(self):
            return {
                "subfinder": ToolCheckResult(
                    tool_name="subfinder",
                    available=True,
                    executable="/usr/bin/subfinder",
                    version="2.17.0",
                    detail="Version check successful.",
                ),
                "dnsx": ToolCheckResult(
                    tool_name="dnsx",
                    available=True,
                    executable="/usr/bin/dnsx",
                    version="1.3.1",
                    detail="Version check successful.",
                ),
                "katana": ToolCheckResult(
                    tool_name="katana",
                    available=False,
                    detail="Executable not found.",
                ),
            }

    monkeypatch.setattr(
        "subrecon.commands.check.ToolManager",
        FakeToolManager,
    )

    result = runner.invoke(app, ["check"])

    assert result.exit_code == 0
    assert "subfinder" in result.stdout
    assert "dnsx" in result.stdout
    assert "katana" in result.stdout
    assert "AVAILABLE" in result.stdout
    assert "MISSING / FAILED" in result.stdout
    assert "2/3" in result.stdout


def test_check_handles_no_available_tools(monkeypatch):
    """Check command should work when no tools are installed."""

    class FakeToolManager:
        def check_all(self):
            return {
                "subfinder": ToolCheckResult(
                    tool_name="subfinder",
                    available=False,
                    detail="Executable not found.",
                ),
            }

    monkeypatch.setattr(
        "subrecon.commands.check.ToolManager",
        FakeToolManager,
    )

    result = runner.invoke(app, ["check"])

    assert result.exit_code == 0
    assert "0/1" in result.stdout
