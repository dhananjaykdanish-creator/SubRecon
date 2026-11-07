"""Tests for the external integration manager."""

import subprocess

from subrecon.integrations.manager import ToolManager


def create_fake_executable(tmp_path, name):
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return str(path)


def test_detect_and_verify_subfinder(tmp_path, monkeypatch):
    executable = create_fake_executable(tmp_path, "subfinder")

    manager = ToolManager(
        tool_paths={"subfinder": executable}
    )

    def fake_run(command, **kwargs):
        assert command == [executable, "-version"]

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="[INF] Current Version: v2.17.0",
            stderr="",
        )

    monkeypatch.setattr(
        "subrecon.integrations.manager.subprocess.run",
        fake_run,
    )

    result = manager.check_tool("subfinder")

    assert result.available
    assert result.version == "2.17.0"
    assert result.executable == executable


def test_missing_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "subrecon.integrations.manager.shutil.which",
        lambda name: None,
    )

    manager = ToolManager()

    result = manager.check_tool("dnsx")

    assert not result.available
    assert result.executable is None


def test_python_httpx_is_not_projectdiscovery(
    tmp_path,
    monkeypatch,
):
    executable = create_fake_executable(tmp_path, "httpx")

    manager = ToolManager(
        tool_paths={"httpx": executable}
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="Usage: httpx [OPTIONS] URL",
            stderr="Error: No such option: -e",
        )

    monkeypatch.setattr(
        "subrecon.integrations.manager.subprocess.run",
        fake_run,
    )

    result = manager.check_tool("httpx")

    assert not result.available
    assert "not verified as ProjectDiscovery HTTPx" in result.detail


def test_amass_shell_wrapper_is_rejected(tmp_path):
    wrapper = tmp_path / "amass"
    wrapper.write_text("#!/bin/sh\nsudo libpostal_data download all\n")
    wrapper.chmod(0o755)

    manager = ToolManager(
        tool_paths={"amass": str(wrapper)}
    )

    result = manager.check_tool("amass")

    assert not result.available
    assert "shell wrapper" in result.detail


def test_unsupported_tool_rejected():
    manager = ToolManager()

    try:
        manager.check_tool("unknown")
    except ValueError as exc:
        assert "Unsupported tool" in str(exc)
    else:
        raise AssertionError("Unsupported tool should be rejected.")


def test_all_tools_are_registered():
    manager = ToolManager()

    results = manager.check_all()

    expected = {
        "subfinder",
        "amass",
        "dnsx",
        "httpx",
        "katana",
        "nuclei",
    }

    assert set(results) == expected
