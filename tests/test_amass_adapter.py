"""Tests for the passive Amass adapter."""

import subprocess

import pytest

from subrecon.core.models import ToolRunStatus
from subrecon.core.scope import ScopePolicy
from subrecon.integrations.base import IntegrationError
from subrecon.integrations.amass import AmassAdapter, AmassSettings


@pytest.fixture
def scope():
    return ScopePolicy(("example.com",))


def test_build_passive_enum_command(scope, tmp_path):
    adapter = AmassAdapter(executable="/fake/amass")

    command = adapter.build_enum_command(
        "EXAMPLE.COM.",
        scope,
        tmp_path,
    )

    assert command[:3] == ["/fake/amass", "enum", "-d"]
    assert "example.com" in command
    assert "-rigid" in command
    assert "-silent" in command
    assert "-active" not in command
    assert "-brute" not in command
    assert "-alts" not in command


def test_build_names_query_command(scope, tmp_path):
    adapter = AmassAdapter(executable="/fake/amass")

    command = adapter.build_subs_command(
        "example.com",
        scope,
        tmp_path,
    )

    assert command[:2] == ["/fake/amass", "subs"]
    assert "-names" in command
    assert "-nocolor" in command


def test_out_of_scope_target_rejected(scope, tmp_path):
    adapter = AmassAdapter(executable="/fake/amass")

    with pytest.raises(IntegrationError, match="target rejected"):
        adapter.build_enum_command(
            "other.org",
            scope,
            tmp_path,
        )


def test_parse_names_and_deduplicate(scope):
    output = """
api.example.com
API.EXAMPLE.COM.
www.example.com
"""

    results = AmassAdapter.parse_names_output(output, scope)

    assert len(results) == 2
    assert results[0].hostname == "api.example.com"
    assert results[0].sources == ("amass",)
    assert results[1].hostname == "www.example.com"


def test_empty_database_message(scope):
    results = AmassAdapter.parse_names_output(
        "No names were discovered\n",
        scope,
    )

    assert results == ()


def test_out_of_scope_result_rejected(scope):
    with pytest.raises(IntegrationError, match="out-of-scope"):
        AmassAdapter.parse_names_output(
            "attacker.org\n",
            scope,
        )


def test_mocked_successful_execution(scope, tmp_path):
    calls = []

    def fake_runner(command, **kwargs):
        calls.append(command)

        assert kwargs["shell"] is False

        if command[1] == "enum":
            assert "-active" not in command
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="",
                stderr="",
            )

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="api.example.com\nwww.example.com\n",
            stderr="",
        )

    adapter = AmassAdapter(
        executable="/fake/amass",
        runner=fake_runner,
    )

    result = adapter.run("example.com", scope, tmp_path)

    assert len(calls) == 2
    assert result.execution.status == ToolRunStatus.COMPLETED
    assert len(result.discovered) == 2


def test_mocked_enumeration_failure(scope, tmp_path):
    def fake_runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="Simulated Amass failure",
        )

    adapter = AmassAdapter(
        executable="/fake/amass",
        runner=fake_runner,
    )

    result = adapter.run("example.com", scope, tmp_path)

    assert result.execution.status == ToolRunStatus.FAILED
    assert "Simulated Amass failure" in result.execution.stderr


def test_mocked_timeout(scope, tmp_path):
    def timeout_runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, timeout=10)

    adapter = AmassAdapter(
        executable="/fake/amass",
        runner=timeout_runner,
    )

    result = adapter.run("example.com", scope, tmp_path)

    assert result.execution.status == ToolRunStatus.TIMED_OUT


def test_invalid_settings_rejected():
    with pytest.raises(ValueError):
        AmassSettings(enumeration_timeout_minutes=0)


def test_amass_wrapper_rejected(tmp_path):
    wrapper = tmp_path / "amass"
    wrapper.write_text("#!/bin/sh\nsudo libpostal_data download all\n")
    wrapper.chmod(0o755)

    with pytest.raises(IntegrationError, match="usable Amass executable"):
        AmassAdapter(executable=str(wrapper))
