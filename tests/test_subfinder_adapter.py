"""Tests for the passive Subfinder adapter."""

import json
import subprocess

import pytest

from subrecon.core.models import ToolRunStatus
from subrecon.core.scope import ScopePolicy
from subrecon.integrations.base import IntegrationError
from subrecon.integrations.subfinder import (
    SubfinderAdapter,
    SubfinderSettings,
)


@pytest.fixture
def scope():
    return ScopePolicy(("example.com",))


def test_build_passive_command(scope):
    adapter = SubfinderAdapter(executable="/usr/bin/subfinder")

    command = adapter.build_command("EXAMPLE.COM.", scope)

    assert command[:3] == [
        "/usr/bin/subfinder",
        "-d",
        "example.com",
    ]

    assert "-oJ" in command
    assert "-cs" in command
    assert "-silent" in command
    assert "-duc" in command
    assert "-active" not in command


def test_out_of_scope_target_rejected(scope):
    adapter = SubfinderAdapter(executable="/usr/bin/subfinder")

    with pytest.raises(IntegrationError, match="target rejected"):
        adapter.build_command("other.org", scope)


def test_jsonl_parsing_and_deduplication(scope):
    output = "\n".join([
        json.dumps({
            "host": "API.EXAMPLE.COM.",
            "source": "crtsh",
        }),
        json.dumps({
            "host": "api.example.com",
            "source": "hackertarget",
        }),
        json.dumps({
            "host": "www.example.com",
            "sources": ["crtsh", "waybackarchive"],
        }),
    ])

    results = SubfinderAdapter.parse_output(output, scope)

    assert len(results) == 2
    assert results[0].hostname == "api.example.com"
    assert results[0].sources == ("crtsh", "hackertarget")
    assert results[1].hostname == "www.example.com"
    assert results[1].sources == ("crtsh", "waybackarchive")


def test_out_of_scope_result_rejected(scope):
    output = json.dumps({
        "host": "attacker.org",
        "source": "crtsh",
    })

    with pytest.raises(IntegrationError, match="out-of-scope"):
        SubfinderAdapter.parse_output(output, scope)


def test_invalid_json_rejected(scope):
    with pytest.raises(IntegrationError, match="Invalid Subfinder JSON"):
        SubfinderAdapter.parse_output("{invalid json}", scope)


def test_missing_hostname_rejected(scope):
    with pytest.raises(IntegrationError, match="Missing hostname"):
        SubfinderAdapter.parse_output(
            json.dumps({"source": "crtsh"}),
            scope,
        )


def test_mocked_execution_success(scope):
    output = json.dumps({
        "host": "api.example.com",
        "source": "crtsh",
    })

    def fake_runner(command, **kwargs):
        assert kwargs["shell"] is False
        assert "-active" not in command

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=output,
            stderr="",
        )

    adapter = SubfinderAdapter(
        executable="/fake/subfinder",
        runner=fake_runner,
    )

    result = adapter.run("example.com", scope)

    assert result.execution.status == ToolRunStatus.COMPLETED
    assert len(result.discovered) == 1
    assert result.discovered[0].hostname == "api.example.com"


def test_mocked_execution_failure(scope):
    def fake_runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="Simulated execution failure",
        )

    adapter = SubfinderAdapter(
        executable="/fake/subfinder",
        runner=fake_runner,
    )

    result = adapter.run("example.com", scope)

    assert result.execution.status == ToolRunStatus.FAILED
    assert "Simulated execution failure" in result.execution.stderr
    assert result.discovered == ()


def test_invalid_settings_rejected():
    with pytest.raises(ValueError):
        SubfinderSettings(rate_limit_per_second=0)
