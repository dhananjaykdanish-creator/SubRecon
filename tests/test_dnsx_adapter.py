"""Tests for the DNSx integration adapter."""

import json
import subprocess

import pytest

from subrecon.core.models import ToolRunStatus
from subrecon.core.scope import ScopePolicy
from subrecon.integrations.base import IntegrationError
from subrecon.integrations.dnsx import DNSxAdapter, DNSxSettings


@pytest.fixture
def scope():
    return ScopePolicy(("example.com",))


def test_build_dnsx_command(scope):
    adapter = DNSxAdapter(executable="/usr/bin/dnsx")
    command = adapter.build_command(["api.example.com"], scope)

    assert command[0] == "/usr/bin/dnsx"
    assert "-a" in command
    assert "-aaaa" in command
    assert "-cname" in command
    assert "-json" in command
    assert "-silent" in command
    assert "-duc" in command
    assert "-axfr" not in command
    assert "-trace" not in command
    assert "-w" not in command


def test_out_of_scope_target_rejected(scope):
    adapter = DNSxAdapter(executable="/fake/dnsx")

    with pytest.raises(IntegrationError, match="out-of-scope"):
        adapter.build_command(["other.org"], scope)


def test_empty_targets_rejected(scope):
    adapter = DNSxAdapter(executable="/fake/dnsx")

    with pytest.raises(IntegrationError, match="at least one"):
        adapter.build_command([], scope)


def test_single_string_target_rejected(scope):
    adapter = DNSxAdapter(executable="/fake/dnsx")

    with pytest.raises(IntegrationError, match="iterable"):
        adapter.build_command("api.example.com", scope)


def test_jsonl_parsing(scope):
    output = json.dumps({
        "host": "api.example.com",
        "all": [
            "api.example.com.\t300\tIN\tA\t192.0.2.10",
            "api.example.com.\t180\tIN\tAAAA\t2001:db8::10",
            "api.example.com.\t600\tIN\tCNAME\tedge.example.net.",
        ],
    })

    observations = DNSxAdapter.parse_output(
        output, ["api.example.com"], scope
    )

    assert len(observations) == 3
    assert observations[0].hostname == "api.example.com"
    assert observations[0].record_type == "A"
    assert observations[0].value == "192.0.2.10"
    assert observations[0].ttl == 300
    assert observations[1].record_type == "AAAA"
    assert observations[1].value == "2001:db8::10"
    assert observations[2].record_type == "CNAME"
    assert observations[2].value == "edge.example.net"


def test_duplicate_records_removed(scope):
    output = json.dumps({
        "host": "api.example.com",
        "all": [
            "api.example.com.\t300\tIN\tA\t192.0.2.10",
            "api.example.com.\t300\tIN\tA\t192.0.2.10",
        ],
    })

    observations = DNSxAdapter.parse_output(
        output, ["api.example.com"], scope
    )

    assert len(observations) == 1


def test_out_of_scope_result_rejected(scope):
    output = json.dumps({"host": "other.org", "all": []})

    with pytest.raises(IntegrationError, match="out-of-scope"):
        DNSxAdapter.parse_output(
            output, ["api.example.com"], scope
        )


def test_unrequested_hostname_rejected(scope):
    output = json.dumps({"host": "www.example.com", "all": []})

    with pytest.raises(IntegrationError, match="unexpected hostname"):
        DNSxAdapter.parse_output(
            output, ["api.example.com"], scope
        )


def test_out_of_scope_record_owner_rejected(scope):
    output = json.dumps({
        "host": "api.example.com",
        "all": [
            "other.org.\t300\tIN\tA\t192.0.2.10",
        ],
    })

    with pytest.raises(IntegrationError, match="out-of-scope"):
        DNSxAdapter.parse_output(
            output, ["api.example.com"], scope
        )


def test_invalid_json_rejected(scope):
    with pytest.raises(IntegrationError, match="Invalid DNSx JSON"):
        DNSxAdapter.parse_output(
            "{invalid}", ["api.example.com"], scope
        )


def test_invalid_ttl_rejected(scope):
    output = json.dumps({
        "host": "api.example.com",
        "all": [
            "api.example.com.\tbad\tIN\tA\t192.0.2.10",
        ],
    })

    with pytest.raises(IntegrationError, match="Invalid DNS TTL"):
        DNSxAdapter.parse_output(
            output, ["api.example.com"], scope
        )


def test_invalid_ip_address_rejected(scope):
    output = json.dumps({
        "host": "api.example.com",
        "all": [
            "api.example.com.\t300\tIN\tA\tnot-an-ip",
        ],
    })

    with pytest.raises(IntegrationError, match="Invalid IP address"):
        DNSxAdapter.parse_output(
            output, ["api.example.com"], scope
        )


def test_mocked_execution_success(scope):
    output = json.dumps({
        "host": "api.example.com",
        "all": [
            "api.example.com.\t300\tIN\tA\t192.0.2.10",
        ],
    })

    def fake_runner(command, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["input"] == "api.example.com\n"
        assert "-axfr" not in command

        return subprocess.CompletedProcess(
            command, 0, stdout=output, stderr=""
        )

    adapter = DNSxAdapter(
        executable="/fake/dnsx",
        runner=fake_runner,
    )

    result = adapter.run(["api.example.com"], scope)

    assert result.execution.status == ToolRunStatus.COMPLETED
    assert len(result.observations) == 1
    assert result.observations[0].value == "192.0.2.10"


def test_mocked_execution_failure(scope):
    def fake_runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr="Simulated DNSx failure"
        )

    adapter = DNSxAdapter(
        executable="/fake/dnsx",
        runner=fake_runner,
    )

    result = adapter.run(["api.example.com"], scope)

    assert result.execution.status == ToolRunStatus.FAILED
    assert "Simulated DNSx failure" in result.execution.stderr
    assert result.observations == ()


def test_mocked_execution_timeout(scope):
    def fake_runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 120)

    adapter = DNSxAdapter(
        executable="/fake/dnsx",
        runner=fake_runner,
    )

    result = adapter.run(["api.example.com"], scope)

    assert result.execution.status == ToolRunStatus.TIMED_OUT
    assert result.observations == ()


def test_invalid_settings_rejected():
    with pytest.raises(ValueError):
        DNSxSettings(threads=0)

    with pytest.raises(ValueError):
        DNSxSettings(rate_limit_per_second=0)

    with pytest.raises(ValueError):
        DNSxSettings(retries=0)
