"""Tests for TXT report exporting."""

import pytest

from subrecon.reporting.txt_export import (
    export_txt,
    format_report_text,
)


@pytest.fixture
def sample_report():
    return {
        "schema_version": "1.0",
        "generated_at": "2026-11-08T10:05:00+00:00",
        "scan": {
            "scan_id": "txt-test-001",
            "root_domain": "example.com",
            "status": "completed",
            "started_at": "2026-11-08T10:00:00+00:00",
            "completed_at": "2026-11-08T10:05:00+00:00",
        },
        "summary": {
            "discovered_hostname_count": 1,
            "dns_observation_count": 1,
            "http_observation_count": 1,
            "technology_observation_count": 1,
            "tool_run_count": 1,
        },
        "discovered_subdomains": [
            {
                "hostname": "api.example.com",
                "sources": ["subfinder", "amass"],
                "discovered_at": "2026-11-08T10:01:00+00:00",
            },
        ],
        "dns_observations": [
            {
                "hostname": "api.example.com",
                "record_type": "A",
                "value": "192.0.2.10",
                "ttl": 300,
                "observed_at": "2026-11-08T10:02:00+00:00",
            },
        ],
        "http_observations": [
            {
                "hostname": "api.example.com",
                "url": "https://api.example.com",
                "status_code": 200,
                "final_url": None,
                "title": "Example API",
                "server": "Example Server",
                "content_type": "application/json",
                "observed_at": "2026-11-08T10:03:00+00:00",
            },
        ],
        "technology_observations": [
            {
                "hostname": "api.example.com",
                "name": "Example Framework",
                "version": "1.0",
                "source": "test",
                "observed_at": "2026-11-08T10:04:00+00:00",
            },
        ],
        "tool_runs": [
            {
                "tool_name": "dnsx",
                "status": "completed",
                "started_at": "2026-11-08T10:02:00+00:00",
                "finished_at": "2026-11-08T10:03:00+00:00",
                "exit_code": 0,
            },
        ],
    }


def test_txt_export_creates_file(tmp_path, sample_report):
    output = tmp_path / "report.txt"

    result = export_txt(sample_report, output)

    assert result == output
    assert output.is_file()


def test_txt_export_contains_all_sections(sample_report):
    content = format_report_text(sample_report)

    expected_sections = [
        "SCAN INFORMATION",
        "SUMMARY",
        "DISCOVERED SUBDOMAINS",
        "DNS OBSERVATIONS",
        "HTTP OBSERVATIONS",
        "TECHNOLOGY OBSERVATIONS",
        "TOOL EXECUTION HISTORY",
    ]

    for section in expected_sections:
        assert section in content


def test_txt_export_preserves_report_data(sample_report):
    content = format_report_text(sample_report)

    assert "txt-test-001" in content
    assert "example.com" in content
    assert "api.example.com" in content
    assert "192.0.2.10" in content
    assert "Example API" in content
    assert "Example Framework" in content
    assert "subfinder, amass" in content
    assert "dnsx" in content


def test_txt_export_creates_parent_directories(
    tmp_path,
    sample_report,
):
    output = tmp_path / "reports" / "txt" / "report.txt"

    export_txt(sample_report, output)

    assert output.is_file()


def test_txt_export_preserves_unicode(tmp_path):
    report = {
        "scan": {
            "scan_id": "unicode-001",
            "root_domain": "example.com",
            "status": "completed",
        },
        "discovered_subdomains": [
            {
                "hostname": "api.example.com",
                "sources": ["Grüße"],
            },
        ],
    }

    output = tmp_path / "unicode.txt"

    export_txt(report, output)

    assert "Grüße" in output.read_text(encoding="utf-8")


def test_txt_export_handles_empty_sections():
    report = {
        "scan": {
            "scan_id": "empty-001",
            "root_domain": "example.com",
            "status": "completed",
        },
    }

    content = format_report_text(report)

    assert "No discovered subdomains recorded." in content
    assert "No DNS observations recorded." in content
    assert "No HTTP observations recorded." in content
    assert "No technology observations recorded." in content
    assert "No tool execution history recorded." in content


def test_invalid_report_rejected(tmp_path):
    with pytest.raises(TypeError, match="dictionary"):
        export_txt([], tmp_path / "invalid.txt")


def test_invalid_section_rejected():
    report = {
        "scan": {},
        "summary": {},
        "dns_observations": "invalid",
    }

    with pytest.raises(ValueError, match="must be a list"):
        format_report_text(report)


def test_txt_export_adds_trailing_newline(tmp_path, sample_report):
    output = tmp_path / "report.txt"

    export_txt(sample_report, output)

    assert output.read_bytes().endswith(b"\n")
