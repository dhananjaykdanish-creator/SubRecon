"""Tests for HTML report exporting."""

import pytest

from subrecon.reporting.html_export import (
    export_html,
    format_report_html,
)


@pytest.fixture
def sample_report():
    return {
        "schema_version": "1.0",
        "generated_at": "2026-11-08T10:05:00+00:00",
        "scan": {
            "scan_id": "html-test-001",
            "root_domain": "example.com",
            "status": "completed",
            "started_at": "2026-11-08T10:00:00+00:00",
            "completed_at": "2026-11-08T10:05:00+00:00",
        },
        "summary": {
            "discovered_hostname_count": 1,
            "dns_observation_count": 1,
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
                "title": "Example API",
                "server": "Example Server",
                "content_type": "application/json",
            },
        ],
        "technology_observations": [
            {
                "hostname": "api.example.com",
                "name": "Example Framework",
                "version": "1.0",
                "source": "test",
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


def test_html_export_creates_file(tmp_path, sample_report):
    output = tmp_path / "report.html"

    result = export_html(sample_report, output)

    assert result == output
    assert output.is_file()


def test_html_export_contains_all_sections(sample_report):
    content = format_report_html(sample_report)

    for section in (
        "Scan Information",
        "Summary",
        "Discovered Subdomains",
        "DNS Observations",
        "HTTP Observations",
        "Technology Observations",
        "Tool Execution History",
    ):
        assert section in content


def test_html_export_preserves_report_data(sample_report):
    content = format_report_html(sample_report)

    assert "html-test-001" in content
    assert "api.example.com" in content
    assert "192.0.2.10" in content
    assert "Example API" in content
    assert "Example Framework" in content
    assert "subfinder" in content


def test_html_export_escapes_untrusted_values():
    report = {
        "scan": {
            "scan_id": "safe-001",
            "root_domain": "<script>alert('xss')</script>",
            "status": "completed",
        },
        "http_observations": [
            {
                "hostname": "example.com",
                "title": '<img src=x onerror="alert(1)">',
            },
        ],
    }

    content = format_report_html(report)

    assert "<script>alert" not in content
    assert "<img src=x" not in content
    assert "&lt;script&gt;" in content
    assert "&lt;img" in content


def test_html_export_has_no_external_assets(sample_report):
    content = format_report_html(sample_report)

    assert "<!DOCTYPE html>" in content
    assert '<meta charset="UTF-8">' in content
    assert "<style>" in content
    assert "<script" not in content
    assert "https://" not in content or "https://api.example.com" in content


def test_html_export_creates_parent_directories(
    tmp_path,
    sample_report,
):
    output = tmp_path / "reports" / "html" / "report.html"

    export_html(sample_report, output)

    assert output.is_file()


def test_html_export_preserves_unicode(tmp_path):
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

    output = tmp_path / "unicode.html"

    export_html(report, output)

    assert "Grüße" in output.read_text(encoding="utf-8")


def test_html_export_handles_empty_sections():
    report = {
        "scan": {
            "scan_id": "empty-001",
            "root_domain": "example.com",
            "status": "completed",
        },
    }

    content = format_report_html(report)

    assert content.count("No records available.") == 5


def test_invalid_report_rejected(tmp_path):
    with pytest.raises(TypeError, match="dictionary"):
        export_html([], tmp_path / "invalid.html")


def test_invalid_section_rejected():
    report = {
        "scan": {},
        "summary": {},
        "dns_observations": "invalid",
    }

    with pytest.raises(ValueError, match="must be a list"):
        format_report_html(report)


def test_html_export_adds_closing_document_tags(tmp_path, sample_report):
    output = tmp_path / "report.html"

    export_html(sample_report, output)

    content = output.read_text(encoding="utf-8")

    assert "</body>" in content
    assert "</html>" in content
