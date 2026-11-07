"""Tests for CSV report exporting."""

import csv

import pytest

from subrecon.reporting.csv_export import (
    CSV_FIELDS,
    export_csv,
)


@pytest.fixture
def sample_report():
    return {
        "schema_version": "1.0",
        "scan": {
            "scan_id": "csv-test-001",
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


def read_rows(path):
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def test_csv_export_creates_file(tmp_path, sample_report):
    output = tmp_path / "report.csv"

    result = export_csv(sample_report, output)

    assert result == output
    assert output.is_file()


def test_csv_export_contains_all_sections(tmp_path, sample_report):
    output = tmp_path / "report.csv"

    export_csv(sample_report, output)

    rows = read_rows(output)
    record_types = {row["record_type"] for row in rows}

    assert record_types == {
        "scan",
        "summary",
        "subdomain",
        "dns",
        "http",
        "technology",
        "tool_run",
    }


def test_csv_export_preserves_dns_values(tmp_path, sample_report):
    output = tmp_path / "report.csv"

    export_csv(sample_report, output)

    rows = read_rows(output)
    dns_row = next(row for row in rows if row["record_type"] == "dns")

    assert dns_row["hostname"] == "api.example.com"
    assert dns_row["dns_record_type"] == "A"
    assert dns_row["value"] == "192.0.2.10"
    assert dns_row["ttl"] == "300"


def test_csv_export_preserves_discovery_sources(tmp_path, sample_report):
    output = tmp_path / "report.csv"

    export_csv(sample_report, output)

    rows = read_rows(output)
    row = next(
        row for row in rows
        if row["record_type"] == "subdomain"
    )

    assert row["discovery_sources"] == "subfinder, amass"


def test_csv_export_preserves_unicode(tmp_path):
    report = {
        "scan": {
            "scan_id": "unicode-001",
            "root_domain": "example.com",
            "status": "completed",
        },
        "summary": {},
        "discovered_subdomains": [
            {
                "hostname": "api.example.com",
                "sources": ["Grüße"],
            },
        ],
    }

    output = tmp_path / "unicode.csv"
    export_csv(report, output)

    content = output.read_text(encoding="utf-8")

    assert "Grüße" in content


def test_csv_export_creates_parent_directories(
    tmp_path,
    sample_report,
):
    output = tmp_path / "reports" / "csv" / "report.csv"

    export_csv(sample_report, output)

    assert output.is_file()


def test_csv_export_uses_stable_headers(tmp_path, sample_report):
    output = tmp_path / "report.csv"

    export_csv(sample_report, output)

    with output.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.DictReader(file)
        assert tuple(reader.fieldnames) == CSV_FIELDS


def test_invalid_report_rejected(tmp_path):
    with pytest.raises(TypeError, match="dictionary"):
        export_csv([], tmp_path / "invalid.csv")


def test_invalid_section_rejected(tmp_path):
    report = {
        "scan": {},
        "summary": {},
        "discovered_subdomains": "not-a-list",
    }

    with pytest.raises(ValueError, match="must be a list"):
        export_csv(report, tmp_path / "invalid.csv")
