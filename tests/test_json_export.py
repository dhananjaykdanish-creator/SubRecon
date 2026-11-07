"""Tests for JSON report exporting."""

import json

import pytest

from subrecon.reporting.json_export import export_json


@pytest.fixture
def sample_report():
    return {
        "schema_version": "1.0",
        "scan": {
            "scan_id": "json-test-001",
            "root_domain": "example.com",
            "status": "completed",
        },
        "discovered_subdomains": [
            {
                "hostname": "api.example.com",
                "sources": ["subfinder", "amass"],
            },
        ],
    }


def test_json_export_creates_file(tmp_path, sample_report):
    output = tmp_path / "report.json"

    result = export_json(sample_report, output)

    assert result == output
    assert output.is_file()


def test_json_export_preserves_report_data(tmp_path, sample_report):
    output = tmp_path / "report.json"

    export_json(sample_report, output)

    loaded = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert loaded == sample_report


def test_json_export_creates_parent_directories(
    tmp_path,
    sample_report,
):
    output = tmp_path / "reports" / "json" / "report.json"

    export_json(sample_report, output)

    assert output.is_file()


def test_json_export_preserves_unicode(tmp_path):
    report = {
        "description": "Grüße aus Köln",
        "hostname": "example.com",
    }

    output = tmp_path / "unicode.json"

    export_json(report, output)

    content = output.read_text(encoding="utf-8")

    assert "Grüße aus Köln" in content


def test_json_export_is_indented(tmp_path, sample_report):
    output = tmp_path / "report.json"

    export_json(sample_report, output)

    content = output.read_text(encoding="utf-8")

    assert "\n" in content
    assert '  "schema_version"' in content


def test_json_export_adds_trailing_newline(
    tmp_path,
    sample_report,
):
    output = tmp_path / "report.json"

    export_json(sample_report, output)

    assert output.read_bytes().endswith(b"\n")


def test_invalid_report_rejected(tmp_path):
    with pytest.raises(TypeError, match="dictionary"):
        export_json(["invalid"], tmp_path / "report.json")


def test_json_export_returns_path(tmp_path, sample_report):
    output = tmp_path / "report.json"

    result = export_json(sample_report, output)

    assert isinstance(result, type(output))
    assert result.exists()
