"""Tests for the standardized reporting data builder."""

import json

import pytest

from subrecon.core.models import (
    DNSObservation,
    DiscoveredSubdomain,
    HTTPObservation,
    Scan,
    ScanStatus,
    TechnologyObservation,
    ToolRun,
    ToolRunStatus,
    utc_now,
)

from subrecon.reporting.data import (
    REPORT_SCHEMA_VERSION,
    build_scan_report,
)

from subrecon.storage.database import (
    connect_database,
    initialize_database,
)

from subrecon.storage.repositories.dns import add_dns_observation
from subrecon.storage.repositories.http import add_http_observation
from subrecon.storage.repositories.scans import (
    add_discovered_subdomain,
    create_scan,
)
from subrecon.storage.repositories.technologies import (
    add_technology_observation,
)
from subrecon.storage.repositories.tool_runs import add_tool_run


@pytest.fixture
def connection(tmp_path):
    path = tmp_path / "report.db"

    initialize_database(path)
    db = connect_database(path)

    create_scan(
        db,
        Scan(
            scan_id="report-test-001",
            root_domain="example.com",
            status=ScanStatus.COMPLETED,
            completed_at=utc_now(),
        ),
    )

    add_discovered_subdomain(
        db,
        "report-test-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("subfinder", "amass"),
        ),
    )

    add_dns_observation(
        db,
        "report-test-001",
        DNSObservation(
            hostname="api.example.com",
            record_type="A",
            value="192.0.2.10",
            ttl=300,
        ),
    )

    add_http_observation(
        db,
        "report-test-001",
        HTTPObservation(
            hostname="api.example.com",
            url="https://api.example.com",
            status_code=200,
            title="Example API",
            server="example-server",
        ),
    )

    add_technology_observation(
        db,
        "report-test-001",
        TechnologyObservation(
            hostname="api.example.com",
            name="Example Framework",
            version="1.0",
            source="test",
        ),
    )

    add_tool_run(
        db,
        "report-test-001",
        ToolRun(
            tool_name="dnsx",
            status=ToolRunStatus.COMPLETED,
            finished_at=utc_now(),
            exit_code=0,
        ),
    )

    db.commit()

    yield db

    db.close()


def test_report_contains_all_sections(connection):
    report = build_scan_report(
        connection,
        "report-test-001",
    )

    assert report["schema_version"] == REPORT_SCHEMA_VERSION

    assert report["scan"]["root_domain"] == "example.com"
    assert report["scan"]["status"] == "completed"

    assert report["summary"]["discovered_hostname_count"] == 1
    assert report["summary"]["dns_observation_count"] == 1
    assert report["summary"]["http_observation_count"] == 1
    assert report["summary"]["technology_observation_count"] == 1
    assert report["summary"]["tool_run_count"] == 1
    assert report["summary"]["completed_tool_count"] == 1

    assert len(report["discovered_subdomains"]) == 1
    assert len(report["dns_observations"]) == 1
    assert len(report["http_observations"]) == 1
    assert len(report["technology_observations"]) == 1
    assert len(report["tool_runs"]) == 1


def test_report_preserves_discovery_sources(connection):
    report = build_scan_report(
        connection,
        "report-test-001",
    )

    discovery = report["discovered_subdomains"][0]

    assert discovery["hostname"] == "api.example.com"
    assert discovery["sources"] == ["amass", "subfinder"]


def test_report_preserves_dns_details(connection):
    report = build_scan_report(
        connection,
        "report-test-001",
    )

    dns = report["dns_observations"][0]

    assert dns["record_type"] == "A"
    assert dns["value"] == "192.0.2.10"
    assert dns["ttl"] == 300


def test_report_is_json_serializable(connection):
    report = build_scan_report(
        connection,
        "report-test-001",
    )

    encoded = json.dumps(report)
    decoded = json.loads(encoded)

    assert decoded["scan"]["scan_id"] == "report-test-001"


def test_missing_scan_rejected(connection):
    with pytest.raises(LookupError, match="Scan not found"):
        build_scan_report(
            connection,
            "missing-scan",
        )


def test_empty_scan_has_empty_sections(tmp_path):
    path = tmp_path / "empty-report.db"

    initialize_database(path)
    db = connect_database(path)

    try:
        create_scan(
            db,
            Scan(
                scan_id="empty-report-001",
                root_domain="example.com",
            ),
        )

        db.commit()

        report = build_scan_report(
            db,
            "empty-report-001",
        )

        assert report["summary"]["discovered_hostname_count"] == 0
        assert report["summary"]["dns_observation_count"] == 0
        assert report["summary"]["http_observation_count"] == 0

        assert report["discovered_subdomains"] == []
        assert report["dns_observations"] == []
        assert report["http_observations"] == []
        assert report["technology_observations"] == []
        assert report["tool_runs"] == []

    finally:
        db.close()
