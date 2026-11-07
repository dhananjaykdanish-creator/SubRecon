"""Tests for SubRecon scan and subdomain repositories."""

import pytest

from subrecon.core.models import DiscoveredSubdomain, Scan
from subrecon.core.scope import ScopeValidationError
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.scans import (
    add_discovered_subdomain,
    create_scan,
    get_scan,
    list_discovered_subdomains,
)


@pytest.fixture
def connection(tmp_path):
    """Create a temporary initialized database."""

    path = tmp_path / "subrecon.db"
    initialize_database(path)

    db = connect_database(path)

    create_scan(
        db,
        Scan(
            scan_id="scan-001",
            root_domain="EXAMPLE.COM.",
        ),
    )
    db.commit()

    yield db

    db.close()


def test_create_and_retrieve_scan(connection):
    scan = get_scan(connection, "scan-001")

    assert scan is not None
    assert scan.scan_id == "scan-001"
    assert scan.root_domain == "example.com"
    assert scan.status.value == "pending"


def test_missing_scan_returns_none(connection):
    assert get_scan(connection, "missing") is None


def test_add_subdomain(connection):
    subdomain = DiscoveredSubdomain(
        hostname="API.EXAMPLE.COM.",
        sources=("subfinder",),
    )

    subdomain_id = add_discovered_subdomain(
        connection,
        "scan-001",
        subdomain,
    )

    connection.commit()

    assert subdomain_id > 0

    results = list_discovered_subdomains(
        connection,
        "scan-001",
    )

    assert len(results) == 1
    assert results[0].hostname == "api.example.com"
    assert results[0].sources == ("subfinder",)


def test_duplicate_subdomains_merge_sources(connection):
    add_discovered_subdomain(
        connection,
        "scan-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("subfinder",),
        ),
    )

    add_discovered_subdomain(
        connection,
        "scan-001",
        DiscoveredSubdomain(
            hostname="API.EXAMPLE.COM.",
            sources=("amass", "subfinder"),
        ),
    )

    connection.commit()

    results = list_discovered_subdomains(
        connection,
        "scan-001",
    )

    assert len(results) == 1
    assert results[0].sources == ("amass", "subfinder")


def test_out_of_scope_subdomain_rejected(connection):
    with pytest.raises(ScopeValidationError):
        add_discovered_subdomain(
            connection,
            "scan-001",
            DiscoveredSubdomain(
                hostname="attacker-example.com",
            ),
        )


def test_unrelated_domain_rejected(connection):
    with pytest.raises(ScopeValidationError):
        add_discovered_subdomain(
            connection,
            "scan-001",
            DiscoveredSubdomain(
                hostname="other.org",
            ),
        )


def test_missing_scan_rejected(connection):
    with pytest.raises(LookupError, match="Scan not found"):
        add_discovered_subdomain(
            connection,
            "missing",
            DiscoveredSubdomain(
                hostname="api.example.com",
            ),
        )


def test_empty_source_rejected(connection):
    with pytest.raises(ValueError, match="source cannot be empty"):
        add_discovered_subdomain(
            connection,
            "scan-001",
            DiscoveredSubdomain(
                hostname="api.example.com",
                sources=("",),
            ),
        )


def test_empty_scan_results(connection):
    results = list_discovered_subdomains(
        connection,
        "scan-001",
    )

    assert results == []

def test_invalid_source_does_not_insert_hostname(connection):
    with pytest.raises(ValueError, match="source cannot be empty"):
        add_discovered_subdomain(
            connection,
            "scan-001",
            DiscoveredSubdomain(
                hostname="new.example.com",
                sources=("",),
            ),
        )

    connection.commit()

    results = list_discovered_subdomains(connection, "scan-001")
    assert results == []


def test_non_string_source_rejected(connection):
    with pytest.raises(ValueError, match="must be text"):
        add_discovered_subdomain(
            connection,
            "scan-001",
            DiscoveredSubdomain(
                hostname="new.example.com",
                sources=(123,),
            ),
        )
