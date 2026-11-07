"""Tests for DNS observation storage."""

import pytest

from subrecon.core.models import DNSObservation, DiscoveredSubdomain, Scan
from subrecon.core.scope import ScopeValidationError
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.dns import (
    add_dns_observation,
    list_dns_observations,
)
from subrecon.storage.repositories.scans import (
    add_discovered_subdomain,
    create_scan,
)


@pytest.fixture
def connection(tmp_path):
    """Create a database with one authorized scan and hostname."""

    path = tmp_path / "subrecon.db"
    initialize_database(path)

    db = connect_database(path)

    create_scan(
        db,
        Scan(
            scan_id="scan-dns-001",
            root_domain="example.com",
        ),
    )

    add_discovered_subdomain(
        db,
        "scan-dns-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("test",),
        ),
    )

    db.commit()

    yield db

    db.close()


def test_add_and_retrieve_dns_observation(connection):
    observation = DNSObservation(
        hostname="api.example.com",
        record_type="a",
        value="192.0.2.10",
        ttl=300,
    )

    observation_id = add_dns_observation(
        connection,
        "scan-dns-001",
        observation,
    )

    connection.commit()

    assert observation_id > 0

    results = list_dns_observations(
        connection,
        "scan-dns-001",
    )

    assert len(results) == 1
    assert results[0].hostname == "api.example.com"
    assert results[0].record_type == "A"
    assert results[0].value == "192.0.2.10"
    assert results[0].ttl == 300


def test_dns_history_is_preserved(connection):
    first = DNSObservation(
        hostname="api.example.com",
        record_type="A",
        value="192.0.2.10",
        ttl=300,
    )

    second = DNSObservation(
        hostname="api.example.com",
        record_type="A",
        value="192.0.2.20",
        ttl=600,
    )

    add_dns_observation(connection, "scan-dns-001", first)
    add_dns_observation(connection, "scan-dns-001", second)
    connection.commit()

    results = list_dns_observations(
        connection,
        "scan-dns-001",
    )

    assert len(results) == 2
    assert results[0].value == "192.0.2.10"
    assert results[1].value == "192.0.2.20"


def test_undiscovered_hostname_rejected(connection):
    with pytest.raises(LookupError, match="has not been discovered"):
        add_dns_observation(
            connection,
            "scan-dns-001",
            DNSObservation(
                hostname="www.example.com",
                record_type="A",
                value="192.0.2.10",
            ),
        )


def test_out_of_scope_hostname_rejected(connection):
    with pytest.raises(ScopeValidationError):
        add_dns_observation(
            connection,
            "scan-dns-001",
            DNSObservation(
                hostname="other.org",
                record_type="A",
                value="192.0.2.10",
            ),
        )


def test_missing_scan_rejected(connection):
    with pytest.raises(LookupError, match="Scan not found"):
        add_dns_observation(
            connection,
            "missing",
            DNSObservation(
                hostname="api.example.com",
                record_type="A",
                value="192.0.2.10",
            ),
        )


def test_invalid_record_type_rejected(connection):
    with pytest.raises(ValueError, match="record type"):
        add_dns_observation(
            connection,
            "scan-dns-001",
            DNSObservation(
                hostname="api.example.com",
                record_type="INVALID TYPE",
                value="192.0.2.10",
            ),
        )


def test_empty_dns_value_rejected(connection):
    with pytest.raises(ValueError, match="cannot be empty"):
        add_dns_observation(
            connection,
            "scan-dns-001",
            DNSObservation(
                hostname="api.example.com",
                record_type="A",
                value="   ",
            ),
        )


def test_negative_ttl_rejected(connection):
    with pytest.raises(ValueError, match="non-negative"):
        add_dns_observation(
            connection,
            "scan-dns-001",
            DNSObservation(
                hostname="api.example.com",
                record_type="A",
                value="192.0.2.10",
                ttl=-1,
            ),
        )


def test_dns_observation_with_unknown_scan_retrieval(connection):
    with pytest.raises(LookupError, match="Scan not found"):
        list_dns_observations(connection, "missing")

def test_boolean_ttl_rejected(connection):
    with pytest.raises(ValueError, match="non-negative"):
        add_dns_observation(
            connection,
            "scan-dns-001",
            DNSObservation(
                hostname="api.example.com",
                record_type="A",
                value="192.0.2.10",
                ttl=True,
            ),
        )
