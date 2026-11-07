"""Tests for technology observation storage."""

import pytest

from subrecon.core.models import (
    DiscoveredSubdomain,
    Scan,
    TechnologyObservation,
)
from subrecon.core.scope import ScopeValidationError
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.scans import (
    add_discovered_subdomain,
    create_scan,
)
from subrecon.storage.repositories.technologies import (
    add_technology_observation,
    list_technology_observations,
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
            scan_id="scan-tech-001",
            root_domain="example.com",
        ),
    )

    add_discovered_subdomain(
        db,
        "scan-tech-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("test",),
        ),
    )

    db.commit()

    yield db

    db.close()


def test_add_and_retrieve_technology(connection):
    observation = TechnologyObservation(
        hostname="api.example.com",
        name="Python",
        version="3.14",
        source="httpx",
    )

    observation_id = add_technology_observation(
        connection,
        "scan-tech-001",
        observation,
    )

    connection.commit()

    assert observation_id > 0

    results = list_technology_observations(
        connection,
        "scan-tech-001",
    )

    assert len(results) == 1
    assert results[0].hostname == "api.example.com"
    assert results[0].name == "Python"
    assert results[0].version == "3.14"
    assert results[0].source == "httpx"


def test_unknown_version_is_supported(connection):
    observation = TechnologyObservation(
        hostname="api.example.com",
        name="Nginx",
    )

    add_technology_observation(
        connection,
        "scan-tech-001",
        observation,
    )

    connection.commit()

    results = list_technology_observations(
        connection,
        "scan-tech-001",
    )

    assert results[0].version is None
    assert results[0].source is None


def test_technology_history_is_preserved(connection):
    observations = [
        TechnologyObservation(
            hostname="api.example.com",
            name="Nginx",
            version="1.24",
        ),
        TechnologyObservation(
            hostname="api.example.com",
            name="Nginx",
            version="1.25",
        ),
    ]

    for observation in observations:
        add_technology_observation(
            connection,
            "scan-tech-001",
            observation,
        )

    connection.commit()

    results = list_technology_observations(
        connection,
        "scan-tech-001",
    )

    assert len(results) == 2
    assert [item.version for item in results] == ["1.24", "1.25"]


def test_undiscovered_hostname_rejected(connection):
    with pytest.raises(LookupError, match="has not been discovered"):
        add_technology_observation(
            connection,
            "scan-tech-001",
            TechnologyObservation(
                hostname="www.example.com",
                name="Nginx",
            ),
        )


def test_out_of_scope_hostname_rejected(connection):
    with pytest.raises(ScopeValidationError):
        add_technology_observation(
            connection,
            "scan-tech-001",
            TechnologyObservation(
                hostname="other.org",
                name="Nginx",
            ),
        )


def test_empty_technology_name_rejected(connection):
    with pytest.raises(ValueError, match="Technology name"):
        add_technology_observation(
            connection,
            "scan-tech-001",
            TechnologyObservation(
                hostname="api.example.com",
                name="   ",
            ),
        )


def test_optional_metadata_is_trimmed(connection):
    add_technology_observation(
        connection,
        "scan-tech-001",
        TechnologyObservation(
            hostname="api.example.com",
            name=" Nginx ",
            version=" 1.25 ",
            source=" httpx ",
        ),
    )

    connection.commit()

    result = list_technology_observations(
        connection,
        "scan-tech-001",
    )[0]

    assert result.name == "Nginx"
    assert result.version == "1.25"
    assert result.source == "httpx"


def test_missing_scan_rejected(connection):
    with pytest.raises(LookupError, match="Scan not found"):
        list_technology_observations(
            connection,
            "missing",
        )
