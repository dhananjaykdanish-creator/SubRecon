"""Tests for HTTP observation storage."""

import pytest

from subrecon.core.models import (
    DiscoveredSubdomain,
    HTTPObservation,
    Scan,
)
from subrecon.core.scope import ScopeValidationError
from subrecon.storage.database import (
    connect_database,
    initialize_database,
)
from subrecon.storage.repositories.http import (
    add_http_observation,
    list_http_observations,
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
            scan_id="scan-http-001",
            root_domain="example.com",
        ),
    )

    add_discovered_subdomain(
        db,
        "scan-http-001",
        DiscoveredSubdomain(
            hostname="api.example.com",
            sources=("test",),
        ),
    )

    db.commit()

    yield db

    db.close()


def test_add_and_retrieve_http_observation(connection):
    observation = HTTPObservation(
        hostname="api.example.com",
        url="https://api.example.com",
        status_code=200,
        title="Example API",
        server="ExampleServer",
        content_type="application/json",
    )

    observation_id = add_http_observation(
        connection,
        "scan-http-001",
        observation,
    )

    connection.commit()

    assert observation_id > 0

    results = list_http_observations(
        connection,
        "scan-http-001",
    )

    assert len(results) == 1
    assert results[0].status_code == 200
    assert results[0].title == "Example API"


@pytest.mark.parametrize("status_code", [401, 403, 404, 500])
def test_valid_http_error_responses(connection, status_code):
    observation = HTTPObservation(
        hostname="api.example.com",
        url="https://api.example.com",
        status_code=status_code,
    )

    add_http_observation(
        connection,
        "scan-http-001",
        observation,
    )

    connection.commit()

    results = list_http_observations(
        connection,
        "scan-http-001",
    )

    assert results[-1].status_code == status_code


def test_connection_failure_can_be_recorded(connection):
    observation = HTTPObservation(
        hostname="api.example.com",
        url="https://api.example.com",
        status_code=None,
    )

    add_http_observation(
        connection,
        "scan-http-001",
        observation,
    )

    connection.commit()

    results = list_http_observations(
        connection,
        "scan-http-001",
    )

    assert results[-1].status_code is None


def test_http_history_is_preserved(connection):
    for status in (200, 403):
        add_http_observation(
            connection,
            "scan-http-001",
            HTTPObservation(
                hostname="api.example.com",
                url="https://api.example.com",
                status_code=status,
            ),
        )

    connection.commit()

    results = list_http_observations(
        connection,
        "scan-http-001",
    )

    assert len(results) == 2
    assert [item.status_code for item in results] == [200, 403]


def test_undiscovered_hostname_rejected(connection):
    with pytest.raises(LookupError, match="has not been discovered"):
        add_http_observation(
            connection,
            "scan-http-001",
            HTTPObservation(
                hostname="www.example.com",
                url="https://www.example.com",
                status_code=200,
            ),
        )


def test_out_of_scope_hostname_rejected(connection):
    with pytest.raises(ScopeValidationError):
        add_http_observation(
            connection,
            "scan-http-001",
            HTTPObservation(
                hostname="other.org",
                url="https://other.org",
                status_code=200,
            ),
        )


def test_url_hostname_must_match_observation(connection):
    with pytest.raises(ValueError, match="must match"):
        add_http_observation(
            connection,
            "scan-http-001",
            HTTPObservation(
                hostname="api.example.com",
                url="https://www.example.com",
                status_code=200,
            ),
        )


def test_out_of_scope_redirect_rejected(connection):
    with pytest.raises(ScopeValidationError):
        add_http_observation(
            connection,
            "scan-http-001",
            HTTPObservation(
                hostname="api.example.com",
                url="https://api.example.com",
                final_url="https://other.org",
                status_code=302,
            ),
        )


def test_unsupported_url_scheme_rejected(connection):
    with pytest.raises(ValueError, match="Only HTTP and HTTPS"):
        add_http_observation(
            connection,
            "scan-http-001",
            HTTPObservation(
                hostname="api.example.com",
                url="ftp://api.example.com",
                status_code=200,
            ),
        )


@pytest.mark.parametrize("status_code", [0, 99, 600, -1, True])
def test_invalid_status_code_rejected(connection, status_code):
    with pytest.raises(ValueError, match="status code"):
        add_http_observation(
            connection,
            "scan-http-001",
            HTTPObservation(
                hostname="api.example.com",
                url="https://api.example.com",
                status_code=status_code,
            ),
        )


def test_missing_scan_rejected(connection):
    with pytest.raises(LookupError, match="Scan not found"):
        list_http_observations(connection, "missing")
