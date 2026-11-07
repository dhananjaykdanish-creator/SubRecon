"""Database operations for HTTP observations."""

import sqlite3
from datetime import datetime
from urllib.parse import urlsplit

from subrecon.core.models import HTTPObservation
from subrecon.core.normalization import normalize_hostname
from subrecon.core.scope import ScopePolicy
from subrecon.storage.repositories.scans import get_scan


def _validate_http_url(
    value: str,
    policy: ScopePolicy,
    expected_hostname: str | None = None,
) -> str:
    """Validate an HTTP URL against the authorized scope."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("HTTP URL cannot be empty.")

    value = value.strip()

    try:
        parsed = urlsplit(value)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.hostname:
            raise ValueError("HTTP URL must contain a hostname.")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials are not allowed.")

        # Accessing port validates its syntax.
        _ = parsed.port

        hostname = normalize_hostname(parsed.hostname)

    except ValueError as exc:
        raise ValueError(f"Invalid HTTP URL: {exc}") from exc

    policy.require_allowed(hostname)

    if expected_hostname is not None and hostname != expected_hostname:
        raise ValueError(
            "HTTP URL hostname must match the observation hostname."
        )

    return value


def add_http_observation(
    connection: sqlite3.Connection,
    scan_id: str,
    observation: HTTPObservation,
) -> int:
    """Store an HTTP observation for a discovered hostname."""

    scan = get_scan(connection, scan_id)

    if scan is None:
        raise LookupError(f"Scan not found: {scan_id}")

    hostname = normalize_hostname(observation.hostname)

    policy = ScopePolicy((scan.root_domain,))
    policy.require_allowed(hostname)

    if observation.status_code is not None:
        if (
            isinstance(observation.status_code, bool)
            or not isinstance(observation.status_code, int)
            or not 100 <= observation.status_code <= 599
        ):
            raise ValueError("HTTP status code must be between 100 and 599.")

    url = _validate_http_url(
        observation.url,
        policy,
        expected_hostname=hostname,
    )

    final_url = None

    if observation.final_url is not None:
        final_url = _validate_http_url(
            observation.final_url,
            policy,
        )

    subdomain = connection.execute(
        """
        SELECT id
        FROM discovered_subdomains
        WHERE scan_id = ? AND hostname = ?
        """,
        (scan_id, hostname),
    ).fetchone()

    if subdomain is None:
        raise LookupError(
            f"Hostname '{hostname}' has not been discovered in this scan."
        )

    cursor = connection.execute(
        """
        INSERT INTO http_observations (
            subdomain_id,
            url,
            status_code,
            final_url,
            title,
            server,
            content_type,
            observed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            subdomain["id"],
            url,
            observation.status_code,
            final_url,
            observation.title,
            observation.server,
            observation.content_type,
            observation.observed_at.isoformat(),
        ),
    )

    return cursor.lastrowid


def list_http_observations(
    connection: sqlite3.Connection,
    scan_id: str,
) -> list[HTTPObservation]:
    """Retrieve HTTP observations belonging to a scan."""

    if get_scan(connection, scan_id) is None:
        raise LookupError(f"Scan not found: {scan_id}")

    rows = connection.execute(
        """
        SELECT
            d.hostname,
            h.url,
            h.status_code,
            h.final_url,
            h.title,
            h.server,
            h.content_type,
            h.observed_at
        FROM http_observations AS h
        JOIN discovered_subdomains AS d
            ON d.id = h.subdomain_id
        WHERE d.scan_id = ?
        ORDER BY h.observed_at, h.id
        """,
        (scan_id,),
    ).fetchall()

    return [
        HTTPObservation(
            hostname=row["hostname"],
            url=row["url"],
            status_code=row["status_code"],
            final_url=row["final_url"],
            title=row["title"],
            server=row["server"],
            content_type=row["content_type"],
            observed_at=datetime.fromisoformat(row["observed_at"]),
        )
        for row in rows
    ]
