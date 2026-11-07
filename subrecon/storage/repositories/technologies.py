"""Database operations for technology observations."""

import sqlite3
from datetime import datetime

from subrecon.core.models import TechnologyObservation
from subrecon.core.normalization import normalize_hostname
from subrecon.core.scope import ScopePolicy
from subrecon.storage.repositories.scans import get_scan


def _clean_required_text(value: str, field_name: str) -> str:
    """Validate and normalize a required text field."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} cannot be empty.")

    return value.strip()


def _clean_optional_text(
    value: str | None,
    field_name: str,
) -> str | None:
    """Validate an optional text field."""

    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be text.")

    return value.strip() or None


def add_technology_observation(
    connection: sqlite3.Connection,
    scan_id: str,
    observation: TechnologyObservation,
) -> int:
    """Store a technology observation for a discovered hostname."""

    scan = get_scan(connection, scan_id)

    if scan is None:
        raise LookupError(f"Scan not found: {scan_id}")

    hostname = normalize_hostname(observation.hostname)

    policy = ScopePolicy((scan.root_domain,))
    policy.require_allowed(hostname)

    name = _clean_required_text(
        observation.name,
        "Technology name",
    )

    version = _clean_optional_text(
        observation.version,
        "Technology version",
    )

    source = _clean_optional_text(
        observation.source,
        "Technology source",
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
        INSERT INTO technology_observations (
            subdomain_id,
            name,
            version,
            source,
            observed_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            subdomain["id"],
            name,
            version,
            source,
            observation.observed_at.isoformat(),
        ),
    )

    return cursor.lastrowid


def list_technology_observations(
    connection: sqlite3.Connection,
    scan_id: str,
) -> list[TechnologyObservation]:
    """Retrieve technology observations belonging to a scan."""

    if get_scan(connection, scan_id) is None:
        raise LookupError(f"Scan not found: {scan_id}")

    rows = connection.execute(
        """
        SELECT
            d.hostname,
            t.name,
            t.version,
            t.source,
            t.observed_at
        FROM technology_observations AS t
        JOIN discovered_subdomains AS d
            ON d.id = t.subdomain_id
        WHERE d.scan_id = ?
        ORDER BY t.observed_at, t.id
        """,
        (scan_id,),
    ).fetchall()

    return [
        TechnologyObservation(
            hostname=row["hostname"],
            name=row["name"],
            version=row["version"],
            source=row["source"],
            observed_at=datetime.fromisoformat(row["observed_at"]),
        )
        for row in rows
    ]
