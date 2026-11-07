"""Database operations for scans and discovered subdomains."""

import sqlite3
from datetime import datetime

from subrecon.core.models import DiscoveredSubdomain, Scan, ScanStatus
from subrecon.core.normalization import normalize_hostname
from subrecon.core.scope import ScopePolicy


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def create_scan(connection: sqlite3.Connection, scan: Scan) -> None:
    """Insert a new scan."""

    root_domain = normalize_hostname(scan.root_domain)

    connection.execute(
        """
        INSERT INTO scans (
            scan_id, root_domain, status, started_at, completed_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            scan.scan_id,
            root_domain,
            scan.status.value,
            scan.started_at.isoformat(),
            scan.completed_at.isoformat() if scan.completed_at else None,
        ),
    )


def get_scan(
    connection: sqlite3.Connection,
    scan_id: str,
) -> Scan | None:
    """Retrieve a scan by ID."""

    row = connection.execute(
        "SELECT * FROM scans WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()

    if row is None:
        return None

    return Scan(
        scan_id=row["scan_id"],
        root_domain=row["root_domain"],
        status=ScanStatus(row["status"]),
        started_at=_parse_datetime(row["started_at"]),
        completed_at=_parse_datetime(row["completed_at"]),
    )


def add_discovered_subdomain(
    connection: sqlite3.Connection,
    scan_id: str,
    subdomain: DiscoveredSubdomain,
) -> int:
    """Store a discovered hostname and its validated sources."""

    scan = get_scan(connection, scan_id)

    if scan is None:
        raise LookupError(f"Scan not found: {scan_id}")

    hostname = normalize_hostname(subdomain.hostname)

    policy = ScopePolicy((scan.root_domain,))
    policy.require_allowed(hostname)

    # Validate every source before writing to the database.
    normalized_sources = []

    for source in subdomain.sources:
        if not isinstance(source, str):
            raise ValueError("Discovery source must be text.")

        source = source.strip()

        if not source:
            raise ValueError("Discovery source cannot be empty.")

        if source not in normalized_sources:
            normalized_sources.append(source)

    timestamp = subdomain.discovered_at.isoformat()

    connection.execute(
        """
        INSERT OR IGNORE INTO discovered_subdomains (
            scan_id, hostname, discovered_at
        )
        VALUES (?, ?, ?)
        """,
        (scan_id, hostname, timestamp),
    )

    row = connection.execute(
        """
        SELECT id FROM discovered_subdomains
        WHERE scan_id = ? AND hostname = ?
        """,
        (scan_id, hostname),
    ).fetchone()

    if row is None:
        raise RuntimeError("Could not retrieve the stored subdomain.")

    subdomain_id = row["id"]

    for source in normalized_sources:
        connection.execute(
            """
            INSERT OR IGNORE INTO subdomain_sources (
                subdomain_id, source, discovered_at
            )
            VALUES (?, ?, ?)
            """,
            (subdomain_id, source, timestamp),
        )

    return subdomain_id


def list_discovered_subdomains(
    connection: sqlite3.Connection,
    scan_id: str,
) -> list[DiscoveredSubdomain]:
    """Retrieve discovered hostnames and their sources."""

    if get_scan(connection, scan_id) is None:
        raise LookupError(f"Scan not found: {scan_id}")

    rows = connection.execute(
        """
        SELECT
            d.hostname,
            d.discovered_at,
            s.source
        FROM discovered_subdomains AS d
        LEFT JOIN subdomain_sources AS s
            ON s.subdomain_id = d.id
        WHERE d.scan_id = ?
        ORDER BY d.hostname, s.source
        """,
        (scan_id,),
    ).fetchall()

    results = {}

    for row in rows:
        hostname = row["hostname"]

        if hostname not in results:
            results[hostname] = {
                "discovered_at": _parse_datetime(row["discovered_at"]),
                "sources": [],
            }

        if row["source"] is not None:
            results[hostname]["sources"].append(row["source"])

    return [
        DiscoveredSubdomain(
            hostname=hostname,
            sources=tuple(data["sources"]),
            discovered_at=data["discovered_at"],
        )
        for hostname, data in results.items()
    ]


def update_scan_status(
    connection: sqlite3.Connection,
    scan_id: str,
    status: ScanStatus,
    completed_at: datetime | None = None,
) -> None:
    """Update a scan's status and completion timestamp."""

    from subrecon.core.models import utc_now

    if not isinstance(status, ScanStatus):
        raise ValueError("Invalid scan status.")

    if get_scan(connection, scan_id) is None:
        raise LookupError(f"Scan not found: {scan_id}")

    if status in (
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    ):
        completed_at = completed_at or utc_now()
    else:
        completed_at = None

    connection.execute(
        """
        UPDATE scans
        SET status = ?, completed_at = ?
        WHERE scan_id = ?
        """,
        (
            status.value,
            completed_at.isoformat() if completed_at else None,
            scan_id,
        ),
    )


def list_scans(
    connection: sqlite3.Connection,
    limit: int = 20,
) -> list[Scan]:
    """Retrieve recent scans, newest first."""

    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit <= 0
    ):
        raise ValueError("Scan history limit must be a positive integer.")

    rows = connection.execute(
        """
        SELECT *
        FROM scans
        ORDER BY started_at DESC, scan_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return [
        Scan(
            scan_id=row["scan_id"],
            root_domain=row["root_domain"],
            status=ScanStatus(row["status"]),
            started_at=_parse_datetime(row["started_at"]),
            completed_at=_parse_datetime(row["completed_at"]),
        )
        for row in rows
    ]
