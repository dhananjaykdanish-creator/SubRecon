"""Database operations for DNS observations."""

import re
import sqlite3
from datetime import datetime

from subrecon.core.models import DNSObservation
from subrecon.core.normalization import normalize_hostname
from subrecon.core.scope import ScopePolicy
from subrecon.storage.repositories.scans import get_scan


_RECORD_TYPE_PATTERN = re.compile(r"^[A-Z][A-Z0-9-]{0,15}$")


def add_dns_observation(
    connection: sqlite3.Connection,
    scan_id: str,
    observation: DNSObservation,
) -> int:
    """Store a DNS observation for a discovered hostname."""

    scan = get_scan(connection, scan_id)

    if scan is None:
        raise LookupError(f"Scan not found: {scan_id}")

    hostname = normalize_hostname(observation.hostname)

    policy = ScopePolicy((scan.root_domain,))
    policy.require_allowed(hostname)

    if not isinstance(observation.record_type, str):
        raise ValueError("Invalid DNS record type.")

    record_type = observation.record_type.strip().upper()

    if not _RECORD_TYPE_PATTERN.fullmatch(record_type):
        raise ValueError("Invalid DNS record type.")

    if not isinstance(observation.value, str):
        raise ValueError("DNS record value must be text.")

    value = observation.value.strip()

    if not value:
        raise ValueError("DNS record value cannot be empty.")

    if observation.ttl is not None:
        if (
            isinstance(observation.ttl, bool)
            or not isinstance(observation.ttl, int)
            or observation.ttl < 0
        ):
            raise ValueError("DNS TTL must be a non-negative integer.")

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
        INSERT INTO dns_observations (
            subdomain_id, record_type, value, ttl, observed_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            subdomain["id"],
            record_type,
            value,
            observation.ttl,
            observation.observed_at.isoformat(),
        ),
    )

    return cursor.lastrowid


def list_dns_observations(
    connection: sqlite3.Connection,
    scan_id: str,
) -> list[DNSObservation]:
    """Retrieve DNS observations belonging to a scan."""

    if get_scan(connection, scan_id) is None:
        raise LookupError(f"Scan not found: {scan_id}")

    rows = connection.execute(
        """
        SELECT
            d.hostname,
            dns.record_type,
            dns.value,
            dns.ttl,
            dns.observed_at
        FROM dns_observations AS dns
        JOIN discovered_subdomains AS d
            ON d.id = dns.subdomain_id
        WHERE d.scan_id = ?
        ORDER BY dns.observed_at, dns.id
        """,
        (scan_id,),
    ).fetchall()

    return [
        DNSObservation(
            hostname=row["hostname"],
            record_type=row["record_type"],
            value=row["value"],
            ttl=row["ttl"],
            observed_at=datetime.fromisoformat(row["observed_at"]),
        )
        for row in rows
    ]
