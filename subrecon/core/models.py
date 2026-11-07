"""Core data models used throughout SubRecon."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    """Possible states of a reconnaissance scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ToolRunStatus(str, Enum):
    """Possible states of an external tool execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class Scan:
    """Represents one reconnaissance scan."""

    scan_id: str
    root_domain: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = field(default_factory=utc_now)
    completed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class DiscoveredSubdomain:
    """Represents a discovered subdomain."""

    hostname: str
    sources: tuple[str, ...] = ()
    discovered_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class DNSObservation:
    """Represents an observed DNS record."""

    hostname: str
    record_type: str
    value: str
    ttl: int | None = None
    observed_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class HTTPObservation:
    """Represents an HTTP observation.

    A missing status code means no HTTP response was received.
    HTTP responses such as 401 and 403 remain valid observations.
    """

    hostname: str
    url: str
    status_code: int | None
    final_url: str | None = None
    title: str | None = None
    server: str | None = None
    content_type: str | None = None
    observed_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class TechnologyObservation:
    """Represents a detected website technology."""

    hostname: str
    name: str
    version: str | None = None
    source: str | None = None
    observed_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class ToolRun:
    """Represents the execution of an external reconnaissance tool."""

    tool_name: str
    status: ToolRunStatus = ToolRunStatus.PENDING
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    exit_code: int | None = None
    error_message: str | None = None
