"""Shared types for external tool integrations."""

from dataclasses import dataclass

from subrecon.core.models import ToolRunStatus


class IntegrationError(RuntimeError):
    """Raised when an integration encounters an error."""


@dataclass(frozen=True, slots=True)
class ToolCheckResult:
    """Represents the availability of an external tool."""

    tool_name: str
    available: bool
    executable: str | None = None
    version: str | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class ToolExecutionResult:
    """Standardized result from an external tool execution."""

    tool_name: str
    status: ToolRunStatus
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
