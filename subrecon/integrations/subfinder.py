"""Passive Subfinder integration adapter."""

import json
import shutil
import subprocess
import time

from dataclasses import dataclass
from typing import Callable

from subrecon.core.models import (
    DiscoveredSubdomain,
    ToolRunStatus,
)
from subrecon.core.scope import (
    ScopePolicy,
    ScopeValidationError,
)
from subrecon.integrations.base import (
    IntegrationError,
    ToolExecutionResult,
)


@dataclass(frozen=True, slots=True)
class SubfinderSettings:
    """Configuration for passive Subfinder execution."""

    source_timeout_seconds: int = 30
    max_time_minutes: int = 10
    rate_limit_per_second: int = 5

    def __post_init__(self):
        values = (
            self.source_timeout_seconds,
            self.max_time_minutes,
            self.rate_limit_per_second,
        )

        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            for value in values
        ):
            raise ValueError("Subfinder settings must be positive integers.")


@dataclass(frozen=True, slots=True)
class SubfinderRunResult:
    """Combined execution and discovery results."""

    execution: ToolExecutionResult
    discovered: tuple[DiscoveredSubdomain, ...] = ()


class SubfinderAdapter:
    """Execute and process passive Subfinder results."""

    def __init__(
        self,
        executable: str | None = None,
        settings: SubfinderSettings | None = None,
        runner: Callable | None = None,
    ):
        self.executable = executable or shutil.which("subfinder")

        if not self.executable:
            raise IntegrationError("Subfinder executable was not found.")

        self.settings = settings or SubfinderSettings()
        self.runner = runner

    def build_command(
        self,
        target_domain: str,
        scope: ScopePolicy,
    ) -> list[str]:
        """Build a scope-validated passive Subfinder command."""

        try:
            domain = scope.require_allowed(target_domain)
        except ScopeValidationError as exc:
            raise IntegrationError(
                f"Subfinder target rejected: {exc}"
            ) from exc

        return [
            self.executable,
            "-d", domain,
            "-oJ",
            "-cs",
            "-silent",
            "-duc",
            "-rl", str(self.settings.rate_limit_per_second),
            "-timeout", str(self.settings.source_timeout_seconds),
            "-max-time", str(self.settings.max_time_minutes),
        ]

    @staticmethod
    def parse_output(
        output: str,
        scope: ScopePolicy,
    ) -> tuple[DiscoveredSubdomain, ...]:
        """Parse JSONL output and enforce authorized scope."""

        discoveries: dict[str, set[str]] = {}

        for line_number, line in enumerate(output.splitlines(), start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise IntegrationError(
                    f"Invalid Subfinder JSON on line {line_number}."
                ) from exc

            if not isinstance(record, dict):
                raise IntegrationError(
                    f"Unexpected Subfinder record on line {line_number}."
                )

            hostname = record.get("host")

            if not isinstance(hostname, str):
                raise IntegrationError(
                    f"Missing hostname on Subfinder line {line_number}."
                )

            try:
                hostname = scope.require_allowed(hostname)
            except ScopeValidationError as exc:
                raise IntegrationError(
                    f"Subfinder returned an out-of-scope hostname "
                    f"on line {line_number}."
                ) from exc

            raw_sources = record.get("sources")

            if raw_sources is None:
                raw_sources = record.get("source")

            if raw_sources is None:
                sources = []
            elif isinstance(raw_sources, str):
                sources = [raw_sources]
            elif isinstance(raw_sources, list):
                sources = raw_sources
            else:
                raise IntegrationError(
                    f"Invalid discovery sources on line {line_number}."
                )

            if not all(isinstance(source, str) for source in sources):
                raise IntegrationError(
                    f"Invalid discovery source on line {line_number}."
                )

            discoveries.setdefault(hostname, set())

            for source in sources:
                source = source.strip()

                if source:
                    discoveries[hostname].add(source)

            if not discoveries[hostname]:
                discoveries[hostname].add("subfinder")

        return tuple(
            DiscoveredSubdomain(
                hostname=hostname,
                sources=tuple(sorted(sources)),
            )
            for hostname, sources in sorted(discoveries.items())
        )

    def run(
        self,
        target_domain: str,
        scope: ScopePolicy,
    ) -> SubfinderRunResult:
        """Run passive Subfinder and standardize its output."""

        command = self.build_command(target_domain, scope)

        process_timeout = (
            self.settings.max_time_minutes * 60 + 30
        )

        runner = self.runner or subprocess.run
        started = time.monotonic()

        try:
            result = runner(
                command,
                capture_output=True,
                text=True,
                timeout=process_timeout,
                check=False,
                shell=False,
            )

        except subprocess.TimeoutExpired:
            execution = ToolExecutionResult(
                tool_name="subfinder",
                status=ToolRunStatus.TIMED_OUT,
                duration_seconds=time.monotonic() - started,
                stderr="Subfinder execution timed out.",
            )

            return SubfinderRunResult(execution=execution)

        except OSError as exc:
            execution = ToolExecutionResult(
                tool_name="subfinder",
                status=ToolRunStatus.FAILED,
                duration_seconds=time.monotonic() - started,
                stderr=str(exc),
            )

            return SubfinderRunResult(execution=execution)

        duration = time.monotonic() - started
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        if result.returncode != 0:
            execution = ToolExecutionResult(
                tool_name="subfinder",
                status=ToolRunStatus.FAILED,
                exit_code=result.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
            )

            return SubfinderRunResult(execution=execution)

        try:
            discovered = self.parse_output(stdout, scope)

        except IntegrationError as exc:
            execution = ToolExecutionResult(
                tool_name="subfinder",
                status=ToolRunStatus.FAILED,
                exit_code=result.returncode,
                stdout=stdout,
                stderr=f"{stderr}\n{exc}".strip(),
                duration_seconds=duration,
            )

            return SubfinderRunResult(execution=execution)

        execution = ToolExecutionResult(
            tool_name="subfinder",
            status=ToolRunStatus.COMPLETED,
            exit_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
        )

        return SubfinderRunResult(
            execution=execution,
            discovered=discovered,
        )
