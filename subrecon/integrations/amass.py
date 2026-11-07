"""Passive Amass 5 integration adapter."""

import os
import shutil
import subprocess
import time

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from subrecon.core.models import DiscoveredSubdomain, ToolRunStatus
from subrecon.core.scope import ScopePolicy, ScopeValidationError
from subrecon.core.normalization import DomainValidationError, normalize_hostname
from subrecon.integrations.base import IntegrationError, ToolExecutionResult


@dataclass(frozen=True, slots=True)
class AmassSettings:
    """Configuration for passive Amass execution."""

    enumeration_timeout_minutes: int = 15
    query_timeout_seconds: int = 15

    def __post_init__(self):
        values = (
            self.enumeration_timeout_minutes,
            self.query_timeout_seconds,
        )

        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            for value in values
        ):
            raise ValueError(
                "Amass timeout settings must be positive integers."
            )


@dataclass(frozen=True, slots=True)
class AmassRunResult:
    """Standardized Amass execution and discovery results."""

    execution: ToolExecutionResult
    discovered: tuple[DiscoveredSubdomain, ...] = ()


class AmassAdapter:
    """Execute passive Amass 5 enumeration and retrieve discovered names."""

    def __init__(
        self,
        executable: str | None = None,
        settings: AmassSettings | None = None,
        runner: Callable | None = None,
    ):
        self.executable = self._resolve_executable(executable)
        self.settings = settings or AmassSettings()
        self.runner = runner

    @staticmethod
    def _resolve_executable(executable: str | None) -> str:
        """Resolve Amass while refusing shell wrappers."""

        def is_usable_binary(path: Path) -> bool:
            if not path.is_file() or not os.access(path, os.X_OK):
                return False

            try:
                with path.open("rb") as file:
                    return file.read(2) != b"#!"
            except OSError:
                return False

        # An explicitly selected executable must never silently fall back.
        if executable is not None:
            requested = Path(executable).expanduser()

            if requested.exists() and not is_usable_binary(requested):
                raise IntegrationError(
                    f"No usable Amass executable: {requested} "
                    "is not an acceptable executable."
                )

            # Nonexistent paths remain usable with injected test runners.
            return str(requested)

        # An environment-configured executable is also explicit.
        environment_path = os.getenv("SUBRECON_AMASS_BINARY")

        if environment_path:
            configured = Path(environment_path).expanduser()

            if not is_usable_binary(configured):
                raise IntegrationError(
                    f"No usable Amass executable: {configured}"
                )

            return str(configured)

        # Prefer the actual Kali binary over /usr/bin/amass.
        candidates = [
            Path("/usr/lib/amass/amass"),
        ]

        discovered = shutil.which("amass")

        if discovered:
            candidates.append(Path(discovered))

        for candidate in candidates:
            if is_usable_binary(candidate):
                return str(candidate)

        raise IntegrationError(
            "A usable Amass executable was not found. "
            "Distribution shell wrappers will not be launched."
        )

    def build_enum_command(
        self,
        target_domain: str,
        scope: ScopePolicy,
        workspace: str | Path,
    ) -> list[str]:
        """Build a passive, strictly scoped Amass enumeration command."""

        try:
            domain = scope.require_allowed(target_domain)
        except ScopeValidationError as exc:
            raise IntegrationError(
                f"Amass target rejected: {exc}"
            ) from exc

        return [
            self.executable,
            "enum",
            "-d", domain,
            "-dir", str(Path(workspace).expanduser()),
            "-rigid",
            "-silent",
            "-nocolor",
            "-timeout", str(self.settings.enumeration_timeout_minutes),
        ]

    def build_subs_command(
        self,
        target_domain: str,
        scope: ScopePolicy,
        workspace: str | Path,
    ) -> list[str]:
        """Build the Amass names-only database retrieval command."""

        try:
            domain = scope.require_allowed(target_domain)
        except ScopeValidationError as exc:
            raise IntegrationError(
                f"Amass target rejected: {exc}"
            ) from exc

        return [
            self.executable,
            "subs",
            "-dir", str(Path(workspace).expanduser()),
            "-d", domain,
            "-names",
            "-nocolor",
        ]

    @staticmethod
    def parse_names_output(
        output: str,
        scope: ScopePolicy,
    ) -> tuple[DiscoveredSubdomain, ...]:
        """Parse names-only output and enforce authorization scope."""

        if not isinstance(output, str):
            raise IntegrationError("Amass output must be text.")

        discoveries = set()

        for line_number, line in enumerate(output.splitlines(), start=1):
            hostname = line.strip()

            if not hostname:
                continue

            # Amass prints this message when its database is empty.
            if hostname.lower() == "no names were discovered":
                continue

            try:
                hostname = normalize_hostname(hostname)
                scope.require_allowed(hostname)

            except (DomainValidationError, ScopeValidationError) as exc:
                raise IntegrationError(
                    f"Invalid or out-of-scope Amass result "
                    f"on line {line_number}."
                ) from exc

            discoveries.add(hostname)

        return tuple(
            DiscoveredSubdomain(
                hostname=hostname,
                sources=("amass",),
            )
            for hostname in sorted(discoveries)
        )

    def run(
        self,
        target_domain: str,
        scope: ScopePolicy,
        workspace: str | Path,
    ) -> AmassRunResult:
        """Run passive enumeration and retrieve discovered hostnames."""

        enum_command = self.build_enum_command(
            target_domain,
            scope,
            workspace,
        )

        query_command = self.build_subs_command(
            target_domain,
            scope,
            workspace,
        )

        workspace_path = Path(workspace).expanduser()
        workspace_path.mkdir(parents=True, exist_ok=True)

        runner = self.runner or subprocess.run
        started = time.monotonic()

        try:
            enum_result = runner(
                enum_command,
                capture_output=True,
                text=True,
                timeout=(
                    self.settings.enumeration_timeout_minutes * 60 + 30
                ),
                check=False,
                shell=False,
            )

            if enum_result.returncode != 0:
                return AmassRunResult(
                    execution=ToolExecutionResult(
                        tool_name="amass",
                        status=ToolRunStatus.FAILED,
                        exit_code=enum_result.returncode,
                        stderr=enum_result.stderr or "",
                        duration_seconds=time.monotonic() - started,
                    )
                )

            query_result = runner(
                query_command,
                capture_output=True,
                text=True,
                timeout=self.settings.query_timeout_seconds,
                check=False,
                shell=False,
            )

            duration = time.monotonic() - started

            if query_result.returncode != 0:
                return AmassRunResult(
                    execution=ToolExecutionResult(
                        tool_name="amass",
                        status=ToolRunStatus.FAILED,
                        exit_code=query_result.returncode,
                        stdout=query_result.stdout or "",
                        stderr=query_result.stderr or "",
                        duration_seconds=duration,
                    )
                )

            discovered = self.parse_names_output(
                query_result.stdout or "",
                scope,
            )

            execution = ToolExecutionResult(
                tool_name="amass",
                status=ToolRunStatus.COMPLETED,
                exit_code=0,
                stdout=query_result.stdout or "",
                stderr=(
                    f"{enum_result.stderr or ''}"
                    f"{query_result.stderr or ''}"
                ).strip(),
                duration_seconds=duration,
            )

            return AmassRunResult(
                execution=execution,
                discovered=discovered,
            )

        except subprocess.TimeoutExpired:
            return AmassRunResult(
                execution=ToolExecutionResult(
                    tool_name="amass",
                    status=ToolRunStatus.TIMED_OUT,
                    stderr="Amass execution timed out.",
                    duration_seconds=time.monotonic() - started,
                )
            )

        except OSError as exc:
            return AmassRunResult(
                execution=ToolExecutionResult(
                    tool_name="amass",
                    status=ToolRunStatus.FAILED,
                    stderr=str(exc),
                    duration_seconds=time.monotonic() - started,
                )
            )

        except IntegrationError as exc:
            return AmassRunResult(
                execution=ToolExecutionResult(
                    tool_name="amass",
                    status=ToolRunStatus.FAILED,
                    stderr=str(exc),
                    duration_seconds=time.monotonic() - started,
                )
            )
