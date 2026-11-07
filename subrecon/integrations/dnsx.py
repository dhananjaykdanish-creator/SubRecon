"""ProjectDiscovery DNSx integration adapter."""

import ipaddress
import json
import shutil
import subprocess
import time

from dataclasses import dataclass
from typing import Callable, Iterable

from subrecon.core.models import DNSObservation, ToolRunStatus
from subrecon.core.normalization import normalize_hostname
from subrecon.core.scope import ScopePolicy, ScopeValidationError
from subrecon.integrations.base import IntegrationError, ToolExecutionResult


_ALLOWED_RECORD_TYPES = {"A", "AAAA", "CNAME"}


@dataclass(frozen=True, slots=True)
class DNSxSettings:
    """Conservative DNSx execution settings."""

    threads: int = 5
    rate_limit_per_second: int = 10
    retries: int = 1
    timeout_seconds: int = 3
    process_timeout_seconds: int = 120

    def __post_init__(self):
        values = (
            self.threads,
            self.rate_limit_per_second,
            self.retries,
            self.timeout_seconds,
            self.process_timeout_seconds,
        )

        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            for value in values
        ):
            raise ValueError("DNSx settings must be positive integers.")


@dataclass(frozen=True, slots=True)
class DNSxRunResult:
    """Execution result and parsed DNS observations."""

    execution: ToolExecutionResult
    observations: tuple[DNSObservation, ...] = ()


def _normalize_targets(
    hostnames: Iterable[str],
    scope: ScopePolicy,
) -> tuple[str, ...]:
    """Normalize, deduplicate and validate DNS query targets."""

    if isinstance(hostnames, (str, bytes)):
        raise IntegrationError(
            "DNSx requires an iterable of hostnames, not a single string."
        )

    normalized = []

    for hostname in hostnames:
        if not isinstance(hostname, str):
            raise IntegrationError("DNSx received an invalid hostname.")

        try:
            hostname = scope.require_allowed(hostname)
        except ScopeValidationError as exc:
            raise IntegrationError(
                "DNSx rejected an out-of-scope hostname."
            ) from exc

        if hostname not in normalized:
            normalized.append(hostname)

    if not normalized:
        raise IntegrationError(
            "DNSx requires at least one discovered hostname."
        )

    return tuple(normalized)


class DNSxAdapter:
    """Resolve discovered hostnames using ProjectDiscovery DNSx."""

    def __init__(
        self,
        executable: str | None = None,
        settings: DNSxSettings | None = None,
        runner: Callable | None = None,
    ):
        self.executable = executable or shutil.which("dnsx")

        if not self.executable:
            raise IntegrationError("DNSx executable was not found.")

        self.settings = settings or DNSxSettings()
        self.runner = runner

    def build_command(
        self,
        hostnames: Iterable[str],
        scope: ScopePolicy,
    ) -> list[str]:
        """Build a scope-validated DNSx command."""

        _normalize_targets(hostnames, scope)

        return [
            self.executable,
            "-a",
            "-aaaa",
            "-cname",
            "-json",
            "-silent",
            "-duc",
            "-nc",
            "-t", str(self.settings.threads),
            "-rl", str(self.settings.rate_limit_per_second),
            "-retry", str(self.settings.retries),
            "-timeout", f"{self.settings.timeout_seconds}s",
        ]

    @staticmethod
    def parse_output(
        output: str,
        requested_hostnames: Iterable[str],
        scope: ScopePolicy,
    ) -> tuple[DNSObservation, ...]:
        """Parse DNSx JSONL output and validate every returned record."""

        requested = set(
            _normalize_targets(requested_hostnames, scope)
        )

        observations = {}

        for line_number, line in enumerate(output.splitlines(), start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise IntegrationError(
                    f"Invalid DNSx JSON on line {line_number}."
                ) from exc

            if not isinstance(record, dict):
                raise IntegrationError(
                    f"Unexpected DNSx record on line {line_number}."
                )

            raw_host = record.get("host")

            if not isinstance(raw_host, str):
                raise IntegrationError(
                    f"Missing DNSx hostname on line {line_number}."
                )

            try:
                host = scope.require_allowed(raw_host)
            except ScopeValidationError as exc:
                raise IntegrationError(
                    f"DNSx returned an out-of-scope hostname "
                    f"on line {line_number}."
                ) from exc

            if host not in requested:
                raise IntegrationError(
                    f"DNSx returned an unexpected hostname "
                    f"on line {line_number}."
                )

            raw_records = record.get("all", [])

            if not isinstance(raw_records, list):
                raise IntegrationError(
                    f"Invalid DNSx record list on line {line_number}."
                )

            for raw_record in raw_records:
                if not isinstance(raw_record, str):
                    raise IntegrationError(
                        f"Invalid DNSx resource record "
                        f"on line {line_number}."
                    )

                parts = raw_record.split("\t", 4)

                if len(parts) != 5:
                    parts = raw_record.split(None, 4)

                if len(parts) != 5:
                    raise IntegrationError(
                        f"Malformed DNSx resource record "
                        f"on line {line_number}."
                    )

                raw_owner, raw_ttl, dns_class, raw_type, raw_value = parts
                record_type = raw_type.strip().upper()

                if record_type not in _ALLOWED_RECORD_TYPES:
                    continue

                if dns_class.upper() != "IN":
                    raise IntegrationError(
                        f"Unexpected DNS class on line {line_number}."
                    )

                try:
                    owner = scope.require_allowed(raw_owner)
                except ScopeValidationError as exc:
                    raise IntegrationError(
                        f"DNSx returned an out-of-scope record owner "
                        f"on line {line_number}."
                    ) from exc

                if owner not in requested:
                    raise IntegrationError(
                        f"DNSx returned an unexpected record owner "
                        f"on line {line_number}."
                    )

                try:
                    ttl = int(raw_ttl)
                except (TypeError, ValueError) as exc:
                    raise IntegrationError(
                        f"Invalid DNS TTL on line {line_number}."
                    ) from exc

                if ttl < 0:
                    raise IntegrationError(
                        f"Negative DNS TTL on line {line_number}."
                    )

                value = raw_value.strip()

                if not value:
                    raise IntegrationError(
                        f"Empty DNS value on line {line_number}."
                    )

                if record_type in {"A", "AAAA"}:
                    try:
                        address = ipaddress.ip_address(value)
                    except ValueError as exc:
                        raise IntegrationError(
                            f"Invalid IP address on line {line_number}."
                        ) from exc

                    expected_version = 4 if record_type == "A" else 6

                    if address.version != expected_version:
                        raise IntegrationError(
                            f"Incorrect IP address type on line "
                            f"{line_number}."
                        )

                    value = str(address)

                elif record_type == "CNAME":
                    try:
                        value = normalize_hostname(value)
                    except ValueError as exc:
                        raise IntegrationError(
                            f"Invalid CNAME target on line {line_number}."
                        ) from exc

                observation = DNSObservation(
                    hostname=owner,
                    record_type=record_type,
                    value=value,
                    ttl=ttl,
                )

                key = (
                    observation.hostname,
                    observation.record_type,
                    observation.value,
                    observation.ttl,
                )

                observations[key] = observation

        return tuple(observations.values())

    def run(
        self,
        hostnames: Iterable[str],
        scope: ScopePolicy,
    ) -> DNSxRunResult:
        """Resolve discovered hostnames and parse DNS observations."""

        targets = _normalize_targets(hostnames, scope)
        command = self.build_command(targets, scope)

        runner = self.runner or subprocess.run
        started = time.monotonic()
        input_data = "\n".join(targets) + "\n"

        try:
            result = runner(
                command,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=self.settings.process_timeout_seconds,
                check=False,
                shell=False,
            )

        except subprocess.TimeoutExpired:
            execution = ToolExecutionResult(
                tool_name="dnsx",
                status=ToolRunStatus.TIMED_OUT,
                duration_seconds=time.monotonic() - started,
                stderr="DNSx execution timed out.",
            )
            return DNSxRunResult(execution=execution)

        except OSError as exc:
            execution = ToolExecutionResult(
                tool_name="dnsx",
                status=ToolRunStatus.FAILED,
                duration_seconds=time.monotonic() - started,
                stderr=str(exc),
            )
            return DNSxRunResult(execution=execution)

        duration = time.monotonic() - started
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        if result.returncode != 0:
            execution = ToolExecutionResult(
                tool_name="dnsx",
                status=ToolRunStatus.FAILED,
                exit_code=result.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
            )
            return DNSxRunResult(execution=execution)

        try:
            observations = self.parse_output(stdout, targets, scope)
        except IntegrationError as exc:
            execution = ToolExecutionResult(
                tool_name="dnsx",
                status=ToolRunStatus.FAILED,
                exit_code=result.returncode,
                stdout=stdout,
                stderr=f"{stderr}\n{exc}".strip(),
                duration_seconds=duration,
            )
            return DNSxRunResult(execution=execution)

        execution = ToolExecutionResult(
            tool_name="dnsx",
            status=ToolRunStatus.COMPLETED,
            exit_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
        )

        return DNSxRunResult(
            execution=execution,
            observations=observations,
        )
