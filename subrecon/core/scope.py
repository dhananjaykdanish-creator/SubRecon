"""Strict authorization scope enforcement."""

from dataclasses import dataclass

from subrecon.core.normalization import (
    DomainValidationError,
    normalize_hostname,
)


class ScopeValidationError(ValueError):
    """Raised when a hostname is outside the authorized scope."""


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """An explicit allowlist of authorized root domains."""

    allowed_domains: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.allowed_domains:
            raise ScopeValidationError(
                "At least one authorized root domain is required."
            )

        try:
            normalized = tuple(
                dict.fromkeys(
                    normalize_hostname(domain)
                    for domain in self.allowed_domains
                )
            )
        except DomainValidationError as exc:
            raise ScopeValidationError(
                f"Invalid authorized domain: {exc}"
            ) from exc

        object.__setattr__(self, "allowed_domains", normalized)

    def is_allowed(self, hostname: str) -> bool:
        """Return whether a hostname belongs to an authorized domain."""

        try:
            candidate = normalize_hostname(hostname)
        except DomainValidationError:
            return False

        return any(
            candidate == domain or candidate.endswith("." + domain)
            for domain in self.allowed_domains
        )

    def require_allowed(self, hostname: str) -> str:
        """Validate a hostname or raise an authorization error."""

        try:
            candidate = normalize_hostname(hostname)
        except DomainValidationError as exc:
            raise ScopeValidationError(
                f"Invalid target hostname: {exc}"
            ) from exc

        if not self.is_allowed(candidate):
            raise ScopeValidationError(
                f"Target '{candidate}' is outside the authorized scope."
            )

        return candidate
