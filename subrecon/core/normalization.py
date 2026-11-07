"""Hostname normalization and validation utilities."""

import ipaddress
import re


class DomainValidationError(ValueError):
    """Raised when a hostname is invalid."""


_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


def normalize_hostname(value: str) -> str:
    """Normalize a DNS hostname into lowercase ASCII form.

    Performs:
    - Leading/trailing whitespace removal.
    - Trailing DNS root-dot removal.
    - IDN conversion to ASCII/Punycode.
    - Lowercase conversion.
    - DNS hostname validation.

    Rejects URLs, IP addresses, wildcard domains and invalid labels.
    """

    if not isinstance(value, str):
        raise DomainValidationError("Hostname must be a string.")

    hostname = value.strip()

    if not hostname:
        raise DomainValidationError("Hostname cannot be empty.")

    if any(char in hostname for char in (":", "/", "\\", "?", "#", "@", "*")):
        raise DomainValidationError(
            "Provide a hostname, not a URL, IP address, or wildcard."
        )

    hostname = hostname.removesuffix(".")

    if not hostname:
        raise DomainValidationError("Hostname cannot be empty.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise DomainValidationError("IP addresses are not valid hostnames.")

    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DomainValidationError("Invalid internationalized hostname.") from exc

    if len(hostname) > 253:
        raise DomainValidationError("Hostname exceeds the 253-character limit.")

    labels = hostname.split(".")

    if len(labels) < 2:
        raise DomainValidationError(
            "A fully qualified domain name with at least two labels is required."
        )

    for label in labels:
        if not label:
            raise DomainValidationError("Hostname contains an empty label.")

        if len(label) > 63:
            raise DomainValidationError(
                "A hostname label exceeds the 63-character limit."
            )

        if not _LABEL_PATTERN.fullmatch(label):
            raise DomainValidationError(
                f"Invalid hostname label: {label!r}"
            )

    return hostname
