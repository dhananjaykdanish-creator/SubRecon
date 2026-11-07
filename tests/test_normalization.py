"""Tests for hostname normalization."""

import pytest

from subrecon.core.normalization import (
    DomainValidationError,
    normalize_hostname,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("Example.Com.", "example.com"),
        ("  example.com  ", "example.com"),
        ("sub.example.com", "sub.example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_valid_hostname_normalization(value, expected):
    assert normalize_hostname(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "localhost",
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "*.example.com",
        "192.0.2.1",
        "example..com",
        "-example.com",
        "example-.com",
        "example_.com",
    ],
)
def test_invalid_hostnames(value):
    with pytest.raises(DomainValidationError):
        normalize_hostname(value)


def test_non_string_input():
    with pytest.raises(DomainValidationError):
        normalize_hostname(None)
