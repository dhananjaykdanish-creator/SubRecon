"""Tests for strict authorization scope enforcement."""

import pytest

from subrecon.core.scope import (
    ScopePolicy,
    ScopeValidationError,
)


@pytest.fixture
def scope():
    return ScopePolicy(
        allowed_domains=("example.com",)
    )


@pytest.mark.parametrize(
    "hostname",
    [
        "example.com",
        "www.example.com",
        "api.example.com",
        "dev.api.example.com",
        "EXAMPLE.COM",
    ],
)
def test_authorized_hostnames(scope, hostname):
    assert scope.is_allowed(hostname)


@pytest.mark.parametrize(
    "hostname",
    [
        "notexample.com",
        "example.org",
        "other.com",
        "example.com.attacker.org",
        "attacker-example.com",
        "192.0.2.1",
        "https://example.com",
    ],
)
def test_unauthorized_hostnames(scope, hostname):
    assert not scope.is_allowed(hostname)


def test_require_allowed_returns_normalized_hostname(scope):
    result = scope.require_allowed("WWW.EXAMPLE.COM.")

    assert result == "www.example.com"


def test_require_allowed_rejects_outside_scope(scope):
    with pytest.raises(ScopeValidationError, match="outside the authorized scope"):
        scope.require_allowed("other.com")


def test_empty_scope_is_rejected():
    with pytest.raises(ScopeValidationError, match="At least one"):
        ScopePolicy(allowed_domains=())


def test_multiple_authorized_domains():
    policy = ScopePolicy(
        allowed_domains=("example.com", "example.org")
    )

    assert policy.is_allowed("api.example.com")
    assert policy.is_allowed("www.example.org")
    assert not policy.is_allowed("example.net")


def test_duplicate_domains_are_removed():
    policy = ScopePolicy(
        allowed_domains=("example.com", "EXAMPLE.COM")
    )

    assert policy.allowed_domains == ("example.com",)
