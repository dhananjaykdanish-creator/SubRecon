"""Tests for SubRecon application configuration."""

from pathlib import Path

import pytest

from subrecon.config import PROJECT_ROOT, load_config


def test_default_configuration(monkeypatch):
    """Default settings should use project-relative paths."""

    monkeypatch.delenv("SUBRECON_RESULTS_DIR", raising=False)
    monkeypatch.delenv("SUBRECON_DATABASE_PATH", raising=False)
    monkeypatch.delenv("SUBRECON_LOG_LEVEL", raising=False)

    config = load_config()

    assert config.project_root == PROJECT_ROOT
    assert config.results_dir == PROJECT_ROOT / "results"
    assert config.database_path == PROJECT_ROOT / "results" / "subrecon.db"
    assert config.log_level == "INFO"


def test_environment_overrides(monkeypatch):
    """Environment variables should override default settings."""

    monkeypatch.setenv("SUBRECON_RESULTS_DIR", "/tmp/subrecon-results")
    monkeypatch.setenv("SUBRECON_DATABASE_PATH", "/tmp/custom.db")
    monkeypatch.setenv("SUBRECON_LOG_LEVEL", "debug")

    config = load_config()

    assert config.results_dir == Path("/tmp/subrecon-results")
    assert config.database_path == Path("/tmp/custom.db")
    assert config.log_level == "DEBUG"


def test_invalid_log_level(monkeypatch):
    """Invalid log levels should raise a clear error."""

    monkeypatch.setenv("SUBRECON_LOG_LEVEL", "INVALID")

    with pytest.raises(ValueError, match="Invalid log level"):
        load_config()
