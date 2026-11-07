"""Central application configuration for SubRecon."""

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

VALID_LOG_LEVELS = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "CRITICAL",
}


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Application settings."""

    project_root: Path
    results_dir: Path
    database_path: Path
    log_level: str


def load_config() -> AppConfig:
    """Load application settings with optional environment overrides."""

    results_value = os.getenv("SUBRECON_RESULTS_DIR")
    database_value = os.getenv("SUBRECON_DATABASE_PATH")

    results_dir = (
        Path(results_value).expanduser()
        if results_value
        else PROJECT_ROOT / "results"
    )

    database_path = (
        Path(database_value).expanduser()
        if database_value
        else results_dir / "subrecon.db"
    )

    log_level = os.getenv("SUBRECON_LOG_LEVEL", "INFO").upper()

    if log_level not in VALID_LOG_LEVELS:
        raise ValueError(
            f"Invalid log level: {log_level}. "
            f"Choose from: {', '.join(sorted(VALID_LOG_LEVELS))}"
        )

    return AppConfig(
        project_root=PROJECT_ROOT,
        results_dir=results_dir,
        database_path=database_path,
        log_level=log_level,
    )
