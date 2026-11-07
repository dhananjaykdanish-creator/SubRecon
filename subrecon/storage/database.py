"""SQLite connection and schema initialization."""

import re
import sqlite3
from pathlib import Path


MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def connect_database(
    database_path: str | Path,
) -> sqlite3.Connection:
    """Create a configured SQLite connection."""

    if str(database_path) == ":memory:":
        path = ":memory:"
    else:
        path = Path(database_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        path,
        timeout=10.0,
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA journal_mode = WAL")

    return connection


def initialize_database(database_path: str | Path) -> None:
    """Initialize the database and apply unapplied migrations."""

    connection = connect_database(database_path)

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                )
            )
            """
        )

        applied = {
            row["version"]
            for row in connection.execute(
                "SELECT version FROM schema_migrations"
            )
        }

        migrations = sorted(MIGRATIONS_DIR.glob("*.sql"))

        for migration in migrations:
            version = migration.stem

            if not re.fullmatch(r"\d{3}_[a-z0-9_]+", version):
                raise RuntimeError(
                    f"Invalid migration filename: {migration.name}"
                )

            if version in applied:
                continue

            sql = migration.read_text(encoding="utf-8")

            script = (
                "BEGIN IMMEDIATE;\n"
                f"{sql}\n"
                f"INSERT INTO schema_migrations(version) "
                f"VALUES ('{version}');\n"
                "COMMIT;"
            )

            try:
                connection.executescript(script)
            except sqlite3.Error:
                if connection.in_transaction:
                    connection.rollback()
                raise

    finally:
        connection.close()
