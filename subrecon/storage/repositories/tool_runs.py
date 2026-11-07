"""Database operations for external tool execution records."""

import sqlite3
from datetime import datetime

from subrecon.core.models import ToolRun, ToolRunStatus
from subrecon.storage.repositories.scans import get_scan


def _validate_tool_run(run: ToolRun) -> None:
    """Validate tool execution information."""

    if not isinstance(run.tool_name, str) or not run.tool_name.strip():
        raise ValueError("Tool name cannot be empty.")

    if not isinstance(run.status, ToolRunStatus):
        raise ValueError("Invalid tool run status.")

    if run.exit_code is not None:
        if isinstance(run.exit_code, bool) or not isinstance(run.exit_code, int):
            raise ValueError("Tool exit code must be an integer.")

    if run.error_message is not None:
        if not isinstance(run.error_message, str):
            raise ValueError("Tool error message must be text.")


def add_tool_run(
    connection: sqlite3.Connection,
    scan_id: str,
    run: ToolRun,
) -> int:
    """Store a new external tool execution record."""

    if get_scan(connection, scan_id) is None:
        raise LookupError(f"Scan not found: {scan_id}")

    _validate_tool_run(run)

    cursor = connection.execute(
        """
        INSERT INTO tool_runs (
            scan_id,
            tool_name,
            status,
            started_at,
            finished_at,
            exit_code,
            error_message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            run.tool_name.strip(),
            run.status.value,
            run.started_at.isoformat(),
            (
                run.finished_at.isoformat()
                if run.finished_at
                else None
            ),
            run.exit_code,
            run.error_message,
        ),
    )

    return cursor.lastrowid


def update_tool_run(
    connection: sqlite3.Connection,
    run_id: int,
    *,
    status: ToolRunStatus,
    finished_at: datetime | None = None,
    exit_code: int | None = None,
    error_message: str | None = None,
) -> None:
    """Update the outcome of an existing tool execution."""

    if not isinstance(status, ToolRunStatus):
        raise ValueError("Invalid tool run status.")

    if exit_code is not None:
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise ValueError("Tool exit code must be an integer.")

    if error_message is not None and not isinstance(error_message, str):
        raise ValueError("Tool error message must be text.")

    existing = connection.execute(
        "SELECT id FROM tool_runs WHERE id = ?",
        (run_id,),
    ).fetchone()

    if existing is None:
        raise LookupError(f"Tool run not found: {run_id}")

    connection.execute(
        """
        UPDATE tool_runs
        SET status = ?,
            finished_at = ?,
            exit_code = ?,
            error_message = ?
        WHERE id = ?
        """,
        (
            status.value,
            finished_at.isoformat() if finished_at else None,
            exit_code,
            error_message,
            run_id,
        ),
    )


def list_tool_runs(
    connection: sqlite3.Connection,
    scan_id: str,
) -> list[ToolRun]:
    """Retrieve external tool execution records for a scan."""

    if get_scan(connection, scan_id) is None:
        raise LookupError(f"Scan not found: {scan_id}")

    rows = connection.execute(
        """
        SELECT *
        FROM tool_runs
        WHERE scan_id = ?
        ORDER BY started_at, id
        """,
        (scan_id,),
    ).fetchall()

    return [
        ToolRun(
            tool_name=row["tool_name"],
            status=ToolRunStatus(row["status"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=(
                datetime.fromisoformat(row["finished_at"])
                if row["finished_at"]
                else None
            ),
            exit_code=row["exit_code"],
            error_message=row["error_message"],
        )
        for row in rows
    ]
