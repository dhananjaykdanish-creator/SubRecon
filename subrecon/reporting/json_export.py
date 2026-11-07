"""Export reconnaissance reports as JSON."""

import json

from pathlib import Path
from typing import Any


def export_json(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Write a standardized reconnaissance report as JSON."""

    if not isinstance(report, dict):
        raise TypeError("Report must be a dictionary.")

    destination = Path(output_path).expanduser()

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    content = json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
    )

    destination.write_text(
        content + "\n",
        encoding="utf-8",
    )

    return destination
