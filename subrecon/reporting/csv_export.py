"""Export reconnaissance reports as structured CSV."""

import csv

from pathlib import Path
from typing import Any


CSV_FIELDS = (
    "record_type",
    "scan_id",
    "root_domain",
    "scan_status",
    "scan_started_at",
    "scan_completed_at",
    "metric",
    "count",
    "hostname",
    "discovery_sources",
    "dns_record_type",
    "value",
    "ttl",
    "url",
    "status_code",
    "final_url",
    "title",
    "server",
    "content_type",
    "technology",
    "technology_version",
    "technology_source",
    "observed_at",
    "tool_name",
    "tool_status",
    "tool_started_at",
    "tool_finished_at",
    "exit_code",
)


def _get_list(report: dict[str, Any], key: str) -> list:
    """Retrieve and validate a report section."""

    value = report.get(key, [])

    if not isinstance(value, list):
        raise ValueError(f"Report section '{key}' must be a list.")

    if not all(isinstance(item, dict) for item in value):
        raise ValueError(f"Report section '{key}' contains invalid entries.")

    return value


def export_csv(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Export a standardized report into a single CSV file."""

    if not isinstance(report, dict):
        raise TypeError("Report must be a dictionary.")

    scan = report.get("scan", {})
    summary = report.get("summary", {})

    if not isinstance(scan, dict) or not isinstance(summary, dict):
        raise ValueError("Invalid scan or summary section.")

    discoveries = _get_list(report, "discovered_subdomains")
    dns_records = _get_list(report, "dns_observations")
    http_records = _get_list(report, "http_observations")
    technologies = _get_list(report, "technology_observations")
    tool_runs = _get_list(report, "tool_runs")

    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    # Scan metadata.
    rows.append({
        "record_type": "scan",
        "scan_id": scan.get("scan_id"),
        "root_domain": scan.get("root_domain"),
        "scan_status": scan.get("status"),
        "scan_started_at": scan.get("started_at"),
        "scan_completed_at": scan.get("completed_at"),
    })

    # Summary metrics.
    for metric, count in summary.items():
        rows.append({
            "record_type": "summary",
            "scan_id": scan.get("scan_id"),
            "metric": metric,
            "count": count,
        })

    # Discovered hostnames.
    for item in discoveries:
        rows.append({
            "record_type": "subdomain",
            "scan_id": scan.get("scan_id"),
            "hostname": item.get("hostname"),
            "discovery_sources": ", ".join(
                item.get("sources", [])
            ),
            "observed_at": item.get("discovered_at"),
        })

    # DNS observations.
    for item in dns_records:
        rows.append({
            "record_type": "dns",
            "scan_id": scan.get("scan_id"),
            "hostname": item.get("hostname"),
            "dns_record_type": item.get("record_type"),
            "value": item.get("value"),
            "ttl": item.get("ttl"),
            "observed_at": item.get("observed_at"),
        })

    # HTTP observations.
    for item in http_records:
        rows.append({
            "record_type": "http",
            "scan_id": scan.get("scan_id"),
            "hostname": item.get("hostname"),
            "url": item.get("url"),
            "status_code": item.get("status_code"),
            "final_url": item.get("final_url"),
            "title": item.get("title"),
            "server": item.get("server"),
            "content_type": item.get("content_type"),
            "observed_at": item.get("observed_at"),
        })

    # Technology observations.
    for item in technologies:
        rows.append({
            "record_type": "technology",
            "scan_id": scan.get("scan_id"),
            "hostname": item.get("hostname"),
            "technology": item.get("name"),
            "technology_version": item.get("version"),
            "technology_source": item.get("source"),
            "observed_at": item.get("observed_at"),
        })

    # External tool execution history.
    for item in tool_runs:
        rows.append({
            "record_type": "tool_run",
            "scan_id": scan.get("scan_id"),
            "tool_name": item.get("tool_name"),
            "tool_status": item.get("status"),
            "tool_started_at": item.get("started_at"),
            "tool_finished_at": item.get("finished_at"),
            "exit_code": item.get("exit_code"),
        })

    with destination.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=CSV_FIELDS,
            extrasaction="raise",
        )

        writer.writeheader()
        writer.writerows(rows)

    return destination
