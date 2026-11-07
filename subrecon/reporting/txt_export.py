"""Export reconnaissance reports as readable text."""

from pathlib import Path
from typing import Any


def _section(
    report: dict[str, Any],
    name: str,
) -> list[dict[str, Any]]:
    """Validate and retrieve a report section."""

    value = report.get(name, [])

    if not isinstance(value, list):
        raise ValueError(f"Report section '{name}' must be a list.")

    if not all(isinstance(item, dict) for item in value):
        raise ValueError(f"Invalid entries in report section '{name}'.")

    return value


def _display(value: Any) -> str:
    """Convert a value into readable text."""

    if value is None:
        return "-"

    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "-"

    return str(value)


def format_report_text(report: dict[str, Any]) -> str:
    """Convert a standardized report into readable text."""

    if not isinstance(report, dict):
        raise TypeError("Report must be a dictionary.")

    scan = report.get("scan", {})
    summary = report.get("summary", {})

    if not isinstance(scan, dict):
        raise ValueError("Invalid scan section.")

    if not isinstance(summary, dict):
        raise ValueError("Invalid summary section.")

    discoveries = _section(report, "discovered_subdomains")
    dns_records = _section(report, "dns_observations")
    http_records = _section(report, "http_observations")
    technologies = _section(report, "technology_observations")
    tool_runs = _section(report, "tool_runs")

    lines = [
        "=" * 72,
        "SUBRECON - RECONNAISSANCE REPORT",
        "=" * 72,
        "",
        "SCAN INFORMATION",
        "-" * 72,
        f"Scan ID       : {_display(scan.get('scan_id'))}",
        f"Root Domain   : {_display(scan.get('root_domain'))}",
        f"Status        : {_display(scan.get('status'))}",
        f"Started At    : {_display(scan.get('started_at'))}",
        f"Completed At  : {_display(scan.get('completed_at'))}",
        f"Generated At  : {_display(report.get('generated_at'))}",
        "",
        "SUMMARY",
        "-" * 72,
    ]

    for metric, count in summary.items():
        lines.append(f"{metric.replace('_', ' ').title():36}: {_display(count)}")

    lines.extend([
        "",
        f"DISCOVERED SUBDOMAINS ({len(discoveries)})",
        "-" * 72,
    ])

    if discoveries:
        for index, item in enumerate(discoveries, start=1):
            lines.extend([
                f"{index}. Hostname : {_display(item.get('hostname'))}",
                f"   Sources  : {_display(item.get('sources'))}",
                f"   Discovered: {_display(item.get('discovered_at'))}",
                "",
            ])
    else:
        lines.append("No discovered subdomains recorded.")
        lines.append("")

    lines.extend([
        f"DNS OBSERVATIONS ({len(dns_records)})",
        "-" * 72,
    ])

    if dns_records:
        for index, item in enumerate(dns_records, start=1):
            lines.extend([
                f"{index}. Hostname : {_display(item.get('hostname'))}",
                f"   Type     : {_display(item.get('record_type'))}",
                f"   Value    : {_display(item.get('value'))}",
                f"   TTL      : {_display(item.get('ttl'))}",
                f"   Observed : {_display(item.get('observed_at'))}",
                "",
            ])
    else:
        lines.append("No DNS observations recorded.")
        lines.append("")

    lines.extend([
        f"HTTP OBSERVATIONS ({len(http_records)})",
        "-" * 72,
    ])

    if http_records:
        for index, item in enumerate(http_records, start=1):
            lines.extend([
                f"{index}. Hostname    : {_display(item.get('hostname'))}",
                f"   URL         : {_display(item.get('url'))}",
                f"   Status Code : {_display(item.get('status_code'))}",
                f"   Final URL   : {_display(item.get('final_url'))}",
                f"   Title       : {_display(item.get('title'))}",
                f"   Server      : {_display(item.get('server'))}",
                f"   Content Type: {_display(item.get('content_type'))}",
                f"   Observed    : {_display(item.get('observed_at'))}",
                "",
            ])
    else:
        lines.append("No HTTP observations recorded.")
        lines.append("")

    lines.extend([
        f"TECHNOLOGY OBSERVATIONS ({len(technologies)})",
        "-" * 72,
    ])

    if technologies:
        for index, item in enumerate(technologies, start=1):
            lines.extend([
                f"{index}. Hostname  : {_display(item.get('hostname'))}",
                f"   Technology: {_display(item.get('name'))}",
                f"   Version   : {_display(item.get('version'))}",
                f"   Source    : {_display(item.get('source'))}",
                f"   Observed  : {_display(item.get('observed_at'))}",
                "",
            ])
    else:
        lines.append("No technology observations recorded.")
        lines.append("")

    lines.extend([
        f"TOOL EXECUTION HISTORY ({len(tool_runs)})",
        "-" * 72,
    ])

    if tool_runs:
        for index, item in enumerate(tool_runs, start=1):
            lines.extend([
                f"{index}. Tool       : {_display(item.get('tool_name'))}",
                f"   Status     : {_display(item.get('status'))}",
                f"   Started    : {_display(item.get('started_at'))}",
                f"   Finished   : {_display(item.get('finished_at'))}",
                f"   Exit Code  : {_display(item.get('exit_code'))}",
                "",
            ])
    else:
        lines.append("No tool execution history recorded.")
        lines.append("")

    lines.extend([
        "=" * 72,
        "END OF SUBRECON REPORT",
        "=" * 72,
    ])

    return "\n".join(lines) + "\n"


def export_txt(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Write a readable reconnaissance report as UTF-8 text."""

    content = format_report_text(report)

    destination = Path(output_path).expanduser()

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    destination.write_text(
        content,
        encoding="utf-8",
    )

    return destination
