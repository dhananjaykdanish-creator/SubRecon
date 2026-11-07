"""Export reconnaissance reports as safe, standalone HTML."""

from html import escape
from pathlib import Path
from typing import Any


def _section(report: dict[str, Any], name: str) -> list[dict]:
    """Validate and retrieve a report section."""

    value = report.get(name, [])

    if not isinstance(value, list):
        raise ValueError(f"Report section '{name}' must be a list.")

    if not all(isinstance(item, dict) for item in value):
        raise ValueError(f"Invalid entries in report section '{name}'.")

    return value


def _display(value: Any) -> str:
    """Convert a report value to readable text."""

    if value is None:
        return "-"

    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "-"

    if isinstance(value, bool):
        return str(value)

    return str(value)


def _cell(value: Any) -> str:
    """Return an HTML-escaped table cell."""

    return f"<td>{escape(_display(value), quote=True)}</td>"


def _table(
    title: str,
    headers: tuple[str, ...],
    rows: list[tuple[Any, ...]],
) -> str:
    """Render an HTML table using escaped values."""

    safe_headers = "".join(
        f"<th>{escape(header)}</th>"
        for header in headers
    )

    if rows:
        body = "".join(
            "<tr>" + "".join(_cell(value) for value in row) + "</tr>"
            for row in rows
        )
    else:
        body = (
            f'<tr><td class="empty" colspan="{len(headers)}">'
            "No records available."
            "</td></tr>"
        )

    return f"""
    <section class="panel">
      <h2>{escape(title)}</h2>
      <div class="table-wrap">
        <table>
          <thead><tr>{safe_headers}</tr></thead>
          <tbody>{body}</tbody>
        </table>
      </div>
    </section>
    """


def format_report_html(report: dict[str, Any]) -> str:
    """Convert standardized report data into standalone HTML."""

    if not isinstance(report, dict):
        raise TypeError("Report must be a dictionary.")

    scan = report.get("scan", {})
    summary = report.get("summary", {})

    if not isinstance(scan, dict) or not isinstance(summary, dict):
        raise ValueError("Invalid scan or summary section.")

    discoveries = _section(report, "discovered_subdomains")
    dns_records = _section(report, "dns_observations")
    http_records = _section(report, "http_observations")
    technologies = _section(report, "technology_observations")
    tool_runs = _section(report, "tool_runs")

    scan_rows = [
        ("Scan ID", scan.get("scan_id")),
        ("Root domain", scan.get("root_domain")),
        ("Status", scan.get("status")),
        ("Started", scan.get("started_at")),
        ("Completed", scan.get("completed_at")),
        ("Generated", report.get("generated_at")),
    ]

    summary_cards = "".join(
        f"""
        <div class="metric">
          <span>{escape(str(key).replace("_", " ").title())}</span>
          <strong>{escape(_display(value))}</strong>
        </div>
        """
        for key, value in summary.items()
    )

    sections = [
        _table(
            "Scan Information",
            ("Property", "Value"),
            scan_rows,
        ),
        f"""
        <section class="panel">
          <h2>Summary</h2>
          <div class="metrics">{summary_cards}</div>
        </section>
        """,
        _table(
            "Discovered Subdomains",
            ("Hostname", "Sources", "Discovered"),
            [
                (
                    item.get("hostname"),
                    item.get("sources", []),
                    item.get("discovered_at"),
                )
                for item in discoveries
            ],
        ),
        _table(
            "DNS Observations",
            ("Hostname", "Record Type", "Value", "TTL", "Observed"),
            [
                (
                    item.get("hostname"),
                    item.get("record_type"),
                    item.get("value"),
                    item.get("ttl"),
                    item.get("observed_at"),
                )
                for item in dns_records
            ],
        ),
        _table(
            "HTTP Observations",
            (
                "Hostname",
                "URL",
                "Status",
                "Final URL",
                "Title",
                "Server",
                "Content Type",
            ),
            [
                (
                    item.get("hostname"),
                    item.get("url"),
                    item.get("status_code"),
                    item.get("final_url"),
                    item.get("title"),
                    item.get("server"),
                    item.get("content_type"),
                )
                for item in http_records
            ],
        ),
        _table(
            "Technology Observations",
            ("Hostname", "Technology", "Version", "Source"),
            [
                (
                    item.get("hostname"),
                    item.get("name"),
                    item.get("version"),
                    item.get("source"),
                )
                for item in technologies
            ],
        ),
        _table(
            "Tool Execution History",
            (
                "Tool",
                "Status",
                "Started",
                "Finished",
                "Exit Code",
            ),
            [
                (
                    item.get("tool_name"),
                    item.get("status"),
                    item.get("started_at"),
                    item.get("finished_at"),
                    item.get("exit_code"),
                )
                for item in tool_runs
            ],
        ),
    ]

    content = "\n".join(sections)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="SubRecon reconnaissance report">
  <title>SubRecon - Reconnaissance Report</title>
  <style>
    :root {{
      color-scheme: dark;
      font-family: system-ui, -apple-system, sans-serif;
      background: #10151f;
      color: #e8edf5;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 32px 18px;
      line-height: 1.6;
    }}
    main {{
      max-width: 1200px;
      margin: auto;
    }}
    header {{
      padding: 28px;
      margin-bottom: 24px;
      border: 1px solid #29374b;
      border-radius: 14px;
      background: #182335;
    }}
    h1 {{ margin: 0; font-size: 28px; }}
    h2 {{ font-size: 19px; margin-top: 0; }}
    .subtitle {{ color: #aab7ca; margin-bottom: 0; }}
    .panel {{
      padding: 22px;
      margin-bottom: 22px;
      border: 1px solid #29374b;
      border-radius: 12px;
      background: #182335;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
    }}
    .metric {{
      padding: 16px;
      border: 1px solid #34445b;
      border-radius: 9px;
      background: #202e42;
    }}
    .metric span {{
      display: block;
      color: #aab7ca;
      font-size: 13px;
    }}
    .metric strong {{
      display: block;
      font-size: 24px;
      overflow-wrap: anywhere;
    }}
    .table-wrap {{ overflow-x: auto; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      text-align: left;
      padding: 11px;
      border-bottom: 1px solid #34445b;
      overflow-wrap: anywhere;
    }}
    th {{
      color: #9ec5ff;
      background: #202e42;
    }}
    tr:last-child td {{ border-bottom: none; }}
    .empty {{
      text-align: center;
      color: #aab7ca;
      padding: 22px;
    }}
    footer {{
      text-align: center;
      color: #8998ad;
      padding: 18px;
      font-size: 12px;
    }}
    @media print {{
      :root {{ color-scheme: light; background: white; color: black; }}
      body {{ padding: 0; }}
      .panel, header {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>SubRecon</h1>
      <p class="subtitle">Reconnaissance Report</p>
    </header>
    {content}
    <footer>Generated by SubRecon</footer>
  </main>
</body>
</html>
"""


def export_html(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Write a standalone HTML reconnaissance report."""

    content = format_report_html(report)
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
