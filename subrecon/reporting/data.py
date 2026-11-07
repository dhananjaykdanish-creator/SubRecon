"""Build standardized reports from stored reconnaissance data."""

from sqlite3 import Connection

from subrecon.core.models import utc_now
from subrecon.storage.repositories.dns import list_dns_observations
from subrecon.storage.repositories.http import list_http_observations
from subrecon.storage.repositories.scans import (
    get_scan,
    list_discovered_subdomains,
)
from subrecon.storage.repositories.technologies import (
    list_technology_observations,
)
from subrecon.storage.repositories.tool_runs import list_tool_runs


REPORT_SCHEMA_VERSION = "1.0"


def _timestamp(value):
    """Convert an optional datetime into ISO 8601 text."""

    return value.isoformat() if value is not None else None


def build_scan_report(
    connection: Connection,
    scan_id: str,
) -> dict:
    """Build a complete, JSON-compatible report for one scan."""

    scan = get_scan(connection, scan_id)

    if scan is None:
        raise LookupError(f"Scan not found: {scan_id}")

    discoveries = list_discovered_subdomains(
        connection,
        scan_id,
    )

    dns_observations = list_dns_observations(
        connection,
        scan_id,
    )

    http_observations = list_http_observations(
        connection,
        scan_id,
    )

    technologies = list_technology_observations(
        connection,
        scan_id,
    )

    tool_runs = list_tool_runs(
        connection,
        scan_id,
    )

    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": utc_now().isoformat(),

        "scan": {
            "scan_id": scan.scan_id,
            "root_domain": scan.root_domain,
            "status": scan.status.value,
            "started_at": _timestamp(scan.started_at),
            "completed_at": _timestamp(scan.completed_at),
        },

        "summary": {
            "discovered_hostname_count": len(discoveries),
            "dns_observation_count": len(dns_observations),
            "http_observation_count": len(http_observations),
            "technology_observation_count": len(technologies),
            "tool_run_count": len(tool_runs),
            "completed_tool_count": sum(
                run.status.value == "completed"
                for run in tool_runs
            ),
            "failed_tool_count": sum(
                run.status.value == "failed"
                for run in tool_runs
            ),
            "skipped_tool_count": sum(
                run.status.value == "skipped"
                for run in tool_runs
            ),
        },

        "discovered_subdomains": [
            {
                "hostname": item.hostname,
                "sources": list(item.sources),
                "discovered_at": _timestamp(item.discovered_at),
            }
            for item in discoveries
        ],

        "dns_observations": [
            {
                "hostname": item.hostname,
                "record_type": item.record_type,
                "value": item.value,
                "ttl": item.ttl,
                "observed_at": _timestamp(item.observed_at),
            }
            for item in dns_observations
        ],

        "http_observations": [
            {
                "hostname": item.hostname,
                "url": item.url,
                "status_code": item.status_code,
                "final_url": item.final_url,
                "title": item.title,
                "server": item.server,
                "content_type": item.content_type,
                "observed_at": _timestamp(item.observed_at),
            }
            for item in http_observations
        ],

        "technology_observations": [
            {
                "hostname": item.hostname,
                "name": item.name,
                "version": item.version,
                "source": item.source,
                "observed_at": _timestamp(item.observed_at),
            }
            for item in technologies
        ],

        "tool_runs": [
            {
                "tool_name": item.tool_name,
                "status": item.status.value,
                "started_at": _timestamp(item.started_at),
                "finished_at": _timestamp(item.finished_at),
                "exit_code": item.exit_code,
            }
            for item in tool_runs
        ],
    }

    return report
