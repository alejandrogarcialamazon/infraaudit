"""Reporter Markdown."""

from __future__ import annotations

from infraaudit.models import AuditReport, Severity
from infraaudit.reporting.base import BaseReporter

_SEV_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class MarkdownReporter(BaseReporter):
    format_name = "markdown"

    def render(self, report: AuditReport) -> str:
        summary = report.summary()
        lines: list[str] = [
            "# InfraAudit Report",
            "",
            f"- **Inventory**: `{report.inventory_path}`",
            f"- **Started**: {report.started_at.isoformat()}",
            f"- **Finished**: {report.finished_at.isoformat() if report.finished_at else 'N/A'}",
            f"- **Version**: {report.tool_version}",
            f"- **Categories**: {', '.join(c.value for c in report.categories)}",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "| --- | --- |",
            f"| Hosts | {summary['hosts']} |",
            f"| Network checks | {summary['network_checks']} |",
            f"| Total findings | {summary['total_findings']} |",
            f"| Connection errors | {summary['connection_errors']} |",
            "",
            "### Findings by severity",
            "",
            "| Severity | Count |",
            "| --- | ---: |",
        ]
        for sev in _SEV_ORDER:
            lines.append(f"| {sev.value} | {summary['by_severity'].get(sev.value, 0)} |")

        lines.extend(["", "## Hosts", ""])
        for host in report.host_results:
            lines.append(f"### {host.host_id} (`{host.address}`)")
            lines.append("")
            if host.connection_error:
                lines.append(f"> **Connection error**: {host.connection_error}")
                lines.append("")
                continue
            findings = sorted(host.findings, key=lambda f: f.severity_rank(), reverse=True)
            if not findings:
                lines.append("_Sin hallazgos._")
                lines.append("")
                continue
            lines.append("| Severity | Check | Target | Message | Recommendation |")
            lines.append("| --- | --- | --- | --- | --- |")
            for f in findings:
                msg = f.message.replace("|", "\\|")
                rec = f.recommendation.replace("|", "\\|")
                lines.append(f"| {f.severity.value} | `{f.check}` | `{f.target}` | {msg} | {rec} |")
            lines.append("")

        if report.network_results:
            lines.extend(["## Network", ""])
            lines.append("| Severity | Check | Target | Message | Recommendation |")
            lines.append("| --- | --- | --- | --- | --- |")
            for result in report.network_results:
                for f in result.findings:
                    msg = f.message.replace("|", "\\|")
                    rec = f.recommendation.replace("|", "\\|")
                    lines.append(
                        f"| {f.severity.value} | `{f.check}` | `{f.target}` | {msg} | {rec} |"
                    )
            lines.append("")

        return "\n".join(lines) + "\n"
