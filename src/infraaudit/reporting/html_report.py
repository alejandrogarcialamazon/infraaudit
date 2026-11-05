"""Reporter HTML autocontenido."""

from __future__ import annotations

import html
from typing import Any

from infraaudit.models import AuditReport, Finding, Severity
from infraaudit.reporting.base import BaseReporter

_COLORS = {
    Severity.CRITICAL: "#7f1d1d",
    Severity.HIGH: "#b91c1c",
    Severity.MEDIUM: "#c2410c",
    Severity.LOW: "#a16207",
    Severity.INFO: "#1d4ed8",
}


def _esc(value: Any) -> str:
    return html.escape(str(value))


class HtmlReporter(BaseReporter):
    format_name = "html"

    def render(self, report: AuditReport) -> str:
        summary = report.summary()
        severity_cards = "".join(
            f'<div class="card" style="border-color:{_COLORS[Severity(sev)]}">'
            f"<strong>{_esc(sev)}</strong><span>{count}</span></div>"
            for sev, count in summary["by_severity"].items()
        )

        host_sections = []
        for host in report.host_results:
            if host.connection_error:
                body = f'<p class="error">Connection error: {_esc(host.connection_error)}</p>'
            else:
                body = self._findings_table(host.findings)
            host_sections.append(
                f"<section><h3>{_esc(host.host_id)} "
                f"<small>({_esc(host.address)})</small></h3>{body}</section>"
            )

        network_section = ""
        if report.network_results:
            net_findings: list[Finding] = []
            for result in report.network_results:
                net_findings.extend(result.findings)
            network_section = (
                f"<section><h2>Network</h2>{self._findings_table(net_findings)}</section>"
            )

        execution_rows = "".join(
            f"<tr><td>{_esc(r.check_id)}</td><td>{_esc(r.target)}</td>"
            f"<td>{_esc(r.status.value)}</td><td>{_esc(r.reason or '')}</td></tr>"
            for r in report.all_results
        )
        finished = report.finished_at.isoformat() if report.finished_at else "N/A"
        return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>InfraAudit Report</title>
  <style>
    :root {{
      --bg: #0f172a; --panel: #111827; --text: #e5e7eb; --muted: #94a3b8; --line: #1f2937;
    }}
    body {{
      margin: 0; font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, #1e293b, var(--bg));
      color: var(--text); line-height: 1.5;
    }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
    h1,h2,h3 {{ font-family: "IBM Plex Sans", sans-serif; letter-spacing: -0.02em; }}
    h1 {{ font-size: 2rem; margin-bottom: 0.25rem; }}
    .meta {{ color: var(--muted); margin-bottom: 1.5rem; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 0.75rem;
    }}
    .card {{
      background: var(--panel); border: 1px solid var(--line);
      border-left-width: 4px; border-radius: 10px; padding: 0.9rem 1rem;
      display: flex; flex-direction: column; gap: 0.25rem;
    }}
    .card span {{ font-size: 1.4rem; font-weight: 700; }}
    section {{
      background: rgba(17, 24, 39, 0.85); border: 1px solid var(--line);
      border-radius: 12px; padding: 1rem 1.1rem; margin-top: 1.25rem;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
    th, td {{
      text-align: left; padding: 0.55rem 0.45rem;
      border-bottom: 1px solid var(--line); vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 600; }}
    .sev {{
      display: inline-block; padding: 0.1rem 0.45rem; border-radius: 999px;
      font-size: 0.75rem; font-weight: 700; color: white;
    }}
    .error {{ color: #fca5a5; }}
    code {{ background: #0b1220; padding: 0.1rem 0.35rem; border-radius: 4px; }}
  </style>
</head>
<body>
<main>
  <h1>InfraAudit Report</h1>
  <p class="meta">
    Inventory: <code>{_esc(report.inventory_path)}</code><br/>
    Started: {_esc(report.started_at.isoformat())} · Finished: {_esc(finished)} ·
    Version: {_esc(report.tool_version)}
  </p>
  <div class="grid">{severity_cards}</div>
  <section>
    <h2>Overview</h2>
    <p>
      Hosts: <strong>{summary["hosts"]}</strong> ·
      Network checks: <strong>{summary["network_checks"]}</strong> ·
      Findings: <strong>{summary["total_findings"]}</strong> ·
      Connection errors: <strong>{summary["connection_errors"]}</strong>
    </p>
  </section>
  <section>
    <h2>Coverage / cobertura</h2>
    <p>Planned: {summary["planned_checks"]} · Selected: {summary["selected_checks"]} ·
    Completed: {summary["completed_checks"]} · Coverage: {summary["coverage_percent"]}% ·
    Complete: {summary["complete"]}</p>
    <table><thead><tr><th>Check</th><th>Target</th><th>Status</th><th>Reason</th></tr></thead>
    <tbody>{execution_rows}</tbody></table>
  </section>
  <h2>Hosts</h2>
  {"".join(host_sections) or "<p>No hosts audited.</p>"}
  {network_section}
</main>
</body>
</html>
"""

    def _findings_table(self, findings: list[Finding]) -> str:
        if not findings:
            return "<p>Sin hallazgos.</p>"
        rows = []
        ordered = sorted(findings, key=lambda f: f.severity_rank(), reverse=True)
        for f in ordered:
            color = _COLORS[f.severity]
            sev = _esc(f.severity.value)
            rows.append(
                "<tr>"
                f'<td><span class="sev" style="background:{color}">{sev}</span></td>'
                f"<td><code>{_esc(f.check)}</code></td>"
                f"<td><code>{_esc(f.target)}</code></td>"
                f"<td>{_esc(f.message)}</td>"
                f"<td>{_esc(f.recommendation)}</td>"
                "</tr>"
            )
        return (
            "<table><thead><tr>"
            "<th>Severity</th><th>Check</th><th>Target</th><th>Message</th><th>Recommendation</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
