"""Comparación conservadora de hallazgos, sin resolver checks no evaluados."""

from __future__ import annotations

from typing import Any, cast

from infraaudit.models import AuditReport, CheckStatus, Finding
from infraaudit.security import redact


def compare_reports(before: AuditReport, after: AuditReport) -> dict[str, Any]:
    def index(report: AuditReport) -> tuple[dict[str, Finding], dict[str, tuple[str, str]]]:
        findings: dict[str, Finding] = {}
        sources = {}
        for result in report.all_results:
            for finding in result.findings:
                if finding.finding_id in findings:
                    raise ValueError("El reporte contiene identidades ambiguas; requiere rule_id")
                findings[finding.finding_id] = finding
                sources[finding.finding_id] = (result.check_id, result.target)
        return findings, sources

    old, sources = index(before)
    new, _ = index(after)
    completed = {
        (r.check_id, r.target) for r in after.all_results if r.status == CheckStatus.COMPLETED
    }
    missing = old.keys() - new.keys()
    result = {
        "new": sorted(new.keys() - old.keys()),
        "persistent": sorted(old.keys() & new.keys()),
        "resolved": sorted(key for key in missing if sources[key] in completed),
        "not_comparable": sorted(key for key in missing if sources[key] not in completed),
        "severity_changed": sorted(
            key for key in old.keys() & new.keys() if old[key].severity != new[key].severity
        ),
    }
    return cast(dict[str, Any], redact(result))
