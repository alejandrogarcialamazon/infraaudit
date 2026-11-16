"""Contrato de salida para automatización."""

from __future__ import annotations

from infraaudit.models import SEVERITY_ORDER, AuditReport, Severity


def exit_code(report: AuditReport, fail_on: str = "critical", incomplete: str = "fail") -> int:
    if incomplete not in {"fail", "allow"}:
        raise ValueError("incomplete debe ser fail o allow")
    threshold = Severity(fail_on.upper()) if fail_on != "none" else None
    if report.cancelled:
        return 130
    if not report.summary()["complete"] and incomplete == "fail":
        return 1
    if threshold is not None and any(
        f.severity_rank() >= SEVERITY_ORDER[threshold] for f in report.all_findings
    ):
        return 2
    return 0
