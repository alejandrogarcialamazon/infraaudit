"""Tests de modelos Finding y AuditReport."""

from __future__ import annotations

from infraaudit.models import Finding, Severity


def test_finding_severity_rank() -> None:
    low = Finding(
        severity=Severity.LOW,
        check="t",
        target="x",
        message="m",
    )
    critical = Finding(
        severity=Severity.CRITICAL,
        check="t",
        target="x",
        message="m",
    )
    assert critical.severity_rank() > low.severity_rank()


def test_report_summary(sample_report) -> None:  # type: ignore[no-untyped-def]
    summary = sample_report.summary()
    assert summary["hosts"] == 1
    assert summary["total_findings"] == 2
    assert summary["by_severity"]["HIGH"] == 1
    assert summary["by_severity"]["INFO"] == 1
