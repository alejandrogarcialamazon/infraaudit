"""Generadores de informes."""

from __future__ import annotations

from pathlib import Path

from infraaudit.models import AuditReport
from infraaudit.reporting.base import BaseReporter
from infraaudit.reporting.html_report import HtmlReporter
from infraaudit.reporting.json_report import JsonReporter
from infraaudit.reporting.markdown_report import MarkdownReporter

REPORTERS: dict[str, type[BaseReporter]] = {
    "json": JsonReporter,
    "markdown": MarkdownReporter,
    "md": MarkdownReporter,
    "html": HtmlReporter,
}


def get_reporter(fmt: str) -> BaseReporter:
    key = fmt.lower().strip()
    if key not in REPORTERS:
        supported = ", ".join(sorted(set(REPORTERS)))
        raise ValueError(f"Formato no soportado: {fmt}. Use: {supported}")
    return REPORTERS[key]()


def write_report(report: AuditReport, path: Path | str, fmt: str) -> Path:
    reporter = get_reporter(fmt)
    return reporter.write(report, path)


__all__ = [
    "BaseReporter",
    "HtmlReporter",
    "JsonReporter",
    "MarkdownReporter",
    "get_reporter",
    "write_report",
]
