"""Tests de reporters."""

from __future__ import annotations

import json
from pathlib import Path

from infraaudit.reporting import get_reporter, write_report


def test_json_reporter(sample_report, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    path = write_report(sample_report, tmp_path / "out.json", "json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["summary"]["total_findings"] == 2
    assert "host_results" in data


def test_markdown_reporter(sample_report) -> None:  # type: ignore[no-untyped-def]
    md = get_reporter("markdown").render(sample_report)
    assert "# InfraAudit Report" in md
    assert "linux.memory" in md


def test_html_reporter(sample_report) -> None:  # type: ignore[no-untyped-def]
    html = get_reporter("html").render(sample_report)
    assert "<!DOCTYPE html>" in html
    assert "InfraAudit Report" in html
    assert "HIGH" in html
