"""Reporter JSON."""

from __future__ import annotations

from infraaudit.models import AuditReport
from infraaudit.reporting.base import BaseReporter
from infraaudit.security import redact


class JsonReporter(BaseReporter):
    format_name = "json"

    def render(self, report: AuditReport) -> str:
        report = AuditReport.model_validate(redact(report.model_dump()))
        payload = report.model_dump(mode="json")
        payload["summary"] = report.summary()
        import json

        return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
