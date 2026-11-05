"""Modelos de dominio: hallazgos, severidades y resultados de auditoría."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, computed_field, model_validator


class Severity(StrEnum):
    """Niveles de severidad de un hallazgo."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class CheckCategory(StrEnum):
    """Categorías de checks disponibles."""

    LINUX = "linux"
    DOCKER = "docker"
    NETWORK = "network"


class CheckStatus(StrEnum):
    """Estado de ejecución, independiente de la severidad del diagnóstico."""

    COMPLETED = "completed"
    NOT_EVALUATED = "not_evaluated"
    ERROR = "error"
    SKIPPED = "skipped"


class FindingKind(StrEnum):
    SECURITY = "security"
    OPERATIONAL = "operational"
    UNCLASSIFIED = "unclassified"


class Assessment(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


class Finding(BaseModel):
    """Hallazgo individual producido por un check."""

    severity: Severity
    kind: FindingKind = FindingKind.UNCLASSIFIED
    check: str
    target: str
    message: str
    recommendation: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    category: CheckCategory | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]


class CheckResult(BaseModel):
    """Resultado agregado de la ejecución de un check."""

    check_id: str
    category: CheckCategory
    target: str
    success: bool = True
    legacy: bool = False
    status: CheckStatus = CheckStatus.COMPLETED
    reason: str | None = None
    diagnostic_evidence: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0

    @model_validator(mode="before")
    @classmethod
    def load_legacy_status(cls, data: Any) -> Any:
        if isinstance(data, dict) and "status" in data:
            completed = data["status"] == CheckStatus.COMPLETED
            if "success" in data and data["success"] != completed:
                raise ValueError("success contradice el estado de ejecución")
            if completed and data.get("error"):
                raise ValueError("Un resultado completed no puede contener error")
        if isinstance(data, dict) and "status" not in data:
            data = dict(data)
            data["legacy"] = True
            data["status"] = (
                CheckStatus.ERROR
                if data.get("success") is False or data.get("error")
                else CheckStatus.COMPLETED
            )
        return data

    @model_validator(mode="after")
    def normalize_success(self) -> CheckResult:
        self.success = self.status == CheckStatus.COMPLETED
        if not self.success and not self.reason:
            self.reason = self.error or "Sin motivo registrado"
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def assessment(self) -> Assessment:
        if self.status == CheckStatus.SKIPPED:
            return Assessment.SKIPPED
        if self.status != CheckStatus.COMPLETED:
            return Assessment.INCONCLUSIVE
        if self.legacy or any(f.kind == FindingKind.UNCLASSIFIED for f in self.findings):
            return Assessment.UNKNOWN
        if any(f.severity != Severity.INFO for f in self.findings):
            return Assessment.FAILED
        return Assessment.PASSED

    @computed_field  # type: ignore[prop-decorator]
    @property
    def security_failed(self) -> bool:
        return any(
            f.kind == FindingKind.SECURITY and f.severity != Severity.INFO for f in self.findings
        )


class HostResult(BaseModel):
    """Resultados de todos los checks ejecutados contra un host."""

    host_id: str
    hostname: str
    address: str
    check_results: list[CheckResult] = Field(default_factory=list)
    connection_error: str | None = None

    @property
    def findings(self) -> list[Finding]:
        items: list[Finding] = []
        for result in self.check_results:
            items.extend(result.findings)
        return items


class AuditReport(BaseModel):
    """Informe completo de una corrida de InfraAudit."""

    schema_version: str = "2.1"
    inventory_path: str
    started_at: datetime
    finished_at: datetime | None = None
    host_results: list[HostResult] = Field(default_factory=list)
    network_results: list[CheckResult] = Field(default_factory=list)
    tool_version: str = "1.0.0"
    categories: list[CheckCategory] = Field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        items: list[Finding] = []
        for host in self.host_results:
            items.extend(host.findings)
        for result in self.network_results:
            items.extend(result.findings)
        return items

    def findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.all_findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def all_results(self) -> list[CheckResult]:
        return [r for h in self.host_results for r in h.check_results] + self.network_results

    def summary(self) -> dict[str, Any]:
        statuses = {s.value: 0 for s in CheckStatus}
        for result in self.all_results:
            statuses[result.status.value] += 1
        planned = len(self.all_results)
        selected = planned - statuses[CheckStatus.SKIPPED.value]
        completed = statuses[CheckStatus.COMPLETED.value]
        connection_errors = sum(h.connection_error is not None for h in self.host_results)
        complete = (
            selected > 0
            and completed == selected
            and connection_errors == 0
            and self.finished_at is not None
        )
        assessments = {a.value: 0 for a in Assessment}
        for result in self.all_results:
            assessments[result.assessment.value] += 1
        security_findings = [
            f
            for f in self.all_findings
            if f.kind == FindingKind.SECURITY and f.severity != Severity.INFO
        ]
        return {
            "by_assessment": assessments,
            "security_failed_checks": sum(r.security_failed for r in self.all_results),
            "security_findings": len(security_findings),
            "inconclusive_checks": assessments[Assessment.INCONCLUSIVE.value],
            "planned_checks": planned,
            "selected_checks": selected,
            "completed_checks": completed,
            "by_status": statuses,
            "coverage_percent": round(100 * completed / selected, 2) if selected else 0.0,
            "complete": complete,
            "hosts": len(self.host_results),
            "network_checks": len(self.network_results),
            "total_findings": len(self.all_findings),
            "by_severity": self.findings_by_severity(),
            "connection_errors": sum(
                1 for h in self.host_results if h.connection_error is not None
            ),
        }
