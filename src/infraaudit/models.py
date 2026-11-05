"""Modelos de dominio: hallazgos, severidades y resultados de auditoría."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


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


class Finding(BaseModel):
    """Hallazgo individual producido por un check."""

    severity: Severity
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
    success: bool
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0


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

    def summary(self) -> dict[str, Any]:
        return {
            "hosts": len(self.host_results),
            "network_checks": len(self.network_results),
            "total_findings": len(self.all_findings),
            "by_severity": self.findings_by_severity(),
            "connection_errors": sum(
                1 for h in self.host_results if h.connection_error is not None
            ),
        }
