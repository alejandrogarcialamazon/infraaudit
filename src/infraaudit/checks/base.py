"""Contrato base para checks extensibles."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from infraaudit.config import HostConfig, Inventory, Thresholds
from infraaudit.models import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    Finding,
    FindingKind,
    Severity,
)
from infraaudit.security import redact, secret_scope
from infraaudit.ssh import CommandResult, SSHClient

logger = logging.getLogger(__name__)


class CheckNotEvaluableError(Exception):
    """No hay evidencia suficiente para emitir un diagnóstico."""

    def __init__(
        self,
        reason: str,
        evidence: dict[str, Any] | None = None,
        findings: list[Finding] | None = None,
    ) -> None:
        super().__init__(reason)
        self.evidence = evidence or {}
        self.findings = findings or []


class CheckContext:
    """Contexto inmutable pasado a cada check durante la ejecución."""

    def __init__(
        self,
        inventory: Inventory,
        host: HostConfig | None = None,
        ssh: SSHClient | None = None,
        target: str = "",
        extras: dict[str, Any] | None = None,
    ) -> None:
        self.inventory = inventory
        self.host = host
        self.ssh = ssh
        self.target = target
        self.extras = extras or {}

    def command(self, command: str, *, allow_empty: bool = False) -> CommandResult:
        if self.ssh is None:
            raise CheckNotEvaluableError("No hay sesión SSH disponible")
        result = self.ssh.run(command)
        if not result.ok or (not allow_empty and not result.output):
            raise CheckNotEvaluableError(
                "Comando sin evidencia válida: " + command,
                {
                    "command": command,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "stderr": result.stderr,
                },
            )
        return result

    @property
    def thresholds(self) -> Thresholds:
        return self.inventory.thresholds


class BaseCheck(ABC):
    """Clase base para todos los checks de InfraAudit.

    Los checks deben ser estrictamente read-only: solo lectura de estado,
    sin modificar configuración, archivos ni procesos remotos.
    """

    check_id: str = "base"
    category: CheckCategory = CheckCategory.LINUX
    description: str = ""
    requires_ssh: bool = True
    requires_docker: bool = False
    finding_kind: FindingKind = FindingKind.OPERATIONAL

    def run(self, ctx: CheckContext) -> CheckResult:
        with secret_scope(ctx.inventory.secret_values()):
            return CheckResult.model_validate(redact(self._run(ctx).model_dump()))

    def _run(self, ctx: CheckContext) -> CheckResult:
        """Ejecuta el check con medición de duración y captura de errores."""
        target = ctx.target or (ctx.host.id if ctx.host else "unknown")
        started = time.perf_counter()
        try:
            findings = self.execute(ctx)
            if not findings:
                raise CheckNotEvaluableError("El check no produjo evidencia ni hallazgos")
            duration_ms = (time.perf_counter() - started) * 1000
            return CheckResult(
                check_id=self.check_id,
                category=self.category,
                target=target,
                status=CheckStatus.COMPLETED,
                success=True,
                findings=findings,
                duration_ms=round(duration_ms, 2),
            )
        except CheckNotEvaluableError as exc:
            return CheckResult(
                check_id=self.check_id,
                category=self.category,
                target=target,
                status=CheckStatus.NOT_EVALUATED,
                reason=str(exc),
                diagnostic_evidence=exc.evidence,
                findings=exc.findings,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.error("Check %s falló en %s (%s)", self.check_id, target, type(exc).__name__)
            return CheckResult(
                check_id=self.check_id,
                category=self.category,
                target=target,
                success=False,
                status=CheckStatus.ERROR,
                reason=str(exc),
                diagnostic_evidence={"exception_type": type(exc).__name__},
                error=str(exc),
                duration_ms=round(duration_ms, 2),
            )

    @abstractmethod
    def execute(self, ctx: CheckContext) -> list[Finding]:
        """Lógica específica del check. Debe retornar una lista de Findings."""

    def finding(
        self,
        *,
        severity: Severity,
        target: str,
        message: str,
        recommendation: str = "",
        evidence: dict[str, Any] | None = None,
        kind: FindingKind | None = None,
    ) -> Finding:
        return Finding(
            severity=severity,
            kind=kind or self.finding_kind,
            check=self.check_id,
            target=target,
            message=message,
            recommendation=recommendation,
            evidence=evidence or {},
            category=self.category,
        )
