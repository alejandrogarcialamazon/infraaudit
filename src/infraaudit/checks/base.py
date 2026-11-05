"""Contrato base para checks extensibles."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from infraaudit.config import HostConfig, Inventory, Thresholds
from infraaudit.models import CheckCategory, CheckResult, Finding, Severity
from infraaudit.ssh import SSHClient

logger = logging.getLogger(__name__)


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

    def run(self, ctx: CheckContext) -> CheckResult:
        """Ejecuta el check con medición de duración y captura de errores."""
        target = ctx.target or (ctx.host.id if ctx.host else "unknown")
        started = time.perf_counter()
        try:
            findings = self.execute(ctx)
            duration_ms = (time.perf_counter() - started) * 1000
            return CheckResult(
                check_id=self.check_id,
                category=self.category,
                target=target,
                success=True,
                findings=findings,
                duration_ms=round(duration_ms, 2),
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.exception("Check %s falló en %s", self.check_id, target)
            return CheckResult(
                check_id=self.check_id,
                category=self.category,
                target=target,
                success=False,
                findings=[
                    Finding(
                        severity=Severity.HIGH,
                        check=self.check_id,
                        target=target,
                        message=f"Error ejecutando check: {exc}",
                        recommendation="Revisar conectividad, permisos y dependencias del check",
                        evidence={"error": str(exc)},
                        category=self.category,
                    )
                ],
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
    ) -> Finding:
        return Finding(
            severity=severity,
            check=self.check_id,
            target=target,
            message=message,
            recommendation=recommendation,
            evidence=evidence or {},
            category=self.category,
        )
