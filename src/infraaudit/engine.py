"""Motor de ejecución de auditorías."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from infraaudit import __version__
from infraaudit.checks.base import CheckContext
from infraaudit.checks.registry import CheckRegistry, build_default_registry
from infraaudit.config import Inventory, load_inventory
from infraaudit.models import AuditReport, CheckCategory, CheckResult, HostResult
from infraaudit.ssh import SSHClient, SSHError

logger = logging.getLogger(__name__)


class AuditEngine:
    """Orquesta checks Linux/Docker por host y checks de red locales."""

    def __init__(
        self,
        inventory: Inventory,
        registry: CheckRegistry | None = None,
        categories: list[CheckCategory] | None = None,
    ) -> None:
        self.inventory = inventory
        self.registry = registry or build_default_registry()
        self.categories = categories or [
            CheckCategory.LINUX,
            CheckCategory.DOCKER,
            CheckCategory.NETWORK,
        ]

    @classmethod
    def from_path(
        cls,
        path: Path | str,
        only: list[str] | None = None,
    ) -> AuditEngine:
        inventory = load_inventory(path)
        categories: list[CheckCategory] | None = None
        if only:
            categories = [CheckCategory(item) for item in only]
        return cls(inventory=inventory, categories=categories)

    def run(self, inventory_path: str = "") -> AuditReport:
        report = AuditReport(
            inventory_path=inventory_path,
            started_at=datetime.now(UTC),
            categories=list(self.categories),
            tool_version=__version__,
        )

        if CheckCategory.LINUX in self.categories or CheckCategory.DOCKER in self.categories:
            for host in self.inventory.hosts:
                report.host_results.append(self._run_host(host.id))

        if CheckCategory.NETWORK in self.categories:
            report.network_results.extend(self._run_network_checks())

        report.finished_at = datetime.now(UTC)
        return report

    def _run_host(self, host_id: str) -> HostResult:
        host = next(h for h in self.inventory.hosts if h.id == host_id)
        host_result = HostResult(
            host_id=host.id,
            hostname=host.id,
            address=host.address,
        )

        categories = [
            c for c in self.categories if c in {CheckCategory.LINUX, CheckCategory.DOCKER}
        ]
        if CheckCategory.DOCKER in categories and not host.docker:
            categories = [c for c in categories if c != CheckCategory.DOCKER]

        checks = self.registry.filter(
            categories=categories,
            skip=host.skip_checks,
        )
        # Filtrar docker checks si el host no tiene docker habilitado
        checks = [c for c in checks if not (c.requires_docker and not host.docker)]
        if not checks:
            return host_result

        try:
            with SSHClient(host) as ssh:
                for check in checks:
                    if not check.requires_ssh:
                        continue
                    ctx = CheckContext(
                        inventory=self.inventory,
                        host=host,
                        ssh=ssh,
                        target=host.id,
                    )
                    logger.info("Ejecutando %s en %s", check.check_id, host.id)
                    host_result.check_results.append(check.run(ctx))
        except SSHError as exc:
            logger.error("Conexión fallida a %s: %s", host.id, exc)
            host_result.connection_error = str(exc)

        return host_result

    def _run_network_checks(self) -> list[CheckResult]:
        results: list[CheckResult] = []
        dns_check = self.registry.get("network.dns")
        tcp_check = self.registry.get("network.tcp")
        http_check = self.registry.get("network.http")

        for record in self.inventory.dns_records:
            ctx = CheckContext(
                inventory=self.inventory,
                target=record.id,
                extras={"dns_record": record},
            )
            results.append(dns_check.run(ctx))

        for tcp_service in self.inventory.tcp_services:
            ctx = CheckContext(
                inventory=self.inventory,
                target=tcp_service.id,
                extras={"tcp_service": tcp_service},
            )
            results.append(tcp_check.run(ctx))

        for http_service in self.inventory.http_services:
            ctx = CheckContext(
                inventory=self.inventory,
                target=http_service.id,
                extras={"http_service": http_service},
            )
            results.append(http_check.run(ctx))

        return results
