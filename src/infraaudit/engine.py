"""Motor de ejecución de auditorías."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infraaudit import __version__
from infraaudit.checks.base import CheckContext
from infraaudit.checks.registry import CheckRegistry, build_default_registry
from infraaudit.config import Inventory, load_inventory
from infraaudit.models import AuditReport, CheckCategory, CheckResult, CheckStatus, HostResult
from infraaudit.security import redact, secret_scope
from infraaudit.ssh import SSHClient, SSHError

logger = logging.getLogger(__name__)


class AuditEngine:
    """Orquesta checks Linux/Docker por host y checks de red locales."""

    def __init__(
        self,
        inventory: Inventory,
        registry: CheckRegistry | None = None,
        categories: list[CheckCategory] | None = None,
        *,
        host_ids: list[str] | None = None,
        tags: list[str] | None = None,
        check_ids: list[str] | None = None,
        workers: int = 1,
        progress: Callable[[int, int], None] | None = None,
    ) -> None:
        self.inventory = inventory
        self.registry = registry or build_default_registry()
        self.categories = categories or [
            CheckCategory.LINUX,
            CheckCategory.DOCKER,
            CheckCategory.NETWORK,
        ]

        if not 1 <= workers <= 32:
            raise ValueError("workers debe estar entre 1 y 32")
        self.workers = workers
        self.progress = progress
        self.cancel_event = threading.Event()
        self.check_ids = set(check_ids or [])
        if self.check_ids - {c.check_id for c in self.registry.all()}:
            raise ValueError("Identificador de check desconocido")
        requested = set(host_ids or [])
        if requested - {h.id for h in inventory.hosts}:
            raise ValueError("Identificador de host desconocido")
        self.hosts = [
            h
            for h in inventory.hosts
            if (not requested or h.id in requested) and (not tags or set(tags) & set(h.tags))
        ]
        if (requested or tags) and not self.hosts:
            raise ValueError("Filtros sin hosts coincidentes")
        self.host_filter = bool(requested or tags)
        self.requested_hosts = sorted(requested)
        self.requested_tags = list(tags or [])

    @classmethod
    def from_path(
        cls,
        path: Path | str,
        only: list[str] | None = None,
        **options: Any,
    ) -> AuditEngine:
        inventory = load_inventory(path)
        categories: list[CheckCategory] | None = None
        if only:
            categories = [CheckCategory(item) for item in only]
        return cls(inventory=inventory, categories=categories, **options)

    def run(self, inventory_path: str = "") -> AuditReport:
        with secret_scope(self.inventory.secret_values()):
            return AuditReport.model_validate(redact(self._run(inventory_path).model_dump()))

    def _selected(self, check_id: str) -> bool:
        check = self.registry.get(check_id)
        return check.category in self.categories and (
            not self.check_ids or check_id in self.check_ids
        )

    def _network_targets(self) -> list[tuple[str, Any, str]]:
        if self.host_filter or CheckCategory.NETWORK not in self.categories:
            return []
        return [
            (check, item, key)
            for check, items, key in (
                ("network.dns", self.inventory.dns_records, "dns_record"),
                ("network.tcp", self.inventory.tcp_services, "tcp_service"),
                ("network.http", self.inventory.http_services, "http_service"),
            )
            if items and self._selected(check)
            for item in items
        ]

    def plan(self) -> list[dict[str, str]]:
        result = []
        for host in self.hosts:
            for check in self.registry.all():
                if check.category == CheckCategory.NETWORK or not self._selected(check.check_id):
                    continue
                reason = (
                    "skip_checks"
                    if check.check_id in host.skip_checks
                    else "docker_disabled"
                    if check.requires_docker and not host.docker
                    else ""
                )
                result.append({"target": host.id, "check": check.check_id, "skip": reason})
        for check_name, item, _ in self._network_targets():
            result.append({"target": item.id, "check": check_name, "skip": ""})
        return result

    def _network_one(self, check: str, item: Any, key: str) -> CheckResult:
        if self.cancel_event.is_set():
            return CheckResult(
                check_id=check,
                category=CheckCategory.NETWORK,
                target=item.id,
                status=CheckStatus.NOT_EVALUATED,
                reason="Auditoría cancelada",
            )
        return self.registry.get(check).run(
            CheckContext(self.inventory, target=item.id, extras={key: item})
        )

    def _run(self, inventory_path: str = "") -> AuditReport:
        self.cancel_event.clear()
        report = AuditReport(
            inventory_path=inventory_path,
            started_at=datetime.now(UTC),
            categories=list(self.categories),
            tool_version=__version__,
            execution_workers=self.workers,
            selection={
                "hosts": self.requested_hosts,
                "tags": self.requested_tags,
                "checks": sorted(self.check_ids),
            },
            inventory_fingerprint=hashlib.sha256(
                json.dumps(redact(self.inventory.model_dump(mode="json")), sort_keys=True).encode()
            ).hexdigest(),
        )
        hosts = (
            self.hosts
            if any(
                c.category != CheckCategory.NETWORK and self._selected(c.check_id)
                for c in self.registry.all()
            )
            else []
        )
        network = self._network_targets()
        completed = 0
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="infraaudit") as pool:
            futures: dict[Future[Any], tuple[str, int]] = {
                pool.submit(self._run_host, h.id): ("host", i) for i, h in enumerate(hosts)
            }
            futures.update(
                {
                    pool.submit(self._network_one, *target): ("network", i)
                    for i, target in enumerate(network)
                }
            )
            values: dict[tuple[str, int], Any] = {}
            while futures:
                try:
                    for future in as_completed(list(futures)):
                        identity = futures[future]
                        values[identity] = future.result()
                        del futures[future]
                        completed += 1
                        if self.progress:
                            self.progress(completed, len(hosts) + len(network))
                except KeyboardInterrupt:
                    self.cancel_event.set()
                    report.cancelled = True
        report.host_results = [values[("host", i)] for i in range(len(hosts))]
        report.network_results = [values[("network", i)] for i in range(len(network))]
        report.finished_at = datetime.now(UTC)
        return report

    def _run_host(self, host_id: str) -> HostResult:
        host = next(h for h in self.inventory.hosts if h.id == host_id)
        host_result = HostResult(
            host_id=host.id,
            hostname=host.id,
            address=host.address,
        )

        checks = self.registry.filter(
            categories=[
                c for c in self.categories if c in {CheckCategory.LINUX, CheckCategory.DOCKER}
            ]
        )
        selected = []
        for check in checks:
            if self.check_ids and check.check_id not in self.check_ids:
                continue
            reason = None
            if check.check_id in host.skip_checks:
                reason = "Omitido por skip_checks"
            elif check.requires_docker and not host.docker:
                reason = "Docker deshabilitado en el inventario"
            if reason:
                host_result.check_results.append(
                    CheckResult(
                        check_id=check.check_id,
                        category=check.category,
                        target=host.id,
                        status=CheckStatus.SKIPPED,
                        reason=reason,
                    )
                )
            else:
                selected.append(check)
        if self.cancel_event.is_set():
            for check in selected:
                host_result.check_results.append(
                    CheckResult(
                        check_id=check.check_id,
                        category=check.category,
                        target=host.id,
                        status=CheckStatus.NOT_EVALUATED,
                        reason="Auditoría cancelada",
                    )
                )
            return host_result
        if not selected:
            return host_result

        try:
            with SSHClient(host) as ssh:
                shared: dict[str, Any] = {}
                for check in selected:
                    if self.cancel_event.is_set():
                        host_result.check_results.append(
                            CheckResult(
                                check_id=check.check_id,
                                category=check.category,
                                target=host.id,
                                status=CheckStatus.NOT_EVALUATED,
                                reason="Auditoría cancelada",
                            )
                        )
                        continue
                    ctx = CheckContext(
                        inventory=self.inventory,
                        host=host,
                        ssh=ssh,
                        target=host.id,
                        extras=shared,
                    )
                    logger.info("Ejecutando %s en %s", check.check_id, host.id)
                    host_result.check_results.append(check.run(ctx))
        except (SSHError, OSError) as exc:
            logger.error("Conexión SSH fallida a %s", host.id)
            host_result.connection_error = str(exc)
            recorded = {r.check_id for r in host_result.check_results}
            for check in selected:
                if check.check_id not in recorded:
                    host_result.check_results.append(
                        CheckResult(
                            check_id=check.check_id,
                            category=check.category,
                            target=host.id,
                            status=CheckStatus.NOT_EVALUATED,
                            reason=str(exc),
                        )
                    )
        return host_result
