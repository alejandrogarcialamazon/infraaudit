"""Registro de plugins/checks descubribles."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from infraaudit.checks.base import BaseCheck
from infraaudit.models import CheckCategory

logger = logging.getLogger(__name__)


class CheckRegistry:
    """Catálogo central de checks registrados."""

    def __init__(self) -> None:
        self._checks: dict[str, BaseCheck] = {}

    def register(self, check: BaseCheck) -> None:
        if check.check_id in self._checks:
            raise ValueError(f"Check ya registrado: {check.check_id}")
        self._checks[check.check_id] = check
        logger.debug("Registrado check %s (%s)", check.check_id, check.category)

    def get(self, check_id: str) -> BaseCheck:
        return self._checks[check_id]

    def all(self) -> list[BaseCheck]:
        return list(self._checks.values())

    def by_category(self, category: CheckCategory) -> list[BaseCheck]:
        return [c for c in self._checks.values() if c.category == category]

    def filter(
        self,
        categories: Iterable[CheckCategory] | None = None,
        only: Iterable[str] | None = None,
        skip: Iterable[str] | None = None,
    ) -> list[BaseCheck]:
        selected = self.all()
        if categories is not None:
            cats = set(categories)
            selected = [c for c in selected if c.category in cats]
        if only is not None:
            only_set = set(only)
            selected = [c for c in selected if c.check_id in only_set]
        if skip is not None:
            skip_set = set(skip)
            selected = [c for c in selected if c.check_id not in skip_set]
        return selected


def build_default_registry() -> CheckRegistry:
    """Construye el registro con todos los checks incluidos."""
    from infraaudit.checks.docker import ALL_DOCKER_CHECKS
    from infraaudit.checks.linux import ALL_LINUX_CHECKS
    from infraaudit.checks.network import ALL_NETWORK_CHECKS

    registry = CheckRegistry()
    for check in (*ALL_LINUX_CHECKS, *ALL_DOCKER_CHECKS, *ALL_NETWORK_CHECKS):
        registry.register(check)
    return registry
