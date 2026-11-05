"""Interfaz de reportes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from infraaudit.models import AuditReport


class BaseReporter(ABC):
    """Generador de reportes."""

    format_name: str = "base"

    @abstractmethod
    def render(self, report: AuditReport) -> str:
        """Renderiza el informe a texto."""

    def write(self, report: AuditReport, path: Path | str) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.render(report), encoding="utf-8")
        return output
