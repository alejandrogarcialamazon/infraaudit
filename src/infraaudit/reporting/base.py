"""Interfaz de reportes."""

from __future__ import annotations

import os
import tempfile
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
        rendered = self.render(report)
        fd, temporary = tempfile.mkstemp(prefix="." + output.name + ".", dir=output.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, output)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return output
