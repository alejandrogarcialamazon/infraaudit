"""Carga y validación del inventario YAML."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(value: str) -> str:
    """Expande variables de entorno estilo ${VAR} o ${VAR:-default}."""

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        default = match.group(2)
        env_value = os.environ.get(name)
        if env_value is not None:
            return env_value
        if default is not None:
            return default
        raise InventoryError(f"Variable de entorno requerida no definida: {name}")

    return _ENV_PATTERN.sub(_replace, value)


def _expand_tree(node: Any) -> Any:
    if isinstance(node, str):
        return expand_env(node)
    if isinstance(node, list):
        return [_expand_tree(item) for item in node]
    if isinstance(node, dict):
        return {key: _expand_tree(value) for key, value in node.items()}
    return node


class SSHAuth(BaseModel):
    """Credenciales SSH. Nunca se hardcodean; preferir env vars o keys."""

    username: str
    password: str | None = None
    private_key: str | None = None
    private_key_passphrase: str | None = None
    look_for_keys: bool = True
    allow_agent: bool = True

    @model_validator(mode="after")
    def require_auth_method(self) -> SSHAuth:
        if not self.password and not self.private_key and not self.look_for_keys:
            raise ValueError("Debe proporcionar password, private_key o look_for_keys=true")
        return self


class HostConfig(BaseModel):
    """Host Linux/Docker auditado vía SSH."""

    id: str
    address: str
    port: int = 22
    ssh: SSHAuth
    tags: list[str] = Field(default_factory=list)
    timeout: int = Field(default=30, ge=1, le=600)
    docker: bool = True
    skip_checks: list[str] = Field(default_factory=list)


class HttpService(BaseModel):
    """Endpoint HTTP/HTTPS a validar."""

    id: str
    url: str
    method: Literal["GET", "HEAD", "OPTIONS"] = "GET"
    expected_status: list[int] = Field(default_factory=lambda: [200])
    timeout: float = Field(default=10.0, ge=0.5, le=120.0)
    verify_tls: bool = True
    min_days_to_expiry: int = Field(default=30, ge=1)
    headers: dict[str, str] = Field(default_factory=dict)


class TcpService(BaseModel):
    """Puerto TCP a validar."""

    id: str
    host: str
    port: int = Field(ge=1, le=65535)
    timeout: float = Field(default=5.0, ge=0.5, le=60.0)


class DnsRecord(BaseModel):
    """Registro DNS esperado."""

    id: str
    name: str
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT"] = "A"
    expected: list[str] = Field(default_factory=list)
    nameserver: str | None = None


class Thresholds(BaseModel):
    """Umbrales globales para findings."""

    cpu_warn_percent: float = 80.0
    cpu_crit_percent: float = 95.0
    mem_warn_percent: float = 85.0
    mem_crit_percent: float = 95.0
    disk_warn_percent: float = 80.0
    disk_crit_percent: float = 90.0
    inode_warn_percent: float = 80.0
    inode_crit_percent: float = 90.0
    load_warn_ratio: float = 1.0
    load_crit_ratio: float = 2.0
    http_warn_ms: float = 1000.0
    http_crit_ms: float = 3000.0
    tls_warn_days: int = 30
    tls_crit_days: int = 7


class Inventory(BaseModel):
    """Inventario completo de auditoría."""

    name: str = "default"
    description: str = ""
    hosts: list[HostConfig] = Field(default_factory=list)
    http_services: list[HttpService] = Field(default_factory=list)
    tcp_services: list[TcpService] = Field(default_factory=list)
    dns_records: list[DnsRecord] = Field(default_factory=list)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    default_timeout: int = Field(default=30, ge=1, le=600)

    @field_validator("hosts")
    @classmethod
    def unique_host_ids(cls, hosts: list[HostConfig]) -> list[HostConfig]:
        ids = [h.id for h in hosts]
        if len(ids) != len(set(ids)):
            raise ValueError("Los IDs de hosts deben ser únicos")
        return hosts


class InventoryError(Exception):
    """Error al cargar o validar el inventario."""


def load_inventory(path: Path | str) -> Inventory:
    """Carga, expande env vars y valida un inventario YAML."""
    inventory_path = Path(path)
    if not inventory_path.is_file():
        raise InventoryError(f"Inventario no encontrado: {inventory_path}")

    try:
        raw = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise InventoryError(f"YAML inválido: {exc}") from exc

    if not isinstance(raw, dict):
        raise InventoryError("El inventario debe ser un mapping YAML de nivel raíz")

    expanded = _expand_tree(raw)
    try:
        return Inventory.model_validate(expanded)
    except Exception as exc:
        raise InventoryError(f"Validación fallida: {exc}") from exc


def validate_inventory_file(path: Path | str) -> Inventory:
    """Valida un inventario y lo retorna si es correcto."""
    return load_inventory(path)
