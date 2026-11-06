"""Carga y validación del inventario YAML."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

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


class ConfigModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", hide_input_in_errors=True, str_strip_whitespace=True, allow_inf_nan=False
    )


class SSHAuth(ConfigModel):
    """Credenciales SSH. Nunca se hardcodean; preferir env vars o keys."""

    username: str = Field(min_length=1)
    password: SecretStr | None = Field(default=None, repr=False, exclude=True)
    private_key: str | None = None
    private_key_passphrase: SecretStr | None = Field(default=None, repr=False, exclude=True)
    look_for_keys: bool = True
    allow_agent: bool = True

    @model_validator(mode="after")
    def require_auth_method(self) -> SSHAuth:
        if not self.password and not self.private_key and not self.look_for_keys:
            raise ValueError("Debe proporcionar password, private_key o look_for_keys=true")
        return self


class HostConfig(ConfigModel):
    """Host Linux/Docker auditado vía SSH."""

    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    address: str = Field(min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    ssh: SSHAuth
    tags: list[str] = Field(default_factory=list)
    timeout: int = Field(default=30, ge=1, le=600)
    max_output_bytes: int = Field(default=4194304, ge=1024, le=67108864)
    docker: bool = True
    skip_checks: list[str] = Field(default_factory=list)


class HttpService(ConfigModel):
    """Endpoint HTTP/HTTPS a validar."""

    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    url: str
    method: Literal["GET", "HEAD", "OPTIONS"] = "GET"
    expected_status: list[int] = Field(default_factory=lambda: [200])
    timeout: float = Field(default=10.0, ge=0.5, le=120.0)
    verify_tls: bool = True
    min_days_to_expiry: int = Field(default=30, ge=1)
    headers: dict[str, str] = Field(default_factory=dict, repr=False)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or any(c.isspace() for c in value)
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)
            ):
                raise ValueError
        except ValueError:
            raise ValueError("URL HTTP/HTTPS inválida") from None
        return value

    @field_validator("expected_status")
    @classmethod
    def validate_statuses(cls, values: list[int]) -> list[int]:
        if not values or any(not 100 <= value <= 599 for value in values):
            raise ValueError("expected_status debe contener códigos entre 100 y 599")
        return values


class TcpService(ConfigModel):
    """Puerto TCP a validar."""

    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    timeout: float = Field(default=5.0, ge=0.5, le=60.0)


class DnsRecord(ConfigModel):
    """Registro DNS esperado."""

    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    name: str = Field(min_length=1)
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT"] = "A"
    expected: list[str] = Field(default_factory=list)
    nameserver: str | None = None


class Thresholds(ConfigModel):
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

    @model_validator(mode="after")
    def coherent_thresholds(self) -> Thresholds:
        for kind in ("cpu", "mem", "disk", "inode"):
            warn = getattr(self, kind + "_warn_percent")
            crit = getattr(self, kind + "_crit_percent")
            if not 0 <= warn < crit <= 100:
                raise ValueError("Umbrales porcentuales requieren 0 <= warn < crit <= 100")
        for kind, unit in (("load", "ratio"), ("http", "ms")):
            if (
                not 0
                <= getattr(self, kind + "_warn_" + unit)
                < getattr(self, kind + "_crit_" + unit)
            ):
                raise ValueError("Umbrales requieren 0 <= warn < crit")
        if not 0 <= self.tls_crit_days < self.tls_warn_days:
            raise ValueError("TLS requiere 0 <= crit_days < warn_days")
        return self


class Inventory(ConfigModel):
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

    @model_validator(mode="after")
    def validate_ids_and_checks(self) -> Inventory:
        from infraaudit.checks import build_default_registry

        valid = {check.check_id for check in build_default_registry().all()}
        for group in (self.http_services, self.tcp_services, self.dns_records):
            ids = [item.id for item in group]
            if len(ids) != len(set(ids)):
                raise ValueError("Los IDs deben ser únicos dentro de cada tipo de servicio")
        for host in self.hosts:
            if any(check not in valid for check in host.skip_checks):
                raise ValueError("skip_checks contiene un check desconocido")
        return self

    def secret_values(self) -> list[str]:
        from urllib.parse import parse_qsl, urlsplit

        from infraaudit.security import sensitive_key

        values = []
        for host in self.hosts:
            for secret in (host.ssh.password, host.ssh.private_key_passphrase):
                if secret:
                    values.append(secret.get_secret_value())
        for service in self.http_services:
            values.extend(value for key, value in service.headers.items() if sensitive_key(key))
            parsed = urlsplit(service.url)
            values.extend(value for key, value in parse_qsl(parsed.query) if sensitive_key(key))
        return values


class InventoryError(Exception):
    """Error al cargar o validar el inventario."""


def load_inventory(path: Path | str) -> Inventory:
    """Carga, expande env vars y valida un inventario YAML."""
    inventory_path = Path(path)
    if not inventory_path.is_file():
        raise InventoryError(f"Inventario no encontrado: {inventory_path}")

    try:
        raw = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        raise InventoryError("YAML inválido: revisar estructura y sintaxis") from None

    if not isinstance(raw, dict):
        raise InventoryError("El inventario debe ser un mapping YAML de nivel raíz")

    expanded = _expand_tree(raw)
    try:
        return Inventory.model_validate(expanded)
    except Exception as exc:
        from pydantic import ValidationError

        if isinstance(exc, ValidationError):
            locations = [
                ".".join(map(str, error["loc"])) or "inventory"
                for error in exc.errors(include_input=False, include_context=False)
            ]
            raise InventoryError("Validación fallida en: " + ", ".join(locations)) from None
        raise InventoryError("Validación de inventario fallida") from None


def validate_inventory_file(path: Path | str) -> Inventory:
    """Valida un inventario y lo retorna si es correcto."""
    return load_inventory(path)
