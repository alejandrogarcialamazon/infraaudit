"""Checks Docker: versión, containers, seguridad y recursos."""

from __future__ import annotations

import json
import math
import re
from typing import Any

from infraaudit.checks.base import BaseCheck, CheckContext, CheckNotEvaluableError
from infraaudit.models import CheckCategory, Finding, FindingKind, Severity
from infraaudit.ssh import CommandResult


def _docker_command(ctx: CheckContext, command: str, *, allow_empty: bool = False) -> CommandResult:
    cache = ctx.extras.setdefault("docker_commands", {})
    if command not in cache:
        try:
            cache[command] = ctx.command(command, allow_empty=allow_empty)
        except CheckNotEvaluableError as exc:
            error = str(exc.evidence.get("stderr", "")).lower()
            status = (
                "tool_missing"
                if exc.evidence.get("exit_code") == 127
                else "permission_denied"
                if "permission denied" in error
                else "daemon_unavailable"
                if "cannot connect" in error or "is the docker daemon" in error
                else "command_inconclusive"
            )
            raise CheckNotEvaluableError(
                "Docker: " + status, dict(exc.evidence, docker_status=status)
            ) from exc
    return cache[command]  # type: ignore[no-any-return]


def _docker_json(ctx: CheckContext, command: str) -> Any:
    result = _docker_command(ctx, command)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CheckNotEvaluableError("Docker devolvió JSON inválido") from exc


class DockerVersionCheck(BaseCheck):
    check_id = "docker.version"
    category = CheckCategory.DOCKER
    description = "Obtiene la versión de Docker"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        data = _docker_json(ctx, "docker version --format '{{json .}}'")
        if not isinstance(data, dict) or not isinstance(data.get("Server"), dict):
            raise CheckNotEvaluableError("Docker no informó versión del servidor")
        server = data["Server"].get("Version")
        if not isinstance(server, str) or not server:
            raise CheckNotEvaluableError("Versión Docker vacía o inválida")
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Docker server version: {server}",
                evidence={"version": data},
            )
        ]


class DockerContainersCheck(BaseCheck):
    check_id = "docker.containers"
    category = CheckCategory.DOCKER
    description = "Inventaría containers y su estado"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = _docker_command(ctx, "docker ps -a --format '{{json .}}'", allow_empty=True)
        containers = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CheckNotEvaluableError("Fila JSON de docker ps inválida") from exc
            if not isinstance(item, dict) or not item.get("State") or not item.get("Names"):
                raise CheckNotEvaluableError("Fila de docker ps incompleta")
            containers.append(item)

        running = [c for c in containers if str(c.get("State", "")).lower() == "running"]
        stopped = [c for c in containers if str(c.get("State", "")).lower() != "running"]
        summary_msg = (
            f"Containers: {len(containers)} total, {len(running)} running, {len(stopped)} stopped"
        )
        findings: list[Finding] = [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=summary_msg,
                evidence={
                    "total": len(containers),
                    "running": len(running),
                    "stopped": len(stopped),
                    "names": [c.get("Names") for c in containers],
                },
            )
        ]
        for c in containers:
            state = str(c.get("State", "")).lower()
            status = str(c.get("Status", ""))
            name = str(c.get("Names", c.get("ID", "unknown")))
            if "unhealthy" in status.lower():
                findings.append(
                    self.finding(
                        severity=Severity.HIGH,
                        target=f"{ctx.host.id}:{name}",
                        message=f"Container unhealthy: {name}",
                        recommendation="Revisar logs y healthcheck del container",
                        evidence={"status": status, "state": state},
                    )
                )
            elif state == "exited" and "exited (0)" not in status.lower():
                findings.append(
                    self.finding(
                        severity=Severity.MEDIUM,
                        target=f"{ctx.host.id}:{name}",
                        message=f"Container detenido con error: {name} ({status})",
                        recommendation="Investigar causa del exit code distinto de 0",
                        evidence={"status": status, "state": state},
                    )
                )
        return findings


class DockerResourcesCheck(BaseCheck):
    check_id = "docker.resources"
    category = CheckCategory.DOCKER
    description = "Uso de recursos de containers en ejecución"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        stats_fmt = "{{.Name}}\t{{.CPUPerc}}\t{{.MemPerc}}\t{{.MemUsage}}"
        result = _docker_command(
            ctx, f"docker stats --no-stream --format '{stats_fmt}'", allow_empty=True
        )
        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                raise CheckNotEvaluableError("Fila de docker stats incompleta")
            name, cpu_s, mem_s = parts[0], parts[1], parts[2]
            try:
                cpu = float(cpu_s.rstrip("%"))
                mem = float(mem_s.rstrip("%"))
            except ValueError as exc:
                raise CheckNotEvaluableError("Porcentajes Docker inválidos") from exc
            if not math.isfinite(cpu) or not math.isfinite(mem) or cpu < 0 or not 0 <= mem <= 100:
                raise CheckNotEvaluableError("Porcentajes Docker fuera de rango")
            severity = Severity.INFO
            recommendation = ""
            if cpu >= 90 or mem >= 90:
                severity = Severity.HIGH
                recommendation = f"Container {name} con alto consumo; revisar limits"
            elif cpu >= 70 or mem >= 70:
                severity = Severity.MEDIUM
                recommendation = f"Monitorear consumo de {name}"
            findings.append(
                self.finding(
                    severity=severity,
                    target=f"{ctx.host.id}:{name}",
                    message=f"Resources {name}: CPU {cpu_s}, MEM {mem_s}",
                    recommendation=recommendation,
                    evidence={"cpu_percent": cpu, "mem_percent": mem, "raw": line},
                )
            )
        if not findings:
            running = _docker_command(ctx, "docker ps -q", allow_empty=True)
            if running.output:
                raise CheckNotEvaluableError("docker stats sin datos para contenedores activos")
            findings.append(
                self.finding(
                    severity=Severity.INFO,
                    target=ctx.host.id,
                    message="Sin containers running para stats",
                    evidence={},
                )
            )
        return findings


class DockerSecurityCheck(BaseCheck):
    finding_kind = FindingKind.SECURITY
    check_id = "docker.security"
    category = CheckCategory.DOCKER
    description = "Detecta privileged, root y políticas de restart"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = _docker_command(ctx, "docker ps -q", allow_empty=True)
        ids = [x.strip() for x in result.stdout.splitlines() if x.strip()]
        findings: list[Finding] = []
        if any(not re.fullmatch(r"[a-fA-F0-9]{12,64}", identifier) for identifier in ids):
            raise CheckNotEvaluableError("IDs Docker inválidos")
        if not ids:
            return [
                self.finding(
                    severity=Severity.INFO,
                    target=ctx.host.id,
                    message="Sin containers running para auditoría de seguridad",
                )
            ]

        inspect_format = (
            "{{json .Name}}|{{json .Config.User}}|"
            "{{if .Config.Healthcheck}}{{json (index .Config.Healthcheck.Test 0)}}"
            "{{else}}null{{end}}|"
            "{{json .HostConfig.Privileged}}|{{json .HostConfig.RestartPolicy}}|"
            "{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}"
        )
        raw = _docker_command(ctx, f"docker inspect --format '{inspect_format}' {' '.join(ids)}")
        data = []
        for line in raw.output.splitlines():
            try:
                parts = line.split("|")
                if len(parts) != 6:
                    raise ValueError("inspect incompleto")
                name, user, mode, privileged, restart, health = map(json.loads, parts)
                data.append(
                    {
                        "Name": name,
                        "Config": {"User": user, "Healthcheck": mode in {"CMD", "CMD-SHELL"}},
                        "HostConfig": {"Privileged": privileged, "RestartPolicy": restart},
                        "State": {"Health": {"Status": health} if health is not None else None},
                    }
                )
            except (ValueError, TypeError):
                data.append({})

        for item in data:
            if (
                not isinstance(item, dict)
                or not all(isinstance(item.get(k), dict) for k in ("Config", "State", "HostConfig"))
                or not isinstance(item["HostConfig"].get("Privileged"), bool)
            ):
                raise CheckNotEvaluableError(
                    "docker inspect sin campos de seguridad requeridos", findings=findings
                )
            name = str(item.get("Name") or item.get("Id") or "unknown").lstrip("/")
            host_config = item.get("HostConfig") or {}
            config = item.get("Config") or {}
            state = item.get("State") or {}
            privileged = bool(host_config.get("Privileged"))
            user = str(config.get("User") or "")
            restart = str(host_config.get("RestartPolicy", {}).get("Name") or "no")
            health = (state.get("Health") or {}).get("Status")
            has_healthcheck = bool(config.get("Healthcheck"))

            if privileged:
                findings.append(
                    self.finding(
                        severity=Severity.CRITICAL,
                        target=f"{ctx.host.id}:{name}",
                        rule_id="privileged",
                        message=f"Container privileged: {name}",
                        recommendation="Evitar --privileged; usar capabilities mínimas",
                        evidence={"privileged": True},
                    )
                )
            if user in {"", "0", "root", "0:0"}:
                findings.append(
                    self.finding(
                        severity=Severity.MEDIUM,
                        target=f"{ctx.host.id}:{name}",
                        rule_id="root",
                        message=f"Container ejecutándose como root: {name}",
                        recommendation="Definir USER no-root en la imagen",
                        evidence={"user": user or "root(default)"},
                    )
                )
            if restart in {"no", ""}:
                findings.append(
                    self.finding(
                        severity=Severity.LOW,
                        target=f"{ctx.host.id}:{name}",
                        rule_id="restart_policy",
                        message=f"Sin restart policy: {name}",
                        recommendation=(
                            "Configurar unless-stopped o on-failure para workloads críticos"
                        ),
                        evidence={"restart_policy": restart},
                    )
                )
            if not has_healthcheck:
                findings.append(
                    self.finding(
                        severity=Severity.LOW,
                        target=f"{ctx.host.id}:{name}",
                        rule_id="healthcheck",
                        message=f"Sin HEALTHCHECK definido: {name}",
                        recommendation="Agregar HEALTHCHECK en Dockerfile o compose",
                        evidence={"healthcheck": None},
                    )
                )
            elif health == "unhealthy":
                findings.append(
                    self.finding(
                        severity=Severity.HIGH,
                        target=f"{ctx.host.id}:{name}",
                        rule_id="unhealthy",
                        message=f"Health status unhealthy: {name}",
                        recommendation="Revisar probes y logs del container",
                        evidence={"health": health},
                    )
                )
            else:
                findings.append(
                    self.finding(
                        severity=Severity.INFO,
                        target=f"{ctx.host.id}:{name}",
                        rule_id="health_status",
                        message=f"Health status {name}: {health or 'N/A'} (restart={restart})",
                        evidence={
                            "health": health,
                            "restart_policy": restart,
                            "user": user or "root(default)",
                            "privileged": privileged,
                        },
                    )
                )
        if len(data) != len(ids):
            raise CheckNotEvaluableError(
                "Respuesta de docker inspect incompleta", findings=findings
            )

        return findings


class DockerNetworksCheck(BaseCheck):
    check_id = "docker.networks"
    category = CheckCategory.DOCKER
    description = "Inventaría redes Docker"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = _docker_command(
            ctx, "docker network ls --format '{{.Name}}\t{{.Driver}}\t{{.Scope}}'", allow_empty=True
        )
        networks = [ln for ln in result.stdout.splitlines() if ln.strip()]
        if any(len(line.split("\t")) != 3 for line in networks):
            raise CheckNotEvaluableError("Fila de redes Docker incompleta")
        bridge_custom = [n for n in networks if not n.startswith(("bridge\t", "host\t", "none\t"))]
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Redes Docker: {len(networks)} ({len(bridge_custom)} no-default)",
                evidence={"networks": networks},
            )
        ]


class DockerVolumesCheck(BaseCheck):
    check_id = "docker.volumes"
    category = CheckCategory.DOCKER
    description = "Inventaría volúmenes Docker"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = _docker_command(
            ctx, "docker volume ls --format '{{.Name}}\t{{.Driver}}'", allow_empty=True
        )
        volumes = [ln for ln in result.stdout.splitlines() if ln.strip()]
        if any(len(line.split("\t")) != 2 for line in volumes):
            raise CheckNotEvaluableError("Fila de volúmenes Docker incompleta")
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Volúmenes Docker: {len(volumes)}",
                evidence={"volumes": volumes},
            )
        ]
