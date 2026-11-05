"""Checks Docker: versión, containers, seguridad y recursos."""

from __future__ import annotations

import json
from typing import Any

from infraaudit.checks.base import BaseCheck, CheckContext
from infraaudit.models import CheckCategory, Finding, Severity
from infraaudit.ssh import SSHClient


def _docker_json(ssh: SSHClient, command: str) -> Any:
    result = ssh.run(command)
    if not result.ok or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


class DockerVersionCheck(BaseCheck):
    check_id = "docker.version"
    category = CheckCategory.DOCKER
    description = "Obtiene la versión de Docker"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.ssh.run("docker version --format '{{json .}}' 2>/dev/null")
        if not result.ok:
            return [
                self.finding(
                    severity=Severity.HIGH,
                    target=ctx.host.id,
                    message="Docker no disponible o sin permisos",
                    recommendation="Instalar Docker o agregar el usuario al grupo docker",
                    evidence={"stderr": result.stderr},
                )
            ]
        data = _docker_json(ctx.ssh, "docker version --format '{{json .}}'")
        server = (data or {}).get("Server", {}).get("Version", "unknown")
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Docker server version: {server}",
                evidence={"version": data or result.stdout.strip()},
            )
        ]


class DockerContainersCheck(BaseCheck):
    check_id = "docker.containers"
    category = CheckCategory.DOCKER
    description = "Inventaría containers y su estado"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        jq_cmd = "docker ps -a --format '{{json .}}' | jq -s . 2>/dev/null"
        containers = _docker_json(ctx.ssh, jq_cmd)
        if containers is None:
            # Fallback sin jq: una línea JSON por container
            result = ctx.ssh.run("docker ps -a --format '{{json .}}'")
            containers = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

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
        result = ctx.ssh.run(f"docker stats --no-stream --format '{stats_fmt}'")
        findings: list[Finding] = []
        if not result.ok:
            return [
                self.finding(
                    severity=Severity.LOW,
                    target=ctx.host.id,
                    message="No se pudo obtener docker stats",
                    evidence={"stderr": result.stderr},
                )
            ]
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            name, cpu_s, mem_s = parts[0], parts[1], parts[2]
            try:
                cpu = float(cpu_s.rstrip("%"))
                mem = float(mem_s.rstrip("%"))
            except ValueError:
                continue
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
    check_id = "docker.security"
    category = CheckCategory.DOCKER
    description = "Detecta privileged, root y políticas de restart"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.ssh.run("docker ps -q")
        ids = [x.strip() for x in result.stdout.splitlines() if x.strip()]
        findings: list[Finding] = []
        if not ids:
            return [
                self.finding(
                    severity=Severity.INFO,
                    target=ctx.host.id,
                    message="Sin containers running para auditoría de seguridad",
                )
            ]

        inspect = ctx.ssh.run(f"docker inspect {' '.join(ids)}")
        try:
            data = json.loads(inspect.stdout)
        except json.JSONDecodeError:
            return [
                self.finding(
                    severity=Severity.LOW,
                    target=ctx.host.id,
                    message="No se pudo parsear docker inspect",
                    evidence={"stderr": inspect.stderr},
                )
            ]

        for item in data:
            name = item.get("Name", item.get("Id", "unknown")).lstrip("/")
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
                        message=f"Health status {name}: {health or 'N/A'} (restart={restart})",
                        evidence={
                            "health": health,
                            "restart_policy": restart,
                            "user": user or "root(default)",
                            "privileged": privileged,
                        },
                    )
                )
        return findings


class DockerNetworksCheck(BaseCheck):
    check_id = "docker.networks"
    category = CheckCategory.DOCKER
    description = "Inventaría redes Docker"
    requires_docker = True

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.ssh.run("docker network ls --format '{{.Name}}\t{{.Driver}}\t{{.Scope}}'")
        networks = [ln for ln in result.stdout.splitlines() if ln.strip()]
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
        result = ctx.ssh.run("docker volume ls --format '{{.Name}}\t{{.Driver}}'")
        volumes = [ln for ln in result.stdout.splitlines() if ln.strip()]
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Volúmenes Docker: {len(volumes)}",
                evidence={"volumes": volumes},
            )
        ]
