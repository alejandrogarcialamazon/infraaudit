"""Checks de identidad y estado básico del sistema Linux."""

from __future__ import annotations

from infraaudit.checks.base import BaseCheck, CheckContext
from infraaudit.models import CheckCategory, Finding, Severity


class HostnameCheck(BaseCheck):
    check_id = "linux.hostname"
    category = CheckCategory.LINUX
    description = "Obtiene el hostname del sistema"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.ssh.run("hostname")
        hostname = result.output or "unknown"
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Hostname: {hostname}",
                evidence={"hostname": hostname, "exit_code": result.exit_code},
            )
        ]


class DistributionCheck(BaseCheck):
    check_id = "linux.distribution"
    category = CheckCategory.LINUX
    description = "Detecta la distribución Linux"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.ssh.run(
            "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null"
        )
        pretty = "unknown"
        for line in result.stdout.splitlines():
            if line.startswith("PRETTY_NAME="):
                pretty = line.split("=", 1)[1].strip().strip('"')
                break
            if line and "=" not in line:
                pretty = line.strip()
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Distribución: {pretty}",
                evidence={"os_release": result.stdout.strip(), "pretty_name": pretty},
            )
        ]


class KernelCheck(BaseCheck):
    check_id = "linux.kernel"
    category = CheckCategory.LINUX
    description = "Obtiene la versión del kernel"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.ssh.run("uname -r")
        kernel = result.output or "unknown"
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Kernel: {kernel}",
                evidence={"kernel": kernel},
            )
        ]


class UptimeCheck(BaseCheck):
    check_id = "linux.uptime"
    category = CheckCategory.LINUX
    description = "Reporta el uptime del sistema"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.ssh.run("cat /proc/uptime")
        seconds = 0.0
        if result.ok and result.output:
            seconds = float(result.output.split()[0])
        days = seconds / 86400
        severity = Severity.INFO
        recommendation = ""
        if days < 0.05:  # ~1 hora
            severity = Severity.MEDIUM
            recommendation = "Reinicio reciente: verificar causa y estabilidad post-reboot"
        return [
            self.finding(
                severity=severity,
                target=ctx.host.id,
                message=f"Uptime: {days:.2f} días ({int(seconds)}s)",
                recommendation=recommendation,
                evidence={"uptime_seconds": seconds, "uptime_days": round(days, 2)},
            )
        ]


class CpuCheck(BaseCheck):
    check_id = "linux.cpu"
    category = CheckCategory.LINUX
    description = "Evalúa uso de CPU"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        # Snapshot read-only via /proc/stat delta approximation with top batch
        result = ctx.ssh.run(
            "grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'"
        )
        nproc = ctx.ssh.run("nproc")
        cores = int(nproc.output) if nproc.ok and nproc.output.isdigit() else 1
        usage = float(result.output) if result.ok and result.output else 0.0
        thr = ctx.thresholds
        if usage >= thr.cpu_crit_percent:
            severity = Severity.CRITICAL
            recommendation = "CPU crítica: investigar procesos con top/htop y escalar si procede"
        elif usage >= thr.cpu_warn_percent:
            severity = Severity.HIGH
            recommendation = "CPU elevada: revisar procesos y capacidad del host"
        else:
            severity = Severity.INFO
            recommendation = ""
        return [
            self.finding(
                severity=severity,
                target=ctx.host.id,
                message=f"Uso de CPU: {usage:.1f}% ({cores} cores)",
                recommendation=recommendation,
                evidence={"cpu_percent": round(usage, 2), "cores": cores},
            )
        ]


class MemoryCheck(BaseCheck):
    check_id = "linux.memory"
    category = CheckCategory.LINUX
    description = "Evalúa uso de memoria"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.ssh.run("cat /proc/meminfo")
        values: dict[str, int] = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].endswith(":"):
                key = parts[0][:-1]
                try:
                    values[key] = int(parts[1])
                except ValueError:
                    continue
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", values.get("MemFree", 0))
        used = max(total - available, 0)
        percent = (used / total * 100) if total else 0.0
        thr = ctx.thresholds
        if percent >= thr.mem_crit_percent:
            severity = Severity.CRITICAL
            recommendation = "Memoria crítica: revisar leaks, OOM y capacidad"
        elif percent >= thr.mem_warn_percent:
            severity = Severity.HIGH
            recommendation = "Memoria elevada: evaluar presión de memoria y swap"
        else:
            severity = Severity.INFO
            recommendation = ""
        return [
            self.finding(
                severity=severity,
                target=ctx.host.id,
                message=f"Memoria usada: {percent:.1f}% ({used} / {total} kB)",
                recommendation=recommendation,
                evidence={
                    "mem_total_kb": total,
                    "mem_available_kb": available,
                    "mem_used_kb": used,
                    "mem_percent": round(percent, 2),
                },
            )
        ]


class LoadAverageCheck(BaseCheck):
    check_id = "linux.load"
    category = CheckCategory.LINUX
    description = "Evalúa load average respecto a número de CPUs"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        load = ctx.ssh.run("cat /proc/loadavg")
        nproc = ctx.ssh.run("nproc")
        cores = int(nproc.output) if nproc.ok and nproc.output.isdigit() else 1
        parts = load.output.split()
        load1 = float(parts[0]) if parts else 0.0
        ratio = load1 / cores if cores else load1
        thr = ctx.thresholds
        if ratio >= thr.load_crit_ratio:
            severity = Severity.CRITICAL
            recommendation = "Load crítica: posible saturación de CPU o I/O wait"
        elif ratio >= thr.load_warn_ratio:
            severity = Severity.MEDIUM
            recommendation = "Load elevada respecto a cores disponibles"
        else:
            severity = Severity.INFO
            recommendation = ""
        return [
            self.finding(
                severity=severity,
                target=ctx.host.id,
                message=f"Load average 1m: {load1} (ratio {ratio:.2f} sobre {cores} cores)",
                recommendation=recommendation,
                evidence={
                    "loadavg": load.output,
                    "load1": load1,
                    "cores": cores,
                    "ratio": round(ratio, 2),
                },
            )
        ]
