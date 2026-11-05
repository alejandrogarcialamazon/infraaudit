"""Checks de filesystems, inodos y mounts."""

from __future__ import annotations

import math

from infraaudit.checks.base import BaseCheck, CheckContext, CheckNotEvaluableError
from infraaudit.models import CheckCategory, Finding, Severity


class FilesystemCheck(BaseCheck):
    check_id = "linux.filesystems"
    category = CheckCategory.LINUX
    description = "Evalúa uso de espacio en filesystems"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.command("df -P -x tmpfs -x devtmpfs -x squashfs")
        findings: list[Finding] = []
        thr = ctx.thresholds
        lines = result.stdout.strip().splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 6:
                raise CheckNotEvaluableError("Fila de df incompleta")
            filesystem, size, used, avail, usep, mount = parts[:6]
            percent = float(usep.rstrip("%"))
            if not math.isfinite(percent) or not 0 <= percent <= 100:
                raise CheckNotEvaluableError("Porcentaje de filesystem inválido")
            if percent >= thr.disk_crit_percent:
                severity = Severity.CRITICAL
                recommendation = f"Liberar espacio en {mount} o ampliar volumen"
            elif percent >= thr.disk_warn_percent:
                severity = Severity.HIGH
                recommendation = f"Monitorear crecimiento de {mount}"
            else:
                severity = Severity.INFO
                recommendation = ""
            findings.append(
                self.finding(
                    severity=severity,
                    target=f"{ctx.host.id}:{mount}",
                    message=f"Disco {mount}: {usep} usado ({used}/{size})",
                    recommendation=recommendation,
                    evidence={
                        "filesystem": filesystem,
                        "size": size,
                        "used": used,
                        "avail": avail,
                        "use_percent": percent,
                        "mount": mount,
                    },
                )
            )
        if not findings:
            raise CheckNotEvaluableError("No se obtuvieron filas válidas de filesystems")
        return findings


class InodeCheck(BaseCheck):
    check_id = "linux.inodes"
    category = CheckCategory.LINUX
    description = "Evalúa uso de inodos"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.command("df -Pi -x tmpfs -x devtmpfs -x squashfs")
        findings: list[Finding] = []
        thr = ctx.thresholds
        for line in result.stdout.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                raise CheckNotEvaluableError("Fila de df incompleta")
            filesystem, inodes, iused, _ifree, iusep, mount = parts[:6]
            if iusep == "-":
                continue
            percent = float(iusep.rstrip("%"))
            if not math.isfinite(percent) or not 0 <= percent <= 100:
                raise CheckNotEvaluableError("Porcentaje de inodos inválido")
            if percent >= thr.inode_crit_percent:
                severity = Severity.CRITICAL
                recommendation = f"Inodos críticos en {mount}: limpiar archivos pequeños"
            elif percent >= thr.inode_warn_percent:
                severity = Severity.HIGH
                recommendation = f"Inodos elevados en {mount}"
            else:
                severity = Severity.INFO
                recommendation = ""
            findings.append(
                self.finding(
                    severity=severity,
                    target=f"{ctx.host.id}:{mount}",
                    message=f"Inodos {mount}: {iusep} usados ({iused}/{inodes})",
                    recommendation=recommendation,
                    evidence={
                        "filesystem": filesystem,
                        "inodes": inodes,
                        "iused": iused,
                        "iuse_percent": percent,
                        "mount": mount,
                    },
                )
            )
        if not findings:
            raise CheckNotEvaluableError("No se obtuvieron datos evaluables de inodos")
        return findings


class MountsCheck(BaseCheck):
    check_id = "linux.mounts"
    category = CheckCategory.LINUX
    description = "Lista mounts activos y detecta opciones riesgosas"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.command("findmnt -A -n -o TARGET,SOURCE,FSTYPE,OPTIONS")
        findings: list[Finding] = []
        risky = ("noexec",)  # informational flags of interest
        rw_tmp = False
        for line in result.stdout.splitlines():
            parts = line.split(None, 3)
            if len(parts) < 4:
                raise CheckNotEvaluableError("Fila de findmnt incompleta")
            target, source, fstype, options = parts
            evidence = {
                "target": target,
                "source": source,
                "fstype": fstype,
                "options": options,
            }
            if target == "/tmp" and "rw" in options.split(","):
                rw_tmp = True
            if any(flag in options.split(",") for flag in ("suid",)) and target in {
                "/tmp",
                "/var/tmp",
                "/dev/shm",
            }:
                findings.append(
                    self.finding(
                        severity=Severity.MEDIUM,
                        target=f"{ctx.host.id}:{target}",
                        message=f"Mount {target} permite suid",
                        recommendation="Considerar nosuid en mounts temporales",
                        evidence=evidence,
                    )
                )
        findings.insert(
            0,
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Mounts activos: {len(result.stdout.splitlines())}"
                + (" (/tmp es rw)" if rw_tmp else ""),
                evidence={"mounts": result.stdout.strip(), "risky_flags_checked": list(risky)},
            ),
        )
        return findings
