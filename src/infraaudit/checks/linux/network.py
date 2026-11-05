"""Checks de red local del host: gateway, DNS, NTP y puertos listening."""

from __future__ import annotations

from infraaudit.checks.base import BaseCheck, CheckContext, CheckNotEvaluableError
from infraaudit.models import CheckCategory, Finding, Severity


class GatewayCheck(BaseCheck):
    check_id = "linux.gateway"
    category = CheckCategory.LINUX
    description = "Verifica gateway por defecto"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.command(
            "ip route show default 2>/dev/null || route -n 2>/dev/null | awk '/^0.0.0.0/ {print}'"
        )
        if not result.output:
            return [
                self.finding(
                    severity=Severity.HIGH,
                    target=ctx.host.id,
                    message="No se detectó gateway por defecto",
                    recommendation="Verificar tablas de routing e interfaces",
                    evidence={"stdout": result.stdout, "stderr": result.stderr},
                )
            ]
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Gateway: {result.output}",
                evidence={"default_route": result.output},
            )
        ]


class DnsResolversCheck(BaseCheck):
    check_id = "linux.dns"
    category = CheckCategory.LINUX
    description = "Lista resolvers DNS configurados"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.command("cat /etc/resolv.conf 2>/dev/null")
        nameservers = [
            line.split()[1]
            for line in result.stdout.splitlines()
            if line.strip().startswith("nameserver")
        ]
        if not nameservers:
            return [
                self.finding(
                    severity=Severity.MEDIUM,
                    target=ctx.host.id,
                    message="Sin nameservers en /etc/resolv.conf",
                    recommendation="Configurar DNS resolvers válidos",
                    evidence={"resolv_conf": result.stdout},
                )
            ]
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"DNS resolvers: {', '.join(nameservers)}",
                evidence={"nameservers": nameservers},
            )
        ]


class NtpCheck(BaseCheck):
    check_id = "linux.ntp"
    category = CheckCategory.LINUX
    description = "Verifica sincronización NTP/chrony/timedatectl"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        timedate = ctx.ssh.run("timedatectl status 2>/dev/null")
        chronyc = ctx.ssh.run("chronyc tracking 2>/dev/null")
        if not ((timedate.ok and timedate.output) or (chronyc.ok and chronyc.output)):
            raise CheckNotEvaluableError("No se pudo consultar ninguna fuente NTP")
        synced = False
        evidence: dict[str, str] = {
            "timedatectl": timedate.stdout.strip(),
            "chronyc": chronyc.stdout.strip(),
        }
        text = (
            (timedate.stdout if timedate.ok else "") + "\n" + (chronyc.stdout if chronyc.ok else "")
        ).lower()
        if "system clock synchronized:" not in text and "leap status" not in text:
            raise CheckNotEvaluableError("Las fuentes NTP no informaron sincronización", evidence)
        if "system clock synchronized: yes" in text:
            synced = True
        if any(
            "leap status" in line and line.split(":")[-1].strip() == "normal"
            for line in text.splitlines()
        ):
            synced = True
        if synced:
            return [
                self.finding(
                    severity=Severity.INFO,
                    target=ctx.host.id,
                    message="Sincronización horaria activa",
                    evidence=evidence,
                )
            ]
        return [
            self.finding(
                severity=Severity.HIGH,
                target=ctx.host.id,
                message="No se confirmó sincronización NTP",
                recommendation="Activar chronyd/systemd-timesyncd y verificar peers",
                evidence=evidence,
            )
        ]


class ListeningPortsCheck(BaseCheck):
    check_id = "linux.listening_ports"
    category = CheckCategory.LINUX
    description = "Inventaría puertos en listening"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.command("ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null")
        if "State" not in result.stdout and "Proto" not in result.stdout:
            raise CheckNotEvaluableError("Salida de ss/netstat sin cabecera reconocible")
        lines = [
            ln
            for ln in result.stdout.splitlines()
            if "LISTEN" in ln or ln.split()[:1] in (["udp"], ["udp6"])
        ]
        # Detectar binding a 0.0.0.0 en puertos sensibles
        sensitive = {22, 3306, 5432, 6379, 27017, 9200}
        findings: list[Finding] = [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Puertos listening detectados: {len(lines)}",
                evidence={"raw": result.stdout.strip(), "count": len(lines)},
            )
        ]
        for line in lines:
            for port in sensitive:
                port_match = f":{port} " in line or line.rstrip().endswith(f":{port}")
                exposed = "0.0.0.0" in line or "[::]" in line or "*:" in line
                if port_match and exposed:
                    findings.append(
                        self.finding(
                            severity=Severity.MEDIUM,
                            target=f"{ctx.host.id}:{port}",
                            message=(f"Puerto sensible {port} expuesto en todas las interfaces"),
                            recommendation=("Restringir bind a interfaces internas o firewall"),
                            evidence={"line": line.strip()},
                        )
                    )
        return findings


class SystemdFailedCheck(BaseCheck):
    check_id = "linux.systemd_failed"
    category = CheckCategory.LINUX
    description = "Detecta unidades systemd fallidas"

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.command(
            "systemctl --failed --no-legend --no-pager 2>/dev/null", allow_empty=True
        )
        lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
        if not lines:
            return [
                self.finding(
                    severity=Severity.INFO,
                    target=ctx.host.id,
                    message="Sin unidades systemd fallidas",
                    evidence={"failed_units": []},
                )
            ]
        rows = [ln.lstrip("● ").split() for ln in lines]
        if any(len(row) < 4 or "failed" not in row[1:] for row in rows):
            raise CheckNotEvaluableError("Salida de systemctl no reconocida")
        units = [row[0] for row in rows]
        return [
            self.finding(
                severity=Severity.HIGH,
                target=ctx.host.id,
                message=f"Unidades systemd fallidas: {', '.join(units)}",
                recommendation="Investigar journalctl -u <unit> y corregir dependencias",
                evidence={"failed_units": units, "raw": result.stdout.strip()},
            )
        ]
