"""Checks de red externos: DNS, TCP, HTTP/HTTPS y TLS."""

from __future__ import annotations

import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any

import dns.exception
import dns.resolver
import httpx

from infraaudit.checks.base import BaseCheck, CheckContext, CheckNotEvaluableError
from infraaudit.config import DnsRecord, HttpService, TcpService
from infraaudit.models import CheckCategory, Finding, FindingKind, Severity


class DnsQueryError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _normalize_dns(value: str, record_type: str) -> str:
    if record_type in {"CNAME", "MX"}:
        return value.rstrip(".").lower()
    return value.rstrip(".") if record_type in {"A", "AAAA"} else value


def _resolve_dns(
    name: str, record_type: str, nameserver: str | None = None, timeout: float = 5.0, port: int = 53
) -> list[str]:
    try:
        resolver = dns.resolver.Resolver(configure=nameserver is None)
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.port = port
        resolver.timeout = min(timeout, 2)
        resolver.lifetime = timeout
        answer = resolver.resolve(name, record_type, lifetime=timeout, search=False)
        return sorted(
            {
                b"".join(row.strings).decode("utf-8", errors="replace")
                if record_type == "TXT"
                else _normalize_dns(row.to_text(), record_type)
                for row in answer
            }
        )
    except dns.resolver.NXDOMAIN as exc:
        raise DnsQueryError("nxdomain") from exc
    except dns.resolver.NoAnswer as exc:
        raise DnsQueryError("no_answer") from exc
    except dns.exception.Timeout as exc:
        raise DnsQueryError("timeout") from exc
    except dns.resolver.NoNameservers as exc:
        raise DnsQueryError("no_nameservers") from exc
    except (dns.exception.DNSException, OSError, ValueError) as exc:
        raise DnsQueryError("resolver_error") from exc


class DnsCheck(BaseCheck):
    check_id = "network.dns"
    category = CheckCategory.NETWORK
    description = "Valida registros DNS esperados"
    requires_ssh = False

    def execute(self, ctx: CheckContext) -> list[Finding]:
        record: DnsRecord = ctx.extras["dns_record"]
        expected = [_normalize_dns(value, record.record_type) for value in record.expected]
        try:
            actual = _resolve_dns(
                record.name, record.record_type, record.nameserver, record.timeout, record.port
            )
        except DnsQueryError as exc:
            if exc.code in {"nxdomain", "no_answer"}:
                return [
                    self.finding(
                        severity=Severity.HIGH,
                        target=record.id,
                        message=f"DNS {record.name}: {exc.code}",
                        evidence={"dns_status": exc.code, "expected": expected},
                    )
                ]
            raise CheckNotEvaluableError(
                "Consulta DNS inconclusa: " + exc.code, {"dns_status": exc.code}
            ) from exc
        if not actual:
            raise CheckNotEvaluableError(
                f"Sin evidencia DNS para {record.name} ({record.record_type})",
                {"actual": actual, "expected": expected},
            )
        if not expected:
            resolved = ", ".join(actual) or "sin respuesta"
            return [
                self.finding(
                    severity=Severity.INFO,
                    target=record.id,
                    message=f"DNS {record.record_type} {record.name}: {resolved}",
                    evidence={"actual": actual, "type": record.record_type},
                )
            ]
        missing = [v for v in expected if v not in actual]
        unexpected = [v for v in actual if v not in expected]
        if missing or unexpected:
            return [
                self.finding(
                    severity=Severity.HIGH,
                    target=record.id,
                    message=f"DNS mismatch para {record.name} ({record.record_type})",
                    recommendation="Corregir registros DNS para coincidir con el inventario",
                    evidence={
                        "expected": expected,
                        "actual": actual,
                        "missing": missing,
                        "unexpected": unexpected,
                    },
                )
            ]
        return [
            self.finding(
                severity=Severity.INFO,
                target=record.id,
                message=f"DNS OK: {record.name} {record.record_type} -> {', '.join(actual)}",
                evidence={"expected": expected, "actual": actual},
            )
        ]


class TcpPortCheck(BaseCheck):
    check_id = "network.tcp"
    category = CheckCategory.NETWORK
    description = "Valida conectividad TCP"
    requires_ssh = False

    def execute(self, ctx: CheckContext) -> list[Finding]:
        service: TcpService = ctx.extras["tcp_service"]
        started = time.perf_counter()
        try:
            with socket.create_connection((service.host, service.port), service.timeout):
                pass
            elapsed_ms = (time.perf_counter() - started) * 1000
            return [
                self.finding(
                    severity=Severity.INFO,
                    target=service.id,
                    message=(f"TCP {service.host}:{service.port} abierto ({elapsed_ms:.0f} ms)"),
                    evidence={
                        "host": service.host,
                        "port": service.port,
                        "rtt_ms": round(elapsed_ms, 2),
                    },
                )
            ]
        except OSError as exc:
            if not isinstance(exc, ConnectionRefusedError):
                raise CheckNotEvaluableError(
                    f"Conectividad TCP inconclusa: {exc}",
                    {"host": service.host, "port": service.port, "error": str(exc)},
                ) from exc
            return [
                self.finding(
                    severity=Severity.CRITICAL,
                    target=service.id,
                    message=f"TCP {service.host}:{service.port} no alcanzable: {exc}",
                    recommendation="Verificar firewall, servicio y DNS",
                    evidence={"host": service.host, "port": service.port, "error": str(exc)},
                )
            ]


def _tls_info(
    hostname: str, port: int = 443, timeout: float = 10.0, ca_bundle: str | None = None
) -> dict[str, Any]:
    context = ssl.create_default_context(cafile=ca_bundle)
    with (
        socket.create_connection((hostname, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=hostname) as ssock,
    ):
        cert = ssock.getpeercert()
    if not cert:
        return {}
    not_after = cert.get("notAfter")
    expires: datetime | None = None
    days_left: int | None = None
    if isinstance(not_after, str):
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        days_left = (expires - datetime.now(UTC)).days
    san: list[str] = []
    san_entries = cert.get("subjectAltName") or ()
    if isinstance(san_entries, tuple):
        for entry in san_entries:
            if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == "DNS":
                san.append(str(entry[1]))
    issuer_parts: list[str] = []
    issuer = cert.get("issuer") or ()
    if isinstance(issuer, tuple):
        for rdn in issuer:
            if not isinstance(rdn, tuple):
                continue
            for attr in rdn:
                if isinstance(attr, tuple) and len(attr) == 2:
                    issuer_parts.append(f"{attr[0]}={attr[1]}")
    return {
        "not_after": not_after,
        "expires_at": expires.isoformat() if expires else None,
        "days_left": days_left,
        "issuer": ", ".join(issuer_parts),
        "san": san,
        "subject": cert.get("subject"),
        "version": cert.get("version"),
    }


def _certificate_error(exc: BaseException) -> ssl.SSLCertVerificationError | None:
    """Reconoce causas tipadas, sin deducir vulnerabilidades del texto del error."""
    pending = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return current
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return None


class HttpCheck(BaseCheck):
    check_id = "network.http"
    category = CheckCategory.NETWORK
    description = "Valida HTTP/HTTPS, latencia y certificado TLS"
    requires_ssh = False

    def execute(self, ctx: CheckContext) -> list[Finding]:
        service: HttpService = ctx.extras["http_service"]
        findings: list[Finding] = []
        thr = ctx.thresholds
        started = time.perf_counter()
        try:
            with httpx.Client(
                timeout=service.timeout,
                verify=(
                    ssl.create_default_context(cafile=service.ca_bundle)
                    if service.ca_bundle and service.verify_tls
                    else service.verify_tls
                ),
                follow_redirects=service.follow_redirects,
                headers=service.headers,
            ) as client:
                response = client.request(service.method, service.url)
            elapsed_ms = (time.perf_counter() - started) * 1000
        except (httpx.HTTPError, OSError, ValueError) as exc:
            cert_error = _certificate_error(exc)
            if cert_error is not None:
                findings.append(
                    self.finding(
                        severity=Severity.HIGH,
                        kind=FindingKind.SECURITY,
                        target=service.id,
                        message="Certificado rechazado por la política de confianza TLS",
                        recommendation="Verificar identidad y confianza TLS",
                        evidence={"verify_code": getattr(cert_error, "verify_code", None)},
                    )
                )
            raise CheckNotEvaluableError(
                f"HTTP no evaluable para {service.url}: {exc}",
                {"url": service.url, "error": str(exc)},
                findings=findings,
            ) from exc

        if response.status_code not in service.expected_status:
            findings.append(
                self.finding(
                    severity=Severity.HIGH,
                    target=service.id,
                    message=(
                        f"Status inesperado {response.status_code} "
                        f"(esperado {service.expected_status}) en {service.url}"
                    ),
                    recommendation="Revisar health endpoint y balanceadores",
                    evidence={
                        "status_code": response.status_code,
                        "expected": service.expected_status,
                        "elapsed_ms": round(elapsed_ms, 2),
                    },
                )
            )
        else:
            if elapsed_ms >= thr.http_crit_ms:
                sev = Severity.HIGH
                rec = "Latencia crítica: investigar backend y red"
            elif elapsed_ms >= thr.http_warn_ms:
                sev = Severity.MEDIUM
                rec = "Latencia elevada"
            else:
                sev = Severity.INFO
                rec = ""
            findings.append(
                self.finding(
                    severity=sev,
                    target=service.id,
                    message=f"HTTP {response.status_code} en {service.url} ({elapsed_ms:.0f} ms)",
                    recommendation=rec,
                    evidence={
                        "status_code": response.status_code,
                        "elapsed_ms": round(elapsed_ms, 2),
                        "url": service.url,
                    },
                )
            )

        if not service.verify_tls and service.url.startswith("https://"):
            findings.append(
                self.finding(
                    severity=Severity.MEDIUM,
                    kind=FindingKind.SECURITY,
                    target=service.id,
                    message="Verificación TLS deshabilitada por configuración",
                )
            )
        final_url = getattr(response, "url", None)
        endpoint = final_url if isinstance(final_url, httpx.URL) else httpx.URL(service.url)
        if service.url.startswith("https://") and endpoint.scheme == "http":
            findings.append(
                self.finding(
                    severity=Severity.HIGH,
                    kind=FindingKind.SECURITY,
                    target=service.id,
                    rule_id="tls_downgrade",
                    message="Redirección HTTPS a HTTP",
                    evidence={"final_url": str(endpoint)},
                )
            )
        if endpoint.scheme == "https" and not service.inspect_tls:
            findings.append(
                self.finding(
                    severity=Severity.INFO,
                    kind=FindingKind.SECURITY,
                    target=service.id,
                    rule_id="tls_inspection_skipped",
                    message="Inspección adicional TLS omitida por configuración",
                )
            )
        if endpoint.scheme == "https" and service.inspect_tls and service.verify_tls:
            parsed_host = endpoint.host
            port = endpoint.port or 443
            if parsed_host:
                try:
                    tls = _tls_info(
                        parsed_host, port, timeout=service.timeout, ca_bundle=service.ca_bundle
                    )
                except OSError as exc:
                    if isinstance(exc, ssl.SSLCertVerificationError):
                        findings.append(
                            self.finding(
                                severity=Severity.HIGH,
                                kind=FindingKind.SECURITY,
                                target=service.id,
                                message="Certificado rechazado por la política de confianza TLS",
                                recommendation="Verificar identidad y confianza TLS",
                                evidence={"verify_code": getattr(exc, "verify_code", None)},
                            )
                        )
                    raise CheckNotEvaluableError(
                        f"No se pudo inspeccionar TLS de {parsed_host}: {exc}",
                        {"error": str(exc)},
                        findings=findings,
                    ) from exc
                days = tls.get("days_left")
                if isinstance(days, int):
                    if days <= thr.tls_crit_days:
                        sev = Severity.CRITICAL
                        rec = "Renovar certificado TLS inmediatamente"
                    elif days <= (service.min_days_to_expiry or thr.tls_warn_days):
                        sev = Severity.HIGH
                        rec = "Planificar renovación del certificado TLS"
                    else:
                        sev = Severity.INFO
                        rec = ""
                    findings.append(
                        self.finding(
                            severity=sev,
                            kind=FindingKind.SECURITY,
                            target=service.id,
                            message=(
                                f"TLS {parsed_host}: expira en {days} días "
                                f"(issuer: {tls.get('issuer', 'unknown')})"
                            ),
                            recommendation=rec,
                            evidence=tls,
                        )
                    )
                else:
                    raise CheckNotEvaluableError(
                        f"TLS info incompleta para {parsed_host}",
                        tls,
                        findings=findings,
                    )
        return findings
