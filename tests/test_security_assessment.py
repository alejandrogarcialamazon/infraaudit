"""Separar hallazgos confirmados de limitaciones de diagnóstico."""

from __future__ import annotations

import json
import socket
import ssl
from unittest.mock import MagicMock

import httpx
import pytest

from infraaudit.checks.base import BaseCheck, CheckContext, CheckNotEvaluableError
from infraaudit.checks.docker.containers import DockerSecurityCheck
from infraaudit.checks.network.services import HttpCheck, TcpPortCheck
from infraaudit.config import HttpService, Inventory, TcpService
from infraaudit.models import Assessment, CheckResult, CheckStatus, Finding, FindingKind, Severity
from infraaudit.reporting import get_reporter
from infraaudit.ssh import CommandResult
from tests.test_execution_status import context, report_with


def test_unexpected_plugin_error_is_diagnostic_not_security() -> None:
    class Broken(BaseCheck):
        def execute(self, ctx):
            raise RuntimeError("programming bug")

    result = Broken().run(CheckContext(Inventory()))
    assert result.status == CheckStatus.ERROR
    assert result.assessment == Assessment.INCONCLUSIVE
    assert not result.security_failed
    assert result.findings == []
    assert result.diagnostic_evidence["exception_type"] == "RuntimeError"
    assert report_with(result).summary()["by_severity"]["HIGH"] == 0


def docker_context(payload: object) -> CheckContext:
    ctx = context(CommandResult("probe", 0, "abcdef123456\n", ""))
    ctx.ssh.run.side_effect = [
        CommandResult("ps", 0, "abcdef123456\n", ""),
        CommandResult("inspect", 0, json.dumps(payload), ""),
    ]
    return ctx


def test_confirmed_privileged_container_is_security_failure() -> None:
    payload = [
        {
            "Name": "/probe",
            "Config": {"User": "1001", "Healthcheck": {}},
            "State": {},
            "HostConfig": {"Privileged": True, "RestartPolicy": {"Name": "always"}},
        }
    ]
    result = DockerSecurityCheck().run(docker_context(payload))
    assert result.status == CheckStatus.COMPLETED
    assert result.assessment == Assessment.FAILED
    assert result.security_failed
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert report_with(result).summary()["security_failed_checks"] == 1


def test_incomplete_security_data_is_not_a_security_failure() -> None:
    result = DockerSecurityCheck().run(docker_context([{"Name": "/probe"}]))
    assert result.assessment == Assessment.INCONCLUSIVE
    assert not result.security_failed
    assert not result.findings


def test_partial_security_evidence_is_preserved() -> None:
    class Partial(BaseCheck):
        def execute(self, ctx):
            finding = self.finding(
                severity=Severity.HIGH,
                kind=FindingKind.SECURITY,
                target="probe",
                message="confirmed policy failure",
            )
            raise CheckNotEvaluableError("another subcheck unavailable", findings=[finding])

    result = Partial().run(CheckContext(Inventory()))
    summary = report_with(result).summary()
    assert result.assessment == Assessment.INCONCLUSIVE
    assert result.security_failed
    assert summary["inconclusive_checks"] == 1
    assert summary["security_findings"] == 1
    assert not summary["complete"]


def http_context(url: str = "http://example.invalid") -> CheckContext:
    service = HttpService(id="http", url=url)
    return CheckContext(Inventory(), target=service.id, extras={"http_service": service})


def mock_http(monkeypatch: pytest.MonkeyPatch, *, error=None, status=200) -> None:
    client = MagicMock()
    client.__enter__.return_value = client
    if error is not None:
        client.request.side_effect = error
    else:
        client.request.return_value = httpx.Response(status)
    monkeypatch.setattr("infraaudit.checks.network.services.httpx.Client", lambda **kw: client)


@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectTimeout("timeout"),
        httpx.ConnectError("DNS failed"),
        httpx.ProxyError("proxy unavailable"),
    ],
)
def test_http_transport_failure_is_inconclusive(monkeypatch: pytest.MonkeyPatch, error) -> None:
    mock_http(monkeypatch, error=error)
    result = HttpCheck().run(http_context())
    assert result.assessment == Assessment.INCONCLUSIVE
    assert not result.findings
    assert not result.security_failed


def test_http_500_is_confirmed_operational_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_http(monkeypatch, status=500)
    result = HttpCheck().run(http_context())
    assert result.assessment == Assessment.FAILED
    assert result.findings[0].kind == FindingKind.OPERATIONAL
    assert not result.security_failed


def test_cert_policy_rejection_is_confirmed_but_http_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert = ssl.SSLCertVerificationError(1, "certificate rejected")
    error = httpx.ConnectError("TLS failed")
    error.__cause__ = cert
    mock_http(monkeypatch, error=error)
    result = HttpCheck().run(http_context("https://example.invalid"))
    assert result.assessment == Assessment.INCONCLUSIVE
    assert result.security_failed
    assert result.findings[0].kind == FindingKind.SECURITY


def test_tls_inspection_timeout_does_not_fabricate_security_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_http(monkeypatch)

    def timeout(*args, **kwargs):
        raise TimeoutError("TLS inspection timeout")

    monkeypatch.setattr("infraaudit.checks.network.services._tls_info", timeout)
    result = HttpCheck().run(http_context("https://example.invalid"))
    assert result.assessment == Assessment.INCONCLUSIVE
    assert not result.security_failed
    assert len(result.findings) == 1  # HTTP evidence survives.
    assert result.findings[0].severity == Severity.INFO


def test_expiring_tls_is_security_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_http(monkeypatch)
    monkeypatch.setattr(
        "infraaudit.checks.network.services._tls_info", lambda *a, **kw: {"days_left": 2}
    )
    result = HttpCheck().run(http_context("https://example.invalid"))
    assert result.assessment == Assessment.FAILED
    assert result.security_failed
    assert result.findings[-1].severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "error", [socket.gaierror("DNS"), TimeoutError("timeout"), PermissionError("local sandbox")]
)
def test_tcp_ambiguous_failure_is_inconclusive(monkeypatch: pytest.MonkeyPatch, error) -> None:
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr("socket.create_connection", fail)
    service = TcpService(id="tcp", host="example.invalid", port=443)
    result = TcpPortCheck().run(CheckContext(Inventory(), extras={"tcp_service": service}))
    assert result.assessment == Assessment.INCONCLUSIVE
    assert not result.security_failed
    assert result.findings == []


def test_old_high_finding_is_not_reclassified_as_security() -> None:
    result = CheckResult.model_validate(
        dict(
            check_id="old",
            category="linux",
            target="old",
            success=False,
            error="old plugin error",
            findings=[dict(severity="HIGH", check="old", target="old", message="old")],
        )
    )
    assert result.assessment == Assessment.INCONCLUSIVE
    assert result.findings[0].kind == FindingKind.UNCLASSIFIED
    assert report_with(result).summary()["security_findings"] == 0


@pytest.mark.parametrize("fmt", ["json", "markdown", "html"])
def test_reports_show_both_security_failure_and_inconclusive(fmt: str) -> None:
    result = CheckResult(
        check_id="partial",
        category="linux",
        target="partial",
        status=CheckStatus.NOT_EVALUATED,
        reason="missing source",
        findings=[
            Finding(
                kind=FindingKind.SECURITY,
                severity=Severity.HIGH,
                check="partial",
                target="partial",
                message="confirmed",
            )
        ],
    )
    rendered = get_reporter(fmt).render(report_with(result))
    assert "inconclusive" in rendered.lower()
    assert "security" in rendered.lower()
    assert "missing source" in rendered


def test_serialized_assessment_is_recomputed_from_evidence() -> None:
    result = CheckResult(
        check_id="probe",
        category="linux",
        target="probe",
        status=CheckStatus.NOT_EVALUATED,
        reason="missing tool",
    )
    payload = result.model_dump(mode="json")
    payload["assessment"] = "failed"
    payload["security_failed"] = True
    restored = CheckResult.model_validate(payload)
    assert restored.assessment == Assessment.INCONCLUSIVE
    assert not restored.security_failed


def test_legacy_completed_finding_remains_unknown() -> None:
    result = CheckResult.model_validate(
        dict(
            check_id="old",
            category="linux",
            target="old",
            success=True,
            findings=[dict(severity="INFO", check="old", target="old", message="old")],
        )
    )
    assert result.assessment == Assessment.UNKNOWN
    assert not result.security_failed


def test_docker_partial_findings_survive_missing_fields() -> None:
    ctx = context(CommandResult("probe", 0, "", ""))
    first = {
        "Name": "/confirmed",
        "Config": {"User": "1001"},
        "State": {},
        "HostConfig": {"Privileged": True, "RestartPolicy": {"Name": "always"}},
    }
    ctx.ssh.run.side_effect = [
        CommandResult("ps", 0, "abcdef123456\nabcdef123457\n", ""),
        CommandResult("inspect", 0, json.dumps([first, {"Name": "/unknown"}]), ""),
    ]
    result = DockerSecurityCheck().run(ctx)
    assert result.assessment == Assessment.INCONCLUSIVE
    assert result.security_failed
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
