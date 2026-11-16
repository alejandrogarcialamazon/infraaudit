"""Regresiones observables de las mejoras 05-15."""

from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.exception
import dns.resolver
import httpx
import pytest
from typer.testing import CliRunner

from infraaudit.checks.base import BaseCheck, CheckContext
from infraaudit.checks.linux.network import NtpCheck
from infraaudit.checks.linux.system import CpuCheck
from infraaudit.checks.network.services import DnsCheck, DnsQueryError, HttpCheck, _resolve_dns
from infraaudit.checks.registry import CheckRegistry
from infraaudit.cli import app
from infraaudit.comparison import compare_reports
from infraaudit.config import DnsRecord, HostConfig, HttpService, Inventory, SSHAuth, TcpService
from infraaudit.engine import AuditEngine
from infraaudit.models import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    Finding,
    Severity,
)
from infraaudit.policy import exit_code
from infraaudit.reporting import write_report
from infraaudit.ssh import CommandResult
from tests.test_execution_status import context, item, report_with


def test_cpu_uses_delta_and_excludes_guest_double_counting(monkeypatch):
    ctx = context(CommandResult("", 0, "", ""))
    values = ["cpu 100 0 100 800 0 0 0 0 50 0", "cpu 150 0 150 900 0 0 0 0 100 0", "4"]
    ctx.ssh.run.side_effect = [CommandResult("", 0, value, "") for value in values]
    monkeypatch.setattr("infraaudit.checks.linux.system.time.sleep", lambda _: None)
    result = CpuCheck().run(ctx)
    assert result.findings[0].evidence["cpu_percent"] == 50
    assert result.findings[0].evidence["total_delta"] == 200


@pytest.mark.parametrize("second", ["cpu 1 0 0 0 0 0 0 0", "cpu 100 0 100 800 0 0 0 0"])
def test_cpu_reset_or_no_delta_inconclusive(monkeypatch, second):
    ctx = context(CommandResult("", 0, "", ""))
    ctx.ssh.run.side_effect = [
        CommandResult("", 0, text, "") for text in ["cpu 100 0 100 800 0 0 0 0", second]
    ]
    monkeypatch.setattr("infraaudit.checks.linux.system.time.sleep", lambda _: None)
    assert CpuCheck().run(ctx).status == CheckStatus.NOT_EVALUATED


@pytest.mark.parametrize(
    "timedate,chrony,severity",
    [
        ("System clock synchronized: yes", "Leap status : Normal", Severity.INFO),
        ("System clock synchronized: yes", "Leap status : Not synchronised", Severity.HIGH),
        ("NTP service: active", "Leap status : Not synchronised", Severity.HIGH),
    ],
)
def test_ntp_conflicts_do_not_pass(timedate, chrony, severity):
    ctx = context(CommandResult("", 0, "", ""))
    ctx.ssh.run.side_effect = [CommandResult("", 0, timedate, ""), CommandResult("", 0, chrony, "")]
    assert NtpCheck().run(ctx).findings[0].severity == severity


@pytest.mark.parametrize(
    "error,code",
    [
        (dns.resolver.NXDOMAIN(), "nxdomain"),
        (dns.resolver.NoAnswer(), "no_answer"),
        (dns.exception.Timeout(), "timeout"),
        (dns.resolver.NoNameservers(), "no_nameservers"),
    ],
)
def test_dns_typed_failures(monkeypatch, error, code):
    resolver = MagicMock()
    resolver.resolve.side_effect = error
    monkeypatch.setattr("dns.resolver.Resolver", lambda **kw: resolver)
    with pytest.raises(DnsQueryError) as raised:
        _resolve_dns("probe.invalid", "A")
    assert raised.value.code == code


@pytest.mark.parametrize(
    "code,complete", [("nxdomain", True), ("no_answer", True), ("timeout", False)]
)
def test_dns_negative_answer_differs_from_timeout(monkeypatch, code, complete):
    def fail(*a):
        raise DnsQueryError(code)

    monkeypatch.setattr("infraaudit.checks.network.services._resolve_dns", fail)
    ctx = CheckContext(
        Inventory(), extras={"dns_record": DnsRecord(id="dns", name="probe.invalid")}
    )
    result = DnsCheck().run(ctx)
    assert result.success == complete
    assert bool(result.findings) == complete


def test_tls_override_final_redirect_and_disabled_validation(monkeypatch):
    client = MagicMock()
    client.__enter__.return_value = client
    client.request.return_value = httpx.Response(
        200, request=httpx.Request("GET", "https://final.invalid:8443/")
    )
    monkeypatch.setattr("httpx.Client", lambda **kw: client)
    calls = []
    monkeypatch.setattr(
        "infraaudit.checks.network.services._tls_info",
        lambda *a, **kw: calls.append(a) or {"days_left": 45},
    )
    service = HttpService(id="http", url="https://original.invalid", min_days_to_expiry=60)
    ctx = CheckContext(Inventory(), extras={"http_service": service})
    result = HttpCheck().run(ctx)
    assert calls[0] == ("final.invalid", 8443)
    assert result.findings[-1].severity == Severity.HIGH
    service.verify_tls = False
    calls.clear()
    assert HttpCheck().run(ctx).security_failed
    assert calls == []


@pytest.mark.parametrize(
    "fail_on,expected", [("critical", 0), ("high", 2), ("none", 0), ("info", 2)]
)
def test_exit_policy_severity(fail_on, expected, sample_report):
    assert exit_code(sample_report, fail_on) == expected


def test_incomplete_policy_explicit_opt_in():
    report = report_with(item(CheckStatus.NOT_EVALUATED))
    assert exit_code(report, "none") == 1
    assert exit_code(report, "none", "allow") == 0


def test_atomic_failure_preserves_existing_report(tmp_path, monkeypatch, sample_report):
    path = tmp_path / "report.json"
    path.write_text("previous")

    def fail(*a):
        raise OSError("replace failed")

    monkeypatch.setattr("os.replace", fail)
    with pytest.raises(OSError):
        write_report(sample_report, path, "json")
    assert path.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [path]


def test_finding_identity_stable_while_evidence_changes():
    a = Finding(
        severity="HIGH",
        kind="security",
        check="probe",
        target="h",
        rule_id="rule",
        message="90",
        evidence={"n": 90},
    )
    b = a.model_copy(update={"message": "95", "evidence": {"n": 95}, "severity": Severity.CRITICAL})
    assert a.finding_id == b.finding_id
    before = report_with(
        CheckResult(
            check_id="probe", category="linux", target="h", status="completed", findings=[a]
        )
    )
    after = report_with(
        CheckResult(
            check_id="probe", category="linux", target="h", status="completed", findings=[b]
        )
    )
    assert compare_reports(before, after)["severity_changed"] == [a.finding_id]
    unknown = report_with(
        CheckResult(check_id="probe", category="linux", target="h", status="not_evaluated")
    )
    assert compare_reports(before, unknown)["resolved"] == []
    assert compare_reports(before, unknown)["not_comparable"] == [a.finding_id]
    clean = report_with(
        CheckResult(check_id="probe", category="linux", target="h", status="completed")
    )
    assert compare_reports(before, clean)["resolved"] == [a.finding_id]


def test_dry_run_and_doctor_do_not_connect(tmp_path, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("No network allowed")

    monkeypatch.setattr("infraaudit.ssh.SSHClient.connect", forbidden)
    path = tmp_path / "inv.yml"
    path.write_text(
        "hosts:\n - id: h\n   address: localhost\n   tags: [web]\n   ssh:\n     username: test\n"
    )
    result = CliRunner().invoke(
        app, ["run", str(path), "--dry-run", "--host", "h", "--check", "linux.cpu"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == [{"target": "h", "check": "linux.cpu", "skip": ""}]
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert not json.loads(result.stdout)["network_probes"]


def test_parallel_network_bounded_and_results_ordered(monkeypatch):
    registry = CheckRegistry()
    active = 0
    peak = 0
    lock = threading.Lock()

    class Check(BaseCheck):
        check_id = "network.tcp"
        category = CheckCategory.NETWORK
        requires_ssh = False

        def execute(self, ctx):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return [self.finding(severity=Severity.INFO, target=ctx.target, message="ok")]

    registry.register(Check())
    inventory = Inventory(
        tcp_services=[TcpService(id=f"s{i}", host="localhost", port=1) for i in range(8)]
    )
    report = AuditEngine(
        inventory, registry=registry, categories=[CheckCategory.NETWORK], workers=3
    ).run()
    assert 1 < peak <= 3
    assert [r.target for r in report.network_results] == [f"s{i}" for i in range(8)]
    assert report.summary()["complete"]
    assert len(report.inventory_fingerprint) == 64


def test_cancellation_preserves_partial_report(monkeypatch):
    import infraaudit.engine as module

    original = module.as_completed
    calls = 0

    def interrupted(futures):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt
        return original(futures)

    monkeypatch.setattr(module, "as_completed", interrupted)
    report = AuditEngine(Inventory(), categories=[CheckCategory.NETWORK]).run()
    assert not report.summary()["complete"]
    # With work pending, cancellation is explicitly recorded.
    inv = Inventory(tcp_services=[TcpService(id="p", host="localhost", port=1)])
    calls = 0
    monkeypatch.setattr("socket.create_connection", MagicMock(side_effect=TimeoutError()))
    report = AuditEngine(inv, categories=[CheckCategory.NETWORK]).run()
    assert report.cancelled
    assert not report.summary()["complete"]


def test_doctor_inspects_explicit_known_hosts_without_network(tmp_path, monkeypatch):
    from infraaudit.diagnostics import doctor

    known = tmp_path / "known_hosts"
    known.write_text("")
    client = MagicMock()
    client.get_host_keys.return_value.lookup.return_value = None
    monkeypatch.setattr("infraaudit.diagnostics.paramiko.SSHClient", lambda: client)
    host = HostConfig(
        id="h", address="localhost", ssh=SSHAuth(username="u", known_hosts=str(known))
    )
    result = doctor(Inventory(hosts=[host]))
    assert not result["ready"]
    client.load_host_keys.assert_called_once_with(str(known))
    client.connect.assert_not_called()


def test_cancelled_exit_is_never_success_even_when_incomplete_allowed():
    report = report_with(item(CheckStatus.COMPLETED))
    report.cancelled = True
    assert exit_code(report, "none", "allow") == 130


def test_selection_rejects_unknown_hosts_and_checks():
    with pytest.raises(ValueError):
        AuditEngine(Inventory(), host_ids=["missing"])
    with pytest.raises(ValueError):
        AuditEngine(Inventory(), check_ids=["linux.typo"])


def test_docker_cache_is_shared_across_checks():
    from infraaudit.checks.docker.containers import _docker_command

    ctx = context(CommandResult("docker ps -q", 0, "abcdef123456", ""))
    first = _docker_command(ctx, "docker ps -q")
    second = _docker_command(ctx, "docker ps -q")
    assert first is second
    ctx.ssh.run.assert_called_once()


def test_dns_txt_multichunk_normalization(monkeypatch):
    resolver = MagicMock()
    resolver.resolve.return_value = [SimpleNamespace(strings=(b"a", b"b"))]
    monkeypatch.setattr("dns.resolver.Resolver", lambda **kw: resolver)
    assert _resolve_dns("txt.invalid", "TXT") == ["ab"]


@pytest.mark.parametrize(
    "stratum,severity", [(0, Severity.HIGH), (2, Severity.INFO), (16, Severity.HIGH)]
)
def test_chrony_normal_requires_valid_stratum(stratum, severity):
    ctx = context(CommandResult("", 0, "", ""))
    ctx.ssh.run.side_effect = [
        CommandResult("", 1, "", "unavailable"),
        CommandResult("", 0, f"Stratum : {stratum}\nLeap status : Normal", ""),
    ]
    assert NtpCheck().run(ctx).findings[0].severity == severity


@pytest.mark.parametrize(
    "code,stderr,expected",
    [
        (127, "not found", "tool_missing"),
        (1, "permission denied while connecting", "permission_denied"),
        (1, "Cannot connect to the Docker daemon", "daemon_unavailable"),
    ],
)
def test_docker_failure_classification(code, stderr, expected):
    from infraaudit.checks.docker.containers import DockerVersionCheck

    ctx = context(CommandResult("", code, "", stderr))
    result = DockerVersionCheck().run(ctx)
    assert not result.success and not result.security_failed
    assert result.diagnostic_evidence["docker_status"] == expected
