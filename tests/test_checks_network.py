"""Tests de checks de red."""

from __future__ import annotations

from infraaudit.checks.base import CheckContext
from infraaudit.checks.network.services import DnsCheck, TcpPortCheck
from infraaudit.config import DnsRecord, Inventory, TcpService, Thresholds
from infraaudit.models import Severity


def test_dns_info_without_expected(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "infraaudit.checks.network.services._resolve_dns",
        lambda *a, **k: ["93.184.216.34"],
    )
    inventory = Inventory(name="t", thresholds=Thresholds())
    record = DnsRecord(id="ex", name="example.com", record_type="A", expected=[])
    ctx = CheckContext(inventory=inventory, target=record.id, extras={"dns_record": record})
    findings = DnsCheck().execute(ctx)
    assert findings[0].severity == Severity.INFO


def test_dns_mismatch(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "infraaudit.checks.network.services._resolve_dns",
        lambda *a, **k: ["1.2.3.4"],
    )
    inventory = Inventory(name="t", thresholds=Thresholds())
    record = DnsRecord(
        id="ex",
        name="example.com",
        record_type="A",
        expected=["9.9.9.9"],
    )
    ctx = CheckContext(inventory=inventory, target=record.id, extras={"dns_record": record})
    findings = DnsCheck().execute(ctx)
    assert findings[0].severity == Severity.HIGH


def test_tcp_unreachable() -> None:
    inventory = Inventory(name="t", thresholds=Thresholds())
    service = TcpService(id="closed", host="127.0.0.1", port=1, timeout=0.5)
    ctx = CheckContext(inventory=inventory, target=service.id, extras={"tcp_service": service})
    findings = TcpPortCheck().execute(ctx)
    assert findings[0].severity == Severity.CRITICAL


def test_dns_unresolved_is_not_healthy(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("infraaudit.checks.network.services._resolve_dns", lambda *a: [])
    record = DnsRecord(id="missing", name="missing.invalid")
    ctx = CheckContext(inventory=Inventory(), extras={"dns_record": record})
    result = DnsCheck().run(ctx)
    assert result.status.value == "not_evaluated"
    assert not result.findings


def test_dns_custom_nameserver_is_used(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from types import SimpleNamespace

    from infraaudit.checks.network.services import _resolve_dns

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/dig")
    commands = []

    def run(cmd, **kwargs):
        commands.append(cmd)
        return SimpleNamespace(stdout="203.0.113.10\n")

    monkeypatch.setattr("subprocess.run", run)
    assert _resolve_dns("example.com", "A", "192.0.2.53") == ["203.0.113.10"]
    assert "@192.0.2.53" in commands[0]
