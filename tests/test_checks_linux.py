"""Tests unitarios de checks Linux con SSH mock."""

from __future__ import annotations

from typing import Any

from infraaudit.checks.base import CheckContext
from infraaudit.checks.linux.system import HostnameCheck, MemoryCheck, UptimeCheck
from infraaudit.config import HostConfig, Inventory, SSHAuth, Thresholds
from infraaudit.models import Severity
from infraaudit.ssh import CommandResult


class FakeSSH:
    def __init__(self, outputs: dict[str, CommandResult]) -> None:
        self.outputs = outputs

    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        for key, value in self.outputs.items():
            if key in command:
                return value
        return CommandResult(command, 1, "", "not mocked")


def _ctx(ssh: Any) -> CheckContext:
    host = HostConfig(
        id="web-01",
        address="10.0.0.1",
        ssh=SSHAuth(username="u", password="p", look_for_keys=False),
    )
    inventory = Inventory(name="t", hosts=[host], thresholds=Thresholds())
    return CheckContext(inventory=inventory, host=host, ssh=ssh, target=host.id)


def test_hostname_check() -> None:
    ssh = FakeSSH({"hostname": CommandResult("hostname", 0, "web-01\n", "")})
    findings = HostnameCheck().execute(_ctx(ssh))
    assert findings[0].severity == Severity.INFO
    assert "web-01" in findings[0].message


def test_uptime_recent_reboot() -> None:
    ssh = FakeSSH({"uptime": CommandResult("cat /proc/uptime", 0, "60.0 0.0\n", "")})
    findings = UptimeCheck().execute(_ctx(ssh))
    assert findings[0].severity == Severity.MEDIUM


def test_memory_critical() -> None:
    meminfo = """MemTotal:       1000000 kB
MemAvailable:     20000 kB
MemFree:          10000 kB
"""
    ssh = FakeSSH({"meminfo": CommandResult("cat /proc/meminfo", 0, meminfo, "")})
    findings = MemoryCheck().execute(_ctx(ssh))
    assert findings[0].severity == Severity.CRITICAL
