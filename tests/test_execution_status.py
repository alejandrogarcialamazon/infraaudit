"""Regresiones de cobertura y fuentes de datos no evaluables."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from infraaudit.checks import build_default_registry
from infraaudit.checks.base import BaseCheck, CheckContext
from infraaudit.checks.docker.containers import DockerContainersCheck, DockerSecurityCheck
from infraaudit.checks.linux.network import SystemdFailedCheck
from infraaudit.config import HostConfig, Inventory, SSHAuth
from infraaudit.engine import AuditEngine
from infraaudit.models import AuditReport, CheckCategory, CheckResult, CheckStatus
from infraaudit.reporting import get_reporter
from infraaudit.ssh import CommandResult, SSHError

HOST_CHECKS = [c for c in build_default_registry().all() if c.requires_ssh]


def context(result: CommandResult) -> CheckContext:
    host = HostConfig(id="test", address="localhost", ssh=SSHAuth(username="test"))
    ssh = MagicMock()
    ssh.run.return_value = result
    return CheckContext(inventory=Inventory(hosts=[host]), host=host, ssh=ssh, target=host.id)


@pytest.mark.parametrize("check", HOST_CHECKS, ids=lambda c: c.check_id)
@pytest.mark.parametrize("code,timed_out", [(127, False), (126, False), (-1, True)])
def test_unavailable_source_is_never_healthy(check: BaseCheck, code: int, timed_out: bool) -> None:
    result = check.run(context(CommandResult("probe", code, "", "unavailable", timed_out)))
    assert result.status == CheckStatus.NOT_EVALUATED
    assert not result.success
    assert result.reason
    assert not result.findings


@pytest.mark.parametrize(
    "check", [SystemdFailedCheck(), DockerContainersCheck(), DockerSecurityCheck()]
)
def test_successful_empty_resource_list_is_valid(check: BaseCheck) -> None:
    result = check.run(context(CommandResult("probe", 0, "", "")))
    assert result.status == CheckStatus.COMPLETED
    assert result.success


@pytest.mark.parametrize(
    "check_id", ["linux.memory", "linux.filesystems", "linux.inodes", "linux.cpu"]
)
def test_missing_required_data_is_not_evaluated(check_id: str) -> None:
    check = build_default_registry().get(check_id)
    assert check.run(context(CommandResult("probe", 0, "", ""))).status != CheckStatus.COMPLETED


def test_invalid_memory_counters_are_not_healthy() -> None:
    check = build_default_registry().get("linux.memory")
    result = check.run(context(CommandResult("probe", 0, "MemFree: 10 kB\n", "")))
    assert result.status == CheckStatus.NOT_EVALUATED


def report_with(*results: CheckResult) -> AuditReport:
    return AuditReport(
        inventory_path="test.yml",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        network_results=list(results),
    )


def item(status: CheckStatus) -> CheckResult:
    return CheckResult(
        check_id="test",
        target="test",
        category=CheckCategory.NETWORK,
        status=status,
        reason="test" if status != CheckStatus.COMPLETED else None,
    )


def test_coverage_excludes_explicit_skips_but_counts_inconclusive() -> None:
    report = report_with(
        item(CheckStatus.COMPLETED), item(CheckStatus.SKIPPED), item(CheckStatus.NOT_EVALUATED)
    )
    summary = report.summary()
    assert summary["planned_checks"] == 3
    assert summary["selected_checks"] == 2
    assert summary["coverage_percent"] == 50
    assert not summary["complete"]
    assert report_with().summary()["complete"] is False
    assert report_with(item(CheckStatus.SKIPPED)).summary()["complete"] is False
    assert report_with(item(CheckStatus.COMPLETED)).summary()["complete"] is True


def test_legacy_results_map_execution_status() -> None:
    legacy = CheckResult.model_validate(
        dict(check_id="test", target="test", category="linux", success=False, error="old error")
    )
    assert legacy.status == CheckStatus.ERROR
    assert legacy.reason == "old error"
    assert not legacy.success


def test_explicit_contradictory_success_is_rejected() -> None:
    with pytest.raises(ValidationError):
        CheckResult.model_validate(
            dict(
                check_id="test",
                target="test",
                category="linux",
                status="not_evaluated",
                success=True,
            )
        )


def test_failed_ssh_counts_every_selected_check(monkeypatch: pytest.MonkeyPatch) -> None:
    host = HostConfig(
        id="test",
        address="localhost",
        ssh=SSHAuth(username="test"),
        docker=False,
        skip_checks=["linux.hostname"],
    )

    def fail(self: object) -> None:
        raise SSHError("probe denied")

    monkeypatch.setattr("infraaudit.ssh.SSHClient.connect", fail)
    report = AuditEngine(Inventory(hosts=[host]), categories=[CheckCategory.LINUX]).run()
    summary = report.summary()
    assert summary["by_status"]["skipped"] == 1
    assert summary["by_status"]["not_evaluated"] == len(HOST_CHECKS) - 6 - 1
    assert not summary["complete"]
    assert summary["coverage_percent"] == 0


@pytest.mark.parametrize("fmt", ["json", "markdown", "html"])
def test_report_exposes_no_data_and_coverage(fmt: str) -> None:
    rendered = get_reporter(fmt).render(report_with(item(CheckStatus.NOT_EVALUATED)))
    assert "not_evaluated" in rendered
    assert "coverage" in rendered.lower()


def test_html_escapes_diagnostic_reason() -> None:
    result = item(CheckStatus.NOT_EVALUATED)
    result.reason = "<script>probe</script>"
    rendered = get_reporter("html").render(report_with(result))
    assert "<script>probe</script>" not in rendered
    assert "&lt;script&gt;" in rendered


@pytest.mark.parametrize("check", HOST_CHECKS, ids=lambda c: c.check_id)
def test_empty_output_only_valid_for_explicit_empty_resources(check: BaseCheck) -> None:
    result = check.run(context(CommandResult("probe", 0, "", "")))
    valid_empty = {
        "linux.systemd_failed",
        "docker.containers",
        "docker.security",
        "docker.resources",
        "docker.networks",
        "docker.volumes",
    }
    assert result.success == (check.check_id in valid_empty)


@pytest.mark.parametrize(
    "check_id,output",
    [
        ("linux.memory", "MemTotal: 10 kB\nMemAvailable: 20 kB\n"),
        ("linux.systemd_failed", "unparseable"),
        ("linux.listening_ports", "unparseable"),
        ("docker.containers", '{"State":"running"}'),
        ("docker.networks", "unparseable"),
        ("docker.volumes", "unparseable"),
        ("docker.version", "{}"),
        ("docker.security", "invalid-id"),
    ],
)
def test_malformed_data_cannot_report_completed(check_id: str, output: str) -> None:
    result = (
        build_default_registry().get(check_id).run(context(CommandResult("probe", 0, output, "")))
    )
    assert result.status != CheckStatus.COMPLETED


def test_critical_finding_can_have_completed_execution() -> None:
    result = (
        build_default_registry()
        .get("linux.memory")
        .run(context(CommandResult("probe", 0, "MemTotal: 100 kB\nMemAvailable: 1 kB\n", "")))
    )
    assert result.status == CheckStatus.COMPLETED
    assert result.findings[0].severity.value == "CRITICAL"


def test_empty_plugin_result_is_inconclusive() -> None:
    class Empty(BaseCheck):
        def execute(self, ctx):
            return []

    result = Empty().run(context(CommandResult("probe", 0, "", "")))
    assert result.status == CheckStatus.NOT_EVALUATED
