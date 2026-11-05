"""Tests del CLI."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from infraaudit.cli import app
from infraaudit.reporting import write_report

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_cli_validate(examples_dir: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("INFRAAUDIT_SSH_USER", "tester")
    monkeypatch.setenv("INFRAAUDIT_SSH_KEY", "/tmp/fake_key")
    result = runner.invoke(app, ["validate", str(examples_dir / "inventory.example.yml")])
    assert result.exit_code == 0
    assert "OK" in result.stdout or "OK" in result.output


def test_cli_list_checks() -> None:
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    assert "linux.hostname" in result.output


def test_cli_report(sample_report, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    results = tmp_path / "results.json"
    write_report(sample_report, results, "json")
    out = tmp_path / "report.html"
    result = runner.invoke(
        app,
        ["report", str(results), "--format", "html", "--output", str(out)],
    )
    assert result.exit_code == 0
    assert out.is_file()
    assert "InfraAudit" in out.read_text(encoding="utf-8")


def test_run_invalid_format_does_not_start_audit(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def unexpected(*args, **kwargs):
        raise AssertionError("No debe iniciar conexiones")

    monkeypatch.setattr("infraaudit.cli.AuditEngine.from_path", unexpected)
    result = runner.invoke(app, ["run", "unused.yml", "--format", "invalid"])
    assert result.exit_code == 2
    assert not (tmp_path / "results.json").exists()


def test_run_ssh_failure_returns_error(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from infraaudit.ssh import SSHError

    inventory = tmp_path / "inventory.yml"
    inventory.write_text(
        "hosts:\n  - id: test\n    address: localhost\n    ssh:\n      username: test\n"
    )

    def fail_connect(self):
        raise SSHError("Conexión de prueba fallida")

    monkeypatch.setattr("infraaudit.ssh.SSHClient.connect", fail_connect)
    output = tmp_path / "results.json"
    result = runner.invoke(app, ["run", str(inventory), "-o", str(output)])
    assert result.exit_code == 1
    assert output.is_file()
    assert "Conexión de prueba fallida" in output.read_text()
