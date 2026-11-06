"""Credenciales sintéticas: errores, reportes y validación antes de conexiones."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from infraaudit.checks.base import BaseCheck, CheckContext
from infraaudit.cli import app
from infraaudit.config import (
    HostConfig,
    HttpService,
    Inventory,
    InventoryError,
    SSHAuth,
    Thresholds,
    load_inventory,
)
from infraaudit.logging_setup import RedactingFormatter
from infraaudit.models import CheckCategory, CheckResult, CheckStatus
from infraaudit.reporting import get_reporter
from infraaudit.security import redact, secret_scope
from tests.test_execution_status import report_with

SECRET = "synthetic-Credential-8z!"


def test_auth_repr_dump_and_validation_hide_secrets() -> None:
    auth = SSHAuth(username="test", password=SECRET, private_key_passphrase=SECRET)
    assert SECRET not in repr(auth)
    assert SECRET not in auth.model_dump_json()
    assert auth.password.get_secret_value() == SECRET
    with pytest.raises(ValidationError) as error:
        HostConfig(id="test", address="localhost", port=0, ssh=auth)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize("fmt", ["json", "html", "markdown"])
def test_nested_report_credentials_are_redacted(fmt: str) -> None:
    result = CheckResult(
        check_id="probe",
        category=CheckCategory.NETWORK,
        target="probe",
        status=CheckStatus.NOT_EVALUATED,
        reason=f"failed https://user:{SECRET}@example.invalid?token={SECRET}",
        diagnostic_evidence={"Authorization": f"Bearer {SECRET}", "nested": [{"password": SECRET}]},
    )
    rendered = get_reporter(fmt).render(report_with(result))
    assert SECRET not in rendered
    assert "REDACTED" in rendered
    if fmt == "json":
        json.loads(rendered)


def test_plugin_error_redacts_known_password_and_logs(caplog) -> None:
    class Broken(BaseCheck):
        def execute(self, ctx):
            raise RuntimeError(f"error contains {SECRET}")

    host = HostConfig(id="test", address="localhost", ssh=SSHAuth(username="test", password=SECRET))
    result = Broken().run(CheckContext(Inventory(hosts=[host])))
    assert SECRET not in result.model_dump_json()
    assert SECRET not in caplog.text
    assert result.status == CheckStatus.ERROR


def test_logging_formatter_and_scope_cleanup() -> None:
    record = logging.LogRecord(
        "infraaudit", logging.ERROR, "test", 1, "failure %s", (SECRET,), None
    )
    with secret_scope([SECRET]):
        assert SECRET not in RedactingFormatter().format(record)
        assert SECRET not in str(redact({"raw": SECRET}))
    assert redact(SECRET) == SECRET


@pytest.mark.parametrize(
    "payload",
    [
        {"hosts": [{"id": "x", "address": "localhost", "ssh": {"username": "u"}, "port": 0}]},
        {"hosts": [{"id": "x", "address": "localhost", "ssh": {"username": "u"}, "port": 65536}]},
        {"unknown_option": True},
        {
            "hosts": [
                {"id": "x", "address": "localhost", "ssh": {"username": "u", "pasword": SECRET}}
            ]
        },
        {"http_services": [{"id": "x", "url": "ftp://example.invalid"}]},
        {"http_services": [{"id": "x", "url": "https://"}]},
        {"http_services": [{"id": "x", "url": "https://example.invalid:99999"}]},
        {"http_services": [{"id": "x", "url": "https://example.invalid", "expected_status": []}]},
        {"thresholds": {"cpu_warn_percent": 99, "cpu_crit_percent": 80}},
        {"thresholds": {"mem_warn_percent": float("nan")}},
        {"thresholds": {"tls_warn_days": 5, "tls_crit_days": 7}},
        {"tcp_services": [{"id": "same", "host": "localhost", "port": 22}] * 2},
        {
            "hosts": [
                {
                    "id": "x",
                    "address": "localhost",
                    "ssh": {"username": "u"},
                    "skip_checks": ["linux.typo"],
                }
            ]
        },
    ],
)
def test_invalid_schema_is_rejected(payload: dict) -> None:
    with pytest.raises(ValidationError):
        Inventory.model_validate(payload)


def test_invalid_yaml_and_validation_do_not_echo_secret(tmp_path: Path) -> None:
    path = tmp_path / "bad.yml"
    path.write_text(f"password: {SECRET}\nbroken: [\n")
    with pytest.raises(InventoryError) as error:
        load_inventory(path)
    assert SECRET not in str(error.value)
    path.write_text(
        "hosts:\n - id: x\n   address: localhost\n   port: 0\n   ssh:\n"
        f"     username: u\n     password: {SECRET}\n"
    )
    result = CliRunner().invoke(app, ["validate", str(path)])
    assert result.exit_code == 1
    assert SECRET not in result.output


def test_invalid_inventory_does_not_open_ssh(tmp_path: Path, monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("SSH must not start")

    monkeypatch.setattr("infraaudit.ssh.SSHClient.connect", forbidden)
    path = tmp_path / "bad.yml"
    path.write_text(
        "hosts:\n - id: x\n   address: localhost\n   port: 0\n   ssh:\n     username: u\n"
    )
    assert CliRunner().invoke(app, ["run", str(path)]).exit_code == 1


def test_valid_ipv6_and_thresholds() -> None:
    assert HttpService(id="ipv6", url="https://[::1]:8443/").url
    assert Thresholds(cpu_warn_percent=70, cpu_crit_percent=90)
