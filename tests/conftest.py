"""Fixtures compartidas."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from infraaudit.config import Inventory, load_inventory
from infraaudit.models import (
    AuditReport,
    CheckCategory,
    CheckResult,
    Finding,
    HostResult,
    Severity,
)


@pytest.fixture
def examples_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def sample_inventory(examples_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Inventory:
    monkeypatch.setenv("INFRAAUDIT_SSH_USER", "tester")
    monkeypatch.setenv("INFRAAUDIT_SSH_KEY", "/tmp/fake_key")
    return load_inventory(examples_dir / "inventory.example.yml")


@pytest.fixture
def sample_report() -> AuditReport:
    finding = Finding(
        severity=Severity.HIGH,
        check="linux.memory",
        target="web-01",
        message="Memoria usada: 90%",
        recommendation="Revisar procesos",
        evidence={"mem_percent": 90},
        category=CheckCategory.LINUX,
    )
    return AuditReport(
        inventory_path="examples/inventory.example.yml",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        categories=[CheckCategory.LINUX, CheckCategory.NETWORK],
        host_results=[
            HostResult(
                host_id="web-01",
                hostname="web-01",
                address="10.0.0.1",
                check_results=[
                    CheckResult(
                        check_id="linux.memory",
                        category=CheckCategory.LINUX,
                        target="web-01",
                        success=True,
                        findings=[finding],
                        duration_ms=12.5,
                    )
                ],
            )
        ],
        network_results=[
            CheckResult(
                check_id="network.tcp",
                category=CheckCategory.NETWORK,
                target="ssh-local",
                success=True,
                findings=[
                    Finding(
                        severity=Severity.INFO,
                        check="network.tcp",
                        target="ssh-local",
                        message="TCP abierto",
                        category=CheckCategory.NETWORK,
                    )
                ],
            )
        ],
    )


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Ejecutar servicios temporales HTTP/TCP/TLS en loopback",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-integration"):
        return
    skip = pytest.mark.skip(reason="Requiere --run-integration y sockets loopback")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)
