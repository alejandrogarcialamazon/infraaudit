"""Tests de registry y engine (sin SSH real)."""

from __future__ import annotations

from infraaudit.checks import build_default_registry
from infraaudit.engine import AuditEngine
from infraaudit.models import CheckCategory


def test_default_registry_has_categories() -> None:
    registry = build_default_registry()
    ids = {c.check_id for c in registry.all()}
    assert "linux.hostname" in ids
    assert "docker.version" in ids
    assert "network.http" in ids
    assert len(registry.by_category(CheckCategory.LINUX)) >= 10


def test_engine_network_only(sample_inventory, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "infraaudit.checks.network.services._resolve_dns",
        lambda *a, **k: ["1.1.1.1"],
    )
    engine = AuditEngine(
        inventory=sample_inventory,
        categories=[CheckCategory.NETWORK],
    )
    # Evitar HTTP externo lento: vaciar http_services
    sample_inventory.http_services.clear()
    sample_inventory.tcp_services.clear()
    report = engine.run(inventory_path="examples/inventory.example.yml")
    assert report.host_results == []
    assert len(report.network_results) == len(sample_inventory.dns_records)
    assert report.finished_at is not None


def test_docker_only_skips_ssh_for_disabled_host(sample_inventory, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sample_inventory.hosts[0].docker = False
    sample_inventory.hosts = sample_inventory.hosts[:1]

    def unexpected(self):
        raise AssertionError("No debe abrir SSH sin checks seleccionados")

    monkeypatch.setattr("infraaudit.ssh.SSHClient.connect", unexpected)
    report = AuditEngine(sample_inventory, categories=[CheckCategory.DOCKER]).run()
    assert report.host_results[0].connection_error is None
    assert report.host_results[0].check_results == []
