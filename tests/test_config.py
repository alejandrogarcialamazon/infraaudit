"""Tests de carga y validación de inventario."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from infraaudit.config import InventoryError, expand_env, load_inventory, validate_inventory_file


def test_expand_env_with_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_VAR", raising=False)
    assert expand_env("${MISSING_VAR:-fallback}") == "fallback"
    monkeypatch.setenv("MISSING_VAR", "present")
    assert expand_env("${MISSING_VAR:-fallback}") == "present"


def test_load_example_inventory(sample_inventory) -> None:  # type: ignore[no-untyped-def]
    assert sample_inventory.name == "demo-lab"
    assert len(sample_inventory.hosts) >= 1
    assert sample_inventory.hosts[0].ssh.username == "tester"


def test_validate_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InventoryError, match="no encontrado"):
        validate_inventory_file(tmp_path / "nope.yml")


def test_duplicate_host_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("U", "u")
    data = {
        "name": "bad",
        "hosts": [
            {
                "id": "a",
                "address": "1.1.1.1",
                "ssh": {"username": "${U}", "password": "x", "look_for_keys": False},
            },
            {
                "id": "a",
                "address": "2.2.2.2",
                "ssh": {"username": "${U}", "password": "x", "look_for_keys": False},
            },
        ],
    }
    path = tmp_path / "inv.yml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    with pytest.raises(InventoryError):
        load_inventory(path)


def test_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "bad.yml"
    path.write_text(":\n  - invalid: [", encoding="utf-8")
    with pytest.raises(InventoryError, match="YAML inválido"):
        load_inventory(path)


def test_missing_environment_variable_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INFRAAUDIT_TEST_MISSING", raising=False)
    with pytest.raises(InventoryError, match="INFRAAUDIT_TEST_MISSING"):
        expand_env("${INFRAAUDIT_TEST_MISSING}")
