"""Tests del cliente SSH (modo read-only)."""

from __future__ import annotations

import pytest

from infraaudit.config import HostConfig, SSHAuth
from infraaudit.ssh import SSHClient, SSHError


def test_blocked_destructive_command() -> None:
    host = HostConfig(
        id="h1",
        address="127.0.0.1",
        ssh=SSHAuth(username="u", password="p", look_for_keys=False),
    )
    client = SSHClient(host)
    client._client = object()  # type: ignore[assignment]
    with pytest.raises(SSHError, match="bloqueado"):
        client._assert_readonly("rm -rf /tmp/data")


def test_allowed_readonly_command() -> None:
    host = HostConfig(
        id="h1",
        address="127.0.0.1",
        ssh=SSHAuth(username="u", password="p", look_for_keys=False),
    )
    client = SSHClient(host)
    client._assert_readonly("cat /proc/uptime")
    client._assert_readonly("docker ps -a")


def test_ssh_rejects_unknown_host_keys(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from unittest.mock import MagicMock

    import paramiko

    remote = MagicMock()
    monkeypatch.setattr("infraaudit.ssh.paramiko.SSHClient", lambda: remote)
    host = HostConfig(id="test", address="localhost", ssh=SSHAuth(username="test"))
    with SSHClient(host):
        remote.load_system_host_keys.assert_called_once()
        policy = remote.set_missing_host_key_policy.call_args.args[0]
        assert isinstance(policy, paramiko.RejectPolicy)
    remote.close.assert_called_once()
