"""Preflight local; las conexiones requieren --probe explícito."""

from __future__ import annotations

import importlib.util
import platform
from pathlib import Path
from typing import Any

import paramiko

from infraaudit.config import Inventory
from infraaudit.ssh import SSHClient


def doctor(inventory: Inventory | None = None, probe: bool = False) -> dict[str, Any]:
    checks: list[dict[str, Any]] = [
        {
            "check": "python",
            "ok": tuple(map(int, platform.python_version_tuple()[:2])) >= (3, 12),
            "version": platform.python_version(),
        },
        {"check": "dns_library", "ok": importlib.util.find_spec("dns.resolver") is not None},
    ]
    for host in inventory.hosts if inventory else []:
        if host.ssh.private_key:
            checks.append(
                {
                    "check": "private_key_file",
                    "target": host.id,
                    "ok": Path(host.ssh.private_key).expanduser().is_file(),
                }
            )
        client = paramiko.SSHClient()
        try:
            known_file = (
                Path(host.ssh.known_hosts).expanduser()
                if host.ssh.known_hosts
                else Path.home() / ".ssh" / "known_hosts"
            )
            if known_file.is_file():
                client.load_host_keys(str(known_file))
            hostname = host.address if host.port == 22 else f"[{host.address}]:{host.port}"
            checks.append(
                {
                    "check": "known_host",
                    "target": host.id,
                    "ok": client.get_host_keys().lookup(hostname) is not None,
                }
            )
        except (OSError, paramiko.SSHException):
            checks.append({"check": "known_host", "target": host.id, "ok": False})
        finally:
            client.close()
        if probe:
            try:
                with SSHClient(host) as ssh:
                    ok = ssh.run("true").ok
            except Exception:
                ok = False
            checks.append({"check": "ssh_probe", "target": host.id, "ok": ok})
    return {"ready": all(c["ok"] for c in checks), "network_probes": probe, "checks": checks}
