"""Checks de red externos."""

from __future__ import annotations

from infraaudit.checks.base import BaseCheck
from infraaudit.checks.network.services import DnsCheck, HttpCheck, TcpPortCheck

ALL_NETWORK_CHECKS: list[BaseCheck] = [
    DnsCheck(),
    TcpPortCheck(),
    HttpCheck(),
]

__all__ = ["ALL_NETWORK_CHECKS"]
