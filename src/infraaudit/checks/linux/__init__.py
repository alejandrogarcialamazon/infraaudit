"""Checks de sistema Linux."""

from __future__ import annotations

from infraaudit.checks.base import BaseCheck
from infraaudit.checks.linux.network import (
    DnsResolversCheck,
    GatewayCheck,
    ListeningPortsCheck,
    NtpCheck,
    SystemdFailedCheck,
)
from infraaudit.checks.linux.storage import FilesystemCheck, InodeCheck, MountsCheck
from infraaudit.checks.linux.system import (
    CpuCheck,
    DistributionCheck,
    HostnameCheck,
    KernelCheck,
    LoadAverageCheck,
    MemoryCheck,
    UptimeCheck,
)

ALL_LINUX_CHECKS: list[BaseCheck] = [
    HostnameCheck(),
    DistributionCheck(),
    KernelCheck(),
    UptimeCheck(),
    CpuCheck(),
    MemoryCheck(),
    LoadAverageCheck(),
    FilesystemCheck(),
    InodeCheck(),
    MountsCheck(),
    GatewayCheck(),
    DnsResolversCheck(),
    NtpCheck(),
    ListeningPortsCheck(),
    SystemdFailedCheck(),
]

__all__ = ["ALL_LINUX_CHECKS"]
