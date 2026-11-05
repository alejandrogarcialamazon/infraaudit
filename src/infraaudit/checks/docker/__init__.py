"""Checks de Docker."""

from __future__ import annotations

from infraaudit.checks.base import BaseCheck
from infraaudit.checks.docker.containers import (
    DockerContainersCheck,
    DockerNetworksCheck,
    DockerResourcesCheck,
    DockerSecurityCheck,
    DockerVersionCheck,
    DockerVolumesCheck,
)

ALL_DOCKER_CHECKS: list[BaseCheck] = [
    DockerVersionCheck(),
    DockerContainersCheck(),
    DockerResourcesCheck(),
    DockerSecurityCheck(),
    DockerNetworksCheck(),
    DockerVolumesCheck(),
]

__all__ = ["ALL_DOCKER_CHECKS"]
