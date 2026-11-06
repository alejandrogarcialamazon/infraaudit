"""Cliente SSH read-only con timeouts y manejo robusto de errores."""

from __future__ import annotations

import logging
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import Self

import paramiko

from infraaudit.config import HostConfig, SSHAuth

logger = logging.getLogger(__name__)


class SSHError(Exception):
    """Error de conexión o ejecución SSH."""


class CommandResult:
    """Resultado de un comando remoto (solo lectura)."""

    def __init__(
        self,
        command: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        timed_out: bool = False,
    ) -> None:
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        return self.stdout.strip()


class SSHClient(AbstractContextManager["SSHClient"]):
    """Wrapper paramiko limitado a operaciones no destructivas."""

    # Prefijos/comandos bloqueados para reforzar el modo read-only.
    _BLOCKED_PATTERNS = (
        "rm ",
        "rm\t",
        "mkfs",
        "dd if=",
        "shutdown",
        "reboot",
        "poweroff",
        "halt",
        "userdel",
        "passwd ",
        "chmod 777",
        "> /",
        "tee ",
        "mv ",
        "truncate",
        "kill -9",
        "systemctl stop",
        "systemctl restart",
        "systemctl disable",
        "docker rm",
        "docker rmi",
        "docker stop",
        "docker kill",
        "docker volume rm",
        "iptables -F",
    )

    def __init__(self, host: HostConfig) -> None:
        self.host = host
        self._client: paramiko.SSHClient | None = None

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def connect(self) -> None:
        auth = self.host.ssh
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs: dict[str, object] = {
            "hostname": self.host.address,
            "port": self.host.port,
            "username": auth.username,
            "timeout": self.host.timeout,
            "allow_agent": auth.allow_agent,
            "look_for_keys": auth.look_for_keys,
            "banner_timeout": self.host.timeout,
            "auth_timeout": self.host.timeout,
        }

        if auth.password:
            connect_kwargs["password"] = auth.password.get_secret_value()

        pkey = self._load_private_key(auth)
        if pkey is not None:
            connect_kwargs["pkey"] = pkey

        try:
            client.connect(**connect_kwargs)  # type: ignore[arg-type]
        except (paramiko.SSHException, OSError) as exc:
            client.close()
            raise SSHError(
                f"No se pudo conectar a {self.host.id} ({self.host.address}): {exc}"
            ) from exc

        self._client = client
        logger.info("SSH conectado a %s (%s)", self.host.id, self.host.address)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        """Ejecuta un comando remoto de solo lectura."""
        if self._client is None:
            raise SSHError("Cliente SSH no conectado")

        self._assert_readonly(command)
        effective_timeout = timeout or self.host.timeout
        logger.debug("[%s] RUN: %s", self.host.id, command)

        try:
            _stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=effective_timeout,
            )
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return CommandResult(command, exit_code, out, err)
        except TimeoutError as exc:
            logger.warning("[%s] Timeout ejecutando: %s", self.host.id, command)
            return CommandResult(command, -1, "", str(exc), timed_out=True)
        except (paramiko.SSHException, OSError) as exc:
            raise SSHError(f"Error ejecutando '{command}': {exc}") from exc

    def _assert_readonly(self, command: str) -> None:
        lowered = command.lower().strip()
        for pattern in self._BLOCKED_PATTERNS:
            if pattern in lowered:
                raise SSHError(
                    f"Comando bloqueado (modo read-only): patrón '{pattern}' en '{command}'"
                )

    @staticmethod
    def _load_private_key(auth: SSHAuth) -> paramiko.PKey | None:
        if not auth.private_key:
            return None

        key_path = Path(auth.private_key).expanduser()
        if not key_path.is_file():
            raise SSHError(f"Clave privada no encontrada: {key_path}")

        passphrase = (
            auth.private_key_passphrase.get_secret_value() if auth.private_key_passphrase else None
        )
        loaders = (
            paramiko.Ed25519Key,
            paramiko.RSAKey,
            paramiko.ECDSAKey,
        )
        last_error: Exception | None = None
        for loader in loaders:
            try:
                return loader.from_private_key_file(str(key_path), password=passphrase)
            except paramiko.SSHException as exc:
                last_error = exc
                continue
        raise SSHError(f"No se pudo cargar la clave privada: {last_error}")
