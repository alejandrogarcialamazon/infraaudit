"""Cliente SSH read-only con timeouts y manejo robusto de errores."""

from __future__ import annotations

import logging
import queue
import threading
import time
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import Any, Self

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
        truncated: bool = False,
    ) -> None:
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.truncated = truncated

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.truncated

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
        effective_timeout = self.host.timeout if timeout is None else timeout
        if effective_timeout <= 0:
            raise ValueError("El timeout debe ser positivo")
        deadline = time.monotonic() + effective_timeout
        client = self._client
        opened: queue.Queue[Any] = queue.Queue(maxsize=1)

        def open_command() -> None:
            try:
                opened.put(client.exec_command(command, timeout=effective_timeout))
            except Exception as exc:
                opened.put(exc)

        # Paramiko puede esperar indefinidamente el ACK de exec aun con timeout de canal.
        # El hilo daemon permite acotar también esa espera y cerrar la sesión si no responde.
        worker = threading.Thread(target=open_command, daemon=True, name="infraaudit-ssh-exec")
        worker.start()
        try:
            streams = opened.get(timeout=max(0.001, deadline - time.monotonic()))
        except queue.Empty:
            self.close()
            return CommandResult(command, -1, "", "Timeout abriendo comando SSH", timed_out=True)
        except BaseException:
            self.close()
            raise
        if isinstance(streams, Exception):
            self.close()
            if isinstance(streams, TimeoutError):
                return CommandResult(
                    command, -1, "", "Timeout abriendo comando SSH", timed_out=True
                )
            raise SSHError("No se pudo abrir el comando SSH") from streams
        stdin, stdout, _stderr = streams
        channel = stdout.channel
        chunks: list[bytearray] = [bytearray(), bytearray()]
        retained = 0
        truncated = False
        try:
            stdin.close()
            while True:
                if time.monotonic() >= deadline:
                    return CommandResult(
                        command,
                        -1,
                        chunks[0].decode("utf-8", errors="replace"),
                        chunks[1].decode("utf-8", errors="replace"),
                        timed_out=True,
                        truncated=truncated,
                    )
                received = False
                for index, ready, read in (
                    (0, channel.recv_ready, channel.recv),
                    (1, channel.recv_stderr_ready, channel.recv_stderr),
                ):
                    if ready():
                        data = read(32768)
                        available = max(0, self.host.max_output_bytes - retained)
                        chunks[index].extend(data[:available])
                        retained += min(len(data), available)
                        truncated = truncated or len(data) > available
                        received = True
                drained = not channel.recv_ready() and not channel.recv_stderr_ready()
                if (
                    channel.exit_status_ready()
                    and drained
                    and (channel.eof_received or channel.closed)
                ):
                    code = channel.recv_exit_status()
                    if code < 0:
                        raise SSHError("Canal SSH cerrado sin estado de salida")
                    return CommandResult(
                        command,
                        code,
                        chunks[0].decode("utf-8", errors="replace"),
                        chunks[1].decode("utf-8", errors="replace"),
                        truncated=truncated,
                    )
                if channel.closed and drained:
                    raise SSHError("Canal SSH cerrado antes de completar el comando")
                if not received:
                    time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        except (paramiko.SSHException, OSError) as exc:
            raise SSHError("Error leyendo el canal SSH") from exc
        finally:
            try:
                channel.close()
            except (paramiko.SSHException, OSError):
                logger.debug("No se pudo cerrar limpiamente el canal de %s", self.host.id)

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
