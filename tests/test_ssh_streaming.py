"""Streaming SSH con ventanas llenas, límites de evidencia y plazo total."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from infraaudit.checks.base import CheckContext, CheckNotEvaluableError
from infraaudit.config import HostConfig, Inventory, SSHAuth
from infraaudit.ssh import CommandResult, SSHClient, SSHError


class Channel:
    def __init__(
        self, stdout: bytes = b"", stderr: bytes = b"", *, complete: bool = True, code: int = 0
    ):
        self.output = [bytearray(stdout), bytearray(stderr)]
        self.closed = False
        self.eof_received = complete
        self.complete = complete
        self.code = code
        self.read_order = []

    def recv_ready(self):
        return bool(self.output[0])

    def recv_stderr_ready(self):
        return bool(self.output[1])

    def read(self, index, size):
        data = bytes(self.output[index][:size])
        del self.output[index][:size]
        self.read_order.append(index)
        return data

    def recv(self, size):
        return self.read(0, size)

    def recv_stderr(self, size):
        return self.read(1, size)

    def exit_status_ready(self):
        return self.complete

    def recv_exit_status(self):
        assert not any(self.output), "No esperar exit status antes de drenar ambos canales"
        return self.code

    def close(self):
        self.closed = True


def make_client(channel: Channel, limit: int = 4194304):
    host = HostConfig(
        id="probe", address="localhost", ssh=SSHAuth(username="test"), max_output_bytes=limit
    )
    client = SSHClient(host)
    remote = MagicMock()
    stdin = MagicMock()
    remote.exec_command.return_value = (
        stdin,
        SimpleNamespace(channel=channel),
        SimpleNamespace(channel=channel),
    )
    client._client = remote
    return client, remote, stdin


def test_large_stdout_and_stderr_are_drained_before_exit_status() -> None:
    channel = Channel(b"O" * 1048576, b"E" * 1048576)
    client, _, stdin = make_client(channel)
    result = client.run("probe")
    assert result.ok
    assert len(result.stdout) == len(result.stderr) == 1048576
    assert channel.read_order[:4] == [0, 1, 0, 1]
    assert channel.closed
    stdin.close.assert_called_once()


def test_combined_limit_drains_but_marks_result_incomplete() -> None:
    channel = Channel(b"O" * 100000, b"E" * 100000)
    client, _, _ = make_client(channel, 1024)
    result = client.run("probe")
    assert result.truncated and not result.ok
    assert len(result.stdout.encode()) + len(result.stderr.encode()) == 1024
    assert not any(channel.output)
    assert channel.closed
    ctx = CheckContext(Inventory(hosts=[client.host]), host=client.host, ssh=MagicMock())
    ctx.ssh.run.return_value = result
    with pytest.raises(CheckNotEvaluableError) as error:
        ctx.command("probe")
    assert error.value.evidence["truncated"] is True


def test_total_timeout_closes_channel_with_partial_evidence() -> None:
    channel = Channel(b"partial", complete=False)
    client, _, _ = make_client(channel)
    started = time.monotonic()
    result = client.run("probe", timeout=1)
    assert time.monotonic() - started < 2
    assert result.timed_out and not result.ok
    assert result.stdout == "partial"
    assert channel.closed


def test_exec_ack_wait_is_bounded_and_connection_closed() -> None:
    client, remote, _ = make_client(Channel())
    closed = threading.Event()
    worker_done = threading.Event()

    def blocked(*args, **kwargs):
        closed.wait(5)
        worker_done.set()
        raise SSHError("closed")

    remote.exec_command.side_effect = blocked
    remote.close.side_effect = closed.set
    started = time.monotonic()
    result = client.run("probe", timeout=1)
    assert time.monotonic() - started < 2
    assert result.timed_out
    assert client._client is None
    assert worker_done.wait(1)


def test_nonzero_exit_status_is_preserved() -> None:
    client, _, _ = make_client(Channel(b"", b"denied", code=126))
    result = client.run("probe")
    assert not result.ok and result.exit_code == 126
    assert result.stderr == "denied"


def test_closed_channel_without_status_is_error() -> None:
    channel = Channel(complete=False)
    channel.closed = True
    client, _, _ = make_client(channel)
    with pytest.raises(SSHError, match="cerrado"):
        client.run("probe")


def test_missing_status_negative_code_is_error() -> None:
    client, _, _ = make_client(Channel(code=-1))
    with pytest.raises(SSHError, match="sin estado"):
        client.run("probe")


def test_receive_failure_closes_channel() -> None:
    channel = Channel(b"probe")
    channel.recv = MagicMock(side_effect=OSError("network error"))
    client, _, _ = make_client(channel)
    with pytest.raises(SSHError, match="canal"):
        client.run("probe")
    assert channel.closed


@pytest.mark.parametrize("timeout", [0, -1])
def test_invalid_timeout_rejected(timeout: int) -> None:
    client, _, _ = make_client(Channel())
    with pytest.raises(ValueError):
        client.run("probe", timeout=timeout)


def test_timeout_open_error_is_not_success() -> None:
    client, remote, _ = make_client(Channel())
    remote.exec_command.side_effect = TimeoutError("open timeout")
    assert client.run("probe").timed_out


def test_truncated_command_result_never_ok() -> None:
    assert not CommandResult("probe", 0, "partial", "", truncated=True).ok


def test_continuous_output_cannot_extend_total_deadline() -> None:
    channel = Channel(complete=False)
    channel.recv_ready = lambda: True
    channel.recv = lambda size: b"X" * size
    client, _, _ = make_client(channel, 1024)
    started = time.monotonic()
    result = client.run("probe", timeout=1)
    assert time.monotonic() - started < 2
    assert result.timed_out and result.truncated
    assert len(result.stdout) == 1024
    assert channel.closed


def test_utf8_split_at_limit_remains_inconclusive() -> None:
    channel = Channel(b"A" * 1023 + "á".encode())
    client, _, _ = make_client(channel, 1024)
    result = client.run("probe")
    assert result.truncated and not result.ok
    assert result.stdout.endswith("\ufffd")


def test_open_exception_closes_connection() -> None:
    client, remote, _ = make_client(Channel())
    remote.exec_command.side_effect = OSError("connection lost")
    with pytest.raises(SSHError, match="abrir"):
        client.run("probe")
    remote.close.assert_called_once()
    assert client._client is None


def test_ssh_transport_failure_is_inconclusive() -> None:
    from infraaudit.checks.linux.system import HostnameCheck
    from infraaudit.models import Assessment

    host = HostConfig(id="test", address="localhost", ssh=SSHAuth(username="test"))
    remote = MagicMock()
    remote.run.side_effect = SSHError("transport interrupted")
    ctx = CheckContext(Inventory(hosts=[host]), host=host, ssh=remote)
    result = HostnameCheck().run(ctx)
    assert result.assessment == Assessment.INCONCLUSIVE
    assert not result.security_failed
    assert result.findings == []


@pytest.mark.parametrize("limit", [0, 1023, 67108865])
def test_evidence_limit_must_be_bounded(limit: int) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HostConfig(
            id="test", address="localhost", ssh=SSHAuth(username="test"), max_output_bytes=limit
        )
