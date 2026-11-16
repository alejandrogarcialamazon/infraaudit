"""Integración real UDP DNS y SSH con servidor Paramiko efímero y Docker simulado."""

from __future__ import annotations

import json
import socket
import socketserver
import threading
import time

import dns.message
import dns.rcode
import dns.rrset
import paramiko
import pytest

from infraaudit.checks.network.services import DnsQueryError, _resolve_dns
from infraaudit.config import HostConfig, Inventory, SSHAuth
from infraaudit.engine import AuditEngine
from infraaudit.models import CheckCategory

pytestmark = pytest.mark.integration


@pytest.fixture
def dns_server():
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            name = str(request.question[0].name)
            if name == "missing.invalid.":
                response.set_rcode(dns.rcode.NXDOMAIN)
            elif name != "empty.invalid.":
                response.answer.append(dns.rrset.from_text(name, 60, "IN", "A", "203.0.113.7"))
            sock.sendto(response.to_wire(), self.client_address)

    instance = socketserver.UDPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance.server_address[1]
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(2)


def test_real_dns_udp_answers_and_negative_responses(dns_server):
    assert _resolve_dns("healthy.invalid", "A", "127.0.0.1", 1, dns_server) == ["203.0.113.7"]
    for name, code in [("missing.invalid", "nxdomain"), ("empty.invalid", "no_answer")]:
        with pytest.raises(DnsQueryError) as error:
            _resolve_dns(name, "A", "127.0.0.1", 1, dns_server)
        assert error.value.code == code


@pytest.fixture
def ssh_server(tmp_path):
    key = paramiko.RSAKey.generate(2048)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    stop = threading.Event()
    transports = []
    commands = []
    known = tmp_path / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")

    class Server(paramiko.ServerInterface):
        def check_auth_password(self, user, password):
            return (
                paramiko.AUTH_SUCCESSFUL
                if (user, password) == ("test", "synthetic")
                else paramiko.AUTH_FAILED
            )

        def get_allowed_auths(self, user):
            return "password"

        def check_channel_request(self, kind, channel_id):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_exec_request(self, channel, command):
            text = command.decode()
            commands.append(text)

            def respond():
                time.sleep(0.02)  # Permitir que Paramiko envíe primero el ACK de exec.
                if text.startswith("docker version"):
                    data = json.dumps({"Server": {"Version": "28.0.0"}})
                elif text.startswith("docker ps -a"):
                    data = json.dumps(
                        {"Names": "probe", "State": "running", "Status": "Up", "ID": "abcdef123456"}
                    )
                elif text == "docker ps -q":
                    data = "abcdef123456"
                elif text.startswith("docker inspect --format"):
                    data = '"/probe"|"1000"|"CMD"|true|{"Name":"always"}|"healthy"'
                else:
                    channel.send_stderr(b"unsupported command")
                    channel.send_exit_status(127)
                    channel.close()
                    return
                channel.sendall((data + "\n").encode())
                channel.send_exit_status(0)
                channel.shutdown_write()
                channel.close()

            threading.Thread(target=respond, daemon=True).start()
            return True

    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            transport = paramiko.Transport(connection)
            transports.append(transport)
            transport.add_server_key(key)
            try:
                transport.start_server(server=Server())
            except paramiko.SSHException:
                continue

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    # Transport retains channels weakly; retain accepted channels until teardown.
    channels = []

    def accept_channels():
        while not stop.is_set():
            for transport in list(transports):
                channel = transport.accept(timeout=0.02)
                if channel:
                    channels.append(channel)
            stop.wait(0.01)

    acceptor = threading.Thread(target=accept_channels, daemon=True)
    acceptor.start()
    host = HostConfig(
        id="integration",
        address="127.0.0.1",
        port=port,
        timeout=3,
        ssh=SSHAuth(
            username="test",
            password="synthetic",
            known_hosts=str(known),
            allow_agent=False,
            look_for_keys=False,
        ),
    )
    try:
        yield host, commands
    finally:
        stop.set()
        listener.close()
        for transport in transports:
            transport.close()
        thread.join(2)
        acceptor.join(2)


def test_real_ssh_docker_protocol_and_selective_inspect(ssh_server):
    host, commands = ssh_server
    report = AuditEngine(
        Inventory(hosts=[host]),
        categories=[CheckCategory.DOCKER],
        check_ids=["docker.version", "docker.containers", "docker.security"],
    ).run()
    assert report.summary()["complete"], [
        (r.check_id, r.status, r.reason) for r in report.all_results
    ]
    assert report.summary()["security_failed_checks"] == 1
    inspect = next(command for command in commands if command.startswith("docker inspect"))
    assert ".Config.Env" not in inspect and "{{json .}}" not in inspect
    assert ".State.Health.Status" in inspect
