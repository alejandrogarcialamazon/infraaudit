"""Servicios reales efímeros; sin acceso a infraestructura ni red externa."""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from tests.test_security_assessment import http_context
from typer.testing import CliRunner

from infraaudit.checks.network.services import HttpCheck, TcpPortCheck
from infraaudit.cli import app
from infraaudit.config import TcpService
from infraaudit.models import Assessment, FindingKind

pytestmark = pytest.mark.integration


class Health(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(500 if self.path == "/down" else 200)
        self.end_headers()
        self.wfile.write(b"health")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def server():
    instance = ThreadingHTTPServer(("127.0.0.1", 0), Health)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def test_real_http_and_tcp_healthy(server, monkeypatch) -> None:
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    port = server.server_address[1]
    ctx = http_context(f"http://127.0.0.1:{port}/health")
    assert HttpCheck().run(ctx).assessment == Assessment.PASSED
    ctx.extras = {"tcp_service": TcpService(id="tcp", host="127.0.0.1", port=port)}
    assert TcpPortCheck().run(ctx).assessment == Assessment.PASSED


def test_real_http_500_is_operational(server, monkeypatch) -> None:
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    result = HttpCheck().run(http_context(f"http://127.0.0.1:{server.server_address[1]}/down"))
    assert result.assessment == Assessment.FAILED
    assert not result.security_failed
    assert result.findings[0].kind == FindingKind.OPERATIONAL


@pytest.fixture
def certificate(tmp_path):
    openssl = shutil.which("openssl")
    assert openssl, "La prueba TLS requiere openssl"
    key, cert = tmp_path / "test.key", tmp_path / "test.crt"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    return key, cert


@pytest.fixture
def tls_server(certificate):
    key, cert = certificate
    instance = ThreadingHTTPServer(("127.0.0.1", 0), Health)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    instance.socket = context.wrap_socket(instance.socket, server_side=True)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance, cert
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def test_real_untrusted_tls_is_confirmed_policy_failure(tls_server, monkeypatch) -> None:
    instance, _ = tls_server
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    result = HttpCheck().run(http_context(f"https://127.0.0.1:{instance.server_address[1]}/"))
    assert result.assessment == Assessment.INCONCLUSIVE
    assert result.security_failed
    assert result.findings[0].kind == FindingKind.SECURITY


def test_real_trusted_tls_near_expiry_is_security_failure(tls_server, monkeypatch) -> None:
    instance, cert = tls_server
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    result = HttpCheck().run(http_context(f"https://127.0.0.1:{instance.server_address[1]}/"))
    assert result.assessment == Assessment.FAILED
    assert result.success
    assert result.security_failed
    assert result.findings[-1].evidence["days_left"] <= 1


def test_cli_refused_port_saves_critical_operational_result(tmp_path: Path) -> None:
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))  # Bound without listen: deterministic refused connection.
        port = reserved.getsockname()[1]
        inventory = tmp_path / "inventory.yml"
        inventory.write_text(
            f"tcp_services:\n  - id: closed\n    host: 127.0.0.1\n    port: {port}\n"
        )
        output = tmp_path / "results.json"
        result = CliRunner().invoke(app, ["run", str(inventory), "-o", str(output), "-f", "html"])
        assert result.exit_code == 2
        data = json.loads(output.read_text())
        assert data["summary"]["complete"]
        assert data["summary"]["security_findings"] == 0
        assert data["network_results"][0]["assessment"] == "failed"
        assert output.with_suffix(".html").is_file()
