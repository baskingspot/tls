import os
import select
import socket
import subprocess
import time
from pathlib import Path

import pytest

CONF_DIR = Path(__file__).resolve().parents[1]
CLIENT_BIN = CONF_DIR / "zig-out" / "bin" / "anvil_client"


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def _read_until(proc: subprocess.Popen, expected: bytes) -> bytes:
    assert proc.stdout is not None
    output = bytearray()
    deadline = time.monotonic() + 10
    while expected not in output and time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], deadline - time.monotonic())
        if not ready:
            break
        chunk = os.read(proc.stdout.fileno(), 4096)
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


@pytest.mark.requires_capability("server_group.x25519", "certificate_verify.ecdsa_secp256r1_sha256")
def test_openssl_client_exchanges_application_data_with_tls_server(tls_server):
    payload = b"tls-server-openssl-client\n"
    client = subprocess.Popen(
        [
            "openssl",
            "s_client",
            "-connect",
            f"127.0.0.1:{tls_server['port']}",
            "-tls1_3",
            "-alpn",
            "http/1.1",
            "-quiet",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    try:
        assert client.stdin is not None
        os.write(client.stdin.fileno(), payload)
        client.stdin.close()
        output = _read_until(client, payload)
        assert payload in output, output.decode(errors="replace")
    finally:
        _stop(client)


@pytest.mark.requires_capability("client_group.x25519", "certificate_verify.ecdsa_secp256r1_sha256")
def test_tls_client_exchanges_application_data_with_openssl_server(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ],
        capture_output=True,
        check=True,
    )

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = subprocess.Popen(
        [
            "openssl",
            "s_server",
            "-accept",
            f"127.0.0.1:{port}",
            "-cert",
            str(cert),
            "-key",
            str(key),
            "-tls1_3",
            "-alpn",
            "h2",
            "-quiet",
            "-naccept",
            "1",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    env = os.environ.copy()
    env.update(
        HOST="127.0.0.1",
        PORT=str(port),
        TLS_INSECURE_NO_CHAIN_ANCHOR="1",
        TLS_INSECURE_NO_HOST_NAME="1",
    )
    client = subprocess.Popen(
        [str(CLIENT_BIN)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    try:
        assert server.stdin is not None
        payload = b"tls-client-openssl-server\n"
        os.write(server.stdin.fileno(), payload)
        output = _read_until(server, payload)
        assert payload in output, output.decode(errors="replace")
        assert client.poll() is None
    finally:
        _stop(client)
        _stop(server)
