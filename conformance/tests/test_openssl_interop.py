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


def _generate_certificate(directory: Path, curve: str = "P-256", subject: str = "localhost"):
    directory.mkdir(parents=True, exist_ok=True)
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            f"ec_paramgen_curve:{curve}",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            f"/CN={subject}",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        capture_output=True,
        check=True,
    )
    return cert, key


def _start_openssl_server(cert: Path, key: Path, group: str | None = None):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    command = [
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
    ]
    if group is not None:
        command.extend(["-groups", group])
    server = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    return server, port


def _start_tls_client(
    port: int,
    ca_file: Path | None = None,
    host_name: str | None = None,
    group: str | None = None,
):
    env = os.environ.copy()
    env.update(HOST="127.0.0.1", PORT=str(port))
    if ca_file is None:
        env.update(TLS_INSECURE_NO_CHAIN_ANCHOR="1", TLS_INSECURE_NO_HOST_NAME="1")
    else:
        env["TLS_CA_FILE"] = str(ca_file)
    if host_name is not None:
        env["TLS_HOST_NAME"] = host_name
    if group is not None:
        env["TLS_CLIENT_GROUP"] = group
    return subprocess.Popen(
        [str(CLIENT_BIN)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )


def _assert_application_exchange(server: subprocess.Popen, client: subprocess.Popen) -> None:
    assert server.stdin is not None
    payload = b"tls-client-openssl-server\n"
    os.write(server.stdin.fileno(), payload)
    output = _read_until(server, payload)
    assert payload in output, output.decode(errors="replace")
    assert client.poll() is None


def _collected_output(proc: subprocess.Popen) -> str:
    stdout, stderr = proc.communicate(timeout=2)
    return (stdout or b"").decode(errors="replace") + (stderr or b"").decode(errors="replace")


def _assert_client_failure(
    server: subprocess.Popen,
    client: subprocess.Popen,
    client_text: tuple[str, ...],
    server_text: tuple[str, ...] = (),
) -> None:
    try:
        client.wait(timeout=10)
        assert client.returncode != 0
        if server.stdin is not None:
            server.stdin.close()
    finally:
        _stop(client)
        _stop(server)
    client_output = _collected_output(client)
    server_output = _collected_output(server)
    for expected in client_text:
        assert expected in client_output, client_output
    for expected in server_text:
        assert expected in server_output.lower(), server_output


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
    cert, key = _generate_certificate(tmp_path)
    server, port = _start_openssl_server(cert, key)
    client = _start_tls_client(port)
    try:
        _assert_application_exchange(server, client)
    finally:
        _stop(client)
        _stop(server)


@pytest.mark.requires_capability("client_group.x25519", "certificate_verify.ecdsa_secp256r1_sha256")
def test_tls_client_verifies_openssl_chain_and_hostname(tmp_path):
    cert, key = _generate_certificate(tmp_path)
    server, port = _start_openssl_server(cert, key)
    client = _start_tls_client(port, ca_file=cert, host_name="localhost")
    try:
        _assert_application_exchange(server, client)
    finally:
        _stop(client)
        _stop(server)


@pytest.mark.requires_capability("client_group.x25519", "certificate_verify.ecdsa_secp256r1_sha256")
def test_tls_client_rejects_openssl_certificate_with_wrong_hostname(tmp_path):
    cert, key = _generate_certificate(tmp_path)
    server, port = _start_openssl_server(cert, key)
    client = _start_tls_client(port, ca_file=cert, host_name="wrong.example")
    _assert_client_failure(
        server,
        client,
        client_text=("CertificateHostMismatch",),
        server_text=("certificate unknown",),
    )


@pytest.mark.requires_capability("client_group.x25519", "certificate_verify.ecdsa_secp256r1_sha256")
def test_tls_client_rejects_openssl_certificate_with_untrusted_anchor(tmp_path):
    cert, key = _generate_certificate(tmp_path / "server")
    other_anchor, _ = _generate_certificate(tmp_path / "other", subject="untrusted.example")
    server, port = _start_openssl_server(cert, key)
    client = _start_tls_client(port, ca_file=other_anchor, host_name="localhost")
    _assert_client_failure(
        server,
        client,
        client_text=("CertificateIssuerNotFound",),
        server_text=("unknown ca",),
    )


@pytest.mark.requires_capability(
    "client_group.x25519_mlkem768", "certificate_verify.ecdsa_secp256r1_sha256"
)
def test_tls_client_negotiates_x25519_mlkem768_with_openssl(tmp_path):
    cert, key = _generate_certificate(tmp_path)
    server, port = _start_openssl_server(cert, key, group="X25519MLKEM768")
    client = _start_tls_client(port, group="x25519_mlkem768")
    try:
        _assert_application_exchange(server, client)
    finally:
        _stop(client)
        _stop(server)


@pytest.mark.requires_capability(
    "client_group.x25519",
    "client_group.x25519_mlkem768",
    "certificate_verify.ecdsa_secp256r1_sha256",
)
def test_tls_client_falls_back_when_openssl_declines_hybrid_group(tmp_path):
    cert, key = _generate_certificate(tmp_path)
    server, port = _start_openssl_server(cert, key, group="X25519")
    client = _start_tls_client(port, group="x25519_mlkem768")
    try:
        _assert_application_exchange(server, client)
    finally:
        _stop(client)
        _stop(server)


@pytest.mark.requires_capability(
    "client_group.x25519_mlkem768", "certificate_verify.ecdsa_secp256r1_sha256"
)
def test_tls_client_receives_handshake_failure_when_openssl_shares_no_group(tmp_path):
    cert, key = _generate_certificate(tmp_path)
    server, port = _start_openssl_server(cert, key, group="P-521")
    client = _start_tls_client(port, group="x25519_mlkem768")
    _assert_client_failure(
        server,
        client,
        client_text=("PeerAlert", "anvil_client peer_alert=handshake_failure"),
    )


@pytest.mark.requires_capability(
    "client_group.secp384r1", "certificate_verify.ecdsa_secp256r1_sha256"
)
def test_tls_client_uses_p384_key_exchange_with_openssl(tmp_path):
    cert, key = _generate_certificate(tmp_path)
    server, port = _start_openssl_server(cert, key, group="P-384")
    client = _start_tls_client(port, group="secp384r1")
    try:
        _assert_application_exchange(server, client)
    finally:
        _stop(client)
        _stop(server)


@pytest.mark.requires_capability("client_group.x25519", "certificate_verify.ecdsa_secp384r1_sha384")
def test_tls_client_verifies_p384_certificate_verify_from_openssl(tmp_path):
    cert, key = _generate_certificate(tmp_path, curve="P-384")
    server, port = _start_openssl_server(cert, key)
    client = _start_tls_client(port, ca_file=cert, host_name="localhost")
    try:
        _assert_application_exchange(server, client)
    finally:
        _stop(client)
        _stop(server)
