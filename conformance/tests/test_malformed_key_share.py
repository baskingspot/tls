import socket
import threading
import traceback

import pytest
from tlslite.constants import AlertDescription, AlertLevel, ContentType

from tests.test_openssl_interop import _start_tls_client, _stop

ALERT_HEADER = b"\x15\x03\x03\x00\x02"
ILLEGAL_PARAMETER = bytes([AlertLevel.fatal, AlertDescription.illegal_parameter])


def _record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + len(body).to_bytes(2, "big") + body


def _read_exact(stream: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise AssertionError(f"peer closed with {length - len(data)} bytes outstanding")
        data.extend(chunk)
    return bytes(data)


def _read_record(stream: socket.socket) -> bytes:
    header = _read_exact(stream, 5)
    length = int.from_bytes(header[3:5], "big")
    return header + _read_exact(stream, length)


def _parse_client_hello(record: bytes):
    assert record[0] == ContentType.handshake
    assert int.from_bytes(record[3:5], "big") == len(record) - 5
    message = record[5:]
    assert message[0] == 1  # ClientHello handshake type.
    assert int.from_bytes(message[1:4], "big") == len(message) - 4

    pos = 4 + 2 + 32
    session_id_len = message[pos]
    pos += 1
    session_id = message[pos : pos + session_id_len]
    pos += session_id_len
    cipher_suites_len = int.from_bytes(message[pos : pos + 2], "big")
    pos += 2 + cipher_suites_len
    compression_len = message[pos]
    pos += 1 + compression_len
    extensions_len = int.from_bytes(message[pos : pos + 2], "big")
    pos += 2
    extensions_end = pos + extensions_len
    assert extensions_end == len(message)

    key_shares = set()
    while pos < extensions_end:
        extension_type = int.from_bytes(message[pos : pos + 2], "big")
        extension_len = int.from_bytes(message[pos + 2 : pos + 4], "big")
        data = message[pos + 4 : pos + 4 + extension_len]
        pos += 4 + extension_len
        if extension_type == 51:
            shares_end = 2 + int.from_bytes(data[:2], "big")
            assert shares_end == len(data)
            share_pos = 2
            while share_pos < shares_end:
                group = int.from_bytes(data[share_pos : share_pos + 2], "big")
                share_len = int.from_bytes(data[share_pos + 2 : share_pos + 4], "big")
                share_pos += 4 + share_len
                key_shares.add(group)
            assert share_pos == shares_end
    return session_id, key_shares


def _server_hello(session_id: bytes, group: int, point: bytes) -> bytes:
    key_share = group.to_bytes(2, "big") + len(point).to_bytes(2, "big") + point
    extensions = (
        b"\x00\x2b\x00\x02\x03\x04" + b"\x00\x33" + len(key_share).to_bytes(2, "big") + key_share
    )
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + bytes([len(session_id)])
        + session_id
        + b"\x13\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return _record(ContentType.handshake, handshake)


class _MalformedPointServer:
    def __init__(self, group: int, point: bytes):
        self.group = group
        self.point = point
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        self.alert_record: bytes | None = None
        self.error: str | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        try:
            with self.listener:
                connection, _ = self.listener.accept()
                with connection:
                    connection.settimeout(10)
                    client_hello = _read_record(connection)
                    session_id, key_shares = _parse_client_hello(client_hello)
                    assert self.group in key_shares, "client omitted the selected key share"
                    connection.sendall(_server_hello(session_id, self.group, self.point))
                    self.alert_record = _read_record(connection)
        except Exception:  # noqa: BLE001 -- return thread failures to the test thread.
            self.error = traceback.format_exc()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback_object):
        self.thread.join(timeout=12)
        assert not self.thread.is_alive()
        assert self.error is None, self.error


def _point(case: str, coordinate_len: int) -> bytes:
    if case == "off_curve":
        # x = 1, y = 0 does not satisfy either curve equation.
        return b"\x04" + (1).to_bytes(coordinate_len, "big") + bytes(coordinate_len)
    if case == "infinity":
        return b"\x00"
    assert case == "wrong_length"
    return b"\x04" + bytes(2 * coordinate_len - 1)


@pytest.mark.parametrize(
    ("curve", "case", "client_error"),
    [
        pytest.param(
            "secp256r1",
            case,
            error,
            marks=pytest.mark.requires_capability("client_group.secp256r1"),
            id=f"p256-{case}",
        )
        for case, error in (
            ("off_curve", "IdentityElement"),
            ("infinity", "UnsupportedKeyShareGroup"),
            ("wrong_length", "UnsupportedKeyShareGroup"),
        )
    ]
    + [
        pytest.param(
            "secp384r1",
            case,
            error,
            marks=pytest.mark.requires_capability("client_group.secp384r1"),
            id=f"p384-{case}",
        )
        for case, error in (
            ("off_curve", "IdentityElement"),
            ("infinity", "UnsupportedKeyShareGroup"),
            ("wrong_length", "UnsupportedKeyShareGroup"),
        )
    ],
)
def test_client_rejects_malformed_server_key_share_with_illegal_parameter(
    curve, case, client_error
):
    coordinate_len = 32 if curve == "secp256r1" else 48
    group = 23 if curve == "secp256r1" else 24
    with _MalformedPointServer(group, _point(case, coordinate_len)) as server:
        client = _start_tls_client(server.port, group=curve)
        try:
            client.wait(timeout=10)
            assert client.returncode != 0
        finally:
            _stop(client)

    _, stderr = client.communicate(timeout=2)
    client_output = (stderr or b"").decode(errors="replace")
    assert f"error.{client_error}" in client_output, client_output
    assert server.alert_record == ALERT_HEADER + ILLEGAL_PARAMETER
