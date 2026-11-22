import socket

import pytest
from tlsfuzzer.expect import (
    ExpectAlert,
    ExpectApplicationData,
    ExpectCertificate,
    ExpectCertificateVerify,
    ExpectChangeCipherSpec,
    ExpectClose,
    ExpectEncryptedExtensions,
    ExpectFinished,
    ExpectKeyUpdate,
    ExpectServerHello,
)
from tlsfuzzer.helpers import key_share_gen
from tlsfuzzer.messages import (
    AlertGenerator,
    ApplicationDataGenerator,
    ClientHelloGenerator,
    Connect,
    FinishedGenerator,
    KeyUpdateGenerator,
    RawMessageGenerator,
    RawSocketWriteGenerator,
)
from tlsfuzzer.runner import Runner
from tlslite.constants import (
    TLS_1_3_DRAFT,
    AlertDescription,
    AlertLevel,
    CipherSuite,
    ContentType,
    ExtensionType,
    GroupName,
    KeyUpdateMessageType,
    SignatureScheme,
)
from tlslite.extensions import (
    ALPNExtension,
    ClientKeyShareExtension,
    SignatureAlgorithmsCertExtension,
    SignatureAlgorithmsExtension,
    SupportedGroupsExtension,
    SupportedVersionsExtension,
)

CIPHERS = [
    CipherSuite.TLS_AES_128_GCM_SHA256,
    CipherSuite.TLS_AES_256_GCM_SHA384,
    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
]


OMIT_EXTENSION = object()


def tls13_extensions(
    alpn_protocols=None,
    signature_schemes=None,
    signature_schemes_cert=None,
):
    if signature_schemes is None:
        signature_schemes = [
            SignatureScheme.ecdsa_secp256r1_sha256,
            SignatureScheme.rsa_pss_rsae_sha256,
        ]
    ext = {
        ExtensionType.key_share: ClientKeyShareExtension().create(
            [key_share_gen(GroupName.x25519)]
        ),
        ExtensionType.supported_versions: SupportedVersionsExtension().create(
            [TLS_1_3_DRAFT, (3, 3)]
        ),
        ExtensionType.supported_groups: SupportedGroupsExtension().create([GroupName.x25519]),
        ExtensionType.signature_algorithms: SignatureAlgorithmsExtension().create(
            signature_schemes
        ),
    }
    if signature_schemes_cert is not OMIT_EXTENSION:
        cert_schemes = (
            signature_schemes if signature_schemes_cert is None else signature_schemes_cert
        )
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension().create(
            cert_schemes
        )
    if alpn_protocols is not None:
        ext[ExtensionType.alpn] = ALPNExtension().create(alpn_protocols)
    return ext


def tls13_handshake(node):
    node = node.add_child(ExpectServerHello())
    ccs = node.add_child(ExpectChangeCipherSpec())
    ee = ExpectEncryptedExtensions()
    ccs.add_child(ee)
    ccs.next_sibling = ee
    node = ee
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    return node


def expect_alert_or_close(node, level, description):
    alert = node.add_child(ExpectAlert(level, description))
    alert.next_sibling = ExpectClose()
    alert.add_child(ExpectClose())


def close_notify(node):
    send = node.add_child(AlertGenerator(AlertLevel.warning, AlertDescription.close_notify))
    alert = send.add_child(ExpectAlert())
    alert.next_sibling = ExpectClose()
    alert.add_child(ExpectClose())
    send.next_sibling = ExpectClose()


def raw_connect(tls_server):
    sock = socket.create_connection((tls_server["host"], tls_server["port"]), timeout=2)
    sock.settimeout(1)
    return sock


def expect_closed_or_alert(sock):
    try:
        data = sock.recv(1)
        assert data in (b"", b"\x15"), f"expected close or alert, got {data!r}"
    except ConnectionResetError, TimeoutError:
        pass


def record(content_type: int, body: bytes, version: bytes = b"\x03\x03") -> bytes:
    return bytes([content_type]) + version + len(body).to_bytes(2, "big") + body


def minimal_client_hello_with_ext(ext_type: int, ext_body: bytes) -> bytes:
    extensions = ext_type.to_bytes(2, "big") + len(ext_body).to_bytes(2, "big") + ext_body
    body = (
        b"\x03\x03"
        + (b"\x11" * 32)
        + b"\x00"
        + b"\x00\x02"
        + CipherSuite.TLS_AES_128_GCM_SHA256.to_bytes(2, "big")
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return record(ContentType.handshake, handshake)


def run_echo_conversation(
    tls_server,
    ciphers,
    signature_schemes=None,
    signature_schemes_cert=None,
):
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(
        ClientHelloGenerator(
            ciphers,
            extensions=tls13_extensions(
                signature_schemes=signature_schemes,
                signature_schemes_cert=signature_schemes_cert,
            ),
        )
    )
    node = tls13_handshake(node)
    node = node.add_child(ApplicationDataGenerator(bytearray(b"tls tlsfuzzer smoke\n")))
    node = node.add_child(ExpectApplicationData())
    close_notify(node)
    Runner(conversation).run()


@pytest.mark.lockstep
def test_tls13_handshake_and_application_echo(tls_server):
    run_echo_conversation(tls_server, CIPHERS)


@pytest.mark.requires_capability("private_key.rsa_pss_rsae_sha256")
def test_tls13_rsa_pss_handshake_and_application_echo(rsa_server):
    run_echo_conversation(
        rsa_server,
        CIPHERS,
        signature_schemes=[SignatureScheme.rsa_pss_rsae_sha256],
        signature_schemes_cert=[SignatureScheme.rsa_pkcs1_sha256],
    )


def test_tls13_excluded_cert_signature_algorithm_is_handshake_failure(tls_server):
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(
        ClientHelloGenerator(
            CIPHERS,
            extensions=tls13_extensions(
                signature_schemes=[SignatureScheme.ecdsa_secp256r1_sha256],
                signature_schemes_cert=[SignatureScheme.rsa_pkcs1_sha256],
            ),
        )
    )
    node = node.add_child(ExpectServerHello())
    ccs = node.add_child(ExpectChangeCipherSpec())
    alert = ccs.add_child(ExpectAlert(AlertLevel.fatal, AlertDescription.handshake_failure))
    ccs.next_sibling = alert
    alert.add_child(ExpectClose())
    Runner(conversation).run()


@pytest.mark.requires_capability("private_key.rsa_pss_rsae_sha256")
def test_tls13_omitted_signature_algorithms_cert_excludes_rsa_cert(rsa_server):
    conversation = Connect(rsa_server["host"], rsa_server["port"])
    node = conversation.add_child(
        ClientHelloGenerator(
            CIPHERS,
            extensions=tls13_extensions(
                signature_schemes=[SignatureScheme.rsa_pss_rsae_sha256],
                signature_schemes_cert=OMIT_EXTENSION,
            ),
        )
    )
    node = node.add_child(ExpectServerHello())
    ccs = node.add_child(ExpectChangeCipherSpec())
    alert = ccs.add_child(ExpectAlert(AlertLevel.fatal, AlertDescription.handshake_failure))
    ccs.next_sibling = alert
    alert.add_child(ExpectClose())
    Runner(conversation).run()


def test_tls13_omitted_signature_algorithms_cert_allows_matching_ecdsa(tls_server):
    run_echo_conversation(
        tls_server,
        CIPHERS,
        signature_schemes=[SignatureScheme.ecdsa_secp256r1_sha256],
        signature_schemes_cert=OMIT_EXTENSION,
    )


@pytest.mark.requires_capability("private_key.rsa_pss_rsae_sha256")
def test_tls13_omitted_signature_algorithms_cert_allows_matching_rsa(rsa_server):
    run_echo_conversation(
        rsa_server,
        CIPHERS,
        signature_schemes=[
            SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pkcs1_sha256,
        ],
        signature_schemes_cert=OMIT_EXTENSION,
    )


def test_tls13_unusable_signature_offer_is_handshake_failure(tls_server, crypto_capabilities):
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(
        ClientHelloGenerator(
            CIPHERS,
            extensions=tls13_extensions(signature_schemes=[SignatureScheme.rsa_pss_rsae_sha256]),
        )
    )
    if crypto_capabilities["certificate_verify.rsa_pss_rsae_sha256"]:
        # The ECDSA server accepts the backend-supported offer, then finds no
        # scheme its credential can sign before the authenticated flight.
        node = node.add_child(ExpectServerHello())
        ccs = node.add_child(ExpectChangeCipherSpec())
        alert = ccs.add_child(ExpectAlert(AlertLevel.fatal, AlertDescription.handshake_failure))
        ccs.next_sibling = alert
        node = alert
    else:
        node = node.add_child(ExpectAlert(AlertLevel.fatal, AlertDescription.handshake_failure))
    node.add_child(ExpectClose())
    Runner(conversation).run()


def test_tls13_aes256_gcm_echo(tls_server):
    run_echo_conversation(
        tls_server,
        [
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        ],
    )


def test_tls13_chacha20_poly1305_echo(tls_server):
    run_echo_conversation(
        tls_server,
        [
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        ],
    )


@pytest.mark.lockstep
def test_tls13_keyupdate_update_requested(tls_server):
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(ClientHelloGenerator(CIPHERS, extensions=tls13_extensions()))
    node = tls13_handshake(node)
    node = node.add_child(KeyUpdateGenerator(message_type=KeyUpdateMessageType.update_requested))
    node = node.add_child(ApplicationDataGenerator(bytearray(b"after key update\n")))
    node = node.add_child(ExpectKeyUpdate(message_type=KeyUpdateMessageType.update_not_requested))
    node = node.add_child(ExpectApplicationData())
    close_notify(node)
    Runner(conversation).run()


def test_tls13_corrupted_app_data_record_is_rejected(tls_server):
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(ClientHelloGenerator(CIPHERS, extensions=tls13_extensions()))
    node = tls13_handshake(node)
    node = node.add_child(
        RawSocketWriteGenerator(data=bytearray(b"\x17\x03\x03\x00\x20" + b"\xaa" * 32))
    )
    expect_alert_or_close(node, AlertLevel.fatal, AlertDescription.bad_record_mac)
    Runner(conversation).run()


def test_tls13_rejects_truncated_keyupdate(tls_server):
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(ClientHelloGenerator(CIPHERS, extensions=tls13_extensions()))
    node = tls13_handshake(node)
    node = node.add_child(
        RawMessageGenerator(ContentType.handshake, bytearray(b"\x18\x00\x00\x00"))
    )
    expect_alert_or_close(node, AlertLevel.fatal, AlertDescription.decode_error)
    Runner(conversation).run()


def test_tls13_rejects_invalid_keyupdate_request(tls_server):
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(ClientHelloGenerator(CIPHERS, extensions=tls13_extensions()))
    node = tls13_handshake(node)
    node = node.add_child(
        RawMessageGenerator(ContentType.handshake, bytearray(b"\x18\x00\x00\x01\x02"))
    )
    expect_alert_or_close(node, AlertLevel.fatal, AlertDescription.illegal_parameter)
    Runner(conversation).run()


def test_tls13_oversized_record_is_rejected(tls_server):
    oversized_len = 0x4101
    oversized_record = bytearray(bytes([ContentType.application_data]) + b"\x03\x03")
    oversized_record.extend(oversized_len.to_bytes(2, "big"))
    oversized_record.extend(b"\x00" * 16)
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(ClientHelloGenerator(CIPHERS, extensions=tls13_extensions()))
    node = tls13_handshake(node)
    node = node.add_child(RawSocketWriteGenerator(data=oversized_record))
    expect_alert_or_close(
        node,
        AlertLevel.fatal,
        (AlertDescription.record_overflow, AlertDescription.decode_error),
    )
    Runner(conversation).run()


def test_tls13_close_notify_before_handshake(tls_server):
    sock = raw_connect(tls_server)
    try:
        sock.sendall(record(ContentType.alert, b"\x01\x00"))
        expect_closed_or_alert(sock)
    finally:
        sock.close()


def test_tls13_rejects_garbage_pre_handshake(tls_server):
    sock = raw_connect(tls_server)
    try:
        sock.sendall(b"this is not a TLS record\r\n")
        expect_closed_or_alert(sock)
    finally:
        sock.close()


def test_tls13_rejects_finished_before_handshake(tls_server):
    sock = raw_connect(tls_server)
    try:
        sock.sendall(record(ContentType.handshake, b"\x14\x00\x00\x20" + b"\x00" * 32))
        expect_closed_or_alert(sock)
    finally:
        sock.close()


def test_tls13_rejects_truncated_client_hello_record(tls_server):
    sock = raw_connect(tls_server)
    try:
        sock.sendall(b"\x16\x03\x03\x00\xc8")
        sock.close()
    finally:
        sock.close()


def test_tls13_rejects_empty_client_hello_record(tls_server):
    sock = raw_connect(tls_server)
    try:
        sock.sendall(record(ContentType.handshake, b""))
        expect_closed_or_alert(sock)
    finally:
        sock.close()


def test_tls13_rejects_truncated_key_share_extension(tls_server):
    sock = raw_connect(tls_server)
    try:
        sock.sendall(minimal_client_hello_with_ext(ExtensionType.key_share, b"\x00\x04\x00\x1d"))
        expect_closed_or_alert(sock)
    finally:
        sock.close()


@pytest.mark.lockstep
def test_tls13_rejects_unshared_alpn(tls_server):
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(
        ClientHelloGenerator(
            CIPHERS,
            extensions=tls13_extensions(alpn_protocols=[b"not-supported"]),
        )
    )
    alert = node.add_child(ExpectAlert(AlertLevel.fatal, AlertDescription.no_application_protocol))
    alert.add_child(ExpectClose())
    Runner(conversation).run()


def test_tls13_rejects_unsupported_cipher_suite(tls_server):
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(
        ClientHelloGenerator(
            [
                CipherSuite.TLS_AES_128_CCM_SHA256,
                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            ],
            extensions=tls13_extensions(),
        )
    )
    alert = node.add_child(ExpectAlert(AlertLevel.fatal, AlertDescription.handshake_failure))
    alert.add_child(ExpectClose())
    Runner(conversation).run()
