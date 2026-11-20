import hashlib
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import pytest
from tlsfuzzer.expect import ExpectAlert, ExpectClose
from tlsfuzzer.helpers import key_share_gen
from tlsfuzzer.messages import ClientHelloGenerator, Connect
from tlsfuzzer.runner import Runner
from tlslite.constants import AlertDescription, AlertLevel, ExtensionType, GroupName
from tlslite.extensions import ClientKeyShareExtension, SupportedGroupsExtension

from tests.test_tls13 import CIPHERS, tls13_extensions

# Keep this revision aligned with the tlsfuzzer pin in pyproject.toml. The
# package excludes its _apps modules, so run the pinned upstream driver as a
# downloaded test artifact rather than maintaining a local fork.
TLSFUZZER_REVISION = "bf7f579dc0e65498cfb21b60e9b152f6bd84a3bf"
DRIVER_SHA256 = "f2a5fef6ecf61332018e536d22dfc7a7828fb8010c20c29b346923e309648d91"
DRIVER_URL = (
    "https://raw.githubusercontent.com/tlsfuzzer/tlsfuzzer/"
    f"{TLSFUZZER_REVISION}/tlsfuzzer/_apps/test_tls13_mlkem.py"
)
RFC10024_GROUPS = {
    "secp256r1_mlkem768": "secp256r1mlkem768",
    "x25519_mlkem768": "x25519mlkem768",
    "secp384r1_mlkem1024": "secp384r1mlkem1024",
}


@pytest.mark.lockstep
@pytest.mark.parametrize(
    "group",
    [
        pytest.param(
            group,
            marks=pytest.mark.requires_capability(f"server_group.{group}"),
        )
        for group in RFC10024_GROUPS
    ],
)
def test_upstream_tls13_mlkem_matrix(start_tls_server, group):
    tls_server = start_tls_server(hybrid_group=group)
    with urllib.request.urlopen(DRIVER_URL, timeout=30) as response:
        driver = response.read()
    assert hashlib.sha256(driver).hexdigest() == DRIVER_SHA256

    with tempfile.TemporaryDirectory() as tmp:
        driver_path = Path(tmp) / "test_tls13_mlkem.py"
        driver_path.write_bytes(driver)
        result = subprocess.run(
            [
                sys.executable,
                str(driver_path),
                "-h",
                tls_server["host"],
                "-p",
                str(tls_server["port"]),
                "--no-fuzz",
                "--kems",
                RFC10024_GROUPS[group],
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

    print(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.requires_capability_false("server_group.secp384r1_mlkem1024")
def test_tls13_unsupported_mlkem1024_offer_fails_with_handshake_failure(tls_server):
    extensions = tls13_extensions()
    extensions[ExtensionType.supported_groups] = SupportedGroupsExtension().create(
        [GroupName.secp384r1mlkem1024]
    )
    extensions[ExtensionType.key_share] = ClientKeyShareExtension().create(
        [key_share_gen(GroupName.secp384r1mlkem1024)]
    )
    conversation = Connect(tls_server["host"], tls_server["port"])
    node = conversation.add_child(ClientHelloGenerator(CIPHERS, extensions=extensions))
    alert = node.add_child(ExpectAlert(AlertLevel.fatal, AlertDescription.handshake_failure))
    alert.add_child(ExpectClose())
    Runner(conversation).run()
