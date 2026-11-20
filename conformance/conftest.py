import fcntl
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

CONF_DIR = Path(__file__).resolve().parent
SERVER_BIN = CONF_DIR / "zig-out" / "bin" / "tlsfuzzer_server"
UNSUPPORTED_PREFIX = "UNSUPPORTED "


def _wait_for_ready(proc: subprocess.Popen, host: str, port: int, timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    marker = b"tls tlsfuzzer server listening on"
    captured = bytearray()
    assert proc.stdout is not None
    flags = fcntl.fcntl(proc.stdout, fcntl.F_GETFL)
    fcntl.fcntl(proc.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    saw_marker = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"tlsfuzzer_server exited early rc={proc.returncode}: {captured.decode(errors='replace')!r}"
            )
        try:
            chunk = proc.stdout.read(4096)
            if chunk:
                captured.extend(chunk)
                saw_marker = marker in captured
        except BlockingIOError, OSError:
            pass
        if saw_marker:
            try:
                with socket.create_connection((host, port), timeout=0.2):
                    return
            except OSError:
                pass
        time.sleep(0.05)
    raise RuntimeError(
        f"tlsfuzzer_server not ready on {host}:{port}; output={captured.decode(errors='replace')!r}"
    )


def _start_server(
    credential: str, hybrid_group: str | None = None
) -> tuple[subprocess.Popen, dict[str, object]]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = os.environ.copy()
    env["PORT"] = str(port)
    env["TLS_CREDENTIAL"] = credential
    if hybrid_group is not None:
        env["TLS_HYBRID_GROUP"] = hybrid_group
    proc = subprocess.Popen(
        [str(SERVER_BIN)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    _wait_for_ready(proc, "127.0.0.1", port)
    return proc, {"host": "127.0.0.1", "port": port, "proc": proc}


def _stop_server(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


@pytest.fixture(scope="session")
def tls_server():
    proc, server = _start_server("ecdsa")
    try:
        yield server
    finally:
        _stop_server(proc)


@pytest.fixture
def start_tls_server():
    processes = []

    def start(credential="ecdsa", hybrid_group=None):
        proc, server = _start_server(credential, hybrid_group)
        processes.append(proc)
        return server

    yield start
    for proc in processes:
        _stop_server(proc)


@pytest.fixture
def rsa_server():
    proc, server = _start_server("rsa")
    try:
        yield server
    finally:
        _stop_server(proc)


@pytest.fixture(scope="session")
def crypto_capabilities() -> dict[str, str | bool]:
    result = subprocess.run(
        [str(SERVER_BIN), "--capabilities"], capture_output=True, text=True, check=True
    )
    values: dict[str, str | bool] = {}
    for line in (result.stdout + result.stderr).splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            raise RuntimeError(f"malformed capability line: {line!r}")
        if key == "backend":
            values[key] = value
        elif key.startswith("capability.") and value in ("true", "false"):
            values[key.removeprefix("capability.")] = value == "true"
        else:
            raise RuntimeError(f"unknown capability line: {line!r}")
    if "backend" not in values:
        raise RuntimeError("the server did not report its crypto backend")
    return values


@pytest.fixture(autouse=True)
def _capability_exclusions(request):
    marker = request.node.get_closest_marker("requires_capability")
    if marker is None:
        yield
        return
    capabilities = request.getfixturevalue("crypto_capabilities")
    for capability in marker.args:
        if capability not in capabilities:
            raise RuntimeError(f"the server did not report capability {capability!r}")
        if not capabilities[capability]:
            pytest.skip(
                f"{UNSUPPORTED_PREFIX}backend={capabilities['backend']} "
                f"capability={capability} value=false"
            )
    yield


@pytest.fixture(autouse=True)
def _server_alive(request, _capability_exclusions):
    server_names = [name for name in ("tls_server", "rsa_server") if name in request.fixturenames]
    for name in server_names:
        proc = request.getfixturevalue(name)["proc"]
        if proc.poll() is not None:
            pytest.fail(f"{name} died before test rc={proc.returncode}", pytrace=False)
    yield
    for name in server_names:
        proc = request.getfixturevalue(name)["proc"]
        if proc.poll() is not None:
            captured = proc.stdout.read() if proc.stdout else b""
            pytest.fail(
                f"{name} died during test rc={proc.returncode}: "
                f"{captured.decode(errors='replace')!r}",
                pytrace=False,
            )


def _unsupported_reason(report) -> str | None:
    if not report.skipped:
        return None
    if isinstance(report.longrepr, tuple):
        reason = str(report.longrepr[-1])
    else:
        reason = str(report.longrepr)
    start = reason.find(UNSUPPORTED_PREFIX)
    if start >= 0:
        return reason[start:]
    return None


def pytest_report_teststatus(report):
    if _unsupported_reason(report) is not None:
        return "unsupported", "U", "UNSUPPORTED"


def pytest_terminal_summary(terminalreporter):
    seen = set()
    exclusions = []
    for reports in terminalreporter.stats.values():
        for report in reports:
            reason = _unsupported_reason(report)
            if reason is not None and report.nodeid not in seen:
                seen.add(report.nodeid)
                exclusions.append((report.nodeid, reason))
    if exclusions:
        terminalreporter.write_line("Named capability exclusions:")
        for nodeid, reason in exclusions:
            terminalreporter.write_line(f"{reason} case={nodeid}")
