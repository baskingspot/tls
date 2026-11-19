import subprocess
from pathlib import Path

import click
import pytest
from click.testing import CliRunner
from ec2bench.config import Config
from ec2bench.parallel import Outcome

from tls_bench import adapter


def make_config(root: Path) -> Config:
    return Config(
        root=root,
        project={
            "name": "tls-bench",
            "region": "us-west-2",
            "profile": "tls-bench",
            "image_version": "1",
            "remote_dir": "/root/tls",
            "results_dir": "zig-out/perf",
            "cache_dir": ".bench-cache",
        },
        fleet={"default_ttl": "4h", "max_ttl": "12h", "default_owner": "agent"},
        targets={
            "c7i": {"instance_type": "c7i.large", "arch": "x86_64"},
            "c7g": {"instance_type": "c7g.2xlarge", "arch": "arm64"},
        },
    )


class FakeFleet:
    def __init__(self, config: Config, *, existing: bool = False) -> None:
        self.config = config
        self.existing = existing
        self.instance = {
            "InstanceId": "i-test",
            "InstanceType": "c7i.large",
            "State": {"Name": "running"},
        }
        self.sizes = []
        self.waited = []
        self.terminated = []

    def selected(self, names):
        assert names == ["c7i"]
        return [self.instance] if self.existing else []

    def one(self, target):
        assert target == "c7i"
        return self.instance

    def terminate(self, ids):
        self.terminated.append(ids)

    def wait_terminated(self, ids):
        self.waited.append(ids)


class FakeBox:
    def __init__(self, output: str = "zig-out/perf/20261118-120000\n") -> None:
        self.output = output
        self.upload = None
        self.commands = []
        self.downloads = []
        self.poweroffs = 0
        self.error = None

    def upload_contents(self, source, destination, *, exclude, delete):
        self.upload = (source, destination, tuple(exclude), delete)

    def run(self, command, *, timeout, stream):
        self.commands.append((command, timeout))
        if self.error:
            raise self.error
        stream("remote workload log")
        return self.output

    def download(self, source, destination):
        self.downloads.append((source, destination))
        destination.mkdir(parents=True)
        (destination / "metadata.txt").write_text("git_revision=abc123\n")

    def poweroff(self):
        self.poweroffs += 1


def install_fakes(monkeypatch, config, box, *, existing=False):
    fleet = FakeFleet(config, existing=existing)

    def ensure_up(actual_fleet, names, ttl=None, size=None):
        assert actual_fleet is fleet
        assert names == ["c7i"]
        assert ttl is None
        fleet.sizes.append(size)
        if size:
            fleet.instance["InstanceType"] = f"c7i.{size}"
        return {"c7i": Outcome(value="i-test")}

    monkeypatch.setattr(adapter, "Fleet", lambda _actual_config: fleet)
    monkeypatch.setattr(adapter, "ensure_up", ensure_up)
    monkeypatch.setattr(adapter, "box_for", lambda _actual_fleet, _instance: box)
    monkeypatch.setattr(adapter, "git", lambda *_args: "")
    return fleet


def fake_analyze(monkeypatch):
    calls = []

    def run(args, *, cwd, check, stdout):
        assert check is True
        calls.append((args, cwd))
        stdout.write("benchstat output\n")
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(adapter.subprocess, "run", run)
    return calls


def test_target_and_matrix_parsing(tmp_path):
    config = make_config(tmp_path)
    assert adapter._target_for_type(config, "c7i.2xlarge") == ("c7i", "2xlarge")
    assert adapter._target_for_type(config, "c7g.large") == ("c7g", "large")
    assert adapter._matrix("c7i.large, c7g.2xlarge\nc7i.2xlarge") == [
        "c7i.large",
        "c7g.2xlarge",
        "c7i.2xlarge",
    ]
    with pytest.raises(click.UsageError):
        adapter._target_for_type(config, "c8i.large")
    with pytest.raises(click.UsageError):
        adapter._matrix(" , ")


@pytest.mark.parametrize(
    "path",
    ["", "/capture", "zig-out/other/capture", "zig-out/perf/../escape", "text"],
)
def test_result_path_rejects_escape(path):
    with pytest.raises(click.ClickException):
        adapter._result_path(path)


def test_capture_syncs_runs_downloads_analyzes_and_terminates(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    box = FakeBox()
    fleet = install_fakes(monkeypatch, config, box)
    analyzed = fake_analyze(monkeypatch)

    adapter._run_capture(
        config,
        "c7i.large",
        "openssl",
        5,
        "500ms",
        False,
        False,
        ("--filter", "Benchmark AppPingPong"),
    )

    assert fleet.sizes == ["large"]
    assert box.upload[0] == tmp_path
    assert box.upload[1] == "/root/tls"
    assert box.upload[3] is True
    excludes = box.upload[2]
    assert "/.envrc.local" in excludes
    assert "/zig-out/" in excludes
    assert ".terraform" in excludes
    assert "*.tfstate" in excludes
    assert ".git" not in excludes
    assert "bench/remote-capture.sh" in box.commands[0][0]
    assert "'Benchmark AppPingPong'" in box.commands[0][0]
    assert box.commands[0][1] == adapter._REMOTE_TIMEOUT_SECONDS
    capture = tmp_path / "zig-out/perf/20261118-120000-c7i.large-openssl"
    assert box.downloads == [("/root/tls/zig-out/perf/20261118-120000", capture)]
    metadata = (capture / "metadata.txt").read_text()
    assert "ec2_instance_type=c7i.large" in metadata
    assert "ec2_instance_id=i-test" in metadata
    assert "ec2_instance_ip" not in metadata
    assert analyzed == [([str(tmp_path / "scripts/bench-analyze.sh"), str(capture)], tmp_path)]
    assert (capture / "benchstat.txt").read_text() == "benchstat output\n"
    assert box.poweroffs == 1
    assert fleet.waited == [["i-test"]]


def test_reused_matching_box_is_not_terminated(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    box = FakeBox()
    fleet = install_fakes(monkeypatch, config, box, existing=True)
    fake_analyze(monkeypatch)

    adapter._run_capture(config, "c7i.large", "openssl", 5, "500ms", False, False, ())

    assert box.poweroffs == 0
    assert fleet.waited == []


def test_failed_workload_still_terminates_a_new_box(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    box = FakeBox()
    box.error = RuntimeError("workload failed")
    fleet = install_fakes(monkeypatch, config, box)

    with pytest.raises(RuntimeError, match="workload failed"):
        adapter._run_capture(config, "c7i.large", "openssl", 5, "500ms", False, False, ())

    assert box.poweroffs == 1
    assert fleet.waited == [["i-test"]]


def test_perf_rows_preserves_options_and_keep_instance(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    box = FakeBox("zig-out/perf/20261118-120000-row-perf\n")
    fleet = install_fakes(monkeypatch, config, box)

    adapter._run_perf_rows(
        config,
        "c7i.2xlarge",
        "aws-lc",
        3,
        "1x",
        None,
        "cycles,instructions",
        2,
        True,
        True,
        True,
        True,
        False,
        True,
    )

    assert fleet.sizes == ["2xlarge"]
    command = box.commands[0][0]
    assert "bench/remote-perf-rows.sh" in command
    assert "--samples 3" in command
    assert "--events cycles,instructions" in command
    assert "--pin-cpu 2" in command
    for flag in (
        "--include-handshake",
        "--skip-disasm",
        "--full-linked-disasm",
        "--keep-perf-data",
    ):
        assert flag in command
    capture = tmp_path / "zig-out/perf/20261118-120000-row-perf-c7i.2xlarge-aws-lc"
    assert "ec2_crypto_backend=aws-lc" in (capture / "metadata.txt").read_text()
    assert box.poweroffs == 0
    assert fleet.waited == []


def test_click_preserves_remote_arguments_after_separator(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    received = []

    def run(*args):
        received.append(args)

    monkeypatch.setattr(adapter, "_run_capture", run)
    group = click.Group()
    adapter.register(group)

    result = CliRunner().invoke(
        group,
        ["capture", "--count", "1", "--", "--filter", "Benchmark AppPingPong"],
        obj=config,
    )

    assert result.exit_code == 0, result.output
    assert received[0][0] is config
    assert received[0][1] == "c7i.large"
    assert received[0][2] == "openssl"
    assert received[0][3] == 1
    assert received[0][-1] == ("--filter", "Benchmark AppPingPong")


@pytest.mark.parametrize(
    ("script", "argument", "expected_status"),
    [
        ("remote-capture.sh", "--invalid", 2),
        ("remote-perf-rows.sh", "--help", 0),
    ],
)
def test_workload_scripts_start_outside_the_checkout(tmp_path, script, argument, expected_status):
    executable = Path(__file__).parents[1] / script

    result = subprocess.run(
        [str(executable), argument],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == expected_status, result.stderr
    assert "No such file or directory" not in result.stderr


def test_dirty_tree_fails_before_fleet_construction(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    monkeypatch.setattr(adapter, "git", lambda *_args: " M src/lib.zig")

    def unexpected_fleet(_config):
        raise AssertionError("Fleet must not be constructed")

    monkeypatch.setattr(adapter, "Fleet", unexpected_fleet)
    with pytest.raises(click.ClickException, match="worktree is dirty"):
        adapter._run_capture(config, "c7i.large", "openssl", 5, "500ms", False, False, ())
