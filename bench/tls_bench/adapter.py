"""tls benchmark workloads over the ec2bench fleet and SSM transport."""

import re
import shlex
import subprocess
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import click
from ec2bench.box import Box
from ec2bench.cli import box_for, ensure_up
from ec2bench.config import Config
from ec2bench.fleet import Fleet
from ec2bench.runs import git

_BACKENDS = ("openssl", "aws-lc", "boringssl")
_EVENTS = (
    "cycles,instructions,branches,branch-misses,cache-misses,L1-dcache-load-misses,LLC-load-misses"
)
_REMOTE_TIMEOUT_SECONDS = 6 * 60 * 60

# Keep .git and tracked PEM fixtures. Remote results survive the mirrored
# sync. Generated directories stay out at every depth.
_SYNC_EXCLUDES = (
    "/.bench-cache/",
    "/.direnv/",
    "/.envrc.local",
    "/.tmp/",
    ".venv/",
    ".zig-cache/",
    "zig-out/",
    ".terraform",
    "*.tfstate",
    "*.tfstate.backup",
    "__pycache__",
    "*.pyc",
)


@dataclass(frozen=True)
class _Session:
    box: Box
    instance: dict[str, Any]
    instance_type: str


def _matrix(value: str) -> list[str]:
    matrix = [item for item in re.split(r"[\s,]+", value.strip()) if item]
    if not matrix:
        raise click.UsageError("The instance matrix cannot be empty")
    return matrix


def _target_for_type(config: Config, instance_type: str) -> tuple[str, str]:
    family, separator, size = instance_type.partition(".")
    if not separator or not family or not size:
        raise click.UsageError(f"Invalid EC2 instance type: {instance_type}")
    matches = [
        name
        for name, target in config.targets.items()
        if target["instance_type"].partition(".")[0] == family
    ]
    if len(matches) != 1:
        raise click.UsageError(f"No unique target for EC2 instance family: {family}")
    return matches[0], size


def _check_clean(config: Config, allow_dirty: bool) -> None:
    if allow_dirty:
        return
    status = git(config.root, "status", "--porcelain", "--untracked-files=all")
    if status:
        click.echo(status, err=True)
        raise click.ClickException(
            "The worktree is dirty. Commit first or use --allow-dirty for a smoke run."
        )


@contextmanager
def _session(
    config: Config, fleet: Fleet, instance_type: str, keep_instance: bool
) -> Generator[_Session]:
    target, size = _target_for_type(config, instance_type)
    existing = {instance["InstanceId"] for instance in fleet.selected([target])}
    # The six-hour workload deadline must expire before the box's TTL guard.
    outcome = ensure_up(fleet, [target], ttl=config.fleet["max_ttl"], size=size)[target]
    if outcome.error:
        raise click.ClickException(f"{target}: {outcome.error}") from outcome.error
    instance_id = outcome.value
    if instance_id is None:
        raise click.ClickException(f"{target}: launch returned no instance ID")

    launched = instance_id not in existing
    box: Box | None = None
    try:
        instance = fleet.one(target)
        box = box_for(fleet, instance)
        actual_type = instance["InstanceType"]
        if actual_type != instance_type:
            raise click.ClickException(
                f"{target} runs {actual_type}, not {instance_type}. "
                f"Stop it with `bench down {target}` before requesting a different size."
            )
        remote_dir = config.project["remote_dir"]
        box.upload_contents(
            config.root,
            remote_dir,
            exclude=_SYNC_EXCLUDES,
            delete=True,
        )
        # rsync preserves the source UID and GID. Root must own the checkout
        # before git accepts it for the provenance checks.
        box.run(f"chown -R root:root -- {shlex.quote(remote_dir)}", timeout=120)
        yield _Session(box, instance, instance_type)
    finally:
        if launched and not keep_instance:
            if box is None:
                fleet.terminate([instance_id])
            else:
                box.poweroff()
            fleet.wait_terminated([instance_id])


_RESULT_ROOT = ("zig-out", "perf")


def _is_result_path(line: str) -> bool:
    if any(character.isspace() for character in line):
        return False
    path = PurePosixPath(line)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and len(path.parts) >= 3
        and path.parts[:2] == _RESULT_ROOT
    )


def _result_path(output: str) -> PurePosixPath:
    """Return the capture directory printed by the remote workload.

    `Box.run` merges stdout and stderr, so the result line has no fixed
    position: a log line can arrive after it. Match the line by shape and take
    the last one, so a log line that merely mentions the path cannot win.
    """
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    matches = [line for line in lines if _is_result_path(line)]
    if not matches:
        seen = "\n".join(f"  {line}" for line in lines[-5:]) or "  (no output)"
        raise click.ClickException(
            "The remote workload returned no capture directory under zig-out/perf/.\n"
            f"Last lines received:\n{seen}"
        )
    return PurePosixPath(matches[-1])


def _run_remote(config: Config, box: Box, script: str, args: Sequence[str]) -> PurePosixPath:
    command = [
        "nix",
        "--extra-experimental-features",
        "nix-command flakes",
        "develop",
        ".#openssl",
        "--command",
        script,
        *args,
    ]
    remote_dir = config.project["remote_dir"]
    shell = f"cd {shlex.quote(remote_dir)} && {shlex.join(command)}"
    output = box.run(
        shell,
        timeout=_REMOTE_TIMEOUT_SECONDS,
        stream=lambda line: click.echo(line, err=True),
    )
    return _result_path(output)


def _download(
    config: Config, session: _Session, remote: PurePosixPath, crypto_backend: str
) -> Path:
    safe_instance = re.sub(r"[^A-Za-z0-9._-]", "_", session.instance_type)
    local = config.results_dir / f"{remote.name}-{safe_instance}-{crypto_backend}"
    if local.exists():
        raise click.ClickException(f"Local result already exists: {local}")
    source = f"{config.project['remote_dir']}/{remote}"
    session.box.download(source, local)
    with (local / "metadata.txt").open("a") as metadata:
        metadata.write(
            "\n[ec2]\n"
            f"ec2_instance_type={session.instance_type}\n"
            f"ec2_region={config.project['region']}\n"
            f"ec2_instance_id={session.instance['InstanceId']}\n"
            f"ec2_crypto_backend={crypto_backend}\n"
            f"ec2_image_version={config.project['image_version']}\n"
        )
    return local


def _analyze(config: Config, capture: Path) -> None:
    with (capture / "benchstat.txt").open("w") as output:
        subprocess.run(
            [str(config.root / "scripts/bench-analyze.sh"), str(capture)],
            cwd=config.root,
            check=True,
            stdout=output,
        )


def _run_capture(
    config: Config,
    instance_types: str,
    crypto_backend: str,
    count: int,
    benchtime: str,
    allow_dirty: bool,
    keep_instance: bool,
    remote_args: tuple[str, ...],
) -> None:
    _check_clean(config, allow_dirty)
    fleet = Fleet(config)
    for instance_type in _matrix(instance_types):
        with _session(config, fleet, instance_type, keep_instance) as session:
            args = [
                "--crypto-backend",
                crypto_backend,
                "--count",
                str(count),
                "--benchtime",
                benchtime,
            ]
            if allow_dirty:
                args.append("--allow-dirty")
            args.extend(remote_args)
            remote = _run_remote(config, session.box, "bench/remote-capture.sh", args)
            capture = _download(config, session, remote, crypto_backend)
            _analyze(config, capture)
            click.echo(str(capture))


def _run_perf_rows(
    config: Config,
    instance_type: str,
    crypto_backend: str,
    count: int,
    benchtime: str,
    samples: int | None,
    events: str,
    pin_cpu: int,
    include_handshake: bool,
    skip_disasm: bool,
    full_linked_disasm: bool,
    keep_perf_data: bool,
    allow_dirty: bool,
    keep_instance: bool,
) -> None:
    _check_clean(config, allow_dirty)
    fleet = Fleet(config)
    with _session(config, fleet, instance_type, keep_instance) as session:
        args = [
            "--crypto-backend",
            crypto_backend,
            "--count",
            str(count),
            "--benchtime",
            benchtime,
            "--samples",
            str(samples if samples is not None else count),
            "--events",
            events,
            "--pin-cpu",
            str(pin_cpu),
        ]
        for enabled, flag in (
            (include_handshake, "--include-handshake"),
            (skip_disasm, "--skip-disasm"),
            (full_linked_disasm, "--full-linked-disasm"),
            (keep_perf_data, "--keep-perf-data"),
            (allow_dirty, "--allow-dirty"),
        ):
            if enabled:
                args.append(flag)
        remote = _run_remote(config, session.box, "bench/remote-perf-rows.sh", args)
        capture = _download(config, session, remote, crypto_backend)
        click.echo(str(capture))


def register(group: click.Group) -> None:
    """Attach tls workload commands to the generic ec2bench CLI."""

    @group.command(context_settings={"help_option_names": ["-h", "--help"]})
    @click.option(
        "--instance-types",
        default="c7i.large",
        show_default=True,
        help="Comma-separated or space-separated EC2 instance types.",
    )
    @click.option(
        "--crypto-backend", type=click.Choice(_BACKENDS), default="openssl", show_default=True
    )
    @click.option("--count", type=click.IntRange(min=1), default=5, show_default=True)
    @click.option("--benchtime", default="500ms", show_default=True)
    @click.option("--allow-dirty", is_flag=True, help="Permit a dirty worktree for smoke runs.")
    @click.option("--keep-instance", is_flag=True, help="Leave each new box alive until its TTL.")
    @click.argument("remote_args", nargs=-1, type=click.UNPROCESSED)
    @click.pass_obj
    def capture(
        config: Config,
        instance_types: str,
        crypto_backend: str,
        count: int,
        benchtime: str,
        allow_dirty: bool,
        keep_instance: bool,
        remote_args: tuple[str, ...],
    ) -> None:
        """Capture wall-time comparisons. Put remote benchmark filters after --."""
        _run_capture(
            config,
            instance_types,
            crypto_backend,
            count,
            benchtime,
            allow_dirty,
            keep_instance,
            remote_args,
        )

    @group.command(name="perf-rows", context_settings={"help_option_names": ["-h", "--help"]})
    @click.option("--instance-type", default="c7i.2xlarge", show_default=True)
    @click.option(
        "--crypto-backend", type=click.Choice(_BACKENDS), default="openssl", show_default=True
    )
    @click.option("--count", type=click.IntRange(min=1), default=5, show_default=True)
    @click.option("--benchtime", default="500ms", show_default=True)
    @click.option(
        "--samples", type=click.IntRange(min=1), default=None, help="Rustls sample count."
    )
    @click.option("--events", default=_EVENTS, show_default=True, help="Perf stat event list.")
    @click.option("--pin-cpu", type=click.IntRange(min=0), default=1, show_default=True)
    @click.option("--include-handshake", is_flag=True)
    @click.option("--skip-disasm", is_flag=True)
    @click.option("--full-linked-disasm", is_flag=True)
    @click.option("--keep-perf-data", is_flag=True)
    @click.option("--allow-dirty", is_flag=True, help="Permit a dirty worktree for smoke runs.")
    @click.option("--keep-instance", is_flag=True, help="Leave a new box alive until its TTL.")
    @click.pass_obj
    def perf_rows(
        config: Config,
        instance_type: str,
        crypto_backend: str,
        count: int,
        benchtime: str,
        samples: int | None,
        events: str,
        pin_cpu: int,
        include_handshake: bool,
        skip_disasm: bool,
        full_linked_disasm: bool,
        keep_perf_data: bool,
        allow_dirty: bool,
        keep_instance: bool,
    ) -> None:
        """Capture row perf counters and disassembly on one EC2 box."""
        _run_perf_rows(
            config,
            instance_type,
            crypto_backend,
            count,
            benchtime,
            samples,
            events,
            pin_cpu,
            include_handshake,
            skip_disasm,
            full_linked_disasm,
            keep_perf_data,
            allow_dirty,
            keep_instance,
        )
