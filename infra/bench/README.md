# EC2 benchmarks

The `tls-bench` fleet uses `baskingspot/infra`. This repository owns the project-specific image fragment and workload adapter. The shared modules own IAM, the reaper, security groups, launch templates, and the base image.

No box accepts inbound connections. SSH uses SSM and a key that EC2 Instance Connect accepts for 60 seconds. The harness uses an assumed role and creates no access key.

## Retire the old stacks

Complete this migration step before you initialize or apply the new roots. The old roots can have Git-ignored Terraform state in `infra/bench/` and `infra/iam/`.

Use a pre-migration checkout that contains the old configuration and local state. Destroy the base stack first. Destroy IAM second:

```sh
export AWS_PROFILE=<iam-capable-bootstrap-profile>
tofu -chdir=infra/bench destroy
tofu -chdir=infra/iam destroy
```

Do not run either command against the rewritten roots. The new configuration replaces every old resource address.

## Bootstrap

The base stack finds the shared `baskingspot-bench` network by tag. Apply `stacks/bench-network/` from `baskingspot/infra` once before the first base-stack apply.

Set `TF_VAR_account_id` to the twelve-digit AWS account ID. Use an IAM-capable AWS profile for both stacks. Apply IAM before the base stack:

```sh
tofu -chdir=infra/iam init
tofu -chdir=infra/iam apply
tofu -chdir=infra/bench init
tofu -chdir=infra/bench apply
```

Configure `tls-bench` as an AWS role profile. Set `role_arn` from the IAM stack's `role_arn` output. Set `source_profile` to an SSO profile with access to that role. Set the region to `us-west-2`.

The devshell supplies `session-manager-plugin`, `uv`, and OpenTofu. No command reads OpenTofu state during a benchmark.

## Fleet commands

Run these commands from the repository root:

```sh
uv run --project bench bench up c7i
uv run --project bench bench ssh c7i -- uname -a
uv run --project bench bench ls
uv run --project bench bench down c7i
```

The `c7i` target defaults to `c7i.large`. The `c7g` target defaults to `c7g.2xlarge`. Use `--size` with `up` to override only the size:

```sh
uv run --project bench bench up c7i --size 2xlarge
```

Every new instance has an expiry tag. The on-box TTL guard and the external reaper bound its lifetime.

## Capture workloads

The existing just recipes call the adapter:

```sh
just bench-remote-capture
just bench-remote-capture --instance-types c7i.large,c7g.2xlarge
just bench-remote-capture --count 1 --benchtime 1x -- \
  --filter 'BenchmarkAppPingPong/.*/size=128'
just bench-remote-perf-rows
```

The capture command defaults to one `c7i.large` box. The perf command defaults to one `c7i.2xlarge` box. Both commands reject a dirty worktree unless `--allow-dirty` is present.

The adapter copies the checkout to `/root/tls`, including `.git`. It excludes local credentials, state, caches, virtual environments, and results. It runs `bench/remote-capture.sh` or `bench/remote-perf-rows.sh` through `nix develop .#openssl`.

Results land under `zig-out/perf/`. The instance-type and backend suffix remains unchanged. The metadata records the instance ID instead of a public IP address. The wall-time capture also writes `benchstat.txt` through `scripts/bench-analyze.sh`.

A new box terminates at the end of its command. The adapter waits for EC2 to report termination before another size uses the same target. `--keep-instance` leaves a new box alive until its expiry. An existing box from `bench up` remains under operator control.

`just bench-regression-check` uses a `c7i.2xlarge` capture with ten samples. It then compares the fresh capture with the committed baseline.
