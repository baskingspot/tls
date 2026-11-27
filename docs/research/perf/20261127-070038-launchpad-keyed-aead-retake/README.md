# #229 re-take: keyed native AES-GCM context — 2026-11-27

`#230` measured a keyed native AES-GCM context at −1.77% seal and −1.99% open
at 4 KiB, and left it out: about 2% was not worth a 560-byte context and a
tagged union. Those numbers were taken while `build.zig` pinned every aarch64
Linux build to `apple_m1` (#229). This capture re-runs the same A/B with the
host CPU target.

## Result

`benchstat` over 60 samples per row per binary, `taskset -c 3`, ABBA-alternated
across three rounds:

| row | baseline | keyed context | delta |
| --- | ---: | ---: | ---: |
| `aes256/seal/4096` | 3.374 µs | 3.309 µs | −1.93% |
| `aes256/open/4096` | 3.393 µs | 3.319 µs | −2.18% |
| `aes256/seal/16384` | 12.90 µs | 12.80 µs | −0.70% |
| `aes256/open/16384` | 12.92 µs | 12.81 µs | −0.81% |

The re-take lands within about 0.2 percentage points of the original result at
4 KiB and reproduces the 16 KiB rows at under 1%. The decision in `#230` does
not change: the context stays out.

## Method

- Baseline: `issue-229` at `43b499ff351ba765841e9c8134f2c7305fbd2a79`, native
  backend, no keyed state.
- Candidate: the same tree plus `keyed-context.patch`, which stores the AES key
  schedule and all 16 GHASH H powers in `AeadContext` and drops the per-call
  key expansion and GHASH setup. The patch is the experiment, not a proposed
  commit.
- Both binaries built with Zig 0.17.0, `-Doptimize=ReleaseFast`,
  `-Dcrypto=native`. `ldd` reports `not a dynamic executable` for both.
- The benchmark header reports `cpu: neoverse_v3` for every run; this is the
  host target after #229.
- Each invocation ran `--filter aes256/ --count=10 --benchtime=500ms`; six
  invocations per side, 60 samples per row. `baseline.txt` and `keyed.txt` are
  the concatenated raw outputs; the `r*-*.txt` files are the individual runs.

## Caveats

This is a local measurement on a shared `launchpad` box, not an EC2 production
comparison. Pinning and ABBA alternation reduce drift, but the result is only
about a 1–2% effect; treat it as a decision check, not a precise performance
claim. The candidate patch is retained for reproducibility and is not part of
the fix.
