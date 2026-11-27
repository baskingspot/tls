# Host-native launchpad re-take after #229 — 2026-11-27

Local re-take of the app-data and record rows on `launchpad` after the build
stopped pinning `apple_m1` on every aarch64 Linux host (#229).

The benchmark header now reports the host CPU:

```text
target: aarch64-linux-gnu
cpu: neoverse_v3
mode: fast
```

The previous launchpad and `c7g.2xlarge` captures report `cpu: apple_m1`
because `build.zig` replaced native CPU detection with an explicit model. That
pin dropped the host's SVE2 and crypto features. This capture is the same
harness with the default target restored; the compared libraries were already
built for the host.

## Command

```sh
scripts/bench-capture.sh --count=10 --benchtime=500ms \
  --filter 'BenchmarkRecordEncryptPrepared/,BenchmarkRecordDecrypt/,BenchmarkAppClientToServer/,BenchmarkAppServerToClient/,BenchmarkAppPingPong/,BenchmarkEncrypt/,BenchmarkDecrypt/'
scripts/bench-analyze.sh zig-out/perf/20261127-060603 > benchstat.txt
```

## Provenance

- git revision `069cdfadc19a1cef2637ff67a276e135d2fcea41`, clean tree.
- Zig 0.17.0, `-Doptimize=ReleaseFast`, `-Dcrypto=openssl`.
- OpenSSL 3.6.5; rustls 0.23.45; benchstat from nixpkgs 2026-09-29.
- Host: Linux `launchpad` 7.3.5, aarch64 Neoverse-V3, 8 vCPU. The benchmark
  header records `cpu: neoverse_v3` for all four binaries.
- Raw outputs are `tls.txt`, `evp.txt`, `libssl.txt`, and `rustls.txt`;
  `metadata.txt` records the toolchain, library paths, `lscpu`, and arguments.

## Scope and caveats

- This capture covers the 45 comparable TLS application-data rows and the
  record-protection rows. It excludes handshake, parser, and other tls-only
  diagnostic rows.
- It is a local `launchpad` measurement, not a replacement for the canonical
  n=10 `c7g.2xlarge` baseline. That baseline was built for `apple_m1` on a
  Graviton host and still needs a host-native re-take before its rows are
  quoted as a host-native Graviton result.
- The `evp.txt` rows are the crypto floor, not TLS-to-TLS comparisons. The
  `benchstat.txt` tables keep the boundaries separate.
