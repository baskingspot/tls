<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/static/logo-dark.svg">
    <img src="docs/static/logo.svg" alt="tls" height="48">
  </picture>
</h1>

Sans-I/O TLS 1.3 in Zig: no sockets, no engine allocations, caller-owned buffers.

The library is a TLS 1.3 state machine. You feed it the bytes you read off the
wire and it hands back the bytes to write. The socket, the event loop, and the
buffers stay yours.

It is in production use. The API is not frozen, so pin a commit.

## Performance

It is faster than OpenSSL's libssl on every comparable application-data row
measured, on x86_64, aarch64, and macOS Apple Silicon. Against rustls it wins on
AES-GCM on all three, and loses on small ChaCha20 records.

Headline row: AES-128-GCM ping-pong at 1350-byte records, near the common MTU
boundary, from the x86_64 capture
([`docs/research/perf/20260712-102422-ec2-c7i-2xlarge/`](docs/research/perf/20260712-102422-ec2-c7i-2xlarge/)):

| impl | ns/op | vs tls |
|---|---:|---:|
| tls | 790.7 | |
| rustls | 1447.5 | 1.83x slower |
| OpenSSL libssl | 1820.5 | 2.30x slower |

On this row the engine executes 42.7% of libssl's cycles per op and 54.8% of
rustls's. The perf counters and hot symbols are captured next to the timings.
libssl spends the difference in `WPACKET` and `tls13_cipher` wrapper work over
the same OpenSSL primitive. rustls spends it in `ChunkVecBuffer::write_to`, an
AVX-512 memmove, and malloc.

The evidence is three n=10 captures: a `c7i.2xlarge` (Intel Xeon, x86_64), a
`c7g.2xlarge` (Graviton3, aarch64), and an M1 Max (macOS). OpenSSL 3.6.3,
rustls 0.23.4x, Zig 0.15.2 ReleaseFast, captured before the library required Zig
0.16; the relative deltas stand and the absolute numbers are historical. The
smallest win over rustls on a comparable AES-GCM row is +69.86% on x86_64,
+39.30% on aarch64, and +59.51% on macOS. The smallest win over libssl is
+65.25% on x86_64, +24.16% on aarch64, and +29.87% on macOS. Every comparable
row carries a confidence interval and p=0.000.

Where it loses:

- **Small ChaCha20 records.** On x86_64, rustls is 50% to 56% faster at 16 and
  128 bytes. The samples sit in OpenSSL's ChaCha symbols, not in the framing, so
  this is a backend-primitive gap, not a record-path one. On aarch64 the two tie
  at 16 bytes and rustls is about 20% ahead at 128 bytes. The engine wins from
  1350 bytes up on both.
- **Measurement shapes differ.** rustls's harness times batches. The engine's
  and libssl's time single iterations. The row-by-row equivalence accounting is
  in [`docs/research/PERFORMANCE.md`](docs/research/PERFORMANCE.md).
- **The handshake is not a head-to-head.** The library verifies the server's
  CertificateVerify signature, rustls's harness uses a `NoVerifier` that skips
  it, and libssl's behavior without a trust store is opaque. That row is
  reported on its own and never quoted as a comparison.

AMD and older Graviton parts are not measured. Full row tables, methodology, and
the mechanism writeups are in
[`docs/research/PERFORMANCE.md`](docs/research/PERFORMANCE.md). The 15%
regression gate compares a fresh n=10 capture against the committed baseline
(`just bench-regression-check`). It runs on EC2, by hand, not in CI.

## Why it works this way

Most TLS libraries own their sockets, which means they own your I/O model too:
blocking calls, or their async runtime, or a callback shape they define. The
engine owns none of that. It is a state machine. Drive it from blocking reads,
epoll, io_uring, or an in-memory pipe. The examples do all four.

The engine never calls an allocator. You hand it buffers, it uses those buffers,
and that is all the memory it touches. One caveat: the primitive crypto is
delegated to a libcrypto backend (OpenSSL, AWS-LC, or BoringSSL, all three live
and CI-gated), and those backends allocate during setup and inside their own
routines. The engine's own code, the parsing, framing, transcript, and record
sequencing, allocates nothing.

Scope is narrow. TLS 1.3 only, on Linux and macOS. No 1.2 fallback to get
downgraded into, no DTLS, no Windows portability layer. Less code, and less to
attack.

The protocol path is Zig. AEAD, X25519 and P-256 ECDHE, and CertificateVerify
sign and verify come from the libcrypto backend, as does the SHA-2 under the key
schedule and transcript hash. Ed25519 certificate-chain signature verification
stays on `std.crypto`. The only C is at the edge: the partial C ABI and its
example.

## Start here

The [guide](https://baskingspot.dev/tls/) covers the buffer model, the drive
loop, and working client and server code. To start from running code instead,
these examples are built and run in CI:

- [`examples/in_memory_handshake.zig`](examples/in_memory_handshake.zig): both endpoints in one process, no sockets.
- [`examples/tcp_loopback.zig`](examples/tcp_loopback.zig): client and server over `std.net.Stream` loopback.
- [`examples/epoll_pingpong.zig`](examples/epoll_pingpong.zig): non-blocking Linux epoll ping-pong.
- [`examples/iouring_pingpong.zig`](examples/iouring_pingpong.zig): Linux io_uring ping-pong.
- [`integrations/tls-ktls/examples/ktls_pingpong.zig`](integrations/tls-ktls/examples/ktls_pingpong.zig): Zig 0.16 and Linux kTLS, with exact handoff, kernel data plane, live KeyUpdate, and close alerts.

Run them from the devshell:

```sh
nix develop .#openssl
just examples-ci
just integrations/tls-ktls/ci
```

`nix develop .#aws-lc` selects AWS-LC headers and libraries.
`nix develop .#boringssl` selects BoringSSL. The compiler infers the backend
family from those headers. The default shell selects OpenSSL.

## Supported surface

The engine owns protocol state, record framing, encryption, transcript hashing,
alerts, and key updates over caller-owned buffers. You own transport I/O, the
buffers, and the drive loop. Both client and server roles are implemented.

**Supported** means it is exercised in CI. **Partial** means the engine side is
proven and part of the contract belongs to the caller. **Out of scope** means it
is not coming.

| Feature | Status | Notes |
|---|---|---|
| TLS 1.3 handshake, 1-RTT | Supported | Client and server roles |
| TLS 1.2 fallback | Out of scope | No downgrade target, by design |
| DTLS | Out of scope | |
| Cipher suites | Supported | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| Key exchange: X25519, P-256 | Supported | ECDHE |
| Key exchange: P-384 | Supported | Opt-in; bidirectional OpenSSL 3.6 interop on every non-FIPS backend |
| Post-quantum: RFC 10024 hybrid groups | Supported | X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024; opt-in, OpenSSL-interoperable, upstream tlsfuzzer matrix |
| Server certificate auth | Supported | Hostname verification, chain validation, leaf policy |
| Client certificate auth | Supported | Both roles, EKU and KU enforcement, OpenSSL interop |
| Session resumption (PSK) | Partial | Ticket persistence, expiry, rotation, replay rejection, and SNI partitioning are caller obligations |
| 0-RTT early data | Partial | Offer, accept, reject are proven; anti-replay is the caller's, and the engine default is disabled |
| HelloRetryRequest | Supported | Both roles; forced-HRR OpenSSL interop is not gated |
| KeyUpdate | Supported | Both directions, both roles |
| Application data, alerts, `close_notify` | Supported | |
| kTLS offload | Supported | Linux only; key export and kernel data plane |
| Windows | Out of scope | Linux and macOS only |

Crypto primitives come from a libcrypto backend, selected at build time:

| Backend | Status |
|---|---|
| OpenSSL | Supported; selected by its `libcrypto.pc` and headers |
| AWS-LC | Supported; selected by its `libcrypto.pc` and headers |
| BoringSSL | Supported; selected by its `libcrypto.pc` and headers |

All three RFC 10024 groups use provider-backed pure ML-KEM with engine-owned
hybrid composition on OpenSSL, AWS-LC, and BoringSSL. The FIPS backend
identities do not advertise them. `-Dcrypto-fips=true` selects the FIPS
capability identity for OpenSSL or AWS-LC. It does not verify runtime
FIPS-provider activation. A BoGo conformance runner is deferred.

## Install

```sh
zig fetch --save git+https://github.com/baskingspot/tls
```

Add the module to your build:

```zig
const tls = b.dependency("tls", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("tls", tls.module("tls"));
```

Then import it:

```zig
const tls = @import("tls");
```

`std.crypto.tls` exists, so a file that imports both should bind this module as
`tlsx`.

The same dependency exposes `tls_std`, `tls_xev` (opt-in with `.xev = true`),
and `tls_ktls` (Linux). The [guide](https://baskingspot.dev/tls/#fresh-project-setup)
has the full setup.

tls builds with Zig 0.16 only.

## C ABI

The C surface is partial and client only: `include/ztls.h`, `libztls.a` from
`zig build -Dcapi`, and `examples/c_client.c`. It is wired into `just ci` as
`capi-ci`. The names stay `ztls_*` until the C namespace is chosen. The repo is
`tls`; the C prefix is not, and `libtls.a` belongs to LibreSSL. That decision is
[#149](https://github.com/baskingspot/tls/issues/149).

## Documentation

- The [guide](https://baskingspot.dev/tls/) covers the buffer model, the drive loop, and working client and server code.
- The [API reference](https://baskingspot.dev/tls/api/) documents every public declaration.
- [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) is the single source of truth for status.
- Design notes, the threat model, and the performance evidence live under [`docs/research/`](docs/research/).
- [`SECURITY.md`](SECURITY.md) is the security policy.

## Work on it

```sh
nix develop
just ci
```

`nix develop` provides the toolchain and the OpenSSL backend. `just` lists the
recipes, and `just ci` runs what CI runs.

## License

Apache-2.0. See `LICENSE`. Code adapted from Zig's standard library is covered by
`LICENSE-ZIG`. The logo files in `docs/static/` are baskingspot marks and are not
covered by either. See `docs/static/LICENSE`.

## How it's made

Built with LLM assistance. [How, in detail](https://github.com/baskingspot/.github/blob/main/docs/AI.md).

<a href="https://github.com/baskingspot"><img src="https://raw.githubusercontent.com/baskingspot/.github/main/brand/assets/badge.svg" alt="baskingspot" height="24"></a>
