<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/static/logo-dark.svg">
    <img src="docs/static/logo.svg" alt="tls" height="48">
  </picture>
</h1>

TLS 1.3 in Zig: a sans-I/O engine over caller-owned buffers, with blocking, nonblocking, and kTLS integrations.

**Warning: the default `native` backend is for development and iteration, not
production.** No performance measurement against libcrypto or independent
security review exists for native. Production builds must select
`-Dcrypto=openssl` or `-Dcrypto=aws-lc`.

Native does not support RSA signing, encrypted PEM, or ML-KEM-1024. A native
server needs an ECDSA P-256 or P-384 credential. Native loads Ed25519 keys and
verifies Ed25519 chain signatures, but it does not support Ed25519 CertificateVerify.

The engine is a TLS 1.3 state machine. You feed it the bytes you read off the
wire and it hands back the bytes to write. The socket, the event loop, and the
buffers stay yours. The `tls_std`, `tls_nonblocking`, and `tls_ktls` modules
drive that engine over a transport; the core never opens one.

The libcrypto builds are faster than OpenSSL's libssl on every comparable
application-data row measured, on x86_64, aarch64, and macOS Apple Silicon.
Against rustls they win on AES-GCM on all three, and lose on small ChaCha20
records.

The engine is in production use with libcrypto. The test suite is 910 tests with
fuzzing on the parser and record-decrypt surfaces, four crypto backends, and
conformance runs against TLS-Anvil and tlsfuzzer. The API is not frozen, so pin a
version.

## What is in it

- [Why this exists](https://baskingspot.dev/tls/#why-this-exists): when to reach for it, when to use something mature instead, and what the engine and libcrypto each do. TLS 1.3 only, on Linux and macOS.
- [Supported surface](https://baskingspot.dev/tls/#supported-surface): what CI exercises, what the caller owns, and what is out of scope. Native crypto is the development default. OpenSSL and AWS-LC are the production choices.
- [The buffer model](https://baskingspot.dev/tls/#the-buffer-model): the engine owns the protocol, you own every buffer, and `RecordBuffer` frames a byte stream into records.
- [The drive loop](https://baskingspot.dev/tls/#the-drive-loop): working client and server code, the `pending_write` interlock, close semantics, and peer alerts.
- [Credentials and negotiation](https://baskingspot.dev/tls/#credentials-and-negotiation): server credentials, certificate policy, tickets, SNI, ALPN, and the RFC 10024 hybrid groups.
- [Integrations](https://baskingspot.dev/tls/#integrations): blocking streams, epoll, io_uring, and kTLS.
- [C ABI](https://baskingspot.dev/tls/#c-abi): the partial, client-only C surface: `baskingspot_tls_*`, `include/baskingspot_tls.h`, and `libbaskingspot_tls.a`.
- [Performance](https://baskingspot.dev/tls/#performance): the AES-128-GCM headline row against rustls and libssl, three n=10 captures, and where it loses.

Not implemented:

- Sockets, trust stores, and `connect()` in the core: `tls_std` has those on `std.Io.net`, and `tls_ktls` hands the data plane to the kernel. Every other transport is yours to drive.
- TLS 1.2, DTLS, and Windows: out of scope, with no downgrade target.
- Exporters: not planned until someone asks for one.

## Install

```sh
zig fetch --save https://baskingspot.dev/tls/v0.4.6.tar.gz
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

The same dependency exposes `tls_std`, `tls_nonblocking` (caller-driven server),
and `tls_ktls` (Linux).
The [guide](https://baskingspot.dev/tls/#install) has the full setup.

The library and every integration module build on Zig 0.17.

The default `native` backend uses `std.crypto` and in-tree primitives. It needs
no libcrypto headers, library, or `pkg-config`. `-Dcrypto=auto` remains
selectable and detects OpenSSL, AWS-LC, or BoringSSL from the selected headers.

For a production build, set `.crypto = .openssl` or `.crypto = .@"aws-lc"` in
`b.dependency`. The corresponding root build flags are `-Dcrypto=openssl` and
`-Dcrypto=aws-lc`.

An explicit libcrypto build needs `pkg-config`. The module calls
`linkSystemLibrary("crypto")`, and the C ABI step runs `pkg-config --variable=libdir
libcrypto` directly, so supplying a library path is not enough:

```nix
buildInputs = [ pkgs.openssl.dev pkgs.openssl.out pkgs.pkg-config ];
PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
```

Without the `.pc` file a libcrypto build fails while translating the headers
with a message about the dynamic system library `crypto` and no search paths.

Native verifies RSA PKCS#1 v1.5 certificate-chain signatures and RSA-PSS
CertificateVerify with SHA-256, SHA-384, and SHA-512. It loads unencrypted
P-256/P-384 PKCS#8 and SEC1 keys from PEM and DER, plus Ed25519 seeds from
PKCS#8.

## Documentation

- The [guide](https://baskingspot.dev/tls/) covers the buffer model, the drive loop, and working client and server code.
- The [API reference](https://baskingspot.dev/tls/api/) documents every public declaration.
- [`examples/`](examples/) has in-memory, TCP, epoll, and io_uring programs. CI builds and runs them.
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
