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

It is faster than OpenSSL's libssl on every comparable application-data row
measured, on x86_64, aarch64, and macOS Apple Silicon. Against rustls it wins on
AES-GCM on all three, and loses on small ChaCha20 records.

It is in production use. The test suite is 910 tests with fuzzing on the parser
and record-decrypt surfaces, three crypto backends, and conformance runs against
TLS-Anvil and tlsfuzzer. The API is not frozen, so pin a commit.

## What is in it

- [Why this exists](https://baskingspot.dev/tls/#why-this-exists): when to reach for it, when to use something mature instead, and what the engine and libcrypto each do. TLS 1.3 only, on Linux and macOS.
- [Supported surface](https://baskingspot.dev/tls/#supported-surface): what CI exercises, what the caller owns, and what is out of scope. The libcrypto backend is OpenSSL, AWS-LC, or BoringSSL, chosen at build time.
- [The buffer model](https://baskingspot.dev/tls/#the-buffer-model): the engine owns the protocol, you own every buffer, and `RecordBuffer` frames a byte stream into records.
- [The drive loop](https://baskingspot.dev/tls/#the-drive-loop): working client and server code, the `pending_write` interlock, close semantics, and peer alerts.
- [Credentials and negotiation](https://baskingspot.dev/tls/#credentials-and-negotiation): server credentials, certificate policy, tickets, SNI, ALPN, and the RFC 10024 hybrid groups.
- [Integrations](https://baskingspot.dev/tls/#integrations): blocking streams, epoll, io_uring, libxev, and kTLS.
- [C ABI](https://baskingspot.dev/tls/#c-abi): the partial, client-only C surface: `baskingspot_tls_*`, `include/baskingspot_tls.h`, and `libbaskingspot_tls.a`.
- [Performance](https://baskingspot.dev/tls/#performance): the AES-128-GCM headline row against rustls and libssl, three n=10 captures, and where it loses.

Not implemented:

- Sockets, trust stores, and `connect()`: the engine is the state machine, and you write the drive loop.
- TLS 1.2, DTLS, and Windows: out of scope, with no downgrade target.
- Exporters: not planned until someone asks for one.

## Install

```sh
zig fetch --save https://baskingspot.dev/tls/v0.1.0.tar.gz
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
and `tls_ktls` (Linux). The [guide](https://baskingspot.dev/tls/#install)
has the full setup.

The library builds with Zig 0.16 only.

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
