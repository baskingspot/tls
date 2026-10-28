+++
title = "tls"
+++

Sans-I/O TLS 1.3 in Zig: no sockets, no engine allocations, caller-owned buffers.

A TLS 1.3 implementation that does no I/O. You feed it the bytes you read off
the wire; it hands you back the bytes to write. Your socket, your event loop,
your buffers. The engine does the protocol.

Production readiness is tracked per commit in
[`PRODUCTION_READINESS.md`](https://github.com/baskingspot/tls/blob/main/PRODUCTION_READINESS.md);
there is no tagged release, so pin a commit.

- [Why this exists](#why-this-exists): when to reach for it, when to use something mature instead, and what the engine and libcrypto each do.
- [Supported surface](#supported-surface): what CI exercises, what the caller owns, and what is out of scope.
- [The buffer model](#the-buffer-model): the engine owns the protocol, you own every buffer, and `RecordBuffer` frames a byte stream into records.
- [The drive loop](#the-drive-loop): working client and server code, the `pending_write` interlock, close semantics, and peer alerts.
- [Credentials and negotiation](#credentials-and-negotiation): server credentials, certificate policy, tickets, SNI, ALPN, and the RFC 10024 hybrid groups.
- [Integrations](#integrations): blocking streams, epoll, io_uring, libxev, and kTLS.
- [C ABI](#c-abi): the partial, client-only C surface.
- [Performance](#performance): the headline row, the three captures, and where it loses.
- [Limits](#limits): what the engine does not do.

The [API reference](api/) documents every public declaration.

# Getting started

## Install

```sh
zig fetch --save git+https://github.com/baskingspot/tls
```

Add the module to your build:

```zig
const tls = b.dependency("tls", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("tls", tls.module("tls"));
```

The same dependency exposes the integration modules. The import name is yours to
choose:

| Module     | Requirement                                      |
| ---------- | ------------------------------------------------ |
| `tls`      | Zig 0.16                                         |
| `tls_std`  | Zig 0.16                                         |
| `tls_xev`  | Zig 0.16 and the dependency option `.xev = true` |
| `tls_ktls` | Zig 0.16 on Linux                                |

A libxev consumer opts in when resolving the dependency, so a core-only consumer
does not fetch libxev:

```zig
const tls = b.dependency("tls", .{ .target = target, .optimize = optimize, .xev = true });
exe.root_module.addImport("tls_xev", tls.module("tls_xev"));
```

All modules use the same libcrypto headers and library, selected through
`PKG_CONFIG_PATH`. The compiler infers OpenSSL, AWS-LC, or BoringSSL from the
headers. Add `.@"crypto-fips" = true` only for an explicitly configured FIPS
build. Importing `tls_xev` without `.xev = true` reports the missing opt-in.

The integration directories keep standalone manifests for in-tree development.
External consumers depend only on the root package.

## Read the examples

To start from running code, these examples are built and run in CI:

- [`examples/in_memory_handshake.zig`](https://github.com/baskingspot/tls/blob/main/examples/in_memory_handshake.zig): both engines in one process, no sockets. Read this first: it shows the full 1-RTT handshake and application data in both directions.
- [`examples/tcp_loopback.zig`](https://github.com/baskingspot/tls/blob/main/examples/tcp_loopback.zig): client and server over `std.net.Stream` on loopback.
- [`examples/epoll_pingpong.zig`](https://github.com/baskingspot/tls/blob/main/examples/epoll_pingpong.zig): non-blocking Linux epoll client/server ping-pong.
- [`examples/iouring_pingpong.zig`](https://github.com/baskingspot/tls/blob/main/examples/iouring_pingpong.zig): Linux io_uring client/server ping-pong.
- [`integrations/tls-ktls/examples/ktls_pingpong.zig`](https://github.com/baskingspot/tls/blob/main/integrations/tls-ktls/examples/ktls_pingpong.zig): Zig 0.16/Linux userspace handshake followed by kernel TX/RX, live KeyUpdate, and explicit close alerts.

Run them from the devshell:

```sh
nix develop .#openssl
just examples-ci
just integrations/tls-ktls/ci
```

`nix develop .#aws-lc` selects AWS-LC headers and libraries. `nix develop .#boringssl` selects BoringSSL. The compiler infers the backend family from those headers. The default shell selects OpenSSL.

`just examples-ci` builds and runs the core paths. The Zig 0.16 integration gate runs the packaged examples and tests. When this page and the examples disagree, the examples are right.

# Why this exists

A TLS library that owns its sockets owns your I/O model too. OpenSSL wants its
BIOs. A language-native library wants a blocking stream, or its own async
runtime, or a callback shape it defines. Pull one in and its assumptions about
how bytes move become your assumptions.

That works until you are writing an io_uring server, or running a custom event
loop, or accounting for every allocation. Then a library that owns its sockets
fights you, and you spend the time wrapping and shimming a design that assumed
it was in charge.

Sans-I/O separates the protocol from the transport. You give the engine the
bytes that came off the wire. It tells you what to send back and hands you the
decrypted application data. It never touches a socket, never blocks, and has no
thread of its own.

rustls showed this model works in production. The difference here is memory: the
engine never calls an allocator.

## When to use it

- You own your I/O and want to keep owning it: epoll, io_uring, a green-thread
  scheduler, an in-memory test harness. The engine has no opinion about how you
  run.
- You care where memory comes from. The engine holds no heap state. You give it
  buffers and it uses those, so memory behavior is something to reason about
  rather than profile after the fact.
- You are on Zig and do not want a C library's I/O assumptions in your build,
  even though the primitive crypto underneath is still libcrypto.
- You want TLS 1.3 and nothing else. No 1.2 downgrade path, no DTLS, no Windows
  portability layer.

## Why trust it

The evidence sits in
[`PRODUCTION_READINESS.md`](https://github.com/baskingspot/tls/blob/main/PRODUCTION_READINESS.md)
and is recorded per commit. The protocol is checked against RFC 8448 vectors,
Wycheproof boundary vectors, OpenSSL interop in both directions, and the
TLS-Anvil and tlsfuzzer conformance suites. The parser and record-decrypt
surfaces are fuzzed with `zig build test --fuzz`. A merge runs three crypto
backends (OpenSSL, AWS-LC, BoringSSL), four transport examples, the C ABI
example, a distribution smoke test, and valgrind.

Third-party audit status is stated in
[`SECURITY.md`](https://github.com/baskingspot/tls/blob/main/SECURITY.md).

## Where the work happens

The engine never calls an allocator. You hand it buffers, it uses those buffers,
and that is all the memory it touches. One caveat: the primitive crypto is
delegated to a libcrypto backend (OpenSSL, AWS-LC, or BoringSSL, all three live
and CI-gated), and those backends allocate during setup and inside their own
routines. The engine's own code, the parsing, framing, transcript, and record
sequencing, allocates nothing.

The protocol path is Zig. AEAD, X25519 and P-256 ECDHE, and CertificateVerify
sign and verify come from the libcrypto backend, as does the SHA-2 under the key
schedule and transcript hash. Ed25519 certificate-chain signature verification
stays on `std.crypto`. The only C is at the edge: the partial C ABI and its
example.

# Supported surface

The engine owns protocol state, record framing, encryption, transcript hashing,
alerts, and key updates over caller-owned buffers. You own transport I/O, the
buffers, and the drive loop. Both client and server roles are implemented.

**Supported** means it is exercised in CI. **Partial** means the engine side is
proven and part of the contract belongs to the caller. **Out of scope** means it
is not coming.

| Feature                                  | Status       | Notes                                                                                                               |
| ---------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------- |
| TLS 1.3 handshake, 1-RTT                 | Supported    | Client and server roles                                                                                             |
| TLS 1.2 fallback                         | Out of scope | No downgrade target, by design                                                                                      |
| DTLS                                     | Out of scope |                                                                                                                     |
| Cipher suites                            | Supported    | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305                                                                         |
| Key exchange: X25519, P-256              | Supported    | ECDHE                                                                                                               |
| Key exchange: P-384                      | Supported    | Opt-in; bidirectional OpenSSL 3.6 interop on every non-FIPS backend                                                 |
| Post-quantum: RFC 10024 hybrid groups    | Supported    | X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024; opt-in, OpenSSL-interoperable, upstream tlsfuzzer matrix |
| Server certificate auth                  | Supported    | Hostname verification, chain validation, leaf policy                                                                |
| Client certificate auth                  | Supported    | Both roles, EKU and KU enforcement, OpenSSL interop                                                                 |
| Session resumption (PSK)                 | Partial      | Ticket persistence, expiry, rotation, replay rejection, and SNI partitioning are caller obligations                 |
| 0-RTT early data                         | Partial      | Offer, accept, reject are proven; accept is gated on the ticket's exact cipher suite, ALPN, and first identity; anti-replay is the caller's, and the engine default is disabled |
| HelloRetryRequest                        | Supported    | Both roles; forced-HRR OpenSSL interop is not gated                                                                 |
| KeyUpdate                                | Supported    | Both directions, both roles                                                                                         |
| Application data, alerts, `close_notify` | Supported    |                                                                                                                     |
| kTLS offload                             | Supported    | Linux only; key export and kernel data plane                                                                        |
| Windows                                  | Out of scope | Linux and macOS only                                                                                                |

Crypto primitives come from a libcrypto backend, selected at build time:

| Backend   | Status                                                |
| --------- | ----------------------------------------------------- |
| OpenSSL   | Supported; selected by its `libcrypto.pc` and headers |
| AWS-LC    | Supported; selected by its `libcrypto.pc` and headers |
| BoringSSL | Supported; selected by its `libcrypto.pc` and headers |

All three RFC 10024 groups use provider-backed pure ML-KEM with engine-owned
hybrid composition on OpenSSL, AWS-LC, and BoringSSL. The FIPS backend
identities do not advertise them. `-Dcrypto-fips=true` selects the FIPS
capability identity for OpenSSL or AWS-LC. It does not verify runtime
FIPS-provider activation. A BoGo conformance runner is deferred.

# The buffer model

The engine is a pure TLS 1.3 state machine. You supply the bytes, the buffers, the transport I/O, and the drive loop. Protocol code allocates no memory; production crypto backends can allocate inside provider operations.

## Mental model

```
     Network bytes (TLS records)
           |         ^
     feed  |         | drain
           v         |
     +-----+---------+-----+
     |                     |
     |    Engine (tls)     |
     |    state machine    |
     |                     |
     +-----+---------+-----+
           |         ^
    read   |         | write
           v         |
     Plaintext application data
```

The engine owns the TLS protocol: framing, encryption, transcript hashing, alerts, and key ratcheting. The caller owns all buffers, all transport I/O, and the drive loop that moves bytes between the two.

## Buffer ownership

- **Caller owns every buffer.** The engine holds no heap state and never allocates.
- **`out`**: caller-provided scratch for records the engine emits (ClientHello, Finished, app data, alerts).
- **`storage`**: caller-provided backing for `RecordBuffer`, which turns a byte stream into whole records.
- **Records are decrypted in place.** `RecordBuffer.next()` returns a mutable slice into `storage`. Hand it to `handleRecord`, which may mutate it during decryption. The slice is valid only until the next `next()` or `writable()` call.
- **Application data** returned in `Event.application_data` is a slice into that same record buffer. Copy it before the next engine call if you need it longer.

## Frame records with `RecordBuffer`

Transports deliver bytes; the engine consumes complete TLS records. `RecordBuffer` bridges the gap.

```zig
var storage: [tls.RecordBuffer.recommended_storage]u8 = undefined;
var rb: tls.RecordBuffer = .init(&storage);

// Read transport bytes into the free region.
const n = try stream.read(rb.writable());
if (n == 0) return error.PeerClosed;
rb.advance(n);

// Pull whole records and feed them to the engine.
while (try rb.next()) |record| {
    const ev = try hs.handleRecord(record, &out);
    // ... handle event
}
```

- `writable()` compacts unconsumed bytes to the front, then returns the largest contiguous free region.
- `advance(n)` reports how many bytes were written.
- `next()` returns `null` until a full record is buffered. No partial record is ever handed out.
- `recommended_storage = 2 * min_storage` (about 33 KiB). This fits a partial record plus a full one, so a read that straddles a boundary still makes progress.

## Buffer sizing

| Purpose              | Public type or bound           | Capacity contract                        |
| -------------------- | ------------------------------ | ---------------------------------------- |
| Client output        | `ClientHandshake.OutBuffer`    | Holds one maximum wire record.           |
| Server output        | `ServerHandshake.OutBuffer`    | Holds one maximum wire record.           |
| Server flight        | `ServerHandshake.FlightBuffer` | Holds one authenticated server flight.   |
| Stream input         | `RecordBuffer.Storage`         | Uses `RecordBuffer.recommended_storage`. |
| Minimum stream input | `RecordBuffer.MinStorage`      | Holds one maximum wire record.           |

Use the public buffer types unless the application needs custom storage. Smaller custom slices can return `error.BufferTooShort`.

# The drive loop

Every connection follows the same pattern, whether client or server:

1. **Emit** — call an engine method that produces bytes (`start`, `handleRecord`, `sendApplicationData`).
2. **Write** — send those bytes to the transport.
3. **Acknowledge** — call `completeWrite()` to tell the engine the bytes were sent.
4. **Read** — pull more bytes from the transport into `RecordBuffer`.
5. **Repeat** until connected, then keep repeating for application data.

## Client drive loop

```zig
var out: tls.ClientHandshake.OutBuffer = .empty;
var storage: tls.RecordBuffer.Storage = .empty;
var rb: tls.RecordBuffer = .init(&storage.buffer);

var random: tls.Random = undefined;
std.crypto.random.bytes(&random.data);

var hs: tls.ClientHandshake = .init(.{
    .keypairs = try .init(keypair),
    .host_name = "example.com",
    .now_sec = std.time.timestamp(),
    .random = random,
});

try stream.writeAll(try hs.start(&out.buffer));
hs.completeWrite();

while (!hs.isConnected()) {
    const n = try stream.read(rb.writable());
    if (n == 0) return error.ServerClosed;
    rb.advance(n);
    while (try rb.next()) |record| switch (try hs.handleRecord(record, &out.buffer)) {
        .write => |w| {
            try stream.writeAll(w);
            hs.completeWrite();
        },
        .application_data, .closed => return error.UnexpectedDuringHandshake,
        .none => {},
    };
}
```

## Server drive loop

The server loop is identical in shape, with two differences:

1. `ServerHandshake.Config` carries the ServerHello random up front.
2. Server credentials are configured before the ClientHello arrives, and `sendServerFlightBuffered` sends the authenticated server flight after ServerHello is written.

```zig
var random: tls.Random = undefined;
std.crypto.random.bytes(&random.data);
var hs: tls.ServerHandshake = .init(.{
    .keypairs = try .init(server_keypair),
    .random = random,
    .alpn_protocols = &.{"h2"},
});

var signer: tls.signature.PrivateKey = try .fromP256Scalar(scalar[0..32]);
defer signer.deinit();
hs.setCredentials(&.{cert_der}, signer.signer());

var out: tls.ServerHandshake.OutBuffer = .empty;
var flight: tls.ServerHandshake.FlightBuffer = .empty;
var storage: tls.RecordBuffer.Storage = .empty;
var rb: tls.RecordBuffer = .init(&storage.buffer);

while (!hs.isConnected()) {
    const n = try stream.read(rb.writable());
    if (n == 0) return error.ClientClosed;
    rb.advance(n);
    while (try rb.next()) |record| {
        switch (try hs.handleRecord(record, &out.buffer)) {
            .write => |w| {
                try stream.writeAll(w);
                hs.completeWrite();
                if (try hs.sendServerFlightBuffered(&flight)) |flight_bytes| {
                    try stream.writeAll(flight_bytes);
                    hs.completeWrite();
                }
            },
            .none => {},
            .application_data, .closed => return error.UnexpectedDuringHandshake,
        }
        if (hs.isConnected()) break;
    }
}
```

Break out as soon as client Finished makes the server connected. Any later
record already in `rb` remains buffered; this gives post-handshake work such as
a `NewSessionTicket` write priority over coalesced application data.

## The `pending_write` interlock

Every engine method that produces bytes sets an internal `pending_write` flag. The next engine call returns `error.PendingWrite` until `completeWrite()` clears the flag.

This prevents a silent desync: if the caller drops a write (kernel buffer full, async task cancelled, early return), the engine would otherwise advance its sequence numbers while the peer never saw the record. `pending_write` forces the caller to acknowledge every emitted record before the state machine moves on.

Rules:

- Call `completeWrite()` **immediately after** the bytes are written to the transport.
- Never call two engine send-methods in a row without `completeWrite()` between them.
- In async code, `completeWrite()` belongs in the write-completion callback.

For blocking transports:

```zig
try stream.writeAll(record);
hs.completeWrite();
```

For non-blocking transports, use `tls.Outbox` to own the unsent tail and call
`completeWrite()` only after the full TLS record drains:

```zig
const Sender = struct {
    fd: std.posix.fd_t,

    pub fn write(self: Sender, bytes: []const u8) !usize {
        return std.posix.send(self.fd, bytes, 0) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
    }
};

var outbox: tls.Outbox = .init;
const sender: Sender = .{ .fd = fd };
const result = try outbox.send(&hs, record, sender);

// Later, when the fd is writable again:
const next_result = try outbox.flush(&hs, sender);
```

`FlushResult.drained` means the record fully drained and `completeWrite()` was
called; `FlushResult.pending` means bytes remain queued and the caller should
retry `flush` when the transport is writable again.

```zig
_ = result;
_ = next_result;
```

`Outbox` borrows the queued record slice, so the output buffer that produced the
record must stay alive and unchanged until `outbox.writeBlocked()` is false. The
writer contract is small: `write(bytes)` returns the number of
bytes accepted, and `0` means no progress / would-block. While an outbox owns a
record, do not call `completeWrite()` manually; the outbox does that after a full
record drain. The writer must not call back into the engine.

## Event union

`handleRecord` returns an `Event`:

| Variant              | Meaning                                    | When it occurs                             |
| -------------------- | ------------------------------------------ | ------------------------------------------ |
| `.write: []const u8` | A record that must be sent to the peer     | Client Finished, KeyUpdate response        |
| `.application_data`  | Decrypted plaintext from the peer          | Connected phase only                       |
| `.none`              | Nothing to send; state advanced internally | ChangeCipherSpec discarded, flight partial |
| `.closed`            | Peer sent `close_notify`                   | Any phase                                  |

`.application_data` during the handshake is an error (`UnexpectedDuringHandshake`) because application data must not arrive before the handshake completes.

## Close semantics

A clean close is a bidirectional `close_notify` alert exchange (RFC 8446 §6.1). Send one when you're done:

```zig
const rec = try engine.sendAlert(.close_notify, &out);
try stream.writeAll(rec);
engine.completeWrite();
```

When the peer sends `close_notify`, `handleRecord` returns `.closed`. Receiving `.closed` does not automatically send a `close_notify` back — the caller decides whether to half-close, reply in kind, or drop the connection.

Fatal alerts (`decode_error`, `unexpected_message`, etc.) are sent the same way but always at fatal level:

```zig
const rec = try engine.sendAlert(.decode_error, &out);
try stream.writeAll(rec);
// don't call completeWrite; treat the connection as dead
```

Before the handshake is encrypted (`.wait_ch` state), `sendAlert` emits a plaintext alert record. Once handshake keys are installed, all alerts are encrypted.

## Peer alert diagnostics

When the peer sends a non-close_notify alert — a fatal error alert, or a warning-level `user_canceled` — `handleRecord` returns `error.PeerAlert` (RFC 8446 §6.2). The engine retains the exact level and description so you can log it:

```zig
_ = engine.handleRecord(record, &out) catch |err| switch (err) {
    error.PeerAlert => {
        if (engine.lastPeerAlert()) |peer_alert| {
            // Level/Description are non-exhaustive: unknown codes are legal
            // on the wire, so tagName can return null. Fall back to the code.
            const level_name = std.enums.tagName(tls.alert.Level, peer_alert.level)
                orelse "unknown";
            const desc_name = std.enums.tagName(tls.alert.Description, peer_alert.description)
                orelse "unknown";
            // e.g. "peer alert: fatal(2)/handshake_failure(40)"
            std.log.err("peer alert: {s}({d})/{s}({d})", .{
                level_name,
                @intFromEnum(peer_alert.level),
                desc_name,
                @intFromEnum(peer_alert.description),
            });
        }
        return err; // the connection is dead
    },
    else => return err,
};
```

`lastPeerAlert()` returns null until the first peer alert; a later peer alert replaces an earlier one, while `close_notify` (§6.1) and malformed records leave it unchanged, and reinitialization clears it. Do not use `@tagName` directly on these values — unknown codes would panic. The engine still returns `error.PeerAlert`; only the detail is new.

# Credentials and negotiation

## Server credentials

Unlike the client, which only needs a certificate policy, the server must send a certificate chain and sign the `CertificateVerify` message. Configure that before processing the ClientHello:

```zig
var signer: tls.signature.PrivateKey = try .fromP256Scalar(scalar[0..32]);
defer signer.deinit();
// RFC 6979 deterministic nonces (baskingspot/tls#82): reproducible
// CertificateVerify bytes for seeded test harnesses; see "Signing and key
// exchange" for the capability contract.
// signer.nonce_mode = .deterministic;
server.setCredentials(&.{leaf_cert_der}, signer.signer());
```

The certificate chain is a DER slice list in leaf-first order. `sendServerFlightBuffered` uses the configured credentials, owns the authenticated-flight one-shot latch, and returns `null` if there is no server flight to send.

```zig
var flight: tls.ServerHandshake.FlightBuffer = .empty;
if (try server.sendServerFlightBuffered(&flight)) |flight_bytes| {
    try stream.writeAll(flight_bytes);
    server.completeWrite();
}
```

`sendAuthenticatedFlight` remains available as a lower-level escape hatch, but new callers should prefer up-front `setCredentials` plus `sendServerFlightBuffered`. On PSK resumption these methods automatically omit Certificate and CertificateVerify. `PrivateKey.deinit()` zeroes key material via libcrypto.

## Certificate policy

The client validates the server certificate chain against a caller-owned policy.
The `Config` struct seeds `policy` at init time from `host_name`, `now_sec`,
`bundle`, and `insecure_no_chain_anchor`; `policy` remains public for advanced
overrides after init:

```zig
var hs: tls.ClientHandshake = .init(.{
    .keypairs = try .init(keypair),
    .host_name = "example.com",      // SAN/CN check + SNI
    .now_sec = std.time.timestamp(),  // validity-period check
    .bundle = &bundle,                // trust-anchor anchoring
    .random = random,
});
// Advanced override (optional):
// hs.policy.insecure_no_chain_anchor = true;  // test/demo only
```

A client policy without `bundle` rejects the server Certificate unless the
caller explicitly sets `insecure_no_chain_anchor = true` for a test/demo
fixture. The bundle type is Zig's `std.crypto.Certificate.Bundle`; load it from
the trust anchors appropriate for your application and keep it caller-owned for
the connection lifetime. The insecure fixture mode still verifies
CertificateVerify key possession, but it does not authenticate the chain to any
trust root.

## Server session tickets

After verifying client Finished, a server can issue one or more resumable TLS
1.3 tickets without allocating. Ticket identity encoding, persistence,
expiration, key rotation, replay policy, absolute resumption-chain lifetime,
and any client-auth identity continuity remain caller policy.

```zig
var prepared = try server.deriveTicketPsk();
defer prepared.secureZero();

// Stage prepared.psk and prepared.cipher_suite under this opaque identity, or
// include them in a caller-encrypted and authenticated stateless ticket.
const identity = "opaque-ticket";

// `fresh_ticket_age_add` came from the application's CSPRNG for this ticket.
const record = try server.sendNewSessionTicket(
    &prepared,
    .{
        .ticket_lifetime = 3600,
        .ticket_age_add = fresh_ticket_age_add,
        .ticket = identity,
    },
    &out.buffer,
);
try stream.writeAll(record);
server.completeWrite();
```

`deriveTicketPsk()` assigns a unique per-connection nonce and permits only one
prepared ticket at a time. RFC 8446 §4.6.1 puts `ticket_age_add` freshness on
the server; the engine owns no CSPRNG, so the caller must provide a fresh
cryptographically random value for every call. Ticket identities are non-empty
and at most 256 bytes so clients can cache them. The server emits one ticket per
record, caps issuance at 32 tickets per connection, and does not advertise
0-RTT from this API.

Clients that did not advertise `psk_dhe_ke` make ticket preparation fail with
`error.IncompatiblePskModes`. Commit a stateful ticket row only after the record
has been fully written. If identity construction or persistence fails, call
`discardTicketPsk()`; it erases the PSK and burns the nonce.

Issue and flush every userspace ticket before kTLS activation. A prepared ticket
blocks `tls_ktls.Server.activate`; after successful activation,
`deriveTicketPsk()` and `sendNewSessionTicket()` fail with
`error.KtlsTxActive`.

PSK resumption never implicitly preserves a client-certificate identity. A
server configured for fresh client authentication declines offered PSKs and
runs a full authenticated handshake. Applications that carry an identity in a ticket must authenticate and authorize
that caller-owned ticket state themselves.

## SNI (server name indication)

After `handleRecord` returns the first `.write` event (the ServerHello), the server can read the hostname the client requested:

```zig
if (server.clientServerName()) |name| {
    // select certificate based on `name`
}
```

`clientServerName()` returns `null` if the client sent no `server_name` extension. The slice points into the caller's record buffer; copy it if you need it past the next `handleRecord` call.

> Virtual hosting pattern: call `handleRecord` for the ClientHello, inspect `clientServerName()`, select the appropriate keypair/cert, call `setCredentials`, then send the authenticated flight with `sendServerFlightBuffered`.

## ALPN

Both sides offer protocol lists before the handshake begins:

```zig
// Client — via Config at init time
var hs: tls.ClientHandshake = .init(.{
    .keypairs = try .init(keypair),
    .host_name = "example.com",
    .now_sec = std.time.timestamp(),
    .random = random,
    .alpn_protocols = &.{ "h2", "http/1.1" },
});
// or after init:
// client.offerAlpn(&.{ "h2", "http/1.1" });

// Server
server.supportAlpn(&.{"h2"});
```

After the handshake, `selectedAlpnProtocol()` returns the negotiated protocol (or `null` if none was agreed). The server picks the first entry from its list that the client also offered; if both sides sent ALPN but no protocol matches, `acceptClientHello` returns `error.NoApplicationProtocol`. The client rejects a server-selected protocol that was not offered (`error.UnofferedAlpnProtocol`).

## RFC 10024 hybrid key exchange

Hybrid groups are opt-in. The non-FIPS OpenSSL, AWS-LC, and BoringSSL backends support all three RFC 10024 groups. The provider supplies pure ML-KEM operations. The engine owns group negotiation and classical-secret composition. FIPS backend identities advertise no hybrid groups.

`tls.capabilities.active_backend` identifies the inferred backend and explicit FIPS policy. `tls.capabilities.is_fips` reports compile-time FIPS narrowing. It does not prove the provider runtime mode. `supportsHybridGroup(role, group)` reports role support. Provider operations can still fail at runtime.

Start with one group:

```zig
const hybrid_groups = [_]tls.kex.NamedGroup{.x25519_mlkem768};
try tls.capabilities.validateHybridGroups(.client, &hybrid_groups);
try tls.capabilities.validateHybridGroups(.server, &hybrid_groups);

var client_keypairs: tls.ClientHandshake.KeyPairs = try .init(.generate());
defer client_keypairs.secureZero();
const client_config: tls.ClientHandshake.Config = .{
    .keypairs = client_keypairs,
    .host_name = "example.com",
    .now_sec = std.time.timestamp(),
    .random = client_random,
    .hybrid = .{
        .supported_groups = &hybrid_groups,
        .initial_key_share = .x25519_mlkem768,
    },
};
try client_config.validate();
var client: tls.ClientHandshake = .init(client_config);
defer client.deinit();

var server_keypairs: tls.ServerHandshake.KeyPairs = try .init(.generate());
defer server_keypairs.secureZero();
const server_config: tls.ServerHandshake.Config = .{
    .keypairs = server_keypairs,
    .random = server_random,
    .hybrid_groups = &hybrid_groups,
};
try server_config.validate();
var server: tls.ServerHandshake = .init(server_config);
defer server.deinit();
```

Set `initial_key_share = null` to omit the hybrid share from ClientHello1. A compatible server can select the group through HelloRetryRequest.

A hybrid offer still permits classical key exchange. Invalid explicit policy never causes a silent classical fallback. A failure after hybrid selection ends the handshake.

`error.InvalidHybridPolicy` reports malformed lists or an inconsistent initial share. `error.HybridGroupUnavailable` reports compile-time backend policy. `error.MissingP384KeyPair` reports absent P-384 material.

`secp384r1_mlkem1024` requires a P-384 keypair on each enabled role. All three group values can appear in one policy.

The group slices are borrowed. They must outlive the handshake. A reusable xev configuration requires them until every associated connection ends.

Call `tls-std` option `validate()` methods before socket creation. `connect` and `accept` repeat validation before key generation. The fallible xev configuration constructors validate before trust-store work.

# Integrations

The drive loop is the protocol boundary. What changes by transport model:

## Blocking `std.net.Stream`

[`examples/tcp_loopback.zig`](https://github.com/baskingspot/tls/blob/main/examples/tcp_loopback.zig) drives a client and a server over loopback TCP. Read into `RecordBuffer.writable()`, feed each complete record to the engine, `writeAll` each emitted record, then call `completeWrite()`. [`tls_std`](https://github.com/baskingspot/tls/blob/main/integrations/tls-std/README.md) packages that shape as a wrapper.

## In-memory transport

[`examples/in_memory_handshake.zig`](https://github.com/baskingspot/tls/blob/main/examples/in_memory_handshake.zig) connects both engines by passing record slices directly. It uses the low-level hooks (`acceptClientHello`, `processServerHello`, `processClientFinished`, `receiveApplicationData`) because there is no byte-stream transport to frame with `RecordBuffer`.

## epoll

[`examples/epoll_pingpong.zig`](https://github.com/baskingspot/tls/blob/main/examples/epoll_pingpong.zig) is Linux-only and non-blocking. It uses `tls.Outbox` for the write side: keep at most one emitted record queued, wait for writability when the socket blocks, and do not call another record-producing method until the outbox drains. Reads still fill `RecordBuffer.writable()`.

## io_uring

[`examples/iouring_pingpong.zig`](https://github.com/baskingspot/tls/blob/main/examples/iouring_pingpong.zig) is Linux-only. Setup may use ordinary blocking `listen`, `accept`, and `connect`; the record data path submits sends and receives through the ring. The pending-write rule still applies: every emitted record completes through the ring before the next call that can advance protocol state.

## libxev

[`tls_xev`](https://github.com/baskingspot/tls/blob/main/integrations/tls-xev/README.md) is the non-blocking adapter for [libxev](https://github.com/mitchellh/libxev). It is opt-in: set `.xev = true` in the dependency options.

## kTLS

[`tls_ktls`](https://github.com/baskingspot/tls/blob/main/integrations/tls-ktls/README.md) exports traffic keys for Linux kTLS and drives the kernel data plane after the userspace handshake. [`examples/ktls_pingpong.zig`](https://github.com/baskingspot/tls/blob/main/integrations/tls-ktls/examples/ktls_pingpong.zig) is the runnable version.

## kTLS key export

After the handshake is connected, `txKtlsInfo()` and `rxKtlsInfo()` return copied Linux kTLS key material for the current traffic-key epoch. `tx` is the local write direction; `rx` is the peer write direction. The core still does no socket I/O and does not call `setsockopt`.

The Zig 0.16/Linux [`integrations/tls-ktls`](https://github.com/baskingspot/tls/blob/main/integrations/tls-ktls/README.md) package owns the safe activation and data-plane lifecycle. It requires an empty `RecordBuffer`, no pending engine write, no unanswered KeyUpdate request, and an application-level barrier preventing the peer from racing a new record into the socket during activation; keeps key snapshots internal to immediate `setsockopt` calls; receives control-record metadata with `recvmsg`; processes kernel-decrypted records through `receiveKtlsRecord`; ratchets external TX records through `ratchetKtlsTx`; and sends `close_notify` explicitly. Use that package instead of open-coding the sequence from the raw getters.

The raw exports remain available for specialized integrations. They are immediate-use snapshots: retaining one across any record operation, or reinstalling stale sequence/key material, can cause epoch desynchronization or nonce reuse.

# C ABI

The C surface is partial and client only: `include/baskingspot_tls.h`,
`libbaskingspot_tls.a` from `zig build -Dcapi`, and `examples/c_client.c`. It is
wired into `just ci` as `capi-ci`.

The C names are not the package name. A C symbol namespace has to survive being
linked into programs that already carry LibreSSL, mbedTLS, or wolfSSL, so it
names the project rather than the protocol: `baskingspot_tls_*` symbols,
`BASKINGSPOT_TLS_*` enumerators, `BASKINGSPOT_TLS_H` for the guard. `tls_*`
and `libtls.a` are LibreSSL's, and a short abbreviation reads as noise in a
linker error.

# Performance

It is faster than OpenSSL's libssl on every comparable application-data row
measured, on x86_64, aarch64, and macOS Apple Silicon. Against rustls it wins on
AES-GCM on all three, and loses on small ChaCha20 records.

Headline row: AES-128-GCM ping-pong at 1350-byte records, near the common MTU
boundary, from the x86_64 capture
([`docs/research/perf/20260712-102422-ec2-c7i-2xlarge/`](https://github.com/baskingspot/tls/blob/main/docs/research/perf/20260712-102422-ec2-c7i-2xlarge/)):

| impl           |  ns/op |     vs `tls` |
| -------------- | -----: | -----------: |
| `tls`          |  790.7 |              |
| rustls         | 1447.5 | 1.83x slower |
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
  in [`docs/research/PERFORMANCE.md`](https://github.com/baskingspot/tls/blob/main/docs/research/PERFORMANCE.md).
- **The handshake is not a head-to-head.** The library verifies the server's
  CertificateVerify signature, rustls's harness uses a `NoVerifier` that skips
  it, and libssl's behavior without a trust store is opaque. That row is
  reported on its own and never quoted as a comparison.

AMD and older Graviton parts are not measured. Full row tables, methodology, and
the mechanism writeups are in
[`docs/research/PERFORMANCE.md`](https://github.com/baskingspot/tls/blob/main/docs/research/PERFORMANCE.md). The 15%
regression gate compares a fresh n=10 capture against the committed baseline
(`just bench-regression-check`). It runs on EC2, by hand, not in CI.

# Limits

- **A drop-in OpenSSL replacement.** The engine is the TLS state machine. It does not open sockets, load OS trust stores, or give you a `connect()`. You write the drive loop.
- **The full TLS feature set.** It supports a bounded TLS 1.3 surface. [`PRODUCTION_READINESS.md`](https://github.com/baskingspot/tls/blob/main/PRODUCTION_READINESS.md) is the authority on what is proven and what is not.
- **A stable API.** Signatures move, and there are no release tags yet. `main` is the only artifact, so pin a commit and read the docs at that commit.
- **TLS 1.2, DTLS, and Windows.** Out of scope. There is no downgrade target, and the library runs on Linux and macOS only.
- **Exporters.** Not implemented, and not planned until someone asks for one.
- **A general io_uring or arbitrary-runtime wrapper.** The in-tree integration packages cover `std.Io`, libxev, and Linux kTLS without moving transport I/O into the core engine.
