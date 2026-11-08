# tls-nonblocking

Caller-driven TLS 1.3 transports for Zig 0.16.

`tls_nonblocking.Server` and `tls_nonblocking.Client` turn transport bytes into
borrowed plaintext and expose one outbound record at a time. The caller owns the
socket and the readiness loop. No handshake operation waits for a peer, and
neither transport allocates. The integration has no runtime dependency.

`Client` takes the same shape as `Server`: `next()` returns one event, `write()`
returns the bytes it accepted, and the caller acks wire bytes with `sent()`.
Neither enforces ALPN. A caller that requires `h2` reads `selectedAlpn()` after
`handshake_complete` and rejects the connection itself, because requiring a
protocol is policy, not framing. `close_notify` and `closed` are separate events:
RX can end while TX stays open (RFC 8446 §6.1).

Readiness status lives in [`PRODUCTION_READINESS.md`](../../PRODUCTION_READINESS.md).

## Import

The root package exports this module without an opt-in or a libxev dependency:

```zig
const tls_dep = b.dependency("tls", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("tls_nonblocking", tls_dep.module("tls_nonblocking"));
```

```zig
const transport = @import("tls_nonblocking");
const tls = transport.core;
```

## Trust anchors from bytes

A caller that holds a PEM bundle in memory — a conformance runner or a config
blob — loads it without touching the filesystem:

```zig
var bundle: Certificate.Bundle = .empty;
defer bundle.deinit(gpa);
const added = try transport.anchors.addCertsFromPemBytes(&bundle, gpa, pem, now_sec);
```

`added` is the number of anchors the bundle gained. std drops an expired
certificate or one with an unrecognized object identifier without an error, so
zero means the trust store came up empty — check it before the first handshake
rather than debugging the verification failure it produces. `now_sec` is the
caller's clock; anchors are skipped when it is past their `notAfter`.

## Connection storage

The caller supplies these disjoint buffers:

- `Buffers.record`: at least `tls.RecordBuffer.min_storage` bytes for input records and in-place decryption.
- `Buffers.out`: at least `tls.frame.max_wire_record_len` bytes for one outbound record.
- `ServerHandshake.Config.reassembly`: storage for fragmented ClientHello messages. The core's default capacity is `tls.ServerHandshake.ch_reassembly_buffer_size`.
- `ServerHandshake.Config.client_cert_buffer`: storage for an optional client certificate chain, when the client-auth policy requires it.

A fixed connection slot can contain the buffers beside `Server`:

```zig
const Slot = struct {
    server: transport.Server,
    record: [tls.RecordBuffer.min_storage]u8,
    out: [tls.frame.max_wire_record_len]u8,
    reassembly: [tls.ServerHandshake.ch_reassembly_buffer_size]u8,
};
```

Initialize `Server` in its final slot. Do not move or copy a live connection.
Keep the credentials and all referenced configuration storage alive until `deinit()`.
Supply fresh ephemeral keys and random bytes for each connection.

Build `Options` once for the listener. Reuse it for every accepted connection.
`Options` contains no keypairs, random values, or connection buffers.

`Server.init()` accepts `Options`, `ServerHandshake.Config`, and `Buffers`.
`Options.handshake` is the core's `ServerHandshake.ServerConfig`. It contains
listener policy. `Options.cert_chain` and `Options.signer` supply the server
credentials. `ServerHandshake.Config` supplies one connection's keypairs, random,
and optional buffers. Initialization performs no handshake or transport I/O.

`Server.deinit()` releases backend handles and erases inline secrets. Repeated calls
are harmless. It does not erase borrowed buffers. Erase those buffers before reuse
if their contents require it.

Run `zig build footprint` from this directory to measure the slot on your target.
The report excludes shared credentials and optional client-certificate storage.
The engine owns no allocations. Libcrypto can allocate internally.

## Readiness loop

All calls for one connection must run serially. Separate connections share no
mutable driver state. The caller sets deadlines and a per-turn work budget.

1. Call `next()` until the connection needs transport I/O or reaches the work budget.
2. If `sendBuffer()` is nonempty, attempt a nonblocking write.
3. Pass only the accepted byte count to `sent(n)`.
4. If `receiveBuffer()` is nonempty, attempt a nonblocking read into that slice.
5. Pass a positive byte count to `received(n)`.
6. On transport EOF, call `endInput()`.
7. After any progress, call `next()` again before a readiness wait.

`EAGAIN` consumes nothing. A short write retains the unsent tail. An empty
`receiveBuffer()` means backpressure, not EOF. Do not retain a buffer slice across
calls that advance its state.

Never read from or write to the socket except through `receiveBuffer()` /
`received(n)` and `sendBuffer()` / `sent(n)`. On an encrypted connection the fd
carries ciphertext, so a read taken directly from the socket bypasses record
framing: the next `next()` sees its bytes missing and a caller that parses the
returned bytes reads a TLS record header as if it were protocol data. A deadline
is the most common reason to reach for the fd, and it is the wrong reason. Set the
socket nonblocking, wait for readiness with the deadline, and still move the bytes
through these four calls.

| Event | Caller action |
| --- | --- |
| `need_input` | Watch readability. Also watch writability if `sendBuffer()` is nonempty. |
| `need_output` | Drain `sendBuffer()`, then call `next()` without a readiness wait. |
| `progress` | Call `next()` again within the work budget. |
| `handshake_complete` | Check `selectedAlpn()` before application use. |
| `application_data` | Consume borrowed plaintext with `consumeApplication(n)`. |
| `early_data` | Apply the replay policy before use, then call `consumeApplication(n)`. |
| `key_update` | Call `next()` to queue any required response. |
| `close_notify` | Mark RX closed and continue any required TX work. |
| `closed` | Stop reads. Drain TX or call `closeWrite()`. |

`next()` processes at most one input record. Decrypted plaintext remains pinned
until the caller consumes every byte. Partial consumption exposes the remaining
slice on a later application event. It also prevents input-buffer compaction.
A required KeyUpdate response can precede that event without a plaintext release.

A connected server can process input while an unrelated outbound record remains
partly sent. `need_input` therefore does not imply an empty output buffer.

For HTTP/2, set `Options.handshake.alpn_protocols` to `&.{"h2"}`. Require
`selectedAlpn()` to equal `"h2"` at `handshake_complete`. A peer that omits ALPN can
complete TLS with no selected protocol. A disjoint ALPN offer fails with
`NoApplicationProtocol`.

The core config controls PSK lookup and optional 0-RTT acceptance. The default is
off. `early_data` is distinct from authenticated `application_data` and precedes
`handshake_complete`. The caller owns ticket policy and replay rejection.

## Application output and shutdown

`write(plaintext)` accepts at most `tls.frame.max_plaintext_len` bytes per call.
It copies the accepted fragment into the output record for encryption. It retains
no reference to the plaintext. The caller retains any unaccepted suffix.

`WouldBlock` accepts zero bytes. Drain output and call `next()` before a retry.
A required KeyUpdate response precedes later application output and `closeWrite()`.

`closeWrite()` queues `close_notify` after accepted output. It can return
`WouldBlock`. Drain output and retry after `next()`. This closes TX only and never
closes the socket. A peer's `close_notify` closes RX only.

Transport EOF drains buffered records and plaintext first. Without an authenticated
`close_notify`, the next input request fails with `UnexpectedEof`.

Errors latch permanently. `PeerAlert` discards queued output. `lastPeerAlert()`
preserves the exact alert. Close the socket without an alert response.

For a local protocol error, preserve any partly sent record. Drain it, then call
`next()` again to queue a best-effort fatal alert. The original error remains
latched. Enforce a write deadline and abandon a peer that cannot drain output.

## Tests

From this directory:

```sh
just ci
zig build test -Doptimize=ReleaseSafe
zig build test -Doptimize=ReleaseFast
```

The OpenSSL test forces three-byte writes and seven-byte reads over a real socket.
Its test adapter uses `poll`, `recv`, and `send`. Those calls are absent from the
library module.
