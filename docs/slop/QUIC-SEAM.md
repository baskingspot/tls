# QUIC handshake seam

Plan for letting `baskingspot/quic` drive this TLS 1.3 handshake. Written for the
decision, not the implementation. Cites are against `567257a`.

The shape: the handshake emits and accepts bare handshake messages, and the caller
wraps them - `RecordLayer` for TLS, CRYPTO frames for QUIC. The engine keeps one
runtime `carrier` field.

A comptime carrier lost because the choice is per connection, not per type: it
would instantiate both handshake state machines twice, and generate two copies of
the largest types in the repository, to save a branch at nine sites.

The read side stays engine-owned because a TLS record does not carry its
encryption level and a QUIC packet header does. The engine swaps `rx` as the
handshake advances, so a caller holding TLS ciphertext cannot choose a key; QUIC
callers can, and only they invert. That asymmetry is the reason full inversion
does not work here.

## 1. The record sites

Nine in production code, counted outside `test` blocks. Two are the kTLS path, so
eight touch the handshake itself.

| Site | Today | Becomes |
| --- | --- | --- |
| `ClientHandshake.zig:1225` | `sendAlert` encrypts | alert message + epoch |
| `ClientHandshake.zig:1253` | `sendEarlyData` | app data + `.early` epoch |
| `ClientHandshake.zig:2060` | `EndOfEarlyData` under early keys | suppressed for QUIC (see §5) |
| `ClientHandshake.zig:2157` | client `Finished` under handshake keys | message + `.handshake` |
| `ClientHandshake.zig:2671` | decrypt inbound in `processHandshakeRecord` | unchanged for TLS; QUIC passes plaintext |
| `ClientHandshake.zig:2715` | kTLS inline encrypt | unchanged |
| `ServerHandshake.zig:2086` | server flight encrypt | message sequence + `.handshake` |
| `ServerHandshake.zig:4785` | kTLS inline encrypt | unchanged |
| `ServerHandshake.zig:4840` | client `Finished` (mTLS) | message + `.handshake` |

Each site already knows only the bytes and the epoch. None needs record framing,
a sequence number, or a content type. `sendAlert` (`ServerHandshake.zig:2698`)
also has a plaintext branch, which becomes "no epoch yet".

## 2. Prerequisites, in order

**Secret capture at derivation.** Handshake traffic secrets are derived and wiped
inside `installHandshakeArm` (`ServerHandshake.zig:1805`); application secrets
live on the private `suite_state.HashArm`. Capture all of them where they are
derived and hold them on the engine until teardown. Additive, and it is what QUIC
packet protection needs first.

**A bare-message entry for the server `Finished`.** `processClientFinished`
(`ServerHandshake.zig:2133`) takes a record and decrypts inside, so the server
cannot complete a handshake from plaintext. The client already has this entry:
`processFlight` (`ClientHandshake.zig:1781`).

## 3. Public surface

Additive:

```zig
pub const TrafficSecrets = struct {
    client_handshake: Secret,   // zeroed until derived
    server_handshake: Secret,
    client_application: Secret,
    server_application: Secret,
    client_early: ?Secret,      // 0-RTT only
    len: u8,                    // 32 for SHA-256 suites, 48 for SHA-384
};
pub const Secret = struct { data: [48]u8, pub fn secureZero(*Secret) void };

pub fn trafficSecrets(self: *const ClientHandshake) TrafficSecrets;
pub fn trafficSecrets(self: *const ServerHandshake) TrafficSecrets;

pub fn expandLabel(secret: *const Secret, label: []const u8, out: []u8) void;

pub const ExtraExtension = struct { extension_type: u16, data: []const u8 };
pub fn addExtraExtension(self: *ClientHandshake, ext: ExtraExtension) void;
pub fn requireExtraExtension(self: *ClientHandshake, extension_type: u16) void;
```

The three QUIC labels (`quic key`, `quic iv`, `quic hp`) stay in
`baskingspot/quic`. `tls` hands out the secret and the label expansion and learns
nothing about QUIC.

Changed: `client_hello.encodeWithHybridGroups` (`client_hello.zig:1164`) and the
EncryptedExtensions encoder/parser (`encrypted_extensions.zig:59`, `:180`) need an
extension slot. `client_hello` is exported from `root.zig`; the EE module is not.
Grow them with an options argument rather than a new parallel function, and note
it in the changelog - there is no API contract yet.

Unchanged for every existing user: `tls_std`, `tls_xev`, `tls_ktls`, the C ABI,
and the record entry points they call.

## 4. The maintenance risk

Two carriers means a handshake change tested in one mode ships green and breaks
the other. Three things hold it:

- Every record site switches on `carrier`. Zig's exhaustiveness check then
  refuses a new epoch or a new site that forgets an arm.
- The scenario table becomes the test. Each existing handshake scenario runs
  twice - once through records, once through bare messages - and the record run
  must equal `wrap(bare run)` byte for byte.
- The interop tests (OpenSSL `s_server`/`s_client`) keep driving the record path,
  so the mode nobody ships cannot silently rot without a test failing.

If a future site cannot be expressed as message-plus-epoch, that is the signal to
revisit the split, not to add a third carrier.

## 5. Order of work

| Slice | Content | Size |
| --- | --- | --- |
| 1 | Secret capture, accessors, zeroization tests | ~3 days |
| 2 | Bare-message server `Finished`; message-level client `Finished` | ~4 days |
| 3 | `carrier` field and the nine sites | ~1 week |
| 4 | Extra extensions and the required-extension rule | ~4 days |
| 5 | Suppress `EndOfEarlyData` and `KeyUpdate` for QUIC; alerts to connection errors | ~2 days |

Slices 1 and 2 are useful on their own and land first, as asked. Slice 1 unblocks
QUIC packet protection, which needs the handshake secrets and nothing else.

`EndOfEarlyData` is the one trap: it must not be sent and must not enter the
transcript (RFC 9001 §4.5), so a carrier cannot drop the message afterwards. It
is a handshake option either way, not a carrier decision.

## 6. If the answer is no

Slice 1 is still worth landing: traffic-secret access is useful for kTLS
diagnostics and for anyone debugging a handshake, and it changes nothing.

QUIC itself can start without this seam. Initial packet protection derives its
keys from the connection IDs (RFC 9001 §5.2), not from TLS, so header protection,
Initial packets, ACK handling, and a client/server pair can be built and tested
against each other before any TLS integration. What waits is the handshake, and
with it 0-RTT and everything after. I would rather build Initial first than
duplicate the handshake, and that is what I would say at the next gate.

## Not reusable

Record framing, sequence numbers, content types, `KeyUpdate` (RFC 9001 §6 has no
such message; both engines send and receive one), alert records (QUIC wants
`CONNECTION_CLOSE`; `lastPeerAlert()` gives the translation), and `EndOfEarlyData`
as a wire message.

## Reusable unchanged

ClientHello and ServerHello construction, HRR, transcript hashing, certificate and
CertificateVerify and Finished verification, certificate policy, ALPN, PSK
tickets and resumption (`startWithPsk`, `deriveSessionTicket`).
