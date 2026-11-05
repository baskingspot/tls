# QUIC handshake seam

Plan for letting `baskingspot/quic` drive this TLS 1.3 handshake. Written for the
decision, not the implementation. Cites are against `cf98e22`.

## 1. The real inventory

The first version of this note counted nine sites. That was wrong. Recounted from
a clean tree, excluding test helpers and crypto primitives, the handshake touches
the record layer at **32 production sites in four files**.

Client, `src/ClientHandshake.zig` (10):

| Line | What it is |
| --- | --- |
| 1039 | `start` frames the ClientHello as a record |
| 1133 | `startWithPsk` frames the ClientHello as a record |
| 1342 | `sendAlert` frames a plaintext alert before keys exist |
| 1343 | `sendAlert` encrypts an alert |
| 1371 | `sendEarlyData` encrypts 0-RTT data |
| 1471 | `processHandshakeRecord` decrypts the server flight |
| 1764 | `processHelloRetryRequest` frames ClientHello2 |
| 2193 | `clientFinished` encrypts EndOfEarlyData |
| 2222 | `clientFinished` encrypts the Finished |
| 2390 | `receiveRecord` decrypts |

Server, `src/ServerHandshake.zig` (15):

| Line | What it is |
| --- | --- |
| 1559 | `processClientHelloMessage` frames the ServerHello |
| 1593 | `appendCompatibilityChangeCipherSpec` frames a CCS record |
| 1614 | `encodeHelloRetryRequest` frames the HRR |
| 2031 | `sendPreparedCertificateChainFlight` encrypts |
| 2074 | `sendPreparedServerFlight` encrypts |
| 2178 | `encryptServerFlight` encrypts |
| 2194 | `encryptPreparedServerFlight` encrypts |
| 2229 | `processClientFinished` decrypts |
| 2602 | `handleWaitClientFinished` decrypts early data |
| 2654 | `handleWaitClientFinished` decrypts |
| 2671 | `handleWaitClientFinished` decrypts |
| 2827 | `sendAlert` frames a plaintext alert |
| 2885 | `sendNewSessionTicket` encrypts |
| 2935 | `receiveApplicationData` decrypts |
| 3480 | `deferredServerHello` frames a ServerHello |

Shared, `src/handshake.zig` (6) and `src/alert.zig` (1):

| Line | What it is |
| --- | --- |
| handshake.zig:140 | `decryptProtected`, the single decrypt entry for established paths |
| handshake.zig:157 | `sendApplicationData` encrypts |
| handshake.zig:173 | `sendPreparedApplicationData` encrypts |
| handshake.zig:192 | `sendKeyUpdate` encrypts |
| handshake.zig:339 | `serverReceiveRecord` decrypts |
| handshake.zig:375 | `sendEstablishedAlert` encrypts |
| alert.zig:81 | `plaintextRecord` frames pre-key alerts |

Not counted, and not to be touched: `RecordLayer.encrypt`/`decrypt`,
`aead.zig`, `RecordBuffer` header parsing. Those are the primitives the adapter
uses; they already exist and work.

The old table also counted four file-scope test helpers as production sites:
`expectEncryptedAlert`, the two `encryptAllZeroInnerForTest`, and
`connectedTestServerConfigure`. They are tests, and they move with the tests.

## 2. Why the carrier flag was the wrong shape

The cancelled design added `Config.carrier = .record | .message` and branched at
the call sites. Three things are wrong with it, in increasing order of severity.

It cannot express encryption levels. A QUIC handshake has four (plaintext, early,
handshake, application), and RFC 9001 §4.1.3 requires a receiver to **reject**
CRYPTO data delivered at the wrong level. A boolean says nothing about level, so
every one of the 32 sites would need a second branch, and the caller would still
have to re-derive the level from the message type.

It leaves the handshake owning the RecordLayer. The engine would still build,
retain, and promote record layers; "message mode" would merely decline to use
them. The concept survives; only its output changes. That is the old architecture
wearing a new name, which is what a flag always is.

`clientFinished` already emits two epochs into one buffer. EndOfEarlyData under
early keys and Finished under handshake keys are coalesced by the record path
today (ClientHandshake.zig:2193 and :2222). Any design that returns "bytes" from
the handshake without a level cannot represent that, and a message-mode client
with 0-RTT silently loses a message.

## 3. The shape

The handshake stops knowing what a record is. It consumes handshake messages
tagged with a level and produces handshake messages tagged with a level.

```zig
pub const Level = enum { plaintext, early, handshake, application };

/// Feed bytes the caller obtained at `level`. The engine checks the level
/// against the message it parses and fails on a mismatch (RFC 9001 §4.1.3).
pub fn provide(self: *Handshake, level: Level, bytes: []const u8) Error!void;

/// Exactly one outcome per call, in order.
pub const Output = union(enum) {
    /// A handshake message the caller must protect at `level` and send.
    message: struct { level: Level, bytes: []const u8 },
    /// The level the caller must use for reads from now on.
    read_level: Level,
    /// The level the caller must use for writes from now on.
    write_level: Level,
    /// A read key became available for `level`. The caller fetches the secret
    /// and derives its own keys; tls never derives record keys in this path.
    key_available: Level,
    /// The handshake is complete for this role.
    done,
};

pub fn next(self: *Handshake) ?Output;
```

What each piece means:

- `provide` is the only input. It replaces `handleRecord`, `receiveRecord`,
  `processClientFinished`, `processFlight`, and `acceptClientHello` for a caller
  that owns protection. The record path becomes `provide` fed by the adapter.
- `message` carries the level explicitly, so EndOfEarlyData and Finished are two
  outputs with two levels rather than one coalesced record.
- `read_level` and `write_level` fire at the transitions the record path computes
  today: after ServerHello, after the server flight, after the client Finished.
  The adapter installs its cipher state on those events instead of the handshake
  promoting `rx`/`tx` internally.
- `key_available` is the only new ordering constraint: the caller may not protect
  a message at a level before that event, and a caller that ignores it fails
  loudly rather than shipping plaintext.
- Alerts become a terminal outcome carrying the alert description, not bytes. A
  QUIC caller maps it to CONNECTION_CLOSE; a TLS adapter maps it to an alert
  record. The engine never frames an alert.

## 4. The record adapter sits outside

The TLS record path becomes an object beside the handshake, not a mode inside it:

```
caller bytes -> record adapter (parse, decrypt, level) -> provide(level, msg)
               handshake -> next() -> (level, msg) -> record adapter -> wire
```

The adapter owns the `RecordLayer`s, the sequence numbers, the content type, and
the compatibility CCS. The handshake owns the transcript, the key schedule, and
the state machine. Nothing in the handshake knows a record header exists.

The differential test changes shape with it. There is no longer "record mode
versus message mode", because there is one handshake. The proof becomes:

- **Record adapter conformance**: the adapter fed the same deterministic inputs
  reproduces the RFC 8448 §3 byte streams for the handshake, the application
  data, and the key update. That is a stronger test than the old differential,
  because it pins real wire bytes.
- **Interop unchanged**: `openssl s_server` and `s_client` keep driving the
  adapter path, so the shipping path stays the tested path.
- **Level discipline**: a table of message type to level, checked at `provide`
  and at `next`, so a wrong-level delivery fails a test rather than a peer.

## 5. Sizes

Against the 32 sites, not nine:

| Piece | Content | Size |
| --- | --- | --- |
| `Level`, `Output`, `next()` queue | Types plus the per-role drain | ~3 days |
| Client handshake migration | 10 sites; two-epoch Finished split is the delicate one | ~1 week |
| Server handshake migration | 15 sites; the three `handleWaitClientFinished` branches and the prepared-flight wrappers | ~2 weeks |
| `handshake.zig` established paths | 6 sites; KeyUpdate and alerts become adapter work | ~4 days |
| Record adapter | Parse, frame, encrypt, decrypt, level events, CCS, tickets | ~1 week |
| Consumer migration | `tls_std`, `tls_xev`, `tls_ktls`, the C ABI, conformance | ~1-2 weeks |
| QUIC handshake driver | `provide`/`next` over CRYPTO frames, transport parameters, alerts | ~1 week |

Roughly six to eight weeks, and the risk is the consumer migration, not the
handshake: four consumers change in lockstep or the tree is broken between
commits. The old estimate was a week because it counted nine sites.

## 6. What is already done

- `1f411ce`: caller-supplied extensions on both handshakes and both
  encoders, plus a required-extension rule that names the missing type. QUIC's
  transport parameters need nothing more from tls.
- Traffic-secret retention (`b2bd024`) gives a QUIC caller the secrets to derive
  its own packet keys.
- Alert selection that does not blame the peer for our own failures (`52dc00f`).

## 7. If the answer is no

Initial packet protection derives from the connection IDs (RFC 9001 §5.2), not
from TLS, so `baskingspot/quic` can build Initial, header protection, ACK
handling, and a client/server pair without this work. It cannot handshake. That
is the honest split, and it is why the two shipped slices above are worth having
either way.
