# Threat model

`tls` is a Sans-I/O TLS 1.3 engine. The caller owns transport I/O, buffers, trust
anchors, private-key storage, connection lifetime, and deployment policy. The
engine owns record framing, record protection plumbing, handshake state,
verification gates, KeyUpdate handling, alert emission helpers, and the contract
between TLS logic and the libcrypto-family backend.

The adversary is an active network attacker or a malicious TLS peer. What
follows is the surface the engine implements. The malformed-input catalogue is
in `NEGATIVE_SPACE.md`, and the RFC MUST matrix is in `RFC8446_MUST_MATRIX.md`.

## Supported surface covered here

- TLS 1.3 only. No TLS 1.2 fallback, no DTLS.
- X25519, P-256, opt-in P-384, and the three opt-in RFC 10024 hybrid key
  exchanges. Hybrid composition belongs to the engine; pure ML-KEM is
  provider-backed.
- The three mandatory TLS 1.3 AEAD suites:
  `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and
  `TLS_CHACHA20_POLY1305_SHA256`.
- Server-authenticated 1-RTT handshake, and client certificate authentication
  in both directions.
- HelloRetryRequest in memory and in TLS-Anvil. OpenSSL forced-HRR interop is
  still a gap.
- PSK and session resumption, ticket storage, and binder verification, with
  OpenSSL interop gated in CI.
- 0-RTT early data with EndOfEarlyData in both directions and OpenSSL interop
  gated in CI. Anti-replay belongs to the caller.
- Application data, alerts, `close_notify`, and KeyUpdate in both directions.
- NewSessionTicket is parsed by clients and emitted explicitly by servers.
  Clients surface an `early_data` `max_early_data_size`; the v1 server does not
  advertise early data. Ticket identity, persistence, rotation, expiry, replay
  handling, and client-auth continuity are caller policy.
- P-521, FFDHE, and named groups beyond the documented classical and RFC 10024
  sets are outside the supported surface. Extension behavior beyond that
  surface is tracked by the feature issue that introduces it.

## In-scope adversary capabilities

The attacker may be an active network attacker or a malicious TLS peer. Assume
it can:

- read, inject, modify, truncate, drop, replay, and reorder TLS records;
- send arbitrary byte sequences at parser and `handleRecord` entry points;
- send syntactically valid but semantically illegal TLS messages;
- choose invalid, unsupported, duplicated, or missing extensions;
- corrupt AEAD ciphertexts, tags, AAD, and record sequence expectations;
- present arbitrary certificates, chains, public keys, and signatures;
- attempt downgrade and version-confusion patterns;
- send unbounded streams of post-handshake control messages;
- close the connection at any point with alerts or transport EOF.

The attacker cannot force the engine to perform transport I/O or to allocate
inside it. The engine has neither transport ownership nor heap state.
Backend-owned libcrypto allocations are outside that contract and are documented
as backend behavior, not engine buffer ownership.

## Defended attack classes

### Record tampering and replay

Encrypted records are authenticated with the negotiated AEAD, and the per-record
nonce is the traffic IV XOR the big-endian record sequence number. Modified
ciphertext, tag, AAD, or replay under the wrong sequence number fails AEAD
authentication instead of yielding plaintext.

Evidence:

- `RecordLayer.zig`: `decrypt: replayed record is rejected`.
- `RecordLayer.zig`: sequence-overflow and key-usage-limit tests.
- `aead.zig`: tampered ciphertext, tag, and AAD tests.
- `ClientHandshake.zig`: `handleRecord: corrupted encrypted flight is rejected`.
- tlsfuzzer corrupted application-data record conversation.
- `NEGATIVE_SPACE.md` record-framing and record-protection rows.

### Record-boundary and parser robustness

The engine rejects oversized records, treats incomplete records as incomplete
input, and fuzzes the major parser and dispatch surfaces. A malformed input
produces an error or an incomplete-input signal, not a panic or an out-of-bounds
access.

Evidence:

- `frame.zig`: short and oversized header tests plus parse fuzzing.
- `RecordBuffer.zig`: truncated and oversized record tests.
- `RecordLayer.zig`: truncated ciphertext and decrypt fuzzing.
- `alert.zig`, `server_hello.zig`, `client_hello.zig`, `NewSessionTicket.zig`:
  parser tests and fuzz targets.
- `ClientHandshake.zig`: bad-server tests for malformed ServerHello, truncated
  encrypted flight, out-of-order flight messages, and illegal application data.
- `ServerHandshake.zig`: pre-auth and connected `handleRecord` fuzz targets.
- `NEGATIVE_SPACE.md` parser and fuzz rows.

### Handshake authentication and key promotion

The client verifies Certificate, CertificateVerify, and the server Finished
before it sends its own Finished and promotes to application traffic keys. The
server verifies the client Finished before it promotes to connected keys. A bad
CertificateVerify signature or a bad Finished MAC stops the handshake. The
server-side bad-Finished rejection path is structurally enforced; dedicated
state-machine negative tests are a gap listed below.

Evidence:

- `ClientHandshake.zig`: `processFlight: rejects wrong CertificateVerify
  signature`.
- `ClientHandshake.zig`: `processFlight: rejects wrong server Finished
  verify_data`.
- `ClientHandshake.zig`: `clientFinished: RFC 8448 §3 emits Finished and
  upgrades to app keys`.
- `ServerHandshake.zig`: `processClientFinished: verifies Finished and installs
  app keys`.
- `finished.zig`: wrong verify_data and wrong handshake type tests.
- `certificate.zig`: signature verification and policy tests.
- `NEGATIVE_SPACE.md` verification-gate rows.

### Certificate policy failures

The engine verifies server certificate chains against caller-provided trust
anchors and enforces hostname, KeyUsage, EKU, signature-algorithm policy, and
RFC 5280 name constraints before the client handshake completes. The caller
supplies the trust bundle and the policy; the engine does not load OS roots.

Chain anchoring happens only when `certificate.Policy.bundle` is set. A client
policy with neither a bundle nor the explicit `insecure_no_chain_anchor`
test/demo opt-in rejects the Certificate with `error.MissingTrustAnchor`. The
insecure opt-in still verifies CertificateVerify key possession, applies leaf
certificate policy, and lets `ClientHandshake.start()` fill `Policy.host_name`
from SNI when no hostname is set, but it does not authenticate the chain to a
trust root. In that mode an active MITM can present a self-signed certificate
for the target hostname and the engine will not stop it.

DNS-ID verification accepts ASCII reference names. The caller validates
reference-name syntax and converts internationalized labels to A-labels before
verification. The engine rejects non-ASCII reference names and compares A-labels
with ASCII case folding. It does not perform IDNA conversion or Punycode
validation. `Parsed.verifyHostName` does not compare IP-ID entries.

Evidence:

- `certificate.zig` and `certificate_policy.zig` tests for hostname mismatch,
  missing intermediates, untrusted leaf, KeyUsage without `digitalSignature`,
  EKU without `serverAuth`, and unsupported signature algorithms.
- `ClientHandshake.zig` server-flight tests bind CertificateVerify to the leaf
  public key and the transcript.

Name-constraints enforcement covers DNS, IP, rfc822Name, and URI GeneralName
forms in permitted and excluded subtrees. Chain-level fixture tests cover DNS;
synthetic DER unit tests cover IP, rfc822Name, URI, critical unsupported-subtree
rejection, and explicit `minimum = 0`. Unsupported GeneralName forms inside a
critical Name Constraints extension are rejected, not ignored.

### Key-exchange invalid-point handling

X25519 arithmetic is delegated to libcrypto, and identity-element shared secrets
are rejected before they enter the TLS key schedule.

Evidence:

- `x25519.zig`: identity and small-order public-key rejection tests.
- Wycheproof boundary vectors for X25519.
- `NEGATIVE_SPACE.md` key-exchange rows.

### Version confusion and downgrade attempts

The engine implements TLS 1.3 only. There is no TLS 1.2 fallback path to
negotiate. ServerHello `supported_versions` must select TLS 1.3, and unsupported
versions are rejected.

Evidence:

- `server_hello.zig`: unsupported TLS version tests; `parse: rejects TLS 1.2
  downgrade sentinel` and `parse: rejects TLS 1.1 downgrade sentinel` cover
  RFC 8446 §4.1.3 downgraded-connection sentinel detection (R004-020
  `PROVEN`).
- Client and server handshake tests use the TLS 1.3 key schedule and RFC 8448
  vectors.

### KeyUpdate abuse and post-handshake control traffic

The engine bounds consecutive post-handshake control messages, rejects KeyUpdate
when it does not end at a record boundary, and handles simultaneous update
requests without disconnecting or desynchronizing traffic keys.

Evidence:

- `ClientHandshake.zig` and `ServerHandshake.zig`: KeyUpdate flood tests.
- `ClientHandshake.zig` and `ServerHandshake.zig`: KeyUpdate record-boundary
  tests.
- `ServerHandshake.zig`: simultaneous KeyUpdate integration test.
- `NEGATIVE_SPACE.md` post-handshake rows.

### Alert and close semantics

`close_notify` is the only clean closure alert. Any other peer alert aborts the
TLS conversation with `error.PeerAlert`. Client-side bad-server tests also check
that callers can emit the RFC-required alert descriptions for the highest-risk
local error paths.

Evidence:

- `alert.zig`: parse and encode tests plus a fuzz target.
- `ClientHandshake.zig`: plaintext and encrypted fatal alert tests, and
  emitted-alert checks for `decode_error`, `decrypt_error`,
  `unexpected_message`, and `bad_record_mac`.
- `ServerHandshake.zig`: close_notify and fatal alert tests.

## Non-goals and caller responsibilities

### Transport and connection policy

The engine does not own sockets, files, DNS, timers, retries, or connection
limits. The caller owns transport-level DoS handling, rate limiting beyond the
engine's KeyUpdate bound, timeout policy, EOF handling, and the decision to close
after an error.

### Trust-store and private-key lifecycle

The engine does not load system trust stores and does not own private-key
storage. The caller supplies `certificate.Policy` and server `Signer`
implementations. If the caller sets `insecure_no_chain_anchor`, client
connections are not authenticated to any root and are open to active MITM
certificate substitution. The engine cannot protect keys outside its own structs
or backend handles.

### Side-channel resistance

The engine does not claim whole-engine constant-time behavior. It uses
timing-safe comparisons for Finished verify_data and X25519 identity detection,
and relies on the selected libcrypto-family backend for primitive side-channel
posture. Cache, power, EM, and backend-internal timing are deployment and
backend concerns.

### Secret erasure and backend compromise

The engine clears designated owned key and suite-state fields on teardown.
Compiler-generated copies and Zig HKDF/HMAC scratch can survive those writes.
The [secret-lifetime audit](security/ZEROIZATION-2026-09.md) records that
distinction in optimized binaries.

`deinit` releases backend contexts. Providers control erasure of backend-owned
memory. The engine does not implement fallback primitives. A compromised crypto
backend compromises the engine.

### Replay safety for 0-RTT

0-RTT early data is implemented but disabled by default (`offer_early_data=false`).
Replay protection is a contract between the engine and the caller: a Sans-I/O
library cannot own a global replay cache, so the caller decides the policy,
whether single-use tickets or a bounded replay window. 0-RTT data is not
forward-secret and can be replayed by a network attacker. RFC 8446 §8.1
idempotency guidance applies: the caller must make 0-RTT requests replay-safe or
reject 0-RTT.

### Unsupported TLS features

P-521 and FFDHE key exchange, exporters, and broader extension negotiation
beyond the implemented surface are not defended as features. Exporters and
unscheduled extensions are not on the timeline.

## Open threat-relevant gaps

| Gap | Boundary | Tracking |
|---|---|---|
| directoryName name-constraint forms are unsupported: a critical NameConstraints extension rejects, non-critical instances are ignored (RFC 5280 §4.2) | Certificate policy | out of scope; no expansion issue |
| BoGo is deferred; TLS-Anvil stays outside PR `just ci` but has dedicated server and client workflows | External conformance breadth | `BOGO_DEFERRED.md`, #50 |
| Oversized SNI hostnames are accepted on the ClientHello parse path (`parseSni`); the encode path caps at 253 octets | Parser hardening | `NEGATIVE_SPACE.md` policy difference, #123 |
| Finished-with-a-trailing-message and non-Finished-in-`wait_client_finished` negative unit tests are absent | Server state-machine evidence | #124 |
| EncryptedExtensions has no standalone parser fuzz target | Parser fuzz breadth | #124 |
| The provider matrix lacks runtime FIPS-provider verification and full facade-direct Wycheproof coverage | Backend diversity | `PRODUCTION_READINESS.md` provider residuals |

## Boundary diagram

```text
caller / embedder
  owns transport I/O, buffers, trust anchors, private-key storage,
  timeouts, connection lifecycle, rate limiting, and deployment policy
        |
        | complete TLS records / caller-owned plaintext buffers
        v
tls engine
  owns record framing, AEAD nonce/AAD/sequence plumbing, handshake state,
  transcript/key schedule, verification gates, KeyUpdate and alert handling
        |
        | primitive calls and backend-owned contexts
        v
libcrypto-family backend
  owns AEAD, X25519, signature verification, provider internals,
  primitive side-channel posture, and backend allocation/zeroization behavior
```

The boundary is narrow: the engine defends the TLS state machine and the record
protocol over caller-provided buffers. Everything below the primitive API
belongs to the backend, and everything around the engine belongs to the caller.
