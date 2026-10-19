# Production readiness

This page answers one question: what does tls actually do, and what proves it?

It is not a release note and not a roadmap. There is no tagged release and no
frozen API, so pin a commit. The claims below bind to the commits that produced
their evidence; a later commit inherits nothing automatically.

## The claim

`tls` is in production use as a Sans-I/O TLS 1.3 engine. The last qualified
candidate is `8814f1e55642a7ce73841779ca0b25e530d31ef8`. It passed the
conformance, consumer, resource, and recovery gates, and two downstream
consumers run it.

Qualification is per commit and per profile. It does not travel to a later
commit because the branch moved.

## What works, and how it is known

| Surface | Status | What the status rests on |
|---|---|---|
| TLS 1.3 handshake, client and server | Proven | In-memory handshakes and OpenSSL interop in both directions, in CI |
| Record layer, framing, alerts, `close_notify` | Proven | RFC 8446 §5 tests, fuzz targets, and tlsfuzzer |
| Certificate chains, hostname verification, leaf policy | Proven | Chain and policy tests, name-constraint fixtures, and TLS-Anvil |
| AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | Proven | Record tests and OpenSSL interop for each |
| X25519 and P-256 key exchange | Proven | Handshake tests and OpenSSL interop |
| P-384 key exchange | Proven, opt-in | Bidirectional OpenSSL interop on every non-FIPS backend |
| RFC 10024 hybrid groups | Proven, opt-in | Provider-backed ML-KEM on OpenSSL, AWS-LC, and BoringSSL; OpenSSL interop and the upstream tlsfuzzer matrix |
| KeyUpdate | Proven | Both directions and both roles, with a flood bound |
| HelloRetryRequest | Proven | Both roles in memory and in TLS-Anvil; forced-HRR OpenSSL interop is not gated |
| Session resumption | Partial | The engine side is proven; persistence, expiry, rotation, replay, and SNI partitioning are yours |
| 0-RTT early data | Partial | Offer, accept, and reject are proven; anti-replay is yours, and the engine default is off |
| kTLS | Proven | Linux only; key export and the kernel data plane |
| C ABI | Partial | Client lifecycle only; see `include/ztls.h` |
| TLS 1.2, DTLS, Windows | Out of scope | Not coming |

Crypto primitives come from a libcrypto backend chosen at build time. OpenSSL,
AWS-LC, and BoringSSL are each CI-gated and each passed the same conformance
run. The engine itself, meaning parsing, framing, transcript, and record
sequencing, allocates nothing. The backends allocate during setup and inside
their own routines, and that is stated rather than hidden.

## How a claim gets proven

A claim is proven when a command in this repository fails if the claim becomes
false. Four gates carry most of the weight.

**`just ci`** runs the unit tests, the handshake replays against OpenSSL, the
three backend lanes, the examples, the C ABI example, the distribution smoke
test, and the conformance subproject. It is the gate a change must pass before
it lands.

**TLS-Anvil** runs the full test catalogue against a wrapper around the engine,
as both client and server, on all three backends. The most recent all-backend
run, on a commit later than the qualified candidate, completed 437 cases per
role on each backend with zero unexpected results. The expected failures are the
DSA-root cases in #52, and the not-attempted rows are endpoint-mode cases the
harness did not exercise. The #91 series captures, with per-case results and
provenance, are committed under `docs/research/TLS_ANVIL_91_CHAIN_FIXTURE/`.

**tlsfuzzer** drives the server over a real socket with an independently
maintained TLS test suite. It covers the server side only; client-side behavior
against a hostile server is covered by the unit and replay tests instead.

**The consumer gate** replaces the dependency pins in two downstream consumers
and runs their suites against one fixed tls commit. It proves the package works
outside this repository, which no amount of in-tree testing does. The procedure
is `docs/research/CONSUMER_GATE.md`.

Security claims rest on `docs/research/THREAT_MODEL.md` for the attacker model
and `docs/research/NEGATIVE_SPACE.md` for what the engine does with each class
of malformed input.

## Performance

Three n=10 captures, on an Intel `c7i.2xlarge`, a Graviton `c7g.2xlarge`, and
an Apple M1 Max. On every comparable application-data row, tls is faster than
OpenSSL libssl. Against rustls it wins every AES-GCM row and loses on small
ChaCha20 records, where rustls's ring path beats OpenSSL EVP.

The row-by-row accounting, including which rows are not comparable across
implementations and why, is in `docs/research/PERFORMANCE.md`. The raw captures
and the disassembly are next to it under `docs/research/perf/`. A 15% regression
gate compares a fresh n=10 capture against the committed baseline; it runs by
hand on EC2, not in CI.

The handshake row is deliberately excluded from cross-implementation claims.
tls verifies the server's CertificateVerify signature, rustls's harness uses a
verifier that does not, and libssl's behavior without a trust store is opaque.
The row is reported on its own.

## What is not proven

- **No external audit.** The security work here is an internal adversarial pass,
  not a third-party audit. Say so if you are evaluating it for a decision.
- **Caller obligations.** Ticket storage, expiry, rotation, replay rejection,
  SNI partitioning, 0-RTT anti-replay, trust anchors, and the drive loop belong
  to you. The engine documents the seam; it does not enforce your policy.
- **The hardware matrix.** AMD, Graviton3, and Intel Macs are not measured. The
  claims cover the three captures named above.
- **The C ABI.** Client lifecycle only. Server shims, record-buffer access, and
  certificate verification do not exist in C yet.
- **Forced-HRR interop.** HelloRetryRequest is proven in memory and in
  TLS-Anvil. The harness does not yet force OpenSSL into HRR, so that path is
  not gated.
- **Deployment shapes beyond the tested profiles.** The resource and recovery
  checks cover the recorded Linux profiles, not every kernel, allocator, or
  connection pattern a deployment will see.

## Changing this page

A claim moves when its evidence moves, in the same commit. If you land work that
changes the status of a row, change the row. If you land evidence that a row is
wrong, fix it before you do anything else.

A stale readiness page is worse than no page: it is a claim nobody checked.
