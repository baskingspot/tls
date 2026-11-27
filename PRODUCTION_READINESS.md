# Production readiness

This page answers one question: what does tls actually do, and what proves it?

It is not a release note and not a roadmap. Tags through v0.4.4 exist, but the
API is not frozen. The claims below bind to the commits that produced their
evidence; a later commit inherits nothing automatically.

## The claim

`tls` is in production use as a Sans-I/O TLS 1.3 engine. The last qualified
candidate is `8814f1e55642a7ce73841779ca0b25e530d31ef8`. It passed the
conformance, consumer, resource, and recovery gates, and two downstream
consumers run it.

Qualification is per commit and per profile. It does not travel to a later
commit because the branch moved.

**Warning: the default `native` backend is for development and iteration. It is
not yet for production use.** No performance measurement against libcrypto or
independent security review exists for native. Production builds must select
`-Dcrypto=openssl` or `-Dcrypto=aws-lc`.

Native does not support RSA signing, encrypted PEM, or ML-KEM-1024. A native
server needs an ECDSA P-256 or P-384 credential. Native loads Ed25519 keys and
verifies Ed25519 chain signatures, but it does not support Ed25519 CertificateVerify.

## What works, and how it is known

| Surface | Status | What the status rests on |
|---|---|---|
| TLS 1.3 handshake, client and server | Proven | In-memory handshakes and OpenSSL interop in both directions, in CI |
| Record layer, framing, alerts, `close_notify` | Proven | RFC 8446 §5 tests, fuzz targets, and tlsfuzzer |
| Certificate chains, hostname verification, leaf policy | Proven | Chain and policy tests, name-constraint fixtures, and TLS-Anvil |
| AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | Proven | Record tests and OpenSSL interop for each |
| Default `native` crypto backend | Partial | ECDH, ECDSA, ML-KEM-768, RSA PKCS#1 v1.5 and RSA-PSS chain verification, and RSA-PSS CertificateVerify match libcrypto. Native client/server examples exchange application data in memory and over TCP. The in-memory server loads its P-256 key from a PKCS#8 PEM file. Native loads unencrypted P-256/P-384 PKCS#8 and SEC1 keys from PEM and DER, and Ed25519 seeds from PKCS#8. Native/OpenSSL tests cover verified chains, hostname rejection, untrusted anchors, RSA-signed ECDSA chains, RSA-PSS-signed RSA chains, RSA-PSS CertificateVerify with SHA-256/384/512, P-384 ECDH, P-384 CertificateVerify, and `x25519_mlkem768`. Captured Google, Cloudflare, and example.com chains verify through their RSA issuer roots. All 777 RSA PKCS#1 v1.5 and 428 RSA-PSS Wycheproof cases match the expected results. Captured signatures match libcrypto on acceptance and tamper rejection. Both excluded capabilities have wire-level failure controls. Native ECDH and ECDSA reject malformed P-256 and P-384 points. A foreign ServerHello with those points receives an exact `illegal_parameter` alert. ML-KEM-1024, RSA signing, and encrypted PEM remain unsupported. A native TLS-Anvil client run disabled all 65 RFC 8446 cases after feature extraction failed to detect TLS 1.3. No native TLS-Anvil mutation result exists |
| X25519 and P-256 key exchange | Proven | Handshake tests and OpenSSL interop |
| P-384 key exchange | Proven, opt-in | Bidirectional OpenSSL interop on every non-FIPS libcrypto backend. Native adds client-side OpenSSL interop to its primitive differential evidence |
| RFC 10024 hybrid groups | Proven, opt-in | Provider-backed ML-KEM on OpenSSL, AWS-LC, and BoringSSL; OpenSSL interop and the upstream tlsfuzzer matrix. Native ML-KEM-768 adds client-side OpenSSL negotiation and classical fallback to its key-exchange differentials and server-side upstream tlsfuzzer coverage |
| KeyUpdate | Proven | Both directions and both roles, with a flood bound |
| HelloRetryRequest | Proven | Both roles in memory and in TLS-Anvil; forced-HRR OpenSSL interop is not gated |
| External PSK | Proven | In-memory client/server handshakes with no server certificate, application data in both directions, certificate fallback, exact `psk_dhe_ke` encoding, and binder-tamper rejection |
| Session resumption | Partial | The engine side is proven; persistence, expiry, rotation, replay, and SNI partitioning are yours |
| 0-RTT early data | Partial | Offer, accept, and reject are proven; accept is gated on the RFC 8446 §4.2.10 exact-suite, ALPN, and first-identity checks; ticket-age and anti-replay policy are yours, and the engine default is off |
| Caller-driven readiness server | Proven | `tls_nonblocking.Server` has byte-stream and OpenSSL tests on Linux. `http` runs `just conformance-run-tls-readiness` in `just ci`, and `h2spec` over TLS passes on ubuntu-26.04 and macos-26 (run 44221027341, `503515f`, against `tls` v0.4.4 at `3ba8fbd`). |
| Caller-driven readiness client | Proven | `tls_nonblocking.Client` has in-memory handshake, ALPN, partial-write, and close_notify tests against `tls_nonblocking.Server`. `SocketClient` retains its loopback coverage. OpenSSL `s_server` tests run in the integration gate. Seven-byte reads and three-byte writes fragment the handshake and application data. The exchange verifies the generated certificate and hostname, negotiates `h2`, and transfers data in both directions. It also transfers data before and after a KeyUpdate. The request arrives while inbound plaintext remains partially consumed. OpenSSL's trace must contain the client's `update_not_requested` response. A disjoint ALPN test requires the exact OpenSSL `no_application_protocol` peer alert. Both directions send authenticated `close_notify`. `zig build footprint` reports the `Client` and `SocketClient` storage. HTTP's consumer evidence remains bound to its recorded dependency revision, not this commit. |
| kTLS | Proven | Linux only; key export and the kernel data plane |
| C ABI | Partial | Client lifecycle only; see `include/baskingspot_tls.h` |
| TLS 1.2, DTLS, Windows | Out of scope | Not coming |

The default build selects `native` and links no libcrypto. `-Dcrypto=auto`
retains header detection. OpenSSL, AWS-LC, and BoringSSL are each CI-gated and
each passed the same conformance run. The default path completes native/native
and native/OpenSSL handshakes through the evidence in the table. Its facade
caller owns all primitive buffers. The C ABI stays libcrypto-only and rejects
`-Dcapi -Dcrypto=native`.

Native verifies RSA PKCS#1 v1.5 and RSA-PSS certificate-chain signatures and
RSA-PSS CertificateVerify with SHA-256/384/512, and loads unencrypted
P-256/P-384 PKCS#8 and SEC1 keys from PEM and DER, plus Ed25519 seeds from
PKCS#8. RSA signing and encrypted PEM remain unsupported (#215, #216).
RSASSA-PSS SubjectPublicKeyInfo issuer keys return
`CertificateSignatureAlgorithmUnsupported` because `rsa_pss_pss_*` is
unsupported (#219).

The engine itself, meaning parsing, framing, transcript, and record sequencing,
allocates nothing. The libcrypto backends allocate during setup and inside their
own routines, and that is stated rather than hidden.

Certificate signature verification and ECDSA signature arithmetic are not
part of that seam. CertificateVerify and certificate-chain signatures verify
in-tree:
ECDSA through `std.crypto`, RSA-PSS and RSA PKCS#1 v1.5 through the module in
`certificate_parser.zig`, and Ed25519 chain signatures through `std.crypto`.
ECDSA P-256/P-384 signing uses `crypto/ecdsa.zig` over `std.crypto` curve
arithmetic, with RFC 6979 nonces on every backend (#82, #183).
CertificateVerify accepts ECDSA P-256/P-384 and RSA-PSS only. Ed25519 is a
chain-signature scheme here. The libcrypto backend covers AEAD, SHA-2, key
exchange, ML-KEM, and RSA-PSS signing (#183). Native advertises RSA PKCS#1 v1.5 and RSA-PSS certificate-chain signatures and
RSA-PSS CertificateVerify, but no RSA signing.

## How a claim gets proven

A claim is proven when a command in this repository fails if the claim becomes
false. Four gates carry most of the weight.

**`just ci`** runs the unit tests, the handshake replays against OpenSSL, the
libcrypto and native backend lanes, the examples, the C ABI example,
auto-detected libcrypto conformance, and native conformance. It is the gate a change must pass before
it lands. **`just distribution-ci`** runs the distribution smoke as its own CI
job.

**TLS-Anvil** runs the full test catalogue against a wrapper around the engine,
as both client and server, on all three backends. The most recent all-backend
run, on a commit later than the qualified candidate, completed 437 cases per
role on each backend with zero unexpected results. The expected failures are the
DSA-root cases in #52, and the not-attempted rows are endpoint-mode cases the
harness did not exercise. The #91 series captures, with per-case results and
provenance, are committed under `docs/research/TLS_ANVIL_91_CHAIN_FIXTURE/`.

**tlsfuzzer** drives the server over a real socket with an independently
maintained TLS test suite. The conformance suite also connects the built client
to OpenSSL `s_server` and the built server to OpenSSL `s_client`. Client-side
behavior against a hostile server is covered by the unit and replay tests.

**The consumer gate** replaces the dependency pins in two downstream consumers
and runs their suites against one fixed tls commit. It proves the package works
outside this repository, which no amount of in-tree testing does. The procedure
is `docs/research/CONSUMER_GATE.md`.

Security claims rest on `docs/research/THREAT_MODEL.md` for the attacker model
and `docs/research/NEGATIVE_SPACE.md` for what the engine does with each class
of malformed input.

## Performance

No performance measurement compares native against libcrypto. The captures
below measure libcrypto builds.

Three n=10 captures, on an Intel `c7i.2xlarge`, a Graviton `c7g.2xlarge`, and
an Apple M1 Max. On every comparable application-data row, tls is faster than
OpenSSL libssl. Against rustls it wins every AES-GCM row and loses on small
ChaCha20 records, where rustls's ring path beats OpenSSL EVP.

The x86_64 capture was built for `sapphirerapids` and the macOS capture for
`apple_m1`, both matching their hosts. The aarch64 Linux capture was built for
`apple_m1` on the Graviton host because the build pinned that model until #229.
Its rows are not a host-native Graviton baseline. A host-native launchpad
re-take is committed at
`docs/research/perf/20261127-060603-launchpad-neoverse-v3/`; the `c7g.2xlarge`
baseline still needs one.

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

- **No FIPS 140-3 claim, and the approved-only build cannot support one.**
  `-Dcrypto-approved-only=true` narrows negotiation to approved algorithms; it
  is an algorithm policy, not a validation. These operations run outside the
  linked module in every build: ECDSA signing and signature verification for
  certificate chains and CertificateVerify (#183), the TLS key schedule
  (`hmac.zig`, `hkdf.zig`),
  all randomness (`entropy.zig` fills ephemeral scalars and Hello randoms from
  the OS, so the module's DRBG is never used), and on OpenSSL the transcript
  hash (`SHA*_Init` bypasses the provider) and EC key construction
  (`EC_POINT_mul`, `EC_KEY_*`). A consumer that must use only validated
  cryptography should use a stack whose whole policy is inside the module. What
  the flag does buy is negotiation that an approved-mode peer accepts: AES-GCM
  suites, P-256/P-384 groups, and no X25519.

- **No external audit.** The security work here is an internal adversarial pass,
  not a third-party audit. Say so if you are evaluating it for a decision.
- **The qualified candidate predates the October 2026 audit.** PlanetScale's
  audit run `tls-95c3d57` found twelve issues in #153–#163. Each fix landed with
  a regression test after candidate `8814f1e`, but no gate run has re-qualified
  a commit that contains them. The candidate's qualification is evidence for
  that commit only.
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
- **HTTP readiness client's dependency revision.** The caller-driven server
  clears its consumer gate: HTTP runs `just conformance-run-tls-readiness` in
  `just ci`, and `h2spec` over TLS passes on ubuntu-26.04 and macos-26 (run
  44221027341, `503515f`). The HTTP client transport still has loopback evidence
  only at the consumer layer. The OpenSSL peer evidence above belongs to this
  repository's `SocketClient` tests. Both HTTP results remain bound to `tls`
  v0.4.4 (`3ba8fbd`), HTTP's pinned revision, not this commit.
- **Deployment shapes beyond the tested profiles.** The resource and recovery
  checks cover the recorded Linux profiles, not every kernel, allocator, or
  connection pattern a deployment will see.

## Changing this page

A claim moves when its evidence moves, in the same commit. If you land work that
changes the status of a row, change the row. If you land evidence that a row is
wrong, fix it before you do anything else.

A stale readiness page is worse than no page: it is a claim nobody checked.
