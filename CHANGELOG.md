# Changelog

All notable changes to tls are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- A verified certificate's identity is readable without a second X.509 parser.
  `Parsed.subjectAttributes()` and `issuerAttributes()` walk the distinguished
  name as `NameEntry` values (modeled attribute or raw OID, plus the string
  with its ASN.1 encoding), `Parsed.subjectAltNames()` walks the SANs as
  `GeneralName` values, and `DirectoryString.write` renders one value into an
  `Io.Writer`. Nothing allocates and nothing is decoded until it is rendered.
  `write` transcodes BMPString and UniversalString, and escapes C0 controls,
  DEL, and invalid UTF-8, because the text came from the peer (#172).
- `tls.der.validCertificate` checks the DER envelope of a certificate without
  decoding its fields: one SEQUENCE that fills the buffer, three children, and a
  tbsCertificate with its mandatory fields. It exists so a caller can refuse
  malformed DER before std's unchecked `der.Element.parse` walks it.
- `tls_std.trust_store` loads trust anchors from PEM bytes, a file, or the OS
  store, and rejects a block whose DER envelope is malformed.
- `handshake_core` carries QUIC transport parameters (RFC 9001 §8.2) in both
  directions. `Client.receiveExtensions(allowed, slots)` and
  `Server.receiveExtensions(allowed, slots)` name the extension types to keep
  and the caller-owned slots to keep them in, and `peerExtensions()` returns what
  the peer sent, in wire order. The bytes borrow the peer's message, so copy them
  before the next call into the core. `Server.sendExtensions(extras)` adds the
  server's own to EncryptedExtensions, and `flightBufferLen` counts them. A
  client that allows nothing still refuses an unexpected extension with
  `error.UnsupportedExtension`; a server ignores an unlisted one. A listed type
  with no free slot is `error.ExtensionSinkFull`.
- `handshake_core.Server.applicationSecrets()` returns the application traffic
  secrets once `sendFlight` has derived them, and null before. A QUIC server
  needs them to protect 1-RTT packets (RFC 9001 §4.1.1).
- `client_hello.parseWithExtensions(msg, ParseOptions)` keeps the extensions the
  caller allows in `Parsed.extensions`. `parse` is unchanged.
  `extension_type.ExtensionSink` is the sink type; `encrypted_extensions.ExtensionSink`
  stays as an alias.

### Changed

- `alert.alertForError` answers every engine error with the alert RFC 8446 §6.2
  defines for it, and `alert.alertForHandshakeError` replaces the old
  fall-through with a switch that is exhaustive over the engine's error set: a
  new error does not compile until someone decides what the peer is told. 27
  errors that reached `internal_error` now say what actually happened —
  `unexpected_message` for a HelloRetryRequest, a record with the wrong content
  type, or a post-handshake flood; `decode_error` for a malformed ALPN entry;
  `bad_certificate` for an oversized chain or a repeated extension;
  `decrypt_error` for a certificate signature that did not verify. The rest are
  ours by fault (buffer sizing, caller options, missing backend capability) and
  stay `internal_error` deliberately, each with a reason at its arm (#171).
- An address-literal `host_name` sends no SNI. `host_name` is both the SNI value
  and the certificate reference identity, and RFC 6066 §3 forbids a literal
  IPv4 or IPv6 address in the `server_name` extension. The extension is now
  omitted for an address, the way every other TLS stack does it; the
  `iPAddress` SAN check still runs against the same `host_name` (#178).
- `tls_std` reports why a certificate was refused instead of one opaque
  `CertificateVerificationFailed`: `CertificateExpired`, `CertificateNotYetValid`,
  `CertificateHostMismatch`, `CertificateIssuerNotFound`, and
  `CertificateSignatureInvalid`, on both `ConnectError` and `AcceptError`
  (`AcceptError` has no hostname cause). A cause with no distinct corrective
  action stays `CertificateVerificationFailed` (#173).
- Hostname verification accepts an address literal. `Policy.host_name` with an
  IPv4 or IPv6 address is compared against `iPAddress` subjectAltName entries
  instead of `dNSName` (RFC 9525 §6.2.1), in the four-octet and sixteen-octet
  forms, with an IPv4-mapped address treated as its IPv4 address. A DNS
  reference still matches `dNSName` only, and a wildcard still matches no
  address. Before this, an address literal could only connect with
  `host_name = null`, which disables the check (#176).
- `tls_std` with `Verify.system_bundle` reads the Linux trust store itself
  instead of calling `Bundle.rescan`. A truncated certificate in `/etc/ssl/certs`
  is now `error.CertificateVerificationFailed`; before this it panicked a Debug
  or ReleaseSafe build and read out of bounds in ReleaseFast (#177). macOS still
  rescans the keychain, whose binary store format std owns.

### Fixed

- `handshake_core.Client` derives its application traffic secrets over the
  transcript through the server Finished, as RFC 8446 §7.1 requires. A client
  that sent a Certificate and CertificateVerify hashed those in as well, and so
  disagreed with its server on every 1-RTT key.

## [0.4.1] - 2026-11-12

### Changed

- The `stdx` pin is v0.4.0, so one stdx instance serves every graph that also
  holds stdx directly. Additive over 0.3.0: no API change for tls.

## [0.4.0] - 2026-11-11

### Removed

- `tls_xev`, the `.xev` dependency option, and the root package's libxev
  dependency. A consumer that imports `tls_xev` must drive the engine from its
  own libxev completions, use `tls_nonblocking`, or stay on v0.3.0. The module
  is no longer exported, and `.xev = true` in `b.dependency("tls", ...)` now
  fails with `error: invalid option: "xev"`.

## [0.3.0] - 2026-11-10

### Added

- `Certificate` exposes the bounds-checked X.509 parser. PEM anchor validation uses it before the standard-library bundle parser.
- `handshake_core.Server` derives the shared secret too, so no public entry in
  either role accepts one. The server retains the client's classical key shares
  from the ClientHello in caller-owned storage (`usePeerShareStorage`, sized by
  `peer_share_storage_len`) and derives in `provideServerHello` from its own
  keypairs (`useKeypairs`). A short buffer is
  `error.PeerShareStorageTooSmall`, never a truncated share, and a ClientHello
  offering RFC 10024 hybrid is `error.HybridServerUnsupported` because the core
  has no server-side KEM path yet. The retained shares are public material and
  are not zeroized; the keypairs are, in `deinit`.
- `handshake_core.Client` derives the shared secret itself. `provide` takes the
  ServerHello and nothing else: the client retains the keypairs from
  `startEncoded`/`startEncodedWithPsk` (or `useKeypairs` for a caller-encoded
  ClientHello) and derives classical ECDHE and RFC 10024 hybrid alike. Both the
  ephemeral keypairs and the retained KEM key are secret state, zeroized in
  `deinit`. `offerHybrid` sets the hybrid policy and optional initial share;
  `capabilities.HybridPolicy` is the one policy type, and
  `ClientHandshake.HybridPolicy` aliases it. A caller can no longer hand the
  core a shared secret, so it cannot hand it the wrong one.
- `tls_nonblocking.Client`: a caller-driven TLS 1.3 client with the same shape
  as `Server` — caller-owned buffers, one outbound record at a time, no
  thread and no blocking call. Events are `need_input`, `need_output`,
  `progress`, `handshake_complete`, `application_data`, `key_update`,
  `new_session_ticket`, `close_notify`, and `closed`; `close_notify` stays
  distinct from `closed` because RX can end while TX stays open (RFC 8446
  §6.1). ALPN is reported, not enforced: a caller that requires `h2` checks
  `selectedAlpn()` after `handshake_complete`. Trust anchors come from
  `Options.ca` (Baskingspot issue #167).
- `tls_nonblocking.SocketClient` is a blocking TLS client over a caller-owned `std.Io.net.Stream`. It exposes plaintext byte interfaces and preserves TLS errors through diagnostic methods. Read deadlines include handshake waits and exclude writes. Future deadlines require Zig 0.17. Zig 0.16 reports `DeadlineUnsupported` for future waits. The caller owns the socket.
- `tls_nonblocking.anchors.build` parses PEM trust anchors into an owned bundle. A parse failure discards the incomplete bundle.
- `ClientHandshake.NewSessionTicket` is public, so a caller can name the type
  its `new_session_ticket` event carries.
- `tls_nonblocking.anchors.addCertsFromPemBytes` loads trust anchors from PEM
  bytes into a caller-owned `Certificate.Bundle`, so a client handed a CA in
  memory no longer needs a file on disk. It returns the number of anchors
  added, because std drops an expired or unrecognized one silently (#175).

### Changed

- The tree builds and tests on Zig 0.16 and 0.17 from one source. `nix develop`
  is 0.17; `nix develop .#zig-old` is 0.16. `just check` runs the Debug and
  release-mode suites on whichever compiler the shell carries, and CI runs the
  full gate on 0.17 plus `just check` on 0.16 (#174). The minimum supported Zig
  is still 0.16.
- `tls_std`, `tls_nonblocking`, and `tls_ktls` build and test on Zig 0.17 as well as 0.16. `tls_xev` stays 0.16 because its pinned libxev commit does not implement the 0.17 `std.Io` vtable.
- `alert.alertForError` returns `?Description` and maps `error.PeerAlert` to null. The peer already sent its own alert, so answering it with another alert — previously `internal_error` — blamed the wrong side (RFC 8446 §6.2). Integrations drop their `PeerAlert` special case.

### Added

- Caller-supplied TLS extensions: `extension_type.ExtraExtension` rides `ClientHello` or `EncryptedExtensions` as opaque bytes, and `Config.required_extensions` makes an absent one fail the handshake with `error.MissingRequiredExtension` and `missingExtension()` naming the type. The peer sees `missing_extension` (RFC 8446 §6.2). Every existing encoder signature is unchanged; the extensions-aware forms are new functions. QUIC transport parameters need nothing more from tls than this.
- `ClientHandshake.clientFinishedMessage` and `ServerHandshake.processClientFinishedMessage` exchange the Finished as bare handshake messages, for a caller that owns its own record layer (QUIC CRYPTO frames). Both enter the same state machine as the record paths: `clientFinished` and `processClientFinished` are now thin wrappers around the shared assembly and verification code, and the record output is unchanged. The bare client path rejects a 0-RTT handshake with `error.EarlyDataUnsupported`, because EndOfEarlyData is not part of that flight; it classifies as an internal limitation, not a peer protocol error.
- `ClientHandshake` and `ServerHandshake` can retain the TLS 1.3 traffic secrets when the caller asks: set `Config.traffic_secrets` or call `useTrafficSecretStorage`, and `trafficSecrets()` returns them. Without it the engine derives and wipes exactly as before, and the accessor returns `error.NotRetained` rather than zeros. `traffic_secrets.TrafficSecrets.expand` applies HKDF-Expand-Label to a held secret for callers that derive their own keys, such as QUIC (RFC 8446 §7.1, RFC 9001 §5.1).

### Fixed

- `tls_nonblocking.anchors` returns `InvalidCertificateDer` for certificates with excessive fields instead of an integer-overflow panic.
- `SocketClient.init` rejects out-of-order handshake application data with `UnexpectedRecord` instead of a loop without progress.

## [0.2.1] - 2026-11-05

### Fixed

- The source archive no longer carries `docs/`, so `zig fetch` pulls 826 KB instead of 10.3 MB. The release workflow refuses an archive over 2 MiB, so research cannot creep back in (#170).

## [0.2.0] - 2026-11-05

### Added

- `tls_nonblocking.Server`: a caller-driven TLS 1.3 server with caller-owned buffers, incremental handshake progress, and explicit backpressure (#167).

### Changed

- `ServerHandshake.init` now takes reusable `ServerConfig` policy separately from per-connection `Config` keys, random, and buffers. `tls_nonblocking.Server.init` takes the same split, so listener `Options` cannot hold ephemeral connection state (#168).

## [0.1.1] - 2026-10-31

### Changed

- `ClientHandshake.Config` and `ServerHandshake.Config` are options bags
  again: build them as a struct literal with the required fields named, and
  drop `Config.init`. The client's `bundle`, `insecure_no_chain_anchor`,
  `alpn_protocols`, `hybrid`, and `reassembly`, and the server's optional
  fields, carry their defaults again. `ClientHandshake.init(.{ ... })` reads
  as one value instead of an argument order plus post-construction writes.

## [0.1.0] - 2026-10-30

### Added

- `ServerHandshake.PskEntry.alpn`: optional ALPN of the connection that
  issued the ticket, required for 0-RTT acceptance (#161).
- `ClientHandshake.SessionTicket.alpn_protocol`: ALPN of the session that
  issued the ticket; `deriveSessionTicket` records it so a resumption can
  check it against accepted early data (#162).

### Changed

- Public structs no longer accept a bare `.{}` or a partial literal; start from
  the named constructor and assign any fields you override. Construction
  changed for `ClientHandshake` (`init(Config.init(...))`),
  `ClientHandshake.Config.init`, `ClientHandshake.HybridPolicy.empty`,
  `ClientHandshake.SessionTicket.init`, `ServerHandshake`
  (`init(Config.init(...))`), `ServerHandshake.Config.init`,
  `ServerHandshake.PskEntry.init`, `ServerHandshake.TicketPsk.init`,
  `EstablishedSession.init`, `Outbox.init`, `RecordBuffer.init`,
  `RecordLayer.init`/`KtlsInfo.init`, `encrypted_extensions.Options.init`/
  `Parsed.empty`, `client_hello.Parsed.init`/`SupportedGroups.empty`,
  `certificate.Policy.init`, `certificate_parser.Parsed.init`,
  `signature.PrivateKey` loaders, `handshake_key_pairs.KeyPairs` constructors,
  and `frame.Header.init`.
- C ABI names are `baskingspot_tls_*`, with `include/baskingspot_tls.h` and
  `libbaskingspot_tls.a`. Rename every `ztls_*` call, `ZTLS_*` enumerator, and
  `#include "ztls.h"`, and link `-lbaskingspot_tls`. The C surface has never
  been released, so there is no compatibility alias (#149).

### Fixed

- Client `wait_sh` handlers are transactional: a rejected ServerHello or
  HelloRetryRequest (e.g. `BufferTooShort` from a large HRR cookie) no longer
  leaves the transcript union collapsed, so retrying with a larger buffer or
  processing the next record no longer reads an inactive union field (#158).
- Client now aborts with `error.IllegalParameter` (illegal_parameter alert)
  when a server accepts 0-RTT under a cipher suite or ALPN that differs from
  the ticket's, per RFC 8446 §4.2.10 (#162).
- C ABI: `baskingspot_tls_client_init_insecure` now copies `host_name` into
  handle-owned storage (caller may free/overwrite it after init), treats an
  empty string as no SNI, and rejects names over 253 bytes with
  `BASKINGSPOT_TLS_ERR_HANDSHAKE_FAILURE` (#159).
- `ServerHandshake` ClientHello processing is now transactional: a
  ClientHello that fails after PSK selection no longer leaves its PSK, 0-RTT
  key, or other negotiation state for the next ClientHello, and a failed
  HelloRetryRequest no longer leaves half-armed retry state (#160).
- `ServerHandshake` now accepts early data only when the RFC 8446 §4.2.10
  preconditions hold: first offered identity, exact ticket/negotiated cipher
  suite equality, and ticket/selected ALPN equality; otherwise the offer is
  declined and in-flight 0-RTT records are skipped (#161).
- The CertificateVerify RSA key loader (`rsaPublicKeyFromDer`) now rejects
  degenerate peer keys — trailing bytes after the RSAPublicKey, an even or
  1-valued or wider-than-32-bit public exponent, and an even or out-of-range
  (below 1024 or above 8192 bits) modulus fail with `error.InvalidEncoding`
  before any signature verification. An exponent-1 key previously made the
  RSA public operation the identity, so any well-formed PSS encoding verified
  as a CertificateVerify signature (#157).
- Name constraints: a zero-length dNSName constraint now matches every DNS
  name per RFC 5280 §4.2.1.10, so an excluded empty dNSName rejects any leaf
  DNS SAN or Common Name fallback beneath that CA (#154).
- Name constraints: an excluded dNSName now rejects a wildcard SAN whose
  single-label expansion set intersects the exclusion (e.g. SAN
  `*.example.com` under excluded `secret.example.com`); this deliberately
  diverges from OpenSSL 3.6, which still compares the wildcard label
  literally (#156).
- Chain verification: `certificate.parse` and `certificate.parseClientChain`
  now apply the leaf's role EKU to every in-chain issuer and to the trust
  anchor — an issuer carrying an ExtendedKeyUsage extension must include the
  role OID or id-kp-anyExtendedKeyUsage, otherwise the chain fails with
  `error.CertificateExtendedKeyUsageRejected` (#155).
- `certificate_policy.verifyIssuerUsage`, `findVerifiedIssuerInBundle`, and
  `verifyAgainstBundle` take a new `role: LeafUsage` parameter (#155).
