# Changelog

All notable changes to tls are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `ServerHandshake.PskEntry.alpn`: optional ALPN of the connection that
  issued the ticket, required for 0-RTT acceptance (#161).

### Fixed

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
