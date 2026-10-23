# Changelog

All notable changes to tls are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- The CertificateVerify RSA key loader (`rsaPublicKeyFromDer`) now rejects
  degenerate peer keys — trailing bytes after the RSAPublicKey, an even or
  1-valued or wider-than-32-bit public exponent, and an even or out-of-range
  (below 1024 or above 8192 bits) modulus fail with `error.InvalidEncoding`
  before any signature verification. An exponent-1 key previously made the
  RSA public operation the identity, so any well-formed PSS encoding verified
  as a CertificateVerify signature (#157).
