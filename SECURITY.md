# Security Policy

This is the security policy for `tls`, a TLS 1.3 library. Security is the whole job. Read it before you rely
on it for anything.

## Status: in production, internally adversarially reviewed

The library has not had an external security audit. The API is not frozen. It is in
production use. The review described here is internal, not a third-party audit.
[`PRODUCTION_READINESS.md`](https://github.com/baskingspot/tls/blob/main/PRODUCTION_READINESS.md)
tracks exactly what is proven and what isn't, with the evidence behind each
claim. If you're weighing
the library for anything security-sensitive, read that first, then decide.

What tls does have: RFC-cited tests, RFC 8448 known-answer vectors, OpenSSL
interop in both directions, tlsfuzzer and TLS-Anvil conformance runs, Wycheproof
boundary vectors at the crypto seam, fuzzing on the parser and record-decrypt
surfaces, and a documented threat model at
[`docs/research/THREAT_MODEL.md`](https://github.com/baskingspot/tls/blob/main/docs/research/THREAT_MODEL.md).

An internal adversarial security review (Project Glasswing harness: recon →
hunt → validate) ran against the supported parser and state-machine surface in
July 2026. It found three vulnerabilities — an integer-overflow DoS class
across 14 parser bounds-check sites (#72), a server authentication bypass via
the PSK fast-path (#73), and a selectPsk binders-length overflow — all fixed
with regression tests. The recon, findings, and verified-handled results are
at
[`docs/research/security/FINDINGS.md`](https://github.com/baskingspot/tls/blob/main/docs/research/security/FINDINGS.md).
That is real evidence. It is not a substitute for an external audit.

## Reporting a vulnerability

Report privately. Do not open a public issue for a security bug.

Use GitHub's private vulnerability reporting: go to the **Security** tab of this
repository and click **Report a vulnerability**. That opens a private advisory
visible only to the maintainer.

Please include what you'd want if the roles were reversed: affected version or
commit, a description of the flaw, and a reproduction — a failing test, a fuzz
input, a packet capture, or a proof-of-concept. If you have a suggested fix,
even better.

## What's in scope

The TLS 1.3 protocol implementation tls owns: record framing, the handshake
state machine, transcript hashing, key schedule, alert handling, certificate
path validation and hostname verification, and the parser surfaces that consume
attacker-controlled bytes.

Out of scope:

- The libcrypto backend itself (OpenSSL, AWS-LC). Report primitive crypto bugs
  upstream. Report *misuse* of the backend by tls here.
- Anything the caller owns: transport I/O, buffer lifetime, trust-store
  provisioning, the drive loop.
  [`docs/research/THREAT_MODEL.md`](https://github.com/baskingspot/tls/blob/main/docs/research/THREAT_MODEL.md)
  draws the line between tls's responsibilities and the caller's.
- Features that don't exist yet. PSK resumption, 0-RTT, and client cert auth
  are implemented and were covered by the adversarial review; features outside
  the current supported surface (PQ key exchange, TLS 1.2) are tracked as open
  issues, not vulnerabilities.

## Expectations

This is software maintained in the open. There is no response-time SLA.
Reports are read and taken seriously, but fixes land on a best-effort basis until
the project reaches a stage where it can promise more. When tls is ready to make
security commitments it can keep, this file will say so.
