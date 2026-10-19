# Security Policy

Report security bugs privately. Do not open a public issue.

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/baskingspot/tls/security/advisories/new).
Include the affected commit, what goes wrong, and a reproduction: a failing
test, a fuzz input, or a packet capture.

## Scope

In scope: the TLS 1.3 protocol implementation. That means record framing, the
handshake state machine, transcript hashing, the key schedule, alerts,
certificate path validation and hostname verification, and the parsers that
consume attacker-controlled bytes.

Out of scope:

- The libcrypto backend (OpenSSL, AWS-LC, BoringSSL). Report primitive crypto
  bugs upstream. Report misuse of the backend by this library here.
- The caller's side: transport I/O, buffer lifetime, trust stores, and the drive
  loop. [`docs/research/THREAT_MODEL.md`](https://github.com/baskingspot/tls/blob/main/docs/research/THREAT_MODEL.md)
  draws the line.
- Features that do not exist.

## What to expect

There is no response-time SLA. Reports are read, and fixes land when they land.
There has been no third-party audit. The status summary and the threat model are
in [`PRODUCTION_READINESS.md`](https://github.com/baskingspot/tls/blob/main/PRODUCTION_READINESS.md)
and [`docs/research/THREAT_MODEL.md`](https://github.com/baskingspot/tls/blob/main/docs/research/THREAT_MODEL.md).
