# research

Design notes, the threat model, conformance plans, and the performance
methodology. Status lives in `PRODUCTION_READINESS.md`; nothing here restates
it.

## Design

- [`DESIGN.md`](DESIGN.md) — goals, non-goals, prior art, the Sans-I/O shape,
  and the crypto backend boundary.
- [`PROVIDER_INTERFACE.md`](PROVIDER_INTERFACE.md) — the crypto facade the
  engine calls: AEAD, hashing, named groups, signatures, and error mapping.
- [`CRYPTO_ROADMAP.md`](CRYPTO_ROADMAP.md) — the backend allocation contract
  and the OpenSSL to AWS-LC to BoringSSL path.

## Correctness

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — the attacker, the defended surface,
  the non-goals, and where the caller's responsibility starts.
- [`NEGATIVE_SPACE.md`](NEGATIVE_SPACE.md) — malformed and malicious peer
  input, and what the engine does about each one.
- [`CORRECTNESS.md`](CORRECTNESS.md) — how to run the local gate and the
  external suites.
- [`CONSUMER_GATE.md`](CONSUMER_GATE.md) — qualifying a commit against the
  downstream consumers.
- [`bettertls.md`](bettertls.md) — what Netflix's bettertls checks, and how
  the local fixtures cover the same ground.

## Plans

These describe work that is not in the supported surface. They are
preconditions and acceptance criteria, not status claims.

- [`CONFORMANCE_ROADMAP.md`](CONFORMANCE_ROADMAP.md) — HelloRetryRequest,
  PSK, 0-RTT, client auth, PQ groups, and the external runners.
- [`API_ROADMAP.md`](API_ROADMAP.md) — the HTTPS wrapper and the io_uring
  client proof.
- [`BOGO_DEFERRED.md`](BOGO_DEFERRED.md) — why BoGo is deferred, and what
  would bring it back.

## Performance

- [`PERFORMANCE.md`](PERFORMANCE.md) — the benchmark scenarios, what each row
  actually times, and where the implementations are comparable.
- [`perf/`](perf/) — the committed captures behind those numbers, plus
  `perf/EXPLANATION_TEMPLATE.md`.

## Reference

- [`rfcs/`](rfcs/) — the RFC text, offline: TLS 1.3, HKDF, ChaCha20-Poly1305,
  X25519, Ed25519, the TLS 1.3 examples, and the PQ hybrid draft.
