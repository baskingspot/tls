# slop

Working notes written for agents. Status dashboards, claims-to-evidence
matrices, recon output, hunt records, and issue-scoped plans live here.

## The rule

Nothing in this directory is linked from a human document.

Every prose document outside this directory is written for a person: the root
`README.md`, `SECURITY.md`, `CHANGELOG.md`, the guide under `docs/content/`,
and the research notes under `docs/research/`. A human who follows a link out
of one of those lands on prose written for them, not on an agent's notes.

Agents may link in here. `AGENTS.md` and `.pi/` are agent files. Nothing else
is.

## The test

Would a person read this on purpose, without the agent's context? If not, it
belongs here.

Slop does not become a human document through light editing. Either the text
is written for a reader, or the file moves.

## Exempt

- **`AGENTS.md` and `.pi/**`** are agent instructions, not documentation.
- **Capture directories** are date-stamped records of raw logs, data, and
  assembly. They are evidence, not prose, and the rule does not classify them.
  A record that backs a human claim sits beside the claim, as the benchmark
  captures in `docs/research/perf/` do.

## Enforcement

`just lint` fails when a document outside this directory names or links
`docs/slop/`.

## Contents

- [`EVIDENCE.md`](EVIDENCE.md) — the run log behind `PRODUCTION_READINESS.md`:
  revisions, run IDs, per-claim tables, and forensic notes.

- [`RFC8446_MUST_MATRIX.md`](RFC8446_MUST_MATRIX.md) — TLS 1.3 normative
  requirements mapped to test evidence and dispositions.
- [`TLS_ANVIL_NOT_ATTEMPTED.md`](TLS_ANVIL_NOT_ATTEMPTED.md) — classification
  of TLS-Anvil rows the completed runs did not exercise.
- [`C_ABI_CONFORMANCE.md`](C_ABI_CONFORMANCE.md) — gate shape for the C ABI
  conformance work in #30.
- [`security/`](security/) — Glasswing recon, hunt findings, full-source
  audit, C ABI design review, and the secret-lifetime audit with its
  captures.
