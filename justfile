# Root justfile: workspace-level entrypoints only.
# Domain subprojects own their local workflows; root delegates to them.

import 'just/check.just'
import 'just/bench.just'
import 'just/brand.just'
import 'just/docs.just'

[private]
default:
    @just --list

[doc("Run one example program, for example `just example tcp_loopback`")]
[group("examples")]
example EXAMPLE *ARGS:
    zig build example-{{ EXAMPLE }} -- {{ ARGS }}

# The full gate runs on Zig 0.17. The release-mode `check` and the
# distribution smoke run on the same shell; see .github/ci.yaml.
[doc("Run all CI gates")]
[group("check")]
ci: test check-native check-backend-aws-lc check-backends check-approved-builds lint bench-adapter-test consumer-gate-selftest examples-ci capi-ci integrations-ci
    if [ "$(uname -s)" = Linux ]; then just check-memory; fi
    just conformance/ci

[doc("Remove local scratch directories (.tmp/, book/, zig-out/)")]
[group("dev")]
clean:
    rm -rf .tmp book zig-out
    just conformance/clean
