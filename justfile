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

# The full gate runs on the current stable Zig. The previous version gets
# `just check`; see .github/ci.yaml. `distribution-ci` and `integrations-ci`
# run on that older lane too: the distribution smoke tests the minimum
# supported Zig, and `integrations/tls-xev` pins a libxev commit that only
# builds on 0.16.
[doc("Run all CI gates")]
[group("check")]
ci: test check-backend-aws-lc check-backends check-fips-builds lint consumer-gate-selftest examples-ci capi-ci
    if [ "$(uname -s)" = Linux ]; then just check-memory; fi
    just conformance/ci

[doc("Remove local scratch directories (.tmp/, book/, zig-out/)")]
[group("dev")]
clean:
    rm -rf .tmp book zig-out
    just conformance/clean
