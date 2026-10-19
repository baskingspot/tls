[doc("Run ztls benchmarks")]
[group("bench")]
bench *ARGS:
    zig build bench -- {{ ARGS }}

[doc("Capture ztls/EVP/libssl/rustls benchmark comparison outputs")]
[group("bench")]
bench-capture *ARGS:
    @scripts/bench-capture.sh {{ ARGS }}

[doc("Capture a full benchmark comparison with default provenance flags")]
[group("bench")]
bench-capture-default:
    @scripts/bench-capture.sh --count=5 --benchtime=500ms

[doc("Provision EC2 benchmark host(s), run capture, pull and analyze results")]
[group("bench")]
bench-remote-capture *ARGS:
    @infra/bench/run-capture.sh {{ ARGS }}

[doc("Provision EC2 benchmark host, run row perf/disassembly evidence, and pull results")]
[group("bench")]
bench-remote-perf-rows *ARGS:
    @infra/bench/run-perf-rows.sh {{ ARGS }}

[doc("Re-run EC2 capture at n=10 and check comparable AES-GCM rows against the committed baseline (manual Pillar 3 regression gate)")]
[group("bench")]
bench-regression-check:
    @infra/bench/run-capture.sh --instance-types c7i.2xlarge --count 10 --benchtime 500ms
    @scripts/bench-regression.sh

[doc("Validate benchmark capture/analyze plumbing quickly; not benchmark evidence")]
[group("bench")]
bench-smoke:
    @capture=$(scripts/bench-capture.sh --count=1 --benchtime=1x); scripts/bench-analyze.sh "$capture"

[doc("Analyze a benchmark capture with benchstat")]
[group("bench")]
bench-analyze CAPTURE="":
    @scripts/bench-analyze.sh {{ CAPTURE }}

[private]
bench-bin:
    zig build bench-bin

[doc("Disassemble the ztls benchmark binary")]
[group("bench")]
bench-disasm: bench-bin
    objdump -d zig-out/bin/benchmark > zig-out/benchmark.asm
    @echo zig-out/benchmark.asm

[doc("Disassemble libcrypto linked by the ztls benchmark binary")]
[group("bench")]
[linux]
bench-disasm-libcrypto: bench-bin
    objdump -d $(ldd zig-out/bin/benchmark | awk '/libcrypto/{print $3; exit}') > zig-out/libcrypto.asm
    @echo zig-out/libcrypto.asm

[doc("Record a perf profile for the ztls benchmark binary")]
[group("bench")]
[linux]
bench-perf *ARGS: bench-bin
    perf record --call-graph dwarf --output zig-out/benchmark.perf.data -- zig-out/bin/benchmark {{ ARGS }}
    @echo zig-out/benchmark.perf.data

[doc("Record a perf profile for one benchmark row and implementation")]
[group("bench")]
[linux]
bench-perf-row *ARGS:
    @scripts/bench-perf-row.sh {{ ARGS }}

[doc("Disassemble a benchmark binary and linked libraries for one implementation")]
[group("bench")]
bench-disasm-row *ARGS:
    @scripts/bench-disasm-row.sh {{ ARGS }}
