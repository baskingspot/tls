const std = @import("std");
const Build = std.Build;

/// Native primitive suite (#199). The root selects the modules whose vectors
/// and contracts apply to this backend. Examples and the conformance
/// subproject exercise native handshakes separately. A second binary selects
/// core regressions that native can execute. Its imports also carry
/// libcrypto-only tests, so the filter is part of the test contract.
pub fn addNativeSteps(b: *Build, opts: struct {
    test_mod: *Build.Module,
    core_test_mod: *Build.Module,
    fuzz: bool,
    testingx: ?*Build.Dependency,
}) void {
    const mod_tests = b.addTest(.{
        .root_module = opts.test_mod,
        .test_runner = if (opts.fuzz) null else if (opts.testingx) |t|
            .{ .path = t.path("src/runner.zig"), .mode = .simple }
        else
            null,
    });
    const run_tests = b.addRunArtifact(mod_tests);
    run_tests.has_side_effects = true;
    const test_step = b.step("test", "Run tests with the pure-Zig native backend");
    test_step.dependOn(&run_tests.step);

    if (!opts.fuzz and opts.testingx != null) {
        const core_tests = b.addTest(.{
            .root_module = opts.core_test_mod,
            .test_runner = .{
                .path = opts.testingx.?.path("src/runner.zig"),
                .mode = .simple,
            },
        });
        const run_core_tests = b.addRunArtifact(core_tests);
        run_core_tests.has_side_effects = true;
        const filter =
            "--filter=CertificateRequest offer,ClientHello parse failures," ++
            "signature_algorithms_cert";
        run_core_tests.addArg(filter);
        test_step.dependOn(&run_core_tests.step);
    }

    const install_tests = b.addInstallArtifact(mod_tests, .{});
    b.step("test-bin", "Install the native test binary").dependOn(&install_tests.step);
}

pub fn addSteps(b: *Build, opts: struct {
    test_mod: *Build.Module,
    /// When true, use the default test runner (needed for `--fuzz`, which
    /// requires the server protocol that testingx's `.mode = .simple` skips).
    fuzz: bool = false,
    /// testingx dependency — supplies the plain-text test runner that writes
    /// one line per test to stderr instead of Zig's TUI. Null when the lazy
    /// dependency has not been fetched (e.g. when building non-test steps).
    testingx: ?*Build.Dependency = null,
    /// The tls library module, for standalone check executables that must
    /// control the process environment before any libcrypto call.
    tls_mod: *Build.Module,
    /// Fixtures module — the #114 non-interaction check loads the encrypted
    /// PEM fixtures directly.
    fixtures_mod: *Build.Module,
    /// Translated POSIX PTY C API (#145) — the #114 non-interaction check
    /// replaces its own standard streams through libc calls.
    pty_c: *Build.Module,
    /// Build target for standalone check executables. Required: the only
    /// caller (build.zig) always passes it.
    target: Build.ResolvedTarget,
    /// Optimization mode for standalone check executables. Required: the
    /// only caller (build.zig) always passes it.
    optimize: std.builtin.OptimizeMode,
}) void {
    const mod_tests = b.addTest(.{
        .root_module = opts.test_mod,
        .test_runner = if (opts.fuzz) null else if (opts.testingx) |t|
            .{ .path = t.path("src/runner.zig"), .mode = .simple }
        else
            null,
    });
    const run_tests = b.addRunArtifact(mod_tests);
    run_tests.has_side_effects = true; // always run tests, don't cache
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);

    // Install the test binary so it can be run under valgrind/external tools:
    //   zig build install
    //   valgrind --leak-check=no --error-exitcode=1 ./zig-out/bin/test
    const install_tests = b.addInstallArtifact(mod_tests, .{});
    const valgrind_step = b.step(
        "test-bin",
        "Install the test binary for external tooling (valgrind, etc.)",
    );
    valgrind_step.dependOn(&install_tests.step);

    // #114 — encrypted-PEM non-interaction check. Same standalone-executable
    // rationale as the errq check: the probe replaces its own stdin/stdout/
    // stderr, which a test inside the shared binary cannot safely do. Runs on
    // every lane, including BoringSSL.
    const pem_mod = b.createModule(.{
        .root_source_file = b.path("src/test/encrypted_pem_check.zig"),
        .target = opts.target,
        .optimize = opts.optimize,
    });
    pem_mod.addImport("tls", opts.tls_mod);
    pem_mod.addImport("fixtures", opts.fixtures_mod);
    pem_mod.addImport("pty_c", opts.pty_c);
    pem_mod.link_libc = true;

    const pem_exe = b.addExecutable(.{
        .name = "encrypted-pem-check",
        .root_module = pem_mod,
    });
    const run_pem = b.addRunArtifact(pem_exe);
    run_pem.has_side_effects = true;
    test_step.dependOn(&run_pem.step);
    const pem_step = b.step(
        "encrypted-pem-check",
        "Run the #114 encrypted-PEM non-interaction check (pipe and terminal probes)",
    );
    pem_step.dependOn(&run_pem.step);
}
