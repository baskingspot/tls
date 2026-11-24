const std = @import("std");

const CryptoBackend = enum { auto, native, openssl, @"aws-lc", boringssl };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const crypto_backend = b.option(
        CryptoBackend,
        "crypto",
        "Crypto backend: native (default), auto, openssl, aws-lc, or boringssl",
    ) orelse .native;
    const crypto_approved_only = b.option(
        bool,
        "crypto-approved-only",
        "Narrow an explicit or auto-detected libcrypto backend to its approved-algorithm policy",
    ) orelse false;

    const tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
        .crypto = crypto_backend,
        .@"crypto-approved-only" = crypto_approved_only,
    });
    const tls_mod = tls_dep.module("tls");
    const fixtures_mod = b.addModule("fixtures", .{
        .root_source_file = tls_dep.path("tests/fixtures/fixtures.zig"),
        .target = target,
        .optimize = optimize,
    });
    const mod = b.addModule("tls_ktls", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .link_libc = true,
        .imports = &.{.{ .name = "tls", .module = tls_mod }},
    });

    const testingx_dep = b.lazyDependency("testingx", .{
        // testingx declares no `optimize` option; the module is compiled at
        // the optimize mode of whatever artifact imports it.
        .target = target,
    });
    if (testingx_dep) |t| fixtures_mod.addImport("testingx", t.module("testingx"));
    const test_runner: ?std.Build.Step.Compile.TestRunner = if (testingx_dep) |t|
        .{ .path = t.path("src/runner.zig"), .mode = .simple }
    else
        null;
    const tests = b.addTest(.{
        .root_module = mod,
        .test_runner = test_runner,
    });
    const run_tests = b.addRunArtifact(tests);
    run_tests.has_side_effects = true;

    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/ktls_pingpong.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "tls_ktls", .module = mod },
                .{ .name = "tls", .module = tls_mod },
                .{ .name = "fixtures", .module = fixtures_mod },
            },
        }),
        .test_runner = test_runner,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    run_integration_tests.has_side_effects = true;

    const test_step = b.step("test", "Run unit and Linux kTLS integration tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    const build_examples_step = b.step("build-examples", "Compile every example");
    const example_mod = b.createModule(.{
        .root_source_file = b.path("examples/ktls_pingpong.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "tls_ktls", .module = mod },
            .{ .name = "tls", .module = tls_mod },
            .{ .name = "fixtures", .module = fixtures_mod },
        },
    });
    const example = b.addExecutable(.{
        .name = "ktls_pingpong",
        .root_module = example_mod,
    });
    build_examples_step.dependOn(&b.addInstallArtifact(example, .{}).step);
}
