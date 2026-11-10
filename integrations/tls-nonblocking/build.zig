const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const crypto_fips = b.option(
        bool,
        "crypto-fips",
        "Use the backend FIPS capability identity",
    ) orelse false;
    const tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
        .@"crypto-fips" = crypto_fips,
    });
    const mod = b.addModule("tls_nonblocking", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "tls", .module = tls_dep.module("tls") }},
    });
    if (b.pkg_hash.len != 0) return;

    const footprint = b.addExecutable(.{
        .name = "tls-nonblocking-footprint",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/footprint.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "tls_nonblocking", .module = mod }},
        }),
    });
    const report = b.addRunArtifact(footprint);
    report.has_side_effects = true;
    b.step("footprint", "Report per-slot TLS storage for this target").dependOn(&report.step);

    const testingx = b.lazyDependency("testingx", .{ .target = target }) orelse return;
    const fixtures = b.createModule(.{
        .root_source_file = tls_dep.path("tests/fixtures/fixtures.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "testingx", .module = testingx.module("testingx") }},
    });
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "tls_nonblocking", .module = mod },
                .{ .name = "tls", .module = tls_dep.module("tls") },
                .{ .name = "fixtures", .module = fixtures },
            },
        }),
        .test_runner = .{ .path = testingx.path("src/runner.zig"), .mode = .simple },
    });
    const run = b.addRunArtifact(tests);
    run.has_side_effects = true;
    const unit_tests = b.addTest(.{
        .root_module = mod,
        .test_runner = .{ .path = testingx.path("src/runner.zig"), .mode = .simple },
    });
    const run_units = b.addRunArtifact(unit_tests);
    run_units.has_side_effects = true;
    const test_step = b.step("test", "Run byte-stream and backpressure tests");
    test_step.dependOn(&run.step);
    test_step.dependOn(&run_units.step);
}
