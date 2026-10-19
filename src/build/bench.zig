const std = @import("std");
const Build = std.Build;

pub const Options = struct {
    target: Build.ResolvedTarget,
    tls_mod: *Build.Module,
    c_mod: *Build.Module,
    c_ssl_mod: *Build.Module,
    /// Translated libcrypto C API (#145) — the benchmark_root tree
    /// reaches src/crypto via relative imports (../aead.zig, ../root.zig),
    /// so it compiles c_openssl.zig within itself.
    openssl_c: *Build.Module,
    build_options: *Build.Step.Options,
    fixtures_mod: *Build.Module,
    stdx_mod: *Build.Module,
};

/// `root` is the build.zig struct of this package. `b.lazyImport` needs it to
/// find the dependency's build.zig, which owns `addBenchExe`.
pub fn addSteps(b: *Build, comptime root: type, opts: Options) void {
    const testingx = b.lazyImport(root, "testingx") orelse return;
    const dep = b.lazyDependency("testingx", .{
        // testingx declares no `optimize` option; the suite executable sets
        // ReleaseFast through `addBenchExe`.
        .target = opts.target,
    }) orelse return;
    const testingx_mod = dep.module("testingx");

    addTlsBenchmarks(b, opts, testingx, testingx_mod);
    addEvpBenchmarks(b, opts, testingx, testingx_mod);
    addLibsslBenchmarks(b, opts, testingx, testingx_mod);
    addReplayFixtureGenerator(b, opts);
}

fn addRunStep(
    b: *Build,
    exe: *Build.Step.Compile,
    step_name: []const u8,
    step_desc: []const u8,
    bin_desc: []const u8,
) void {
    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    b.step(step_name, step_desc).dependOn(&run.step);

    const install = b.addInstallArtifact(exe, .{});
    b.step(b.fmt("{s}-bin", .{step_name}), bin_desc).dependOn(&install.step);
}

fn addTlsBenchmarks(
    b: *Build,
    opts: Options,
    comptime testingx: type,
    testingx_mod: *Build.Module,
) void {
    const exe = testingx.addBenchExe(b, .{
        .name = "benchmark",
        .module = testingx_mod,
        .root_source_file = b.path("src/bench.zig"),
        .target = opts.target,
        .imports = &.{
            .{ .name = "tls", .module = opts.tls_mod },
            .{ .name = "stdx", .module = opts.stdx_mod },
            .{ .name = "fixtures", .module = opts.fixtures_mod },
            .{ .name = "openssl_c", .module = opts.openssl_c },
            .{ .name = "build_options", .module = opts.build_options.createModule() },
        },
    });
    exe.root_module.link_libc = true;
    exe.root_module.linkSystemLibrary("crypto", .{});

    addRunStep(
        b,
        exe,
        "bench",
        "Run performance benchmarks",
        "Build the benchmark binary for profiling",
    );
}

fn addReplayFixtureGenerator(b: *Build, opts: Options) void {
    const exe = b.addExecutable(.{
        .name = "generate_replay_fixtures",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/generate_replay_fixtures.zig"),
            .target = opts.target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "tls", .module = opts.tls_mod },
            },
        }),
    });
    const run = b.addRunArtifact(exe);
    const step = b.step(
        "generate-replay-fixtures",
        "Generate OpenSSL replay fixtures for tls benchmarks",
    );
    step.dependOn(&run.step);
}

fn addEvpBenchmarks(
    b: *Build,
    opts: Options,
    comptime testingx: type,
    testingx_mod: *Build.Module,
) void {
    const exe = testingx.addBenchExe(b, .{
        .name = "evp_bench",
        .module = testingx_mod,
        .root_source_file = b.path("bench/evp.zig"),
        .target = opts.target,
        .imports = &.{
            .{ .name = "tls", .module = opts.tls_mod },
            .{ .name = "stdx", .module = opts.stdx_mod },
            .{ .name = "c", .module = opts.c_mod },
        },
    });

    addRunStep(
        b,
        exe,
        "bench-evp",
        "Run OpenSSL EVP AEAD benchmarks",
        "Build the OpenSSL EVP benchmark binary",
    );
}

fn addLibsslBenchmarks(
    b: *Build,
    opts: Options,
    comptime testingx: type,
    testingx_mod: *Build.Module,
) void {
    const exe = testingx.addBenchExe(b, .{
        .name = "bio_bench",
        .module = testingx_mod,
        .root_source_file = b.path("bench/bio.zig"),
        .target = opts.target,
        .imports = &.{
            .{ .name = "tls", .module = opts.tls_mod },
            .{ .name = "stdx", .module = opts.stdx_mod },
            .{ .name = "c", .module = opts.c_mod },
            .{ .name = "c_ssl", .module = opts.c_ssl_mod },
        },
    });
    exe.root_module.link_libc = true;
    exe.root_module.linkSystemLibrary("ssl", .{});
    exe.root_module.linkSystemLibrary("crypto", .{});

    addRunStep(
        b,
        exe,
        "bench-openssl",
        "Run OpenSSL libssl memory BIO benchmarks",
        "Build the OpenSSL memory BIO benchmark binary",
    );
}
