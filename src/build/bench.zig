const std = @import("std");
const Build = std.Build;
const passthru = @import("args.zig");

pub const Options = struct {
    target: Build.ResolvedTarget,
    tls_mod: *Build.Module,
    crypto_mod: *Build.Module,
    build_options: *Build.Step.Options,
    fixtures_mod: *Build.Module,
    stdx_mod: *Build.Module,
};

pub const NativeOptions = Options;

/// `root` is the build.zig struct of this package. `b.lazyImport` needs it to
/// find the dependency's build.zig, which owns `addBenchExe`.
pub fn addSteps(b: *Build, comptime root: type, opts: Options) void {
    const testingx = b.lazyImport(root, "testingx") orelse return;
    const dep = b.lazyDependency("testingx", .{ .target = opts.target }) orelse return;
    addTlsBenchmarks(b, opts, testingx, dep.module("testingx"));
    addReplayFixtureGenerator(b, opts);
}

/// Native registers only the tls rows. It has no libcrypto modules to import or link.
pub fn addNativeSteps(b: *Build, comptime root: type, opts: NativeOptions) void {
    const testingx = b.lazyImport(root, "testingx") orelse return;
    const dep = b.lazyDependency("testingx", .{ .target = opts.target }) orelse return;
    addTlsBenchmarks(b, opts, testingx, dep.module("testingx"));
}

fn addRunStep(
    b: *Build,
    exe: *Build.Step.Compile,
    step_name: []const u8,
    step_desc: []const u8,
    bin_desc: []const u8,
) void {
    const run = b.addRunArtifact(exe);
    passthru.passthruArgs(run);
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
        .optimize = .ReleaseFast,
        .imports = &.{
            .{ .name = "tls", .module = opts.tls_mod },
            .{ .name = "crypto", .module = opts.crypto_mod },
            .{ .name = "stdx", .module = opts.stdx_mod },
            .{ .name = "fixtures", .module = opts.fixtures_mod },
            .{ .name = "build_options", .module = opts.build_options.createModule() },
        },
    });
    addRunStep(b, exe, "bench", "Run performance benchmarks", "Build the benchmark binary");
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
