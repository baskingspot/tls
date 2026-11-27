const std = @import("std");
const Build = std.Build;
const crypto_libs = @import("crypto_libs.zig");
const passthru = @import("args.zig");

pub const Options = struct {
    target: Build.ResolvedTarget,
    tls_mod: *Build.Module,
    crypto_mod: *Build.Module,
    c_mod: *Build.Module,
    c_ssl_mod: *Build.Module,
    openssl_c: *Build.Module,
    openssl_ssl: *Build.Module,
    build_options: *Build.Step.Options,
    fixtures_mod: *Build.Module,
    stdx_mod: *Build.Module,
    libs: crypto_libs.Libraries,
};

pub const NativeOptions = struct {
    target: Build.ResolvedTarget,
    tls_mod: *Build.Module,
    crypto_mod: *Build.Module,
    build_options: *Build.Step.Options,
    fixtures_mod: *Build.Module,
    stdx_mod: *Build.Module,
};

const TlsOptions = struct {
    target: Build.ResolvedTarget,
    tls_mod: *Build.Module,
    crypto_mod: *Build.Module,
    openssl_c: ?*Build.Module,
    build_options: *Build.Step.Options,
    fixtures_mod: *Build.Module,
    stdx_mod: *Build.Module,
    libs: ?crypto_libs.Libraries,
};

/// `root` is the build.zig struct of this package. `b.lazyImport` needs it to
/// find the dependency's build.zig, which owns `addBenchExe`.
pub fn addSteps(b: *Build, comptime root: type, opts: Options) void {
    const testingx = b.lazyImport(root, "testingx") orelse return;
    const dep = b.lazyDependency("testingx", .{ .target = opts.target }) orelse return;
    const testingx_mod = dep.module("testingx");
    addTlsBenchmarks(b, .{
        .target = opts.target,
        .tls_mod = opts.tls_mod,
        .crypto_mod = opts.crypto_mod,
        .openssl_c = opts.openssl_c,
        .build_options = opts.build_options,
        .fixtures_mod = opts.fixtures_mod,
        .stdx_mod = opts.stdx_mod,
        .libs = opts.libs,
    }, testingx, testingx_mod);
    addEvpBenchmarks(b, opts, testingx, testingx_mod);
    addLibsslBenchmarks(b, opts, testingx, testingx_mod);
    addReplayFixtureGenerator(b, opts);
}

/// Native registers only the tls rows. It has no libcrypto modules to import or link.
pub fn addNativeSteps(b: *Build, comptime root: type, opts: NativeOptions) void {
    const testingx = b.lazyImport(root, "testingx") orelse return;
    const dep = b.lazyDependency("testingx", .{ .target = opts.target }) orelse return;
    const testingx_mod = dep.module("testingx");
    addTlsBenchmarks(b, .{
        .target = opts.target,
        .tls_mod = opts.tls_mod,
        .crypto_mod = opts.crypto_mod,
        .openssl_c = null,
        .build_options = opts.build_options,
        .fixtures_mod = opts.fixtures_mod,
        .stdx_mod = opts.stdx_mod,
        .libs = null,
    }, testingx, testingx_mod);
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
    opts: TlsOptions,
    comptime testingx: type,
    testingx_mod: *Build.Module,
) void {
    var imports: [6]Build.Module.Import = undefined;
    imports[0] = .{ .name = "tls", .module = opts.tls_mod };
    imports[1] = .{ .name = "crypto", .module = opts.crypto_mod };
    imports[2] = .{ .name = "stdx", .module = opts.stdx_mod };
    imports[3] = .{ .name = "fixtures", .module = opts.fixtures_mod };
    imports[4] = .{ .name = "build_options", .module = opts.build_options.createModule() };
    var import_count: usize = 5;
    if (opts.openssl_c) |openssl_c| {
        imports[5] = .{ .name = "openssl_c", .module = openssl_c };
        import_count = 6;
    }
    const exe = testingx.addBenchExe(b, .{
        .name = "benchmark",
        .module = testingx_mod,
        .root_source_file = b.path("src/bench.zig"),
        .target = opts.target,
        .optimize = .ReleaseFast,
        .imports = imports[0..import_count],
    });
    if (opts.libs) |libs| {
        exe.root_module.link_libc = true;
        exe.root_module.linkSystemLibrary(libs.crypto, .{});
    }
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
        "Build the EVP benchmark binary",
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
    exe.root_module.linkSystemLibrary(opts.libs.ssl, .{});
    exe.root_module.linkSystemLibrary(opts.libs.crypto, .{});
    addRunStep(
        b,
        exe,
        "bench-openssl",
        "Run OpenSSL libssl memory BIO benchmarks",
        "Build the libssl benchmark binary",
    );
}
