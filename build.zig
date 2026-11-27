const std = @import("std");
const Build = std.Build;
const Target = std.Target;
const builtin = @import("builtin");
const panic = std.debug.panic;

const CryptoBackend = enum { auto, native, openssl, @"aws-lc", boringssl };

const bench_mod = @import("src/build/bench.zig");
const crypto_libs = @import("src/build/crypto_libs.zig");
const examples_mod = @import("src/build/examples.zig");
const tests = @import("src/build/tests.zig");
const translate_c = @import("src/build/translate_c.zig");

/// The libcrypto-family pkg-config modules this build resolved (#223):
/// `libcrypto`/`libssl` when the package answers to OpenSSL's names,
/// `libcrypto-awslc`/`libssl-awslc` when it suffixes them, and the bare library
/// name when no pkg-config file exists either way.
///
/// A consumer that compiles its own C API against the same libcrypto reaches
/// this through the dependency's build.zig, so both builds name one library:
///
///     const tls_build = b.lazyImport(@This(), "tls") orelse @panic("tls is lazy");
///     const libs = tls_build.cryptoLibs(b);
///     module.linkSystemLibrary(libs.crypto, .{});
///
/// `b` is the caller's build, so the probe reads the caller's pkg-config path.
pub fn cryptoLibs(b: *Build) crypto_libs.Libraries {
    return crypto_libs.resolve(b);
}

fn nativeTarget() Target.Query {
    var query: Target.Query = .{ .cpu_model = .native };
    // Zig's native CPU detection reports generic under some Apple-Silicon Linux
    // VMs despite /proc/cpuinfo exposing aes/pmull. For performance work that
    // silently selects std.crypto's soft AES path, which is not a useful target.
    if (builtin.cpu.arch == .aarch64 and builtin.os.tag == .linux) {
        query.cpu_model = .{ .explicit = &Target.aarch64.cpu.apple_m1 };
    }
    return query;
}

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = nativeTarget(),
    });
    const optimize = b.standardOptimizeOption(.{});
    const crypto_backend = b.option(
        CryptoBackend,
        "crypto",
        "Crypto backend: native (default), auto, openssl, aws-lc, or boringssl; " ++
            "auto detects the libcrypto headers",
    ) orelse .native;
    const native_crypto = crypto_backend == .native;
    const crypto_approved_only = b.option(
        bool,
        "crypto-approved-only",
        "Negotiate only approved algorithms: AES-GCM cipher suites, P-256/P-384 " ++
            "groups, and the corresponding signature schemes. This is an " ++
            "algorithm policy, not a FIPS 140-3 validation claim.",
    ) orelse false;
    // Fuzz mode uses the default test runner, which speaks the server protocol
    // that `zig build test --fuzz` needs; `-Dfuzz=true` selects it. testingx's
    // `.mode = .simple` bypasses that protocol, so it is only used for normal
    // (non-fuzz) test runs.
    const fuzz_mode =
        b.option(bool, "fuzz", "Enable fuzzing (uses the default test runner)") orelse false;

    const build_options = b.addOptions();
    build_options.addOption(CryptoBackend, "crypto", crypto_backend);
    build_options.addOption(bool, "crypto_approved_only", crypto_approved_only);

    // The C ABI is built against system libcrypto headers by contract (#199).
    // Reject the native combination instead of silently omitting the artifact.
    const capi = b.option(
        bool,
        "capi",
        "Build the C ABI library (libbaskingspot_tls.a)",
    ) orelse false;
    if (native_crypto and capi) panic("-Dcapi requires a libcrypto -Dcrypto backend", .{});

    // #223 — resolve the libcrypto family through pkg-config once: the aws-lc
    // packaging may name the modules `libcrypto-awslc`/`libssl-awslc`. The
    // native backend links no libcrypto, so it resolves nothing.
    const c_libs: ?crypto_libs.Libraries = if (native_crypto)
        null
    else
        crypto_libs.resolve(b);

    // Fixed-capacity containers and memory scans. A production dependency:
    // the library imports it, so it is resolved before the consumer early
    // return.
    const stdx_dep = b.dependency("stdx", .{
        .target = target,
        .optimize = optimize,
    });
    const crypto_dep = b.dependency("crypto", .{
        .target = target,
        .optimize = optimize,
        .crypto = crypto_backend,
        .@"crypto-approved-only" = crypto_approved_only,
    });
    const crypto_mod = crypto_dep.module("crypto");

    const mod = b.addModule("tls", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addOptions("build_options", build_options);
    mod.addImport("stdx", stdx_dep.module("stdx"));
    mod.addImport("crypto", crypto_mod);
    if (!native_crypto) {
        mod.link_libc = true;
        mod.linkSystemLibrary(c_libs.?.crypto, .{});
    }

    // Library-only mirrors of the standalone integration build scripts. The
    // distribution smoke compiles each mirror from the fetched root package.
    {
        const nonblocking_mod = b.addModule("tls_nonblocking", .{
            .root_source_file = b.path("integrations/tls-nonblocking/src/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        nonblocking_mod.addImport("tls", mod);

        const std_mod = b.addModule("tls_std", .{
            .root_source_file = b.path("integrations/tls-std/src/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        std_mod.addImport("tls", mod);
        std_mod.link_libc = true;

        const ktls_mod = b.addModule("tls_ktls", .{
            .root_source_file = b.path("integrations/tls-ktls/src/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        ktls_mod.addImport("tls", mod);
        ktls_mod.link_libc = true;
    }

    // Dependency consumers need only the exported modules. Keeping the
    // development graph root-only also keeps benchmark and test-runner packages
    // out of a core consumer's cache.
    if (b.pkg_hash.len != 0) return;

    // tls's test and benchmark harnesses own their C imports separately from
    // the provider package. Native never creates them.
    const c_modules: ?translate_c.Modules = if (native_crypto)
        null
    else
        translate_c.addModules(b, .{
            .target = target,
            .optimize = optimize,
            .libs = c_libs.?,
        });

    if (native_crypto) {
        const testingx_dep = b.lazyDependency("testingx", .{ .target = target });
        const native_test_mod = b.createModule(.{
            .root_source_file = b.path("src/test_native.zig"),
            .target = target,
            .optimize = optimize,
        });
        native_test_mod.addOptions("build_options", build_options);
        native_test_mod.addImport("stdx", stdx_dep.module("stdx"));
        native_test_mod.addImport("crypto", crypto_mod);
        const native_core_test_mod = b.createModule(.{
            .root_source_file = b.path("src/test_native_core.zig"),
            .target = target,
            .optimize = optimize,
        });
        native_core_test_mod.addOptions("build_options", build_options);
        native_core_test_mod.addImport("stdx", stdx_dep.module("stdx"));
        native_core_test_mod.addImport("crypto", crypto_mod);
        var fixtures_mod: ?*Build.Module = null;
        if (testingx_dep) |dep| {
            const testingx_mod = dep.module("testingx");
            native_test_mod.addImport("testingx", testingx_mod);
            native_core_test_mod.addImport("testingx", testingx_mod);
            const fixtures = b.createModule(.{
                .root_source_file = b.path("tests/fixtures/fixtures.zig"),
                .target = target,
                .optimize = optimize,
            });
            fixtures.addImport("testingx", testingx_mod);
            native_test_mod.addImport("fixtures", fixtures);
            native_core_test_mod.addImport("fixtures", fixtures);
            fixtures_mod = fixtures;
        }
        tests.addNativeSteps(b, .{
            .test_mod = native_test_mod,
            .core_test_mod = native_core_test_mod,
            .fuzz = fuzz_mode,
            .testingx = testingx_dep,
        });
        if (fixtures_mod) |fixtures| {
            examples_mod.addSteps(b, .{
                .target = target,
                .optimize = optimize,
                .tls_mod = mod,
                .fixtures_mod = fixtures,
            });
            bench_mod.addNativeSteps(b, @This(), .{
                .target = target,
                .tls_mod = mod,
                .crypto_mod = crypto_mod,
                .build_options = build_options,
                .fixtures_mod = fixtures,
                .stdx_mod = stdx_dep.module("stdx"),
            });
        }
        return;
    }

    const modules = c_modules.?;
    const libs = c_libs.?;
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addOptions("build_options", build_options);
    test_mod.link_libc = true;
    test_mod.linkSystemLibrary(libs.crypto, .{});
    test_mod.addImport("stdx", stdx_dep.module("stdx"));
    test_mod.addImport("crypto", crypto_mod);
    test_mod.addImport("openssl_c", modules.openssl_c);

    // testingx: plain-text test runner, benchmark harness, and comptime
    // fixtures. Lazy — only fetched when a development step is built, not
    // when consumers use tls as a library dependency.
    const testingx_dep = b.lazyDependency("testingx", .{
        // testingx declares no `optimize` option; the module is compiled at
        // the optimize mode of whatever artifact imports it.
        .target = target,
    });
    const testingx_mod = if (testingx_dep) |dep| dep.module("testingx") else null;
    if (testingx_mod) |tm| test_mod.addImport("testingx", tm);

    // Test fixtures module — replaces the old test_fixtures symlinks.
    const fixtures_mod = b.createModule(.{
        .root_source_file = b.path("tests/fixtures/fixtures.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (testingx_mod) |tm| fixtures_mod.addImport("testingx", tm);
    test_mod.addImport("fixtures", fixtures_mod);

    const c_mod = b.createModule(.{
        .root_source_file = b.path("bench/c.zig"),
        .target = target,
        .optimize = optimize,
    });
    c_mod.link_libc = true;
    c_mod.linkSystemLibrary(libs.crypto, .{});
    c_mod.addImport("openssl_c", modules.openssl_c);

    const c_ssl_mod = b.createModule(.{
        .root_source_file = b.path("bench/c_ssl.zig"),
        .target = target,
        .optimize = optimize,
    });
    c_ssl_mod.link_libc = true;
    c_ssl_mod.linkSystemLibrary(libs.ssl, .{});
    c_ssl_mod.linkSystemLibrary(libs.crypto, .{});
    c_ssl_mod.addImport("openssl_ssl", modules.openssl_ssl);

    tests.addSteps(b, .{
        .test_mod = test_mod,
        .fuzz = fuzz_mode,
        .testingx = testingx_dep,
        .tls_mod = mod,
        .fixtures_mod = fixtures_mod,
        .openssl_c = modules.openssl_c,
        .pty_c = modules.pty_c,
        .target = target,
        .optimize = optimize,
        .libs = libs,
    });

    bench_mod.addSteps(b, @This(), .{
        .target = target,
        .tls_mod = mod,
        .crypto_mod = crypto_mod,
        .c_mod = c_mod,
        .c_ssl_mod = c_ssl_mod,
        .openssl_c = modules.openssl_c,
        .openssl_ssl = modules.openssl_ssl,
        .build_options = build_options,
        .fixtures_mod = fixtures_mod,
        .stdx_mod = stdx_dep.module("stdx"),
        .libs = libs,
    });

    examples_mod.addSteps(b, .{
        .target = target,
        .optimize = optimize,
        .tls_mod = mod,
        .fixtures_mod = fixtures_mod,
    });

    // C ABI library (-Dcapi)
    // Produces libbaskingspot_tls.a (static) from src/capi.zig. Consumers link a compatible
    // libcrypto-family library. Installs include/baskingspot_tls.h alongside. Behind the
    // option so default builds are unaffected. #30.
    if (capi) {
        const capi_mod = b.createModule(.{
            .root_source_file = b.path("src/capi.zig"),
            .target = target,
            .optimize = optimize,
        });
        capi_mod.addOptions("build_options", build_options);
        capi_mod.addImport("stdx", stdx_dep.module("stdx"));
        capi_mod.addImport("crypto", crypto_mod);
        capi_mod.link_libc = true;

        // Zig 0.17's system-library search is paths-first and stops at the
        // module's own library paths, so the C ABI build must name libcrypto's
        // directory. pkg-config is the source of truth in the shell.
        const libdir_output = b.run(&.{ "pkg-config", "--variable=libdir", libs.crypto });
        const libdir = std.mem.trim(u8, libdir_output, " \t\r\n");
        if (libdir.len == 0) panic("libcrypto pkg-config libdir is empty", .{});
        capi_mod.addLibraryPath(.{ .cwd_relative = libdir });

        const crypto_cflags = b.run(&.{ "pkg-config", "--cflags-only-I", libs.crypto });
        var include_flags = std.mem.tokenizeAny(u8, crypto_cflags, " \t\r\n");
        var include_count: usize = 0;
        while (include_flags.next()) |flag| {
            const include_dir: []const u8 = if (std.mem.eql(u8, flag, "-I"))
                include_flags.next() orelse panic("pkg-config returned -I without a path", .{})
            else if (std.mem.startsWith(u8, flag, "-I"))
                flag[2..]
            else
                panic("unexpected pkg-config --cflags-only-I output: {s}", .{flag});
            if (include_dir.len == 0) panic("pkg-config returned an empty include path", .{});
            capi_mod.addSystemIncludePath(.{ .cwd_relative = include_dir });
            include_count += 1;
        }
        if (include_count == 0) {
            const includedir_output = b.run(&.{
                "pkg-config", "--variable=includedir", libs.crypto,
            });
            const include_dir = std.mem.trim(u8, includedir_output, " \t\r\n");
            if (include_dir.len == 0) panic("libcrypto pkg-config includedir is empty", .{});
            capi_mod.addSystemIncludePath(.{ .cwd_relative = include_dir });
        }

        const baskingspot_tls_lib = b.addLibrary(.{
            .name = "baskingspot_tls",
            .root_module = capi_mod,
            .linkage = .static,
        });
        // The self-hosted ELF archiver (the default for Debug) can emit
        // truncated/malformed archives in some CI environments even for a
        // clean single-object .a (ziglang/zig#25129). Using the LLVM toolchain
        // routes archiving through llvm-ar, which produces a well-formed
        // archive. Local builds never reproduced the bug; this guards CI.
        baskingspot_tls_lib.use_llvm = true;
        const install_lib = b.addInstallArtifact(baskingspot_tls_lib, .{});
        const install_header = b.addInstallFile(
            b.path("include/baskingspot_tls.h"),
            "include/baskingspot_tls.h",
        );

        const capi_step = b.step("capi", "Build the C ABI library (libbaskingspot_tls.a)");
        capi_step.dependOn(&install_lib.step);
        capi_step.dependOn(&install_header.step);

        // Also wire into the default install step so `zig build -Dcapi` alone
        // produces the artifacts without needing a named step.
        b.getInstallStep().dependOn(&install_lib.step);
        b.getInstallStep().dependOn(&install_header.step);
    }
}
