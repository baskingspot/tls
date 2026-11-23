//! pkg-config module names for the libcrypto family (#223).
//!
//! The libraries behind all three supported backends share one API surface and
//! three different pkg-config spellings. OpenSSL, BoringSSL, and the aws-lc
//! package that installs OpenSSL's filenames answer to `libcrypto` /
//! `libssl`. The aws-lc package that installs suffixed libraries answers to
//! `libcrypto-awslc` / `libssl-awslc` and ships no unsuffixed module at all,
//! so a literal `-lcrypto` resolves nowhere and the translate-c header search
//! gets no include directory.
//!
//! `linkSystemLibrary` reads the module's own Cflags and Libs when pkg-config
//! finds it, so naming the right module fixes the headers and the link
//! together. It emits no extra `-laws-lc` for the product module, which is why
//! the per-library modules below are preferred over `aws-lc`.

const std = @import("std");
const Build = std.Build;

pub const Libraries = struct {
    /// What to pass to `linkSystemLibrary` for the cryptography library:
    /// `libcrypto`, `libcrypto-awslc`, or bare `crypto` when no pkg-config
    /// module of either spelling exists.
    crypto: []const u8,
    /// The same for the TLS library: `libssl`, `libssl-awslc`, or `ssl`.
    ssl: []const u8,
};

pub fn resolve(b: *Build) Libraries {
    return .{
        .crypto = moduleName(b, "libcrypto"),
        .ssl = moduleName(b, "libssl"),
    };
}

fn moduleName(b: *Build, unsuffixed: []const u8) []const u8 {
    if (hasModule(b, unsuffixed)) return unsuffixed;
    const suffixed = b.fmt("{s}-awslc", .{unsuffixed});
    if (hasModule(b, suffixed)) return suffixed;
    // No pkg-config file in either spelling (or no pkg-config at all): fall
    // back to the library name so Zig's own `-l` search applies, as it did
    // before #223.
    return unsuffixed["lib".len..];
}

fn hasModule(b: *Build, module: []const u8) bool {
    const result = b.runFallible(
        &.{ "pkg-config", "--exists", module },
        .{ .stderr_behavior = .ignore },
    );
    return switch (result) {
        .success => true,
        else => false,
    };
}
