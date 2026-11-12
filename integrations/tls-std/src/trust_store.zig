//! OS trust-store loading that does not hand unvalidated DER to std.
//!
//! `std.crypto.Certificate.Bundle.rescan` reads a PEM store through
//! `addCertsFromFile`, which decodes each block and passes it straight to
//! `parseCert`. That parser reaches `der.Element.parse`, whose index reads are
//! unchecked in Zig 0.16.0 and 0.17.0, so one truncated certificate in the OS
//! store panics a Debug or ReleaseSafe process and reads out of bounds in
//! ReleaseFast (#177). Nothing outside std can guard `rescan` itself, because
//! `rescan` owns the file walk.
//!
//! This module owns the walk instead and rejects a block whose DER envelope
//! fails `tls.der.validCertificate` before std parses it. A corrupt entry is a
//! load error, not a crash. Linux and macOS are the supported platforms.
//!
//! It lives beside the transport rather than in `src/`: filling a `Bundle`
//! allocates, and the engine allocates nothing.
//!
//! RFC 7468 §2 (PEM framing).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = @import("tls").der;
const TlsCertificate = @import("tls").Certificate;

/// PEM bodies wrap at 64 columns, so interior newlines are part of the encoding.
const pem_decoder = std.base64.standard.decoderWithIgnore("\t\n\x0b\x0c\r ");

/// Bundle offsets are u32, so no store can hold more than 4 GiB of DER.
const max_store_bytes = std.math.maxInt(u32);

pub const Error = Certificate.Bundle.ParseCertError || error{
    /// Bundle indices are u32, so the concatenated DER cannot exceed 4 GiB.
    BundleTooBig,
    /// A BEGIN marker with no matching END marker after it.
    MissingEndCertificateMarker,
    /// A certificate body that is not valid base64.
    InvalidPemBase64,
    /// The decoded bytes do not form a complete DER certificate.
    InvalidCertificateDer,
};

pub const LoadError = Error ||
    Certificate.Bundle.RescanError ||
    Io.Dir.ReadFileAllocError ||
    Io.Dir.OpenError ||
    Io.Dir.Iterator.Error ||
    error{
        /// `loadSystem` knows where Linux and macOS keep their roots. Anywhere
        /// else, pass `.bundle` or load anchors yourself.
        UnsupportedPlatform,
    };

/// Fill `bundle` with the OS trust store, clearing whatever it held.
///
/// macOS keeps its roots in the keychain database, a binary format std owns;
/// that path still calls `rescan`, and the truncation hazard #177 describes
/// stays std's to fix. The keychain files are OS-owned, so the input a MAC
/// caller controls is not the input that reaches the unchecked parser.
///
/// Every other target reads the PEM files themselves.
pub fn loadSystem(
    bundle: *Certificate.Bundle,
    gpa: Allocator,
    io: Io,
    now: Io.Timestamp,
) LoadError!void {
    bundle.bytes.clearRetainingCapacity();
    bundle.map.clearRetainingCapacity();

    switch (builtin.os.tag) {
        .macos, .maccatalyst => try bundle.rescan(gpa, io, now),
        .linux => try loadLinux(bundle, gpa, io, now.toSeconds()),
        else => return error.UnsupportedPlatform,
    }

    bundle.bytes.shrinkAndFree(gpa, bundle.bytes.items.len);
}

/// A PEM bundle file if the host ships one, otherwise a directory of anchors.
/// Mirrors where `rescan` looks, so a store that loaded before still loads.
fn loadLinux(
    bundle: *Certificate.Bundle,
    gpa: Allocator,
    io: Io,
    now_sec: i64,
) LoadError!void {
    // Stop after the first bundle file that exists: a host has one.
    const cert_files = [_][]const u8{
        "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo
        "/etc/pki/tls/certs/ca-bundle.crt", // Fedora/RHEL 6
        "/etc/ssl/ca-bundle.pem", // openSUSE
        "/etc/pki/tls/cacert.pem", // OpenELEC
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
        "/etc/ssl/cert.pem", // Alpine
    };
    const cert_dirs = [_][]const u8{
        "/etc/ssl/certs", // SLES
        "/etc/pki/tls/certs", // Fedora/RHEL
    };

    scan: {
        for (cert_files) |path| {
            addCertsFromAbsoluteFile(bundle, gpa, io, path, now_sec) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
            break :scan;
        }
        for (cert_dirs) |path| {
            addCertsFromAbsoluteDir(bundle, gpa, io, path, now_sec) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
        }
    }
}

fn addCertsFromAbsoluteFile(
    bundle: *Certificate.Bundle,
    gpa: Allocator,
    io: Io,
    absolute_path: []const u8,
    now_sec: i64,
) (Error || Io.Dir.ReadFileAllocError)!void {
    const bytes = try Io.Dir.cwd().readFileAlloc(
        io,
        absolute_path,
        gpa,
        .limited(max_store_bytes),
    );
    defer gpa.free(bytes);
    _ = try addCertsFromPemBytes(bundle, gpa, bytes, now_sec);
}

fn addCertsFromAbsoluteDir(
    bundle: *Certificate.Bundle,
    gpa: Allocator,
    io: Io,
    absolute_path: []const u8,
    now_sec: i64,
) (Error || Io.Dir.OpenError || Io.Dir.Iterator.Error || Io.Dir.ReadFileAllocError)!void {
    const dir = try Io.Dir.openDirAbsolute(io, absolute_path, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        switch (entry.kind) {
            .file, .sym_link => {},
            else => continue,
        }
        try addCertsFromFile(bundle, gpa, io, dir, entry.name, now_sec);
    }
}

/// Read one PEM file from `dir` and add every anchor in it.
///
/// A file with no CERTIFICATE markers adds nothing and is not an error, so an
/// unrelated file dropped into a trust directory does not break the load.
pub fn addCertsFromFile(
    bundle: *Certificate.Bundle,
    gpa: Allocator,
    io: Io,
    dir: Io.Dir,
    sub_path: []const u8,
    now_sec: i64,
) (Error || Io.Dir.ReadFileAllocError)!void {
    const bytes = try dir.readFileAlloc(io, sub_path, gpa, .limited(max_store_bytes));
    defer gpa.free(bytes);
    _ = try addCertsFromPemBytes(bundle, gpa, bytes, now_sec);
}

/// Add every PEM CERTIFICATE block in `pem` to `bundle` and return how many
/// anchors the bundle gained. Nothing touches the filesystem.
///
/// `parseCert` drops a certificate silently when it is expired at `now_sec` or
/// carries an object identifier the parser does not recognize, so a zero return
/// means nothing usable was added rather than a parse failure.
///
/// Not atomic: a failure on a later block leaves the anchors added before it in
/// `bundle`. To discard the set, drop the bundle rather than truncating
/// `bundle.bytes`, because `Bundle.map` stores offsets into those bytes.
///
/// RFC 7468 §2, RFC 5280 §4.1.
pub fn addCertsFromPemBytes(
    bundle: *Certificate.Bundle,
    gpa: Allocator,
    pem: []const u8,
    now_sec: i64,
) Error!u32 {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    var added: u32 = 0;
    var pos: usize = 0;
    while (std.mem.findPos(u8, pem, pos, begin_marker)) |begin| {
        const body_start = begin + begin_marker.len;
        const body_end = std.mem.findPos(u8, pem, body_start, end_marker) orelse
            return error.MissingEndCertificateMarker;
        pos = body_end + end_marker.len;

        const encoded = std.mem.trim(u8, pem[body_start..body_end], " \t\r\n");
        const start = std.math.cast(u32, bundle.bytes.items.len) orelse
            return error.BundleTooBig;
        const upper = pem_decoder.calcSizeUpperBound(encoded.len);
        if (bundle.bytes.items.len + upper > max_store_bytes)
            return error.BundleTooBig;

        try bundle.bytes.ensureUnusedCapacity(gpa, upper);
        const dest = bundle.bytes.allocatedSlice()[bundle.bytes.items.len..][0..upper];
        const written = pem_decoder.decode(dest, encoded) catch
            // `upper` is calcSizeUpperBound, so NoSpaceLeft cannot happen;
            // every decode failure means the body was not valid base64.
            return error.InvalidPemBase64;
        bundle.bytes.items.len += written;
        if (!der.validCertificate(bundle.bytes.items[start..][0..written])) {
            bundle.bytes.items.len = start;
            return error.InvalidCertificateDer;
        }
        // The envelope check above bounds the walk. This second check runs the
        // engine's fork of the same parser over the same bytes, so a field it
        // refuses never reaches std's copy of the walk.
        _ = TlsCertificate.parse(.{
            .buffer = bundle.bytes.items,
            .index = start,
        }) catch |err| {
            bundle.bytes.items.len = start;
            if (err == error.CertificateHasUnrecognizedObjectId) continue;
            return error.InvalidCertificateDer;
        };
        bundle.parseCert(gpa, start, now_sec) catch |err| {
            bundle.bytes.items.len = start;
            if (err == error.CertificateHasUnrecognizedObjectId) continue;
            return err;
        };
        // parseCert truncates back to `start` when it skips an anchor.
        if (bundle.bytes.items.len > start) added += 1;
    }
    return added;
}
