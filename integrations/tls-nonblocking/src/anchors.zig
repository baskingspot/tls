//! Trust anchors for a caller-driven transport, loaded from bytes.
//!
//! The engine's verification code takes a caller-owned
//! `std.crypto.Certificate.Bundle`. That type allocates, so it lives out here
//! rather than in `src/`, next to the transport whose `Options` takes it.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;

/// PEM bodies wrap at 64 columns, so interior newlines are part of the encoding.
const pem_decoder = std.base64.standard.decoderWithIgnore("\t\n\x0b\x0c\r ");

pub const Error = Certificate.Bundle.ParseCertError || error{
    /// Bundle indices are u32, so the concatenated DER cannot exceed 4 GiB.
    BundleTooBig,
    /// A BEGIN marker with no matching END marker after it.
    MissingEndCertificateMarker,
    /// A certificate body that is not valid base64.
    InvalidPemBase64,
};

/// Add every PEM CERTIFICATE block in `pem` to `bundle` and return how many
/// anchors the bundle gained. Nothing touches the filesystem.
///
/// `parseCert` drops a certificate silently when it is expired at `now_sec` or
/// carries an object identifier the parser does not recognize, so a zero return
/// means nothing usable was added rather than a parse failure. A caller that
/// configured one anchor and got zero back should say so loudly instead of
/// debugging the verification failure that follows.
///
/// `pem` is caller-owned and may hold more than one block. `bundle.deinit(gpa)`
/// still owns the bundle's storage.
///
/// RFC 7468 §2 (PEM framing), RFC 5280 §4.1 (certificate structure).
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
        _ = std.math.cast(u32, bundle.bytes.items.len + upper) orelse
            return error.BundleTooBig;

        try bundle.bytes.ensureUnusedCapacity(gpa, upper);
        const dest = bundle.bytes.allocatedSlice()[bundle.bytes.items.len..][0..upper];
        const written = pem_decoder.decode(dest, encoded) catch
            // `upper` is calcSizeUpperBound, so NoSpaceLeft cannot happen;
            // every decode failure means the body was not valid base64.
            return error.InvalidPemBase64;
        bundle.bytes.items.len += written;
        bundle.parseCert(gpa, start, now_sec) catch |err| {
            bundle.bytes.items.len = start;
            return err;
        };
        // parseCert truncates back to `start` when it skips an anchor.
        if (bundle.bytes.items.len > start) added += 1;
    }
    return added;
}
