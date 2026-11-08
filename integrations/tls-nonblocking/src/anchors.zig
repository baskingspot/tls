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
    /// The decoded bytes are not one DER SEQUENCE that fills the block.
    InvalidCertificateDer,
};

/// A DER certificate is a single SEQUENCE that fills the whole buffer.
///
/// `std.crypto.Certificate.Bundle.parseCert` walks the certificate with
/// unchecked reads: `der.Element.parse` indexes `bytes[i]` and `bytes[i + 1]`
/// past the end of a short or truncated block. In Debug that is a panic; in
/// ReleaseFast it is an out-of-bounds read. The whole buffer is checked here,
/// before std sees it, so caller-supplied PEM cannot reach that path.
fn validCertificateDer(der: []const u8) bool {
    const outer = derElement(der, 0) orelse return false;
    if (outer.tag != 0x30 or outer.end != der.len) return false;

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    // signatureValue }. Requiring all three rejects a bare nested SEQUENCE.
    var seen: u8 = 0;
    var tbs_children: u8 = 0;
    var i = outer.body;
    while (i < outer.end) {
        const child = derElement(der, i) orelse return false;
        if (child.end > outer.end) return false;
        if (seen == 0) {
            if (child.tag != 0x30) return false;
            tbs_children = countChildren(der, child);
            // version, serialNumber, signature, issuer, validity, subject,
            // subjectPublicKeyInfo are the first seven std reads.
            if (tbs_children < 6) return false;
        }
        seen += 1;
        i = child.end;
    }
    return seen == 3;
}

const DerElement = struct { tag: u8, body: usize, end: usize };

/// Parse one TLV at `index`, rejecting anything that does not fit. Children of
/// a constructed element are checked too, up to a fixed depth.
fn derElement(bytes: []const u8, index: usize) ?DerElement {
    return derElementDepth(bytes, index, 8);
}

fn derElementDepth(bytes: []const u8, index: usize, depth: u8) ?DerElement {
    if (depth == 0) return null;
    if (index + 2 > bytes.len) return null;
    const tag = bytes[index];
    const first = bytes[index + 1];
    var body = index + 2;
    var length: usize = 0;
    if (first < 0x80) {
        length = first;
    } else {
        const count: usize = first & 0x7f;
        // Indefinite length, or a length field wider than any real certificate.
        if (count == 0 or count > 4) return null;
        if (body + count > bytes.len) return null;
        for (bytes[body..][0..count]) |byte| length = (length << 8) | byte;
        // Non-minimal long form is malformed DER.
        if (length < 0x80) return null;
        body += count;
    }
    const end = std.math.add(usize, body, length) catch return null;
    if (end > bytes.len) return null;
    if (tag & 0x20 != 0) {
        var i = body;
        while (i < end) {
            const child = derElementDepth(bytes, i, depth - 1) orelse return null;
            if (child.end > end) return null;
            i = child.end;
        }
    }
    return .{ .tag = tag, .body = body, .end = end };
}

fn countChildren(bytes: []const u8, parent: DerElement) u8 {
    var count: u8 = 0;
    var i = parent.body;
    while (i < parent.end) {
        const child = derElement(bytes, i) orelse return 0;
        if (child.end > parent.end) return 0;
        count +|= 1;
        i = child.end;
    }
    return count;
}

/// Add every PEM CERTIFICATE block in `pem` to `bundle` and return how many
/// anchors the bundle gained. Nothing touches the filesystem.
///
/// `parseCert` drops a certificate silently when it is expired at `now_sec` or
/// carries an object identifier the parser does not recognize, so a zero return
/// means nothing usable was added rather than a parse failure. A caller that
/// configured one anchor and got zero back should say so loudly instead of
/// debugging the verification failure that follows.
///
/// Not atomic: a failure on a later block leaves the anchors added before it in
/// `bundle`. Do not undo that by truncating `bundle.bytes`, because `Bundle.map`
/// stores offsets into those bytes and a lookup then slices past the end. To
/// discard the set, drop the bundle.
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
        if (!validCertificateDer(bundle.bytes.items[start..][0..written])) {
            bundle.bytes.items.len = start;
            return error.InvalidCertificateDer;
        }
        bundle.parseCert(gpa, start, now_sec) catch |err| {
            bundle.bytes.items.len = start;
            return err;
        };
        // parseCert truncates back to `start` when it skips an anchor.
        if (bundle.bytes.items.len > start) added += 1;
    }
    return added;
}
