//! Bounds-checked DER envelope validation.
//!
//! `std.crypto.Certificate.der.Element.parse` reads `bytes[index]` and
//! `bytes[index + 1]` without checking either against the buffer, and computes
//! an element end with no check that it fits. Zig 0.16.0 and 0.17.0 both do
//! this. A truncated certificate therefore panics a Debug or ReleaseSafe
//! build, and reads past the buffer in ReleaseFast.
//!
//! That is std's parser, and it is not the one this engine parses with: tls
//! forks the certificate parser precisely to bound those reads (#72). But
//! `std.crypto.Certificate.Bundle.parseCert` reaches std's own copy of the
//! walk, so any caller that fills a trust `Bundle` has to establish the
//! envelope is well formed first. That is what this module is for, and it is
//! the only reason it exists: it allocates nothing and reads no fields.
//!
//! RFC 5280 §4.1, RFC 7468 §2.

const std = @import("std");
const testing = std.testing;
const fixtures = @import("fixtures");
const print = std.debug.print;

const Element = struct {
    tag: u8,
    body: usize,
    end: usize,
};

/// Whether `der` holds exactly one well-formed DER certificate.
///
/// A certificate is a single SEQUENCE that fills the whole buffer, containing
/// a tbsCertificate, a signatureAlgorithm, and a signatureValue, in that
/// order. The tbsCertificate carries the six mandatory fields, or seven when
/// an explicit version precedes them.
///
/// This is the envelope, not the contents: fields are not decoded and the
/// signature is not checked. It is the weaker claim that std's parser cannot
/// walk off the end of the buffer.
pub fn validCertificate(der: []const u8) bool {
    const outer = element(der, 0) orelse return false;
    if (outer.tag != 0x30 or outer.end != der.len) return false;

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    // signatureValue }. Requiring all three rejects a bare nested SEQUENCE.
    var seen: u8 = 0;
    var tbs_children: u8 = 0;
    var i = outer.body;
    while (i < outer.end) {
        if (seen == 3) return false;
        const child = element(der, i) orelse return false;
        if (child.end > outer.end) return false;
        if (seen == 0) {
            if (child.tag != 0x30) return false;
            tbs_children = countChildren(der, child);
            // An explicit version precedes the six mandatory TBS fields.
            const first = element(der, child.body) orelse return false;
            const required: u8 = if (first.tag == 0xa0) 7 else 6;
            if (tbs_children < required) return false;
        }
        seen += 1;
        i = child.end;
    }
    return seen == 3;
}

/// Parse one TLV at `index`, rejecting anything that does not fit. Children of
/// a constructed element are checked too, up to a fixed depth.
fn element(bytes: []const u8, index: usize) ?Element {
    return elementDepth(bytes, index, 8);
}

fn elementDepth(bytes: []const u8, index: usize, depth: u8) ?Element {
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
            const child = elementDepth(bytes, i, depth - 1) orelse return null;
            if (child.end > end) return null;
            i = child.end;
        }
    }
    return .{ .tag = tag, .body = body, .end = end };
}

fn countChildren(bytes: []const u8, parent: Element) u8 {
    var count: u8 = 0;
    var i = parent.body;
    while (i < parent.end) {
        const child = element(bytes, i) orelse return 0;
        if (child.end > parent.end) return 0;
        count +|= 1;
        i = child.end;
    }
    return count;
}

// RFC 5280 §4.1 — a real certificate is one SEQUENCE with three children.
test "der: a certificate from the fixtures is well formed" {
    for ([_][]const u8{
        &fixtures.key_capacity_root_der,
        &fixtures.chain_leaf_der,
        &fixtures.chain_intermediate_der,
        &fixtures.server_cert_der,
        &fixtures.ed25519_cert_der,
    }) |cert| {
        try testing.expect(validCertificate(cert));
    }
}

// The repro from #177: a SEQUENCE holding one INTEGER, five bytes long. It is
// well-formed DER, so a length check on the outer TLV alone accepts it, and
// std's parser then indexes past the end three levels down.
test "der: a short well-formed SEQUENCE is not a certificate" {
    try testing.expectEqual(false, validCertificate(&.{ 0x30, 0x03, 0x02, 0x01, 0x01 }));
    try testing.expectEqual(false, validCertificate(&.{}));
    try testing.expectEqual(false, validCertificate(&.{0x30}));
    try testing.expectEqual(false, validCertificate(&.{ 0x30, 0x00 }));
}

// Every truncation of a valid certificate is rejected, including the ones
// that land on an element boundary: the outer length then runs past the end.
test "der: every truncated prefix of a certificate is rejected" {
    const cert = &fixtures.key_capacity_root_der;
    for (0..cert.len) |len| {
        if (validCertificate(cert[0..len])) {
            print(
                "accepted a {d}-byte prefix of a {d}-byte certificate\n",
                .{ len, cert.len },
            );
            return error.TestUnexpectedResult;
        }
    }
}

// A long-form length that fits the short form is malformed DER. Taking it
// anyway would let two encodings describe one element.
test "der: a non-minimal long-form length is rejected" {
    // 0x81 0x10 encodes a length of 16, which fits the short form.
    try testing.expectEqual(null, element(&.{ 0x30, 0x81, 0x10 }, 0));
    // The same length in long form for a value that needs it is fine.
    var long: [0x92]u8 = @splat(0);
    // A primitive OCTET STRING, 0x8f bytes long: past the short form, so the
    // long form is required rather than tolerated.
    long[0] = 0x04;
    long[1] = 0x81;
    long[2] = 0x8f;
    try testing.expectEqual(@as(usize, long.len), element(&long, 0).?.end);
}

// The shape that reaches std's parser: random blocks, biased toward a SEQUENCE
// prefix with a length that matches the block, are never a certificate.
test "der: random bytes are never a certificate" {
    var prng: std.Random.DefaultPrng = .init(0x1770);
    const random = prng.random();
    var block: [96]u8 = undefined;
    for (0..4_000) |_| {
        const len = random.uintLessThan(usize, block.len + 1);
        random.bytes(block[0..len]);
        if (len >= 2 and random.boolean()) {
            block[0] = 0x30;
            block[1] = @intCast(len - 2);
        }
        if (validCertificate(block[0..len])) return error.TestUnexpectedResult;
    }
}
