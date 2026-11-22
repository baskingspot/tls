//! TLS 1.3 signature scheme identifiers.
//!
//! RFC 8446 §4.2.3
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const compat = @import("compat.zig");
const memx = @import("memx.zig");

/// RFC 8446 §4.2.3 signature schemes supported by tls.
pub const SignatureScheme = enum(u16) {
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    _,

    pub const supported_handshake: []const SignatureScheme = &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
    };

    pub const supported_certificate: []const SignatureScheme = &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .ed25519,
    };

    pub fn supportsHandshake(self: SignatureScheme) bool {
        inline for (supported_handshake) |supported| {
            if (self == supported) return true;
        }
        return false;
    }
};

/// Certificate signature schemes recognized by TLS 1.3 X.509 certificate
/// parsing and policy checks (RFC 8446 §4.2.3, §4.4.2.2).
const recognized_certificate_signature_schemes = [_]SignatureScheme{
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
    .rsa_pkcs1_sha512,
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .ecdsa_secp521r1_sha512,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .ed25519,
};

pub const max_certificate_signature_schemes = recognized_certificate_signature_schemes.len;

/// TLS 1.3 certificate signature schemes from a peer's effective
/// `signature_algorithms_cert` list (or fallback `signature_algorithms`).
/// Retain the mask instead of slices into a transient handshake record.
pub const OfferedCertificateSchemes = struct {
    set: std.bit_set.Integer(max_certificate_signature_schemes),

    pub const empty: OfferedCertificateSchemes = .{ .set = .empty };

    pub fn clear(self: *OfferedCertificateSchemes) void {
        self.set.unsetAll();
    }

    /// Capture a validated, big-endian SignatureScheme vector.
    pub fn capture(self: *OfferedCertificateSchemes, wire_schemes: []const u8) void {
        assert(wire_schemes.len % 2 == 0);
        self.clear();
        var i: usize = 0;
        while (i < wire_schemes.len) : (i += 2) {
            const value = memx.readInt(u16, wire_schemes[i..][0..2]);
            const scheme: SignatureScheme = compat.enumFromInt(SignatureScheme, value);
            const index = schemeIndex(scheme) orelse continue;
            self.set.set(index);
        }
    }

    /// Capture an in-memory slice of SignatureScheme values.
    pub fn captureSchemes(
        self: *OfferedCertificateSchemes,
        schemes: []const SignatureScheme,
    ) void {
        self.clear();
        for (schemes) |scheme| {
            const index = schemeIndex(scheme) orelse continue;
            self.set.set(index);
        }
    }

    pub fn insert(self: *OfferedCertificateSchemes, scheme: SignatureScheme) void {
        const index = schemeIndex(scheme) orelse return;
        self.set.set(index);
    }

    pub fn contains(self: OfferedCertificateSchemes, scheme: SignatureScheme) bool {
        const index = schemeIndex(scheme) orelse return false;
        return self.set.isSet(index);
    }

    pub fn containsAll(
        self: OfferedCertificateSchemes,
        required: OfferedCertificateSchemes,
    ) bool {
        return required.set.subsetOf(self.set);
    }

    /// Write the intersection of `self` and `allowed` into caller storage.
    pub fn intersect(
        self: OfferedCertificateSchemes,
        allowed: []const SignatureScheme,
        out: *[max_certificate_signature_schemes]SignatureScheme,
    ) []const SignatureScheme {
        var count: usize = 0;
        for (recognized_certificate_signature_schemes, 0..) |scheme, index| {
            if (!self.set.isSet(index)) continue;
            if (std.mem.findScalar(SignatureScheme, allowed, scheme) == null) continue;
            out[count] = scheme;
            count += 1;
        }
        return out[0..count];
    }

    fn schemeIndex(scheme: SignatureScheme) ?usize {
        for (recognized_certificate_signature_schemes, 0..) |supported, index| {
            if (scheme == supported) return index;
        }
        return null;
    }
};

// RFC 8446 §4.2.3 — certificate-signature offers capture recognized schemes
// including RSASSA-PSS, ignore legacy/unrecognized values, and intersect
// cleanly with verification policy.
test "OfferedCertificateSchemes: captures recognized certificate schemes and intersects" {
    var offered: OfferedCertificateSchemes = .empty;
    offered.capture(&.{ 0x04, 0x01, 0x08, 0x07, 0x08, 0x04, 0x02, 0x01 });
    try testing.expect(offered.contains(.rsa_pkcs1_sha256));
    try testing.expect(offered.contains(.ed25519));
    try testing.expect(offered.contains(.rsa_pss_rsae_sha256));
    try testing.expect(!offered.contains(.ecdsa_secp256r1_sha256));

    var required: OfferedCertificateSchemes = .empty;
    required.insert(.rsa_pss_rsae_sha256);
    try testing.expect(offered.containsAll(required));
    required.insert(.ecdsa_secp256r1_sha256);
    try testing.expect(!offered.containsAll(required));

    var buf: [max_certificate_signature_schemes]SignatureScheme = undefined;
    const allowed = [_]SignatureScheme{ .ecdsa_secp256r1_sha256, .rsa_pkcs1_sha256 };
    const common = offered.intersect(&allowed, &buf);
    try testing.expectEqualSlices(SignatureScheme, &.{.rsa_pkcs1_sha256}, common);
}
