//! TLS extension type registry values.
//!
//! RFC 8446 §4.2 and related extension RFCs.

const std = @import("std");
const compat = @import("compat.zig");
const testing = std.testing;

const memx = @import("memx.zig");

// Sixty-four is more than twice a normal ClientHello's standard plus GREASE
// extensions, while keeping duplicate detection bounded without extra storage.
const max_extensions: usize = 64;

/// An extension the caller supplies verbatim. The engine frames it, rejects a
/// duplicate or reserved type, and otherwise treats `data` as opaque bytes: a
/// protocol built on TLS (QUIC's transport parameters, for instance) owns the
/// meaning. RFC 8446 §4.2.
pub const ExtraExtension = struct {
    extension_type: u16,
    data: []const u8,
};

/// Extensions the ClientHello and EncryptedExtensions encoders emit themselves.
/// A caller-supplied extension may not collide with one of these, and
/// `pre_shared_key` must stay last (RFC 8446 §4.2.11).
const reserved_types = [_]u16{
    0x0000, // server_name
    0x000a, // supported_groups
    0x000d, // signature_algorithms
    0x0010, // alpn
    0x0029, // pre_shared_key
    0x002b, // supported_versions
    0x002d, // psk_key_exchange_modes
    0x0032, // signature_algorithms_cert
    0x0033, // key_share
};

pub const ExtraExtensionError = error{
    /// The caller supplied a type the engine emits itself.
    ReservedExtension,
    /// The caller supplied the same type twice.
    DuplicateExtension,
    /// extension_data longer than the u16 length field allows.
    ExtensionTooLong,
};

pub fn validateExtraExtensions(
    extras: []const ExtraExtension,
) ExtraExtensionError!void {
    for (extras, 0..) |extra, index| {
        if (extra.data.len > std.math.maxInt(u16)) return error.ExtensionTooLong;
        for (reserved_types) |reserved| {
            if (extra.extension_type == reserved) return error.ReservedExtension;
        }
        for (extras[0..index]) |earlier| {
            if (earlier.extension_type == extra.extension_type)
                return error.DuplicateExtension;
        }
    }
}

/// Wire size of the supplied extensions: type, length, and data each time.
pub fn extraExtensionsLen(extras: []const ExtraExtension) ExtraExtensionError!usize {
    var total: usize = 0;
    for (extras) |extra| {
        if (extra.data.len > std.math.maxInt(u16)) return error.ExtensionTooLong;
        total += 4 + extra.data.len;
    }
    return total;
}

test "validateExtraExtensions: reserved, duplicate, and oversized are refused" {
    const reserved = [_]ExtraExtension{
        .{ .extension_type = 0x0029, .data = "" },
    };
    try testing.expectError(error.ReservedExtension, validateExtraExtensions(&reserved));

    const duplicate = [_]ExtraExtension{
        .{ .extension_type = 0x0039, .data = "a" },
        .{ .extension_type = 0x0039, .data = "b" },
    };
    try testing.expectError(error.DuplicateExtension, validateExtraExtensions(&duplicate));

    const ok = [_]ExtraExtension{
        .{ .extension_type = 0x0039, .data = "params" },
        .{ .extension_type = 0x4469, .data = "" },
    };
    try validateExtraExtensions(&ok);
    try testing.expectEqual(@as(usize, 4 + 6 + 4), try extraExtensionsLen(&ok));
}

pub const OfferedExtension = enum {
    server_name,
    record_size_limit,
    early_data,
};

pub const OfferedExtensions = std.EnumSet(OfferedExtension);

pub const DuplicateExtensionError = error{ InvalidExtensionLength, DuplicateExtension };

pub fn rejectDuplicateExtensions(extensions: []const u8) DuplicateExtensionError!void {
    var extension_count: usize = 0;
    var outer: usize = 0;
    while (outer < extensions.len) {
        if (extensions.len - outer < 4) return error.InvalidExtensionLength;
        extension_count += 1;
        if (extension_count > max_extensions) return error.InvalidExtensionLength;

        const ext_type = memx.readInt(u16, extensions[outer..][0..2]);
        const ext_len = memx.readInt(u16, extensions[outer + 2 ..][0..2]);
        const next = outer + 4 + ext_len;
        if (next > extensions.len) return error.InvalidExtensionLength;

        var inner_count = extension_count;
        var inner: usize = next;
        while (inner < extensions.len) {
            if (extensions.len - inner < 4) return error.InvalidExtensionLength;
            inner_count += 1;
            if (inner_count > max_extensions) return error.InvalidExtensionLength;
            if (memx.readInt(u16, extensions[inner..][0..2]) == ext_type)
                return error.DuplicateExtension;
            const inner_len = memx.readInt(u16, extensions[inner + 2 ..][0..2]);
            // Widen before adding: `4 + inner_len` evaluates in u16 when
            // inner_len is a peer-controlled length near 0xffff, which panics
            // in safety-checked builds before the bounds check can reject it.
            const inner_next = inner + 4 + @as(usize, inner_len);
            if (inner_next > extensions.len) return error.InvalidExtensionLength;
            inner = inner_next;
        }

        outer = next;
    }
}

pub const ExtensionType = enum(u16) {
    server_name = 0x0000,
    status_request = 0x0005,
    supported_groups = 0x000a,
    signature_algorithms = 0x000d,
    heartbeat = 0x000f,
    alpn = 0x0010,
    status_request_v2 = 0x0011,
    signed_certificate_timestamp = 0x0012,
    padding = 0x0015,
    record_size_limit = 0x001c,
    pre_shared_key = 0x0029,
    early_data = 0x002a,
    supported_versions = 0x002b,
    cookie = 0x002c,
    psk_key_exchange_modes = 0x002d,
    certificate_authorities = 0x002f,
    oid_filters = 0x0030,
    post_handshake_auth = 0x0031,
    signature_algorithms_cert = 0x0032,
    key_share = 0x0033,
    _,

    pub fn isGrease(self: ExtensionType) bool {
        const value = compat.enumToInt(self);
        return (value & 0x0f0f) == 0x0a0a and (value >> 8) == (value & 0xff);
    }
};

// RFC 8446 §4.2 — extension blocks contain a vector of Extension entries.
test "rejectDuplicateExtensions: rejects more than the extension count cap" {
    var extensions: [4 * (max_extensions + 1)]u8 = undefined;
    for (0..max_extensions + 1) |index| {
        const offset = index * 4;
        extensions[offset] = @intCast(index >> 8);
        extensions[offset + 1] = @intCast(index & 0xff);
        extensions[offset + 2] = 0;
        extensions[offset + 3] = 0;
    }

    try testing.expectError(error.InvalidExtensionLength, rejectDuplicateExtensions(&extensions));
}

// RFC 8446 §4.2 — an extension block must not contain the same ExtensionType
// more than once, including unknown extension types.
test "rejectDuplicateExtensions: rejects duplicate unknown type" {
    const extensions: [13]u8 = .{
        0xab, 0xcd, 0x00, 0x01, 0x00,
        0x00, 0x15, 0x00, 0x00, 0xab,
        0xcd, 0x00, 0x00,
    };
    try testing.expectError(error.DuplicateExtension, rejectDuplicateExtensions(&extensions));
}

// RFC 8446 §4.2 — a normal block with distinct ExtensionType values is valid.
test "rejectDuplicateExtensions: accepts distinct extension types" {
    const extensions: [15]u8 = .{
        0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x0a, 0x00, 0x00, 0x00,
        0x2b, 0x00, 0x02, 0x03, 0x04,
    };
    try rejectDuplicateExtensions(&extensions);
}

// RFC 8446 §4.2 — extension blocks are vectors of type/length/value entries.
// RFC 8701 §2 — GREASE values reserve code points of the form 0x?a?a.
test "ExtensionType.isGrease: detects reserved GREASE extension code points" {
    const grease_0a: ExtensionType = compat.enumFromInt(ExtensionType, 0x0a0a);
    const grease_1a: ExtensionType = compat.enumFromInt(ExtensionType, 0x1a1a);
    const grease_fa: ExtensionType = compat.enumFromInt(ExtensionType, 0xfafa);
    const unknown: ExtensionType = compat.enumFromInt(ExtensionType, 0x5a5b);
    try testing.expect(grease_0a.isGrease());
    try testing.expect(grease_1a.isGrease());
    try testing.expect(grease_fa.isGrease());
    try testing.expect(!unknown.isGrease());
    try testing.expect(!ExtensionType.heartbeat.isGrease());
}

test "rejectDuplicateExtensions: rejects malformed block" {
    try testing.expectError(
        error.InvalidExtensionLength,
        rejectDuplicateExtensions(&.{ 0x00, 0x15, 0x00 }),
    );
    try testing.expectError(
        error.InvalidExtensionLength,
        rejectDuplicateExtensions(&.{ 0x00, 0x15, 0x00, 0x02, 0x00 }),
    );
}

// RFC 8446 §4.2 — an inner extension length is a u16 from the peer. The
// offset arithmetic must widen before the add so a length near 0xffff is
// rejected instead of overflowing.
test "rejectDuplicateExtensions: oversized inner length field is an error, not an overflow" {
    try testing.expectError(
        error.InvalidExtensionLength,
        rejectDuplicateExtensions(&.{ 0x00, 0x2b, 0x00, 0x00, 0x00, 0x0a, 0xff, 0xfc }),
    );
    try testing.expectError(
        error.InvalidExtensionLength,
        rejectDuplicateExtensions(&.{ 0x00, 0x2b, 0x00, 0x00, 0x00, 0x0a, 0xff, 0xff }),
    );
}
