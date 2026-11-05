//! Encryption levels for handshake messages, shared by both roles.
//!
//! A TLS record hides the level in a sequence-number-selected key; a QUIC
//! packet header states it. The handshake needs the second view to serve both,
//! so the level becomes an explicit property of every message it hands out and
//! accepts (RFC 8446 §5, RFC 9001 §4.1.3).

const std = @import("std");
const testing = std.testing;
const handshake = @import("handshake.zig");

/// The four encryption levels a TLS 1.3 handshake uses. `plaintext` is the
/// ClientHello and ServerHello exchange, which carries no protection at all.
pub const Level = enum {
    plaintext,
    early,
    handshake,
    application,
};

/// One thing the handshake has for its caller, in order.
pub const Output = union(enum) {
    /// A handshake message to protect at `level` and send. The bytes are the
    /// message exactly as it appears after the record protection is removed:
    /// handshake type and length included, nothing around them.
    message: Message,
    /// Reads from now on use keys at this level.
    read_level: Level,
    /// Writes from now on use keys at this level.
    write_level: Level,
    /// Keys for `level` exist and may be used. The caller fetches the traffic
    /// secret and derives its own protection keys; the engine never derives
    /// record keys on this path.
    key_available: Level,
    /// The handshake is complete for this role.
    done,

    pub const Message = struct {
        level: Level,
        bytes: []const u8,
    };
};

pub const MismatchError = error{WrongLevel};

/// The level a handshake message is protected under, or null for a type this
/// engine does not consume as a whole message.
///
/// RFC 8446 §4: ClientHello and ServerHello are plaintext. EndOfEarlyData and
/// 0-RTT-bearing messages ride `early`. Everything between the server flight
/// and the client Finished rides `handshake`. NewSessionTicket and KeyUpdate
/// are post-handshake, so `application`.
pub fn of(msg_type: handshake.Type) ?Level {
    return switch (msg_type) {
        .client_hello => .plaintext,
        .server_hello => .plaintext,
        .end_of_early_data => .early,
        .encrypted_extensions,
        .certificate,
        .certificate_request,
        .certificate_verify,
        .finished,
        => .handshake,
        .new_session_ticket, .key_update => .application,
        .message_hash => null,
        _ => null,
    };
}

/// Reject a message delivered at a level it cannot occupy. RFC 9001 §4.1.3
/// requires this check: CRYPTO data at the wrong level is a connection error,
/// not something to hand to the parser and hope.
pub fn check(msg_type: handshake.Type, provided: Level) MismatchError!void {
    const expected = of(msg_type) orelse return;
    if (expected != provided) return error.WrongLevel;
}

test "of: every message type maps to its RFC 8446 section 4 level" {
    try testing.expectEqual(Level.plaintext, of(.client_hello).?);
    try testing.expectEqual(Level.plaintext, of(.server_hello).?);
    try testing.expectEqual(Level.early, of(.end_of_early_data).?);
    try testing.expectEqual(Level.handshake, of(.encrypted_extensions).?);
    try testing.expectEqual(Level.handshake, of(.certificate).?);
    try testing.expectEqual(Level.handshake, of(.certificate_request).?);
    try testing.expectEqual(Level.handshake, of(.certificate_verify).?);
    try testing.expectEqual(Level.handshake, of(.finished).?);
    try testing.expectEqual(Level.application, of(.new_session_ticket).?);
    try testing.expectEqual(Level.application, of(.key_update).?);
    try testing.expectEqual(@as(?Level, null), of(.message_hash));
    // An unknown code point is not ours to classify.
    try testing.expectEqual(@as(?Level, null), of(@enumFromInt(0x6a)));
}

test "check: a message at the wrong level is refused" {
    try check(.client_hello, .plaintext);
    try testing.expectError(error.WrongLevel, check(.client_hello, .handshake));
    try testing.expectError(error.WrongLevel, check(.finished, .application));
    try testing.expectError(error.WrongLevel, check(.key_update, .handshake));
    // Unclassified types are not rejected here; the parser owns them.
    try check(.message_hash, .application);
}
