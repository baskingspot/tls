//! Encryption levels for handshake messages, shared by both roles.
//!
//! A TLS record hides the level in a sequence-number-selected key; a QUIC
//! packet header states it. The handshake needs the second view to serve both,
//! so the level becomes an explicit property of every message it hands out and
//! accepts (RFC 8446 §5, RFC 9001 §4.1.3).

const std = @import("std");
const compat = @import("compat.zig");
const testing = std.testing;
const alert = @import("alert.zig");
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
    /// An alert the caller must carry: a record for a TLS stream, a
    /// CONNECTION_CLOSE for QUIC. The core never frames or encrypts one.
    alert: Struct,

    pub const Message = struct {
        level: Level,
        bytes: []const u8,
    };

    pub const Struct = struct {
        level: alert.Level,
        description: alert.Description,
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
    try testing.expectEqual(@as(?Level, null), of(compat.enumFromInt(handshake.Type, 0x6a)));
}

test "check: a message at the wrong level is refused" {
    try check(.client_hello, .plaintext);
    try testing.expectError(error.WrongLevel, check(.client_hello, .handshake));
    try testing.expectError(error.WrongLevel, check(.finished, .application));
    try testing.expectError(error.WrongLevel, check(.key_update, .handshake));
    // Unclassified types are not rejected here; the parser owns them.
    try check(.message_hash, .application);
}

/// A bounded FIFO of `Output`s, over caller-owned storage. The handshake fills
/// it and the caller drains it with `next()`; nothing here allocates, and the
/// byte slices in `message` outputs borrow whatever buffer produced them.
pub const Queue = struct {
    slots: []Output,
    head: usize,
    tail: usize,

    pub const Error = error{QueueFull};

    pub fn init(slots: []Output) Queue {
        return .{ .slots = slots, .head = 0, .tail = 0 };
    }

    pub fn isEmpty(self: *const Queue) bool {
        return self.head == self.tail;
    }

    pub fn isFull(self: *const Queue) bool {
        return self.tail - self.head == self.slots.len;
    }

    pub fn push(self: *Queue, item: Output) Error!void {
        if (self.isFull()) return error.QueueFull;
        self.slots[self.tail % self.slots.len] = item;
        self.tail += 1;
    }

    pub fn pop(self: *Queue) ?Output {
        if (self.isEmpty()) return null;
        const item = self.slots[self.head % self.slots.len];
        self.head += 1;
        return item;
    }

    /// Drop everything without freeing; used when a handshake fails.
    pub fn clear(self: *Queue) void {
        self.head = 0;
        self.tail = 0;
    }
};

test "queue: FIFO order, bounded, and reusable after draining" {
    var slots: [2]Output = undefined;
    var q: Queue = .init(&slots);
    try testing.expect(q.isEmpty());

    const a = [_]u8{ 1, 2 };
    const b = [_]u8{3};
    try q.push(.{ .message = .{ .level = .plaintext, .bytes = &a } });
    try q.push(.{ .write_level = .handshake });
    try testing.expect(q.isFull());
    try testing.expectError(error.QueueFull, q.push(.done));

    const first = q.pop().?;
    try testing.expectEqual(Level.plaintext, first.message.level);
    try testing.expectEqualSlices(u8, &a, first.message.bytes);
    try testing.expectEqual(Level.handshake, q.pop().?.write_level);
    try testing.expect(q.isEmpty());
    try testing.expectEqual(@as(?Output, null), q.pop());

    // Drain-then-refill reuses the slots.
    try q.push(.{ .message = .{ .level = .early, .bytes = &b } });
    try testing.expectEqual(Level.early, q.pop().?.message.level);
}
