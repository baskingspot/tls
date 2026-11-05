//! Optional retention of TLS 1.3 traffic secrets.
//!
//! The engine derives these secrets during the handshake and normally wipes
//! them as soon as the record layers exist. A caller that needs the secrets
//! themselves - a QUIC implementation deriving its own packet keys, or a
//! diagnostic - asks for them at construction and lends storage.
//!
//! Retention is opt-in because it lengthens the window in which keying
//! material sits in memory. Without `Config.traffic_secrets`, the engine
//! behaves exactly as before: derive, build the layers, wipe.

const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;
const assert = std.debug.assert;

/// Longest traffic secret: a SHA-384 output.
pub const max_len = 48;

/// One traffic secret. `len` is the negotiated hash length, 32 for SHA-256
/// suites and 48 for SHA-384.
pub const Secret = struct {
    data: [max_len]u8,
    len: u8,

    pub fn init(raw: []const u8) Secret {
        assert(raw.len <= max_len);
        var secret: Secret = .{ .data = undefined, .len = @intCast(raw.len) };
        @memcpy(secret.data[0..raw.len], raw);
        return secret;
    }

    pub fn bytes(self: *const Secret) []const u8 {
        return self.data[0..self.len];
    }

    pub fn secureZero(self: *Secret) void {
        crypto.secureZero(u8, self.data[0..self.len]);
    }
};

/// The secrets a caller asked to keep. Each is null until the handshake
/// derives it, so a caller can tell "not yet" from "not retained".
pub const TrafficSecrets = struct {
    /// RFC 8446 §7.1 - "c hs traffic", "s hs traffic".
    client_handshake: ?Secret,
    server_handshake: ?Secret,
    /// RFC 8446 §7.1 - "c ap traffic", "s ap traffic".
    client_application: ?Secret,
    server_application: ?Secret,
    /// RFC 8446 §7.1 - "c e traffic". Only with 0-RTT.
    client_early: ?Secret,
    /// Negotiated hash length: 32 or 48. Zero before negotiation.
    len: u8,

    pub fn init() TrafficSecrets {
        return .{
            .client_handshake = null,
            .server_handshake = null,
            .client_application = null,
            .server_application = null,
            .client_early = null,
            .len = 0,
        };
    }

    /// Wipe every held secret. The caller owns this storage and owns clearing
    /// it; the engine never writes lent memory on teardown.
    pub fn secureZero(self: *TrafficSecrets) void {
        inline for (.{
            "client_handshake",
            "server_handshake",
            "client_application",
            "server_application",
            "client_early",
        }) |field| {
            if (@field(self, field)) |*value| value.secureZero();
        }
        self.* = .init();
    }

    pub fn setHandshake(self: *TrafficSecrets, client: []const u8, server: []const u8) void {
        self.client_handshake = Secret.init(client);
        self.server_handshake = Secret.init(server);
        self.len = @intCast(client.len);
    }

    pub fn setClientApplication(self: *TrafficSecrets, bytes: []const u8) void {
        self.client_application = Secret.init(bytes);
        self.len = @intCast(bytes.len);
    }

    pub fn setServerApplication(self: *TrafficSecrets, bytes: []const u8) void {
        self.server_application = Secret.init(bytes);
        self.len = @intCast(bytes.len);
    }

    pub fn setClientEarly(self: *TrafficSecrets, bytes: []const u8) void {
        self.client_early = Secret.init(bytes);
        self.len = @intCast(bytes.len);
    }

    /// RFC 8446 §7.1 HKDF-Expand-Label over a held secret, with an empty
    /// context. RFC 9001 §5.1 uses exactly this form with the labels
    /// "quic key", "quic iv", and "quic hp" - those labels belong to the
    /// QUIC implementation, not here.
    pub fn expand(
        comptime Hkdf: type,
        secret: *const Secret,
        comptime label: []const u8,
        out: []u8,
    ) void {
        assert(secret.len == Hkdf.prk_len);
        var prk: Hkdf.Prk = undefined;
        @memcpy(prk.data[0..secret.len], secret.data[0..secret.len]);
        defer crypto.secureZero(u8, &prk.data);
        Hkdf.expandLabel(out, label, "", prk);
    }
};

test "a set secret is readable, sized, and zeroed" {
    var secrets: TrafficSecrets = .init();
    try testing.expectEqual(@as(?Secret, null), secrets.client_handshake);
    try testing.expectEqual(@as(u8, 0), secrets.len);

    secrets.setHandshake(&@as([32]u8, @splat(0xa5)), &@as([32]u8, @splat(0x5a)));
    try testing.expectEqual(@as(u8, 32), secrets.len);
    try testing.expectEqual(@as(usize, 32), secrets.client_handshake.?.bytes().len);
    try testing.expectEqual(@as(u8, 0xa5), secrets.client_handshake.?.bytes()[0]);
    try testing.expectEqual(@as(u8, 0x5a), secrets.server_handshake.?.bytes()[0]);

    secrets.secureZero();
    try testing.expectEqual(@as(?Secret, null), secrets.client_handshake);
    try testing.expectEqual(@as(?Secret, null), secrets.server_handshake);
}

test "sha384 secrets carry 48 bytes" {
    var secrets: TrafficSecrets = .init();
    secrets.setClientApplication(&@as([48]u8, @splat(0x11)));
    try testing.expectEqual(@as(u8, 48), secrets.len);
    try testing.expectEqual(@as(usize, 48), secrets.client_application.?.bytes().len);
    secrets.secureZero();
}

test "secureZero wipes the bytes, not just the optionals" {
    var secret: Secret = .init(&@as([32]u8, @splat(0xff)));
    const held: *const [max_len]u8 = &secret.data;
    secret.secureZero();
    for (held.*[0..32]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "expand derives a QUIC-shaped label from a held secret" {
    // RFC 8448 §3 traffic secrets are SHA-256; the expected bytes here are a
    // self-consistency check, not a published vector: same input, same output.
    const hkdf = @import("hkdf.zig");
    var secrets: TrafficSecrets = .init();
    secrets.setClientApplication(&@as([32]u8, @splat(0x42)));
    var first: [16]u8 = undefined;
    var second: [16]u8 = undefined;
    TrafficSecrets.expand(hkdf.HkdfSha256, &secrets.client_application.?, "quic key", &first);
    TrafficSecrets.expand(hkdf.HkdfSha256, &secrets.client_application.?, "quic key", &second);
    try testing.expectEqualSlices(u8, &first, &second);
    var other: [16]u8 = undefined;
    TrafficSecrets.expand(hkdf.HkdfSha256, &secrets.client_application.?, "quic iv", &other);
    try testing.expect(!std.mem.eql(u8, &first, &other));
    secrets.secureZero();
}
