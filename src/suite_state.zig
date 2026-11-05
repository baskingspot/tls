//! Hash-parameterized TLS 1.3 traffic-secret state shared by client and server.
const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;

const aead = @import("aead.zig");
const CipherSuite = @import("cipher_suite.zig").CipherSuite;
const RecordLayer = @import("RecordLayer.zig");
const hkdf = @import("hkdf.zig");

const sha2 = @import("crypto/backend.zig").sha2;
const Sha256 = sha2.Sha256;
const Sha384 = sha2.Sha384;

pub fn HashArm(comptime Hkdf_: type, comptime Hash: type) type {
    return struct {
        const Self = @This();
        pub const Hkdf = Hkdf_;

        transcript: Hash,
        aead: CipherSuite,
        handshake_secret: Hkdf.Prk = undefined,
        client_finished_key: Hkdf.FinishedKey = undefined,
        server_finished_key: Hkdf.FinishedKey = undefined,
        client_app_secret: Hkdf.TrafficSecret = undefined,
        server_app_secret: Hkdf.TrafficSecret = undefined,
        /// RFC 8446 §7.5 — resumption_master_secret, derived from the master
        /// secret and the transcript through the client Finished. Retained
        /// post-handshake so either role can derive per-ticket PSKs from
        /// NewSessionTicket nonces. NOT in the forgetHandshakeSecrets range.
        resumption_master: Hkdf.Prk = undefined,
        resumption_master_valid: bool,

        /// An arm for the negotiated suite with the transcript started and
        /// every derived secret unset. `installHandshakeArm` fills the
        /// handshake secret from the key exchange.
        pub fn init(transcript: Hash, cipher: CipherSuite) Self {
            return .{
                .transcript = transcript,
                .aead = cipher,
                .handshake_secret = undefined,
                .client_finished_key = undefined,
                .server_finished_key = undefined,
                .client_app_secret = undefined,
                .server_app_secret = undefined,
                .resumption_master = undefined,
                .resumption_master_valid = false,
            };
        }

        pub inline fn secureZero(self: *Self) void {
            crypto.secureZero(u8, mem.asBytes(self));
        }

        pub fn forgetHandshakeSecrets(self: *Self) void {
            // These three values are only needed through Finished verification
            // and application-secret derivation. Keep them adjacent so they can
            // be wiped with one volatile zeroing operation instead of three
            // separate calls.
            //
            // The offset checks make the layout dependency explicit: if someone
            // inserts a field into this range later, the build fails rather than
            // silently leaving part of the handshake secret state uncleared.
            comptime {
                const handshake_end = @offsetOf(Self, "handshake_secret") +
                    @sizeOf(Hkdf.Prk);
                const client_finished_end = @offsetOf(Self, "client_finished_key") +
                    @sizeOf(Hkdf.FinishedKey);
                if (@offsetOf(Self, "client_finished_key") != handshake_end)
                    @compileError("handshake secrets must stay contiguous");
                if (@offsetOf(Self, "server_finished_key") != client_finished_end)
                    @compileError("handshake secrets must stay contiguous");
            }

            const start = @offsetOf(Self, "handshake_secret");
            const end = @offsetOf(Self, "server_finished_key") + @sizeOf(Hkdf.FinishedKey);
            crypto.secureZero(u8, mem.asBytes(self)[start..end]);
        }

        pub fn ratchetClientKey(self: *Self) aead.Error!RecordLayer {
            var next_secret = Hkdf.nextTrafficSecret(self.client_app_secret);
            defer next_secret.secureZero();
            self.client_app_secret.secureZero();
            self.client_app_secret = next_secret;
            return Hkdf.makeRecordLayer(self.aead, self.client_app_secret);
        }

        pub fn ratchetServerKey(self: *Self) aead.Error!RecordLayer {
            var next_secret = Hkdf.nextTrafficSecret(self.server_app_secret);
            defer next_secret.secureZero();
            self.server_app_secret.secureZero();
            self.server_app_secret = next_secret;
            return Hkdf.makeRecordLayer(self.aead, self.server_app_secret);
        }
    };
}

/// The unified handshake suite state: transcript plus key schedule, for both
/// roles. The client starts in `buffering` because the hash is unknown until
/// ServerHello; the server picks an arm at ClientHello and never buffers.
pub const Suite = union(enum) {
    /// Pre-ServerHello: run both candidate transcript hashes and keep the one
    /// the chosen suite uses. RFC 8446 §4.4.1 permits deferring the transcript
    /// until the hash is selected.
    ///
    /// Client-only. A server picks its arm at ClientHello and never buffers, so
    /// every server switch over this union carries `else => unreachable`; a
    /// server that reaches `buffering` is a bug, not a supported state. Extend
    /// buffering to the server by removing those arms, not by ignoring them.
    pub const Buffering = struct {
        sha256: Sha256,
        sha384: Sha384,

        pub fn init() Buffering {
            return .{ .sha256 = .init(.{}), .sha384 = .init(.{}) };
        }
    };

    buffering: Buffering,
    sha256: HashArm(hkdf.HkdfSha256, Sha256),
    sha384: HashArm(hkdf.HkdfSha384, Sha384),

    /// A function, not a constant: libcrypto hash init cannot run at comptime.
    pub fn init() Suite {
        return .{ .buffering = .init() };
    }

    pub fn secureZero(self: *Suite) void {
        switch (self.*) {
            .buffering => {},
            inline .sha256, .sha384 => |*s| s.secureZero(),
        }
    }

    /// Feed one handshake message into the running transcript hash.
    /// RFC 8446 §4.4.1. While buffering, both candidate hashes are fed.
    pub fn update(self: *Suite, msg: []const u8) void {
        switch (self.*) {
            .buffering => |*b| {
                b.sha256.update(msg);
                b.sha384.update(msg);
            },
            inline .sha256, .sha384 => |*s| s.transcript.update(msg),
        }
    }

    pub fn ratchetClientKey(self: *Suite) aead.Error!RecordLayer {
        return switch (self.*) {
            .buffering => unreachable,
            inline .sha256, .sha384 => |*s| s.ratchetClientKey(),
        };
    }

    pub fn ratchetServerKey(self: *Suite) aead.Error!RecordLayer {
        return switch (self.*) {
            .buffering => unreachable,
            inline .sha256, .sha384 => |*s| s.ratchetServerKey(),
        };
    }
};

// RFC 8446 §7.1 — erase obsolete handshake secrets.
// Retain live traffic and resumption secrets until full cleanup.
test "secret lifecycle preserves live epochs and clears owned secret fields" {
    const testing = std.testing;
    inline for (.{
        .{ hkdf.HkdfSha256, Sha256, CipherSuite.aes_128_gcm_sha256 },
        .{ hkdf.HkdfSha384, Sha384, CipherSuite.aes_256_gcm_sha384 },
    }) |parameters| {
        var arm: HashArm(parameters[0], parameters[1]) = .{
            .transcript = .init(.{}),
            .aead = parameters[2],
            .handshake_secret = .init(@splat(0xa5)),
            .client_finished_key = .init(@splat(0xa5)),
            .server_finished_key = .init(@splat(0xa5)),
            .client_app_secret = .init(@splat(0xa5)),
            .server_app_secret = .init(@splat(0xa5)),
            .resumption_master = .init(@splat(0xa5)),
            .resumption_master_valid = true,
        };
        const transcript = arm.transcript.peek();
        const obsolete = .{ "handshake_secret", "client_finished_key", "server_finished_key" };
        const retained = .{ "client_app_secret", "server_app_secret", "resumption_master" };
        arm.forgetHandshakeSecrets();
        inline for (obsolete) |field|
            try testing.expect(mem.allEqual(u8, &@field(arm, field).data, 0));
        inline for (retained) |field|
            try testing.expect(mem.allEqual(u8, &@field(arm, field).data, 0xa5));
        try testing.expect(arm.resumption_master_valid);
        try testing.expectEqual(parameters[2], arm.aead);
        try testing.expectEqualSlices(u8, &transcript, &arm.transcript.peek());
        arm.secureZero();
        inline for (obsolete ++ retained) |field|
            try testing.expect(mem.allEqual(u8, &@field(arm, field).data, 0));
        try testing.expect(!arm.resumption_master_valid);
    }
}
