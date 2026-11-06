//! The step-driven handshake core: levels in, levels out.
//!
//! This is the new type the record engines will become adapters over. It owns
//! the transcript and the key schedule, accepts bare handshake messages tagged
//! with an encryption level, and yields messages and level transitions for a
//! caller that provides its own protection (QUIC CRYPTO frames, or a record
//! adapter).
//!
//! Nothing here encrypts, frames, or decrypts. RFC 8446 §5 puts that around the
//! handshake; RFC 9001 §4.1.3 requires the level to be checked at this
//! boundary, which is what `level.check` does.
//!
//! Scope so far: the plaintext half of both roles. ClientHello and ServerHello
//! are absorbed, the key schedule runs, and both roles derive the same
//! handshake traffic secrets. Message encoding stays with the engines until the
//! adapter exists, so callers pass already-encoded messages in.

/// Derive the handshake traffic secrets from a finished exchange transcript.
/// Shared by both roles: RFC 8446 §7.1 does not care who is asking.
fn deriveHandshakeSecrets(suite: *suite_state.Suite, dhe: []const u8) aead.Error!void {
    switch (suite.*) {
        .buffering => unreachable,
        inline .sha256, .sha384 => |*arm| {
            const H = @TypeOf(arm.*).Hkdf;
            arm.handshake_secret = H.handshakeSecretFor(null, dhe);
            const th: H.TranscriptHash = .init(arm.transcript.peek());
            var handshake_key: H.Keyed = .init(&arm.handshake_secret.data);
            defer handshake_key.secureZero();
            arm.client_hs_secret = H.deriveSecretKeyed(&handshake_key, "c hs traffic", &th);
            arm.server_hs_secret = H.deriveSecretKeyed(&handshake_key, "s hs traffic", &th);
            // The Finished MAC needs the finished key derived from the same
            // traffic secret; the layer it builds with is not wanted here.
            var discard = try H.makeRecordLayerAndFinishedKey(
                arm.aead,
                arm.server_hs_secret,
                &arm.server_finished_key,
            );
            discard.deinit();
        },
    }
}

/// Copy the two handshake traffic secrets out of whichever arm is active.
fn copyHandshakeSecrets(suite: *const suite_state.Suite) ?HandshakeSecrets {
    return switch (suite.*) {
        .buffering => null,
        inline .sha256, .sha384 => |*arm| blk: {
            var secrets: HandshakeSecrets = .{
                .len = @TypeOf(arm.*).Hkdf.prk_len,
                .client = @splat(0),
                .server = @splat(0),
            };
            @memcpy(secrets.client[0..secrets.len], arm.client_hs_secret.data[0..secrets.len]);
            @memcpy(secrets.server[0..secrets.len], arm.server_hs_secret.data[0..secrets.len]);
            break :blk secrets;
        },
    };
}

pub const HandshakeSecrets = struct {
    len: u8,
    client: [48]u8,
    server: [48]u8,
};

const std = @import("std");
const testing = std.testing;

const backend = @import("crypto/backend.zig");
const certificate = @import("certificate.zig");
const encrypted_extensions = @import("encrypted_extensions.zig");
const extension_type = @import("extension_type.zig");
const finished = @import("finished.zig");
const handshake = @import("handshake.zig");
const level = @import("level.zig");
const server_hello = @import("server_hello.zig");
const aead = @import("aead.zig");
// Test-only fixture module; not needed by the core itself.
const fixtures = @import("fixtures");
const suite_state = @import("suite_state.zig");

const CipherSuite = @import("cipher_suite.zig").CipherSuite;

/// Largest leaf public key the core retains between Certificate and
/// CertificateVerify (RSA-4096 is the practical ceiling).
const crypto_max_pub_key = 1024;

pub const Error = error{
    /// A message arrived at a level it cannot occupy. RFC 9001 §4.1.3.
    /// A message arrived at a level it cannot occupy. RFC 9001 §4.1.3.
    WrongLevel,
    /// The caller asked for an output the queue has no room for.
    QueueFull,
    /// A message arrived out of order, or before the handshake reached the
    /// point that accepts it.
    UnexpectedMessage,
    /// The peer's leaf public key does not fit the core's retention buffer.
    CertificateKeyTooLarge,
} || server_hello.ParseError || certificate.VerifyError ||
    certificate.ParseError || finished.VerifyError ||
    encrypted_extensions.ParseError || aead.Error;

pub const Client = struct {
    /// Transcript and key schedule. The client starts buffering both candidate
    /// hashes because the suite is unknown until ServerHello (RFC 8446 §4.4.1).
    suite: suite_state.Suite,
    /// The caller's verification policy, applied by the core at the moment the
    /// transcript requires it. Required at construction: there is no default,
    /// so no caller can compile a handshake that verifies nothing by omission.
    policy: certificate.Policy,
    /// The extensions this client offered, which the EncryptedExtensions
    /// parser uses to reject anything the peer was not entitled to send.
    /// RFC 8446 §4.2.
    offered: extension_type.OfferedExtensions,
    /// The server leaf public key, retained between Certificate and
    /// CertificateVerify because the signature is checked against it.
    leaf_pub_key: [crypto_max_pub_key]u8,
    leaf_pub_key_len: u8,
    queue: level.Queue,
    /// Set once ServerHello selects the suite, so later messages can be checked
    /// against the chosen arm.
    selected: ?CipherSuite,
    state: State,

    pub const State = enum {
        start,
        wait_server_hello,
        server_hello_done,
        wait_encrypted_extensions,
        wait_certificate,
        wait_certificate_verify,
        wait_finished,
        server_finished_verified,
    };

    pub fn init(slots: []level.Output, policy: certificate.Policy) Client {
        return .{
            .suite = .init(),
            .queue = .init(slots),
            .policy = policy,
            .offered = .initEmpty(),
            .leaf_pub_key = undefined,
            .leaf_pub_key_len = 0,
            .selected = null,
            .state = .start,
        };
    }

    pub fn deinit(self: *Client) void {
        self.suite.secureZero();
        self.queue.clear();
        self.* = undefined;
    }

    pub fn next(self: *Client) ?level.Output {
        return self.queue.pop();
    }

    /// Hand the ClientHello to the handshake. The bytes are the message as
    /// `client_hello.encode*` produced it: handshake type and length included,
    /// no record around them. It is absorbed into the transcript and queued at
    /// `.plaintext`, which is the level it must be sent at.
    pub fn start(self: *Client, client_hello_msg: []const u8) Error!void {
        if (self.state != .start) return error.UnexpectedMessage;
        try level.check(.client_hello, .plaintext);
        self.suite.update(client_hello_msg);
        self.queue.push(.{ .message = .{
            .level = .plaintext,
            .bytes = client_hello_msg,
        } }) catch return error.QueueFull;
        self.state = .wait_server_hello;
    }

    /// Feed a plaintext ServerHello. The DHE shared secret is the caller's,
    /// because the key exchange belongs to the role that holds the private key;
    /// this core only needs the result to run the key schedule.
    ///
    /// On success the queue holds, in order: the two level transitions and the
    /// `key_available` event. Reads and writes are both `.handshake` from here
    /// until the server flight completes.
    pub fn provide(
        self: *Client,
        provided: level.Level,
        server_hello_msg: []const u8,
        dhe: []const u8,
    ) Error!void {
        if (self.state != .wait_server_hello) return error.UnexpectedMessage;
        try level.check(.server_hello, provided);

        const sh = try server_hello.parse(server_hello_msg);
        // Move the buffered transcript into the selected arm: the ClientHello
        // is already absorbed, and the hash state carries across.
        switch (self.suite) {
            .buffering => |b| {
                self.suite = switch (sh.cipher_suite) {
                    .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => .{
                        .sha256 = .init(b.sha256, sh.cipher_suite),
                    },
                    .aes_256_gcm_sha384 => .{
                        .sha384 = .init(b.sha384, sh.cipher_suite),
                    },
                };
            },
            inline .sha256, .sha384 => return error.UnexpectedMessage,
        }
        self.selected = sh.cipher_suite;
        self.suite.update(server_hello_msg);
        try self.deriveHandshakeKeys(dhe);

        self.queue.push(.{ .read_level = .handshake }) catch return error.QueueFull;
        self.queue.push(.{ .write_level = .handshake }) catch return error.QueueFull;
        self.queue.push(.{ .key_available = .handshake }) catch return error.QueueFull;
        self.state = .wait_encrypted_extensions;
    }

    /// Feed one message of the server's encrypted flight at `.handshake`. The
    /// core applies the caller's verification policy at the point the
    /// transcript requires it, and surfaces the specific failure rather than a
    /// single "bad certificate": the error sets of `certificate` and `finished`
    /// pass through unchanged.
    pub fn provideHandshake(
        self: *Client,
        provided: level.Level,
        msg: []const u8,
    ) Error!void {
        if (msg.len < 4) return error.UnexpectedEof;
        const msg_type: handshake.Type = @enumFromInt(msg[0]);
        try level.check(msg_type, provided);

        switch (self.state) {
            .start, .wait_server_hello => return error.UnexpectedMessage,
            .server_hello_done, .wait_encrypted_extensions => {
                if (msg_type != .encrypted_extensions) return error.UnexpectedMessage;
                _ = try encrypted_extensions.parse(msg, &.{}, .{
                    .offered_extensions = self.offered,
                });
                self.suite.update(msg);
                self.state = .wait_certificate;
            },
            .wait_certificate => {
                if (msg_type != .certificate) return error.UnexpectedMessage;
                const leaf = try certificate.parse(msg, self.policy);
                if (leaf.len > self.leaf_pub_key.len) return error.CertificateKeyTooLarge;
                @memcpy(self.leaf_pub_key[0..leaf.len], leaf);
                self.leaf_pub_key_len = @intCast(leaf.len);
                self.suite.update(msg);
                self.state = .wait_certificate_verify;
            },
            .wait_certificate_verify => {
                if (msg_type != .certificate_verify) return error.UnexpectedMessage;
                const th = self.transcriptHash();
                try certificate.verifyServerSignatureWithSchemes(
                    msg,
                    self.leaf_pub_key[0..self.leaf_pub_key_len],
                    th.slice(),
                    backend.capabilities.certificate_verify_schemes,
                );
                self.suite.update(msg);
                self.state = .wait_finished;
            },
            .wait_finished, .server_finished_verified => {
                if (msg_type != .finished) return error.UnexpectedMessage;
                const th = self.transcriptHash();
                try self.verifyFinished(msg, th.slice());
                self.suite.update(msg);
                self.state = .server_finished_verified;
            },
        }
    }

    fn verifyFinished(self: *Client, msg: []const u8, transcript_hash: []const u8) Error!void {
        switch (self.suite) {
            .buffering => return error.UnexpectedMessage,
            inline .sha256, .sha384 => |*arm| {
                const Hash = @TypeOf(arm.transcript);
                try finished.verify(
                    Hash,
                    msg,
                    &arm.server_finished_key.data,
                    transcript_hash,
                );
            },
        }
    }

    pub const TranscriptHash = struct {
        data: [48]u8,
        len: u8,

        pub fn init() TranscriptHash {
            return .{ .data = @splat(0), .len = 0 };
        }

        pub fn slice(self: *const TranscriptHash) []const u8 {
            return self.data[0..self.len];
        }
    };

    fn transcriptHash(self: *const Client) TranscriptHash {
        var out: TranscriptHash = .init();
        switch (self.suite) {
            .buffering => {},
            inline .sha256, .sha384 => |*arm| {
                const th = arm.transcript.peek();
                out.len = @intCast(th.len);
                @memcpy(out.data[0..th.len], &th);
            },
        }
        return out;
    }

    /// RFC 8446 §7.1 - mix the DHE shared secret into the key schedule and keep
    /// the handshake traffic secrets. The record layers are the adapter's
    /// problem, so only the secrets live here.
    fn deriveHandshakeKeys(self: *Client, dhe: []const u8) Error!void {
        if (self.suite == .buffering) return error.UnexpectedMessage;
        try deriveHandshakeSecrets(&self.suite, dhe);
    }

    /// The handshake traffic secrets, once ServerHello has been provided.
    pub fn handshakeSecrets(self: *const Client) ?HandshakeSecrets {
        return copyHandshakeSecrets(&self.suite);
    }

    /// The policy this handshake verifies against. Present so a caller can
    /// inspect what it constructed with; the core applies it, not the caller.
    pub fn policyOf(self: *const Client) certificate.Policy {
        return self.policy;
    }
};

// RFC 8448 §3, the plaintext half of the trace, driven through the core with no
// engine underneath. Every assertion is a value the RFC records: the message
// the core queues, the level events it emits, and the two handshake traffic
// secrets it derives.
const rfc8448_client_hello = [_]u8{
    0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34,
    0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38,
    0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2,
    0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef,
    0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, 0x00, 0x00,
    0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01,
    0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00,
    0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76,
    0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00,
    0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01,
    0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00,
    0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d,
    0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e,
    0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e,
    0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69,
    0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00,
    0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20,
    0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
    0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
    0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
    0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02,
    0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c,
    0x00, 0x02, 0x40, 0x01,
};

const rfc8448_server_hello = [_]u8{
    0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf,
    0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e,
    0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c,
    0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55,
    0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13,
    0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24,
    0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76,
    0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb,
    0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25,
    0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0,
    0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02,
    0x03, 0x04,
};

const dhe_rfc8448 = [_]u8{
    0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63,
    0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d,
    0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef,
    0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d,
};

const rfc8448_client_hs_secret = [_]u8{
    0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35,
    0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
    0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96,
    0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21,
};

const rfc8448_server_hs_secret = [_]u8{
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e,
    0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d,
    0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
};

test "core client: RFC 8448 §3 plaintext half" {
    var slots: [8]level.Output = undefined;
    var client: Client = .init(&slots, .init);
    defer client.deinit();

    // The ClientHello goes out at plaintext, after absorption.
    try client.start(&rfc8448_client_hello);
    const ch_out = client.next().?;
    try testing.expectEqual(level.Level.plaintext, ch_out.message.level);
    try testing.expectEqualSlices(u8, &rfc8448_client_hello, ch_out.message.bytes);
    try testing.expectEqual(@as(?level.Output, null), client.next());

    // ServerHello at plaintext: the core owns the transcript from here.
    try client.provide(.plaintext, &rfc8448_server_hello, &dhe_rfc8448);
    try testing.expectEqual(level.Level.handshake, client.next().?.read_level);
    try testing.expectEqual(level.Level.handshake, client.next().?.write_level);
    try testing.expectEqual(level.Level.handshake, client.next().?.key_available);

    const secrets = client.handshakeSecrets().?;
    try testing.expectEqual(@as(u8, 32), secrets.len);
    try testing.expectEqualSlices(u8, &rfc8448_client_hs_secret, secrets.client[0..32]);
    try testing.expectEqualSlices(u8, &rfc8448_server_hs_secret, secrets.server[0..32]);
}

test "core client: verification policy is required, never defaulted" {
    var slots: [8]level.Output = undefined;
    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;
    var client: Client = .init(&slots, policy);
    defer client.deinit();
    try testing.expect(client.policyOf().insecure_no_chain_anchor);
    // There is no `init(slots)` overload on purpose: a caller cannot reach a
    // handshake that verifies nothing by leaving a field out.
}

test "core client: a wrong-level ServerHello is refused" {
    var slots: [8]level.Output = undefined;
    var client: Client = .init(&slots, .init);
    defer client.deinit();
    try client.start(&rfc8448_client_hello);
    _ = client.next().?;
    try testing.expectError(
        error.WrongLevel,
        client.provide(.handshake, &rfc8448_server_hello, &dhe_rfc8448),
    );
}

/// The server's plaintext half: accept the ClientHello, queue the ServerHello,
/// derive the same handshake traffic secrets the client derives.
pub const Server = struct {
    suite: suite_state.Suite,
    queue: level.Queue,
    state: State,

    pub const State = enum { wait_client_hello, server_hello_queued };

    pub fn init(slots: []level.Output) Server {
        return .{ .suite = .init(), .queue = .init(slots), .state = .wait_client_hello };
    }

    pub fn deinit(self: *Server) void {
        self.suite.secureZero();
        self.queue.clear();
        self.* = undefined;
    }

    pub fn next(self: *Server) ?level.Output {
        return self.queue.pop();
    }

    /// Absorb the ClientHello and the ServerHello that answers it, then run the
    /// key schedule. The ServerHello bytes are the caller's, encoded by the
    /// policy that chose them; the core owns the transcript and the level.
    pub fn provide(
        self: *Server,
        provided: level.Level,
        client_hello_msg: []const u8,
        cipher_suite: CipherSuite,
        server_hello_msg: []const u8,
        dhe: []const u8,
    ) Error!void {
        if (self.state != .wait_client_hello) return error.UnexpectedMessage;
        try level.check(.client_hello, provided);

        // The server picks the suite, so the arm exists before the transcript
        // starts: no buffering arm, and the ClientHello is absorbed once.
        self.suite = switch (cipher_suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => .{
                .sha256 = .init(suite_state.Sha256.init(.{}), cipher_suite),
            },
            .aes_256_gcm_sha384 => .{
                .sha384 = .init(suite_state.Sha384.init(.{}), cipher_suite),
            },
        };
        self.suite.update(client_hello_msg);
        self.suite.update(server_hello_msg);
        try deriveHandshakeSecrets(&self.suite, dhe);

        self.queue.push(.{ .message = .{
            .level = .plaintext,
            .bytes = server_hello_msg,
        } }) catch return error.QueueFull;
        self.queue.push(.{ .read_level = .handshake }) catch return error.QueueFull;
        self.queue.push(.{ .write_level = .handshake }) catch return error.QueueFull;
        self.queue.push(.{ .key_available = .handshake }) catch return error.QueueFull;
        self.state = .server_hello_queued;
    }

    pub fn handshakeSecrets(self: *const Server) ?HandshakeSecrets {
        return copyHandshakeSecrets(&self.suite);
    }
};

// Both roles, same transcript, same DHE: the secrets must agree. This is the
// minimal statement of "one key schedule" and it needs no engine underneath.
test "core: client and server derive the same handshake secrets" {
    var client_slots: [8]level.Output = undefined;
    var server_slots: [8]level.Output = undefined;
    var client: Client = .init(&client_slots, .init);
    defer client.deinit();
    var server: Server = .init(&server_slots);
    defer server.deinit();

    try client.start(&rfc8448_client_hello);
    _ = client.next().?;
    try client.provide(.plaintext, &rfc8448_server_hello, &dhe_rfc8448);

    try server.provide(
        .plaintext,
        &rfc8448_client_hello,
        .aes_128_gcm_sha256,
        &rfc8448_server_hello,
        &dhe_rfc8448,
    );

    const from_client = client.handshakeSecrets().?;
    const from_server = server.handshakeSecrets().?;
    try testing.expectEqualSlices(u8, from_client.client[0..32], from_server.client[0..32]);
    try testing.expectEqualSlices(u8, from_client.server[0..32], from_server.server[0..32]);
    // And both are the recorded RFC 8448 values.
    try testing.expectEqualSlices(u8, &rfc8448_client_hs_secret, from_server.client[0..32]);
    try testing.expectEqualSlices(u8, &rfc8448_server_hs_secret, from_server.server[0..32]);
}

test "core: the server queues its ServerHello at plaintext" {
    var slots: [8]level.Output = undefined;
    var server: Server = .init(&slots);
    defer server.deinit();
    try server.provide(
        .plaintext,
        &rfc8448_client_hello,
        .aes_128_gcm_sha256,
        &rfc8448_server_hello,
        &dhe_rfc8448,
    );
    const first = server.next().?;
    try testing.expectEqual(level.Level.plaintext, first.message.level);
    try testing.expectEqualSlices(u8, &rfc8448_server_hello, first.message.bytes);
    try testing.expectEqual(level.Level.handshake, server.next().?.read_level);
    try testing.expectEqual(level.Level.handshake, server.next().?.write_level);
    try testing.expectEqual(level.Level.handshake, server.next().?.key_available);
}

// RFC 8448 §3's server flight, message by message, through the core with the
// caller's policy applied at the Certificate and CertificateVerify points. No
// engine underneath: the transcript, the ordering and the verification are the
// core's.
test "core client: RFC 8448 §3 encrypted flight verifies in order" {
    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;

    var slots: [16]level.Output = undefined;
    var client: Client = .init(&slots, policy);
    defer client.deinit();
    // The RFC 8448 ClientHello offers SNI and record_size_limit, so the trace's
    // EncryptedExtensions answers both.
    client.offered.insert(.server_name);
    client.offered.insert(.record_size_limit);

    try client.start(&rfc8448_client_hello);
    _ = client.next().?;
    try client.provide(.plaintext, &rfc8448_server_hello, &dhe_rfc8448);

    var flight_buf: [4096]u8 = undefined;
    const flight = fixtures.rfc8448.b64("server_flight.b64");
    @memcpy(flight_buf[0..flight.len], flight);

    var reader: handshake.Reader = .init(flight_buf[0..flight.len]);
    var messages: usize = 0;
    while (try reader.next()) |msg| {
        // Level discipline: everything in this flight rides handshake keys.
        try client.provideHandshake(.handshake, msg.raw);
        messages += 1;
    }
    try testing.expectEqual(@as(usize, 4), messages);
    try testing.expectEqual(Client.State.server_finished_verified, client.state);
}

test "core client: the flight is refused at the wrong level" {
    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;
    var slots: [16]level.Output = undefined;
    var client: Client = .init(&slots, policy);
    defer client.deinit();
    try client.start(&rfc8448_client_hello);
    _ = client.next().?;
    try client.provide(.plaintext, &rfc8448_server_hello, &dhe_rfc8448);

    var flight_buf: [4096]u8 = undefined;
    const flight = fixtures.rfc8448.b64("server_flight.b64");
    @memcpy(flight_buf[0..flight.len], flight);
    var reader: handshake.Reader = .init(flight_buf[0..flight.len]);
    const ee = (try reader.next()).?;
    try testing.expectError(
        error.WrongLevel,
        client.provideHandshake(.application, ee.raw),
    );
}
