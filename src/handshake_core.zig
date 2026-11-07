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

/// RFC 8446 §4.4.1 - the HRR transcript replaces ClientHello1 with a
/// message_hash handshake message, then absorbs the HelloRetryRequest.
fn resetTranscriptForHrr(suite: *suite_state.Suite, ch1_hash: []const u8, hrr: []const u8) void {
    switch (suite.*) {
        .buffering => unreachable,
        inline .sha256, .sha384 => |*arm| blk: {
            const Hash = @TypeOf(arm.transcript);
            const hlen = Hash.digest_length;
            arm.transcript = Hash.init(.{});
            var prefix: [4 + 48]u8 = undefined;
            prefix[0] = @intFromEnum(handshake.Type.message_hash);
            prefix[1] = 0;
            prefix[2] = 0;
            prefix[3] = @intCast(hlen);
            @memcpy(prefix[4..][0..hlen], ch1_hash[0..hlen]);
            arm.transcript.update(prefix[0 .. 4 + hlen]);
            arm.transcript.update(hrr);
            break :blk;
        },
    }
}

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
            var discard_client = try H.makeRecordLayerAndFinishedKey(
                arm.aead,
                arm.client_hs_secret,
                &arm.client_finished_key,
            );
            discard_client.deinit();
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

/// What a role signs with when it authenticates.
pub const Credentials = struct {
    chain: CertificateChain,
    signer: signature.Signer,
};

pub const HandshakeSecrets = struct {
    len: u8,
    client: [48]u8,
    server: [48]u8,
};

const std = @import("std");
const testing = std.testing;

const backend = @import("crypto/backend.zig");
const alert = @import("alert.zig");
const certificate = @import("certificate.zig");
const NewSessionTicket = @import("NewSessionTicket.zig");
const certificate_request = @import("certificate_request.zig");
const client_hello = @import("client_hello.zig");
const kex = @import("kex.zig");
const Random = @import("root.zig").Random;
const KeyPairs = @import("handshake_key_pairs.zig").KeyPairs;
const hkdf = @import("hkdf.zig");
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const signature = @import("signature.zig");
const encrypted_extensions = @import("encrypted_extensions.zig");
const extension_type = @import("extension_type.zig");
const finished = @import("finished.zig");
const handshake = @import("handshake.zig");
const level = @import("level.zig");
const server_hello = @import("server_hello.zig");
const aead = @import("aead.zig");
// Test-only modules; not needed by the core itself.
const fixtures = @import("fixtures");
const x25519 = @import("x25519.zig");
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
    /// The server asked for a client certificate and the client sent none.
    ClientCertificateRequired,
} || server_hello.ParseError || certificate.VerifyError ||
    certificate.ParseError || certificate.EncodeError ||
    finished.VerifyError || encrypted_extensions.ParseError ||
    encrypted_extensions.EncodeError || certificate_request.ParseError ||
    signature.SignError || aead.Error ||
    server_hello.HrrParseError || client_hello.RetryEncodeError ||
    alert.ParseError || NewSessionTicket.ParseError ||
    error{
        AlpnProtocolTooLong,
        InvalidServerName,
        ServerNameTooLong,
        TooManyAlpnBytes,
        EmptyAlpnProtocol,
        ExtensionTooLong,
        ReservedExtension,
        DuplicateExtension,
        IdentityTooLong,
        InvalidBinderLength,
        InvalidHybridPolicy,
        HybridGroupUnavailable,
    } ||
    error{ TooManyKeyUpdates, InvalidHandshakeType };

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
    /// Client credentials, used only when the server sent a CertificateRequest.
    credentials: ?Credentials,
    /// True once the server asked for a client certificate; the flight then
    /// carries Certificate and CertificateVerify before Finished.
    received_certificate_request: bool,
    /// The server leaf public key, retained between Certificate and
    /// CertificateVerify because the signature is checked against it.
    leaf_pub_key: [crypto_max_pub_key]u8,
    leaf_pub_key_len: u8,
    queue: level.Queue,
    /// The last alert the peer sent.
    last_alert: ?alert.Alert,
    /// The most recent NewSessionTicket the peer sent.
    ticket: ?NewSessionTicket,
    /// Storage for the KeyUpdate response message the queue may hand out.
    ku_response: [5]u8,
    /// The cipher suite a PSK resumption offer uses. Set by the caller from the
    /// ticket; null means TLS_AES_128_GCM_SHA256.
    psk_suite: ?CipherSuite,
    /// Consecutive post-handshake key updates, capped per RFC 8446 §4.6.3.
    post_handshake_count: u16,
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
        wait_client_hello2,
        server_finished_verified,
        connected,
    };

    pub fn init(slots: []level.Output, policy: certificate.Policy) Client {
        return .{
            .suite = .init(),
            .queue = .init(slots),
            .policy = policy,
            .credentials = null,
            .received_certificate_request = false,
            .offered = .initEmpty(),
            .leaf_pub_key = undefined,
            .leaf_pub_key_len = 0,
            .last_alert = null,
            .ticket = null,
            .ku_response = undefined,
            .psk_suite = null,
            .post_handshake_count = 0,
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
            .start, .wait_server_hello, .wait_client_hello2 => return error.UnexpectedMessage,
            .server_hello_done, .wait_encrypted_extensions => {
                if (msg_type != .encrypted_extensions) return error.UnexpectedMessage;
                _ = try encrypted_extensions.parse(msg, &.{}, .{
                    .offered_extensions = self.offered,
                });
                self.suite.update(msg);
                self.state = .wait_certificate;
            },
            .wait_certificate => {
                if (msg_type == .certificate_request) {
                    const cr = try certificate_request.parse(msg);
                    if (!std.mem.eql(u8, cr.request_context, &.{})) {
                        return error.UnexpectedCertificateRequestContext;
                    }
                    self.received_certificate_request = true;
                    self.suite.update(msg);
                    return;
                }
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
            .connected => return error.UnexpectedMessage,
            .wait_finished, .server_finished_verified => {
                if (msg_type != .finished) return error.UnexpectedMessage;
                const th = self.transcriptHash();
                try self.verifyFinished(msg, th.slice());
                self.suite.update(msg);
                self.state = .server_finished_verified;
            },
        }
    }

    /// Encode a ClientHello and begin the handshake in one call. The encoding
    /// itself is `client_hello`'s; the core owns the sequencing and the
    /// transcript, so there is one builder in the tree, not two.
    pub fn startEncoded(
        self: *Client,
        out: []u8,
        random: Random,
        keypairs: KeyPairs,
        host: ?[]const u8,
        alpn: []const []const u8,
        extras: []const extension_type.ExtraExtension,
    ) Error![]const u8 {
        const ch = try client_hello.encodeWithHybridGroupsAndExtensions(
            out,
            random,
            keypairs.x25519.public_key,
            keypairs.p256.public_key,
            if (keypairs.p384) |k| k.public_key else null,
            host,
            alpn,
            &.{},
            null,
            extras,
        );
        try self.start(ch);
        return ch;
    }

    /// Encode a resumption ClientHello: pre_shared_key last, binder computed
    /// over the truncated prefix and patched in place (RFC 8446 §4.2.11.2).
    /// `out` must hold the whole message.
    pub fn startEncodedWithPsk(
        self: *Client,
        out: []u8,
        random: Random,
        keypairs: KeyPairs,
        host: ?[]const u8,
        alpn: []const []const u8,
        psk: []const u8,
        identity: []const u8,
        obfuscated_ticket_age: u32,
    ) Error![]const u8 {
        const suite = self.psk_suite orelse .aes_128_gcm_sha256;
        const result = try client_hello.encodeWithPskAndHybridGroups(
            out,
            random,
            keypairs.x25519.public_key,
            keypairs.p256.public_key,
            if (keypairs.p384) |k| k.public_key else null,
            host,
            alpn,
            &.{},
            null,
            .psk_dhe_ke,
            identity,
            obfuscated_ticket_age,
            switch (suite) {
                .aes_256_gcm_sha384 => 48,
                else => 32,
            },
            false,
            &.{},
        );
        const msg = result.msg;

        // The binder covers the message truncated before the binders vector,
        // computed with the PSK's own suite hash.
        switch (suite) {
            .aes_256_gcm_sha384 => {
                const key = pskBinderKey(hkdf.HkdfSha384, psk);
                var th: hkdf.HkdfSha384.TranscriptHash = undefined;
                backend.sha2.Sha384.hash(msg[0..result.prefix_len], &th.data, .{});
                const binder = binderFor(hkdf.HkdfSha384, key, &th.data);
                @memcpy(msg[result.binder_offset..][0..48], &binder);
            },
            else => {
                const key = pskBinderKey(hkdf.HkdfSha256, psk);
                var th: hkdf.HkdfSha256.TranscriptHash = undefined;
                backend.sha2.Sha256.hash(msg[0..result.prefix_len], &th.data, .{});
                const binder = binderFor(hkdf.HkdfSha256, key, &th.data);
                @memcpy(msg[result.binder_offset..][0..32], &binder);
            },
        }

        try self.start(msg);
        return msg;
    }

    /// Accept a HelloRetryRequest at `.plaintext` and reset the transcript per
    /// RFC 8446 §4.4.1: ClientHello1 collapses to a message_hash message and
    /// the HRR is absorbed after it.
    ///
    /// The caller supplies nothing but the HRR; the selected group comes back
    /// through `helloRetryGroup()` so the caller can build ClientHello2 with the
    /// matching key share.
    pub fn acceptHelloRetryRequest(
        self: *Client,
        provided: level.Level,
        hrr: []const u8,
    ) Error!kex.NamedGroup {
        if (self.state != .wait_server_hello) return error.UnexpectedMessage;
        try level.check(.server_hello, provided);
        const parsed = try server_hello.parseHelloRetryRequest(hrr);
        // ClientHello1 was absorbed while buffering both candidate hashes. The
        // HRR names the suite, so the message_hash uses that suite's hash.
        const buffered = switch (self.suite) {
            .buffering => |b| b,
            inline .sha256, .sha384 => return error.UnexpectedMessage,
        };
        var ch1_hash: [48]u8 = undefined;
        const ch1_len: usize = switch (parsed.cipher_suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => blk: {
                const th = buffered.sha256.peek();
                @memcpy(ch1_hash[0..th.len], &th);
                break :blk th.len;
            },
            .aes_256_gcm_sha384 => blk: {
                const th = buffered.sha384.peek();
                @memcpy(ch1_hash[0..th.len], &th);
                break :blk th.len;
            },
        };

        self.suite = switch (parsed.cipher_suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => .{
                .sha256 = .init(suite_state.Sha256.init(.{}), parsed.cipher_suite),
            },
            .aes_256_gcm_sha384 => .{
                .sha384 = .init(suite_state.Sha384.init(.{}), parsed.cipher_suite),
            },
        };
        resetTranscriptForHrr(&self.suite, ch1_hash[0..ch1_len], hrr);
        self.state = .wait_client_hello2;
        // A HRR without key_share selects no group; the caller then reuses its
        // existing share, which the engine's retry encoder supports by taking
        // the group it is given.
        return parsed.selected_group orelse .x25519;
    }

    /// Encode and queue ClientHello2 with a fresh key share for `group`, absorb
    /// it, and return to `.wait_server_hello`. RFC 8446 §4.1.2.
    pub fn sendClientHello2(
        self: *Client,
        group: kex.NamedGroup,
        random: Random,
        keypairs: KeyPairs,
        out: []u8,
    ) Error![]const u8 {
        if (self.state != .wait_client_hello2) return error.UnexpectedMessage;
        const ch2 = try client_hello.encodeRetryAfterHrr(
            out,
            random,
            keypairs.x25519.public_key,
            keypairs.p256.public_key,
            if (keypairs.p384) |k| k.public_key else null,
            group,
            null,
            null,
            &.{},
        );
        self.suite.update(ch2);
        try self.queue.push(.{ .message = .{ .level = .plaintext, .bytes = ch2 } });
        self.state = .wait_server_hello;
        return ch2;
    }

    /// Produce the client Finished as a bare handshake message, derive the
    /// application traffic secrets from the transcript through the server
    /// Finished, and move both directions to `.application`. RFC 8446 §4.4.4,
    /// §7.1.
    ///
    /// `out` receives the Finished and stays borrowed by the queued output
    /// until the caller drains it.
    pub fn sendClientFinished(self: *Client, out: []u8) Error![]const u8 {
        if (self.state != .server_finished_verified) return error.UnexpectedMessage;
        var pos: usize = 0;

        // RFC 8446 §4.4.2, §4.4.3 - when the server asked for a certificate,
        // the client flight is Certificate, CertificateVerify, Finished. Each
        // message is its own output at `.handshake`, in that order.
        if (self.received_certificate_request) {
            if (self.credentials) |creds| {
                const cert = try creds.chain.encodeWithRequestContext(out[pos..], &.{});
                try self.queue.push(.{ .message = .{
                    .level = .handshake,
                    .bytes = cert,
                } });
                pos += cert.len;
                self.suite.update(cert);

                const cv_th = self.transcriptHash();
                const ctx_len = certificate.client_certificate_verify_context.len;
                var sign_input: [ctx_len + 48]u8 = undefined;
                sign_input[0..ctx_len].* = certificate.client_certificate_verify_context.*;
                @memcpy(sign_input[ctx_len..][0..cv_th.len], cv_th.slice());
                var sig_buf: [512]u8 = undefined;
                const sig = try creds.signer.sign(
                    creds.signer.context,
                    sign_input[0 .. ctx_len + cv_th.len],
                    &sig_buf,
                );
                const cv = try certificate.encodeCertificateVerify(
                    out[pos..],
                    creds.signer.scheme,
                    sig,
                );
                try self.queue.push(.{ .message = .{
                    .level = .handshake,
                    .bytes = cv,
                } });
                pos += cv.len;
                self.suite.update(cv);
            } else {
                // An empty Certificate is what a client without credentials
                // sends, and the server decides whether that is acceptable.
                const empty = try certificate.encodeWithRequestContext(out[pos..], &.{}, &.{});
                try self.queue.push(.{ .message = .{
                    .level = .handshake,
                    .bytes = empty,
                } });
                pos += empty.len;
                self.suite.update(empty);
            }
        }

        const th = self.transcriptHash();
        const msg = switch (self.suite) {
            .buffering => return error.UnexpectedMessage,
            inline .sha256, .sha384 => |*arm| blk: {
                const Hash = @TypeOf(arm.transcript);
                break :blk try finished.encode(
                    Hash,
                    out[pos..],
                    &arm.client_finished_key.data,
                    th.slice(),
                );
            },
        };
        try self.deriveApplicationSecrets(th.slice());
        self.suite.update(msg);
        self.deriveResumptionMaster();

        self.queue.push(.{ .message = .{
            .level = .handshake,
            .bytes = msg,
        } }) catch return error.QueueFull;
        self.queue.push(.{ .read_level = .application }) catch return error.QueueFull;
        self.queue.push(.{ .write_level = .application }) catch return error.QueueFull;
        self.queue.push(.{ .key_available = .application }) catch return error.QueueFull;
        self.queue.push(.done) catch return error.QueueFull;
        self.state = .connected;
        return msg;
    }

    /// RFC 8446 §7.1 - application traffic secrets, over the transcript through
    /// the server Finished.
    fn deriveApplicationSecrets(self: *Client, transcript_hash: []const u8) Error!void {
        switch (self.suite) {
            .buffering => return error.UnexpectedMessage,
            inline .sha256, .sha384 => |*arm| {
                const H = @TypeOf(arm.*).Hkdf;
                var th_bytes: [H.prk_len]u8 = undefined;
                @memcpy(&th_bytes, transcript_hash[0..H.prk_len]);
                const th: H.TranscriptHash = .init(th_bytes);
                var master = H.masterSecret(arm.handshake_secret);
                defer master.secureZero();
                var master_key: H.Keyed = .init(&master.data);
                defer master_key.secureZero();
                arm.client_app_secret = H.deriveSecretKeyed(&master_key, "c ap traffic", &th);
                arm.server_app_secret = H.deriveSecretKeyed(&master_key, "s ap traffic", &th);
            },
        }
    }

    /// RFC 8446 §7.5 - resumption_master_secret over the transcript through the
    /// client Finished. Ticket issuance and PSK derivation both need it.
    fn deriveResumptionMaster(self: *Client) void {
        switch (self.suite) {
            .buffering => {},
            inline .sha256, .sha384 => |*arm| {
                const H = @TypeOf(arm.*).Hkdf;
                const res_th: H.TranscriptHash = .init(arm.transcript.peek());
                var master = H.masterSecret(arm.handshake_secret);
                defer master.secureZero();
                var master_key: H.Keyed = .init(&master.data);
                defer master_key.secureZero();
                arm.resumption_master = H.deriveSecretKeyed(&master_key, "res master", &res_th);
                arm.resumption_master_valid = true;
            },
        }
    }

    /// The resumption master secret, once the client Finished has gone out.
    pub fn resumptionMaster(self: *const Client) ?[48]u8 {
        return switch (self.suite) {
            .buffering => null,
            inline .sha256, .sha384 => |*arm| blk: {
                if (!arm.resumption_master_valid) break :blk null;
                var out: [48]u8 = @splat(0);
                const len = @TypeOf(arm.*).Hkdf.prk_len;
                @memcpy(out[0..len], arm.resumption_master.data[0..len]);
                break :blk out;
            },
        };
    }

    /// RFC 8446 §4.6.1 - derive a PSK from the resumption master and a ticket
    /// nonce. The nonce is the ticket's, from the server's NewSessionTicket.
    pub fn resumptionPsk(self: *const Client, nonce: []const u8, out: []u8) Error!void {
        switch (self.suite) {
            .buffering => return error.UnexpectedMessage,
            inline .sha256, .sha384 => |*arm| {
                if (!arm.resumption_master_valid) return error.UnexpectedMessage;
                const H = @TypeOf(arm.*).Hkdf;
                // HKDF-Expand-Label(resumption_master_secret, "resumption",
                // nonce, Hash.length); the nonce is the label context, not a
                // length-prefixed hash, so expand it directly.
                var key: H.Keyed = .init(&arm.resumption_master.data);
                defer key.secureZero();
                H.expandLabelKeyed(out, "resumption", nonce, &key);
            },
        }
    }

    /// RFC 8446 §4.6.3 - send a KeyUpdate at `.application`, ratchet the write
    /// secret, and tell the caller to re-derive its write key. The message and
    /// the key change travel as separate outputs so the caller cannot apply one
    /// without the other.
    pub fn sendKeyUpdate(
        self: *Client,
        request: handshake.KeyUpdateRequest,
        out: []u8,
    ) Error![]const u8 {
        if (self.state != .connected) return error.UnexpectedMessage;
        out[0] = @intFromEnum(handshake.Type.key_update);
        out[1] = 0;
        out[2] = 0;
        out[3] = 1;
        out[4] = @intFromEnum(request);
        const msg = out[0..5];
        try self.queue.push(.{ .message = .{ .level = .application, .bytes = msg } });
        // The ratchet is the point; the layer it hands back is the adapter's
        // business, so it is released here rather than leaked.
        var discard_tx = try self.suite.ratchetClientKey();
        discard_tx.deinit();
        try self.queue.push(.{ .key_available = .application });
        try self.queue.push(.{ .write_level = .application });
        return msg;
    }

    /// Process one post-handshake message at `.application`: KeyUpdate, an
    /// alert, or a NewSessionTicket.
    ///
    /// KeyUpdate ratchets the read secret *before* returning, so the caller's
    /// next message is decrypted with the new key, and consecutive updates are
    /// capped at `handshake.max_post_handshake_messages` (RFC 8446 §4.6.3).
    pub fn provideApplication(
        self: *Client,
        provided: level.Level,
        msg: []const u8,
    ) Error!void {
        if (self.state != .connected) return error.UnexpectedMessage;
        if (msg.len < 4) return error.UnexpectedEof;
        const msg_type: handshake.Type = @enumFromInt(msg[0]);
        try level.check(msg_type, provided);

        switch (msg_type) {
            .key_update => {
                const request = try handshake.parseKeyUpdate(msg);
                self.post_handshake_count +|= 1;
                if (self.post_handshake_count > handshake.max_post_handshake_messages)
                    return error.TooManyKeyUpdates;
                // Ratchet first: the next message must use the new key.
                var discard_rx = try self.suite.ratchetServerKey();
                discard_rx.deinit();
                try self.queue.push(.{ .key_available = .application });
                try self.queue.push(.{ .read_level = .application });
                if (request == .update_requested) {
                    self.ku_response = .{
                        @intFromEnum(handshake.Type.key_update),
                        0,
                        0,
                        1,
                        @intFromEnum(handshake.KeyUpdateRequest.update_not_requested),
                    };
                    try self.queue.push(.{ .message = .{
                        .level = .application,
                        .bytes = &self.ku_response,
                    } });
                }
            },
            .new_session_ticket => {
                self.ticket = try NewSessionTicket.parse(msg);
            },
            else => return error.UnexpectedMessage,
        }
    }

    /// A peer alert, whose body is the two alert bytes (level, description).
    /// Alerts are not handshake messages and carry no handshake header, so they
    /// have their own entry point. The core reports the description and level;
    /// it never frames a record.
    pub fn provideAlert(self: *Client, level_: level.Level, body: []const u8) Error!void {
        if (self.state != .connected) return error.UnexpectedMessage;
        if (level_ == .plaintext) return error.WrongLevel;
        const parsed = try alert.parse(body);
        self.last_alert = parsed;
        try self.queue.push(.{ .alert = .{
            .level = parsed.level,
            .description = parsed.description,
        } });
    }

    /// The last alert the peer sent, if any.
    pub fn lastAlert(self: *const Client) ?alert.Alert {
        return self.last_alert;
    }

    /// The most recent NewSessionTicket, borrowed from the message that carried
    /// it. Valid until the caller's buffer is reused.
    pub fn lastTicket(self: *const Client) ?NewSessionTicket {
        return self.ticket;
    }

    /// The application traffic secrets, once the client Finished has been sent.
    pub fn applicationSecrets(self: *const Client) ?HandshakeSecrets {
        return switch (self.suite) {
            .buffering => null,
            inline .sha256, .sha384 => |*arm| blk: {
                var secrets: HandshakeSecrets = .{
                    .len = @TypeOf(arm.*).Hkdf.prk_len,
                    .client = @splat(0),
                    .server = @splat(0),
                };
                @memcpy(secrets.client[0..secrets.len], arm.client_app_secret.data[0..secrets.len]);
                @memcpy(secrets.server[0..secrets.len], arm.server_app_secret.data[0..secrets.len]);
                break :blk secrets;
            },
        };
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
    /// Policy for a client certificate. Null means the server never asks for
    /// one, so a client Certificate is unexpected.
    client_policy: ?certificate.Policy,
    /// The client leaf public key, retained between its Certificate and
    /// CertificateVerify.
    client_pub_key: [1024]u8,
    client_pub_key_len: u8,
    /// Transcript hash of ClientHello1, needed for the HRR message_hash.
    ch1_hash: Client.TranscriptHash,
    hrr_sent: bool,

    pub fn init(slots: []level.Output) Server {
        return .{
            .suite = .init(),
            .queue = .init(slots),
            .state = .wait_client_hello,
            .client_policy = null,
            .client_pub_key = undefined,
            .client_pub_key_len = 0,
            .ch1_hash = .init(),
            .hrr_sent = false,
        };
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
        try self.provideClientHello(provided, client_hello_msg, cipher_suite);
        try self.provideServerHello(.plaintext, server_hello_msg, dhe);
    }

    /// Absorb a ClientHello at `.plaintext`. A server picks the suite, so the
    /// arm exists before the transcript starts and the message is absorbed
    /// once, with no buffering arm.
    pub fn provideClientHello(
        self: *Server,
        provided: level.Level,
        client_hello_msg: []const u8,
        cipher_suite: CipherSuite,
    ) Error!void {
        if (self.state != .wait_client_hello) return error.UnexpectedMessage;
        try level.check(.client_hello, provided);
        self.suite = switch (cipher_suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => .{
                .sha256 = .init(suite_state.Sha256.init(.{}), cipher_suite),
            },
            .aes_256_gcm_sha384 => .{
                .sha384 = .init(suite_state.Sha384.init(.{}), cipher_suite),
            },
        };
        self.suite.update(client_hello_msg);
        self.ch1_hash = self.transcriptHash();
        self.state = .ch_absorbed;
    }

    /// Emit a HelloRetryRequest at `.plaintext` for `selected_group`, replacing
    /// ClientHello1 in the transcript with the RFC 8446 §4.4.1 message_hash.
    pub fn sendHelloRetryRequest(
        self: *Server,
        selected_group: kex.NamedGroup,
        out: []u8,
    ) Error![]const u8 {
        if (self.state != .ch_absorbed) return error.UnexpectedMessage;
        const suite: CipherSuite = switch (self.suite) {
            .buffering => return error.UnexpectedMessage,
            inline .sha256, .sha384 => |*arm| arm.aead,
        };
        const hrr = try server_hello.encodeHelloRetryRequest(
            out,
            &.{},
            suite,
            selected_group,
        );
        resetTranscriptForHrr(&self.suite, self.ch1_hash.slice(), hrr);
        try self.queue.push(.{ .message = .{ .level = .plaintext, .bytes = hrr } });
        self.hrr_sent = true;
        return hrr;
    }

    /// Absorb the ServerHello that answers ClientHello2 (or ClientHello1 when
    /// no HRR was sent), then run the key schedule.
    pub fn provideServerHello(
        self: *Server,
        provided: level.Level,
        server_hello_msg: []const u8,
        dhe: []const u8,
    ) Error!void {
        if (self.state != .ch_absorbed) return error.UnexpectedMessage;
        try level.check(.server_hello, provided);
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

    /// Ask the client for a certificate under this policy. Call before
    /// `sendFlight`.
    pub fn requireClientCertificate(self: *Server, policy: certificate.Policy) void {
        self.client_policy = policy;
    }

    /// Feed one message of the client's flight at `.handshake`: Certificate,
    /// CertificateVerify, and Finished, when a client certificate was
    /// requested. Verification happens here, with the caller's policy, for the
    /// same reason the client does it: the ordering is the state machine.
    pub fn provideClientFlight(
        self: *Server,
        provided: level.Level,
        msg: []const u8,
    ) Error!void {
        if (msg.len < 4) return error.UnexpectedEof;
        const msg_type: handshake.Type = @enumFromInt(msg[0]);
        try level.check(msg_type, provided);

        switch (self.state) {
            .flight_sent => {
                self.state = if (self.client_policy != null)
                    .wait_client_certificate
                else
                    .wait_client_finished;
                return self.provideClientFlight(provided, msg);
            },
            .wait_client_certificate => {
                if (msg_type != .certificate) return error.UnexpectedMessage;
                const policy = self.client_policy orelse return error.UnexpectedMessage;
                _ = policy;
                const cert_der = try certificate.parseClientCertificate(msg, &.{});
                switch (cert_der) {
                    .empty => return error.ClientCertificateRequired,
                    .present => |leaf_der| {
                        // The signature check needs the leaf public key, which
                        // the client chain parse extracts.
                        const verified = try certificate.parseClientChain(
                            msg,
                            &.{},
                            self.client_policy.?,
                        );
                        @memcpy(self.client_pub_key[0..verified.pub_key.len], verified.pub_key);
                        self.client_pub_key_len = @intCast(verified.pub_key.len);
                        _ = leaf_der;
                    },
                }
                self.suite.update(msg);
                self.state = .wait_client_verify;
            },
            .wait_client_verify => {
                if (msg_type != .certificate_verify) return error.UnexpectedMessage;
                const th = self.transcriptHash();
                try certificate.verifyClientSignatureWithSchemes(
                    msg,
                    self.client_pub_key[0..self.client_pub_key_len],
                    th.slice(),
                    backend.capabilities.certificate_verify_schemes,
                );
                self.suite.update(msg);
                self.state = .wait_client_finished;
            },
            .wait_client_finished, .connected => {
                if (msg_type != .finished) return error.UnexpectedMessage;
                const th = self.transcriptHash();
                switch (self.suite) {
                    .buffering => return error.UnexpectedMessage,
                    inline .sha256, .sha384 => |*arm| {
                        const Hash = @TypeOf(arm.transcript);
                        try finished.verify(
                            Hash,
                            msg,
                            &arm.client_finished_key.data,
                            th.slice(),
                        );
                    },
                }
                self.suite.update(msg);
                self.state = .connected;
            },
            .wait_client_hello,
            .ch_absorbed,
            .server_hello_queued,
            => return error.UnexpectedMessage,
        }
    }

    pub fn handshakeSecrets(self: *const Server) ?HandshakeSecrets {
        return copyHandshakeSecrets(&self.suite);
    }

    /// Compose the authenticated server flight as four bare messages at
    /// `.handshake`: EncryptedExtensions, Certificate, CertificateVerify, and
    /// Finished. One `message` output per message, in wire order, because a
    /// caller framing these itself (QUIC CRYPTO, or a record adapter) must see
    /// each one and its level rather than a coalesced blob.
    ///
    /// `out` must hold the largest message in the flight; the queued outputs
    /// borrow slices inside it.
    pub fn sendFlight(
        self: *Server,
        creds: Credentials,
        alpn: ?[]const u8,
        out: []u8,
    ) Error!void {
        if (self.state != .server_hello_queued) return error.UnexpectedMessage;

        // Each message gets its own bytes in `out`: the queue borrows, so they
        // cannot share a start offset.
        var pos: usize = 0;
        const ee = try encrypted_extensions.encode(out[pos..], alpn, false);
        try self.queue.push(.{ .message = .{ .level = .handshake, .bytes = ee } });
        pos += ee.len;
        self.suite.update(ee);

        // RFC 8446 §4.3.2 - a CertificateRequest sits between
        // EncryptedExtensions and Certificate, and is part of the transcript.
        if (self.client_policy != null) {
            const cr = try certificate_request.encode(
                out[pos..],
                backend.capabilities.certificate_verify_schemes,
            );
            try self.queue.push(.{ .message = .{ .level = .handshake, .bytes = cr } });
            pos += cr.len;
            self.suite.update(cr);
        }

        const cert = try creds.chain.encode(out[pos..]);
        try self.queue.push(.{ .message = .{ .level = .handshake, .bytes = cert } });
        pos += cert.len;
        self.suite.update(cert);

        // RFC 8446 §4.4.3 - the signature covers the server context and the
        // transcript through Certificate, snapshotted before CV is absorbed.
        const th = self.transcriptHash();
        const ctx_len = certificate.server_certificate_verify_context.len;
        var sign_input: [ctx_len + 48]u8 = undefined;
        sign_input[0..ctx_len].* = certificate.server_certificate_verify_context.*;
        @memcpy(sign_input[ctx_len..][0..th.len], th.slice());
        var sig_buf: [512]u8 = undefined;
        const sig = try creds.signer.sign(
            creds.signer.context,
            sign_input[0 .. ctx_len + th.len],
            &sig_buf,
        );
        const cv = try certificate.encodeCertificateVerify(out[pos..], creds.signer.scheme, sig);
        try self.queue.push(.{ .message = .{ .level = .handshake, .bytes = cv } });
        pos += cv.len;
        self.suite.update(cv);

        const fin_th = self.transcriptHash();
        const fin = switch (self.suite) {
            .buffering => return error.UnexpectedMessage,
            inline .sha256, .sha384 => |*arm| blk: {
                const Hash = @TypeOf(arm.transcript);
                break :blk try finished.encode(
                    Hash,
                    out[pos..],
                    &arm.server_finished_key.data,
                    fin_th.slice(),
                );
            },
        };
        try self.queue.push(.{ .message = .{ .level = .handshake, .bytes = fin } });
        self.suite.update(fin);
        self.state = .flight_sent;
    }

    pub const State = enum {
        wait_client_hello,
        ch_absorbed,
        server_hello_queued,
        flight_sent,
        wait_client_certificate,
        wait_client_verify,
        wait_client_finished,
        connected,
    };

    pub const TranscriptHash = Client.TranscriptHash;

    fn transcriptHash(self: *const Server) TranscriptHash {
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

// The replay gate from §5.2.1: RFC 8448 §3's complete trace through
// `provide`/`next`, no engine in the path. Every recorded value is asserted:
// the flight verifies in order, the client Finished is the recorded one, the
// application secrets are the recorded ones, and the levels move to
// `.application` before `done`.
test "core client: RFC 8448 §3 full replay closes the gate" {
    const rfc8448_client_finished = [_]u8{
        0x14, 0x00, 0x00, 0x20, 0xa8, 0xec, 0x43, 0x6d,
        0x67, 0x76, 0x34, 0xae, 0x52, 0x5a, 0xc1, 0xfc,
        0xeb, 0xe1, 0x1a, 0x03, 0x9e, 0xc1, 0x76, 0x94,
        0xfa, 0xc6, 0xe9, 0x85, 0x27, 0xb6, 0x42, 0xf2,
        0xed, 0xd5, 0xce, 0x61,
    };
    const rfc8448_client_ap_secret = [_]u8{
        0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d,
        0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce, 0x65, 0x52,
        0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87,
        0xf7, 0x92, 0xeb, 0xb7, 0xc1, 0x75, 0x04, 0xa5,
    };
    const rfc8448_server_ap_secret = [_]u8{
        0xa1, 0x1a, 0xf9, 0xf0, 0x55, 0x31, 0xf8, 0x56,
        0xad, 0x47, 0x11, 0x6b, 0x45, 0xa9, 0x50, 0x32,
        0x82, 0x04, 0xb4, 0xf4, 0x4b, 0xfb, 0x6b, 0x3a,
        0x4b, 0x4f, 0x1f, 0x3f, 0xcb, 0x63, 0x16, 0x43,
    };

    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;

    var slots: [16]level.Output = undefined;
    var client: Client = .init(&slots, policy);
    defer client.deinit();
    client.offered.insert(.server_name);
    client.offered.insert(.record_size_limit);

    try client.start(&rfc8448_client_hello);
    try testing.expectEqual(level.Level.plaintext, client.next().?.message.level);

    try client.provide(.plaintext, &rfc8448_server_hello, &dhe_rfc8448);
    try testing.expectEqual(level.Level.handshake, client.next().?.read_level);
    try testing.expectEqual(level.Level.handshake, client.next().?.write_level);
    try testing.expectEqual(level.Level.handshake, client.next().?.key_available);

    var flight_buf: [4096]u8 = undefined;
    const flight = fixtures.rfc8448.b64("server_flight.b64");
    @memcpy(flight_buf[0..flight.len], flight);
    var reader: handshake.Reader = .init(flight_buf[0..flight.len]);
    while (try reader.next()) |msg| try client.provideHandshake(.handshake, msg.raw);

    var out: [128]u8 = undefined;
    const fin = try client.sendClientFinished(&out);
    try testing.expectEqualSlices(u8, &rfc8448_client_finished, fin);

    // Outputs in order, then the queue empties.
    const fin_out = client.next().?;
    try testing.expectEqual(level.Level.handshake, fin_out.message.level);
    try testing.expectEqualSlices(u8, &rfc8448_client_finished, fin_out.message.bytes);
    try testing.expectEqual(level.Level.application, client.next().?.read_level);
    try testing.expectEqual(level.Level.application, client.next().?.write_level);
    try testing.expectEqual(level.Level.application, client.next().?.key_available);
    try testing.expectEqual(level.Output.done, client.next().?);
    try testing.expectEqual(@as(?level.Output, null), client.next());

    const app = client.applicationSecrets().?;
    try testing.expectEqualSlices(u8, &rfc8448_client_ap_secret, app.client[0..32]);
    try testing.expectEqualSlices(u8, &rfc8448_server_ap_secret, app.server[0..32]);
}

// The core talking to itself: no engine, both roles, a real certificate and a
// real signature. The client accepts the flight the server composed, which is
// the milestone the adapter phase depends on.
test "core: client and server complete a handshake with each other" {
    const server_hello_mod = server_hello;
    const ecdsa_cert = fixtures.server_ecdsa_cert_der;
    const ecdsa_scalar = fixtures.server_ecdsa_scalar;

    var key = try signature.PrivateKey.fromP256Scalar(ecdsa_scalar[0..32]);
    defer key.deinit();
    const signer = key.signer();

    const server_share_keypair: x25519.KeyPair = try .generateDeterministic(.init(@splat(0x61)));
    const key_share: server_hello_mod.KeyShare = .{ .x25519 = server_share_keypair.public_key };

    var sh_buf: [256]u8 = undefined;
    const sh = try server_hello_mod.encodeWithKeyShare(
        &sh_buf,
        @splat(0x62),
        &.{},
        .aes_128_gcm_sha256,
        &key_share,
    );

    const dhe = [_]u8{0x5a} ** 32;

    var server_slots: [16]level.Output = undefined;
    var server: Server = .init(&server_slots);
    defer server.deinit();
    try server.provide(
        .plaintext,
        &rfc8448_client_hello,
        .aes_128_gcm_sha256,
        sh,
        &dhe,
    );

    // Drain the ServerHello and its level events; the flight is next.
    while (server.next()) |_| {}

    var flight_buf: [2048]u8 = undefined;
    try server.sendFlight(
        .{ .chain = .{ .single = &ecdsa_cert }, .signer = signer },
        null,
        &flight_buf,
    );

    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;
    var client_slots: [16]level.Output = undefined;
    var client: Client = .init(&client_slots, policy);
    defer client.deinit();
    try client.start(&rfc8448_client_hello);
    _ = client.next().?;
    try client.provide(.plaintext, sh, &dhe);

    // Drain the server's queued flight and hand each message to the client.
    var flight_messages: usize = 0;
    while (server.next()) |out| switch (out) {
        .message => |m| {
            try testing.expectEqual(level.Level.handshake, m.level);
            try client.provideHandshake(.handshake, m.bytes);
            flight_messages += 1;
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 4), flight_messages);
    try testing.expectEqual(Client.State.server_finished_verified, client.state);

    var fin_buf: [128]u8 = undefined;
    const fin = try client.sendClientFinished(&fin_buf);
    try testing.expectEqual(@as(u8, @intFromEnum(handshake.Type.finished)), fin[0]);
}

// Mutual authentication, core to core: the server asks for a certificate, the
// client signs the CertificateVerify, and the server checks both against the
// policy it was given. No engine in the path.
test "core: client authentication completes both ways" {
    const server_hello_mod = server_hello;
    var server_key = try signature.PrivateKey.fromP256Scalar(fixtures.server_ecdsa_scalar[0..32]);
    defer server_key.deinit();
    var client_key = try signature.PrivateKey.fromP256Scalar(fixtures.client_ecdsa_scalar[0..32]);
    defer client_key.deinit();

    const share: x25519.KeyPair = try .generateDeterministic(.init(@splat(0x71)));
    const key_share: server_hello_mod.KeyShare = .{ .x25519 = share.public_key };
    var sh_buf: [256]u8 = undefined;
    const sh = try server_hello_mod.encodeWithKeyShare(
        &sh_buf,
        @splat(0x72),
        &.{},
        .aes_128_gcm_sha256,
        &key_share,
    );
    const dhe = [_]u8{0x6b} ** 32;

    var server_policy: certificate.Policy = .init;
    server_policy.now_sec = 0;
    server_policy.insecure_no_chain_anchor = true;
    // A client certificate must be a client certificate (RFC 5280 EKU).
    server_policy.leaf_usage = .client_auth;

    var server_slots: [16]level.Output = undefined;
    var server: Server = .init(&server_slots);
    defer server.deinit();
    server.requireClientCertificate(server_policy);
    try server.provide(.plaintext, &rfc8448_client_hello, .aes_128_gcm_sha256, sh, &dhe);

    // Drain the ServerHello and its level events; the flight is next.
    while (server.next()) |_| {}

    var flight_buf: [2048]u8 = undefined;
    try server.sendFlight(
        .{ .chain = .{ .single = &fixtures.server_ecdsa_cert_der }, .signer = server_key.signer() },
        null,
        &flight_buf,
    );

    var client_policy: certificate.Policy = .init;
    client_policy.now_sec = 0;
    client_policy.insecure_no_chain_anchor = true;
    var client_slots: [16]level.Output = undefined;
    var client: Client = .init(&client_slots, client_policy);
    defer client.deinit();
    client.credentials = .{
        .chain = .{ .single = &fixtures.client_ecdsa_cert_der },
        .signer = client_key.signer(),
    };
    try client.start(&rfc8448_client_hello);
    _ = client.next().?;
    try client.provide(.plaintext, sh, &dhe);

    // The server's flight, with a CertificateRequest in its legal position:
    // after EncryptedExtensions and before Certificate (RFC 8446 §4.3.2).
    var flight: [8][]const u8 = undefined;
    var flight_len: usize = 0;
    while (server.next()) |out| switch (out) {
        .message => |m| {
            flight[flight_len] = m.bytes;
            flight_len += 1;
        },
        else => {},
    };
    for (flight[0..flight_len]) |m| try client.provideHandshake(.handshake, m);
    try testing.expectEqual(Client.State.server_finished_verified, client.state);

    var fin_buf: [1024]u8 = undefined;
    _ = try client.sendClientFinished(&fin_buf);

    // Drain the client's queued flight and hand it to the server in order.
    var count: usize = 0;
    while (client.next()) |out| switch (out) {
        .message => |m| {
            try server.provideClientFlight(.handshake, m.bytes);
            count += 1;
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqual(Server.State.connected, server.state);
}

// RFC 8448 §4, the resumption secret: after the client Finished, the core's
// resumption master must produce the PSK the trace records for nonce 0x0000.
test "core client: resumption_master_secret and PSK match RFC 8448 §4" {
    const rfc8448_resumption_master = [_]u8{
        0x7d, 0xf2, 0x35, 0xf2, 0x03, 0x1d, 0x2a, 0x05,
        0x12, 0x87, 0xd0, 0x2b, 0x02, 0x41, 0xb0, 0xbf,
        0xda, 0xf8, 0x6c, 0xc8, 0x56, 0x23, 0x1f, 0x2d,
        0x5a, 0xba, 0x46, 0xc4, 0x34, 0xec, 0x19, 0x6c,
    };
    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;
    var slots: [16]level.Output = undefined;
    var client: Client = .init(&slots, policy);
    defer client.deinit();
    client.offered.insert(.server_name);
    client.offered.insert(.record_size_limit);

    try client.start(&rfc8448_client_hello);
    _ = client.next().?;
    try client.provide(.plaintext, &rfc8448_server_hello, &dhe_rfc8448);

    var flight_buf: [4096]u8 = undefined;
    const flight = fixtures.rfc8448.b64("server_flight.b64");
    @memcpy(flight_buf[0..flight.len], flight);
    var reader: handshake.Reader = .init(flight_buf[0..flight.len]);
    while (try reader.next()) |msg| try client.provideHandshake(.handshake, msg.raw);

    var out: [128]u8 = undefined;
    _ = try client.sendClientFinished(&out);

    const master = client.resumptionMaster().?;
    try testing.expectEqualSlices(u8, &rfc8448_resumption_master, master[0..32]);

    var psk: [32]u8 = undefined;
    try client.resumptionPsk(&.{ 0x00, 0x00 }, &psk);
    try testing.expectEqualSlices(u8, &rfc8448_resumption_psk, &psk);
}

// RFC 8448 §4, the PSK binder. Same construction as Finished (RFC 8446
// §4.2.11.2): early secret -> "res binder" -> "finished" -> HMAC over the
// binder hash.
pub fn pskBinderKey(comptime Hkdf: type, psk: []const u8) [Hkdf.prk_len]u8 {
    const early = Hkdf.pskEarlySecret(psk);
    const binder_key = Hkdf.resumptionBinderKey(early);
    return binder_key.data;
}

pub fn binderFor(
    comptime Hkdf: type,
    binder_key: [Hkdf.prk_len]u8,
    binder_hash: []const u8,
) [Hkdf.prk_len]u8 {
    const finished_key = Hkdf.finishedKey(.{ .data = binder_key });
    var th: Hkdf.TranscriptHash = undefined;
    @memcpy(&th.data, binder_hash[0..Hkdf.prk_len]);
    return Hkdf.binder(finished_key, &th);
}

test "psk binder: RFC 8448 §4 binder key and value" {
    const H = hkdf.HkdfSha256;

    const rfc8448_binder_key = [_]u8{
        0x69, 0xfe, 0x13, 0x1a, 0x3b, 0xba, 0xd5, 0xd6,
        0x3c, 0x64, 0xee, 0xbc, 0xc3, 0x0e, 0x39, 0x5b,
        0x9d, 0x81, 0x07, 0x72, 0x6a, 0x13, 0xd0, 0x74,
        0xe3, 0x89, 0xdb, 0xc8, 0xa4, 0xe4, 0x72, 0x56,
    };
    const rfc8448_binder_hash = [_]u8{
        0x63, 0x22, 0x4b, 0x2e, 0x45, 0x73, 0xf2, 0xd3,
        0x45, 0x4c, 0xa8, 0x4b, 0x9d, 0x00, 0x9a, 0x04,
        0xf6, 0xbe, 0x9e, 0x05, 0x71, 0x1a, 0x83, 0x96,
        0x47, 0x3a, 0xef, 0xa0, 0x1e, 0x92, 0x4a, 0x14,
    };
    const rfc8448_binder = [_]u8{
        0x3a, 0xdd, 0x4f, 0xb2, 0xd8, 0xfd, 0xf8, 0x22,
        0xa0, 0xca, 0x3c, 0xf7, 0x67, 0x8e, 0xf5, 0xe8,
        0x8d, 0xae, 0x99, 0x01, 0x41, 0xc5, 0x92, 0x4d,
        0x57, 0xbb, 0x6f, 0xa3, 0x1b, 0x9e, 0x5f, 0x9d,
    };

    const key = pskBinderKey(H, &rfc8448_resumption_psk);
    try testing.expectEqualSlices(u8, &rfc8448_binder_key, &key);

    const binder = binderFor(H, key, &rfc8448_binder_hash);
    try testing.expectEqualSlices(u8, &rfc8448_binder, &binder);
}

/// How the core asks for a ticket's PSK. The storage is the caller's; the core
/// only knows how to ask and how to check what comes back.
pub const PskLookup = struct {
    context: *anyopaque,
    lookup: *const fn (context: *anyopaque, identity: []const u8) ?[]const u8,
};

pub const PskSelection = struct {
    /// Index into the ClientHello's identity list, which is what the server
    /// echoes in ServerHello.selected_identity.
    index: u16,
    psk: []const u8,
};

/// RFC 8446 §4.2.11.2 - pick a PSK from a ClientHello's pre_shared_key offer
/// and verify its binder.
///
/// The binder covers the ClientHello truncated before the binders vector, and
/// each binder must be checked against the identity at the same index. Checking
/// identity 0 against identity 1's prefix would accept a forgery, so the
/// iterator advances both lists together and the index is what the caller gets
/// back.
///
/// Returns null when the ClientHello offers no PSK or no identity resolves.
pub fn selectPsk(
    comptime Hkdf: type,
    comptime Hash: type,
    client_hello_msg: []const u8,
    lookup: PskLookup,
) error{ InvalidExtensionLength, InvalidVectorLength, UnexpectedEof }!?PskSelection {
    const psk_type: u16 = 0x0029;
    const ext_offset = client_hello.extensionOffset(client_hello_msg, psk_type) orelse return null;
    const ext_data = client_hello.extension(client_hello_msg, psk_type) orelse return null;

    // Prefix: the ClientHello up to and including the identities vector, i.e.
    // everything before the binders' 2-byte length field.
    const identities_len = std.mem.readInt(u16, ext_data[0..2], .big);
    const binders_offset = ext_offset + 4 + 2 + @as(usize, identities_len);
    if (binders_offset + 2 > client_hello_msg.len) return error.InvalidExtensionLength;
    const prefix = client_hello_msg[0..binders_offset];

    var offers: client_hello.PskOfferIter = try .init(ext_data);
    var index: u16 = 0;
    while (try offers.next()) |offer| {
        defer index += 1;
        const psk = lookup.lookup(lookup.context, offer.identity) orelse continue;
        var binder_key: [Hkdf.prk_len]u8 = undefined;
        @memcpy(&binder_key, &pskBinderKey(Hkdf, psk));
        defer @memset(&binder_key, 0);
        var th: Hkdf.TranscriptHash = undefined;
        Hash.hash(prefix, &th.data, .{});
        const expected = binderFor(Hkdf, binder_key, &th.data);
        if (std.crypto.timing_safe.eql([Hkdf.prk_len]u8, expected, blk: {
            var got: [Hkdf.prk_len]u8 = undefined;
            @memcpy(&got, offer.binder[0..Hkdf.prk_len]);
            break :blk got;
        })) {
            return .{ .index = index, .psk = psk };
        }
    }
    return null;
}

// RFC 8448 §4's recorded ClientHello, offered for resumption. The binder is
// verified against the trace, so the parse path is proven without any encoder.
const psk_ch_hex =
    "010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d787648" ++
    "7d95000006130113031302010001cd0000000b0009000006736572766572ff0100010000" ++
    "0a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb6" ++
    "8ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b00" ++
    "03020304000d0020001e0403050306030203080408050806040105010601020104020502" ++
    "06020202002d00020101001c000240010015005700000000000000000000000000000000" ++
    "000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "2900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa" ++
    "90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143ef" ++
    "d3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4" ++
    "dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf2" ++
    "97b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093" ++
    "934ae4d357fad6aacb0021203add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d" ++
    "57bb6fa31b9e5f9d";

test "psk: the recorded resumption offer resolves and verifies" {
    const H = hkdf.HkdfSha256;
    var buf: [1024]u8 = undefined;
    const ch = try std.fmt.hexToBytes(&buf, psk_ch_hex);

    const Lookup = struct {
        fn get(ctx: *anyopaque, identity: []const u8) ?[]const u8 {
            _ = ctx;
            if (identity.len == 0) return null;
            return rfc8448_resumption_psk[0..];
        }
    };

    const selected = try selectPsk(H, backend.sha2.Sha256, ch, .{
        .context = undefined,
        .lookup = Lookup.get,
    });
    try testing.expect(selected != null);
    try testing.expectEqual(@as(u16, 0), selected.?.index);
    try testing.expectEqualSlices(u8, &rfc8448_resumption_psk, selected.?.psk);
}

// A binder that does not match the prefix must not select, even when the
// identity resolves. This is the forgery the index-matching rule prevents.
test "psk: a tampered binder is refused" {
    const H = hkdf.HkdfSha256;
    var buf: [1024]u8 = undefined;
    const ch = try std.fmt.hexToBytes(&buf, psk_ch_hex);
    ch[ch.len - 1] ^= 0x01;

    const Lookup = struct {
        fn get(ctx: *anyopaque, identity: []const u8) ?[]const u8 {
            _ = ctx;
            if (identity.len == 0) return null;
            return rfc8448_resumption_psk[0..];
        }
    };

    const selected = try selectPsk(H, backend.sha2.Sha256, ch, .{
        .context = undefined,
        .lookup = Lookup.get,
    });
    try testing.expect(selected == null);
}

const rfc8448_resumption_psk = [_]u8{
    0x4e, 0xcd, 0x0e, 0xb6, 0xec, 0x3b, 0x4d, 0x87,
    0xf5, 0xd6, 0x02, 0x8f, 0x92, 0x2c, 0xa4, 0xc5,
    0x85, 0x1a, 0x27, 0x7f, 0xd4, 0x13, 0x11, 0xc9,
    0xe6, 0x2d, 0x2c, 0x94, 0x92, 0xe1, 0xc4, 0xf3,
};

// HelloRetryRequest, core to core: the server emits it, the client resets the
// transcript to message_hash(ClientHello1) || HRR, emits ClientHello2, and both
// sides must then agree on the transcript before any key exchange happens.
test "hrr: both roles reset the transcript to message_hash(ClientHello1) || HRR" {
    var client_keypairs: KeyPairs = try .init(try .generateDeterministic(.init(@splat(0x81))));
    client_keypairs.p256 = try .generateDeterministic(.init(@splat(0x82)));

    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;

    var client_slots: [16]level.Output = undefined;
    var client: Client = .init(&client_slots, policy);
    defer client.deinit();

    var ch1_buf: [1024]u8 = undefined;
    const ch1 = try client_hello.encodeWithHybridGroupsAndExtensions(
        &ch1_buf,
        .zero,
        client_keypairs.x25519.public_key,
        client_keypairs.p256.public_key,
        null,
        null,
        &.{},
        &.{},
        null,
        &.{},
    );
    try client.start(ch1);
    _ = client.next().?;

    var server_slots: [16]level.Output = undefined;
    var server: Server = .init(&server_slots);
    defer server.deinit();
    try server.provideClientHello(.plaintext, ch1, .aes_128_gcm_sha256);

    var hrr_buf: [256]u8 = undefined;
    const hrr = try server.sendHelloRetryRequest(.secp256r1, &hrr_buf);

    const group = try client.acceptHelloRetryRequest(.plaintext, hrr);
    try testing.expectEqual(kex.NamedGroup.secp256r1, group);

    // Both roles must now hold the same transcript, before any ClientHello2.
    const client_th = client.transcriptHash();
    const server_th = server.transcriptHash();
    try testing.expectEqual(client_th.len, server_th.len);
    try testing.expectEqualSlices(u8, client_th.slice(), server_th.slice());

    var ch2_buf: [1024]u8 = undefined;
    const ch2 = try client.sendClientHello2(group, .zero, client_keypairs, &ch2_buf);
    try testing.expect(!std.mem.eql(u8, ch1, ch2));
    // ClientHello2 carries the requested group's key share.
}

/// Drive a client core to `.connected` against the RFC 8448 §3 trace, so the
/// post-handshake tests start from a real state rather than a fabricated one.
fn rfc8448ConnectedClient(slots: []level.Output) !Client {
    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;
    var client: Client = .init(slots, policy);
    client.offered.insert(.server_name);
    client.offered.insert(.record_size_limit);
    try client.start(&rfc8448_client_hello);
    _ = client.next().?;
    try client.provide(.plaintext, &rfc8448_server_hello, &dhe_rfc8448);

    var flight_buf: [4096]u8 = undefined;
    const flight = fixtures.rfc8448.b64("server_flight.b64");
    @memcpy(flight_buf[0..flight.len], flight);
    var reader: handshake.Reader = .init(flight_buf[0..flight.len]);
    while (try reader.next()) |msg| try client.provideHandshake(.handshake, msg.raw);

    var out: [128]u8 = undefined;
    _ = try client.sendClientFinished(&out);
    // Drain the handshake outputs so the post-handshake queue starts empty.
    while (client.next()) |_| {}
    return client;
}

// RFC 8446 §4.6.3 - a KeyUpdate ratchets the read secret before the next
// message is decrypted, and the caller learns about it through the queue.
test "key update: the ratchet is queued before the next message is accepted" {
    var slots: [32]level.Output = undefined;
    var client = try rfc8448ConnectedClient(&slots);
    defer client.deinit();

    const update = [_]u8{
        @intFromEnum(handshake.Type.key_update),                       0, 0, 1,
        @intFromEnum(handshake.KeyUpdateRequest.update_not_requested),
    };
    try client.provideApplication(.application, &update);

    const first = client.next().?;
    try testing.expectEqual(level.Level.application, first.key_available);
    const second = client.next().?;
    try testing.expectEqual(level.Level.application, second.read_level);
    try testing.expectEqual(@as(?level.Output, null), client.next());
}

// A peer that asks for a response gets one, at the same level, and the core
// does not exceed the §4.6.3 consecutive-update cap.
test "key update: a requested response is queued, and the flood cap holds" {
    var slots: [64]level.Output = undefined;
    var client = try rfc8448ConnectedClient(&slots);
    defer client.deinit();

    const request = [_]u8{
        @intFromEnum(handshake.Type.key_update),                   0, 0, 1,
        @intFromEnum(handshake.KeyUpdateRequest.update_requested),
    };
    try client.provideApplication(.application, &request);
    _ = client.next().?; // key_available
    _ = client.next().?; // read_level
    const response = client.next().?.message;
    try testing.expectEqual(level.Level.application, response.level);
    try testing.expectEqual(@as(u8, @intFromEnum(handshake.Type.key_update)), response.bytes[0]);
    try testing.expectEqual(
        @as(u8, @intFromEnum(handshake.KeyUpdateRequest.update_not_requested)),
        response.bytes[4],
    );

    // Drive past the cap: the next update past the bound is refused.
    var accepted: usize = 1;
    while (accepted <= handshake.max_post_handshake_messages) : (accepted += 1) {
        client.provideApplication(.application, &request) catch |err| {
            try testing.expectEqual(error.TooManyKeyUpdates, err);
            return;
        };
        while (client.next()) |_| {}
    }
    try testing.expect(false); // the cap never triggered
}

test "alerts: the core reports level and description, never bytes" {
    var slots: [16]level.Output = undefined;
    var client = try rfc8448ConnectedClient(&slots);
    defer client.deinit();

    try client.provideAlert(.application, &.{
        2,
        @intFromEnum(alert.Description.unexpected_message),
    });
    const out = client.next().?;
    try testing.expectEqual(alert.Level.fatal, out.alert.level);
    try testing.expectEqual(alert.Description.unexpected_message, out.alert.description);
    try testing.expectEqual(alert.Description.unexpected_message, client.lastAlert().?.description);
}

const binder_psk = [_]u8{
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

fn binderLookup(ctx: *anyopaque, identity: []const u8) ?[]const u8 {
    _ = ctx;
    if (identity.len != 4) return null;
    return binder_psk[0..];
}

// The core encodes the offer, and the core's own verifier accepts it. That is
// the seam B was pulled for: one builder in the tree, and the binder patched by
// the same code that checks it.
test "psk offer: encoded by the core, accepted by the core's verifier" {
    var keypairs: KeyPairs = try .init(try .generateDeterministic(.init(@splat(0x91))));
    keypairs.p256 = try .generateDeterministic(.init(@splat(0x92)));

    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;
    var slots: [16]level.Output = undefined;
    var client: Client = .init(&slots, policy);
    defer client.deinit();
    client.psk_suite = .aes_128_gcm_sha256;

    var buf: [1024]u8 = undefined;
    const ch = try client.startEncodedWithPsk(
        &buf,
        .zero,
        keypairs,
        null,
        &.{},
        &binder_psk,
        "tkt1",
        0,
    );
    // The offered message parses, and its binder verifies against the PSK.
    const selected = try selectPsk(
        hkdf.HkdfSha256,
        backend.sha2.Sha256,
        ch,
        .{ .context = undefined, .lookup = binderLookup },
    );
    try testing.expect(selected != null);
    try testing.expectEqual(@as(u16, 0), selected.?.index);
    try testing.expectEqualSlices(u8, &binder_psk, selected.?.psk);
}

test "startEncoded: the core encodes what it then absorbs" {
    var keypairs: KeyPairs = try .init(try .generateDeterministic(.init(@splat(0x93))));
    keypairs.p256 = try .generateDeterministic(.init(@splat(0x94)));

    var policy: certificate.Policy = .init;
    policy.now_sec = 0;
    policy.insecure_no_chain_anchor = true;
    var slots: [16]level.Output = undefined;
    var client: Client = .init(&slots, policy);
    defer client.deinit();

    var buf: [1024]u8 = undefined;
    const ch = try client.startEncoded(&buf, .zero, keypairs, null, &.{}, &.{});
    // The ClientHello is the queued output, and it parses as a ClientHello.
    const out = client.next().?;
    try testing.expectEqual(level.Level.plaintext, out.message.level);
    try testing.expectEqualSlices(u8, ch, out.message.bytes);
    _ = try client_hello.parse(ch);
}
