//! Backend-supplied pure ML-KEM primitives used by RFC 10024 hybrid groups.
//!
//! tls owns the hybrid construction: this module only generates ML-KEM keys,
//! validates encapsulation keys, and encapsulates/decapsulates fixed-size
//! ciphertexts. Keeping the combiner above the backend seam makes the TLS wire
//! construction identical for OpenSSL, AWS-LC, BoringSSL, and native.
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const backend = @import("crypto");
const kem_impl = backend.kem;

pub const ParameterSet = @import("crypto").ParameterSet;
pub const Error = error{
    BufferTooShort,
    IdentityElement,
    LibcryptoFailed,
    MalformedKeyShare,
    UnsupportedPrimitive,
};

pub const max_public_key_len = ParameterSet.mlkem1024.publicKeyLen();
pub const max_ciphertext_len = ParameterSet.mlkem1024.ciphertextLen();
pub const max_shared_secret_len = ParameterSet.mlkem1024.sharedSecretLen();

const coefficient_modulus = 3329;
const public_seed_len = 32;

pub const KeyHandle = struct {
    parameter_set: ParameterSet,
    key: kem_impl.KemKey,

    pub fn deinit(self: *KeyHandle) void {
        kem_impl.freeKey(self.key);
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }
};

pub const PeerHandle = struct {
    parameter_set: ParameterSet,
    key: kem_impl.KemPeerKey,

    pub fn deinit(self: *PeerHandle) void {
        kem_impl.freeKey(self.key);
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }
};

pub fn generate(parameter_set: ParameterSet) Error!KeyHandle {
    return .{
        .parameter_set = parameter_set,
        .key = try kem_impl.kemKeygen(parameter_set),
    };
}

pub fn publicKey(key: *const KeyHandle, out: []u8) Error![]u8 {
    const expected = key.parameter_set.publicKeyLen();
    if (out.len < expected) return error.BufferTooShort;
    const public_key = try kem_impl.kemPublic(key.key, out[0..expected]);
    if (public_key.len != expected) return error.LibcryptoFailed;
    return public_key;
}

/// Validate before provider import because providers differ on when they apply
/// the FIPS 203 §7.2 encapsulation-key check.
pub fn loadPeerPublic(
    parameter_set: ParameterSet,
    public_key: []const u8,
    out: *PeerHandle,
) Error!void {
    if (public_key.len != parameter_set.publicKeyLen())
        return error.MalformedKeyShare;
    if (!encapsulationKeyIsCanonical(parameter_set, public_key))
        return error.IdentityElement;
    out.* = .{ .parameter_set = parameter_set, .key = undefined };
    try kem_impl.kemLoadPublic(parameter_set, public_key, &out.key);
}

fn encapsulationKeyIsCanonical(
    parameter_set: ParameterSet,
    public_key: []const u8,
) bool {
    assert(public_key.len == parameter_set.publicKeyLen());
    const polynomial_bytes_len = public_key.len - public_seed_len;
    assert(polynomial_bytes_len % 3 == 0);

    var offset: usize = 0;
    while (offset < polynomial_bytes_len) : (offset += 3) {
        const coefficient_0 = @as(u16, public_key[offset]) |
            (@as(u16, public_key[offset + 1] & 0x0f) << 8);
        const coefficient_1 = @as(u16, public_key[offset + 1] >> 4) |
            (@as(u16, public_key[offset + 2]) << 4);
        if (coefficient_0 >= coefficient_modulus) return false;
        if (coefficient_1 >= coefficient_modulus) return false;
    }
    return true;
}

pub fn encapsulate(
    peer: *const PeerHandle,
    ciphertext_out: []u8,
    secret_out: []u8,
) Error!struct { ciphertext: []const u8, secret: []const u8 } {
    const ciphertext_len = peer.parameter_set.ciphertextLen();
    const secret_len = peer.parameter_set.sharedSecretLen();
    if (ciphertext_out.len < ciphertext_len or secret_out.len < secret_len)
        return error.BufferTooShort;
    const result = try kem_impl.kemEncapsulate(
        peer.parameter_set,
        &peer.key,
        ciphertext_out[0..ciphertext_len],
        secret_out[0..secret_len],
    );
    if (result.ciphertext.len != ciphertext_len or result.secret.len != secret_len)
        return error.LibcryptoFailed;
    return .{ .ciphertext = result.ciphertext, .secret = result.secret };
}

pub fn decapsulate(
    key: *const KeyHandle,
    ciphertext: []const u8,
    secret_out: []u8,
) Error![]u8 {
    const expected_ciphertext_len = key.parameter_set.ciphertextLen();
    const expected_secret_len = key.parameter_set.sharedSecretLen();
    if (ciphertext.len != expected_ciphertext_len) return error.MalformedKeyShare;
    if (secret_out.len < expected_secret_len) return error.BufferTooShort;
    const secret = try kem_impl.kemDecapsulate(
        key.parameter_set,
        key.key,
        ciphertext,
        secret_out[0..expected_secret_len],
    );
    if (secret.len != expected_secret_len) return error.LibcryptoFailed;
    return secret;
}

// RFC 10024 §4 and FIPS 203 — each provider-backed parameter set must produce
// an encapsulation key and a fixed-size ciphertext that round-trips to the same
// 32-byte shared secret.
test "ML-KEM-768 encapsulate/decapsulate round-trip" {
    try testRoundTrip(.mlkem768);
}

// RFC 10024 §4 and FIPS 203 — ML-KEM-1024 uses its distinct fixed public-key
// and ciphertext sizes while retaining a 32-byte shared secret.
test "ML-KEM-1024 encapsulate/decapsulate round-trip" {
    try testRoundTrip(.mlkem1024);
}

fn testRoundTrip(parameter_set: ParameterSet) !void {
    if (!backend.supportsParameterSet(parameter_set)) return error.SkipZigTest;

    var client_key = try generate(parameter_set);
    defer client_key.deinit();

    var public_key_buf: [max_public_key_len]u8 = undefined;
    const client_public = try publicKey(&client_key, &public_key_buf);
    try testing.expectEqual(@as(usize, parameter_set.publicKeyLen()), client_public.len);

    var peer: PeerHandle = undefined;
    try loadPeerPublic(parameter_set, client_public, &peer);
    defer peer.deinit();

    var ciphertext_buf: [max_ciphertext_len]u8 = undefined;
    var server_secret_buf: [max_shared_secret_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &server_secret_buf);
    const result = try encapsulate(&peer, &ciphertext_buf, &server_secret_buf);
    try testing.expectEqual(@as(usize, parameter_set.ciphertextLen()), result.ciphertext.len);
    try testing.expectEqual(@as(usize, parameter_set.sharedSecretLen()), result.secret.len);

    var client_secret_buf: [max_shared_secret_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &client_secret_buf);
    const client_secret = try decapsulate(
        &client_key,
        result.ciphertext,
        &client_secret_buf,
    );
    try testing.expectEqualSlices(u8, result.secret, client_secret);
}

// FIPS 203 §7.2 — the modulus check accepts q - 1, excludes the public seed,
// and rejects q in either packed position through the final coefficient group.
test "ML-KEM encapsulation-key modulus boundary" {
    for ([_]ParameterSet{ .mlkem768, .mlkem1024 }) |parameter_set| {
        var public_key_storage: [max_public_key_len]u8 = @splat(0);
        const public_key = public_key_storage[0..parameter_set.publicKeyLen()];
        const polynomial_end = public_key.len - public_seed_len;

        public_key[public_key.len - 1] = 0xff;
        try testing.expect(encapsulationKeyIsCanonical(parameter_set, public_key));
        public_key[public_key.len - 1] = 0;

        public_key[0] = @intCast((coefficient_modulus - 1) & 0xff);
        public_key[1] = @intCast((coefficient_modulus - 1) >> 8);
        try testing.expect(encapsulationKeyIsCanonical(parameter_set, public_key));

        public_key[0] = @intCast(coefficient_modulus & 0xff);
        public_key[1] = @intCast(coefficient_modulus >> 8);
        try testing.expect(!encapsulationKeyIsCanonical(parameter_set, public_key));

        public_key[0] = 0;
        public_key[1] = @intCast((coefficient_modulus & 0x0f) << 4);
        public_key[2] = @intCast(coefficient_modulus >> 4);
        try testing.expect(!encapsulationKeyIsCanonical(parameter_set, public_key));

        @memset(public_key[0..3], 0);
        public_key[polynomial_end - 2] = @intCast((coefficient_modulus & 0x0f) << 4);
        public_key[polynomial_end - 1] = @intCast(coefficient_modulus >> 4);
        try testing.expect(!encapsulationKeyIsCanonical(parameter_set, public_key));
    }
}

// RFC 10024 §4.2 / FIPS 203 §7.2 — the server rejects encapsulation keys
// whose 12-bit polynomial coefficients do not encode values modulo q.
test "ML-KEM rejects non-canonical encapsulation keys" {
    for ([_]ParameterSet{ .mlkem768, .mlkem1024 }) |parameter_set| {
        var public_key: [max_public_key_len]u8 = @splat(0);
        @memset(public_key[0..3], 0xff);

        var peer: PeerHandle = undefined;
        try testing.expectError(error.IdentityElement, loadPeerPublic(
            parameter_set,
            public_key[0..parameter_set.publicKeyLen()],
            &peer,
        ));
    }
}

// RFC 10024 §4.2 — the client rejects a ciphertext whose length does not
// exactly match the selected group's ML-KEM parameter set before decapsulation.
test "ML-KEM rejects a wrong-length ciphertext" {
    if (!backend.supportsParameterSet(.mlkem768))
        return error.SkipZigTest;
    var key = try generate(.mlkem768);
    defer key.deinit();
    var secret: [max_shared_secret_len]u8 = undefined;
    try testing.expectError(error.MalformedKeyShare, decapsulate(
        &key,
        &@as([(ParameterSet.mlkem768.ciphertextLen() - 1)]u8, @splat(0)),
        &secret,
    ));
}

// FIPS 203 §7.3 — invalid ciphertexts and the wrong recipient use implicit
// rejection. Success returns a pseudorandom secret, so agreement is the failure
// signal rather than an error from decapsulation.
test "ML-KEM tampering and a wrong recipient derive different secrets" {
    if (!backend.supportsParameterSet(.mlkem768))
        return error.SkipZigTest;
    var key = try generate(.mlkem768);
    defer key.deinit();
    var public_buf: [ParameterSet.mlkem768.publicKeyLen()]u8 = undefined;
    const public = try publicKey(&key, &public_buf);
    var peer: PeerHandle = undefined;
    try loadPeerPublic(.mlkem768, public, &peer);
    defer peer.deinit();
    var ciphertext_buf: [ParameterSet.mlkem768.ciphertextLen()]u8 = undefined;
    var server_secret_buf: [32]u8 = undefined;
    const server = try encapsulate(&peer, &ciphertext_buf, &server_secret_buf);

    ciphertext_buf[0] ^= 1;
    var tampered_secret_buf: [32]u8 = undefined;
    const tampered_secret = try decapsulate(
        &key,
        server.ciphertext,
        &tampered_secret_buf,
    );
    try testing.expect(!std.mem.eql(u8, server.secret, tampered_secret));

    var wrong_key = try generate(.mlkem768);
    defer wrong_key.deinit();
    var wrong_public_buf: [ParameterSet.mlkem768.publicKeyLen()]u8 = undefined;
    const wrong_public = try publicKey(&wrong_key, &wrong_public_buf);
    var wrong_peer: PeerHandle = undefined;
    try loadPeerPublic(.mlkem768, wrong_public, &wrong_peer);
    defer wrong_peer.deinit();
    var wrong_ciphertext_buf: [ParameterSet.mlkem768.ciphertextLen()]u8 = undefined;
    var wrong_server_secret_buf: [32]u8 = undefined;
    const wrong_server = try encapsulate(
        &wrong_peer,
        &wrong_ciphertext_buf,
        &wrong_server_secret_buf,
    );
    var wrong_recipient_secret_buf: [32]u8 = undefined;
    const wrong_recipient_secret = try decapsulate(
        &key,
        wrong_server.ciphertext,
        &wrong_recipient_secret_buf,
    );
    try testing.expect(!std.mem.eql(u8, wrong_server.secret, wrong_recipient_secret));
}
