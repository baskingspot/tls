//! Independent native/OpenSSL ML-KEM and RFC 10024 differentials (#199).
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;

const backend = @import("backend.zig");
const backend_native = @import("backend_native.zig");
const c_openssl = @import("c_openssl.zig");
const c = c_openssl.openssl;
const hkdf = @import("../hkdf.zig");
const hybrid_kex = @import("../hybrid_kex.zig");
const HybridKeyPairs = @import("../handshake_key_pairs.zig").KeyPairs;
const kex = @import("../kex.zig");
const NamedGroup = kex.NamedGroup;
const p256 = @import("../p256.zig");
const x25519 = @import("../x25519.zig");
const MlKem768 = crypto.kem.ml_kem.MLKem768;
const assert = std.debug.assert;

/// OpenSSL imports the exact expanded FIPS 203 decapsulation key that std
/// derives from the native seed. The comparison therefore shares one key pair.
fn opensslKeyFromNativeSeed(
    seed: *const [MlKem768.seed_length]u8,
) !backend.kem_impl.KemKey {
    var keypair = try MlKem768.KeyPair.generateDeterministic(seed.*);
    defer crypto.secureZero(u8, mem.asBytes(&keypair));
    var encoded = keypair.secret_key.toBytes();
    defer crypto.secureZero(u8, &encoded);
    return c.EVP_PKEY_new_raw_private_key_ex(
        null,
        "ML-KEM-768",
        null,
        &encoded,
        encoded.len,
    ) orelse error.LibcryptoFailed;
}

fn expectNativeMlKem768Differential(seed: *const [MlKem768.seed_length]u8) !void {
    var native_key = try backend_native.kemKeygenFromSeed(.mlkem768, seed);
    defer crypto.secureZero(u8, mem.asBytes(&native_key));
    var native_public_buf: [MlKem768.PublicKey.encoded_length]u8 = undefined;
    const native_public = try backend_native.kemPublic(native_key, &native_public_buf);

    const linked_key = try opensslKeyFromNativeSeed(seed);
    defer backend.kem_impl.freeKey(linked_key);
    var linked_public_buf: [MlKem768.PublicKey.encoded_length]u8 = undefined;
    const linked_public = try backend.kem_impl.kemPublic(linked_key, &linked_public_buf);
    try testing.expectEqualSlices(u8, native_public, linked_public);

    var linked_peer: backend.kem_impl.KemPeerKey = undefined;
    try backend.kem_impl.kemLoadPublic(.mlkem768, native_public, &linked_peer);
    defer backend.kem_impl.freeKey(linked_peer);
    var linked_ciphertext: [MlKem768.ciphertext_length]u8 = undefined;
    var linked_server_secret: [MlKem768.shared_length]u8 = undefined;
    defer crypto.secureZero(u8, &linked_server_secret);
    const linked_server = try backend.kem_impl.kemEncapsulate(
        .mlkem768,
        &linked_peer,
        &linked_ciphertext,
        &linked_server_secret,
    );

    var native_client_secret: [MlKem768.shared_length]u8 = undefined;
    defer crypto.secureZero(u8, &native_client_secret);
    _ = try backend_native.kemDecapsulate(
        .mlkem768,
        native_key,
        linked_server.ciphertext,
        &native_client_secret,
    );
    var linked_client_secret: [MlKem768.shared_length]u8 = undefined;
    defer crypto.secureZero(u8, &linked_client_secret);
    _ = try backend.kem_impl.kemDecapsulate(
        .mlkem768,
        linked_key,
        linked_server.ciphertext,
        &linked_client_secret,
    );
    try testing.expectEqualSlices(u8, linked_server.secret, &native_client_secret);
    try testing.expectEqualSlices(u8, linked_server.secret, &linked_client_secret);

    var native_peer: backend_native.KemPeerKey = undefined;
    try backend_native.kemLoadPublic(.mlkem768, linked_public, &native_peer);
    var native_ciphertext: [MlKem768.ciphertext_length]u8 = undefined;
    var native_server_secret: [MlKem768.shared_length]u8 = undefined;
    defer crypto.secureZero(u8, &native_server_secret);
    const native_server = try backend_native.kemEncapsulate(
        .mlkem768,
        &native_peer,
        &native_ciphertext,
        &native_server_secret,
    );
    var linked_native_client_secret: [MlKem768.shared_length]u8 = undefined;
    defer crypto.secureZero(u8, &linked_native_client_secret);
    _ = try backend.kem_impl.kemDecapsulate(
        .mlkem768,
        linked_key,
        native_server.ciphertext,
        &linked_native_client_secret,
    );
    try testing.expectEqualSlices(u8, native_server.secret, &linked_native_client_secret);
}

// FIPS 203 §7 — two fixed seeds produce identical public keys and ML-KEM
// secrets on std and OpenSSL. Encapsulation runs in both backend directions.
test "backend.native differential: ML-KEM-768 secrets match libcrypto in both roles" {
    if (comptime c_openssl.family != .openssl) return error.SkipZigTest;
    var prng: std.Random.DefaultPrng = .init(0x199303);
    for (0..2) |_| {
        var seed: [MlKem768.seed_length]u8 = undefined;
        defer crypto.secureZero(u8, &seed);
        prng.random().bytes(&seed);
        try expectNativeMlKem768Differential(&seed);
    }
}

fn fixedHybridKeyPairs() !struct { client: HybridKeyPairs, server: HybridKeyPairs } {
    const client: HybridKeyPairs = .initWithP256(
        try .fromSecret(.init(@splat(0x31))),
        try .fromSecret(.init(@splat(0x42))),
    );
    const server: HybridKeyPairs = .initWithP256(
        try .fromSecret(.init(@splat(0x73))),
        try .fromSecret(.init(@splat(0x24))),
    );
    return .{ .client = client, .server = server };
}

fn nativeClassicalPublic(
    group: NamedGroup,
    keypairs: *const HybridKeyPairs,
    out: []u8,
) !void {
    switch (group) {
        .x25519 => {
            assert(out.len == x25519.public_length);
            var private = try backend_native.privateKeyFromSecret(&keypairs.x25519.secret_key.data);
            defer backend_native.x25519FreeKey(&private);
            const public = try backend_native.rawPublicKeyFromPrivate(&private);
            @memcpy(out, &public);
        },
        .secp256r1 => {
            assert(out.len == p256.public_length);
            const public = try backend_native.p256PublicFromSecret(&keypairs.p256.secret_key.data);
            @memcpy(out, &public);
        },
        else => unreachable,
    }
}

fn nativeClassicalSecret(
    group: NamedGroup,
    keypairs: *const HybridKeyPairs,
    peer_public: []const u8,
    out: []u8,
) !void {
    switch (group) {
        .x25519 => {
            assert(peer_public.len == x25519.public_length);
            assert(out.len == x25519.secret_length);
            var ours = try backend_native.privateKeyFromSecret(&keypairs.x25519.secret_key.data);
            defer backend_native.x25519FreeKey(&ours);
            const peer_bytes = peer_public[0..x25519.public_length].*;
            var peer = try backend_native.publicKeyFromRaw(&peer_bytes);
            defer backend_native.x25519FreeKey(&peer);
            try backend_native.sharedSecretDerive(&ours, &peer, out[0..x25519.secret_length]);
        },
        .secp256r1 => {
            assert(peer_public.len == p256.public_length);
            assert(out.len == p256.secret_length);
            var ours = try backend_native.p256PrivateKeyFromSecret(&keypairs.p256.secret_key.data);
            defer backend_native.freeEcKey(&ours);
            const peer_bytes = peer_public[0..p256.public_length].*;
            var peer = try backend_native.p256PublicKeyFromRaw(&peer_bytes);
            defer backend_native.freeEcKey(&peer);
            try backend_native.p256SharedSecretDerive(ours, peer, out[0..p256.secret_length]);
        },
        else => unreachable,
    }
}

fn writeNativeHybridSecret(
    group: NamedGroup,
    classical_secret: []const u8,
    mlkem_secret: []const u8,
    out: []u8,
) []u8 {
    assert(classical_secret.len == 32);
    assert(mlkem_secret.len == 32);
    assert(out.len == 64);
    switch (group) {
        .x25519_mlkem768 => {
            @memcpy(out[0..32], mlkem_secret);
            @memcpy(out[32..64], classical_secret);
        },
        .secp256r1_mlkem768 => {
            @memcpy(out[0..32], classical_secret);
            @memcpy(out[32..64], mlkem_secret);
        },
        else => unreachable,
    }
    return out;
}

fn nativeHybridClientShare(
    group: NamedGroup,
    key: backend_native.KemKey,
    keypairs: *const HybridKeyPairs,
    out: []u8,
) ![]const u8 {
    var mlkem_public: [MlKem768.PublicKey.encoded_length]u8 = undefined;
    _ = try backend_native.kemPublic(key, &mlkem_public);
    switch (group) {
        .x25519_mlkem768 => {
            @memcpy(out[0..1184], &mlkem_public);
            try nativeClassicalPublic(.x25519, keypairs, out[1184..1216]);
            return out[0..1216];
        },
        .secp256r1_mlkem768 => {
            try nativeClassicalPublic(.secp256r1, keypairs, out[0..65]);
            @memcpy(out[65..1249], &mlkem_public);
            return out[0..1249];
        },
        else => unreachable,
    }
}

fn nativeHybridDecapsulate(
    group: NamedGroup,
    key: backend_native.KemKey,
    server_share: []const u8,
    keypairs: *const HybridKeyPairs,
    out: []u8,
) ![]u8 {
    const spec = group.hybridSpec().?;
    if (server_share.len != spec.server_share_len) return error.MalformedKeyShare;
    const ciphertext = if (group == .x25519_mlkem768)
        server_share[0..1088]
    else
        server_share[65..1153];
    const classical = if (group == .x25519_mlkem768)
        server_share[1088..1120]
    else
        server_share[0..65];
    var classical_secret: [32]u8 = undefined;
    defer crypto.secureZero(u8, &classical_secret);
    try nativeClassicalSecret(spec.classical_group, keypairs, classical, &classical_secret);
    var mlkem_secret: [32]u8 = undefined;
    defer crypto.secureZero(u8, &mlkem_secret);
    _ = try backend_native.kemDecapsulate(.mlkem768, key, ciphertext, &mlkem_secret);
    return writeNativeHybridSecret(group, &classical_secret, &mlkem_secret, out[0..64]);
}

fn nativeHybridEncapsulate(
    group: NamedGroup,
    client_share: []const u8,
    keypairs: *const HybridKeyPairs,
    server_share: []u8,
    out: []u8,
) !hybrid_kex.Encapsulation {
    const spec = group.hybridSpec().?;
    if (client_share.len != spec.client_share_len) return error.MalformedKeyShare;
    const mlkem_public = if (group == .x25519_mlkem768)
        client_share[0..1184]
    else
        client_share[65..1249];
    const client_classical = if (group == .x25519_mlkem768)
        client_share[1184..1216]
    else
        client_share[0..65];
    const ciphertext = if (group == .x25519_mlkem768)
        server_share[0..1088]
    else
        server_share[65..1153];
    const server_classical = if (group == .x25519_mlkem768)
        server_share[1088..1120]
    else
        server_share[0..65];

    var peer: backend_native.KemPeerKey = undefined;
    try backend_native.kemLoadPublic(.mlkem768, mlkem_public, &peer);
    var classical_secret: [32]u8 = undefined;
    defer crypto.secureZero(u8, &classical_secret);
    try nativeClassicalSecret(
        spec.classical_group,
        keypairs,
        client_classical,
        &classical_secret,
    );
    try nativeClassicalPublic(spec.classical_group, keypairs, server_classical);
    var mlkem_secret: [32]u8 = undefined;
    defer crypto.secureZero(u8, &mlkem_secret);
    _ = try backend_native.kemEncapsulate(.mlkem768, &peer, ciphertext, &mlkem_secret);
    return .{
        .server_share = server_share[0..spec.server_share_len],
        .shared_secret = writeNativeHybridSecret(
            group,
            &classical_secret,
            &mlkem_secret,
            out[0..64],
        ),
    };
}

fn expectTrafficSecretsMatch(native_shared: []const u8, linked_shared: []const u8) !void {
    const NativeHkdf = hkdf.Hkdf(backend_native.sha2.Sha256, crypto.hash.sha2.Sha256);
    const LinkedHkdf = hkdf.Hkdf(backend.sha2.Sha256, crypto.hash.sha2.Sha256);
    const handshake_hash: NativeHkdf.TranscriptHash = .init(@splat(0x5a));
    const application_hash: NativeHkdf.TranscriptHash = .init(@splat(0xa5));
    const native_handshake = NativeHkdf.handshakeSecretFor(null, native_shared);
    const linked_handshake = LinkedHkdf.handshakeSecretFor(null, linked_shared);
    try testing.expectEqualSlices(
        u8,
        &LinkedHkdf.clientHandshakeTrafficSecret(linked_handshake, &handshake_hash).data,
        &NativeHkdf.clientHandshakeTrafficSecret(native_handshake, &handshake_hash).data,
    );
    try testing.expectEqualSlices(
        u8,
        &LinkedHkdf.serverHandshakeTrafficSecret(linked_handshake, &handshake_hash).data,
        &NativeHkdf.serverHandshakeTrafficSecret(native_handshake, &handshake_hash).data,
    );
    const native_master = NativeHkdf.masterSecret(native_handshake);
    const linked_master = LinkedHkdf.masterSecret(linked_handshake);
    try testing.expectEqualSlices(
        u8,
        &LinkedHkdf.clientApplicationTrafficSecret(linked_master, &application_hash).data,
        &NativeHkdf.clientApplicationTrafficSecret(native_master, &application_hash).data,
    );
    try testing.expectEqualSlices(
        u8,
        &LinkedHkdf.serverApplicationTrafficSecret(linked_master, &application_hash).data,
        &NativeHkdf.serverApplicationTrafficSecret(native_master, &application_hash).data,
    );
}

fn expectNativeHybridDifferential(
    group: NamedGroup,
    seed: *const [MlKem768.seed_length]u8,
) !void {
    var keys = try fixedHybridKeyPairs();
    defer keys.client.secureZero();
    defer keys.server.secureZero();
    var native_key = try backend_native.kemKeygenFromSeed(.mlkem768, seed);
    defer crypto.secureZero(u8, mem.asBytes(&native_key));
    var native_client_share_buf: [hybrid_kex.max_client_share_len]u8 = undefined;
    const native_client_share = try nativeHybridClientShare(
        group,
        native_key,
        &keys.client,
        &native_client_share_buf,
    );

    var linked_server_share_buf: [hybrid_kex.max_server_share_len]u8 = undefined;
    var linked_server_secret_buf: [hybrid_kex.max_shared_secret_len]u8 = undefined;
    const linked_server = try hybrid_kex.encapsulate(
        group,
        native_client_share,
        &keys.server,
        &linked_server_share_buf,
        &linked_server_secret_buf,
    );
    var native_client_secret_buf: [hybrid_kex.max_shared_secret_len]u8 = undefined;
    const native_client_secret = try nativeHybridDecapsulate(
        group,
        native_key,
        linked_server.server_share,
        &keys.client,
        &native_client_secret_buf,
    );
    try testing.expectEqualSlices(u8, linked_server.shared_secret, native_client_secret);
    try expectTrafficSecretsMatch(native_client_secret, linked_server.shared_secret);

    var linked_client: hybrid_kex.ClientKeyPair = .{
        .group = group,
        .mlkem_key = .{
            .parameter_set = .mlkem768,
            .key = try opensslKeyFromNativeSeed(seed),
        },
    };
    defer linked_client.deinit();
    var linked_client_share_buf: [hybrid_kex.max_client_share_len]u8 = undefined;
    const linked_client_share = try linked_client.publicKey(
        &keys.client,
        &linked_client_share_buf,
    );
    try testing.expectEqualSlices(u8, native_client_share, linked_client_share);

    var native_server_share_buf: [hybrid_kex.max_server_share_len]u8 = undefined;
    var native_server_secret_buf: [hybrid_kex.max_shared_secret_len]u8 = undefined;
    const native_server = try nativeHybridEncapsulate(
        group,
        linked_client_share,
        &keys.server,
        &native_server_share_buf,
        &native_server_secret_buf,
    );
    var linked_client_secret_buf: [hybrid_kex.max_shared_secret_len]u8 = undefined;
    const linked_client_secret = try hybrid_kex.decapsulate(
        &linked_client,
        native_server.server_share,
        &keys.client,
        &linked_client_secret_buf,
    );
    try testing.expectEqualSlices(u8, native_server.shared_secret, linked_client_secret);
    try expectTrafficSecretsMatch(native_server.shared_secret, linked_client_secret);
}

// RFC 10024 §4.1-§4.3 and RFC 8446 §7.1/§7.3 — both ML-KEM-768 groups match
// OpenSSL byte for byte in each role, then derive identical traffic secrets.
test "backend.native differential: ML-KEM-768 hybrid groups match libcrypto in both roles" {
    if (comptime c_openssl.family != .openssl) return error.SkipZigTest;
    var prng: std.Random.DefaultPrng = .init(0x199304);
    for (0..2) |_| {
        var seed: [MlKem768.seed_length]u8 = undefined;
        defer crypto.secureZero(u8, &seed);
        prng.random().bytes(&seed);
        for ([_]NamedGroup{ .x25519_mlkem768, .secp256r1_mlkem768 }) |group| {
            try expectNativeHybridDifferential(group, &seed);
        }
    }
}
