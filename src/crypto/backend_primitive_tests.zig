//! Backend primitive contract tests for native and linked libcrypto lanes.
//!
//! The same facade-direct known vectors run on every backend. Unsupported
//! P-curve, RSA, and libcrypto error-queue coverage lives in the companion
//! backend_libcrypto_primitive_tests.zig file. Selected Wycheproof vectors are
//! included here, but this is not a full Wycheproof harness.
const std = @import("std");
const stdx = @import("stdx");
const testing = std.testing;
const assert = std.debug.assert;

const backend = @import("backend.zig");
const backend_native = @import("backend_native.zig");
const hmac = @import("../hmac.zig");
const Hkdf = @import("../hkdf.zig").Hkdf;
const CipherSuite = @import("../cipher_suite.zig").CipherSuite;
const fixtures = @import("fixtures");
const P256 = std.crypto.ecc.P256;
const P384 = std.crypto.ecc.P384;

test {
    if (comptime !backend.native_selected) {
        _ = @import("backend_libcrypto_primitive_tests.zig");
    }
}

// ---------------------------------------------------------------------------
// X25519 — direct backend.x25519 facade
// ---------------------------------------------------------------------------

// RFC 7748 §5.2 — X25519 scalar multiplication test vector.
test "backend.x25519: RFC 7748 §5.2 shared secret" {
    const scalar: [32]u8 = stdx.fmt.comptimeHex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    );
    const peer_pub: [32]u8 = stdx.fmt.comptimeHex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
    );
    const want: [32]u8 = stdx.fmt.comptimeHex(
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    );

    var priv = try backend.x25519.privateKeyFromSecret(&scalar);
    defer backend.x25519.freeKey(&priv);
    var peer = try backend.x25519.publicKeyFromRaw(&peer_pub);
    defer backend.x25519.freeKey(&peer);

    var shared: [32]u8 = undefined;
    try backend.x25519.sharedSecretDerive(&priv, &peer, &shared);
    try testing.expectEqualSlices(u8, &want, &shared);
}

// RFC 7748 §6.1 — two parties derive the same shared secret.
test "backend.x25519: RFC 7748 §6.1 mutual key agreement" {
    const alice_secret: [32]u8 = stdx.fmt.comptimeHex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    );
    const bob_secret: [32]u8 = stdx.fmt.comptimeHex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    );

    var alice_priv = try backend.x25519.privateKeyFromSecret(&alice_secret);
    defer backend.x25519.freeKey(&alice_priv);
    const alice_pub = try backend.x25519.rawPublicKeyFromPrivate(&alice_priv);

    var bob_priv = try backend.x25519.privateKeyFromSecret(&bob_secret);
    defer backend.x25519.freeKey(&bob_priv);
    const bob_pub = try backend.x25519.rawPublicKeyFromPrivate(&bob_priv);

    var alice_peer = try backend.x25519.publicKeyFromRaw(&bob_pub);
    defer backend.x25519.freeKey(&alice_peer);
    var alice_shared: [32]u8 = undefined;
    try backend.x25519.sharedSecretDerive(&alice_priv, &alice_peer, &alice_shared);

    var bob_peer = try backend.x25519.publicKeyFromRaw(&alice_pub);
    defer backend.x25519.freeKey(&bob_peer);
    var bob_shared: [32]u8 = undefined;
    try backend.x25519.sharedSecretDerive(&bob_priv, &bob_peer, &bob_shared);

    try testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — X25519 tcId 1, normal case,
// exercised directly through the backend facade.
test "backend.x25519: Wycheproof tcId 1 shared secret" {
    const scalar: [32]u8 = stdx.fmt.comptimeHex(
        "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475",
    );
    const peer_pub: [32]u8 = stdx.fmt.comptimeHex(
        "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829",
    );
    const want: [32]u8 = stdx.fmt.comptimeHex(
        "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320",
    );

    var priv = try backend.x25519.privateKeyFromSecret(&scalar);
    defer backend.x25519.freeKey(&priv);
    var peer = try backend.x25519.publicKeyFromRaw(&peer_pub);
    defer backend.x25519.freeKey(&peer);

    var shared: [32]u8 = undefined;
    try backend.x25519.sharedSecretDerive(&priv, &peer, &shared);
    try testing.expectEqualSlices(u8, &want, &shared);
}

// RFC 7748 §6.1 / Wycheproof low-order public keys — all-zero shared secret
// indicates a low-order peer public key and must be rejected by the backend facade.
test "backend.x25519: all-zero public key is rejected (IdentityElement)" {
    const scalar: [32]u8 = stdx.fmt.comptimeHex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    );
    const zero_pub: [32]u8 = @splat(0);

    var priv = try backend.x25519.privateKeyFromSecret(&scalar);
    defer backend.x25519.freeKey(&priv);
    var peer = try backend.x25519.publicKeyFromRaw(&zero_pub);
    defer backend.x25519.freeKey(&peer);

    var shared: [32]u8 = undefined;
    try testing.expectError(
        error.IdentityElement,
        backend.x25519.sharedSecretDerive(&priv, &peer, &shared),
    );
}

// RFC 7748 §6.1 — a small-order twist public key produces all-zero output.
test "backend.x25519: small-order public key is rejected (IdentityElement)" {
    const scalar: [32]u8 = stdx.fmt.comptimeHex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    );
    const small_order_pub: [32]u8 = stdx.fmt.comptimeHex(
        "0100000000000000000000000000000000000000000000000000000000000000",
    );

    var priv = try backend.x25519.privateKeyFromSecret(&scalar);
    defer backend.x25519.freeKey(&priv);
    var peer = try backend.x25519.publicKeyFromRaw(&small_order_pub);
    defer backend.x25519.freeKey(&peer);

    var shared: [32]u8 = undefined;
    try testing.expectError(
        error.IdentityElement,
        backend.x25519.sharedSecretDerive(&priv, &peer, &shared),
    );
}

// RFC 8446 §4.4.2 and §4.4.3 — a native P-256 scalar pairs only with the
// certificate carrying its SEC1 public key. Mismatches are independent of DER
// validity, and trailing bytes do not describe one CertificateEntry.
test "backend.native: P-256 certificate key pairing accepts a match and rejects a mismatch" {
    var key = try backend_native.privateKeyFromP256Scalar(&fixtures.server_ecdsa_scalar);
    defer backend_native.freeEcKey(&key);
    try testing.expect(try backend_native.privateKeyPairsWithCertificate(
        key,
        &fixtures.server_ecdsa_cert_der,
    ));
    try testing.expect(!try backend_native.privateKeyPairsWithCertificate(
        key,
        &fixtures.client_ecdsa_cert_der,
    ));
    try testing.expect(!try backend_native.privateKeyPairsWithCertificate(
        key,
        &fixtures.rsa_pss_cert_der,
    ));
    try testing.expectError(
        error.InvalidEncoding,
        backend_native.privateKeyPairsWithCertificate(key, "garbage"),
    );
    const trailing = fixtures.server_ecdsa_cert_der ++ [_]u8{0};
    try testing.expectError(
        error.InvalidEncoding,
        backend_native.privateKeyPairsWithCertificate(key, &trailing),
    );
}

// ---------------------------------------------------------------------------
// AEAD — direct backend.aead facade for every advertised cipher suite
// ---------------------------------------------------------------------------

// RFC 8446 §5.2 — TLS 1.3 record protection uses AEAD with a 16-byte tag and
// 12-byte nonce. The backend must encrypt/decrypt consistently for every
// cipher suite advertised in `backend.capabilities.cipher_suites`.
test "backend.aead: round-trip for every advertised cipher suite" {
    inline for (backend.capabilities.cipher_suites) |suite| {
        const key_bytes: [keyLenForSuite(suite)]u8 = @splat(0xab);
        const nonce: [backend.aead.nonce_len]u8 = @splat(0xcd);
        const ad = "tls-record-header";
        const plaintext = "backend-aead-contract";

        var ctx: backend.aead.Context = try backend.aead.init(suite, &key_bytes);
        defer backend.aead.deinit(&ctx);

        var ciphertext: [plaintext.len]u8 = undefined;
        var tag: [backend.aead.tag_len]u8 = undefined;
        try backend.aead.encrypt(&ctx, &ciphertext, &tag, plaintext, ad, &nonce);

        var decrypted: [plaintext.len]u8 = undefined;
        try backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, ad, &nonce);
        try testing.expectEqualSlices(u8, plaintext, &decrypted);
    }
}

// RFC 8446 §5.2 — AEAD must reject tag corruption for every advertised suite.
test "backend.aead: tag corruption is rejected for every advertised cipher suite" {
    inline for (backend.capabilities.cipher_suites) |suite| {
        const key_bytes: [keyLenForSuite(suite)]u8 = @splat(0xab);
        const nonce: [backend.aead.nonce_len]u8 = @splat(0xcd);
        const ad = "tls-record-header";
        const plaintext = "backend-aead-contract";

        var ctx: backend.aead.Context = try backend.aead.init(suite, &key_bytes);
        defer backend.aead.deinit(&ctx);

        var ciphertext: [plaintext.len]u8 = undefined;
        var tag: [backend.aead.tag_len]u8 = undefined;
        try backend.aead.encrypt(&ctx, &ciphertext, &tag, plaintext, ad, &nonce);

        tag[0] ^= 0xff;
        var decrypted: [plaintext.len]u8 = undefined;
        try testing.expectError(
            error.AuthenticationFailed,
            backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, ad, &nonce),
        );
    }
}

// RFC 8446 §5.2 — AEAD must reject ciphertext corruption for every advertised suite.
test "backend.aead: ciphertext corruption is rejected for every advertised cipher suite" {
    inline for (backend.capabilities.cipher_suites) |suite| {
        const key_bytes: [keyLenForSuite(suite)]u8 = @splat(0xab);
        const nonce: [backend.aead.nonce_len]u8 = @splat(0xcd);
        const ad = "tls-record-header";
        const plaintext = "backend-aead-contract";

        var ctx: backend.aead.Context = try backend.aead.init(suite, &key_bytes);
        defer backend.aead.deinit(&ctx);

        var ciphertext: [plaintext.len]u8 = undefined;
        var tag: [backend.aead.tag_len]u8 = undefined;
        try backend.aead.encrypt(&ctx, &ciphertext, &tag, plaintext, ad, &nonce);

        ciphertext[0] ^= 0xff;
        var decrypted: [plaintext.len]u8 = undefined;
        try testing.expectError(
            error.AuthenticationFailed,
            backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, ad, &nonce),
        );
    }
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — AES-128-GCM tcId 2, exercised
// directly through the backend facade with tag corruption rejection.
test "backend.aead: Wycheproof AES-128-GCM tcId 2" {
    const key: [16]u8 = stdx.fmt.comptimeHex("5b9604fe14eadba931b0ccf34843dab9");
    const nonce: [12]u8 = stdx.fmt.comptimeHex("921d2507fa8007b7bd067d34");
    const ad = stdx.fmt.comptimeHex("00112233445566778899aabbccddeeff");
    const plaintext = stdx.fmt.comptimeHex("001d0c231287c1182784554ca3a21908");
    const expected_ct = stdx.fmt.comptimeHex("49d8b9783e911913d87094d1f63cc765");
    const expected_tag = stdx.fmt.comptimeHex("1e348ba07cca2cf04c618cb4d43a5b92");

    var ctx: backend.aead.Context = try backend.aead.init(.aes_128_gcm_sha256, &key);
    defer backend.aead.deinit(&ctx);

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [backend.aead.tag_len]u8 = undefined;
    try backend.aead.encrypt(&ctx, &ciphertext, &tag, &plaintext, &ad, &nonce);
    try testing.expectEqualSlices(u8, &expected_ct, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);

    var decrypted: [plaintext.len]u8 = undefined;
    try backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, &ad, &nonce);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    tag[0] ^= 1;
    try testing.expectError(
        error.AuthenticationFailed,
        backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, &ad, &nonce),
    );
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — AES-256-GCM non-empty AAD
// boundary vector, exercised directly through the backend facade.
test "backend.aead: Wycheproof AES-256-GCM AAD boundary" {
    const key: [32]u8 = stdx.fmt.comptimeHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
    const nonce: [12]u8 = stdx.fmt.comptimeHex("000102030405060708090a0b");
    const ad = stdx.fmt.comptimeHex("00112233445566778899aabbccddeeff");
    const plaintext = stdx.fmt.comptimeHex("001d0c231287c1182784554ca3a21908");
    const expected_ct = stdx.fmt.comptimeHex("471fda38d7620303aac5c2c7124b6165");
    const expected_tag = stdx.fmt.comptimeHex("01af015e2daf8b415dc2027e8d51aa80");

    var ctx: backend.aead.Context = try backend.aead.init(.aes_256_gcm_sha384, &key);
    defer backend.aead.deinit(&ctx);

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [backend.aead.tag_len]u8 = undefined;
    try backend.aead.encrypt(&ctx, &ciphertext, &tag, &plaintext, &ad, &nonce);
    try testing.expectEqualSlices(u8, &expected_ct, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);

    var decrypted: [plaintext.len]u8 = undefined;
    try backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, &ad, &nonce);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    tag[0] ^= 1;
    try testing.expectError(
        error.AuthenticationFailed,
        backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, &ad, &nonce),
    );
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — ChaCha20-Poly1305 non-empty AAD
// boundary vector, exercised directly through the backend facade.
test "backend.aead: Wycheproof ChaCha20-Poly1305 AAD boundary" {
    const key: [32]u8 = stdx.fmt.comptimeHex(
        "cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273",
    );
    const nonce: [12]u8 = stdx.fmt.comptimeHex("99e23ec48985bccdeeab60f1");
    const ad = stdx.fmt.comptimeHex("00112233445566778899aabbccddeeff");
    const plaintext = stdx.fmt.comptimeHex("2a");
    const expected_ct = stdx.fmt.comptimeHex("3a");
    const expected_tag = stdx.fmt.comptimeHex("d7d9204f3da54c5438a2454128a7438e");

    var ctx: backend.aead.Context = try backend.aead.init(.chacha20_poly1305_sha256, &key);
    defer backend.aead.deinit(&ctx);

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [backend.aead.tag_len]u8 = undefined;
    try backend.aead.encrypt(&ctx, &ciphertext, &tag, &plaintext, &ad, &nonce);
    try testing.expectEqualSlices(u8, &expected_ct, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);

    var decrypted: [plaintext.len]u8 = undefined;
    try backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, &ad, &nonce);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    tag[15] ^= 1;
    try testing.expectError(
        error.AuthenticationFailed,
        backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, &ad, &nonce),
    );
}

// RFC 8439 §2.8.2 — ChaCha20-Poly1305 known-answer vector through the backend facade.
test "backend.aead: ChaCha20-Poly1305 RFC 8439 §2.8.2 known-answer vector" {
    const key: [32]u8 = stdx.fmt.comptimeHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    );
    const nonce: [12]u8 = stdx.fmt.comptimeHex("070000004041424344454647");
    const ad = stdx.fmt.comptimeHex("50515253c0c1c2c3c4c5c6c7");
    const plaintext = stdx.fmt.comptimeHex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c61737320" ++
            "6f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c7920" ++
            "6f6e652074697020666f7220746865206675747572652c2073756e73637265656e20" ++
            "776f756c642062652069742e",
    );
    const expected_ct = stdx.fmt.comptimeHex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d" ++
            "63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b" ++
            "3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831" ++
            "d7bc3ff4def08e4b7a9de576d26586cec64b6116",
    );
    const expected_tag = stdx.fmt.comptimeHex("1ae10b594f09e26a7e902ecbd0600691");

    var ctx: backend.aead.Context = try backend.aead.init(
        .chacha20_poly1305_sha256,
        &key,
    );
    defer backend.aead.deinit(&ctx);

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [backend.aead.tag_len]u8 = undefined;
    try backend.aead.encrypt(&ctx, &ciphertext, &tag, &plaintext, &ad, &nonce);
    try testing.expectEqualSlices(u8, &expected_ct, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);

    var decrypted: [plaintext.len]u8 = undefined;
    try backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, &ad, &nonce);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

fn keyLenForSuite(suite: CipherSuite) usize {
    return switch (suite) {
        .aes_128_gcm_sha256 => 16,
        .aes_256_gcm_sha384, .chacha20_poly1305_sha256 => 32,
    };
}

// RFC 7748 §5.2 — with libcrypto active, the native X25519 implementation
// derives the same shared secret through the same boundary as the linked path.
test "backend.native differential: X25519 shared secret matches libcrypto" {
    if (comptime backend.native_selected) return error.SkipZigTest;
    const scalar: [32]u8 = stdx.fmt.comptimeHex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    );
    const peer_pub: [32]u8 = stdx.fmt.comptimeHex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
    );

    var native_priv = try backend_native.privateKeyFromSecret(&scalar);
    defer backend_native.x25519FreeKey(&native_priv);
    var native_peer = try backend_native.publicKeyFromRaw(&peer_pub);
    defer backend_native.x25519FreeKey(&native_peer);
    var native_secret: [32]u8 = undefined;
    try backend_native.sharedSecretDerive(&native_priv, &native_peer, &native_secret);

    var linked_priv = try backend.x25519.privateKeyFromSecret(&scalar);
    defer backend.x25519.freeKey(&linked_priv);
    var linked_peer = try backend.x25519.publicKeyFromRaw(&peer_pub);
    defer backend.x25519.freeKey(&linked_peer);
    var linked_secret: [32]u8 = undefined;
    try backend.x25519.sharedSecretDerive(&linked_priv, &linked_peer, &linked_secret);
    try testing.expectEqualSlices(u8, &linked_secret, &native_secret);
}

fn nativeEcPrivate(
    comptime Curve: type,
    secret: *const [Curve.scalar.encoded_length]u8,
) backend_native.Error!backend_native.pkey {
    return if (comptime Curve == P256)
        backend_native.p256PrivateKeyFromSecret(secret)
    else
        backend_native.p384PrivateKeyFromSecret(secret);
}

fn nativeEcPublic(
    comptime Curve: type,
    secret: *const [Curve.scalar.encoded_length]u8,
) backend_native.Error![1 + 2 * Curve.Fe.encoded_length]u8 {
    if (comptime Curve == P256) return backend_native.p256PublicFromSecret(secret);
    var key = try backend_native.p384PrivateKeyFromSecret(secret);
    defer backend_native.freeEcKey(&key);
    return backend_native.p384RawPublicKeyFromPrivate(key);
}

fn nativeEcPeer(
    comptime Curve: type,
    public_key: *const [1 + 2 * Curve.Fe.encoded_length]u8,
) backend_native.Error!backend_native.pkey {
    return if (comptime Curve == P256)
        backend_native.p256PublicKeyFromRaw(public_key)
    else
        backend_native.p384PublicKeyFromRaw(public_key);
}

fn nativeEcShared(
    comptime Curve: type,
    ours: backend_native.pkey,
    peer: backend_native.pkey,
    out: *[Curve.Fe.encoded_length]u8,
) backend_native.Error!void {
    return if (comptime Curve == P256)
        backend_native.p256SharedSecretDerive(ours, peer, out)
    else
        backend_native.p384SharedSecretDerive(ours, peer, out);
}

fn expectNativeEcdhPair(
    comptime Curve: type,
    a_secret: *const [Curve.scalar.encoded_length]u8,
    b_secret: *const [Curve.scalar.encoded_length]u8,
) !void {
    const Linked = if (comptime Curve == P256) backend.p256 else backend.p384;
    var linked_a = try Linked.privateKeyFromSecret(a_secret);
    defer Linked.freeKey(&linked_a);
    var linked_b = try Linked.privateKeyFromSecret(b_secret);
    defer Linked.freeKey(&linked_b);
    const linked_a_public = try Linked.rawPublicKeyFromPrivate(linked_a);
    const linked_b_public = try Linked.rawPublicKeyFromPrivate(linked_b);
    const native_a_public = try nativeEcPublic(Curve, a_secret);
    const native_b_public = try nativeEcPublic(Curve, b_secret);
    try testing.expectEqualSlices(u8, &linked_a_public, &native_a_public);
    try testing.expectEqualSlices(u8, &linked_b_public, &native_b_public);

    var native_a = try nativeEcPrivate(Curve, a_secret);
    defer backend_native.freeEcKey(&native_a);
    var native_b = try nativeEcPrivate(Curve, b_secret);
    defer backend_native.freeEcKey(&native_b);
    var native_a_peer = try nativeEcPeer(Curve, &linked_b_public);
    defer backend_native.freeEcKey(&native_a_peer);
    var native_b_peer = try nativeEcPeer(Curve, &linked_a_public);
    defer backend_native.freeEcKey(&native_b_peer);
    var linked_a_peer = try Linked.publicKeyFromRaw(&native_b_public);
    defer Linked.freeKey(&linked_a_peer);
    var linked_b_peer = try Linked.publicKeyFromRaw(&native_a_public);
    defer Linked.freeKey(&linked_b_peer);

    var native_ab: [Curve.Fe.encoded_length]u8 = undefined;
    var native_ba: [Curve.Fe.encoded_length]u8 = undefined;
    var linked_ab: [Curve.Fe.encoded_length]u8 = undefined;
    var linked_ba: [Curve.Fe.encoded_length]u8 = undefined;
    try nativeEcShared(Curve, native_a, native_a_peer, &native_ab);
    try nativeEcShared(Curve, native_b, native_b_peer, &native_ba);
    try Linked.sharedSecretDerive(linked_a, linked_a_peer, &linked_ab);
    try Linked.sharedSecretDerive(linked_b, linked_b_peer, &linked_ba);
    try testing.expectEqualSlices(u8, &linked_ab, &native_ab);
    try testing.expectEqualSlices(u8, &linked_ba, &native_ba);
    try testing.expectEqualSlices(u8, &native_ab, &native_ba);
}

// SEC 1 §3.2.2 and RFC 8446 §7.4.2 — native and libcrypto derive identical
// SEC1 public keys and ECDH x-coordinates. Four pairs per curve cross both
// public-key producers and both directions of the shared-secret operation.
test "backend.native differential: P-256 and P-384 ECDH match libcrypto" {
    if (comptime backend.native_selected) return error.SkipZigTest;
    var prng: std.Random.DefaultPrng = .init(0x199200);
    const random = prng.random();
    inline for (.{ P256, P384 }) |Curve| {
        for (0..4) |_| {
            var a: [Curve.scalar.encoded_length]u8 = undefined;
            var b: [Curve.scalar.encoded_length]u8 = undefined;
            random.bytes(&a);
            random.bytes(&b);
            try expectNativeEcdhPair(Curve, &a, &b);
        }
    }
}

// RFC 8446 §5.2 — native and libcrypto agree on ciphertext bytes and tags for
// all three TLS 1.3 AEAD suites, not just on decrypting their own output.
test "backend.native differential: AEAD ciphertext and tags match libcrypto" {
    if (comptime backend.native_selected) return error.SkipZigTest;
    const lengths = [_]usize{ 0, 1, 15, 16, 17, 127, 128, 129, 255, 256, 300 };
    var source: [300]u8 = undefined;
    for (&source, 0..) |*byte, i| byte.* = @truncate(i);

    inline for (backend_native.capabilities.cipher_suites) |suite| {
        inline for (lengths) |len| {
            const key: [keyLenForSuite(suite)]u8 = @splat(0xa5);
            const nonce: [backend.aead.nonce_len]u8 = @splat(0x5a);
            const plaintext = source[0..len];
            const ad = source[300 - len ..];

            var native_ctx = try backend_native.aeadInit(suite, &key);
            defer backend_native.aeadDeinit(&native_ctx);
            var linked_ctx = try backend.aead.init(suite, &key);
            defer backend.aead.deinit(&linked_ctx);

            var native_ciphertext: [plaintext.len]u8 = undefined;
            var native_tag: [backend_native.aead_tag_len]u8 = undefined;
            backend_native.aeadEncrypt(
                &native_ctx,
                &native_ciphertext,
                &native_tag,
                plaintext,
                ad,
                &nonce,
            ) catch unreachable;
            var linked_ciphertext: [plaintext.len]u8 = undefined;
            var linked_tag: [backend.aead.tag_len]u8 = undefined;
            try backend.aead.encrypt(
                &linked_ctx,
                &linked_ciphertext,
                &linked_tag,
                plaintext,
                ad,
                &nonce,
            );
            try testing.expectEqualSlices(u8, &linked_ciphertext, &native_ciphertext);
            try testing.expectEqualSlices(u8, &linked_tag, &native_tag);
        }
    }
}

// ---------------------------------------------------------------------------
// SHA-2 — backend.sha2 against std.crypto.hash.sha2 (#138)
// ---------------------------------------------------------------------------

const sha2_pairs = .{
    .{ backend.sha2.Sha256, std.crypto.hash.sha2.Sha256 },
    .{ backend.sha2.Sha384, std.crypto.hash.sha2.Sha384 },
};

fn sha2Input(buf: []u8, seed: u64) []u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    prng.random().bytes(buf);
    return buf;
}

// FIPS 180-4 §6.2/§6.5, RFC 2104 §2, RFC 5869 §2, and RFC 8446 §7.1 —
// product HMAC and the TLS key schedule agree across native and libcrypto
// hashes. This compares the product types in hmac.zig and hkdf.zig, not a
// libcrypto HMAC or HKDF entry point.
test "backend.native differential: product HMAC and HKDF match across backends" {
    if (comptime backend.native_selected) return error.SkipZigTest;
    var buf: [300]u8 = undefined;
    const input = sha2Input(&buf, 0x199138);
    inline for (.{
        .{ backend_native.sha2.Sha256, backend.sha2.Sha256 },
        .{ backend_native.sha2.Sha384, backend.sha2.Sha384 },
    }) |pair| {
        const NativeHash, const LinkedHash = pair;
        const NativeHmac = hmac.Hmac(NativeHash);
        const LinkedHmac = hmac.Hmac(LinkedHash);
        for ([_]usize{ 0, 1, NativeHash.block_length, 300 }) |key_len| {
            const key = input[0..key_len];
            const msg = input[key_len / 2 ..];
            var native_digest: [NativeHash.digest_length]u8 = undefined;
            var linked_digest: [LinkedHash.digest_length]u8 = undefined;
            NativeHash.hash(msg, &native_digest, .{});
            LinkedHash.hash(msg, &linked_digest, .{});
            try testing.expectEqualSlices(u8, &linked_digest, &native_digest);

            var native_mac: [NativeHmac.mac_length]u8 = undefined;
            var linked_mac: [LinkedHmac.mac_length]u8 = undefined;
            NativeHmac.create(&native_mac, msg, key);
            LinkedHmac.create(&linked_mac, msg, key);
            try testing.expectEqualSlices(u8, &linked_mac, &native_mac);

            const NativeHkdf = Hkdf(NativeHash, NativeHash);
            const LinkedHkdf = Hkdf(LinkedHash, NativeHash);
            const native_prk = NativeHkdf.extract(key, msg);
            const linked_prk = LinkedHkdf.extract(key, msg);
            try testing.expectEqualSlices(u8, &linked_prk.data, &native_prk.data);
            var native_okm: [2 * NativeHash.digest_length + 7]u8 = undefined;
            var linked_okm: [2 * LinkedHash.digest_length + 7]u8 = undefined;
            NativeHkdf.expandLabel(&native_okm, "native differential", "", native_prk);
            LinkedHkdf.expandLabel(&linked_okm, "native differential", "", linked_prk);
            try testing.expectEqualSlices(u8, &linked_okm, &native_okm);
        }
    }
}

// FIPS 180-4 §6.2, §6.5 — SHA-256 and SHA-384 digests. The backend types
// match std for every length 0..300, which crosses one and two block
// boundaries and every padding case for both block sizes.
test "backend.sha2: one-shot hash matches std for lengths 0..300" {
    var buf: [300]u8 = undefined;
    const input = sha2Input(&buf, 0x138);
    inline for (sha2_pairs) |pair| {
        const B, const S = pair;
        comptime assert(B.digest_length == S.digest_length);
        comptime assert(B.block_length == S.block_length);
        for (0..input.len + 1) |len| {
            var got: [B.digest_length]u8 = undefined;
            var want: [S.digest_length]u8 = undefined;
            B.hash(input[0..len], &got, .{});
            S.hash(input[0..len], &want, .{});
            try testing.expectEqualSlices(u8, &want, &got);
        }
    }
}

// FIPS 180-4 §6.2, §6.5 — multi-block inputs, including lengths that end one
// byte past a block boundary.
test "backend.sha2: large inputs match std" {
    var buf: [(1 << 16) + 129]u8 = undefined;
    const input = sha2Input(&buf, 0x1380);
    const lengths = [_]usize{ 4096, 4097, 1 << 16, (1 << 16) + 1, input.len };
    inline for (sha2_pairs) |pair| {
        const B, const S = pair;
        for (lengths) |len| {
            var got: [B.digest_length]u8 = undefined;
            var want: [S.digest_length]u8 = undefined;
            B.hash(input[0..len], &got, .{});
            S.hash(input[0..len], &want, .{});
            try testing.expectEqualSlices(u8, &want, &got);
        }
    }
}

// RFC 8446 §4.4.1 — the transcript hash absorbs messages at arbitrary
// boundaries and takes Transcript-Hash snapshots by copying the running
// context. Random split points and a snapshot after every update must match
// std, and the snapshot must not disturb the running hash.
test "backend.sha2: random update splits and copy-then-continue snapshots match std" {
    var buf: [2048]u8 = undefined;
    const input = sha2Input(&buf, 0x13800);
    var prng: std.Random.DefaultPrng = .init(0x138000);
    const random = prng.random();
    inline for (sha2_pairs) |pair| {
        const B, const S = pair;
        for (0..200) |_| {
            const len = random.uintAtMost(usize, input.len);
            var b: B = .init(.{});
            var s: S = .init(.{});
            var pos: usize = 0;
            while (pos < len) {
                const n = random.uintAtMost(usize, @min(len - pos, 300));
                b.update(input[pos..][0..n]);
                s.update(input[pos..][0..n]);
                pos += n;

                var snapshot = b;
                try testing.expectEqualSlices(u8, &s.peek(), &snapshot.finalResult());
                try testing.expectEqualSlices(u8, &s.peek(), &b.peek());
            }
            var got: [B.digest_length]u8 = undefined;
            b.final(&got);
            try testing.expectEqualSlices(u8, &s.finalResult(), &got);
        }
    }
}

// RFC 8446 §4.4.1 — a copied context is an independent value: the copy and
// the original diverge on different input without sharing state.
test "backend.sha2: copied contexts diverge independently" {
    inline for (sha2_pairs) |pair| {
        const B, const S = pair;
        var original: B = .init(.{});
        original.update("ClientHello");
        var copy = original;
        copy.update("HelloRetryRequest");
        original.update("ServerHello");

        var want_original: [S.digest_length]u8 = undefined;
        var want_copy: [S.digest_length]u8 = undefined;
        S.hash("ClientHelloServerHello", &want_original, .{});
        S.hash("ClientHelloHelloRetryRequest", &want_copy, .{});
        try testing.expectEqualSlices(u8, &want_original, &original.finalResult());
        try testing.expectEqualSlices(u8, &want_copy, &copy.finalResult());
    }
}

// RFC 2104 §2, RFC 5869 §2 — std's generic HMAC and HKDF instantiated over
// the backend types match the all-std instantiation. Key lengths cover the
// empty key, a digest-sized key, a block-sized key, and a key longer than a
// block (hashed first).
test "backend.sha2: HMAC and HKDF over backend types match std" {
    var buf: [300]u8 = undefined;
    const input = sha2Input(&buf, 0x138000);
    inline for (sha2_pairs) |pair| {
        const B, const S = pair;
        const HmacB = std.crypto.auth.hmac.Hmac(B);
        const HmacS = std.crypto.auth.hmac.Hmac(S);
        const key_lengths = [_]usize{ 0, B.digest_length, B.block_length, B.block_length + 1, 300 };
        for (key_lengths) |key_len| {
            const key = input[0..key_len];
            const msg = input[key_len / 2 ..];
            var got: [HmacB.mac_length]u8 = undefined;
            var want: [HmacS.mac_length]u8 = undefined;
            HmacB.create(&got, msg, key);
            HmacS.create(&want, msg, key);
            try testing.expectEqualSlices(u8, &want, &got);

            const HkdfB = std.crypto.kdf.hkdf.Hkdf(HmacB);
            const HkdfS = std.crypto.kdf.hkdf.Hkdf(HmacS);
            const prk_b = HkdfB.extract(key, msg);
            try testing.expectEqualSlices(u8, &HkdfS.extract(key, msg), &prk_b);
            var okm_b: [3 * B.digest_length + 5]u8 = undefined;
            var okm_s: [3 * S.digest_length + 5]u8 = undefined;
            HkdfB.expand(&okm_b, "tls13 derived", prk_b);
            HkdfS.expand(&okm_s, "tls13 derived", prk_b);
            try testing.expectEqualSlices(u8, &okm_s, &okm_b);
        }
    }
}
