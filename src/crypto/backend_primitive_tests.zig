//! Backend primitive contract tests — run under every linked libcrypto lane.
//!
//! These tests exercise the backend facade (`src/crypto/backend.zig`) directly
//! rather than the higher-level `aead`/`x25519`/`p256`/`signature` wrapper modules.
//! They run under both the OpenSSL and AWS-LC build lanes because
//! `backend.active` is resolved at compile time from the build option, and the
//! test entry point in `src/test.zig` imports this file unconditionally.
//!
//! The goal is a narrow contract: the same known vectors must pass regardless
//! of which libcrypto-family provider is linked. This includes selected
//! facade-direct Wycheproof vectors, but is not a full Wycheproof harness or
//! full provider matrix claim.
const std = @import("std");
const stdx = @import("stdx");
const testing = std.testing;
const assert = std.debug.assert;

const backend = @import("backend.zig");
const certificate = @import("../certificate.zig");
const Certificate = @import("../certificate_parser.zig");
const CipherSuite = @import("../cipher_suite.zig").CipherSuite;
const SignatureScheme = @import("../signature_scheme.zig").SignatureScheme;
const fixtures = @import("fixtures");
const fuzz_compat = @import("../fuzz_compat.zig");

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

// ---------------------------------------------------------------------------
// P-256 ECDH — direct backend.p256 facade
// ---------------------------------------------------------------------------

// SEC 1 §2.3.4 (via RFC 8446 §4.2.8) — P-256 uncompressed SEC1 public key is
// 65 bytes: 0x04 || X || Y. Two parties with fixed scalars must derive the
// same 32-byte shared secret through the backend facade.
test "backend.p256: mutual key agreement with fixed scalars" {
    const alice_scalar: [32]u8 = stdx.fmt.comptimeHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
    const bob_scalar: [32]u8 = stdx.fmt.comptimeHex(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    );

    const alice_priv = try backend.p256.privateKeyFromSecret(&alice_scalar);
    defer backend.p256.freeKey(alice_priv);
    const alice_pub = try backend.p256.rawPublicKeyFromPrivate(alice_priv);

    const bob_priv = try backend.p256.privateKeyFromSecret(&bob_scalar);
    defer backend.p256.freeKey(bob_priv);
    const bob_pub = try backend.p256.rawPublicKeyFromPrivate(bob_priv);

    // Both public keys must be uncompressed SEC1 (0x04 prefix, 65 bytes).
    try testing.expectEqual(@as(u8, 0x04), alice_pub[0]);
    try testing.expectEqual(@as(u8, 0x04), bob_pub[0]);

    const alice_peer = try backend.p256.publicKeyFromRaw(&bob_pub);
    defer backend.p256.freeKey(alice_peer);
    var alice_shared: [32]u8 = undefined;
    try backend.p256.sharedSecretDerive(alice_priv, alice_peer, &alice_shared);

    const bob_peer = try backend.p256.publicKeyFromRaw(&alice_pub);
    defer backend.p256.freeKey(bob_peer);
    var bob_shared: [32]u8 = undefined;
    try backend.p256.sharedSecretDerive(bob_priv, bob_peer, &bob_shared);

    try testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

// SEC 1 §2.3.4 — an uncompressed P-256 public key must start with 0x04. A
// malformed prefix is rejected by the backend facade before any point math.
test "backend.p256: non-04 SEC1 prefix is rejected" {
    const scalar: [32]u8 = @splat(0);
    var fixed_scalar: [32]u8 = scalar;
    fixed_scalar[31] = 1;

    const priv = try backend.p256.privateKeyFromSecret(&fixed_scalar);
    defer backend.p256.freeKey(priv);
    const pub_bytes = try backend.p256.rawPublicKeyFromPrivate(priv);

    // Tamper with the prefix: 0x03 (compressed) is not accepted by this facade.
    var bad_pub = pub_bytes;
    bad_pub[0] = 0x03;

    try testing.expectError(
        error.IdentityElement,
        backend.p256.publicKeyFromRaw(&bad_pub),
    );
}

// SEC 1 §2.3.3 — a point with valid 0x04 prefix but coordinates not on the
// P-256 curve must be rejected. x=1, y=0 does not satisfy the curve equation.
test "backend.p256: off-curve point is rejected" {
    var off_curve: [65]u8 = @splat(0);
    off_curve[0] = 0x04;
    off_curve[32] = 0x01; // x = 1 (big-endian, last byte of X field)

    try testing.expectError(
        error.IdentityElement,
        backend.p256.publicKeyFromRaw(&off_curve),
    );
}

// SEC 1 §3.2.1 — a private key scalar must be in [1, n - 1]. Scalar zero is
// invalid and must not construct a usable backend P-256 key.
test "backend.p256: zero scalar private key is rejected" {
    // `IdentityElement`, not `LibcryptoFailed`: the backend range-checks the
    // scalar against [1, n-1] before any point math, so this rejection is a
    // property of the caller's data — the one rejection a caller may answer
    // by drawing again. Keeping it distinct from the library failing is what
    // stops `KeyPair.generate`'s retry from spinning on an error no draw can
    // fix (#88).
    const scalar: [32]u8 = @splat(0);
    try testing.expectError(
        error.IdentityElement,
        backend.p256.privateKeyFromSecret(&scalar),
    );
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — P-256 ECDH tcId 1, normal case.
// Source: ecdh_secp256r1_test.json. The public key is the SEC1 uncompressed
// point extracted from the Wycheproof SPKI; the private scalar and shared
// secret are taken verbatim from the test vector.
test "backend.p256: Wycheproof tcId 1 shared secret" {
    const scalar: [32]u8 = stdx.fmt.comptimeHex(
        "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
    );
    const peer_pub: [65]u8 = stdx.fmt.comptimeHex(
        "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26" ++
            "ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf",
    );
    const want: [32]u8 = stdx.fmt.comptimeHex(
        "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285",
    );

    const priv = try backend.p256.privateKeyFromSecret(&scalar);
    defer backend.p256.freeKey(priv);
    const peer = try backend.p256.publicKeyFromRaw(&peer_pub);
    defer backend.p256.freeKey(peer);

    var shared: [32]u8 = undefined;
    try backend.p256.sharedSecretDerive(priv, peer, &shared);
    try testing.expectEqualSlices(u8, &want, &shared);
}

// #134 — `publicFromSecret` (one fixed-base multiplication, no EC_KEY) must
// produce the point the checked key construction stores, for every scalar.
test "backend.p256: publicFromSecret matches the checked construction" {
    const scalars = [_][32]u8{
        stdx.fmt.comptimeHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        stdx.fmt.comptimeHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
        stdx.fmt.comptimeHex("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346"),
        // n - 1, the largest valid scalar.
        stdx.fmt.comptimeHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),
    };
    for (&scalars) |*scalar| {
        const priv = try backend.p256.privateKeyFromSecret(scalar);
        defer backend.p256.freeKey(priv);
        const want = try backend.p256.rawPublicKeyFromPrivate(priv);
        const got = try backend.p256.publicFromSecret(scalar);
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

// #134 — an ECDH key built from the scalar alone (no public point) derives
// the Wycheproof tcId 1 secret, and both new entry points keep the SEC 1
// §3.2.1 range check: 0 and n are `IdentityElement` (#88).
test "backend.p256: ecdhKeyFromSecret derives the Wycheproof secret and range-checks" {
    const scalar: [32]u8 = stdx.fmt.comptimeHex(
        "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
    );
    const peer_pub: [65]u8 = stdx.fmt.comptimeHex(
        "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26" ++
            "ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf",
    );
    const want: [32]u8 = stdx.fmt.comptimeHex(
        "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285",
    );
    const ours = try backend.p256.ecdhKeyFromSecret(&scalar);
    defer backend.p256.freeKey(ours);
    const peer = try backend.p256.publicKeyFromRaw(&peer_pub);
    defer backend.p256.freeKey(peer);
    var shared: [32]u8 = undefined;
    try backend.p256.sharedSecretDerive(ours, peer, &shared);
    try testing.expectEqualSlices(u8, &want, &shared);

    const zero: [32]u8 = @splat(0);
    const order: [32]u8 = stdx.fmt.comptimeHex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    for ([_]*const [32]u8{ &zero, &order }) |bad| {
        try testing.expectError(error.IdentityElement, backend.p256.publicFromSecret(bad));
        try testing.expectError(error.IdentityElement, backend.p256.ecdhKeyFromSecret(bad));
    }
}

// The existing deterministic off-curve rejection tests ("backend.p256: off-
// curve point is rejected", "backend.p256: non-04 SEC1 prefix is rejected")
// already cover the boundary where OpenSSL rejects invalid P-256 public keys.
// Wycheproof off-curve vectors (tcId 332+) use all-zero points which cause
// OpenSSL to hang rather than return an error, so they are not usable here.
// Source: ecdh_secp256r1_test.json (tcId 332+).

// ---------------------------------------------------------------------------
// P-384 ECDH — direct backend.p384 facade
// ---------------------------------------------------------------------------

// SEC 1 §2.3.4 (via RFC 8446 §4.2.8) — P-384 uncompressed SEC1 public key is
// 97 bytes: 0x04 || X || Y. Two parties with fixed scalars must derive the
// same 48-byte shared secret through the backend facade.
test "backend.p384: mutual key agreement with fixed scalars" {
    const alice_scalar: [48]u8 = stdx.fmt.comptimeHex(
        "000102030405060708090a0b0c0d0e0f" ++
            "101112131415161718191a1b1c1d1e1f" ++
            "202122232425262728292a2b2c2d2e2f",
    );
    const bob_scalar: [48]u8 = stdx.fmt.comptimeHex(
        "303132333435363738393a3b3c3d3e3f" ++
            "404142434445464748494a4b4c4d4e4f" ++
            "505152535455565758595a5b5c5d5e5f",
    );

    const alice_priv = try backend.p384.privateKeyFromSecret(&alice_scalar);
    defer backend.p384.freeKey(alice_priv);
    const alice_pub = try backend.p384.rawPublicKeyFromPrivate(alice_priv);

    const bob_priv = try backend.p384.privateKeyFromSecret(&bob_scalar);
    defer backend.p384.freeKey(bob_priv);
    const bob_pub = try backend.p384.rawPublicKeyFromPrivate(bob_priv);

    try testing.expectEqual(@as(u8, 0x04), alice_pub[0]);
    try testing.expectEqual(@as(u8, 0x04), bob_pub[0]);

    const alice_peer = try backend.p384.publicKeyFromRaw(&bob_pub);
    defer backend.p384.freeKey(alice_peer);
    var alice_shared: [48]u8 = undefined;
    try backend.p384.sharedSecretDerive(alice_priv, alice_peer, &alice_shared);

    const bob_peer = try backend.p384.publicKeyFromRaw(&alice_pub);
    defer backend.p384.freeKey(bob_peer);
    var bob_shared: [48]u8 = undefined;
    try backend.p384.sharedSecretDerive(bob_priv, bob_peer, &bob_shared);

    try testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

// SEC 1 §2.3.4 — an uncompressed P-384 public key must start with 0x04.
test "backend.p384: non-04 SEC1 prefix is rejected" {
    var scalar: [48]u8 = @splat(0);
    scalar[47] = 1;

    const priv = try backend.p384.privateKeyFromSecret(&scalar);
    defer backend.p384.freeKey(priv);
    const pub_bytes = try backend.p384.rawPublicKeyFromPrivate(priv);

    var bad_pub = pub_bytes;
    bad_pub[0] = 0x03;

    try testing.expectError(
        error.IdentityElement,
        backend.p384.publicKeyFromRaw(&bad_pub),
    );
}

// SEC 1 §2.3.3 — a point with valid 0x04 prefix but coordinates not on the
// P-384 curve must be rejected. x=1, y=0 does not satisfy the curve equation.
test "backend.p384: off-curve point is rejected" {
    var off_curve: [97]u8 = @splat(0);
    off_curve[0] = 0x04;
    off_curve[48] = 0x01; // x = 1 (big-endian, last byte of X field)

    try testing.expectError(
        error.IdentityElement,
        backend.p384.publicKeyFromRaw(&off_curve),
    );
}

// SEC 1 §3.2.1 — a private key scalar must be in [1, n - 1]. Scalar zero is
// invalid and must not construct a usable backend P-384 key.
test "backend.p384: zero scalar private key is rejected" {
    // `IdentityElement` for the same reason as the P-256 case above (#88).
    const scalar: [48]u8 = @splat(0);
    try testing.expectError(
        error.IdentityElement,
        backend.p384.privateKeyFromSecret(&scalar),
    );
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — P-384 ECDH tcId 1, normal case.
// Source: ecdh_secp384r1_test.json. The public key is the SEC1 uncompressed
// point extracted from the Wycheproof SPKI; the private scalar and shared
// secret are taken verbatim from the test vector.
test "backend.p384: Wycheproof tcId 1 shared secret" {
    const scalar: [48]u8 = stdx.fmt.comptimeHex(
        "766e61425b2da9f846c09fc3564b93a6f8603b7392c785165bf20da948c49fd1" ++
            "fb1dee4edd64356b9f21c588b75dfd81",
    );
    const peer_pub: [97]u8 = stdx.fmt.comptimeHex(
        "04790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f" ++
            "791b64a6be15969ffa012dd9185d8796d9b954baa8a75e82df711b3b56eadff6b" ++
            "0f668c3b26b4b1aeb308a1fcc1c680d329a6705025f1c98a0b5e5bfcb163caa",
    );
    const want: [48]u8 = stdx.fmt.comptimeHex(
        "6461defb95d996b24296f5a1832b34db05ed031114fbe7d98d098f93859866e4" ++
            "de1e229da71fef0c77fe49b249190135",
    );

    const priv = try backend.p384.privateKeyFromSecret(&scalar);
    defer backend.p384.freeKey(priv);
    const peer = try backend.p384.publicKeyFromRaw(&peer_pub);
    defer backend.p384.freeKey(peer);

    var shared: [48]u8 = undefined;
    try backend.p384.sharedSecretDerive(priv, peer, &shared);
    try testing.expectEqualSlices(u8, &want, &shared);
}

// The existing deterministic off-curve rejection tests ("backend.p384: off-
// curve point is rejected", "backend.p384: non-04 SEC1 prefix is rejected")
// already cover the boundary where OpenSSL rejects invalid P-384 public keys.
// Wycheproof off-curve vectors (tcId 773+) use all-zero points which cause
// OpenSSL to hang rather than return an error, so they are not usable here.
// Source: ecdh_secp384r1_test.json (tcId 773+).

// ---------------------------------------------------------------------------
// Signature — direct backend.sign facade
// ---------------------------------------------------------------------------
//
// Verification left this facade in #183: every scheme CertificateVerify
// accepts verifies natively, so a peer cannot reach libcrypto through a
// signature. RSA-PSS signs with libcrypto. ECDSA signs in-tree and checks the
// same DER bytes through both the public CertificateVerify verifier and
// libcrypto's independent ECDSA verifier.

const rsa_pss_key_pem = @import("fixtures").rsa_pss_key_pem;

fn rsaPssPublicKeyBits() ![]const u8 {
    const parsed = try Certificate.parse(.{
        .buffer = &fixtures.rsa_pss_cert_der,
        .index = 0,
    });
    return parsed.pubKey();
}

/// Build the CertificateVerify signed content for a transcript hash: the
/// context string followed by the hash, with no separator. RFC 8446 §4.4.3.
fn serverSignedContent(buf: []u8, transcript_hash: []const u8) []const u8 {
    const context: []const u8 = certificate.server_certificate_verify_context;
    const len = context.len + transcript_hash.len;
    assert(buf.len >= len);
    @memcpy(buf[0..context.len], context);
    @memcpy(buf[context.len..len], transcript_hash);
    return buf[0..len];
}

/// Encode a CertificateVerify message around `sig` and verify it the way a
/// client verifies a server's proof of possession.
fn verifyAsServerCertificateVerify(
    sig: []const u8,
    scheme: SignatureScheme,
    pub_key: []const u8,
    transcript_hash: []const u8,
) !void {
    var cv_buf: [640]u8 = undefined;
    const cv = try certificate.encodeCertificateVerify(&cv_buf, scheme, sig);
    try certificate.verifyServerSignature(cv, pub_key, transcript_hash);
}

fn verifyEcdsaDigestWithLibcrypto(
    key: *backend.sign.pkey,
    digest: []const u8,
    sig: []const u8,
) !void {
    _ = c.ERR_set_mark();
    defer _ = c.ERR_pop_to_mark();
    const ec = c.EVP_PKEY_get0_EC_KEY(key) orelse return error.LibcryptoFailed;
    // OpenSSL's legacy declaration omits const from a key it only reads.
    const result = c.ECDSA_verify(
        0,
        digest.ptr,
        @intCast(digest.len),
        sig.ptr,
        @intCast(sig.len),
        @constCast(ec),
    );
    if (result != 1) return error.SignatureVerificationFailed;
}

/// Verify the signature through the native path and through libcrypto's
/// separate implementation of the ECDSA equation over the same digest.
fn verifyEcdsaWithLibcrypto(
    key: *backend.sign.pkey,
    scheme: SignatureScheme,
    msg: []const u8,
    sig: []const u8,
) !void {
    switch (scheme) {
        .ecdsa_secp256r1_sha256 => {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
            try verifyEcdsaDigestWithLibcrypto(key, &digest, sig);
        },
        .ecdsa_secp384r1_sha384 => {
            var digest: [48]u8 = undefined;
            std.crypto.hash.sha2.Sha384.hash(msg, &digest, .{});
            try verifyEcdsaDigestWithLibcrypto(key, &digest, sig);
        },
        else => unreachable,
    }
}

fn verifyEcdsaBoth(
    key: *backend.sign.pkey,
    sig: []const u8,
    scheme: SignatureScheme,
    pub_key: []const u8,
    transcript_hash: []const u8,
    signed_content: []const u8,
) !void {
    try verifyAsServerCertificateVerify(sig, scheme, pub_key, transcript_hash);
    try verifyEcdsaWithLibcrypto(key, scheme, signed_content, sig);
}

// RFC 8446 §4.4.3 — CertificateVerify signs caller-assembled bytes; the
// libcrypto signer and the native verifier must agree on that content.
test "backend.sign: RSA-PSS SHA-256 signature verifies natively" {
    const private_key = try backend.sign.privateKeyFromPem(rsa_pss_key_pem);
    defer backend.sign.freeKey(private_key);
    const pub_key = try rsaPssPublicKeyBits();

    const transcript_hash: [32]u8 = @splat(0x42);
    var content_buf: [160]u8 = undefined;
    const content = serverSignedContent(&content_buf, &transcript_hash);

    var sig_buf: [512]u8 = undefined;
    const scheme: SignatureScheme = .rsa_pss_rsae_sha256;
    const sig = try backend.sign.sign(private_key, scheme, content, &sig_buf, .random);
    try verifyAsServerCertificateVerify(sig, scheme, pub_key, &transcript_hash);
}

// RFC 8446 §4.4.3 — signature verification must reject a tampered signature.
test "backend.sign: RSA-PSS SHA-256 tampered signature is rejected natively" {
    const private_key = try backend.sign.privateKeyFromPem(rsa_pss_key_pem);
    defer backend.sign.freeKey(private_key);
    const pub_key = try rsaPssPublicKeyBits();

    const transcript_hash: [32]u8 = @splat(0x42);
    var content_buf: [160]u8 = undefined;
    const content = serverSignedContent(&content_buf, &transcript_hash);

    var sig_buf: [512]u8 = undefined;
    const scheme: SignatureScheme = .rsa_pss_rsae_sha256;
    const sig = try backend.sign.sign(private_key, scheme, content, &sig_buf, .random);
    sig_buf[sig.len - 1] ^= 0xff;

    try testing.expectError(
        error.SignatureVerificationFailed,
        verifyAsServerCertificateVerify(sig, scheme, pub_key, &transcript_hash),
    );
}

// RFC 8446 §4.4.3 — RSA-PSS SHA-384 is advertised for CertificateVerify and
// must round-trip through the signer and the native verifier.
test "backend.sign: RSA-PSS SHA-384 signature verifies natively and tamper is rejected" {
    const private_key = try backend.sign.privateKeyFromPem(rsa_pss_key_pem);
    defer backend.sign.freeKey(private_key);
    const pub_key = try rsaPssPublicKeyBits();

    const transcript_hash: [48]u8 = @splat(0x24);
    var content_buf: [160]u8 = undefined;
    const content = serverSignedContent(&content_buf, &transcript_hash);

    var sig_buf: [512]u8 = undefined;
    const scheme: SignatureScheme = .rsa_pss_rsae_sha384;
    const sig = try backend.sign.sign(private_key, scheme, content, &sig_buf, .random);
    try verifyAsServerCertificateVerify(sig, scheme, pub_key, &transcript_hash);

    sig_buf[sig.len - 1] ^= 0xff;
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifyAsServerCertificateVerify(sig, scheme, pub_key, &transcript_hash),
    );
}

// RFC 8446 §4.4.3 + RFC 6979 §3.2 — random and deterministic in-tree P-256
// signatures verify through both independent implementations.
test "backend.sign: ECDSA P-256 signatures verify natively and through libcrypto" {
    const scalar: [32]u8 = stdx.fmt.comptimeHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );

    const priv = try backend.sign.privateKeyFromP256Scalar(&scalar);
    defer backend.sign.freeKey(priv);

    // The native verifier takes the certificate's SubjectPublicKey bits
    // directly, so the SEC1 encoding is the whole key.
    const pub_bytes = try backend.p256.rawPublicKeyFromPrivate(priv);

    const transcript_hash: [32]u8 = @splat(0x99);
    var content_buf: [160]u8 = undefined;
    const content = serverSignedContent(&content_buf, &transcript_hash);

    var sig_buf: [128]u8 = undefined;
    const scheme: SignatureScheme = .ecdsa_secp256r1_sha256;
    const sig = try backend.sign.sign(priv, scheme, content, &sig_buf, .random);
    try verifyEcdsaBoth(priv, sig, scheme, &pub_bytes, &transcript_hash, content);

    var deterministic_buf: [128]u8 = undefined;
    const deterministic = try backend.sign.sign(
        priv,
        scheme,
        content,
        &deterministic_buf,
        .deterministic,
    );
    try verifyEcdsaBoth(priv, deterministic, scheme, &pub_bytes, &transcript_hash, content);
    var again_buf: [128]u8 = undefined;
    const again = try backend.sign.sign(priv, scheme, content, &again_buf, .deterministic);
    try testing.expectEqualSlices(u8, deterministic, again);
}

// RFC 8446 §4.4.3 — ECDSA signature verification must reject a tampered signature.
test "backend.sign: ECDSA P-256 SHA-256 tampered signature is rejected natively" {
    const scalar: [32]u8 = stdx.fmt.comptimeHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );

    const priv = try backend.sign.privateKeyFromP256Scalar(&scalar);
    defer backend.sign.freeKey(priv);

    const pub_bytes = try backend.p256.rawPublicKeyFromPrivate(priv);

    const transcript_hash: [32]u8 = @splat(0x99);
    var content_buf: [160]u8 = undefined;
    const content = serverSignedContent(&content_buf, &transcript_hash);

    var sig_buf: [128]u8 = undefined;
    const sig = try backend.sign.sign(priv, .ecdsa_secp256r1_sha256, content, &sig_buf, .random);
    sig_buf[0] ^= 0xff;

    try testing.expectError(
        error.SignatureVerificationFailed,
        verifyAsServerCertificateVerify(sig, .ecdsa_secp256r1_sha256, &pub_bytes, &transcript_hash),
    );
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifyEcdsaWithLibcrypto(priv, .ecdsa_secp256r1_sha256, content, sig),
    );
}

// RFC 8446 §4.4.3 + RFC 6979 §3.2 — random and deterministic in-tree P-384
// signatures verify through both independent implementations, and tampering
// with the native signature still fails native verification.
test "backend.sign: ECDSA P-384 signatures verify natively and through libcrypto" {
    const scalar: [48]u8 = stdx.fmt.comptimeHex(
        "000102030405060708090a0b0c0d0e0f" ++
            "101112131415161718191a1b1c1d1e1f" ++
            "202122232425262728292a2b2c2d2e2f",
    );

    const priv = try backend.p384.privateKeyFromSecret(&scalar);
    defer backend.p384.freeKey(priv);

    const pub_bytes = try backend.p384.rawPublicKeyFromPrivate(priv);

    const transcript_hash: [48]u8 = @splat(0x66);
    var content_buf: [160]u8 = undefined;
    const content = serverSignedContent(&content_buf, &transcript_hash);

    var sig_buf: [160]u8 = undefined;
    const scheme: SignatureScheme = .ecdsa_secp384r1_sha384;
    const sig = try backend.sign.sign(priv, scheme, content, &sig_buf, .random);
    try verifyEcdsaBoth(priv, sig, scheme, &pub_bytes, &transcript_hash, content);

    var deterministic_buf: [160]u8 = undefined;
    const deterministic = try backend.sign.sign(
        priv,
        scheme,
        content,
        &deterministic_buf,
        .deterministic,
    );
    try verifyEcdsaBoth(priv, deterministic, scheme, &pub_bytes, &transcript_hash, content);
    var again_buf: [160]u8 = undefined;
    const again = try backend.sign.sign(priv, scheme, content, &again_buf, .deterministic);
    try testing.expectEqualSlices(u8, deterministic, again);

    sig_buf[0] ^= 0xff;
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifyAsServerCertificateVerify(sig, .ecdsa_secp384r1_sha384, &pub_bytes, &transcript_hash),
    );
}

// RFC 8446 §4.2.3 — rsa_pss_rsae_sha512 is a legal CertificateVerify scheme
// even though the default capability tables do not advertise it, so the
// verifier must handle it. SHA-512 needs a 2048-bit key: emLen has to hold
// hLen + sLen + 2.
test "backend.sign: RSA-PSS SHA-512 signature verifies natively" {
    const private_key = try backend.sign.privateKeyFromPem(rsa_pss_key_pem);
    defer backend.sign.freeKey(private_key);
    const pub_key = try rsaPssPublicKeyBits();

    const transcript_hash: [64]u8 = @splat(0x11);
    var content_buf: [192]u8 = undefined;
    const content = serverSignedContent(&content_buf, &transcript_hash);

    var sig_buf: [512]u8 = undefined;
    const scheme: SignatureScheme = .rsa_pss_rsae_sha512;
    const sig = try backend.sign.sign(private_key, scheme, content, &sig_buf, .random);
    try verifyAsServerCertificateVerify(sig, scheme, pub_key, &transcript_hash);
}

// RFC 8446 §4.4.3 — the signing output buffer must be large enough or the
// backend returns BufferTooShort without truncation.
test "backend.sign: BufferTooShort on undersized output" {
    const key = try backend.sign.privateKeyFromPem(rsa_pss_key_pem);
    defer backend.sign.freeKey(key);

    var sig_buf: [1]u8 = undefined;
    try testing.expectError(
        error.BufferTooShort,
        backend.sign.sign(key, .rsa_pss_rsae_sha256, "test message", &sig_buf, .random),
    );
}

// RFC 8446 §4.2.3 — the ECDSA scheme names both the curve and hash. A P-256
// key cannot sign as P-384, even though its scalar fits in either width.
test "backend.sign: ECDSA curve mismatch is a named failure" {
    const scalar: [32]u8 = @splat(0);
    var fixed: [32]u8 = scalar;
    fixed[31] = 1;
    const priv = try backend.sign.privateKeyFromP256Scalar(&fixed);
    defer backend.sign.freeKey(priv);

    var sig_buf: [104]u8 = undefined;
    try testing.expectError(
        error.LibcryptoFailed,
        backend.sign.sign(priv, .ecdsa_secp384r1_sha384, "test message", &sig_buf, .deterministic),
    );
}

// RFC 8446 §4.2.3 — the CertificateVerify scheme must be compatible with the
// signing key; an ECDSA key with an RSA-PSS scheme is a backend failure.
test "backend.sign: key/scheme mismatch is a libcrypto failure" {
    const scalar: [32]u8 = @splat(0);
    var fixed: [32]u8 = scalar;
    fixed[31] = 1;
    const priv = try backend.sign.privateKeyFromP256Scalar(&fixed);
    defer backend.sign.freeKey(priv);

    var sig_buf: [256]u8 = undefined;
    try testing.expectError(
        error.LibcryptoFailed,
        backend.sign.sign(priv, .rsa_pss_rsae_sha256, "test message", &sig_buf, .random),
    );
}

// ---------------------------------------------------------------------------
// Signature — the signer/verifier differential, fuzzed
// ---------------------------------------------------------------------------
//
// The hand-written tests above check a handful of vectors. This target runs the
// same agreement over fuzz-chosen keys and content: libcrypto signs, the
// shipped in-tree verifier verifies, and the same signature fails after one bit
// changes. A disagreement is a test failure rather than a crash, so the fuzzer
// reports it as a find. That is the contract: the verifier holds no secrets and
// every signature the C signer produces must verify.
//
// Input: a case selector byte, then the private-key seed for the ECDSA cases
// (32 octets for P-256, 48 for P-384; the RSA cases use the fixture key), then
// the transcript hash, clamped to the 64 octets the signed-content buffer holds.
// Run with `just fuzz 100K`.
const differential_schemes = [_]SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
};

/// Transcript-hash octets the verifier's signed-content buffer holds past the
/// context string. Every hash a TLS 1.3 suite uses fits.
const differential_transcript_max = 64;

/// Sign with a deterministic nonce where the lane supports it, so the signature
/// is a function of the fuzzer's input and a crash input reproduces. The
/// provider can still refuse the parameter at run time.
fn signDeterministically(
    key: *backend.sign.pkey,
    scheme: SignatureScheme,
    content: []const u8,
    out: []u8,
) backend.sign.SignError![]const u8 {
    const ecdsa = scheme == .ecdsa_secp256r1_sha256 or scheme == .ecdsa_secp384r1_sha384;
    if (backend.sign.supportsDeterministicNonce() and ecdsa) {
        if (backend.sign.sign(key, scheme, content, out, .deterministic)) |sig| {
            return sig;
        } else |err| switch (err) {
            error.DeterministicNonceUnsupported => {},
            else => return err,
        }
    }
    return backend.sign.sign(key, scheme, content, out, .random);
}

fn expectSignerVerifierAgreement(
    key: *backend.sign.pkey,
    scheme: SignatureScheme,
    pub_key: []const u8,
    content: []const u8,
    transcript_hash: []const u8,
    sig_buf: []u8,
) !void {
    const sig = try signDeterministically(key, scheme, content, sig_buf);
    try verifyAsServerCertificateVerify(sig, scheme, pub_key, transcript_hash);

    var tampered: [512]u8 = undefined;
    @memcpy(tampered[0..sig.len], sig);
    tampered[sig.len - 1] ^= 0x01;
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifyAsServerCertificateVerify(tampered[0..sig.len], scheme, pub_key, transcript_hash),
    );
}

fn fuzzSignVerifyDifferential(_: void, input: []const u8) anyerror!void {
    if (input.len == 0) return;
    const scheme = differential_schemes[input[0] % differential_schemes.len];
    const seed_len: usize = switch (scheme) {
        .ecdsa_secp256r1_sha256 => 32,
        .ecdsa_secp384r1_sha384 => 48,
        else => 0,
    };
    if (input.len < 1 + seed_len) return;
    const rest = input[1 + seed_len ..];
    const transcript_hash = rest[0..@min(rest.len, differential_transcript_max)];

    const context = certificate.server_certificate_verify_context;
    var content_buf: [context.len + differential_transcript_max]u8 = undefined;
    const content = serverSignedContent(&content_buf, transcript_hash);

    var sig_buf: [512]u8 = undefined;
    switch (scheme) {
        .ecdsa_secp256r1_sha256 => {
            // Zero and out-of-range scalars cannot form a key. Skip them
            // instead of reporting an expected key-construction error.
            const key = backend.sign.privateKeyFromP256Scalar(input[1..33]) catch return;
            defer backend.sign.freeKey(key);
            const pub_key = try backend.p256.rawPublicKeyFromPrivate(key);
            try expectSignerVerifierAgreement(
                key,
                scheme,
                &pub_key,
                content,
                transcript_hash,
                &sig_buf,
            );
        },
        .ecdsa_secp384r1_sha384 => {
            const key = backend.p384.privateKeyFromSecret(input[1..49]) catch return;
            defer backend.sign.freeKey(key);
            const pub_key = try backend.p384.rawPublicKeyFromPrivate(key);
            try expectSignerVerifierAgreement(
                key,
                scheme,
                &pub_key,
                content,
                transcript_hash,
                &sig_buf,
            );
        },
        else => {
            const key = try backend.sign.privateKeyFromPem(rsa_pss_key_pem);
            defer backend.sign.freeKey(key);
            const pub_key = try rsaPssPublicKeyBits();
            try expectSignerVerifierAgreement(
                key,
                scheme,
                pub_key,
                content,
                transcript_hash,
                &sig_buf,
            );
        },
    }
}

fn encodeDifferentialInput(
    buf: []u8,
    scheme: SignatureScheme,
    key_seed: []const u8,
    transcript_hash: []const u8,
) []const u8 {
    const total = 1 + key_seed.len + transcript_hash.len;
    assert(buf.len >= total);
    const tag = std.mem.findScalar(SignatureScheme, &differential_schemes, scheme) orelse
        unreachable;
    buf[0] = @intCast(tag);
    @memcpy(buf[1..][0..key_seed.len], key_seed);
    @memcpy(buf[1 + key_seed.len ..][0..transcript_hash.len], transcript_hash);
    return buf[0..total];
}

// RFC 8446 §4.4.3 — one valid seed per case uses the deterministic scalars
// from the hand-written tests. Zero and all-ones scalars must return without a
// finding. The ordinary test build replays the whole corpus.
test "fuzz: libcrypto-signed CertificateVerify verifies in-tree" {
    const p256_scalar: [32]u8 = stdx.fmt.comptimeHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
    const p384_scalar: [48]u8 = stdx.fmt.comptimeHex(
        "000102030405060708090a0b0c0d0e0f" ++
            "101112131415161718191a1b1c1d1e1f" ++
            "202122232425262728292a2b2c2d2e2f",
    );
    const sha256_hash: [32]u8 = @splat(0x42);
    const sha384_hash: [48]u8 = @splat(0x66);
    const sha512_hash: [64]u8 = @splat(0x11);

    const zero_p256: [32]u8 = @splat(0);
    const max_p256: [32]u8 = @splat(0xff);
    const zero_p384: [48]u8 = @splat(0);
    const max_p384: [48]u8 = @splat(0xff);

    var storage: [9][160]u8 = undefined;
    var corpus: [9][]const u8 = undefined;
    corpus[0] = encodeDifferentialInput(
        &storage[0],
        .ecdsa_secp256r1_sha256,
        &p256_scalar,
        &sha256_hash,
    );
    corpus[1] = encodeDifferentialInput(
        &storage[1],
        .ecdsa_secp384r1_sha384,
        &p384_scalar,
        &sha384_hash,
    );
    corpus[2] = encodeDifferentialInput(&storage[2], .rsa_pss_rsae_sha256, "", &sha256_hash);
    corpus[3] = encodeDifferentialInput(&storage[3], .rsa_pss_rsae_sha384, "", &sha384_hash);
    corpus[4] = encodeDifferentialInput(&storage[4], .rsa_pss_rsae_sha512, "", &sha512_hash);
    corpus[5] = encodeDifferentialInput(&storage[5], .ecdsa_secp256r1_sha256, &zero_p256, "");
    corpus[6] = encodeDifferentialInput(&storage[6], .ecdsa_secp256r1_sha256, &max_p256, "");
    corpus[7] = encodeDifferentialInput(&storage[7], .ecdsa_secp384r1_sha384, &zero_p384, "");
    corpus[8] = encodeDifferentialInput(&storage[8], .ecdsa_secp384r1_sha384, &max_p384, "");

    try fuzz_compat.fuzzBytes(fuzzSignVerifyDifferential, {}, .{ .corpus = &corpus });
}

// ---------------------------------------------------------------------------
// Error-queue hygiene (#88 finding 2) — a public backend wrapper owns the
// libcrypto error-queue entries it pushes and preserves the caller's
// ---------------------------------------------------------------------------
//
// Failed libcrypto calls may push per-thread error-queue entries. Nothing in
// tls reads the queue, so without a guard every attacker-reachable failure
// (malformed key_share, bad CertificateVerify, failed record decrypt) leaves
// residue that persists for the life of the thread. Every outermost public
// fallible wrapper — AEAD seal/open included — brackets its libcrypto calls
// with ERR_set_mark/ERR_pop_to_mark (see backend_openssl.zig for the bounds,
// including the DER/PEM key-load caveat on BoringSSL-family lanes). These
// tests pin the contract through the facade so they run under every backend
// lane.

const c = @import("c_openssl.zig").openssl;
const c_openssl = @import("c_openssl.zig");

/// A malformed uncompressed P-256 point (0x04 || 0xff×64): the same shape an
/// attacker sends in a bad key_share. Rejected by `o2i_ECPublicKey`.
fn malformedP256Point() [65]u8 {
    var point: [65]u8 = @splat(0xff);
    point[0] = 0x04;
    return point;
}

/// Push real caller-owned entries with a failed libcrypto call of the
/// embedder's own (garbage DER through d2i_AutoPrivateKey), so preservation
/// is proven against genuine queue state, not synthetic plumbing.
fn pushCallerQueueEntries() void {
    const bad_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 }; // Truncated DER.
    var ptr: ?[*]const u8 = &bad_der;
    _ = c.d2i_AutoPrivateKey(null, &ptr, bad_der.len);
}

/// libcrypto ring capacity per thread (16 slots, 15 usable) — the loop bound
/// for draining. `ERR_get_error` pops the oldest entry first, so the drained
/// sequence is the queue's FIFO order.
const queue_capacity = 16;

fn drainQueueCodes(codes: *[queue_capacity]u64) usize {
    var count: usize = 0;
    while (count < queue_capacity) : (count += 1) {
        const code = c.ERR_get_error();
        if (code == 0) return count;
        codes[count] = @intCast(code);
    }
    return count;
}

/// The exact preservation contract: the queue as the wrapper left it (captured
/// FIRST, before anything clears or pushes) must equal the FIFO code sequence
/// of one fresh caller push on a quiet queue. Entries the wrapper pushed must
/// be gone; entries the caller pushed must all survive.
fn expectQueueMatchesCallerResidue() !void {
    // Capture what the wrapper left before touching the queue: draining is
    // destructive, so any later clear/push would destroy the evidence.
    var got: [queue_capacity]u64 = undefined;
    const got_count = drainQueueCodes(&got);

    // Canonical FIFO sequence of one fresh caller push on a quiet queue.
    c.ERR_clear_error();
    pushCallerQueueEntries();
    var want: [queue_capacity]u64 = undefined;
    const want_count = drainQueueCodes(&want);
    try testing.expect(want_count > 0);

    try testing.expectEqual(want_count, got_count);
    try testing.expectEqualSlices(u64, want[0..want_count], got[0..got_count]);
}

// #88 finding 2 — a handled backend failure must leave the error queue as it
// found it; residue would otherwise accumulate for the thread's lifetime.
test "backend error-queue hygiene: malformed EC public key leaves no residue (#88)" {
    c.ERR_clear_error();
    const point = malformedP256Point();

    try testing.expectError(error.IdentityElement, backend.p256.publicKeyFromRaw(&point));
    try testing.expect(c.ERR_get_error() == 0);
}

// #88 finding 2 — pre-existing caller entries (an embedder's own unread
// errors) must survive a failing tls wrapper call, and the wrapper's own
// entries must not linger above them.
test "backend error-queue hygiene: caller queue entries survive a failing wrapper (#88)" {
    c.ERR_clear_error();
    pushCallerQueueEntries();
    const point = malformedP256Point();
    try testing.expectError(error.IdentityElement, backend.p256.publicKeyFromRaw(&point));

    try expectQueueMatchesCallerResidue();
}

// #88 finding 2 — the guard is only safe at outermost wrappers: BoringSSL
// family queues mark with a per-entry boolean flag, so a nested mark/pop
// pair would let the outer pop drain the caller's entries. This pins the
// non-nesting rule on the one wrapper that would nest
// (privateKeyFromP256Scalar → p256PrivateKeyFromSecret).
test "backend error-queue hygiene: scalar key load does not nest guards (#88)" {
    c.ERR_clear_error();
    pushCallerQueueEntries();
    const zero_scalar: [32]u8 = @splat(0);
    try testing.expectError(
        error.LibcryptoFailed,
        backend.sign.privateKeyFromP256Scalar(&zero_scalar),
    );

    try expectQueueMatchesCallerResidue();
}

// #88 finding 2 — every round must return the queue empty. 32 rounds (> the
// 16-slot ring) give a leaked or stale mark room to manifest: a mark that is
// set but never popped would make a later round's errqExit stop above the
// residue instead of draining it.
test "backend error-queue hygiene: repeated failures leave the queue empty each round (#88)" {
    c.ERR_clear_error();
    const point = malformedP256Point();

    var round: usize = 0;
    while (round < 32) : (round += 1) {
        try testing.expectError(error.IdentityElement, backend.p256.publicKeyFromRaw(&point));
        try testing.expect(c.ERR_get_error() == 0);
    }
}

// #88 finding 2 — pins over-drain on the success path: a successful guarded
// call must leave the caller's entries intact (red if errqExit ever clears
// the whole queue). No current wrapper pushes on success, so this test does
// not distinguish defer from errdefer — the defer choice is a documented
// forward-looking contract in backend_openssl.zig, not a pinned behavior.
test "backend error-queue hygiene: successful key load preserves caller entries (#88)" {
    c.ERR_clear_error();
    pushCallerQueueEntries();
    // Any in-range scalar: 0x0101…01 < the P-256 group order.
    const scalar: [32]u8 = @splat(0x01);
    const key = try backend.p256.privateKeyFromSecret(&scalar);
    defer backend.p256.freeKey(key);

    try expectQueueMatchesCallerResidue();
}

// #88 finding 2 — the per-record decrypt path is guarded like every other
// outermost wrapper: a failed record decrypt must leave nothing behind. On
// lanes whose EVP pushes on a bad tag (BoringSSL-family) this is red without
// the guard; OpenSSL's EVP pushes nothing on a bad tag, so there the
// assertion is vacuous and the fork lanes carry the red.
test "backend error-queue hygiene: failed record decrypt leaves no residue (#88)" {
    inline for (backend.capabilities.cipher_suites) |suite| {
        c.ERR_clear_error();
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
        try testing.expect(c.ERR_get_error() == 0);
    }
}

// #88 finding 2 — the exact preservation contract on the per-record path:
// after a failed decrypt the queue holds exactly the caller's entries and
// nothing above them. Red under over-drain (an unconditional clear wipes the
// caller's entries) and, on lanes whose EVP pushes on a bad tag, under guard
// removal.
test "backend error-queue hygiene: failed decrypt preserves caller entries exactly (#88)" {
    c.ERR_clear_error();
    pushCallerQueueEntries();

    const key_bytes: [keyLenForSuite(.aes_128_gcm_sha256)]u8 = @splat(0xab);
    const nonce: [backend.aead.nonce_len]u8 = @splat(0xcd);
    const plaintext = "backend-aead-contract";
    var ctx: backend.aead.Context = try backend.aead.init(.aes_128_gcm_sha256, &key_bytes);
    defer backend.aead.deinit(&ctx);

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [backend.aead.tag_len]u8 = undefined;
    try backend.aead.encrypt(&ctx, &ciphertext, &tag, plaintext, "", &nonce);

    tag[0] ^= 0xff;
    var decrypted: [plaintext.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        backend.aead.decrypt(&ctx, &decrypted, &ciphertext, &tag, "", &nonce),
    );

    try expectQueueMatchesCallerResidue();
}

// #88 finding 2 — pins the actual lane behavior for DER key loads. The
// BoringSSL-family d2i key parsers call ERR_clear_error between parse
// fallbacks (aws-lc 5.5.0 evp_asn1.c, boringssl evp_asn1.cc), destroying
// pre-existing caller entries — and the guard's mark — before errqExit
// runs: caller preservation is impossible on that path there, and the
// pinned result is an empty queue (the wrapper leaves no residue of its
// own). OpenSSL's d2i path does not clear between fallbacks, so the
// caller's entries survive exactly there.
test "backend error-queue hygiene: DER key load preservation is lane-dependent (#88)" {
    c.ERR_clear_error();
    pushCallerQueueEntries();
    const bad_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 }; // Truncated DER.
    try testing.expectError(
        error.LibcryptoFailed,
        backend.sign.privateKeyFromDer(&bad_der),
    );

    if (comptime c_openssl.is_boringssl_family) {
        try testing.expect(c.ERR_get_error() == 0);
    } else {
        try expectQueueMatchesCallerResidue();
    }
}

// #88 finding 2 / #112 — scheme inference is an outermost guarded wrapper;
// a successful inference must leave the caller's queue entries intact.
test "backend error-queue hygiene: scheme inference preserves caller entries (#112)" {
    c.ERR_clear_error();
    pushCallerQueueEntries();
    const scalar: [32]u8 = @splat(0x01);
    const key = try backend.sign.privateKeyFromP256Scalar(&scalar);
    defer backend.sign.freeKey(key);

    const scheme = try backend.sign.keyScheme(key);
    try testing.expectEqual(SignatureScheme.ecdsa_secp256r1_sha256, scheme);

    try expectQueueMatchesCallerResidue();
}

// #88 finding 2 / #114 — the declined encrypted-PEM load is an outermost
// guarded wrapper: two failures on a quiet queue must leave it empty, so an
// unattended startup that keeps retrying encrypted keys cannot accumulate
// residue for the life of the thread. The guard pops every entry the provider
// queued on this path (removing it turns this test red). Caller preservation
// here is the same lane-dependent caveat as the DER loads above, so this pins
// only the residue axis.
test "backend error-queue hygiene: declined encrypted PEM loads leave no residue (#114)" {
    const encrypted_pems = [_][]const u8{
        fixtures.rsa_pss_key_encrypted_pkcs8_pem,
        fixtures.rsa_pss_key_encrypted_legacy_pem,
    };
    for (encrypted_pems) |pem| {
        c.ERR_clear_error();
        try testing.expectError(
            error.LibcryptoFailed,
            backend.sign.privateKeyFromPem(pem),
        );
        try testing.expect(c.ERR_get_error() == 0);
    }
}

// #88 finding 2 / #113 — a clean cert/key mismatch pushes an error-queue
// entry on every lane (X509_R_KEY_VALUES_MISMATCH) and the guard pops it,
// so the wrapper leaves no residue of its own. Caller preservation is
// lane-dependent, like the DER key loads: aws-lc's d2i_X509 clears the
// queue during SPKI conversion on every parse (x_pubkey.c reaches its
// ERR_clear_error unconditionally, even on success), so pre-existing
// caller entries cannot survive there and the pinned result is an empty
// queue. BoringSSL clears only on the SPKI-decode-failure path, and
// OpenSSL uses counted marks, so on both of those lanes the caller's
// entries survive exactly.
test "backend error-queue hygiene: cert/key mismatch preservation is lane-dependent (#113)" {
    c.ERR_clear_error();
    pushCallerQueueEntries();
    const scalar: [32]u8 = @splat(0x01);
    const key = try backend.sign.privateKeyFromP256Scalar(&scalar);
    defer backend.sign.freeKey(key);

    try testing.expect(
        try backend.sign.privateKeyPairsWithCertificate(key, &fixtures.rsa_pss_cert_der) == false,
    );

    if (comptime c_openssl.family == .@"aws-lc") {
        try testing.expect(c.ERR_get_error() == 0);
    } else {
        try expectQueueMatchesCallerResidue();
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
