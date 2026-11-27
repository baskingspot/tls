//! TLS certificate and CertificateVerify differentials against libcrypto.
const std = @import("std");
const stdx = @import("stdx");
const testing = std.testing;
const assert = std.debug.assert;

const backend = @import("crypto");
const certificate = @import("../certificate.zig");
const tls_signature = @import("../signature.zig");
const Certificate = @import("../certificate_parser.zig");
const SignatureAlgorithm = backend.SignatureAlgorithm;
const fixtures = @import("fixtures");
const fuzz_compat = @import("../fuzz_compat.zig");
const c = @import("openssl_c");

const rsa_pss_key_pem = @import("fixtures").rsa_pss_key_pem;

fn rsaPssPublicKeyBits() ![]const u8 {
    const parsed = try Certificate.parse(.{
        .buffer = &fixtures.rsa_pss_cert_der,
        .index = 0,
    });
    return parsed.pubKey();
}

fn verifyCertificateWithLibcrypto(subject_der: []const u8, issuer_der: []const u8) !void {
    _ = c.ERR_set_mark();
    defer _ = c.ERR_pop_to_mark();
    var subject_ptr: ?[*]const u8 = subject_der.ptr;
    const subject = c.d2i_X509(null, &subject_ptr, @intCast(subject_der.len)) orelse
        return error.InvalidEncoding;
    defer c.X509_free(subject);
    if (subject_ptr != subject_der.ptr + subject_der.len) return error.InvalidEncoding;

    var issuer_ptr: ?[*]const u8 = issuer_der.ptr;
    const issuer = c.d2i_X509(null, &issuer_ptr, @intCast(issuer_der.len)) orelse
        return error.InvalidEncoding;
    defer c.X509_free(issuer);
    if (issuer_ptr != issuer_der.ptr + issuer_der.len) return error.InvalidEncoding;

    const public_key = c.X509_get0_pubkey(issuer) orelse return error.LibcryptoFailed;
    if (c.X509_verify(subject, public_key) != 1) return error.LibcryptoFailed;
}

/// Check one real certificate signature through both implementations, then
/// flip its final signature octet and require the same rejection from both.
fn expectCertificateSignatureDifferential(subject_der: []const u8, issuer_der: []const u8) !void {
    const subject = try Certificate.parse(.{ .buffer = subject_der, .index = 0 });
    const issuer = try Certificate.parse(.{ .buffer = issuer_der, .index = 0 });
    try subject.verify(issuer, fixtures.public_chain_now_sec);
    try verifyCertificateWithLibcrypto(subject_der, issuer_der);

    var tampered_buf: [4096]u8 = undefined;
    @memcpy(tampered_buf[0..subject_der.len], subject_der);
    const tampered_der = tampered_buf[0..subject_der.len];
    tampered_der[tampered_der.len - 1] ^= 1;
    const tampered = try Certificate.parse(.{ .buffer = tampered_der, .index = 0 });
    try testing.expectError(
        error.CertificateSignatureInvalid,
        tampered.verify(issuer, fixtures.public_chain_now_sec),
    );
    try testing.expectError(
        error.LibcryptoFailed,
        verifyCertificateWithLibcrypto(tampered_der, issuer_der),
    );
}

// RFC 5280 §6.1, RFC 8017 §8.2 — every signature in the three captured
// chains agrees with libcrypto. The cross-root-to-issuer rows exercise RSA;
// the remaining rows pin the same accept/reject behavior for ECDSA links.
test "certificate signatures: captured public chains match libcrypto and reject tampering" {
    const cases = [_][2][]const u8{
        .{ &fixtures.public_google_leaf_der, &fixtures.public_google_intermediate_der },
        .{ &fixtures.public_google_intermediate_der, &fixtures.public_gts_cross_root_der },
        .{ &fixtures.public_gts_cross_root_der, &fixtures.public_globalsign_root_der },
        .{ &fixtures.public_cloudflare_leaf_der, &fixtures.public_cloudflare_intermediate_der },
        .{ &fixtures.public_cloudflare_intermediate_der, &fixtures.public_gts_cross_root_der },
        .{ &fixtures.public_gts_cross_root_der, &fixtures.public_globalsign_root_der },
        .{ &fixtures.public_example_leaf_der, &fixtures.public_example_intermediate_der },
        .{ &fixtures.public_example_intermediate_der, &fixtures.public_example_transit_der },
        .{ &fixtures.public_example_transit_der, &fixtures.public_example_cross_root_der },
        .{ &fixtures.public_example_cross_root_der, &fixtures.public_aaa_root_der },
    };
    for (cases) |case| try expectCertificateSignatureDifferential(case[0], case[1]);
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
    scheme: SignatureAlgorithm,
    pub_key: []const u8,
    transcript_hash: []const u8,
) !void {
    var cv_buf: [640]u8 = undefined;
    const cv = try certificate.encodeCertificateVerify(
        &cv_buf,
        tls_signature.fromProvider(scheme),
        sig,
    );
    try certificate.verifyServerSignature(cv, pub_key, transcript_hash);
}

const differential_schemes = [_]SignatureAlgorithm{
    .ecdsa_p256_sha256,
    .ecdsa_p384_sha384,
    .rsa_pss_sha256,
    .rsa_pss_sha384,
    .rsa_pss_sha512,
};

/// Transcript-hash octets the verifier's signed-content buffer holds past the
/// context string. Every hash a TLS 1.3 suite uses fits.
const differential_transcript_max = 64;

/// Deterministic ECDSA makes a crash input reproduce on every backend. RSA-PSS
/// uses its random nonce construction.
fn signDeterministically(
    key: backend.sign.pkey,
    scheme: SignatureAlgorithm,
    content: []const u8,
    out: []u8,
) backend.sign.SignError![]const u8 {
    const nonce_mode: backend.sign.NonceMode = switch (scheme) {
        .ecdsa_p256_sha256, .ecdsa_p384_sha384 => .deterministic,
        else => .random,
    };
    return backend.sign.sign(key, scheme, content, out, nonce_mode);
}

fn expectSignerVerifierAgreement(
    key: backend.sign.pkey,
    scheme: SignatureAlgorithm,
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
        .ecdsa_p256_sha256 => 32,
        .ecdsa_p384_sha384 => 48,
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
        .ecdsa_p256_sha256 => {
            // Zero and out-of-range scalars cannot form a key. Skip them
            // instead of reporting an expected key-construction error.
            var key = backend.sign.privateKeyFromP256Scalar(input[1..33]) catch return;
            defer backend.sign.freeKey(&key);
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
        .ecdsa_p384_sha384 => {
            var key = backend.p384.privateKeyFromSecret(input[1..49]) catch return;
            defer backend.sign.freeKey(&key);
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
            var key = try backend.sign.privateKeyFromPem(rsa_pss_key_pem);
            defer backend.sign.freeKey(&key);
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
    scheme: SignatureAlgorithm,
    key_seed: []const u8,
    transcript_hash: []const u8,
) []const u8 {
    const total = 1 + key_seed.len + transcript_hash.len;
    assert(buf.len >= total);
    const tag = std.mem.findScalar(SignatureAlgorithm, &differential_schemes, scheme) orelse
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
        .ecdsa_p256_sha256,
        &p256_scalar,
        &sha256_hash,
    );
    corpus[1] = encodeDifferentialInput(
        &storage[1],
        .ecdsa_p384_sha384,
        &p384_scalar,
        &sha384_hash,
    );
    corpus[2] = encodeDifferentialInput(&storage[2], .rsa_pss_sha256, "", &sha256_hash);
    corpus[3] = encodeDifferentialInput(&storage[3], .rsa_pss_sha384, "", &sha384_hash);
    corpus[4] = encodeDifferentialInput(&storage[4], .rsa_pss_sha512, "", &sha512_hash);
    corpus[5] = encodeDifferentialInput(&storage[5], .ecdsa_p256_sha256, &zero_p256, "");
    corpus[6] = encodeDifferentialInput(&storage[6], .ecdsa_p256_sha256, &max_p256, "");
    corpus[7] = encodeDifferentialInput(&storage[7], .ecdsa_p384_sha384, &zero_p384, "");
    corpus[8] = encodeDifferentialInput(&storage[8], .ecdsa_p384_sha384, &max_p384, "");

    try fuzz_compat.fuzzBytes(fuzzSignVerifyDifferential, {}, .{ .corpus = &corpus });
}
