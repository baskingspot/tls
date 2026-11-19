//! Pure-Zig crypto primitives for the opt-in native backend (#199).
//!
//! This backend is not a production replacement for libcrypto. P-256/P-384,
//! ML-KEM, and RSA remain unsupported in this slice.
const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;
const assert = std.debug.assert;

const CipherSuite = @import("../cipher_suite.zig").CipherSuite;
const ParameterSet = @import("mlkem_parameters.zig").ParameterSet;
const SignatureScheme = @import("../signature_scheme.zig").SignatureScheme;
const aes_gcm = @import("aes_gcm_native.zig");

pub const capabilities = struct {
    pub const cipher_suites: []const CipherSuite = &.{
        .aes_128_gcm_sha256,
        .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256,
    };

    pub const client_x25519 = true;
    pub const client_p256 = false;
    pub const client_p384 = false;
    pub const client_x25519_mlkem768 = false;
    pub const client_secp256r1_mlkem768 = false;
    pub const client_secp384r1_mlkem1024 = false;
    pub const server_x25519 = true;
    pub const server_p256 = false;
    pub const server_p384 = false;
    pub const server_x25519_mlkem768 = false;
    pub const server_secp256r1_mlkem768 = false;
    pub const server_secp384r1_mlkem1024 = false;

    // Ed25519 primitive signing and verification exist below. The
    // CertificateVerify key-loading and verification path is a later slice.
    pub const certificate_verify_schemes: []const SignatureScheme = &.{};

    // Certificate-chain Ed25519 verification already uses std.crypto in
    // certificate_parser.zig and needs no libcrypto calls.
    pub const certificate_signature_schemes: []const SignatureScheme = &.{.ed25519};
};

pub const sha2 = crypto.hash.sha2;
pub const hmac = crypto.auth.hmac;
pub const hkdf = crypto.kdf.hkdf;

pub const Error = error{ IdentityElement, LibcryptoFailed, UnsupportedPrimitive };

// X25519 handles are values, as on the BoringSSL-family backends.
pub const x25519_pkey = union(enum) {
    private: [32]u8,
    public: [32]u8,
};

pub fn privateKeyFromSecret(secret: *const [32]u8) Error!x25519_pkey {
    return .{ .private = secret.* };
}

pub fn publicKeyFromRaw(public_key: *const [32]u8) Error!x25519_pkey {
    return .{ .public = public_key.* };
}

pub fn rawPublicKeyFromPrivate(key: *const x25519_pkey) Error![32]u8 {
    assert(std.meta.activeTag(key.*) == .private);
    return crypto.dh.X25519.recoverPublicKey(key.private);
}

pub fn sharedSecretDerive(
    ours: *const x25519_pkey,
    peer: *const x25519_pkey,
    out: *[32]u8,
) Error!void {
    assert(std.meta.activeTag(ours.*) == .private);
    assert(std.meta.activeTag(peer.*) == .public);
    out.* = try crypto.dh.X25519.scalarmult(ours.private, peer.public);

    // RFC 7748 §6.1 — reject all-zero output from low-order peer public keys.
    if (crypto.timing_safe.eql([32]u8, out.*, @splat(0))) return error.IdentityElement;
}

pub fn x25519FreeKey(key: *x25519_pkey) void {
    switch (key.*) {
        .private => |*private| crypto.secureZero(u8, private),
        .public => {},
    }
    key.* = undefined;
}

pub const AeadError = error{
    AuthenticationFailed,
    AeadSetupFailed,
    AeadEncryptFailed,
};

/// One copied key, no provider state, and no allocation.
pub const AeadContext = struct {
    suite: CipherSuite,
    key: [32]u8,
};

pub const aead_tag_len = 16;
pub const aead_nonce_len = 12;

fn aeadKeyLen(suite: CipherSuite) usize {
    return switch (suite) {
        .aes_128_gcm_sha256 => 16,
        .aes_256_gcm_sha384, .chacha20_poly1305_sha256 => 32,
    };
}

pub fn aeadInit(suite: CipherSuite, key_bytes: []const u8) AeadError!AeadContext {
    const key_len = aeadKeyLen(suite);
    if (key_bytes.len != key_len) return error.AeadSetupFailed;
    var ctx: AeadContext = .{ .suite = suite, .key = @splat(0) };
    @memcpy(ctx.key[0..key_len], key_bytes);
    return ctx;
}

pub fn aeadDeinit(ctx: *AeadContext) void {
    crypto.secureZero(u8, std.mem.asBytes(ctx));
}

pub fn aeadEncrypt(
    ctx: *AeadContext,
    ciphertext: []u8,
    tag: *[aead_tag_len]u8,
    plaintext: []const u8,
    ad: []const u8,
    npub: *const [aead_nonce_len]u8,
) AeadError!void {
    assert(ciphertext.len == plaintext.len);
    switch (ctx.suite) {
        .aes_128_gcm_sha256 => aes_gcm.Aes128Gcm.encrypt(
            ciphertext,
            tag,
            plaintext,
            ad,
            npub.*,
            ctx.key[0..16].*,
        ),
        .aes_256_gcm_sha384 => aes_gcm.Aes256Gcm.encrypt(
            ciphertext,
            tag,
            plaintext,
            ad,
            npub.*,
            ctx.key,
        ),
        .chacha20_poly1305_sha256 => crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext,
            tag,
            plaintext,
            ad,
            npub.*,
            ctx.key,
        ),
    }
}

pub fn aeadDecrypt(
    ctx: *AeadContext,
    plaintext: []u8,
    ciphertext: []const u8,
    tag: *const [aead_tag_len]u8,
    ad: []const u8,
    npub: *const [aead_nonce_len]u8,
) AeadError!void {
    assert(plaintext.len == ciphertext.len);
    return switch (ctx.suite) {
        .aes_128_gcm_sha256 => aes_gcm.Aes128Gcm.decrypt(
            plaintext,
            ciphertext,
            tag.*,
            ad,
            npub.*,
            ctx.key[0..16].*,
        ),
        .aes_256_gcm_sha384 => aes_gcm.Aes256Gcm.decrypt(
            plaintext,
            ciphertext,
            tag.*,
            ad,
            npub.*,
            ctx.key,
        ),
        .chacha20_poly1305_sha256 => crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext,
            tag.*,
            ad,
            npub.*,
            ctx.key,
        ),
    } catch |err| switch (err) {
        error.AuthenticationFailed => return error.AuthenticationFailed,
    };
}

/// Raw-seed Ed25519 operations. No PEM/DER key loader exists in this slice.
pub const ed25519 = struct {
    const Ed = crypto.sign.Ed25519;

    pub const KeyPair = Ed.KeyPair;
    pub const seed_length = Ed.KeyPair.seed_length;
    pub const public_length = Ed.PublicKey.encoded_length;
    pub const signature_length = Ed.Signature.encoded_length;

    pub const GenerateError = error{IdentityElement};
    pub const SignError = error{ BufferTooShort, SigningFailed };
    pub const VerifyError = error{ InvalidEncoding, SignatureVerificationFailed };

    pub fn keyPairFromSeed(seed: *const [seed_length]u8) GenerateError!KeyPair {
        return KeyPair.generateDeterministic(seed.*);
    }

    /// RFC 8032 §5.1.6 — deterministic PureEdDSA over the complete message.
    pub fn sign(key: *const KeyPair, msg: []const u8, out: []u8) ed25519.SignError![]const u8 {
        if (out.len < signature_length) return error.BufferTooShort;
        const signature = key.sign(msg, null) catch return error.SigningFailed;
        out[0..signature_length].* = signature.toBytes();
        return out[0..signature_length];
    }

    /// RFC 8032 §5.1.7 — verify a raw public key and a 64-byte signature.
    pub fn verify(
        public_key: *const [public_length]u8,
        msg: []const u8,
        signature: []const u8,
    ) VerifyError!void {
        if (signature.len != signature_length) return error.InvalidEncoding;
        const pk = Ed.PublicKey.fromBytes(public_key.*) catch return error.InvalidEncoding;
        const sig = Ed.Signature.fromBytes(signature[0..signature_length].*);
        sig.verify(msg, pk) catch return error.SignatureVerificationFailed;
    }
};

// Unsupported facade entries fail by name. Capabilities prevent negotiation;
// these errors also stop a direct caller from getting a silent no-op.
pub const pkey = struct {};
pub const KemKey = *pkey;
pub const KemPeerKey = *pkey;

pub fn freeKey(key: anytype) void {
    _ = key;
}

pub fn p256PrivateKeyFromSecret(secret: *const [32]u8) Error!*pkey {
    _ = secret;
    return error.UnsupportedPrimitive;
}

pub fn p256PublicKeyFromRaw(public_key: *const [65]u8) Error!*pkey {
    _ = public_key;
    return error.UnsupportedPrimitive;
}

pub fn p256RawPublicKeyFromPrivate(key: *pkey) Error![65]u8 {
    _ = key;
    return error.UnsupportedPrimitive;
}

pub fn p256PublicFromSecret(secret: *const [32]u8) Error![65]u8 {
    _ = secret;
    return error.UnsupportedPrimitive;
}

pub fn p256EcdhKeyFromSecret(secret: *const [32]u8) Error!*pkey {
    _ = secret;
    return error.UnsupportedPrimitive;
}

pub fn p256SharedSecretDerive(ours: *pkey, peer: *pkey, out: *[32]u8) Error!void {
    _ = ours;
    _ = peer;
    _ = out;
    return error.UnsupportedPrimitive;
}

pub fn p384PrivateKeyFromSecret(secret: *const [48]u8) Error!*pkey {
    _ = secret;
    return error.UnsupportedPrimitive;
}

pub fn p384PublicKeyFromRaw(public_key: *const [97]u8) Error!*pkey {
    _ = public_key;
    return error.UnsupportedPrimitive;
}

pub fn p384RawPublicKeyFromPrivate(key: *pkey) Error![97]u8 {
    _ = key;
    return error.UnsupportedPrimitive;
}

pub fn p384SharedSecretDerive(ours: *pkey, peer: *pkey, out: *[48]u8) Error!void {
    _ = ours;
    _ = peer;
    _ = out;
    return error.UnsupportedPrimitive;
}

pub fn kemKeygen(parameter_set: ParameterSet) Error!KemKey {
    _ = parameter_set;
    return error.UnsupportedPrimitive;
}

pub fn kemPublic(key: KemKey, out: []u8) Error![]u8 {
    _ = key;
    _ = out;
    return error.UnsupportedPrimitive;
}

pub fn kemLoadPublic(parameter_set: ParameterSet, public_key: []const u8) Error!KemPeerKey {
    _ = parameter_set;
    _ = public_key;
    return error.UnsupportedPrimitive;
}

pub fn kemEncapsulate(
    parameter_set: ParameterSet,
    peer_key: KemPeerKey,
    ciphertext_out: []u8,
    secret_out: []u8,
) Error!struct { ciphertext: []u8, secret: []u8 } {
    _ = parameter_set;
    _ = peer_key;
    _ = ciphertext_out;
    _ = secret_out;
    return error.UnsupportedPrimitive;
}

pub fn kemDecapsulate(
    parameter_set: ParameterSet,
    our_key: KemKey,
    ciphertext: []const u8,
    secret_out: []u8,
) Error![]u8 {
    _ = parameter_set;
    _ = our_key;
    _ = ciphertext;
    _ = secret_out;
    return error.UnsupportedPrimitive;
}

pub const SignatureError = error{
    BufferTooShort,
    InvalidEncoding,
    LibcryptoFailed,
    SignatureVerificationFailed,
    UnsupportedPrimitive,
    UnsupportedSignatureScheme,
};
pub const SignError = SignatureError || error{DeterministicNonceUnsupported};
pub const NonceMode = @import("ecdsa.zig").NonceMode;
pub const KeySchemeError = error{UnsupportedKeyScheme};

pub fn privateKeyFromDer(der: []const u8) SignatureError!*pkey {
    _ = der;
    return error.UnsupportedPrimitive;
}

pub fn privateKeyFromPem(pem: []const u8) SignatureError!*pkey {
    _ = pem;
    return error.UnsupportedPrimitive;
}

pub fn keyScheme(key: *const pkey) KeySchemeError!SignatureScheme {
    _ = key;
    return error.UnsupportedKeyScheme;
}

pub fn privateKeyPairsWithCertificate(
    key: *const pkey,
    leaf_cert_der: []const u8,
) error{InvalidEncoding}!bool {
    _ = key;
    _ = leaf_cert_der;
    return error.InvalidEncoding;
}

pub fn privateKeyFromP256Scalar(scalar: *const [32]u8) SignatureError!*pkey {
    _ = scalar;
    return error.UnsupportedPrimitive;
}

pub fn signatureSign(
    key: *pkey,
    scheme: SignatureScheme,
    msg: []const u8,
    out: []u8,
    nonce_mode: NonceMode,
) SignError![]const u8 {
    _ = key;
    _ = scheme;
    _ = msg;
    _ = out;
    _ = nonce_mode;
    return error.UnsupportedPrimitive;
}

// The backend boundary rejects slices that cannot satisfy the fixed-size key.
test "native AEAD initialization rejects wrong key length" {
    inline for (capabilities.cipher_suites) |suite| {
        const wrong_key: [1]u8 = @splat(0);
        try testing.expectError(error.AeadSetupFailed, aeadInit(suite, &wrong_key));
    }
}

test "native AEAD deinit clears the key and suite" {
    const key: [32]u8 = @splat(0xa5);
    var ctx = try aeadInit(.aes_256_gcm_sha384, &key);
    aeadDeinit(&ctx);
    for (std.mem.asBytes(&ctx)) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

// RFC 8032 §7.1 TEST 1 — empty-message Ed25519 known-answer vector.
test "native Ed25519 matches RFC 8032 TEST 1" {
    const seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const expected_public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const expected_signature = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" ++
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    var key = try ed25519.keyPairFromSeed(&seed);
    defer crypto.secureZero(u8, std.mem.asBytes(&key));
    try testing.expectEqualSlices(u8, &expected_public, &key.public_key.toBytes());

    var signature: [ed25519.signature_length]u8 = undefined;
    const signed = try ed25519.sign(&key, "", &signature);
    try testing.expectEqualSlices(u8, &expected_signature, signed);
    try ed25519.verify(&expected_public, "", signed);

    signature[0] ^= 1;
    try testing.expectError(error.SignatureVerificationFailed, ed25519.verify(
        &expected_public,
        "",
        &signature,
    ));
    try testing.expectError(error.InvalidEncoding, ed25519.verify(&expected_public, "", "short"));

    var short: [ed25519.signature_length - 1]u8 = undefined;
    try testing.expectError(error.BufferTooShort, ed25519.sign(&key, "", &short));
}

fn hex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    comptime assert(encoded.len % 2 == 0);
    var out: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, encoded) catch unreachable;
    return out;
}
