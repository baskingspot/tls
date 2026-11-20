//! Pure-Zig crypto primitives for the opt-in native backend (#199).
//!
//! This backend is not a production replacement for libcrypto. ML-KEM-1024 and
//! RSA remain unsupported in this slice.
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;
const assert = std.debug.assert;

const CipherSuite = @import("../cipher_suite.zig").CipherSuite;
const Certificate = @import("../certificate_parser.zig");
const ParameterSet = @import("mlkem_parameters.zig").ParameterSet;
const SignatureScheme = @import("../signature_scheme.zig").SignatureScheme;
const aes_gcm = @import("aes_gcm_native.zig");
const ecdsa = @import("ecdsa.zig");
const entropy = @import("../entropy.zig");
const MlKem768 = crypto.kem.ml_kem.MLKem768;
const P256 = crypto.ecc.P256;
const P384 = crypto.ecc.P384;

pub const capabilities = struct {
    pub const cipher_suites: []const CipherSuite = &.{
        .aes_128_gcm_sha256,
        .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256,
    };

    pub const client_x25519 = true;
    pub const client_p256 = true;
    pub const client_p384 = true;
    pub const client_x25519_mlkem768 = true;
    pub const client_secp256r1_mlkem768 = true;
    pub const client_secp384r1_mlkem1024 = false;
    pub const server_x25519 = true;
    pub const server_p256 = true;
    pub const server_p384 = true;
    pub const server_x25519_mlkem768 = true;
    pub const server_secp256r1_mlkem768 = true;
    pub const server_secp384r1_mlkem1024 = false;

    // CertificateVerify and chain verification use the in-tree ECDSA module.
    // Ed25519 remains a chain-signature scheme, not a CertificateVerify scheme.
    pub const certificate_verify_schemes: []const SignatureScheme = &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
    };

    pub const certificate_signature_schemes: []const SignatureScheme = &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .ed25519,
    };
};

pub const sha2 = crypto.hash.sha2;
const Sha256 = sha2.Sha256;
const Sha384 = sha2.Sha384;

pub const Error = error{ IdentityElement, LibcryptoFailed };
pub const KemError = Error || error{UnsupportedPrimitive};

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
    crypto.secureZero(u8, mem.asBytes(ctx));
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

/// Inline keys keep native construction allocation-free. Libcrypto backends
/// use a pointer at the same facade boundary.
pub const pkey = union(enum) {
    p256_private: [32]u8,
    p256_public: [65]u8,
    p384_private: [48]u8,
    p384_public: [97]u8,
};
pub const EcKey = pkey;

// Keep the private handle to the FIPS 203 seed. Expansion is expensive but
// native favors a small caller-owned handle over cached provider state.
// std.crypto.kem.hybrid implements C2PRI, not RFC 10024 concatenation, so
// hybrid_kex.zig remains the owner of the TLS construction.
pub const KemKey = union(enum) {
    mlkem768: [MlKem768.seed_length]u8,
};
pub const KemPeerKey = union(enum) {
    mlkem768: [MlKem768.PublicKey.encoded_length]u8,
};

// Native KEM handles have no external resource. mlkem.zig wipes their inline
// storage after this call, including the private seed.
pub fn freeKey(key: anytype) void {
    _ = key;
}

pub fn freeEcKey(key: *EcKey) void {
    crypto.secureZero(u8, mem.asBytes(key));
    key.* = undefined;
}

/// SEC 1 §3.2.1 — reject zero and every scalar outside [1, n - 1].
fn validateSecret(comptime Curve: type, secret: anytype) Error!void {
    const scalar = Curve.scalar.Scalar.fromBytes(secret.*, .big) catch
        return error.IdentityElement;
    if (scalar.isZero()) return error.IdentityElement;
}

fn publicFromSecret(
    comptime Curve: type,
    secret: anytype,
) Error![1 + 2 * Curve.Fe.encoded_length]u8 {
    try validateSecret(Curve, secret);
    const point = Curve.basePoint.mul(secret.*, .big) catch return error.IdentityElement;
    return point.toUncompressedSec1();
}

fn decodePublic(comptime Curve: type, public_key: anytype) Error!Curve {
    if (public_key[0] != 0x04) return error.IdentityElement;
    const point = Curve.fromSec1(public_key) catch return error.IdentityElement;
    point.rejectIdentity() catch return error.IdentityElement;
    return point;
}

fn deriveShared(
    comptime Curve: type,
    secret: anytype,
    public_key: anytype,
    out: anytype,
) Error!void {
    try validateSecret(Curve, secret);
    const point = try decodePublic(Curve, public_key);
    const shared = point.mul(secret.*, .big) catch return error.IdentityElement;
    out.* = shared.affineCoordinates().x.toBytes(.big);
}

pub fn p256PrivateKeyFromSecret(secret: *const [32]u8) Error!pkey {
    try validateSecret(P256, secret);
    return .{ .p256_private = secret.* };
}

pub fn p256PublicKeyFromRaw(public_key: *const [65]u8) Error!pkey {
    _ = try decodePublic(P256, public_key);
    return .{ .p256_public = public_key.* };
}

pub fn p256RawPublicKeyFromPrivate(key: pkey) Error![65]u8 {
    return switch (key) {
        .p256_private => |secret| publicFromSecret(P256, &secret),
        else => error.LibcryptoFailed,
    };
}

pub fn p256PublicFromSecret(secret: *const [32]u8) Error![65]u8 {
    return publicFromSecret(P256, secret);
}

pub fn p256EcdhKeyFromSecret(secret: *const [32]u8) Error!pkey {
    return p256PrivateKeyFromSecret(secret);
}

pub fn p256SharedSecretDerive(ours: pkey, peer: pkey, out: *[32]u8) Error!void {
    switch (ours) {
        .p256_private => |*secret| switch (peer) {
            .p256_public => |*public_key| return deriveShared(P256, secret, public_key, out),
            else => return error.LibcryptoFailed,
        },
        else => return error.LibcryptoFailed,
    }
}

pub fn p384PrivateKeyFromSecret(secret: *const [48]u8) Error!pkey {
    try validateSecret(P384, secret);
    return .{ .p384_private = secret.* };
}

pub fn p384PublicKeyFromRaw(public_key: *const [97]u8) Error!pkey {
    _ = try decodePublic(P384, public_key);
    return .{ .p384_public = public_key.* };
}

pub fn p384RawPublicKeyFromPrivate(key: pkey) Error![97]u8 {
    return switch (key) {
        .p384_private => |secret| publicFromSecret(P384, &secret),
        else => error.LibcryptoFailed,
    };
}

pub fn p384SharedSecretDerive(ours: pkey, peer: pkey, out: *[48]u8) Error!void {
    switch (ours) {
        .p384_private => |*secret| switch (peer) {
            .p384_public => |*public_key| return deriveShared(P384, secret, public_key, out),
            else => return error.LibcryptoFailed,
        },
        else => return error.LibcryptoFailed,
    }
}

pub fn kemKeygen(parameter_set: ParameterSet) KemError!KemKey {
    if (parameter_set != .mlkem768) return error.UnsupportedPrimitive;
    var seed: [MlKem768.seed_length]u8 = undefined;
    entropy.fill(&seed);
    return .{ .mlkem768 = seed };
}

/// Deterministic key generation for differential vectors and caller tests.
pub fn kemKeygenFromSeed(
    parameter_set: ParameterSet,
    seed: *const [MlKem768.seed_length]u8,
) KemError!KemKey {
    if (parameter_set != .mlkem768) return error.UnsupportedPrimitive;
    return .{ .mlkem768 = seed.* };
}

fn expandMlKem768(seed: *const [MlKem768.seed_length]u8) KemError!MlKem768.KeyPair {
    return MlKem768.KeyPair.generateDeterministic(seed.*) catch
        return error.LibcryptoFailed;
}

pub fn kemPublic(key: KemKey, out: []u8) KemError![]u8 {
    const seed = switch (key) {
        .mlkem768 => |seed| seed,
    };
    if (out.len != MlKem768.PublicKey.encoded_length) return error.LibcryptoFailed;
    var keypair = try expandMlKem768(&seed);
    defer crypto.secureZero(u8, mem.asBytes(&keypair));
    out[0..MlKem768.PublicKey.encoded_length].* = keypair.public_key.toBytes();
    return out;
}

pub fn kemLoadPublic(
    parameter_set: ParameterSet,
    public_key: []const u8,
    out: *KemPeerKey,
) KemError!void {
    if (parameter_set != .mlkem768) return error.UnsupportedPrimitive;
    if (public_key.len != MlKem768.PublicKey.encoded_length)
        return error.LibcryptoFailed;
    out.* = .{ .mlkem768 = public_key[0..MlKem768.PublicKey.encoded_length].* };
}

pub fn kemEncapsulate(
    parameter_set: ParameterSet,
    peer_key: *const KemPeerKey,
    ciphertext_out: []u8,
    secret_out: []u8,
) KemError!struct { ciphertext: []u8, secret: []u8 } {
    if (parameter_set != .mlkem768) return error.UnsupportedPrimitive;
    if (ciphertext_out.len != MlKem768.ciphertext_length or
        secret_out.len != MlKem768.shared_length) return error.LibcryptoFailed;
    const encoded = switch (peer_key.*) {
        .mlkem768 => |*public_key| public_key,
    };
    const public_key = MlKem768.PublicKey.fromBytes(encoded) catch
        return error.IdentityElement;
    var seed: [MlKem768.encaps_seed_length]u8 = undefined;
    defer crypto.secureZero(u8, &seed);
    entropy.fill(&seed);
    const encapsulated = public_key.encapsDeterministic(&seed);
    ciphertext_out[0..MlKem768.ciphertext_length].* = encapsulated.ciphertext;
    secret_out[0..MlKem768.shared_length].* = encapsulated.shared_secret;
    return .{ .ciphertext = ciphertext_out, .secret = secret_out };
}

pub fn kemDecapsulate(
    parameter_set: ParameterSet,
    our_key: KemKey,
    ciphertext: []const u8,
    secret_out: []u8,
) KemError![]u8 {
    if (parameter_set != .mlkem768) return error.UnsupportedPrimitive;
    if (ciphertext.len != MlKem768.ciphertext_length or
        secret_out.len != MlKem768.shared_length) return error.LibcryptoFailed;
    const seed = switch (our_key) {
        .mlkem768 => |seed| seed,
    };
    var keypair = try expandMlKem768(&seed);
    defer crypto.secureZero(u8, mem.asBytes(&keypair));
    const secret = keypair.secret_key.decaps(ciphertext[0..MlKem768.ciphertext_length]) catch
        return error.LibcryptoFailed;
    secret_out[0..MlKem768.shared_length].* = secret;
    return secret_out;
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
pub const NonceMode = ecdsa.NonceMode;
pub const KeySchemeError = error{UnsupportedKeyScheme};

pub fn privateKeyFromDer(der: []const u8) SignatureError!pkey {
    _ = der;
    return error.UnsupportedPrimitive;
}

pub fn privateKeyFromPem(pem: []const u8) SignatureError!pkey {
    _ = pem;
    return error.UnsupportedPrimitive;
}

pub fn keyScheme(key: pkey) KeySchemeError!SignatureScheme {
    return switch (key) {
        .p256_private, .p256_public => .ecdsa_secp256r1_sha256,
        .p384_private, .p384_public => .ecdsa_secp384r1_sha384,
    };
}

pub fn privateKeyPairsWithCertificate(
    key: pkey,
    leaf_cert_der: []const u8,
) error{InvalidEncoding}!bool {
    // One exact DER certificate, matching the libcrypto loader's trailing-byte
    // rejection. No signature or path validation belongs to this comparison.
    const outer = Certificate.der.Element.parse(leaf_cert_der, 0) catch
        return error.InvalidEncoding;
    if (outer.identifier.tag != .sequence or outer.slice.end != leaf_cert_der.len)
        return error.InvalidEncoding;
    const leaf = Certificate.parse(.{ .buffer = leaf_cert_der, .index = 0 }) catch
        return error.InvalidEncoding;

    switch (key) {
        .p256_private => |*secret| {
            const curve = switch (leaf.pub_key_algo) {
                .X9_62_id_ecPublicKey => |curve| curve,
                else => return false,
            };
            if (curve != .X9_62_prime256v1) return false;
            const public_key = publicFromSecret(P256, secret) catch return false;
            return mem.eql(u8, &public_key, leaf.pubKey());
        },
        .p384_private => |*secret| {
            const curve = switch (leaf.pub_key_algo) {
                .X9_62_id_ecPublicKey => |curve| curve,
                else => return false,
            };
            if (curve != .secp384r1) return false;
            const public_key = publicFromSecret(P384, secret) catch return false;
            return mem.eql(u8, &public_key, leaf.pubKey());
        },
        else => return false,
    }
}

pub fn privateKeyFromP256Scalar(scalar: *const [32]u8) SignatureError!pkey {
    return p256PrivateKeyFromSecret(scalar) catch return error.LibcryptoFailed;
}

fn signatureSignEcdsa(
    comptime Curve: type,
    comptime Hash: type,
    secret: *const [Curve.scalar.encoded_length]u8,
    msg: []const u8,
    out: []u8,
    nonce_mode: NonceMode,
) SignError![]const u8 {
    return ecdsa.Ecdsa(Curve, Hash).sign(secret, msg, out, nonce_mode) catch |err| switch (err) {
        error.BufferTooShort => error.BufferTooShort,
        error.InvalidPrivateKey => error.LibcryptoFailed,
    };
}

pub fn signatureSign(
    key: pkey,
    scheme: SignatureScheme,
    msg: []const u8,
    out: []u8,
    nonce_mode: NonceMode,
) SignError![]const u8 {
    switch (scheme) {
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        => return error.UnsupportedPrimitive,
        else => {},
    }
    return switch (key) {
        .p256_private => |*secret| switch (scheme) {
            .ecdsa_secp256r1_sha256 => signatureSignEcdsa(
                P256,
                Sha256,
                secret,
                msg,
                out,
                nonce_mode,
            ),
            else => error.LibcryptoFailed,
        },
        .p384_private => |*secret| switch (scheme) {
            .ecdsa_secp384r1_sha384 => signatureSignEcdsa(
                P384,
                Sha384,
                secret,
                msg,
                out,
                nonce_mode,
            ),
            else => error.LibcryptoFailed,
        },
        else => error.LibcryptoFailed,
    };
}

pub fn signatureVerify(
    key: pkey,
    scheme: SignatureScheme,
    msg: []const u8,
    signature: []const u8,
) SignatureError!void {
    switch (scheme) {
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        => return error.UnsupportedPrimitive,
        else => {},
    }
    return switch (key) {
        .p256_public => |*public_key| switch (scheme) {
            .ecdsa_secp256r1_sha256 => ecdsa.Ecdsa(P256, Sha256).verify(
                public_key,
                msg,
                signature,
            ),
            else => error.LibcryptoFailed,
        },
        .p384_public => |*public_key| switch (scheme) {
            .ecdsa_secp384r1_sha384 => ecdsa.Ecdsa(P384, Sha384).verify(
                public_key,
                msg,
                signature,
            ),
            else => error.LibcryptoFailed,
        },
        else => error.LibcryptoFailed,
    };
}

// SEC 1 §2.3.3, §2.3.4 and RFC 8446 §4.2.8.2 — native ECDH validates
// peer points before scalar multiplication. Cover an off-curve point, the
// SEC1 infinity encoding, and a truncated uncompressed point on both curves.
test "native ECDH rejects off-curve, infinity, and wrong-length points" {
    inline for (.{ P256, P384 }) |Curve| {
        const secret: [Curve.scalar.encoded_length]u8 = @splat(0x42);
        const valid = try publicFromSecret(Curve, &secret);
        var off_curve: [1 + 2 * Curve.Fe.encoded_length]u8 = @splat(0);
        off_curve[0] = 0x04;
        off_curve[Curve.Fe.encoded_length] = 1; // x = 1, y = 0
        const infinity = [_]u8{0};
        const malformed = [_][]const u8{
            &off_curve,
            &infinity,
            valid[0 .. valid.len - 1],
        };
        for (malformed) |point| {
            var shared: [Curve.Fe.encoded_length]u8 = undefined;
            try testing.expectError(
                error.IdentityElement,
                deriveShared(Curve, &secret, point, &shared),
            );
        }
    }
}

// SEC 1 §2.3.3, §2.3.4 and RFC 8446 §4.4.3 — native ECDSA parses the
// certificate public key before it verifies the signature. Use a valid
// signature so each malformed key fails at the key-decoding step.
test "native ECDSA rejects off-curve, infinity, and wrong-length points" {
    inline for (.{
        .{ P256, Sha256 },
        .{ P384, Sha384 },
    }) |case| {
        const Curve, const Hash = case;
        const secret: [Curve.scalar.encoded_length]u8 = @splat(0x42);
        const valid = try publicFromSecret(Curve, &secret);
        const msg = "native malformed ECDSA point";
        var signature_buf: [160]u8 = undefined;
        const signature = try signatureSignEcdsa(
            Curve,
            Hash,
            &secret,
            msg,
            &signature_buf,
            .deterministic,
        );
        const Verify = ecdsa.Ecdsa(Curve, Hash);
        try Verify.verify(&valid, msg, signature);

        var off_curve: [1 + 2 * Curve.Fe.encoded_length]u8 = @splat(0);
        off_curve[0] = 0x04;
        off_curve[Curve.Fe.encoded_length] = 1; // x = 1, y = 0
        const infinity = [_]u8{0};
        const malformed = [_][]const u8{
            &off_curve,
            &infinity,
            valid[0 .. valid.len - 1],
        };
        for (malformed) |point| {
            try testing.expectError(
                error.InvalidEncoding,
                Verify.verify(point, msg, signature),
            );
        }
    }
}

// RFC 8446 §4.4.3 and RFC 6979 §3.2 — both advertised ECDSA curves sign and
// verify through the shared in-tree module. A wrong message, a changed
// signature, and a short output buffer are distinct failing controls.
test "native ECDSA P-256 and P-384 sign, verify, and reject invalid inputs" {
    inline for (.{
        .{ P256, SignatureScheme.ecdsa_secp256r1_sha256 },
        .{ P384, SignatureScheme.ecdsa_secp384r1_sha384 },
    }) |case| {
        const Curve, const scheme = case;
        const scalar: [Curve.scalar.encoded_length]u8 = @splat(0x42);
        var private: pkey = if (comptime Curve == P256)
            try privateKeyFromP256Scalar(&scalar)
        else
            try p384PrivateKeyFromSecret(&scalar);
        defer freeEcKey(&private);

        const public_bytes = if (comptime Curve == P256)
            try p256RawPublicKeyFromPrivate(private)
        else
            try p384RawPublicKeyFromPrivate(private);
        var public: pkey = if (comptime Curve == P256)
            try p256PublicKeyFromRaw(&public_bytes)
        else
            try p384PublicKeyFromRaw(&public_bytes);
        defer freeEcKey(&public);

        try testing.expectEqual(scheme, try keyScheme(private));
        const msg = "native ECDSA differential message";
        var signature_buf: [160]u8 = undefined;
        const signature = try signatureSign(private, scheme, msg, &signature_buf, .deterministic);
        try signatureVerify(public, scheme, msg, signature);
        try testing.expectError(
            error.SignatureVerificationFailed,
            signatureVerify(public, scheme, "wrong message", signature),
        );

        signature_buf[signature.len - 1] ^= 1;
        try testing.expectError(
            error.SignatureVerificationFailed,
            signatureVerify(public, scheme, msg, signature),
        );
        var short: [1]u8 = undefined;
        try testing.expectError(
            error.BufferTooShort,
            signatureSign(private, scheme, msg, &short, .deterministic),
        );
    }
}

// RFC 8446 §4.2.3 and RFC 10024 — native does not advertise or execute RSA
// or ML-KEM-1024. Direct calls fail by name instead of probing libcrypto silently.
test "native capabilities keep RSA and ML-KEM-1024 unsupported" {
    const rsa_schemes = [_]SignatureScheme{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
    };
    for (rsa_schemes) |scheme| {
        try testing.expect(mem.findScalar(
            SignatureScheme,
            capabilities.certificate_verify_schemes,
            scheme,
        ) == null);
        try testing.expect(mem.findScalar(
            SignatureScheme,
            capabilities.certificate_signature_schemes,
            scheme,
        ) == null);
    }
    try testing.expect(capabilities.client_x25519_mlkem768);
    try testing.expect(capabilities.server_x25519_mlkem768);
    try testing.expect(capabilities.client_secp256r1_mlkem768);
    try testing.expect(capabilities.server_secp256r1_mlkem768);
    try testing.expect(!capabilities.client_secp384r1_mlkem1024);
    try testing.expect(!capabilities.server_secp384r1_mlkem1024);

    try testing.expectError(error.UnsupportedPrimitive, kemKeygen(.mlkem1024));
    const seed: [MlKem768.seed_length]u8 = @splat(0x19);
    try testing.expectError(
        error.UnsupportedPrimitive,
        kemKeygenFromSeed(.mlkem1024, &seed),
    );
    var key = try kemKeygenFromSeed(.mlkem768, &seed);
    defer crypto.secureZero(u8, mem.asBytes(&key));

    const scalar: [32]u8 = @splat(0x42);
    var private = try privateKeyFromP256Scalar(&scalar);
    defer freeEcKey(&private);
    var out: [160]u8 = undefined;
    try testing.expectError(
        error.UnsupportedPrimitive,
        signatureSign(private, .rsa_pss_rsae_sha256, "message", &out, .random),
    );
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
    for (mem.asBytes(&ctx)) |byte| try testing.expectEqual(@as(u8, 0), byte);
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
    defer crypto.secureZero(u8, mem.asBytes(&key));
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
