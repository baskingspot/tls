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

/// Raw-seed Ed25519 operations. The PKCS#8 loader uses the same constructor.
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
    ed25519_private: ed25519.KeyPair,
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

/// A key constructed from raw scalar bytes: the signing seam's own errors, plus
/// key material that is not a scalar in [1, n-1]. Kept out of `SignatureError`
/// because the handshake error tables are written once for every backend, and
/// libcrypto reports the same input as a provider failure (baskingspot/tls#88).
pub const ScalarKeyError = SignatureError || error{InvalidPrivateKey};

/// signatureSign-only extension: a load never signs, so the deterministic
/// nonce error stays out of the loader set (baskingspot/tls#82).
pub const SignError = SignatureError || error{DeterministicNonceUnsupported};
pub const KeyLoadError = SignatureError || error{
    CurveMismatch,
    EncryptedPrivateKeyUnsupported,
    InvalidDer,
    InvalidPemEncoding,
    InvalidPrivateKey,
    PemLabelMismatch,
    PrivateKeyTooLarge,
    PublicKeyMismatch,
    RsaUnsupported,
    UnsupportedCurve,
    UnsupportedKeyAlgorithm,
    UnsupportedPemLabel,
    UnsupportedPointFormat,
};
pub const NonceMode = ecdsa.NonceMode;
pub const KeySchemeError = error{UnsupportedKeyScheme};

const DerElement = Certificate.der.Element;
const DerTag = Certificate.der.Tag;

const DerReader = struct {
    bytes: []const u8,
    index: u32 = 0,

    fn next(self: *DerReader) KeyLoadError!DerElement {
        const start: usize = self.index;
        const element = DerElement.parse(self.bytes, self.index) catch
            return error.InvalidDer;

        // DER forbids indefinite and non-minimal lengths. The certificate
        // parser accepts both because X.509 has a different error contract.
        const length_byte = self.bytes[start + 1];
        if (length_byte & 0x80 != 0) {
            if (length_byte & 0x7f == 0) return error.InvalidDer;
            if (self.bytes[start + 2] == 0) return error.InvalidDer;
            if (element.slice.end - element.slice.start < 128) return error.InvalidDer;
        }

        self.index = element.slice.end;
        return element;
    }

    fn read(self: *DerReader, tag: DerTag) KeyLoadError!DerElement {
        const element = try self.next();
        const expected_pc: Certificate.der.PC = if (tag == .sequence or tag == .sequence_of)
            .constructed
        else
            .primitive;
        if (element.identifier.class != .universal or
            element.identifier.pc != expected_pc or
            element.identifier.tag != tag) return error.InvalidDer;
        return element;
    }

    fn readContext(self: *DerReader, tag: u5) KeyLoadError!DerElement {
        const element = try self.next();
        if (!isContext(element, tag)) return error.InvalidDer;
        return element;
    }

    fn content(self: *const DerReader, element: DerElement) []const u8 {
        return self.bytes[element.slice.start..element.slice.end];
    }

    fn done(self: *const DerReader) bool {
        return self.index == self.bytes.len;
    }
};

fn isContext(element: DerElement, tag: u5) bool {
    return element.identifier.class == .context_specific and
        element.identifier.pc == .constructed and
        @backingInt(element.identifier.tag) == tag;
}

fn derBody(der: []const u8) KeyLoadError!DerReader {
    var reader: DerReader = .{ .bytes = der };
    const outer = try reader.read(.sequence);
    if (!reader.done()) return error.InvalidDer;
    return .{ .bytes = reader.content(outer) };
}

fn readVersion(reader: *DerReader, expected: u8) KeyLoadError!void {
    const element = try reader.read(.integer);
    const version = reader.content(element);
    if (version.len != 1 or version[0] != expected) return error.InvalidDer;
}

const EcCurve = enum { p256, p384 };

const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const oid_rsassa_pss = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_p256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_p384 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };

fn curveFromOid(oid: []const u8) KeyLoadError!EcCurve {
    if (mem.eql(u8, oid, &oid_p256)) return .p256;
    if (mem.eql(u8, oid, &oid_p384)) return .p384;
    return error.UnsupportedCurve;
}

const PrivateKeyAlgorithm = union(enum) {
    ec: EcCurve,
    ed25519,
};

fn parsePrivateKeyAlgorithm(contents: []const u8) KeyLoadError!PrivateKeyAlgorithm {
    var reader: DerReader = .{ .bytes = contents };
    const algorithm_element = try reader.read(.object_identifier);
    const algorithm = reader.content(algorithm_element);
    if (mem.eql(u8, algorithm, &oid_rsa_encryption) or
        mem.eql(u8, algorithm, &oid_rsassa_pss)) return error.RsaUnsupported;
    if (mem.eql(u8, algorithm, &oid_ed25519)) {
        // RFC 8410 §3 — Ed25519 AlgorithmIdentifier parameters are absent.
        if (!reader.done()) return error.InvalidDer;
        return .ed25519;
    }
    if (!mem.eql(u8, algorithm, &oid_ec_public_key))
        return error.UnsupportedKeyAlgorithm;

    // RFC 5480 §2.1.1.1 — id-ecPublicKey carries a named-curve OID.
    const parameters_element = try reader.read(.object_identifier);
    const curve = try curveFromOid(reader.content(parameters_element));
    if (!reader.done()) return error.InvalidDer;
    return .{ .ec = curve };
}

fn ed25519KeyFromPkcs8(private_key: []const u8) KeyLoadError!pkey {
    // RFC 8410 §7 — the outer OCTET STRING contains a second OCTET STRING,
    // whose 32 bytes are the seed rather than an expanded secret scalar.
    var reader: DerReader = .{ .bytes = private_key };
    const seed_element = try reader.read(.octetstring);
    const seed = reader.content(seed_element);
    if (!reader.done() or seed.len != ed25519.seed_length) return error.InvalidDer;
    const keypair = ed25519.keyPairFromSeed(seed[0..ed25519.seed_length]) catch
        return error.LibcryptoFailed;
    return .{ .ed25519_private = keypair };
}

fn ecKeyFromSecret(curve: EcCurve, secret: []const u8) KeyLoadError!pkey {
    return switch (curve) {
        .p256 => if (secret.len != 32)
            error.InvalidDer
        else
            privateKeyFromP256Scalar(secret[0..32]),
        .p384 => if (secret.len != 48)
            error.InvalidDer
        else
            p384PrivateKeyFromSecret(secret[0..48]) catch |err| switch (err) {
                error.IdentityElement => error.InvalidPrivateKey,
                error.LibcryptoFailed => error.LibcryptoFailed,
            },
    };
}

fn validateSec1PublicKey(
    key: pkey,
    reader: *const DerReader,
    element: DerElement,
) KeyLoadError!void {
    var public_reader: DerReader = .{ .bytes = reader.content(element) };
    const bit_string = public_reader.content(try public_reader.read(.bitstring));
    if (!public_reader.done() or bit_string.len < 2 or bit_string[0] != 0)
        return error.InvalidDer;
    const actual = bit_string[1..];
    switch (key) {
        .p256_private => |*secret| try expectSec1Point(P256, actual, secret),
        .p384_private => |*secret| try expectSec1Point(P384, actual, secret),
        else => unreachable,
    }
}

// SEC 1 §2.3.3 — the optional public key may use the compressed form, which
// `openssl ec -conv_form compressed` writes. Decode the point and compare it
// to the one the scalar derives, so a valid key loads as it does on libcrypto.
fn expectSec1Point(
    comptime Curve: type,
    actual: []const u8,
    secret: *const [Curve.scalar.encoded_length]u8,
) KeyLoadError!void {
    const point = switch (actual[0]) {
        0x02, 0x03, 0x04 => Curve.fromSec1(actual) catch return error.PublicKeyMismatch,
        // Hybrid points are legal SEC 1, and std.crypto cannot decode them.
        0x06, 0x07 => return error.UnsupportedPointFormat,
        else => return error.InvalidDer,
    };
    const expected = publicFromSecret(Curve, secret) catch return error.LibcryptoFailed;
    if (!mem.eql(u8, &point.toUncompressedSec1(), &expected)) return error.PublicKeyMismatch;
}

fn sec1PrivateKeyFromDer(der: []const u8, outer_curve: ?EcCurve) KeyLoadError!pkey {
    // RFC 5915 §3 — version 1, the scalar, optional named-curve parameters,
    // and an optional public key. PKCS#8 supplies the curve when [0] is absent.
    var reader = try derBody(der);
    try readVersion(&reader, 1);
    const secret = reader.content(try reader.read(.octetstring));
    var curve = outer_curve;
    var public_element: ?DerElement = null;

    if (!reader.done()) {
        const element = try reader.next();
        if (isContext(element, 0)) {
            var parameters: DerReader = .{ .bytes = reader.content(element) };
            const oid = parameters.content(try parameters.read(.object_identifier));
            if (!parameters.done()) return error.InvalidDer;
            const inner_curve = try curveFromOid(oid);
            if (curve) |expected| {
                if (inner_curve != expected) return error.CurveMismatch;
            }
            curve = inner_curve;
        } else if (isContext(element, 1)) {
            public_element = element;
        } else {
            return error.InvalidDer;
        }
    }
    if (public_element == null and !reader.done())
        public_element = try reader.readContext(1);
    if (!reader.done()) return error.InvalidDer;

    var key = try ecKeyFromSecret(curve orelse return error.InvalidDer, secret);
    errdefer freeEcKey(&key);
    if (public_element) |element| try validateSec1PublicKey(key, &reader, element);
    return key;
}

fn pkcs8PrivateKeyFromDer(der: []const u8) KeyLoadError!pkey {
    // RFC 5208 §5 — PrivateKeyInfo version 0, AlgorithmIdentifier, and an
    // OCTET STRING containing the algorithm-specific private-key structure.
    var reader = try derBody(der);
    try readVersion(&reader, 0);
    const algorithm = try parsePrivateKeyAlgorithm(
        reader.content(try reader.read(.sequence)),
    );
    const private_key = reader.content(try reader.read(.octetstring));
    if (!reader.done()) _ = try reader.readContext(0); // Optional attributes.
    if (!reader.done()) return error.InvalidDer;

    return switch (algorithm) {
        .ec => |curve| sec1PrivateKeyFromDer(private_key, curve),
        .ed25519 => ed25519KeyFromPkcs8(private_key),
    };
}

pub fn privateKeyFromDer(der: []const u8) KeyLoadError!pkey {
    var reader = try derBody(der);
    const version = reader.content(try reader.read(.integer));
    const second = try reader.next();
    if (version.len == 1 and version[0] == 0) {
        if (second.identifier.class == .universal and
            second.identifier.pc == .constructed and
            second.identifier.tag == .sequence) return pkcs8PrivateKeyFromDer(der);
        // PKCS#1 RSAPrivateKey has the modulus where PKCS#8 has an
        // AlgorithmIdentifier. Identify the capability before parsing RSA.
        if (second.identifier.class == .universal and
            second.identifier.pc == .primitive and
            second.identifier.tag == .integer) return error.RsaUnsupported;
    }
    if (version.len == 1 and version[0] == 1 and
        second.identifier.class == .universal and
        second.identifier.pc == .primitive and
        second.identifier.tag == .octetstring) return sec1PrivateKeyFromDer(der, null);
    return error.InvalidDer;
}

const PemBlock = struct {
    label: []const u8,
    body: []const u8,
    next: usize,
};

const pem_begin_prefix = "-----BEGIN ";

fn parsePemBlock(pem: []const u8, start: usize) KeyLoadError!?PemBlock {
    const begin = start + (mem.find(u8, pem[start..], pem_begin_prefix) orelse
        return null);
    const label_start = begin + pem_begin_prefix.len;
    const begin_end = label_start + (mem.find(u8, pem[label_start..], "-----") orelse
        return error.InvalidPemEncoding);
    if (begin_end == label_start) return error.InvalidPemEncoding;
    const body_start = begin_end + "-----".len;

    const end_prefix = "-----END ";
    const end = body_start + (mem.find(u8, pem[body_start..], end_prefix) orelse
        return error.InvalidPemEncoding);
    const end_label_start = end + end_prefix.len;
    const end_label_end = end_label_start + (mem.find(
        u8,
        pem[end_label_start..],
        "-----",
    ) orelse return error.InvalidPemEncoding);
    if (!mem.eql(u8, pem[label_start..begin_end], pem[end_label_start..end_label_end]))
        return error.PemLabelMismatch;
    return .{
        .label = pem[label_start..begin_end],
        .body = pem[body_start..end],
        .next = end_label_end + "-----".len,
    };
}

const pem_decoder = std.base64.standard.decoderWithIgnore("\t\n\x0b\x0c\r ");
// Supported EC and Ed25519 keys need only a few hundred bytes. The larger
// bound lets an RSA-8192 PKCS#8 file reach the named RSA capability error.
const max_private_key_der_len = 8192;

pub fn privateKeyFromPem(pem: []const u8) KeyLoadError!pkey {
    var position: usize = 0;
    while (try parsePemBlock(pem, position)) |block| {
        position = block.next;
        if (mem.eql(u8, block.label, "ENCRYPTED PRIVATE KEY") or
            mem.find(u8, block.body, "Proc-Type: 4,ENCRYPTED") != null)
            return error.EncryptedPrivateKeyUnsupported;
        if (mem.eql(u8, block.label, "RSA PRIVATE KEY")) return error.RsaUnsupported;

        const Format = enum { pkcs8, sec1 };
        const format: Format = if (mem.eql(u8, block.label, "PRIVATE KEY"))
            .pkcs8
        else if (mem.eql(u8, block.label, "EC PRIVATE KEY"))
            .sec1
        else {
            continue;
        };

        var der: [max_private_key_der_len]u8 = undefined;
        defer crypto.secureZero(u8, &der);
        const der_len = pem_decoder.decode(&der, block.body) catch |err| return switch (err) {
            error.NoSpaceLeft => error.PrivateKeyTooLarge,
            error.InvalidCharacter, error.InvalidPadding => error.InvalidPemEncoding,
        };
        return switch (format) {
            .pkcs8 => pkcs8PrivateKeyFromDer(der[0..der_len]),
            .sec1 => sec1PrivateKeyFromDer(der[0..der_len], null),
        };
    }
    return if (position == 0) error.InvalidPemEncoding else error.UnsupportedPemLabel;
}

pub fn keyScheme(key: pkey) KeySchemeError!SignatureScheme {
    return switch (key) {
        .p256_private, .p256_public => .ecdsa_secp256r1_sha256,
        .p384_private, .p384_public => .ecdsa_secp384r1_sha384,
        .ed25519_private => .ed25519,
    };
}

pub fn privateKeyPairsWithCertificate(
    key: pkey,
    leaf_cert_der: []const u8,
) error{InvalidEncoding}!bool {
    // One exact DER certificate, matching the libcrypto loader's trailing-byte
    // rejection. No signature or path validation belongs to this comparison.
    const outer = DerElement.parse(leaf_cert_der, 0) catch
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
        .ed25519_private => |*keypair| {
            switch (leaf.pub_key_algo) {
                .curveEd25519 => {},
                else => return false,
            }
            const public_key = keypair.public_key.toBytes();
            return mem.eql(u8, &public_key, leaf.pubKey());
        },
        else => return false,
    }
}

pub fn privateKeyFromP256Scalar(scalar: *const [32]u8) ScalarKeyError!pkey {
    return p256PrivateKeyFromSecret(scalar) catch |err| switch (err) {
        // RFC 6979 §2.2 — a scalar of zero or at least the group order is not
        // a private key, and that is not a provider failure.
        error.IdentityElement => error.InvalidPrivateKey,
        error.LibcryptoFailed => error.LibcryptoFailed,
    };
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

// RFC 5208 §5 and RFC 5915 §3 — existing OpenSSL fixtures load through both
// public input forms, and each DER load constructs the same native key as PEM.
test "native PKCS#8 loads P-256 and P-384 from PEM and DER" {
    // ziglint-ignore: Z007 -- Fixture imports stay test-local for published packages (#66).
    const fixtures = @import("fixtures");
    var p256_pem = try privateKeyFromPem(fixtures.ec_p256_key_pem);
    defer freeEcKey(&p256_pem);
    var p256_der = try privateKeyFromDer(&fixtures.native_p256_pkcs8_der);
    defer freeEcKey(&p256_der);
    try testing.expectEqual(SignatureScheme.ecdsa_secp256r1_sha256, try keyScheme(p256_der));
    try testing.expect(try privateKeyPairsWithCertificate(
        p256_der,
        &fixtures.server_cert_der,
    ));
    const p256_pem_public = try p256RawPublicKeyFromPrivate(p256_pem);
    const p256_der_public = try p256RawPublicKeyFromPrivate(p256_der);
    try testing.expectEqualSlices(u8, &p256_pem_public, &p256_der_public);

    var p384_pem = try privateKeyFromPem(fixtures.ec_p384_key_pem);
    defer freeEcKey(&p384_pem);
    var p384_der = try privateKeyFromDer(&fixtures.native_p384_pkcs8_der);
    defer freeEcKey(&p384_der);
    try testing.expectEqual(SignatureScheme.ecdsa_secp384r1_sha384, try keyScheme(p384_der));
    const p384_pem_public = try p384RawPublicKeyFromPrivate(p384_pem);
    const p384_der_public = try p384RawPublicKeyFromPrivate(p384_der);
    try testing.expectEqualSlices(u8, &p384_pem_public, &p384_der_public);
}

// RFC 7468 §2 and RFC 5915 §3 — SEC1 armor accepts CRLF, carries its own
// named curve, and checks the optional public key against the private scalar.
test "native SEC1 loads P-256 from PEM and DER with CRLF tolerance" {
    // ziglint-ignore: Z007 -- Fixture imports stay test-local for published packages (#66).
    const fixtures = @import("fixtures");
    var der_key = try privateKeyFromDer(&fixtures.native_p256_sec1_der);
    defer freeEcKey(&der_key);
    try testing.expect(try privateKeyPairsWithCertificate(der_key, &fixtures.server_cert_der));

    var crlf: [512]u8 = undefined;
    var crlf_len: usize = 0;
    for (fixtures.native_p256_sec1_pem) |byte| {
        if (byte == '\n') {
            crlf[crlf_len] = '\r';
            crlf_len += 1;
        }
        crlf[crlf_len] = byte;
        crlf_len += 1;
    }
    var pem_key = try privateKeyFromPem(crlf[0..crlf_len]);
    defer freeEcKey(&pem_key);
    const der_public = try p256RawPublicKeyFromPrivate(der_key);
    const pem_public = try p256RawPublicKeyFromPrivate(pem_key);
    try testing.expectEqualSlices(u8, &der_public, &pem_public);
}

// RFC 8410 §3 and §7 — the nested OCTET STRING contains an Ed25519 seed.
// Scheme inference still rejects it for CertificateVerify at the facade.
test "native PKCS#8 loads the same Ed25519 seed from PEM and DER" {
    // ziglint-ignore: Z007 -- Fixture imports stay test-local for published packages (#66).
    const fixtures = @import("fixtures");
    var pem_key = try privateKeyFromPem(fixtures.ed25519_key_pem);
    defer freeEcKey(&pem_key);
    var der_key = try privateKeyFromDer(&fixtures.native_ed25519_pkcs8_der);
    defer freeEcKey(&der_key);
    try testing.expectEqual(SignatureScheme.ed25519, try keyScheme(pem_key));
    const pem_public = switch (pem_key) {
        .ed25519_private => |keypair| keypair.public_key.toBytes(),
        else => unreachable,
    };
    const der_public = switch (der_key) {
        .ed25519_private => |keypair| keypair.public_key.toBytes(),
        else => unreachable,
    };
    try testing.expectEqualSlices(u8, &pem_public, &der_public);
}

// RFC 5208 §5 and RFC 8017 §A.1.1 — RSA containers are recognized as RSA.
// Unsupported curves are capability failures too, not malformed DER (#215/#216).
test "native private-key loading names unsupported algorithms" {
    // ziglint-ignore: Z007 -- Fixture imports stay test-local for published packages (#66).
    const fixtures = @import("fixtures");
    for ([_][]const u8{
        fixtures.rsa_pss_key_pem,
        fixtures.rsa_pkcs1_key_pem,
    }) |pem| {
        try testing.expectError(error.RsaUnsupported, privateKeyFromPem(pem));
    }
    try testing.expectError(
        error.RsaUnsupported,
        privateKeyFromDer(&fixtures.native_rsa_pkcs1_der),
    );
    for ([_][]const u8{
        fixtures.ec_p521_key_pem,
        fixtures.ec_secp224r1_key_pem,
    }) |pem| {
        try testing.expectError(error.UnsupportedCurve, privateKeyFromPem(pem));
    }
}

// RFC 7468 §2 — label mismatch, truncated base64, and encrypted containers
// have distinct errors. Both encrypted PKCS#8 and legacy encryption are named.
test "native PEM rejects wrong labels truncated base64 and encrypted keys" {
    // ziglint-ignore: Z007 -- Fixture imports stay test-local for published packages (#66).
    const fixtures = @import("fixtures");
    const wrong_label = "-----BEGIN PRIVATE KEY-----\nMIGHA\n-----END EC PRIVATE KEY-----";
    try testing.expectError(error.PemLabelMismatch, privateKeyFromPem(wrong_label));
    const truncated = "-----BEGIN PRIVATE KEY-----\nMIGHA\n-----END PRIVATE KEY-----";
    try testing.expectError(error.InvalidPemEncoding, privateKeyFromPem(truncated));
    for ([_][]const u8{
        fixtures.rsa_pss_key_encrypted_pkcs8_pem,
        fixtures.rsa_pss_key_encrypted_legacy_pem,
    }) |pem| {
        try testing.expectError(error.EncryptedPrivateKeyUnsupported, privateKeyFromPem(pem));
    }
}

// RFC 5915 §3 and RFC 5480 §2.1.1.1 — outer and inner curves must agree.
// Invalid lengths and an inconsistent optional public key are separate failures.
test "native DER rejects bad lengths curve mismatches and wrong public keys" {
    // ziglint-ignore: Z007 -- Fixture imports stay test-local for published packages (#66).
    const fixtures = @import("fixtures");
    const bad_length = [_]u8{ 0x30, 0x04, 0x02, 0x01, 0x00 };
    try testing.expectError(error.InvalidDer, privateKeyFromDer(&bad_length));
    const trailing = fixtures.native_p256_pkcs8_der ++ [_]u8{0};
    try testing.expectError(error.InvalidDer, privateKeyFromDer(&trailing));

    // PKCS#8 says P-256 while the inner SEC1 parameters say P-384.
    const curve_mismatch = hex("305A020100301306072A8648CE3D020106082A8648CE3D030107" ++
        "0440303E02010104300101010101010101010101010101010101010101010101010101010101010101" ++
        "01010101010101010101010101010101" ++
        "A00706052B81040022");
    try testing.expectError(error.CurveMismatch, privateKeyFromDer(&curve_mismatch));

    var wrong_public = fixtures.native_p256_sec1_der;
    wrong_public[wrong_public.len - 1] ^= 1;
    try testing.expectError(error.PublicKeyMismatch, privateKeyFromDer(&wrong_public));
}

// RFC 7468 §3 — a PEM file may hold several blocks. `openssl ecparam -genkey`
// writes EC PARAMETERS before the key, and `cat server.crt server.key` puts a
// certificate first. libcrypto loads both; the loader returns the first key
// block instead of rejecting the file's first block.
test "native PEM skips non-key blocks before the first private key" {
    // ziglint-ignore: Z007 -- Fixture imports stay test-local for published packages (#66).
    const fixtures = @import("fixtures");

    // openssl ecparam -name prime256v1 -genkey -out key.pem
    var ecparam_pem: PemFile = .{};
    ecparam_pem.add(fixtures.native_ec_parameters_pem);
    ecparam_pem.add(fixtures.native_p256_sec1_pem);
    var ecparam_key = try privateKeyFromPem(ecparam_pem.text());
    defer freeEcKey(&ecparam_key);
    try testing.expectEqual(SignatureScheme.ecdsa_secp256r1_sha256, try keyScheme(ecparam_key));

    // cat server.crt server.key
    var combined_pem: PemFile = .{};
    combined_pem.add(fixtures.native_server_cert_pem);
    combined_pem.add(fixtures.ec_p256_key_pem);
    var combined_key = try privateKeyFromPem(combined_pem.text());
    defer freeEcKey(&combined_key);
    try testing.expect(try privateKeyPairsWithCertificate(combined_key, &fixtures.server_cert_der));

    // A file with no key block keeps the label error instead of the parse error.
    try testing.expectError(
        error.UnsupportedPemLabel,
        privateKeyFromPem(fixtures.native_server_cert_pem),
    );
}

// SEC 1 §2.3.3 — the optional public key may use the compressed form, which
// `openssl ec -conv_form compressed` writes. The loader decompresses it and
// compares the point, so the key loads as it does on libcrypto.
test "native SEC1 accepts a compressed public point" {
    // ziglint-ignore: Z007 -- Fixture imports stay test-local for published packages (#66).
    const fixtures = @import("fixtures");
    var key = try privateKeyFromDer(&fixtures.native_p256_sec1_compressed_der);
    defer freeEcKey(&key);
    try testing.expect(try privateKeyPairsWithCertificate(key, &fixtures.server_cert_der));

    // The comparison decodes the point, so a different x is still a mismatch.
    var wrong_point = fixtures.native_p256_sec1_compressed_der;
    wrong_point[wrong_point.len - 1] ^= 1;
    try testing.expectError(error.PublicKeyMismatch, privateKeyFromDer(&wrong_point));

    // Hybrid points are legal SEC 1 and std.crypto cannot decode them.
    var hybrid_point = fixtures.native_p256_sec1_der;
    hybrid_point[hybrid_point.len - 65] = 0x06;
    try testing.expectError(error.UnsupportedPointFormat, privateKeyFromDer(&hybrid_point));
}

// SEC 1 §3.2.1 — zero and the curve order are not private scalars in [1, n - 1].
// Invalid key material is distinct from a provider failure on every native path.
test "native private-key loading rejects invalid scalars by name" {
    // ziglint-ignore: Z007 -- Fixture imports stay test-local for published packages (#66).
    const fixtures = @import("fixtures");
    const p256_order = hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    // P-384 order n, 48 bytes.
    const p384_order = hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" ++
        "FFFFFFFFFFFFFFFFC7634D81F4372DDF" ++
        "581A0DB248B0A77AECEC196ACCC52973");

    const zero_scalar: [32]u8 = @splat(0);
    try testing.expectError(error.InvalidPrivateKey, privateKeyFromP256Scalar(&zero_scalar));
    try testing.expectError(error.InvalidPrivateKey, privateKeyFromP256Scalar(&p256_order));

    // SEC 1 §3.2.1 — 7 is the scalar in a P-256 ECPrivateKey, 8 in a P-384 one:
    // the P-384 SEQUENCE length needs three length bytes instead of two.
    var zero_p256 = fixtures.native_p256_sec1_der;
    @memset(zero_p256[7..39], 0);
    try testing.expectError(error.InvalidPrivateKey, privateKeyFromDer(&zero_p256));

    var order_p256 = fixtures.native_p256_sec1_der;
    @memcpy(order_p256[7..39], &p256_order);
    try testing.expectError(error.InvalidPrivateKey, privateKeyFromDer(&order_p256));

    var zero_p384 = fixtures.native_p384_sec1_der;
    @memset(zero_p384[8..56], 0);
    try testing.expectError(error.InvalidPrivateKey, privateKeyFromDer(&zero_p384));

    var order_p384 = fixtures.native_p384_sec1_der;
    @memcpy(order_p384[8..56], &p384_order);
    try testing.expectError(error.InvalidPrivateKey, privateKeyFromDer(&order_p384));
}

/// Concatenated PEM blocks with no separator, the shape `cat` and
/// `openssl ecparam -genkey` produce.
const PemFile = struct {
    bytes: [1024]u8 = undefined,
    len: usize = 0,

    fn add(self: *PemFile, block: []const u8) void {
        const trimmed = mem.trimEnd(u8, block, "\n");
        assert(self.len + trimmed.len + 1 <= self.bytes.len);
        @memcpy(self.bytes[self.len..][0..trimmed.len], trimmed);
        self.len += trimmed.len;
        self.bytes[self.len] = '\n';
        self.len += 1;
    }

    fn text(self: *const PemFile) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn hex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    comptime assert(encoded.len % 2 == 0);
    var out: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, encoded) catch unreachable;
    return out;
}
