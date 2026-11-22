//! Crypto provider selection.
//!
//! The default `auto` backend detects the libcrypto family from its headers.
//! Opt-in `native` selects pure-Zig primitives and does not import the facade.
const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const build_options = @import("build_options");

pub const native_selected = build_options.crypto == .native;
// ziglint-ignore: Z028 — native must not resolve the libcrypto module import.
const c_openssl = if (native_selected) struct {} else @import("c_openssl.zig");

const CipherSuite = @import("../cipher_suite.zig").CipherSuite;
const NamedGroup = @import("../kex.zig").NamedGroup;
const SignatureScheme = @import("../signature_scheme.zig").SignatureScheme;
const backend_native = @import("backend_native.zig");
// ziglint-ignore: Z028 — native must not import any libcrypto backend.
const backend_aws_lc = if (native_selected) struct {} else @import("backend_aws_lc.zig");
// ziglint-ignore: Z028 — native must not import any libcrypto backend.
const backend_boringssl = if (native_selected) struct {} else @import("backend_boringssl.zig");
// ziglint-ignore: Z028 — native must not import any libcrypto backend.
const backend_openssl = if (native_selected) struct {} else @import("backend_openssl.zig");

/// Libcrypto uses runtime dispatch (#138). Opt-in native uses std's
/// compile-time-selected SHA-256 and SHA-384 implementation.
// ziglint-ignore: Z028 — the non-native arm owns the libcrypto SHA import.
pub const sha2 = if (native_selected) backend_native.sha2 else @import("sha2.zig");

pub const Backend = enum {
    native,
    openssl,
    @"aws-lc",
    boringssl,
    @"openssl-approved",
    @"aws-lc-approved",
};

/// Explicit native selection wins without reading libcrypto headers. Auto and
/// explicit libcrypto selections resolve against the selected header family.
pub const active: Backend = if (native_selected)
    (if (approved_only)
        @compileError("-Dcrypto-approved-only=true is unsupported with native")
    else
        .native)
else
    activeLibcrypto();

fn activeLibcrypto() Backend {
    const detected: Backend = switch (c_openssl.family) {
        .openssl => if (approved_only) .@"openssl-approved" else .openssl,
        .@"aws-lc" => if (approved_only) .@"aws-lc-approved" else .@"aws-lc",
        .boringssl => if (approved_only)
            @compileError("-Dcrypto-approved-only=true is unsupported with BoringSSL")
        else
            .boringssl,
    };
    if (build_options.crypto != .auto) {
        const requested: Backend = switch (build_options.crypto) {
            .openssl => .openssl,
            .@"aws-lc" => .@"aws-lc",
            .boringssl => .boringssl,
            .auto, .native => unreachable,
        };
        const detected_family: Backend = switch (detected) {
            .openssl, .@"openssl-approved" => .openssl,
            .@"aws-lc", .@"aws-lc-approved" => .@"aws-lc",
            .boringssl => .boringssl,
            .native => unreachable,
        };
        if (requested != detected_family) {
            @compileError("-Dcrypto=" ++ @tagName(requested) ++
                " does not match the selected libcrypto headers");
        }
    }
    return detected;
}

/// True when the build restricts negotiation to approved algorithms.
///
/// This is an algorithm-policy switch, not a validation claim. tls is not a
/// FIPS 140-3 validated module: signature verification, the TLS key schedule,
/// all randomness, and on OpenSSL the transcript hash and EC key construction
/// run outside the linked module. `PRODUCTION_READINESS.md` lists the split.
pub const approved_only: bool = build_options.crypto_approved_only;

const x25519_impl = switch (active) {
    .native => backend_native,
    .openssl, .@"openssl-approved" => backend_openssl,
    .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc,
    .boringssl => backend_boringssl,
};

const p256_impl = switch (active) {
    .native => backend_native,
    .openssl, .@"openssl-approved" => backend_openssl,
    .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc,
    .boringssl => backend_boringssl,
};

const p384_impl = switch (active) {
    .native => backend_native,
    .openssl, .@"openssl-approved" => backend_openssl,
    .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc,
    .boringssl => backend_boringssl,
};

const aead_impl = switch (active) {
    .native => backend_native,
    .openssl, .@"openssl-approved" => backend_openssl,
    .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc,
    .boringssl => backend_boringssl,
};

const sign_impl = switch (active) {
    .native => backend_native,
    .openssl, .@"openssl-approved" => backend_openssl,
    .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc,
    .boringssl => backend_boringssl,
};

pub const kem_impl = switch (active) {
    .native => backend_native,
    .openssl, .@"openssl-approved" => backend_openssl,
    .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc,
    .boringssl => backend_boringssl,
};

pub const capabilities = switch (active) {
    .native => backend_native.capabilities,
    .openssl => backend_openssl.capabilities,
    .@"openssl-approved" => backend_openssl.capabilities_approved,
    .@"aws-lc" => backend_aws_lc.capabilities,
    .@"aws-lc-approved" => backend_aws_lc.capabilities_approved,
    .boringssl => backend_boringssl.capabilities,
};

comptime {
    assert(capabilities.cipher_suites.len > 0);
    assert(capabilities.client_x25519 or capabilities.client_p256);
    assert(capabilities.server_x25519 or capabilities.server_p256);
    assert(capabilities.certificate_verify_schemes.len > 0);
    // Native pins both ML-KEM-768 hybrids and leaves ML-KEM-1024 unsupported.
    if (active == .native) {
        assert(capabilities.client_p256 and capabilities.server_p256);
        assert(capabilities.client_p384 and capabilities.server_p384);
        assert(capabilities.client_x25519_mlkem768);
        assert(capabilities.server_x25519_mlkem768);
        assert(capabilities.client_secp256r1_mlkem768);
        assert(capabilities.server_secp256r1_mlkem768);
        assert(!capabilities.client_secp384r1_mlkem1024);
        assert(!capabilities.server_secp384r1_mlkem1024);
    } else {
        assert(capabilities.certificate_verify_schemes.len > 0);
    }
    assert(capabilities.certificate_signature_schemes.len > 0);
    assert(capabilities.client_p384 == capabilities.server_p384);
    assert(
        capabilities.client_x25519_mlkem768 == capabilities.server_x25519_mlkem768,
    );
    assert(
        capabilities.client_secp256r1_mlkem768 ==
            capabilities.server_secp256r1_mlkem768,
    );
    assert(
        capabilities.client_secp384r1_mlkem1024 ==
            capabilities.server_secp384r1_mlkem1024,
    );

    // FIPS capability tables must be a strict subset of their non-FIPS
    // counterparts. Native has no approved-only profile.
    if (!native_selected) {
        assertSubset(
            backend_openssl.capabilities_approved.cipher_suites,
            backend_openssl.capabilities.cipher_suites,
        );
        assertSubset(
            backend_openssl.capabilities_approved.certificate_verify_schemes,
            backend_openssl.capabilities.certificate_verify_schemes,
        );
        assertSubset(
            backend_openssl.capabilities_approved.certificate_signature_schemes,
            backend_openssl.capabilities.certificate_signature_schemes,
        );
        assertSubset(
            backend_aws_lc.capabilities_approved.cipher_suites,
            backend_aws_lc.capabilities.cipher_suites,
        );
        assertSubset(
            backend_aws_lc.capabilities_approved.certificate_verify_schemes,
            backend_aws_lc.capabilities.certificate_verify_schemes,
        );
        assertSubset(
            backend_aws_lc.capabilities_approved.certificate_signature_schemes,
            backend_aws_lc.capabilities.certificate_signature_schemes,
        );
    }
}

fn assertSubset(comptime fips: anytype, comptime base: anytype) void {
    for (fips) |item| {
        var found = false;
        for (base) |b| {
            if (item == b) {
                found = true;
                break;
            }
        }
        assert(found);
    }
}

/// Returns the FIPS certificate_signature_schemes for the given backend family.
fn approvedCertSigSchemes(comptime fam: @TypeOf(active)) []const SignatureScheme {
    const openssl_approved =
        backend_openssl.capabilities_approved.certificate_signature_schemes;
    const aws_lc_approved =
        backend_aws_lc.capabilities_approved.certificate_signature_schemes;
    return switch (fam) {
        .native => &.{},
        .openssl, .@"openssl-approved" => openssl_approved,
        .@"aws-lc", .@"aws-lc-approved" => aws_lc_approved,
        .boringssl => &.{},
    };
}

pub fn supportsCipherSuite(suite: CipherSuite) bool {
    for (capabilities.cipher_suites) |supported| {
        if (supported == suite) return true;
    }
    return false;
}

pub fn supportsServerX25519() bool {
    return capabilities.server_x25519;
}

pub fn supportsServerP256() bool {
    return capabilities.server_p256;
}

pub fn supportsServerP384() bool {
    return capabilities.server_p384;
}

pub fn supportsClientP384() bool {
    return capabilities.client_p384;
}

pub fn supportsClientHybridGroup(group: NamedGroup) bool {
    return switch (group) {
        .x25519_mlkem768 => capabilities.client_x25519_mlkem768,
        .secp256r1_mlkem768 => capabilities.client_secp256r1_mlkem768,
        .secp384r1_mlkem1024 => capabilities.client_secp384r1_mlkem1024,
        else => false,
    };
}

pub fn supportsServerHybridGroup(group: NamedGroup) bool {
    return switch (group) {
        .x25519_mlkem768 => capabilities.server_x25519_mlkem768,
        .secp256r1_mlkem768 => capabilities.server_secp256r1_mlkem768,
        .secp384r1_mlkem1024 => capabilities.server_secp384r1_mlkem1024,
        else => false,
    };
}

pub fn supportsServerX25519Mlkem768() bool {
    return supportsServerHybridGroup(.x25519_mlkem768);
}

pub fn supportsCertificateVerifyScheme(scheme: SignatureScheme) bool {
    for (capabilities.certificate_verify_schemes) |supported| {
        if (supported == scheme) return true;
    }
    return false;
}

pub const x25519 = struct {
    pub const Error = x25519_impl.Error;
    pub const pkey = x25519_impl.x25519_pkey;

    pub inline fn privateKeyFromSecret(secret: *const [32]u8) Error!pkey {
        return x25519_impl.privateKeyFromSecret(secret);
    }

    pub inline fn publicKeyFromRaw(public_key: *const [32]u8) Error!pkey {
        return x25519_impl.publicKeyFromRaw(public_key);
    }

    pub inline fn rawPublicKeyFromPrivate(key: *const pkey) Error![32]u8 {
        return x25519_impl.rawPublicKeyFromPrivate(key);
    }

    pub inline fn sharedSecretDerive(
        ours: *const pkey,
        peer: *const pkey,
        out: *[32]u8,
    ) Error!void {
        return x25519_impl.sharedSecretDerive(ours, peer, out);
    }

    pub inline fn freeKey(key: *pkey) void {
        x25519_impl.x25519FreeKey(key);
    }
};

pub const p256 = struct {
    pub const Error = p256_impl.Error;
    /// A libcrypto pointer or an inline native key, depending on the backend.
    pub const pkey = p256_impl.EcKey;

    pub inline fn privateKeyFromSecret(secret: *const [32]u8) Error!pkey {
        return p256_impl.p256PrivateKeyFromSecret(secret);
    }

    pub inline fn publicKeyFromRaw(public_key: *const [65]u8) Error!pkey {
        return p256_impl.p256PublicKeyFromRaw(public_key);
    }

    pub inline fn rawPublicKeyFromPrivate(key: pkey) Error![65]u8 {
        return p256_impl.p256RawPublicKeyFromPrivate(key);
    }

    /// One fixed-base multiplication, SEC1-encoded (#134).
    pub inline fn publicFromSecret(secret: *const [32]u8) Error![65]u8 {
        return p256_impl.p256PublicFromSecret(secret);
    }

    /// The scalar alone, for ECDH (#134).
    pub inline fn ecdhKeyFromSecret(secret: *const [32]u8) Error!pkey {
        return p256_impl.p256EcdhKeyFromSecret(secret);
    }

    pub inline fn sharedSecretDerive(ours: pkey, peer: pkey, out: *[32]u8) Error!void {
        return p256_impl.p256SharedSecretDerive(ours, peer, out);
    }

    pub inline fn freeKey(key: *pkey) void {
        p256_impl.freeEcKey(key);
    }
};

pub const p384 = struct {
    pub const Error = p384_impl.Error;
    /// A libcrypto pointer or an inline native key, depending on the backend.
    pub const pkey = p384_impl.EcKey;

    pub inline fn privateKeyFromSecret(secret: *const [48]u8) Error!pkey {
        return p384_impl.p384PrivateKeyFromSecret(secret);
    }

    pub inline fn publicKeyFromRaw(public_key: *const [97]u8) Error!pkey {
        return p384_impl.p384PublicKeyFromRaw(public_key);
    }

    pub inline fn rawPublicKeyFromPrivate(key: pkey) Error![97]u8 {
        return p384_impl.p384RawPublicKeyFromPrivate(key);
    }

    pub inline fn sharedSecretDerive(ours: pkey, peer: pkey, out: *[48]u8) Error!void {
        return p384_impl.p384SharedSecretDerive(ours, peer, out);
    }

    pub inline fn freeKey(key: *pkey) void {
        p384_impl.freeEcKey(key);
    }
};

pub const aead = struct {
    pub const Error = aead_impl.AeadError;
    pub const Context = aead_impl.AeadContext;
    pub const tag_len = aead_impl.aead_tag_len;
    pub const nonce_len = aead_impl.aead_nonce_len;

    pub inline fn init(suite: CipherSuite, key_bytes: []const u8) Error!Context {
        return aead_impl.aeadInit(suite, key_bytes);
    }

    pub inline fn deinit(ctx: *Context) void {
        aead_impl.aeadDeinit(ctx);
        ctx.* = undefined;
    }

    pub inline fn encrypt(
        ctx: *Context,
        ciphertext: []u8,
        tag: *[tag_len]u8,
        plaintext: []const u8,
        ad: []const u8,
        npub: *const [nonce_len]u8,
    ) Error!void {
        return aead_impl.aeadEncrypt(ctx, ciphertext, tag, plaintext, ad, npub);
    }

    pub inline fn decrypt(
        ctx: *Context,
        plaintext: []u8,
        ciphertext: []const u8,
        tag: *const [tag_len]u8,
        ad: []const u8,
        npub: *const [nonce_len]u8,
    ) Error!void {
        return aead_impl.aeadDecrypt(ctx, plaintext, ciphertext, tag, ad, npub);
    }
};

pub const sign = struct {
    pub const Error = sign_impl.SignatureError;
    pub const SignError = sign_impl.SignError;
    pub const NonceMode = sign_impl.NonceMode;

    /// A libcrypto pointer or an inline native key, depending on the backend.
    pub const pkey = sign_impl.EcKey;
    pub inline fn privateKeyFromDer(der: []const u8) Error!pkey {
        return sign_impl.privateKeyFromDer(der);
    }

    pub inline fn privateKeyFromPem(pem: []const u8) Error!pkey {
        return sign_impl.privateKeyFromPem(pem);
    }

    pub const KeySchemeError = sign_impl.KeySchemeError;

    pub inline fn keyScheme(key: pkey) KeySchemeError!SignatureScheme {
        return sign_impl.keyScheme(key);
    }

    pub inline fn privateKeyPairsWithCertificate(
        key: pkey,
        leaf_cert_der: []const u8,
    ) error{InvalidEncoding}!bool {
        return sign_impl.privateKeyPairsWithCertificate(key, leaf_cert_der);
    }

    pub inline fn privateKeyFromP256Scalar(scalar: *const [32]u8) Error!pkey {
        return sign_impl.privateKeyFromP256Scalar(scalar);
    }

    pub inline fn freeKey(key: *pkey) void {
        sign_impl.freeEcKey(key);
    }

    pub inline fn sign(
        key: pkey,
        scheme: SignatureScheme,
        msg: []const u8,
        out: []u8,
        nonce_mode: NonceMode,
    ) SignError![]const u8 {
        return sign_impl.signatureSign(key, scheme, msg, out, nonce_mode);
    }
};

// docs/research/PROVIDER_INTERFACE.md §1 — the selected headers identify the
// libcrypto family. The explicit FIPS option narrows OpenSSL or AWS-LC to its
// FIPS capability identity without changing the linked library.
test "active backend matches the crypto option and selected libcrypto headers" {
    if (comptime native_selected) {
        try testing.expectEqual(Backend.native, active);
    } else {
        switch (c_openssl.family) {
            .openssl => try testing.expect(active == .openssl or active == .@"openssl-approved"),
            .@"aws-lc" => try testing.expect(active == .@"aws-lc" or active == .@"aws-lc-approved"),
            .boringssl => try testing.expectEqual(Backend.boringssl, active),
        }
    }

    // Field names remain stable public metadata values.
    try testing.expectEqualStrings("native", @tagName(@as(@TypeOf(active), .native)));
    try testing.expectEqualStrings("openssl", @tagName(@as(@TypeOf(active), .openssl)));
    try testing.expectEqualStrings("aws-lc", @tagName(@as(@TypeOf(active), .@"aws-lc")));
    try testing.expectEqualStrings("boringssl", @tagName(@as(@TypeOf(active), .boringssl)));
    try testing.expectEqualStrings(
        "openssl-approved",
        @tagName(@as(@TypeOf(active), .@"openssl-approved")),
    );
    try testing.expectEqualStrings(
        "aws-lc-approved",
        @tagName(@as(@TypeOf(active), .@"aws-lc-approved")),
    );
}

// RFC 8446 §9.1 — TLS 1.3 endpoints need at least one mutually supported
// cipher suite, key-share group, and CertificateVerify scheme to handshake.
test "capabilities are non-empty for the active backend" {
    try testing.expect(capabilities.cipher_suites.len > 0);
    try testing.expect(capabilities.client_x25519 or capabilities.client_p256);
    try testing.expect(capabilities.server_x25519 or capabilities.server_p256);
    try testing.expect(capabilities.certificate_verify_schemes.len > 0);
    try testing.expect(capabilities.certificate_signature_schemes.len > 0);
}

// The AWS-LC and BoringSSL X25519 paths use their flat curve25519 API with a
// value handle; keep it from silently regressing to the OpenSSL EVP_PKEY
// pointer shape.
test "x25519 handle shape matches active backend" {
    const evp_pointer_size = @sizeOf(*anyopaque);
    switch (active) {
        .openssl, .@"openssl-approved" => try testing.expectEqual(
            evp_pointer_size,
            @sizeOf(x25519.pkey),
        ),
        .native, .@"aws-lc", .@"aws-lc-approved", .boringssl => {
            try testing.expect(@sizeOf(x25519.pkey) > evp_pointer_size);
        },
    }
}

// Client first-flight key-share plumbing supports X25519 and P-256. An
// approved-only build carries P-256 only.
test "client group capabilities match implemented client key-share plumbing" {
    try testing.expect(capabilities.client_x25519 or capabilities.client_p256);
    if (active == .native) try testing.expect(capabilities.client_x25519);
    try testing.expect(capabilities.client_p256);
}

test "aead context shape matches active backend" {
    if (comptime native_selected) {
        try testing.expectEqual(@sizeOf(backend_native.AeadContext), @sizeOf(aead.Context));
        return;
    }
    switch (active) {
        .openssl, .@"openssl-approved" => try testing.expectEqual(
            @sizeOf(backend_openssl.AeadContext),
            @sizeOf(aead.Context),
        ),
        .@"aws-lc", .@"aws-lc-approved", .boringssl => try testing.expect(
            @sizeOf(aead.Context) != @sizeOf(backend_openssl.AeadContext),
        ),
        .native => unreachable,
    }
}

test "aws-lc aead deinit clears inline context" {
    if (comptime native_selected) return error.SkipZigTest;
    if (active != .@"aws-lc" and active != .@"aws-lc-approved") return error.SkipZigTest;

    const key: [16]u8 = @splat(0xab);
    var ctx = try backend_aws_lc.aeadInit(.aes_128_gcm_sha256, &key);
    backend_aws_lc.aeadDeinit(&ctx);

    for (std.mem.asBytes(&ctx)) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "capability helpers recognize advertised algorithms" {
    for (capabilities.cipher_suites) |suite| try testing.expect(supportsCipherSuite(suite));
    for (capabilities.certificate_verify_schemes) |scheme| {
        try testing.expect(supportsCertificateVerifyScheme(scheme));
    }
}

// Approved-algorithm divergence: the approved-only table narrows the default
// set to algorithms a NIST-approved FIPS policy covers. These tests are
// comptime-correct regardless of which libcrypto is actually linked.

// ChaCha20-Poly1305 is not a NIST-approved algorithm, so the approved table
// must not advertise it.
test "approved: chacha20_poly1305_sha256 excluded from the approved cipher_suites" {
    const suites = switch (active) {
        .openssl, .@"openssl-approved" => backend_openssl.capabilities_approved.cipher_suites,
        .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc.capabilities_approved.cipher_suites,
        .boringssl, .native => return error.SkipZigTest,
    };
    for (suites) |suite| {
        try testing.expect(suite != .chacha20_poly1305_sha256);
    }
}

// X25519 is not approved for key agreement (FIPS 140-3 IG, SP 800-56Arev3),
// so an approved-only build must not advertise it in either role.
test "approved: x25519 excluded from the approved group capability" {
    const caps = switch (active) {
        .openssl, .@"openssl-approved" => backend_openssl.capabilities_approved,
        .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc.capabilities_approved,
        .boringssl, .native => return error.SkipZigTest,
    };
    try testing.expect(!caps.client_x25519);
    try testing.expect(!caps.server_x25519);
    try testing.expect(caps.client_p256 and caps.server_p256);
}

// FIPS 186-5 approves RSASSA-PKCS1-v1_5 and EdDSA alongside ECDSA, so the
// certificate-chain table keeps them; the approved profile is not a claim
// that they are prohibited.
test "approved: certificate_signature_schemes cover the FIPS 186-5 signature families" {
    const schemes = switch (active) {
        .openssl, .@"openssl-approved" => approvedCertSigSchemes(.openssl),
        .@"aws-lc", .@"aws-lc-approved" => approvedCertSigSchemes(.@"aws-lc"),
        .boringssl, .native => return error.SkipZigTest,
    };
    try testing.expect(schemeInList(.rsa_pkcs1_sha256, schemes));
    try testing.expect(schemeInList(.ecdsa_secp256r1_sha256, schemes));
    try testing.expect(schemeInList(.ed25519, schemes));
}

// FIPS 203 approves ML-KEM, but the RFC 10024 hybrid composition is this
// library's own construction and is not an approved scheme, so the approved
// table disables every hybrid group.
test "approved: hybrid groups disabled in the approved capability table" {
    const fips_caps = switch (active) {
        .openssl, .@"openssl-approved" => backend_openssl.capabilities_approved,
        .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc.capabilities_approved,
        .boringssl, .native => return error.SkipZigTest,
    };
    const hybrid_capabilities = [_]bool{
        fips_caps.client_x25519_mlkem768,
        fips_caps.server_x25519_mlkem768,
        fips_caps.client_secp256r1_mlkem768,
        fips_caps.server_secp256r1_mlkem768,
        fips_caps.client_secp384r1_mlkem1024,
        fips_caps.server_secp384r1_mlkem1024,
    };
    for (hybrid_capabilities) |enabled| try testing.expect(!enabled);
}

// The approved table must be a subset of the default table. The comptime
// assertion above proves this at build time; this test also checks it for the
// active backend pair.
test "approved: approved capabilities are a subset of the default capabilities" {
    const fips_caps = switch (active) {
        .openssl, .@"openssl-approved" => backend_openssl.capabilities_approved,
        .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc.capabilities_approved,
        .boringssl, .native => return error.SkipZigTest,
    };
    const base_caps = switch (active) {
        .openssl, .@"openssl-approved" => backend_openssl.capabilities,
        .@"aws-lc", .@"aws-lc-approved" => backend_aws_lc.capabilities,
        .boringssl, .native => return error.SkipZigTest,
    };
    for (fips_caps.cipher_suites) |suite| {
        try testing.expect(suiteInList(suite, base_caps.cipher_suites));
    }
    for (fips_caps.certificate_verify_schemes) |scheme| {
        try testing.expect(schemeInList(scheme, base_caps.certificate_verify_schemes));
    }
    for (fips_caps.certificate_signature_schemes) |scheme| {
        try testing.expect(schemeInList(scheme, base_caps.certificate_signature_schemes));
    }
}

// An approved-only build must not advertise ChaCha20-Poly1305; a default build
// must.
test "approved: active capabilities follow the build policy" {
    if (approved_only) {
        try testing.expect(!supportsCipherSuite(.chacha20_poly1305_sha256));
    } else {
        try testing.expect(supportsCipherSuite(.chacha20_poly1305_sha256));
    }
}

fn suiteInList(suite: CipherSuite, list: []const CipherSuite) bool {
    for (list) |s| {
        if (s == suite) return true;
    }
    return false;
}

fn schemeInList(scheme: SignatureScheme, list: []const SignatureScheme) bool {
    for (list) |s| {
        if (s == scheme) return true;
    }
    return false;
}
