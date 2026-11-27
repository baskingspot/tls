//! Crypto provider selection.
//!
//! The default `native` backend selects pure-Zig primitives and does not import
//! the facade. `auto` detects the libcrypto family from its headers.
const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const build_options = @import("build_options");

pub const native_selected = build_options.crypto == .native;
// ziglint-ignore: Z028 — native must not resolve the libcrypto module import.
const c_openssl = if (native_selected) struct {} else @import("c_openssl.zig");

pub const ParameterSet = @import("mlkem_parameters.zig").ParameterSet;
pub const AeadAlgorithm = @import("types.zig").AeadAlgorithm;
pub const CurveId = @import("types.zig").CurveId;
pub const SignatureAlgorithm = @import("types.zig").SignatureAlgorithm;
const backend_native = @import("backend_native.zig");
// ziglint-ignore: Z028 — native must not import any libcrypto backend.
const backend_aws_lc = if (native_selected) struct {} else @import("backend_aws_lc.zig");
// ziglint-ignore: Z028 — native must not import any libcrypto backend.
const backend_boringssl = if (native_selected) struct {} else @import("backend_boringssl.zig");
// ziglint-ignore: Z028 — native must not import any libcrypto backend.
const backend_openssl = if (native_selected) struct {} else @import("backend_openssl.zig");

/// Libcrypto uses runtime dispatch (#138). The default native backend uses
/// std's compile-time-selected SHA-256 and SHA-384 implementation.
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

/// Native selection wins without reading libcrypto headers. Auto and
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

pub fn supportsAlg(algorithm: AeadAlgorithm) bool {
    return aead_impl.supportsAlg(algorithm);
}

pub fn supportsCurve(curve: CurveId) bool {
    return switch (curve) {
        .x25519 => x25519_impl.supportsCurve(curve),
        .p256 => p256_impl.supportsCurve(curve),
        .p384 => p384_impl.supportsCurve(curve),
    };
}

pub fn supportsScheme(scheme: SignatureAlgorithm) bool {
    return sign_impl.supportsScheme(scheme);
}

pub fn supportsParameterSet(parameter_set: ParameterSet) bool {
    return kem_impl.supportsParameterSet(parameter_set);
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

fn slicesOverlap(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    return a_start < b_start + b.len and b_start < a_start + a.len;
}

pub const aead = struct {
    pub const Error = aead_impl.AeadError || error{InputAliasesOutput};
    pub const Context = aead_impl.AeadContext;
    pub const tag_len = aead_impl.aead_tag_len;
    pub const nonce_len = aead_impl.aead_nonce_len;

    pub inline fn init(suite: AeadAlgorithm, key_bytes: []const u8) Error!Context {
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
        if (plaintext.ptr != ciphertext.ptr and slicesOverlap(plaintext, ciphertext))
            return error.InputAliasesOutput;
        return aead_impl.aeadDecrypt(ctx, plaintext, ciphertext, tag, ad, npub);
    }
};

pub const sign = struct {
    pub const Error = sign_impl.SignatureError;
    /// A private key loaded from a file or from raw scalar bytes, minus what
    /// only one backend can name (#218). `signature.PrivateKey.fromPemAuto`
    /// adds its own `UnsupportedKeyScheme` on top.
    pub const LoadError = if (native_selected)
        backend_native.KeyLoadError
    else
        sign_impl.SignatureError;
    /// `privateKeyFromP256Scalar` only: native can name an out-of-range scalar,
    /// and libcrypto reports the same input as a provider failure (#88).
    pub const ScalarKeyError = if (native_selected)
        backend_native.ScalarKeyError
    else
        sign_impl.SignatureError;
    pub const SignError = sign_impl.SignError;
    pub const NonceMode = sign_impl.NonceMode;

    /// A libcrypto pointer or an inline native key, depending on the backend.
    pub const pkey = sign_impl.EcKey;
    pub inline fn privateKeyFromDer(der: []const u8) LoadError!pkey {
        return sign_impl.privateKeyFromDer(der);
    }

    pub inline fn privateKeyFromPem(pem: []const u8) LoadError!pkey {
        return sign_impl.privateKeyFromPem(pem);
    }

    pub const KeySchemeError = sign_impl.KeySchemeError;

    pub inline fn keyScheme(key: pkey) KeySchemeError!SignatureAlgorithm {
        return sign_impl.keyScheme(key);
    }

    pub inline fn privateKeyPairsWithCertificate(
        key: pkey,
        leaf_cert_der: []const u8,
    ) error{InvalidEncoding}!bool {
        return sign_impl.privateKeyPairsWithCertificate(key, leaf_cert_der);
    }

    pub inline fn privateKeyFromP256Scalar(scalar: *const [32]u8) ScalarKeyError!pkey {
        return sign_impl.privateKeyFromP256Scalar(scalar);
    }

    pub inline fn freeKey(key: *pkey) void {
        sign_impl.freeEcKey(key);
    }

    pub inline fn sign(
        key: pkey,
        scheme: SignatureAlgorithm,
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
    var ctx = try backend_aws_lc.aeadInit(.aes_128_gcm, &key);
    backend_aws_lc.aeadDeinit(&ctx);

    for (std.mem.asBytes(&ctx)) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "primitive availability follows the active provider" {
    const key: [32]u8 = @splat(0xab);
    for (std.enums.values(AeadAlgorithm)) |algorithm| {
        try testing.expectEqual(
            !approved_only or algorithm != .chacha20_poly1305,
            supportsAlg(algorithm),
        );
        if (supportsAlg(algorithm)) {
            var ctx = try aead.init(algorithm, key[0..algorithm.keyLen()]);
            defer aead.deinit(&ctx);
        }
    }
    for (std.enums.values(CurveId)) |curve| {
        try testing.expectEqual(!approved_only or curve != .x25519, supportsCurve(curve));
    }
    for (std.enums.values(SignatureAlgorithm)) |scheme| {
        const expected = switch (scheme) {
            .ecdsa_p256_sha256, .ecdsa_p384_sha384 => true,
            .rsa_pss_sha256, .rsa_pss_sha384, .rsa_pss_sha512 => active != .native,
            else => false,
        };
        try testing.expectEqual(expected, supportsScheme(scheme));
    }
    for (std.enums.values(ParameterSet)) |parameter_set| {
        const expected = if (active == .native)
            parameter_set == .mlkem768
        else
            !approved_only;
        try testing.expectEqual(expected, supportsParameterSet(parameter_set));
    }
}
