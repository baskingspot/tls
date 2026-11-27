//! TLS capability policy for the selected provider.
const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const backend = @import("crypto/backend.zig");
const CipherSuite = @import("cipher_suite.zig").CipherSuite;
const SignatureScheme = @import("signature_scheme.zig").SignatureScheme;

pub const current = switch (backend.active) {
    .native => native,
    .openssl => openssl,
    .@"openssl-approved" => openssl_approved,
    .@"aws-lc" => aws_lc,
    .@"aws-lc-approved" => aws_lc_approved,
    .boringssl => boringssl,
};

comptime {
    assert(current.cipher_suites.len > 0);
    assert(current.client_x25519 or current.client_p256);
    assert(current.server_x25519 or current.server_p256);
    assert(current.certificate_verify_schemes.len > 0);
    if (backend.active == .native) {
        assert(current.client_p256 and current.server_p256);
        assert(current.client_p384 and current.server_p384);
        assert(current.client_x25519_mlkem768);
        assert(current.server_x25519_mlkem768);
        assert(current.client_secp256r1_mlkem768);
        assert(current.server_secp256r1_mlkem768);
        assert(!current.client_secp384r1_mlkem1024);
        assert(!current.server_secp384r1_mlkem1024);
    }
    assert(current.certificate_signature_schemes.len > 0);
    assert(current.client_p384 == current.server_p384);
    assert(current.client_x25519_mlkem768 == current.server_x25519_mlkem768);
    assert(current.client_secp256r1_mlkem768 == current.server_secp256r1_mlkem768);
    assert(current.client_secp384r1_mlkem1024 == current.server_secp384r1_mlkem1024);

    if (!backend.native_selected) {
        assertSubset(openssl_approved.cipher_suites, openssl.cipher_suites);
        assertSubset(
            openssl_approved.certificate_verify_schemes,
            openssl.certificate_verify_schemes,
        );
        assertSubset(
            openssl_approved.certificate_signature_schemes,
            openssl.certificate_signature_schemes,
        );
        assertSubset(aws_lc_approved.cipher_suites, aws_lc.cipher_suites);
        assertSubset(
            aws_lc_approved.certificate_verify_schemes,
            aws_lc.certificate_verify_schemes,
        );
        assertSubset(
            aws_lc_approved.certificate_signature_schemes,
            aws_lc.certificate_signature_schemes,
        );
    }
}

fn assertSubset(comptime subset: anytype, comptime base: anytype) void {
    for (subset) |item| {
        var found = false;
        for (base) |candidate| {
            if (item == candidate) {
                found = true;
                break;
            }
        }
        assert(found);
    }
}

pub const native = struct {
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

    // CertificateVerify uses in-tree ECDSA and verification-only RSA-PSS.
    // Chain verification also accepts RSA PKCS#1 v1.5. Ed25519 remains a
    // chain-signature scheme, not a CertificateVerify scheme.
    pub const certificate_verify_schemes: []const SignatureScheme = &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
    };

    pub const certificate_signature_schemes: []const SignatureScheme = &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .ed25519,
    };
};

pub const openssl = struct {
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
    pub const client_secp384r1_mlkem1024 = true;
    pub const server_x25519 = true;
    pub const server_p256 = true;
    pub const server_p384 = true;
    pub const server_x25519_mlkem768 = true;
    pub const server_secp256r1_mlkem768 = true;
    pub const server_secp384r1_mlkem1024 = true;

    pub const certificate_verify_schemes: []const SignatureScheme = &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
    };

    // RFC 8446 §4.4.2.2 — signature_algorithms_cert constrains the
    // certificate-chain signature algorithm (cert-to-cert), which is
    // independent of the CertificateVerify scheme (§4.4.3). Ed25519 chain
    // signatures are verified via std.crypto.sign.Ed25519 in
    // certificate_parser.zig, not the backend seam, so they are advertised
    // here even though certificate_verify_schemes omits ed25519.
    pub const certificate_signature_schemes: []const SignatureScheme = &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .ed25519,
    };
};

/// Approved-algorithm capability table. `-Dcrypto-approved-only=true` selects
/// this table when OpenSSL headers are active.
///
/// This narrows negotiation to algorithms a NIST-approved FIPS policy covers.
/// It is not a validation claim: tls is not a FIPS 140-3 validated module, and
/// signature verification, the TLS key schedule, all randomness, and (on
/// OpenSSL) the transcript hash and EC key construction run outside the linked
/// module. `PRODUCTION_READINESS.md` lists what runs where.
pub const openssl_approved = struct {
    // ChaCha20-Poly1305 is not a NIST-approved algorithm.
    pub const cipher_suites: []const CipherSuite = &.{
        .aes_128_gcm_sha256,
        .aes_256_gcm_sha384,
    };

    pub const client_p256 = true;
    pub const client_p384 = true;
    // FIPS 140-3 IG: "Curves that are included in SP 800-186 but not included
    // in SP 800-56Arev3 are not approved for key agreement". X25519 is one of
    // them, so an approved-only build must not advertise it.
    pub const client_x25519 = false;
    // FIPS 203 approves ML-KEM, but the RFC 10024 hybrid composition is this
    // library's own construction and is not an approved scheme.
    pub const client_x25519_mlkem768 = false;
    pub const client_secp256r1_mlkem768 = false;
    pub const client_secp384r1_mlkem1024 = false;
    pub const server_p256 = true;
    pub const server_p384 = true;
    pub const server_x25519 = false;
    pub const server_x25519_mlkem768 = false;
    pub const server_secp256r1_mlkem768 = false;
    pub const server_secp384r1_mlkem1024 = false;

    pub const certificate_verify_schemes: []const SignatureScheme = &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
    };

    // FIPS 186-5 approves RSASSA-PKCS1-v1_5 and EdDSA as well as ECDSA, so
    // certificate-chain signatures accept all three. CertificateVerify above
    // stays narrower because the engine has no Ed25519 CertificateVerify path.
    pub const certificate_signature_schemes: []const SignatureScheme = &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .ed25519,
    };
};

pub const aws_lc = struct {
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
    pub const client_secp384r1_mlkem1024 = true;
    pub const server_x25519 = true;
    pub const server_p256 = true;
    pub const server_p384 = true;
    pub const server_x25519_mlkem768 = true;
    pub const server_secp256r1_mlkem768 = true;
    pub const server_secp384r1_mlkem1024 = true;

    pub const certificate_verify_schemes: []const SignatureScheme = &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
    };

    // RFC 8446 §4.4.2.2 — signature_algorithms_cert constrains the
    // certificate-chain signature algorithm (cert-to-cert), which is
    // independent of the CertificateVerify scheme (§4.4.3). Ed25519 chain
    // signatures are verified via std.crypto.sign.Ed25519 in
    // certificate_parser.zig, not the backend seam, so they are advertised
    // here even though certificate_verify_schemes omits ed25519. These are
    // declared here, not reexported from OpenSSL, so AWS-LC can diverge when
    // provider/FIPS version probing says it must.
    pub const certificate_signature_schemes: []const SignatureScheme = &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .ed25519,
    };
};

/// FIPS 140-3 narrowed capability table. Signature verification is outside the
/// validated module: certificate-chain and CertificateVerify signatures verify
/// in-tree (#183). `-Dcrypto-approved-only=true` selects this
/// table when AWS-LC headers are active. The caller is responsible for ensuring
/// the linked AWS-LC libcrypto is actually a FIPS-validated build. No runtime
/// provider probing is performed by tls.
pub const aws_lc_approved = struct {
    // ChaCha20-Poly1305 is not a NIST-approved algorithm.
    pub const cipher_suites: []const CipherSuite = &.{
        .aes_128_gcm_sha256,
        .aes_256_gcm_sha384,
    };

    pub const client_p256 = true;
    pub const client_p384 = true;
    // FIPS 140-3 IG: "Curves that are included in SP 800-186 but not included
    // in SP 800-56Arev3 are not approved for key agreement". X25519 is one of
    // them, so an approved-only build must not advertise it.
    pub const client_x25519 = false;
    // FIPS 203 approves ML-KEM, but the RFC 10024 hybrid composition is this
    // library's own construction and is not an approved scheme.
    pub const client_x25519_mlkem768 = false;
    pub const client_secp256r1_mlkem768 = false;
    pub const client_secp384r1_mlkem1024 = false;
    pub const server_p256 = true;
    pub const server_p384 = true;
    pub const server_x25519 = false;
    pub const server_x25519_mlkem768 = false;
    pub const server_secp256r1_mlkem768 = false;
    pub const server_secp384r1_mlkem1024 = false;

    pub const certificate_verify_schemes: []const SignatureScheme = &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
    };

    // FIPS 186-5 approves RSASSA-PKCS1-v1_5 and EdDSA as well as ECDSA, so
    // certificate-chain signatures accept all three. CertificateVerify above
    // stays narrower because the engine has no Ed25519 CertificateVerify path.
    pub const certificate_signature_schemes: []const SignatureScheme = &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .ed25519,
    };
};

pub const boringssl = struct {
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
    pub const client_secp384r1_mlkem1024 = true;
    pub const server_x25519 = true;
    pub const server_p256 = true;
    pub const server_p384 = true;
    pub const server_x25519_mlkem768 = true;
    pub const server_secp256r1_mlkem768 = true;
    pub const server_secp384r1_mlkem1024 = true;

    pub const certificate_verify_schemes: []const SignatureScheme = &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
    };

    // RFC 8446 §4.4.2.2 — signature_algorithms_cert constrains the
    // certificate-chain signature algorithm (cert-to-cert), which is
    // independent of the CertificateVerify scheme (§4.4.3). Ed25519 chain
    // signatures are verified via std.crypto.sign.Ed25519 in
    // certificate_parser.zig, not the backend seam, so they are advertised
    // here even though certificate_verify_schemes omits ed25519.
    pub const certificate_signature_schemes: []const SignatureScheme = &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .ed25519,
    };
};

test "capabilities are non-empty for the active backend" {
    try testing.expect(current.cipher_suites.len > 0);
    try testing.expect(current.client_x25519 or current.client_p256);
    try testing.expect(current.server_x25519 or current.server_p256);
    try testing.expect(current.certificate_verify_schemes.len > 0);
    try testing.expect(current.certificate_signature_schemes.len > 0);
}

test "client group capabilities match implemented client key-share plumbing" {
    try testing.expect(current.client_x25519 or current.client_p256);
    if (backend.active == .native) try testing.expect(current.client_x25519);
    try testing.expect(current.client_p256);
}

test "native capabilities scope RSA to verification" {
    if (backend.active != .native) return error.SkipZigTest;
    const pkcs1_schemes = [_]SignatureScheme{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
    };
    for (pkcs1_schemes) |scheme| {
        try testing.expect(std.mem.findScalar(
            SignatureScheme,
            current.certificate_signature_schemes,
            scheme,
        ) != null);
        try testing.expect(std.mem.findScalar(
            SignatureScheme,
            current.certificate_verify_schemes,
            scheme,
        ) == null);
    }
    const pss_schemes = [_]SignatureScheme{
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
    };
    for (pss_schemes) |scheme| {
        try testing.expect(std.mem.findScalar(
            SignatureScheme,
            current.certificate_verify_schemes,
            scheme,
        ) != null);
        try testing.expect(std.mem.findScalar(
            SignatureScheme,
            current.certificate_signature_schemes,
            scheme,
        ) != null);
    }
    try testing.expect(current.client_x25519_mlkem768);
    try testing.expect(current.server_x25519_mlkem768);
    try testing.expect(current.client_secp256r1_mlkem768);
    try testing.expect(current.server_secp256r1_mlkem768);
    try testing.expect(!current.client_secp384r1_mlkem1024);
    try testing.expect(!current.server_secp384r1_mlkem1024);
}

test "approved: chacha20_poly1305_sha256 excluded from the approved cipher_suites" {
    const suites = switch (backend.active) {
        .openssl, .@"openssl-approved" => openssl_approved.cipher_suites,
        .@"aws-lc", .@"aws-lc-approved" => aws_lc_approved.cipher_suites,
        .boringssl, .native => return error.SkipZigTest,
    };
    for (suites) |suite| try testing.expect(suite != .chacha20_poly1305_sha256);
}

test "approved: x25519 excluded from the approved group capability" {
    const caps = switch (backend.active) {
        .openssl, .@"openssl-approved" => openssl_approved,
        .@"aws-lc", .@"aws-lc-approved" => aws_lc_approved,
        .boringssl, .native => return error.SkipZigTest,
    };
    try testing.expect(!caps.client_x25519);
    try testing.expect(!caps.server_x25519);
    try testing.expect(caps.client_p256 and caps.server_p256);
}

fn approvedCertSigSchemes(comptime family: @TypeOf(backend.active)) []const SignatureScheme {
    return switch (family) {
        .openssl => openssl_approved.certificate_signature_schemes,
        .@"aws-lc" => aws_lc_approved.certificate_signature_schemes,
        else => unreachable,
    };
}

test "approved: certificate_signature_schemes cover the FIPS 186-5 signature families" {
    const schemes = switch (backend.active) {
        .openssl, .@"openssl-approved" => approvedCertSigSchemes(.openssl),
        .@"aws-lc", .@"aws-lc-approved" => approvedCertSigSchemes(.@"aws-lc"),
        .boringssl, .native => return error.SkipZigTest,
    };
    try testing.expect(schemeInList(.rsa_pkcs1_sha256, schemes));
    try testing.expect(schemeInList(.ecdsa_secp256r1_sha256, schemes));
    try testing.expect(schemeInList(.ed25519, schemes));
}

test "approved: hybrid groups disabled in the approved capability table" {
    const caps = switch (backend.active) {
        .openssl, .@"openssl-approved" => openssl_approved,
        .@"aws-lc", .@"aws-lc-approved" => aws_lc_approved,
        .boringssl, .native => return error.SkipZigTest,
    };
    const hybrid_capabilities = [_]bool{
        caps.client_x25519_mlkem768,
        caps.server_x25519_mlkem768,
        caps.client_secp256r1_mlkem768,
        caps.server_secp256r1_mlkem768,
        caps.client_secp384r1_mlkem1024,
        caps.server_secp384r1_mlkem1024,
    };
    for (hybrid_capabilities) |enabled| try testing.expect(!enabled);
}

test "approved: approved capabilities are a subset of the default capabilities" {
    const fips_caps = switch (backend.active) {
        .openssl, .@"openssl-approved" => openssl_approved,
        .@"aws-lc", .@"aws-lc-approved" => aws_lc_approved,
        .boringssl, .native => return error.SkipZigTest,
    };
    const base_caps = switch (backend.active) {
        .openssl, .@"openssl-approved" => openssl,
        .@"aws-lc", .@"aws-lc-approved" => aws_lc,
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

fn suiteInList(suite: CipherSuite, list: []const CipherSuite) bool {
    for (list) |candidate| {
        if (candidate == suite) return true;
    }
    return false;
}

fn schemeInList(scheme: SignatureScheme, list: []const SignatureScheme) bool {
    for (list) |candidate| {
        if (candidate == scheme) return true;
    }
    return false;
}
