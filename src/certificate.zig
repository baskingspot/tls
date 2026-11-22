//! TLS 1.3 Certificate and CertificateVerify handshake message handling.
//!
//! RFC 8446 §4.4.2, §4.4.3
const std = @import("std");
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const testing = std.testing;
const print = std.debug.print;
const mem = std.mem;
const assert = std.debug.assert;
const fixtures = @import("fixtures");
const fuzz_compat = @import("fuzz_compat.zig");
const compat = @import("compat.zig");

const stdx = @import("stdx");
const buffer = stdx.buffer;
const certificate_policy = @import("certificate_policy.zig");
pub const LeafUsage = certificate_policy.LeafUsage;
pub const Policy = certificate_policy.Policy;
pub const PolicyError = certificate_policy.PolicyError;
const Certificate = @import("certificate_parser.zig");
const ecdsa = @import("crypto/ecdsa.zig");
const extension_type = @import("extension_type.zig");
const ExtensionType = extension_type.ExtensionType;
const handshake = @import("handshake.zig");
const signature_scheme = @import("signature_scheme.zig");
const OfferedCertificateSchemes = signature_scheme.OfferedCertificateSchemes;
pub const SignatureScheme = signature_scheme.SignatureScheme;
const wire = @import("wire.zig");

/// Test-only overrides for the fields a certificate test varies.
const PolicyOverrides = struct {
    bundle: ?*const Certificate.Bundle = null,
    insecure_no_chain_anchor: bool = false,
    now_sec: i64 = 0,
    host_name: ?[]const u8 = null,
    leaf_usage: LeafUsage = .server_auth,
    certificate_signature_schemes: ?[]const SignatureScheme = null,
};

fn testPolicy(overrides: PolicyOverrides) Policy {
    var policy: Policy = .init;
    policy.bundle = overrides.bundle;
    policy.insecure_no_chain_anchor = overrides.insecure_no_chain_anchor;
    policy.now_sec = overrides.now_sec;
    policy.host_name = overrides.host_name;
    policy.leaf_usage = overrides.leaf_usage;
    if (overrides.certificate_signature_schemes) |schemes|
        policy.certificate_signature_schemes = schemes;
    return policy;
}

pub const ParseError = error{
    UnexpectedEof,
    InvalidHandshakeType,
    InvalidHandshakeLength,
    UnexpectedCertificateRequestContext,
    EmptyCertificateList,
    InvalidExtensionLength,
    DuplicateExtension,
    UnsupportedExtension,
    UnexpectedExtension,
    CertificateIssuerNotFound,
    MissingTrustAnchor,
    CertificateChainTooLong,
} || PolicyError ||
    Certificate.ParseError ||
    Certificate.Parsed.VerifyError ||
    Certificate.Parsed.VerifyHostNameError ||
    Certificate.Parsed.NameConstraintError;

pub const EncodeError = error{ BufferTooShort, RequestContextTooLong };

pub const ClientCertificateStatus = enum {
    empty,
    present,
};

/// Verified client leaf material borrowed from the Certificate message.
pub const VerifiedClientChain = struct {
    pub_key: []const u8,
    leaf_der: []const u8,
};

pub fn encodedLen(certs_der: []const []const u8) usize {
    return encodedLenWithRequestContext(0, certs_der);
}

pub fn encodedLenWithRequestContext(
    request_context_len: usize,
    certs_der: []const []const u8,
) usize {
    var list_len: usize = 0;
    for (certs_der) |cert_der| list_len += 3 + cert_der.len + 2;
    return 4 + 1 + request_context_len + 3 + list_len;
}

/// Encode a TLS 1.3 Certificate handshake message with empty request_context
/// and empty per-certificate extensions. RFC 8446 §4.4.2.
pub fn encode(out: []u8, certs_der: []const []const u8) EncodeError![]const u8 {
    return encodeWithRequestContext(out, &.{}, certs_der);
}

/// Encode a TLS 1.3 Certificate handshake message with the request_context
/// echoed from CertificateRequest. RFC 8446 §4.4.2.
pub fn encodeWithRequestContext(
    out: []u8,
    request_context: []const u8,
    certs_der: []const []const u8,
) EncodeError![]const u8 {
    if (request_context.len > std.math.maxInt(u8)) return error.RequestContextTooLong;
    const len = encodedLenWithRequestContext(request_context.len, certs_der);
    if (out.len < len) return error.BufferTooShort;
    var w: wire.Writer = .init(out);
    const list_len = len - 4 - 1 - request_context.len - 3;
    w.appendAssumeCapacity(handshake.Type, .certificate);
    w.appendAssumeCapacity(u24, @intCast(len - 4));
    w.appendAssumeCapacity(u8, @intCast(request_context.len));
    w.appendSliceAssumeCapacity(request_context);
    w.appendAssumeCapacity(u24, @intCast(list_len));
    for (certs_der) |cert_der| {
        w.appendAssumeCapacity(u24, @intCast(cert_der.len));
        w.appendSliceAssumeCapacity(cert_der);
        w.appendAssumeCapacity(u16, 0x0000);
    }
    return w.buffered();
}

/// Parse a client Certificate message enough for server-side client-auth state
/// machine decisions. Full client certificate validation is intentionally left
/// to the later #4 verification slice; this helper validates framing,
/// request_context echo, list bounds, and per-entry extension syntax.
///
/// RFC 8446 §4.4.2
pub fn parseClientCertificate(
    msg: []const u8,
    expected_request_context: []const u8,
) ParseError!ClientCertificateStatus {
    if (msg.len < 4 + 1 + 3) return error.UnexpectedEof;
    var r: wire.Reader = .init(msg);

    const handshake_type = r.assumeRead(handshake.Type);
    if (handshake_type != .certificate) return error.InvalidHandshakeType;
    const body_len = r.assumeRead(u24);
    if (body_len != msg.len - 4) return error.InvalidHandshakeLength;

    const ctx_len = r.assumeRead(u8);
    if (r.remaining().len < @as(usize, ctx_len) + 3) return error.UnexpectedEof;
    const request_context = r.assumeReadSlice(ctx_len);
    if (!mem.eql(u8, request_context, expected_request_context))
        return error.UnexpectedCertificateRequestContext;

    const list_len = r.assumeRead(u24);
    if (r.remaining().len < list_len) return error.UnexpectedEof;
    if (list_len == 0) return .empty;

    const list_end = r.end + list_len;
    while (r.end < list_end) {
        if (list_end - r.end < 3) return error.UnexpectedEof;
        const cert_len = r.assumeRead(u24);
        if (list_end - r.end < @as(usize, cert_len) + 2) return error.UnexpectedEof;
        r.assumeSkip(cert_len);
        const ext_len = r.assumeRead(u16);
        if (list_end - r.end < ext_len) return error.UnexpectedEof;
        try parseCertificateEntryExtensions(r.assumeReadSlice(ext_len));
    }
    if (r.end != list_end) return error.UnexpectedEof;
    return .present;
}

/// Parse a client Certificate handshake message (echoing the CertificateRequest
/// request_context), return the verified leaf public key and DER as slices into
/// `msg`, and run chain validation per `policy`. Mirrors `parse` but accepts the
/// non-empty client request_context and uses the client-auth leaf policy. The
/// caller must keep `msg` alive until the returned slices have been consumed.
/// RFC 8446 §4.4.2 (client Certificate), §4.4.3 (client CertificateVerify).
pub fn parseClientChain(
    msg: []const u8,
    expected_request_context: []const u8,
    policy: Policy,
) ParseError!VerifiedClientChain {
    if (msg.len < 4 + 1 + 3) return error.UnexpectedEof;
    var r: wire.Reader = .init(msg);

    const handshake_type = r.assumeRead(handshake.Type);
    if (handshake_type != .certificate) return error.InvalidHandshakeType;
    const body_len = r.assumeRead(u24);
    if (body_len != msg.len - 4) return error.InvalidHandshakeLength;

    const ctx_len = r.assumeRead(u8);
    if (r.remaining().len < @as(usize, ctx_len) + 3) return error.UnexpectedEof;
    const request_context = r.assumeReadSlice(ctx_len);
    if (!mem.eql(u8, request_context, expected_request_context))
        return error.UnexpectedCertificateRequestContext;

    const list_len = r.assumeRead(u24);
    if (list_len == 0) return error.EmptyCertificateList;
    if (r.remaining().len < list_len) return error.UnexpectedEof;

    const list_end = r.end + list_len;
    var cert_index: usize = 0;
    var leaf_pub_key: ?[]const u8 = null;
    var leaf_der: ?[]const u8 = null;
    var subject_to_verify: ?Certificate.Parsed = null;
    var chain: buffer.Array(Certificate.Parsed, 8) = .empty;

    while (r.end < list_end) {
        if (list_end - r.end < 3) return error.UnexpectedEof;
        const cert_len = r.assumeRead(u24);
        if (list_end - r.end < @as(usize, cert_len) + 2) return error.UnexpectedEof;
        const cert_der = r.assumeReadSlice(cert_len);
        const ext_len = r.assumeRead(u16);
        if (list_end - r.end < ext_len) return error.UnexpectedEof;
        try parseCertificateEntryExtensions(r.assumeReadSlice(ext_len));

        const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
        const parsed = try cert.parse();
        chain.append(parsed) catch return error.CertificateChainTooLong;

        if (cert_index == 0) {
            leaf_pub_key = parsed.pubKey();
            leaf_der = cert_der;
            switch (policy.leaf_usage) {
                .none => {},
                .server_auth => try certificate_policy.verifyServerAuthWithSignatureSchemes(
                    parsed,
                    policy.certificate_signature_schemes,
                ),
                .client_auth => try certificate_policy.verifyClientAuthWithSignatureSchemes(
                    parsed,
                    policy.certificate_signature_schemes,
                ),
            }
            if (policy.host_name) |host_name| try parsed.verifyHostName(host_name);
        }
        if (subject_to_verify) |subject| {
            try certificate_policy.verifyIssuerUsage(parsed, policy.leaf_usage);
            try subject.verify(parsed, policy.now_sec);
        }
        subject_to_verify = parsed;
        cert_index += 1;
    }
    if (r.end != list_end) return error.UnexpectedEof;

    if (chain.constSlice().len == 0) return error.EmptyCertificateList;
    try verifyChainCertificateSignatureAlgorithms(
        chain.constSlice(),
        policy.certificate_signature_schemes,
    );
    if (policy.bundle) |bundle| {
        const anchored = try anchorChain(
            bundle,
            chain.constSlice(),
            policy.now_sec,
            policy.leaf_usage,
        );
        try verifyChainPathLength(chain.constSlice(), anchored.anchor, anchored.top);
        try verifyChainNameConstraints(chain.constSlice(), anchored.anchor);
    } else if (!policy.insecure_no_chain_anchor) {
        return error.MissingTrustAnchor;
    } else {
        // RFC 5280 §6.1 — with no anchor, the whole presented chain is the
        // path; a presented self-signed root behaves like an anchor because
        // §6.1.4(l) never charges a self-issued certificate budget while
        // §6.1.4(m) still applies its constraint.
        try verifyChainPathLength(chain.constSlice(), null, chain.constSlice().len - 1);
        try verifyChainNameConstraints(chain.constSlice(), null);
    }

    return .{
        .pub_key = leaf_pub_key orelse return error.EmptyCertificateList,
        .leaf_der = leaf_der orelse return error.EmptyCertificateList,
    };
}

/// Trusted-first path building: anchor the presented chain at the highest
/// certificate whose issuer is a trust anchor in the bundle. Servers may
/// terminate the presented chain at a cross-signed root (e.g. SSL.com 2022
/// roots cross-signed by Comodo AAA Certificate Services) whose issuer is not
/// a trust anchor, while a lower certificate's issuer is. Walking the chain
/// from the top down and accepting the first bundle hit matches OpenSSL's
/// default trusted-first behavior. A bundle hit whose signature or usage
/// checks fail is a hard error, not a cue to keep walking.
const AnchoredChain = struct {
    anchor: Certificate.Parsed,
    /// Index of the highest in-path certificate — the one the anchor issues,
    /// RFC 5280 §6.1 certificate 1. Presented certificates above it are
    /// outside the path for this constraint check. The parser separately
    /// verifies all presented signatures before anchor selection.
    top: usize,
};

fn anchorChain(
    bundle: *const Certificate.Bundle,
    chain: []const Certificate.Parsed,
    now_sec: i64,
    leaf_usage: LeafUsage,
) certificate_policy.VerifyAgainstBundleError!AnchoredChain {
    var i = chain.len;
    while (i > 0) {
        i -= 1;
        const anchor = certificate_policy.findVerifiedIssuerInBundle(
            bundle,
            chain[i],
            now_sec,
            leaf_usage,
        ) catch |err| switch (err) {
            error.CertificateIssuerNotFound => continue,
            else => return err,
        };
        return .{ .anchor = anchor, .top = i };
    }
    return error.CertificateIssuerNotFound;
}

/// RFC 5280 §4.2.1.9 / §6.1 — enforce pathLenConstraint over the
/// certification path (#118). `chain` is the presented chain, leaf-first;
/// `top` is the index of the path's first certificate (§6.1 certificate 1,
/// the one the trust anchor issues); `anchor` is the parsed bundle anchor, or
/// null on the explicit no-anchor path where the whole presented chain is
/// the path.
///
/// Tracks the §6.1.2(k) max_path_length state variable: initialized to the
/// trust anchor's pathLenConstraint when the anchor certificate carries one
/// (§6.1.1(d)(g) trust-anchor inputs; OpenSSL applies an anchor's constraint
/// and tls matches — tests/fixtures/pathlen/README.md records the
/// differential), else to the path length n, which no presented chain can
/// exceed. §6.1.4(l) charges one unit for every non-self-issued path
/// certificate except the final one (§4.2.1.9: the last certificate is not
/// an intermediate and is not counted) and rejects when the budget is
/// exhausted; §6.1.4(m) tightens the budget to any smaller pathLenConstraint
/// on a path certificate, so the tightest constraint binds. No allocation:
/// two comparisons per already-parsed certificate.
fn verifyChainPathLength(
    chain: []const Certificate.Parsed,
    anchor: ?Certificate.Parsed,
    top: usize,
) PolicyError!void {
    var max_path_length: usize = top + 1;
    if (anchor) |trust_anchor| {
        if (trust_anchor.basic_constraints_path_len) |limit| {
            max_path_length = @min(max_path_length, limit);
        }
    }

    var i = top;
    while (i > 0) : (i -= 1) {
        const cert = chain[i];
        // §6.1: self-issued certificates are not counted when evaluating
        // path length. §6.1.4(l): verify max_path_length is greater than
        // zero, then decrement.
        if (!mem.eql(u8, cert.subject(), cert.issuer())) {
            if (max_path_length == 0) return error.CertificatePathLengthExceeded;
            max_path_length -= 1;
        }
        // §6.1.4(m): reduce max_path_length to pathLenConstraint when smaller.
        if (cert.basic_constraints_path_len) |plc| {
            if (plc < max_path_length) max_path_length = plc;
        }
    }
}

/// Parse a Certificate handshake message and extract the leaf certificate
/// public key as a slice into `msg`. The caller must keep `msg` alive until
/// verifySignature has been called. Chain anchoring requires a trust bundle or
/// the explicit insecure_no_chain_anchor test/demo opt-in.
///
/// RFC 8446 §4.4.2
pub fn parse(msg: []const u8, policy: Policy) ParseError![]const u8 {
    if (msg.len < 4 + 1 + 3) return error.UnexpectedEof;
    var r: wire.Reader = .init(msg);

    const handshake_type = r.assumeRead(handshake.Type);
    if (handshake_type != .certificate) return error.InvalidHandshakeType;
    const body_len = r.assumeRead(u24);
    if (body_len != msg.len - 4) return error.InvalidHandshakeLength;

    const ctx_len = r.assumeRead(u8);
    if (ctx_len != 0) return error.UnexpectedCertificateRequestContext;
    if (r.remaining().len < 3) return error.UnexpectedEof;

    const list_len = r.assumeRead(u24);
    if (list_len == 0) return error.EmptyCertificateList;
    if (r.remaining().len < list_len) return error.UnexpectedEof;

    const list_end = r.end + list_len;
    var cert_index: usize = 0;
    var leaf_pub_key: ?[]const u8 = null;
    var subject_to_verify: ?Certificate.Parsed = null;
    var chain: buffer.Array(Certificate.Parsed, 8) = .empty;

    while (r.end < list_end) {
        if (list_end - r.end < 3) return error.UnexpectedEof;
        const cert_len = r.assumeRead(u24);
        if (list_end - r.end < @as(usize, cert_len) + 2) return error.UnexpectedEof;
        const cert_der = r.assumeReadSlice(cert_len);
        const ext_len = r.assumeRead(u16);
        if (list_end - r.end < ext_len) return error.UnexpectedEof;
        try parseCertificateEntryExtensions(r.assumeReadSlice(ext_len));

        const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
        const parsed = try cert.parse();
        chain.append(parsed) catch return error.CertificateChainTooLong;

        if (cert_index == 0) {
            leaf_pub_key = parsed.pubKey();
            switch (policy.leaf_usage) {
                .none => {},
                .server_auth => try certificate_policy.verifyServerAuthWithSignatureSchemes(
                    parsed,
                    policy.certificate_signature_schemes,
                ),
                .client_auth => try certificate_policy.verifyClientAuthWithSignatureSchemes(
                    parsed,
                    policy.certificate_signature_schemes,
                ),
            }
            if (policy.host_name) |host_name| try parsed.verifyHostName(host_name);
        }
        if (subject_to_verify) |subject| {
            try certificate_policy.verifyIssuerUsage(parsed, policy.leaf_usage);
            try subject.verify(parsed, policy.now_sec);
        }
        subject_to_verify = parsed;
        cert_index += 1;
    }
    if (r.end != list_end) return error.UnexpectedEof;

    if (chain.constSlice().len == 0) return error.EmptyCertificateList;
    try verifyChainCertificateSignatureAlgorithms(
        chain.constSlice(),
        policy.certificate_signature_schemes,
    );
    if (policy.bundle) |bundle| {
        const anchored = try anchorChain(
            bundle,
            chain.constSlice(),
            policy.now_sec,
            policy.leaf_usage,
        );
        try verifyChainPathLength(chain.constSlice(), anchored.anchor, anchored.top);
        try verifyChainNameConstraints(chain.constSlice(), anchored.anchor);
    } else if (!policy.insecure_no_chain_anchor) {
        return error.MissingTrustAnchor;
    } else {
        // RFC 5280 §6.1 — with no anchor, the whole presented chain is the
        // path; a presented self-signed root behaves like an anchor because
        // §6.1.4(l) never charges a self-issued certificate budget while
        // §6.1.4(m) still applies its constraint.
        try verifyChainPathLength(chain.constSlice(), null, chain.constSlice().len - 1);
        try verifyChainNameConstraints(chain.constSlice(), null);
    }

    return leaf_pub_key orelse error.EmptyCertificateList;
}

pub const ChainSignatureSchemesError = error{
    EmptyCertificateChain,
    InvalidCertificate,
    UnsupportedCertificateSignatureAlgorithm,
};

/// RFC 8446 §4.2.3, §4.4.2.2 — parse a configured certificate chain and return
/// the set of signature schemes the peer must accept to verify it. The leaf
/// (index 0) is always included, matching `parse`; subsequent self-signed
/// certificates (presented trust anchors) are exempt. Malformed DER or
/// unsupported signature algorithms fail loudly so callers surface bad
/// credentials at configuration time rather than failing every handshake.
pub fn chainRequiredSignatureSchemes(
    certs_der: []const []const u8,
) ChainSignatureSchemesError!OfferedCertificateSchemes {
    if (certs_der.len == 0) return error.EmptyCertificateChain;
    var required: OfferedCertificateSchemes = .empty;
    for (certs_der, 0..) |cert_der, index| {
        const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
        const parsed = cert.parse() catch return error.InvalidCertificate;
        if (index > 0 and mem.eql(u8, parsed.subject(), parsed.issuer())) continue;
        const scheme = certificate_policy.certificateSignatureScheme(
            parsed.signature_algorithm,
        ) orelse return error.UnsupportedCertificateSignatureAlgorithm;
        required.insert(scheme);
    }
    return required;
}

/// RFC 8446 §4.2.3, §4.4.2.2 — return true when every validated certificate in
/// `certs_der` uses a signature algorithm offered in `offered`.
pub fn chainMatchesSignatureSchemes(
    certs_der: []const []const u8,
    offered: OfferedCertificateSchemes,
) bool {
    const required = chainRequiredSignatureSchemes(certs_der) catch return false;
    return offered.containsAll(required);
}

fn verifyChainCertificateSignatureAlgorithms(
    chain: []const Certificate.Parsed,
    certificate_signature_schemes: []const SignatureScheme,
) PolicyError!void {
    for (chain) |cert| {
        if (mem.eql(u8, cert.subject(), cert.issuer())) continue;
        try certificate_policy.verifyCertificateSignatureAlgorithm(
            cert.signature_algorithm,
            certificate_signature_schemes,
        );
    }
}

fn parseCertificateEntryExtensions(exts: []const u8) ParseError!void {
    try extension_type.rejectDuplicateExtensions(exts);
    var r: wire.Reader = .init(exts);
    var got_status_request = false;
    var got_sct = false;
    var unsupported = false;
    while (r.remaining().len != 0) {
        if (r.remaining().len < 4) return error.InvalidExtensionLength;
        const ext_type = r.assumeRead(ExtensionType);
        const ext_len = r.assumeRead(u16);
        if (r.remaining().len < ext_len) return error.InvalidExtensionLength;
        r.assumeSkip(ext_len);

        switch (ext_type) {
            .status_request => {
                if (got_status_request) return error.DuplicateExtension;
                got_status_request = true;
                unsupported = true;
            },
            .signed_certificate_timestamp => {
                if (got_sct) return error.DuplicateExtension;
                got_sct = true;
                unsupported = true;
            },
            .status_request_v2 => return error.UnexpectedExtension,
            else => {},
        }
    }
    if (unsupported) return error.UnsupportedExtension;
}

fn verifyChainNameConstraints(
    chain: []const Certificate.Parsed,
    trust_anchor: ?Certificate.Parsed,
) Certificate.Parsed.NameConstraintError!void {
    var ca_index: usize = 1;
    while (ca_index < chain.len) : (ca_index += 1) {
        try verifyIssuerNameConstraints(chain[ca_index], chain[0..ca_index]);
    }
    if (trust_anchor) |issuer| try verifyIssuerNameConstraints(issuer, chain);
}

fn verifyIssuerNameConstraints(
    issuer: Certificate.Parsed,
    subjects: []const Certificate.Parsed,
) Certificate.Parsed.NameConstraintError!void {
    if (issuer.nameConstraints().len == 0) return;

    // `subjects` is ordered leaf-first, so index zero is the final certificate
    // where RFC 5280 does not allow the self-issued intermediate exemption.
    for (subjects, 0..) |subject, subject_index| {
        const leaf = subject_index == 0;
        if (!leaf and mem.eql(u8, subject.subject(), subject.issuer())) continue;
        try issuer.verifyNameConstraints(subject);
    }
}

/// Verify a signature over the CertificateVerify signed content.
///
/// `pub_key` is the leaf certificate's SubjectPublicKey bits: a SEC1 point for
/// ECDSA, an RSAPublicKey for RSA. Every scheme tls accepts for CertificateVerify
/// verifies here, on in-tree primitives rather than the crypto backend:
/// std.crypto for ECDSA, and the RSA module in `certificate_parser.zig` for
/// RSASSA-PSS. That module's PSS verifier had no caller before this path, so
/// #183 is where it starts to run. No libcrypto call is reachable from here,
/// so a peer cannot exercise the C backend through a signature. RFC 8446 §4.4.3.
fn verifySignedContent(
    scheme: SignatureScheme,
    pub_key: []const u8,
    signed_content: []const u8,
    sig: []const u8,
) VerifyError!void {
    const P256 = std.crypto.ecc.P256;
    const P384 = std.crypto.ecc.P384;
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => verifyEcdsa(P256, Sha256, pub_key, signed_content, sig),
        .ecdsa_secp384r1_sha384 => verifyEcdsa(P384, Sha384, pub_key, signed_content, sig),
        .rsa_pss_rsae_sha256 => verifyRsaPss(Sha256, pub_key, signed_content, sig),
        .rsa_pss_rsae_sha384 => verifyRsaPss(Sha384, pub_key, signed_content, sig),
        .rsa_pss_rsae_sha512 => verifyRsaPss(Sha512, pub_key, signed_content, sig),
        else => error.UnsupportedSignatureScheme,
    };
}

/// RFC 8446 §4.2.3 — ECDSA over the curve the scheme names. The key is the
/// certificate's SEC1 point. A point that does not decode on the named curve
/// is an invalid encoding; a well-formed key with a bad signature is a
/// verification failure. Chain verification answers `CertificateSignatureInvalid`
/// for both; this path keeps them apart because the handshake reports
/// `decode_error` for the first and `decrypt_error` for the second.
///
/// The key is decoded before the signature, so a peer that sends garbage for
/// both gets the key verdict, as the deleted EVP path did and as
/// `verifyRsaPss` does.
fn verifyEcdsa(
    comptime Curve: type,
    comptime Hash: type,
    pub_key: []const u8,
    signed_content: []const u8,
    sig: []const u8,
) VerifyError!void {
    return ecdsa.Ecdsa(Curve, Hash).verify(pub_key, signed_content, sig);
}

/// RFC 8446 §4.2.3 — rsa_pss_rsae_* is RSASSA-PSS with MGF1 over the same
/// hash and a salt length equal to the digest length; `Certificate.rsa`
/// enforces the salt length by construction.
///
/// The modulus floor is 1024 bits, the policy this path applied before it moved
/// off libcrypto. Chain verification uses the same `verifyDer` with its lower
/// 512-bit floor for legacy issuer keys.
fn verifyRsaPss(
    comptime Hash: type,
    pub_key: []const u8,
    signed_content: []const u8,
    sig: []const u8,
) VerifyError!void {
    return Certificate.rsa.PSSSignature.verifyDer(
        Hash,
        signed_content,
        sig,
        pub_key,
        1024,
        .forTls(Hash),
    ) catch |err| switch (err) {
        error.CertificateFieldHasWrongDataType,
        error.CertificateFieldHasInvalidLength,
        error.CertificatePublicKeyInvalid,
        error.CertificateSignatureAlgorithmMismatch,
        error.CertificateSignatureUnsupportedBitCount,
        => error.InvalidEncoding,
        error.CertificateSignatureInvalidLength,
        error.CertificateSignatureInvalid,
        => error.SignatureVerificationFailed,
    };
}

pub const server_certificate_verify_context =
    compat.repeatString(" ", 64) ++ "TLS 1.3, server CertificateVerify\x00";
pub const client_certificate_verify_context =
    compat.repeatString(" ", 64) ++ "TLS 1.3, client CertificateVerify\x00";

pub fn certificateVerifyEncodedLen(signature: []const u8) usize {
    return 4 + 2 + 2 + signature.len;
}

/// Encode a CertificateVerify handshake message from a caller-provided
/// signature. tls does not own private keys; server-side code signs
/// `server_context || transcript_hash` outside this helper, then wraps the
/// signature here. RFC 8446 §4.4.3.
pub fn encodeCertificateVerify(
    out: []u8,
    scheme: SignatureScheme,
    signature: []const u8,
) EncodeError![]const u8 {
    const len = certificateVerifyEncodedLen(signature);
    if (out.len < len) return error.BufferTooShort;
    var w: wire.Writer = .init(out);
    w.appendAssumeCapacity(handshake.Type, .certificate_verify);
    w.appendAssumeCapacity(u24, @intCast(len - 4));
    w.appendAssumeCapacity(SignatureScheme, scheme);
    w.appendAssumeCapacity(u16, @intCast(signature.len));
    w.appendSliceAssumeCapacity(signature);
    return w.buffered();
}

pub const VerifyError = error{
    BufferTooShort,
    InvalidEncoding,
    InvalidEnumTag,
    InvalidHandshakeType,
    SignatureVerificationFailed,
    UnexpectedEof,
    UnsupportedSignatureScheme,
};

/// Verify a server CertificateVerify handshake message.
///
/// `pub_key` is a slice into the caller's Certificate message buffer.
/// `transcript_hash` covers all messages up to and including Certificate.
///
/// RFC 8446 §4.4.3
pub fn verifyServerSignature(
    msg: []const u8,
    pub_key: []const u8,
    transcript_hash: []const u8,
) VerifyError!void {
    return verifySignature(server_certificate_verify_context, msg, pub_key, transcript_hash);
}

pub fn verifyServerSignatureWithSchemes(
    msg: []const u8,
    pub_key: []const u8,
    transcript_hash: []const u8,
    offered_schemes: []const SignatureScheme,
) VerifyError!void {
    const scheme = try certificateVerifyScheme(msg);
    if (mem.findScalar(SignatureScheme, offered_schemes, scheme) == null)
        return error.UnsupportedSignatureScheme;
    return verifyServerSignature(msg, pub_key, transcript_hash);
}

/// Verify a client CertificateVerify handshake message. RFC 8446 §4.4.3.
pub fn verifyClientSignature(
    msg: []const u8,
    pub_key: []const u8,
    transcript_hash: []const u8,
) VerifyError!void {
    return verifySignature(client_certificate_verify_context, msg, pub_key, transcript_hash);
}

/// Verify a client CertificateVerify and require the scheme to be one the
/// server offered in the CertificateRequest. RFC 8446 §4.4.3: the signature
/// algorithm MUST be one offered in the signature_algorithms extension of the
/// CertificateRequest. `offered_schemes` is the set the server sent.
pub fn verifyClientSignatureWithSchemes(
    msg: []const u8,
    pub_key: []const u8,
    transcript_hash: []const u8,
    offered_schemes: []const SignatureScheme,
) VerifyError!void {
    const scheme = try certificateVerifyScheme(msg);
    if (mem.findScalar(SignatureScheme, offered_schemes, scheme) == null)
        return error.UnsupportedSignatureScheme;
    return verifyClientSignature(msg, pub_key, transcript_hash);
}

fn certificateVerifyScheme(msg: []const u8) VerifyError!SignatureScheme {
    if (msg.len < 4 + 2) return error.UnexpectedEof;
    var r: wire.Reader = .init(msg);
    const handshake_type = r.assumeRead(handshake.Type);
    if (handshake_type != .certificate_verify) return error.InvalidHandshakeType;
    r.assumeSkip(3);
    return r.read(SignatureScheme);
}

fn verifySignature(
    comptime context: []const u8,
    msg: []const u8,
    pub_key: []const u8,
    transcript_hash: []const u8,
) VerifyError!void {
    if (msg.len < 4 + 2 + 2) return error.UnexpectedEof;
    var r: wire.Reader = .init(msg);

    const scheme = try certificateVerifyScheme(msg);
    r.assumeSkip(4 + 2);
    const sig_len = r.assumeRead(u16);
    if (r.remaining().len < sig_len) return error.UnexpectedEof;
    const sig = r.assumeReadSlice(sig_len);

    // RFC 8446 §4.4.3 — the signed content is the context string followed by
    // the transcript hash, with no separator and no length prefix. 64 octets
    // covers the largest transcript hash any TLS 1.3 suite uses.
    var signed_content: [context.len + 64]u8 = undefined;
    if (transcript_hash.len > signed_content.len - context.len) return error.BufferTooShort;
    @memcpy(signed_content[0..context.len], context);
    @memcpy(signed_content[context.len..][0..transcript_hash.len], transcript_hash);

    try verifySignedContent(
        scheme,
        pub_key,
        signed_content[0 .. context.len + transcript_hash.len],
        sig,
    );
}

// Fixtures generated with: scripts/gen-fixtures.sh
// Wrapped in functions so the @import of fixtures is never analyzed
// unless a test calls these — the published tarball doesn't include
// the fixtures module. Issue #66.
fn fixtureCertDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").server_cert_der;
}
fn fixtureCvSig() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").cv_sig;
}
fn fixtureRsaPssCertDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").rsa_pss_cert_der;
}
fn fixtureRsaPssCvSig() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").rsa_pss_cv_sig;
}
fn fixtureRsaPssCvSalt20Sig() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").rsa_pss_cv_salt20_sig;
}
const chain_root_pem = "tests/fixtures/chain/root.crt";
fn chainLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").chain_leaf_der;
}
fn ed25519CertDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").ed25519_cert_der;
}
fn chainIntermediateDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").chain_intermediate_der;
}
const crosssigned_root_pem = "tests/fixtures/crosssigned/root.crt";
fn crosssignedLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").crosssigned_leaf_der;
}
fn crosssignedIntermediateDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").crosssigned_intermediate_der;
}
fn crosssignedRootCrossDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").crosssigned_root_cross_der;
}
fn auditS5LeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").audit_s5_leaf_der;
}
fn auditS5IssuerDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").audit_s5_issuer_der;
}
fn nameConstraintsDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").name_constraints_der;
}
fn nameConstraintsNoncriticalDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").name_constraints_noncritical_der;
}
const nc_root_pem = "tests/fixtures/nameconstraints/root.crt";
fn ncIntermediateDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").nc_intermediate_der;
}
fn ncLeafAllowedDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").nc_leaf_allowed_der;
}
fn ncLeafExcludedDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").nc_leaf_excluded_der;
}
fn ncLeafOutsideDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").nc_leaf_outside_der;
}
const eku_root_pem = "tests/fixtures/eku/root.crt";
const eku_root_email_only_pem = "tests/fixtures/eku/root_email_only.crt";
fn ekuInterEmailDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_inter_email_der;
}
fn ekuLeafServerDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_leaf_server_der;
}
fn ekuInterAnyDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_inter_any_der;
}
fn ekuLeafAnyDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_leaf_any_der;
}
fn ekuInterServerauthDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_inter_serverauth_der;
}
fn ekuLeafClientDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_leaf_client_der;
}
fn ekuInterPlainDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_inter_plain_der;
}
fn ekuLeafPlainDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_leaf_plain_der;
}
fn ekuLeafClientPlainDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_leaf_client_plain_der;
}
fn ekuAnchorEmailInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_anchor_email_inter_der;
}
fn ekuAnchorEmailLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").eku_anchor_email_leaf_der;
}
const pathlen_root_pem = "tests/fixtures/pathlen/root.crt";
const pathlen_root_plc1_pem = "tests/fixtures/pathlen/root_plc1.crt";
const pathlen_crosssign_root_pem = "tests/fixtures/pathlen/crosssign_root.crt";
const pathlen_crosssign_untrusted_pem = "tests/fixtures/pathlen/crosssign_untrusted.crt";
fn pathlenZeroInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_zero_inter_der;
}
fn pathlenBelowZeroInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_below_zero_inter_der;
}
fn pathlenSelfIssuedInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_self_issued_inter_der;
}
fn pathlenBelowSiInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_below_si_inter_der;
}
fn pathlenBelowZeroLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_below_zero_leaf_der;
}
fn pathlenSelfIssuedLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_self_issued_leaf_der;
}
fn pathlenBelowSiLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_below_si_leaf_der;
}
fn pathlenCaTargetDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_ca_target_der;
}
fn pathlenClientBelowZeroLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_client_below_zero_leaf_der;
}
fn pathlenClientZeroLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_client_zero_leaf_der;
}
fn pathlenOneInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_one_inter_der;
}
fn pathlenOneMidInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_one_mid_inter_der;
}
fn pathlenOneDeepInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_one_deep_inter_der;
}
fn pathlenOneLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_one_leaf_der;
}
fn pathlenOneDeepLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_one_deep_leaf_der;
}
fn pathlenMultiOuterInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_multi_outer_inter_der;
}
fn pathlenMultiInnerInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_multi_inner_inter_der;
}
fn pathlenMultiDeepInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_multi_deep_inter_der;
}
fn pathlenMultiLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_multi_leaf_der;
}
fn pathlenMultiDeepLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_multi_deep_leaf_der;
}
fn pathlenAbsentAInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_absent_a_inter_der;
}
fn pathlenAbsentBInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_absent_b_inter_der;
}
fn pathlenAbsentLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_absent_leaf_der;
}
fn pathlenAnchorMidInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_anchor_mid_inter_der;
}
fn pathlenAnchorDeepInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_anchor_deep_inter_der;
}
fn pathlenAnchorLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_anchor_leaf_der;
}
fn pathlenAnchorDeepLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_anchor_deep_leaf_der;
}
fn pathlenCrossRootCrossDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_cross_root_cross_der;
}
fn pathlenCrossMidInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_cross_mid_inter_der;
}
fn pathlenCrossDeepInterDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_cross_deep_inter_der;
}
fn pathlenCrossLeafDer() []const u8 {
    // ziglint-ignore: Z028
    return &@import("fixtures").pathlen_cross_leaf_der;
}

fn buildCertMsg(buf: []u8, cert_der: []const u8) []const u8 {
    return buildCertChainMsg(buf, &.{cert_der});
}

fn buildCertChainMsg(buf: []u8, certs_der: []const []const u8) []const u8 {
    return encode(buf, certs_der) catch unreachable;
}

fn buildCvMsg(buf: []u8, sig: []const u8) []const u8 {
    return encodeCertificateVerify(buf, .ecdsa_secp256r1_sha256, sig) catch unreachable;
}

fn appendLeafCertificateExtensions(msg: []u8, msg_len: usize, extensions: []const u8) []const u8 {
    const ext_len_pos = msg_len - 2;
    @memcpy(msg[msg_len..][0..extensions.len], extensions);
    const ext_len: u16 = @intCast(extensions.len);
    msg[ext_len_pos..][0..2].* = .{ @intCast(ext_len >> 8), @intCast(ext_len & 0xff) };
    incrementU24(msg[1..4], @intCast(extensions.len));
    incrementU24(msg[5..8], @intCast(extensions.len));
    return msg[0 .. msg_len + extensions.len];
}

fn incrementU24(field: *[3]u8, n: u24) void {
    const value: u24 = (@as(u24, field[0]) << 16) |
        (@as(u24, field[1]) << 8) |
        field[2];
    const updated = value + n;
    field[0] = @intCast(updated >> 16);
    field[1] = @intCast((updated >> 8) & 0xff);
    field[2] = @intCast(updated & 0xff);
}

const test_transcript_hash = blk: {
    @setEvalBranchQuota(100_000);
    var out: [32]u8 = undefined;
    Sha256.hash("test transcript", &out, .{});
    break :blk out;
};

// RFC 8446 §4.4.2 — Certificate message framing. A cert_len near u24 max
// must not overflow the bounds-check arithmetic in the certificate-list loop.
test "parse: oversized cert_len does not overflow bounds check" {
    // 11-byte Certificate: type=0x0b, body_len=7, list_len=3, cert_len=0xFFFFFF
    const msg = [_]u8{ 0x0b, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0xff, 0xff, 0xff };
    const result = parse(&msg, .init);
    _ = result catch return; // any error is fine; a panic is the bug
}

// RFC 8446 §4.4.2 — client Certificate request_context. A ctx_len near u8 max
// must not overflow the bounds-check arithmetic.
test "parseClientCertificate: oversized ctx_len does not overflow" {
    // 8-byte client Certificate: type=0x0b, body_len=4, ctx_len=0xFF
    const msg = [_]u8{ 0x0b, 0x00, 0x00, 0x04, 0xff, 0x00, 0x00, 0x00 };
    const result = parseClientCertificate(&msg, &.{});
    _ = result catch return; // any error is fine; a panic is the bug
}

test "parse: extracts public key from ECDSA P-256 certificate" {
    var buf: [1024]u8 = undefined;
    const msg = buildCertMsg(&buf, fixtureCertDer());
    var policy: Policy = .init;
    policy.insecure_no_chain_anchor = true;
    const pub_key = try parse(msg, policy);
    try testing.expect(pub_key.len > 0);

    // RFC 8446 §4.4.2 — client-chain validation also surfaces the leaf DER
    // borrowed from the Certificate message for caller-owned retention.
    const verified = try parseClientChain(msg, &.{}, policy);
    try testing.expectEqualSlices(u8, pub_key, verified.pub_key);
    try testing.expectEqualSlices(u8, fixtureCertDer(), verified.leaf_der);
}

test "parse: wrong handshake type" {
    var buf: [1024]u8 = undefined;
    _ = buildCertMsg(&buf, fixtureCertDer());
    buf[0] = 0x01;
    try testing.expectError(error.InvalidHandshakeType, parse(&buf, .init));
}

// RFC 8446 §4.4 — the handshake header length must exactly match the
// Certificate body for both server and client chain parsers.
test "parse: rejects mismatched Certificate handshake body length" {
    var buf: [1024]u8 = undefined;
    const msg = buildCertMsg(&buf, fixtureCertDer());
    buf[1..4].* = .{ 0x00, 0x00, 0x00 };
    var policy: Policy = .init;
    policy.insecure_no_chain_anchor = true;

    try testing.expectError(error.InvalidHandshakeLength, parse(msg, policy));
    try testing.expectError(
        error.InvalidHandshakeLength,
        parseClientChain(msg, &.{}, policy),
    );
}

// RFC 8446 §4.4.2 — client Certificate echoes CertificateRequest context
// and may carry an empty certificate_list when no suitable certificate exists.
test "encodeWithRequestContext: encodes empty client certificate list" {
    var buf: [32]u8 = undefined;
    const encoded = try encodeWithRequestContext(&buf, &.{ 0xaa, 0xbb }, &.{});
    try testing.expectEqualSlices(u8, &.{
        0x0b, 0x00, 0x00, 0x06,
        0x02, 0xaa, 0xbb, 0x00,
        0x00, 0x00,
    }, encoded);
}

// RFC 8446 §4.4.2 — Certificate request_context is uint8 length-prefixed.
test "encodeWithRequestContext: rejects oversized request context" {
    var buf: [512]u8 = undefined;
    const context: [256]u8 = @splat(0xaa);
    try testing.expectError(
        error.RequestContextTooLong,
        encodeWithRequestContext(&buf, &context, &.{}),
    );
}

// RFC 8446 §4.4.2 — client Certificate in response to a handshake-time
// CertificateRequest echoes the request_context and may carry an empty list.
test "parseClientCertificate: accepts empty certificate with matching context" {
    var out: [64]u8 = undefined;
    const encoded = try encodeWithRequestContext(&out, &.{}, &.{});
    try testing.expectEqual(.empty, try parseClientCertificate(encoded, &.{}));
}

// RFC 8446 §4.4.2 — client Certificate request_context must match the
// CertificateRequest context byte-for-byte.
test "parseClientCertificate: rejects mismatched request context" {
    var out: [64]u8 = undefined;
    const encoded = try encodeWithRequestContext(&out, &.{0x01}, &.{});
    try testing.expectError(
        error.UnexpectedCertificateRequestContext,
        parseClientCertificate(encoded, &.{}),
    );
}

// RFC 8446 §4.4.2 — server Certificate request_context is always empty.
test "parse: rejects non-empty server certificate request context" {
    var buf: [2048]u8 = undefined;
    const encoded = buildCertMsg(&buf, fixtureCertDer());
    @memmove(buf[6 .. encoded.len + 1], buf[5..encoded.len]);
    buf[4] = 1;
    buf[5] = 0xaa;
    incrementU24(buf[1..4], 1);
    try testing.expectError(
        error.UnexpectedCertificateRequestContext,
        parse(buf[0 .. encoded.len + 1], testPolicy(.{ .insecure_no_chain_anchor = true })),
    );
}

// RFC 8446 §4.4.2.4 — server Certificate certificate_list must be non-empty.
test "parse: rejects empty certificate list" {
    const msg = [_]u8{
        compat.enumToInt(handshake.Type.certificate), 0x00, 0x00, 0x04,
        0x00,                                         0x00, 0x00, 0x00,
    };
    try testing.expectError(error.EmptyCertificateList, parse(&msg, .init));
}

// RFC 8446 §4.4.2 — Certificate.certificate_list is a uint24-length vector;
// its declared length must exactly bound the contained CertificateEntry values.
test "parse: rejects certificate list length shorter than entries" {
    var buf: [1024]u8 = undefined;
    const msg = buildCertMsg(&buf, fixtureCertDer());
    const shortened_list_len = msg.len - 4 - 1 - 3 - 1;
    buf[5..8].* = .{
        @intCast(shortened_list_len >> 16),
        @intCast((shortened_list_len >> 8) & 0xff),
        @intCast(shortened_list_len & 0xff),
    };
    try testing.expectError(
        error.UnexpectedEof,
        parse(msg, testPolicy(.{ .insecure_no_chain_anchor = true })),
    );
}

test "encode: round trips certificate chain" {
    var buf: [4096]u8 = undefined;
    const msg = try encode(&buf, &.{ chainLeafDer(), chainIntermediateDer() });
    try testing.expectEqual(encodedLen(&.{ chainLeafDer(), chainIntermediateDer() }), msg.len);
    const pub_key = try parse(msg, testPolicy(.{
        .host_name = "chain.test",
        .now_sec = 1_780_300_000,
        .insecure_no_chain_anchor = true,
    }));
    try testing.expect(pub_key.len > 0);
}

// RFC 8446 §4.4.2.1 — tls does not request or consume OCSP responses today,
// so a server CertificateEntry status_request extension is unsupported.
test "parse: rejects unsupported CertificateEntry status_request" {
    var buf: [2048]u8 = undefined;
    const msg = buildCertMsg(&buf, fixtureCertDer());
    const ext = [_]u8{ 0x00, 0x05, 0x00, 0x00 };
    const with_ext = appendLeafCertificateExtensions(&buf, msg.len, &ext);
    try testing.expectError(
        error.UnsupportedExtension,
        parse(with_ext, testPolicy(.{ .insecure_no_chain_anchor = true })),
    );
}

// RFC 8446 §4.4.2.1 — tls does not request or consume SCTs today, so a server
// CertificateEntry signed_certificate_timestamp extension is unsupported.
test "parse: rejects unsupported CertificateEntry SCT" {
    var buf: [2048]u8 = undefined;
    const msg = buildCertMsg(&buf, fixtureCertDer());
    const ext = [_]u8{ 0x00, 0x12, 0x00, 0x00 };
    const with_ext = appendLeafCertificateExtensions(&buf, msg.len, &ext);
    try testing.expectError(
        error.UnsupportedExtension,
        parse(with_ext, testPolicy(.{ .insecure_no_chain_anchor = true })),
    );
}

// RFC 8446 §4.4.2.1 — TLS 1.3 servers must not send status_request_v2 in a
// Certificate message.
test "parse: rejects forbidden CertificateEntry status_request_v2" {
    var buf: [2048]u8 = undefined;
    const msg = buildCertMsg(&buf, fixtureCertDer());
    const ext = [_]u8{ 0x00, 0x11, 0x00, 0x00 };
    const with_ext = appendLeafCertificateExtensions(&buf, msg.len, &ext);
    try testing.expectError(
        error.UnexpectedExtension,
        parse(with_ext, testPolicy(.{ .insecure_no_chain_anchor = true })),
    );
}

// RFC 8446 §4.2 — duplicate extensions are forbidden in extension blocks.
test "parse: rejects duplicate CertificateEntry status_request" {
    var buf: [2048]u8 = undefined;
    const msg = buildCertMsg(&buf, fixtureCertDer());
    const ext = [_]u8{
        0x00, 0x05, 0x00, 0x00,
        0x00, 0x05, 0x00, 0x00,
    };
    const with_ext = appendLeafCertificateExtensions(&buf, msg.len, &ext);
    try testing.expectError(
        error.DuplicateExtension,
        parse(with_ext, testPolicy(.{ .insecure_no_chain_anchor = true })),
    );
}

// RFC 8446 §4.2 — extension blocks must be well-formed vectors.
test "parse: rejects malformed CertificateEntry extension length" {
    var buf: [2048]u8 = undefined;
    const msg = buildCertMsg(&buf, fixtureCertDer());
    const ext = [_]u8{ 0xbe, 0xef, 0x00, 0x02, 0xaa };
    const with_ext = appendLeafCertificateExtensions(&buf, msg.len, &ext);
    try testing.expectError(
        error.InvalidExtensionLength,
        parse(with_ext, testPolicy(.{ .insecure_no_chain_anchor = true })),
    );
}

// RFC 8446 §4.2 — unknown extensions are ignorable when they are otherwise
// well-formed.
test "parse: ignores unknown CertificateEntry extension" {
    var buf: [2048]u8 = undefined;
    const msg = buildCertMsg(&buf, fixtureCertDer());
    const ext = [_]u8{ 0xbe, 0xef, 0x00, 0x01, 0xaa };
    const with_ext = appendLeafCertificateExtensions(&buf, msg.len, &ext);
    const pub_key = try parse(with_ext, testPolicy(.{ .insecure_no_chain_anchor = true }));
    try testing.expect(pub_key.len > 0);
}

test "parse: validates hostname" {
    var buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&buf, fixtureCertDer()), testPolicy(.{
        .host_name = "test.local",
        .insecure_no_chain_anchor = true,
    }));
    try testing.expect(pub_key.len > 0);
}

test "parse: rejects hostname mismatch" {
    var buf: [1024]u8 = undefined;
    try testing.expectError(
        error.CertificateHostMismatch,
        parse(buildCertMsg(&buf, fixtureCertDer()), testPolicy(.{ .host_name = "wrong.local" })),
    );
}

test "parse: rejects missing trust anchor by default" {
    var buf: [1024]u8 = undefined;
    try testing.expectError(
        error.MissingTrustAnchor,
        parse(buildCertMsg(&buf, fixtureCertDer()), testPolicy(.{ .host_name = "test.local" })),
    );
}

const empty_bundle: Certificate.Bundle = .empty;

fn addCertsFromFixturePath(bundle: *Certificate.Bundle, path: []const u8) !void {
    return bundle.addCertsFromFilePath(
        testing.allocator,
        testing.io,
        Io.Timestamp.now(testing.io, .real),
        Io.Dir.cwd(),
        path,
    );
}

/// Build a trust bundle from committed DER at the same fixed time as chain
/// validation. PEM loading and the real clock cannot drop the fixture anchor.
fn addCertFromFixtureDer(
    bundle: *Certificate.Bundle,
    der: []const u8,
    now_sec: i64,
) !void {
    const start: u32 = @intCast(bundle.bytes.items.len);
    try bundle.bytes.appendSlice(testing.allocator, der);
    errdefer bundle.bytes.items.len = start;
    try bundle.parseCert(testing.allocator, start, now_sec);
}

test "parse: validates leaf against trust bundle" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, "tests/fixtures/server.crt");

    var buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&buf, fixtureCertDer()), testPolicy(.{
        .bundle = &bundle,
        .now_sec = 1_780_300_000,
        .host_name = "test.local",
    }));
    try testing.expect(pub_key.len > 0);
}

test "parse: validates leaf-intermediate-root chain" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, chain_root_pem);

    var buf: [4096]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{ chainLeafDer(), chainIntermediateDer() }),
        testPolicy(.{ .bundle = &bundle, .now_sec = 1_780_300_000, .host_name = "chain.test" }),
    );
    try testing.expect(pub_key.len > 0);
}

// RFC 5280 §6.1, RFC 8017 §8.2 — the captured chains verify through the RSA
// key that signed each cross-signed root. Anchoring at the newer self-signed
// root instead would skip that RSA link and prove only the ECDSA links.
test "parse: captured public RSA chains verify through RSA issuer roots" {
    const Case = struct {
        name: []const u8,
        host_name: []const u8,
        anchor_der: []const u8,
        certs_der: []const []const u8,
    };
    const cases = [_]Case{
        .{
            .name = "google.com",
            .host_name = "google.com",
            .anchor_der = &fixtures.public_globalsign_root_der,
            .certs_der = &.{
                &fixtures.public_google_leaf_der,
                &fixtures.public_google_intermediate_der,
                &fixtures.public_gts_cross_root_der,
            },
        },
        .{
            .name = "www.cloudflare.com",
            .host_name = "www.cloudflare.com",
            .anchor_der = &fixtures.public_globalsign_root_der,
            .certs_der = &.{
                &fixtures.public_cloudflare_leaf_der,
                &fixtures.public_cloudflare_intermediate_der,
                &fixtures.public_gts_cross_root_der,
            },
        },
        .{
            .name = "example.com",
            .host_name = "example.com",
            .anchor_der = &fixtures.public_aaa_root_der,
            .certs_der = &.{
                &fixtures.public_example_leaf_der,
                &fixtures.public_example_intermediate_der,
                &fixtures.public_example_transit_der,
                &fixtures.public_example_cross_root_der,
            },
        },
    };

    for (cases) |case| {
        var bundle: Certificate.Bundle = empty_bundle;
        defer bundle.deinit(testing.allocator);
        try addCertFromFixtureDer(&bundle, case.anchor_der, fixtures.public_chain_now_sec);

        var buf: [8192]u8 = undefined;
        const pub_key = parse(
            buildCertChainMsg(&buf, case.certs_der),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = fixtures.public_chain_now_sec,
                .host_name = case.host_name,
            }),
        ) catch |err| {
            print("captured chain {s} failed with {t}\n", .{ case.name, err });
            return err;
        };
        try testing.expect(pub_key.len > 0);
    }
}

// RFC 5280 §4.2.1.9 and §4.2.1.3, RFC 8446 §4.4.2 — a certificate used as
// an issuer must assert cA and, when KeyUsage is present, keyCertSign.
test "parse: rejects end-entity certificate used as issuer" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, "tests/fixtures/audit_s5/root.crt");

    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateIssuerNotCa,
        parse(
            buildCertChainMsg(&buf, &.{ auditS5LeafDer(), auditS5IssuerDer() }),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = 1_800_000_000,
                .host_name = "victim.test",
            }),
        ),
    );
}

// RFC 8446 §4.4.2 — the sender certificate is the first CertificateEntry.
test "parse: rejects chain with intermediate before leaf" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, chain_root_pem);

    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateKeyUsageRejected,
        parse(
            buildCertChainMsg(&buf, &.{ chainIntermediateDer(), chainLeafDer() }),
            testPolicy(.{ .bundle = &bundle, .now_sec = 1_780_300_000, .host_name = "chain.test" }),
        ),
    );
}

// RFC 5280 §6.1, RFC 8446 §4.4.2 — trusted-first path building: when the
// presented chain ends in a cross-signed root whose issuer is not a trust
// anchor, the verifier anchors the highest certificate whose issuer IS in
// the bundle. Mirrors production chains like example.com's SSL.com 2022
// root presented cross-signed by Comodo AAA Certificate Services.
test "parse: anchors chain below a cross-signed root" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, crosssigned_root_pem);

    var buf: [8192]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{
            crosssignedLeafDer(),
            crosssignedIntermediateDer(),
            crosssignedRootCrossDer(),
        }),
        testPolicy(.{ .bundle = &bundle, .now_sec = 1_800_000_000, .host_name = "cross.test" }),
    );
    try testing.expect(pub_key.len > 0);
}

// The presented cross-signed root alone must not anchor anything: its issuer
// is not in the bundle, and no lower certificate chains to the bundle root.
test "parse: rejects cross-signed root without a bundle anchor below it" {
    const bundle: Certificate.Bundle = empty_bundle;

    var buf: [8192]u8 = undefined;
    try testing.expectError(
        error.CertificateIssuerNotFound,
        parse(
            buildCertChainMsg(&buf, &.{
                crosssignedLeafDer(),
                crosssignedIntermediateDer(),
                crosssignedRootCrossDer(),
            }),
            testPolicy(.{ .bundle = &bundle, .now_sec = 1_800_000_000, .host_name = "cross.test" }),
        ),
    );
}

test "parse: rejects chain with missing intermediate" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, chain_root_pem);

    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateIssuerNotFound,
        parse(
            buildCertChainMsg(&buf, &.{chainLeafDer()}),
            testPolicy(.{ .bundle = &bundle, .now_sec = 1_780_300_000, .host_name = "chain.test" }),
        ),
    );
}

test "parse: rejects chain hostname mismatch" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, chain_root_pem);

    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateHostMismatch,
        parse(
            buildCertChainMsg(&buf, &.{ chainLeafDer(), chainIntermediateDer() }),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = 1_780_300_000,
                .host_name = "wrong.chain.test",
            }),
        ),
    );
}

test "parse: rejects untrusted leaf when bundle misses issuer" {
    const bundle: Certificate.Bundle = empty_bundle;
    var buf: [1024]u8 = undefined;
    try testing.expectError(
        error.CertificateIssuerNotFound,
        parse(buildCertMsg(&buf, fixtureCertDer()), testPolicy(.{
            .bundle = &bundle,
            .now_sec = 1_780_300_000,
        })),
    );
}

fn nameConstraintsBundle() !Certificate.Bundle {
    var bundle: Certificate.Bundle = empty_bundle;
    try addCertsFromFixturePath(&bundle, nc_root_pem);
    return bundle;
}

// RFC 5280 §4.2.1.10 — an intermediate CA's permitted DNS subtree allows
// subordinate certificates whose DNS SANs are inside that subtree.
test "parse: accepts chain with matching DNS name constraints" {
    var bundle = try nameConstraintsBundle();
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{ ncLeafAllowedDer(), ncIntermediateDer() }),
        testPolicy(.{ .bundle = &bundle, .now_sec = 1_782_864_000, .host_name = "ok.example.com" }),
    );
    try testing.expect(pub_key.len > 0);
}

// RFC 5280 §4.2.1.10 — excluded DNS subtrees override permitted DNS subtrees.
test "parse: rejects chain with excluded DNS name constraints" {
    var bundle = try nameConstraintsBundle();
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateNameConstraintViolation,
        parse(
            buildCertChainMsg(&buf, &.{ ncLeafExcludedDer(), ncIntermediateDer() }),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = 1_782_864_000,
                .host_name = "bad.example.com",
            }),
        ),
    );
}

// RFC 5280 §4.2.1.10 — permitted DNS subtrees reject subordinate names outside
// the constrained CA's namespace even when the leaf hostname itself matches.
test "parse: rejects chain outside permitted DNS name constraints" {
    var bundle = try nameConstraintsBundle();
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateNameConstraintViolation,
        parse(
            buildCertChainMsg(&buf, &.{ ncLeafOutsideDer(), ncIntermediateDer() }),
            testPolicy(.{ .bundle = &bundle, .now_sec = 1_782_864_000, .host_name = "other.test" }),
        ),
    );
}

// RFC 5280 §4.2.1.10 — the explicit no-anchor test/demo path still enforces
// name constraints from certificates carried in the handshake chain.
test "parse: insecure no-anchor path still enforces name constraints" {
    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateNameConstraintViolation,
        parse(
            buildCertChainMsg(&buf, &.{ ncLeafExcludedDer(), ncIntermediateDer() }),
            testPolicy(.{
                .insecure_no_chain_anchor = true,
                .now_sec = 1_782_864_000,
                .host_name = "bad.example.com",
            }),
        ),
    );
}

// RFC 5280 §4.2.1.12 / RFC 8446 §4.4.2 — issuer EKU chaining (#155). When
// an in-chain issuer carries an EKU extension, it must contain the leaf's
// role OID or id-kp-anyExtendedKeyUsage; an absent EKU stays permissive.
// Fixture family and OpenSSL 3.6.5 ground truth: tests/fixtures/eku/README.md.

const eku_now_sec: i64 = 1_800_000_000;

fn ekuBundle(pem: []const u8) !Certificate.Bundle {
    var bundle: Certificate.Bundle = empty_bundle;
    try addCertsFromFixturePath(&bundle, pem);
    return bundle;
}

// RFC 5280 §4.2.1.12 — a sub-CA whose EKU is emailProtection only is not
// authorized to issue a serverAuth leaf (OpenSSL: error 26 "unsuitable
// certificate purpose" at depth 1).
test "parse: rejects server-auth chain through emailProtection-only sub-CA" {
    var bundle = try ekuBundle(eku_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateExtendedKeyUsageRejected,
        parse(
            buildCertChainMsg(&buf, &.{ ekuLeafServerDer(), ekuInterEmailDer() }),
            testPolicy(.{ .bundle = &bundle, .now_sec = eku_now_sec, .host_name = "victim.test" }),
        ),
    );
}

// RFC 5280 §4.2.1.12 — controls: an issuer with no EKU extension is
// permissive, and id-kp-anyExtendedKeyUsage (2.5.29.37.0) satisfies any role
// (Go/webpki semantics; OpenSSL is stricter and rejects the anyEKU row —
// deliberate divergence, see tests/fixtures/eku/README.md).
test "parse: accepts server-auth chains through no-EKU and anyEKU sub-CAs" {
    for ([_][2][]const u8{
        .{ ekuLeafPlainDer(), ekuInterPlainDer() },
        .{ ekuLeafAnyDer(), ekuInterAnyDer() },
    }) |chain_der| {
        var bundle = try ekuBundle(eku_root_pem);
        defer bundle.deinit(testing.allocator);

        var buf: [4096]u8 = undefined;
        const pub_key = try parse(
            buildCertChainMsg(&buf, &chain_der),
            testPolicy(.{ .bundle = &bundle, .now_sec = eku_now_sec, .host_name = "victim.test" }),
        );
        try testing.expect(pub_key.len > 0);
    }
}

// RFC 5280 §4.2.1.12 — mirror for the client-auth path: a serverAuth-only
// sub-CA is not authorized to issue a clientAuth leaf.
test "parseClientChain: rejects client-auth chain through serverAuth-only sub-CA" {
    var bundle = try ekuBundle(eku_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateExtendedKeyUsageRejected,
        parseClientChain(
            buildCertChainMsg(&buf, &.{ ekuLeafClientDer(), ekuInterServerauthDer() }),
            &.{},
            testPolicy(.{ .bundle = &bundle, .now_sec = eku_now_sec, .leaf_usage = .client_auth }),
        ),
    );
}

// RFC 5280 §4.2.1.12 — client-auth control: a no-EKU issuer stays permissive.
test "parseClientChain: accepts client-auth chain through no-EKU sub-CA" {
    var bundle = try ekuBundle(eku_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    const verified = try parseClientChain(
        buildCertChainMsg(&buf, &.{ ekuLeafClientPlainDer(), ekuInterPlainDer() }),
        &.{},
        testPolicy(.{ .bundle = &bundle, .now_sec = eku_now_sec, .leaf_usage = .client_auth }),
    );
    try testing.expect(verified.pub_key.len > 0);
}

// RFC 5280 §6.1 / §4.2.1.12 — the trust anchor is not exempt: OpenSSL 3.6.5
// applies its purpose check to the anchor (error 26 at the anchor's depth
// for an emailProtection-only root anchoring a serverAuth leaf), and tls
// matches.
test "parse: rejects chain anchored by an emailProtection-only root" {
    var bundle = try ekuBundle(eku_root_email_only_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    try testing.expectError(
        error.CertificateExtendedKeyUsageRejected,
        parse(
            buildCertChainMsg(&buf, &.{ ekuAnchorEmailLeafDer(), ekuAnchorEmailInterDer() }),
            testPolicy(.{ .bundle = &bundle, .now_sec = eku_now_sec, .host_name = "victim.test" }),
        ),
    );
}

// RFC 5280 §4.2 — unprocessed critical extensions invalidate either role's chain.
test "parse: rejects signed unprocessed critical extension for both roles" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, "tests/fixtures/critical/root.crt");
    var buf: [2048]u8 = undefined;
    const msg = buildCertChainMsg(&buf, &.{&fixtures.extension_critical_der});
    var policy: Policy = .init;
    policy.bundle = &bundle;
    policy.now_sec = 1_800_000_000;
    try testing.expectError(error.CertificateUnsupportedCriticalExtension, parse(msg, policy));
    try testing.expectError(
        error.CertificateUnsupportedCriticalExtension,
        parseClientChain(msg, &.{}, policy),
    );
}

// RFC 5280 §4.2 — non-critical extensions outside the verifier's support can be ignored.
test "parse: accepts signed noncritical extension and supported critical extensions" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, "tests/fixtures/critical/root.crt");
    for ([_][]const u8{ &fixtures.extension_valid_der, &fixtures.extension_ignored_der }) |cert| {
        var buf: [2048]u8 = undefined;
        const msg = buildCertChainMsg(&buf, &.{cert});
        var policy: Policy = .init;
        policy.bundle = &bundle;
        policy.now_sec = 1_800_000_000;
        policy.host_name = "critical.test";
        try testing.expect((try parse(msg, policy)).len > 0);
        _ = try parseClientChain(msg, &.{}, policy);
    }
}

// RFC 5280 §4.2.1.6 — GeneralNames is a constructed universal SEQUENCE.
test "parse: rejects signed SAN with an invalid wrapper" {
    var bundle: Certificate.Bundle = empty_bundle;
    defer bundle.deinit(testing.allocator);
    try addCertsFromFixturePath(&bundle, "tests/fixtures/critical/root.crt");
    for ([_][]const u8{
        &fixtures.extension_san_application_der,
        &fixtures.extension_san_context_der,
        &fixtures.extension_san_private_der,
        &fixtures.extension_san_set_der,
        &fixtures.extension_san_primitive_der,
    }) |cert| {
        var buf: [2048]u8 = undefined;
        try testing.expectError(error.CertificateFieldHasWrongDataType, parse(
            buildCertChainMsg(&buf, &.{cert}),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = 1_800_000_000,
                .host_name = "critical.test",
            }),
        ));
    }
}

// RFC 5280 §4.2.1.9 / §6.1 — pathLenConstraint enforcement (#118).
//
// Fixture family and per-case OpenSSL 3.6.4 ground truth:
// tests/fixtures/pathlen/README.md. Every verdict below was first recorded
// with `openssl verify` on the same DER (error 25 = "path length constraint
// exceeded" at the constraining certificate's depth).

const pathlen_now_sec: i64 = 1_800_000_000;

fn pathlenBundle(pem: []const u8) !Certificate.Bundle {
    var bundle: Certificate.Bundle = empty_bundle;
    try addCertsFromFixturePath(&bundle, pem);
    return bundle;
}

// RFC 5280 §4.2.1.9 — "A pathLenConstraint of zero indicates that no
// non-self-issued intermediate CA certificates may follow in a valid
// certification path." OpenSSL: error 25 at depth 2 (the pathlen:0 CA).
test "parse: rejects chain exceeding pathLenConstraint zero" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [8192]u8 = undefined;
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        parse(
            buildCertChainMsg(&buf, &.{
                pathlenBelowZeroLeafDer(),
                pathlenBelowZeroInterDer(),
                pathlenZeroInterDer(),
            }),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = pathlen_now_sec,
                .host_name = "below-zero.test",
            }),
        ),
    );
}

// RFC 5280 §4.2.1.9 — the last certificate in the path is not an intermediate
// and is not counted, even when it is itself a CA certificate carrying
// pathLenConstraint. OpenSSL: catarget OK.
test "parse: accepts pathLenConstraint zero with a CA target" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{ pathlenCaTargetDer(), pathlenZeroInterDer() }),
        testPolicy(.{
            .bundle = &bundle,
            .now_sec = pathlen_now_sec,
            .host_name = "catarget.test",
        }),
    );
    try testing.expect(pub_key.len > 0);
}

// RFC 5280 §4.2.1.9 — pathlen:1 admits exactly one non-self-issued
// intermediate. OpenSSL: error 25 at depth 3 (the pathlen:1 CA).
test "parse: rejects chain exceeding pathLenConstraint one" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [16384]u8 = undefined;
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        parse(
            buildCertChainMsg(&buf, &.{
                pathlenOneDeepLeafDer(),
                pathlenOneDeepInterDer(),
                pathlenOneMidInterDer(),
                pathlenOneInterDer(),
            }),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = pathlen_now_sec,
                .host_name = "one-deep.test",
            }),
        ),
    );
}

// RFC 5280 §4.2.1.9 — exactly one non-self-issued intermediate below a
// pathlen:1 CA is valid. OpenSSL: one.test OK.
test "parse: accepts chain at pathLenConstraint one" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [8192]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{
            pathlenOneLeafDer(),
            pathlenOneMidInterDer(),
            pathlenOneInterDer(),
        }),
        testPolicy(.{
            .bundle = &bundle,
            .now_sec = pathlen_now_sec,
            .host_name = "one.test",
        }),
    );
    try testing.expect(pub_key.len > 0);
}

// RFC 5280 §4.2.1.9 — "Where pathLenConstraint does not appear, no limit is
// imposed": two intermediates below an unconstrained CA stay valid.
// OpenSSL: absent.test OK.
test "parse: imposes no path-length limit when pathLenConstraint is absent" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [8192]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{
            pathlenAbsentLeafDer(),
            pathlenAbsentBInterDer(),
            pathlenAbsentAInterDer(),
        }),
        testPolicy(.{
            .bundle = &bundle,
            .now_sec = pathlen_now_sec,
            .host_name = "absent.test",
        }),
    );
    try testing.expect(pub_key.len > 0);
}

// RFC 5280 §6.1.4(m) — pathLenConstraint tightens max_path_length, so the
// tightest constraint binds even when a looser one higher in the path would
// allow the chain (inner pathlen:0 rejects what outer pathlen:2 permits).
// OpenSSL: error 25 at depth 2 (the pathlen:0 inner CA).
test "parse: enforces the tightest of multiple pathLenConstraints" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [16384]u8 = undefined;
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        parse(
            buildCertChainMsg(&buf, &.{
                pathlenMultiDeepLeafDer(),
                pathlenMultiDeepInterDer(),
                pathlenMultiInnerInterDer(),
                pathlenMultiOuterInterDer(),
            }),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = pathlen_now_sec,
                .host_name = "multi-deep.test",
            }),
        ),
    );
}

// RFC 5280 §6.1.4(l),(m) — multiple constraints all satisfied (outer
// pathlen:2 with one intermediate below it, inner pathlen:0 with only the
// target below it). OpenSSL: multi.test OK.
test "parse: accepts multiple satisfied pathLenConstraints" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [8192]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{
            pathlenMultiLeafDer(),
            pathlenMultiInnerInterDer(),
            pathlenMultiOuterInterDer(),
        }),
        testPolicy(.{
            .bundle = &bundle,
            .now_sec = pathlen_now_sec,
            .host_name = "multi.test",
        }),
    );
    try testing.expect(pub_key.len > 0);
}

// RFC 5280 §6.1 — "self-issued certificates are not counted when evaluating
// path length": a self-issued intermediate (§6.1.4(l) skip) below a
// pathlen:0 CA with only the target beneath it stays valid.
// OpenSSL: selfissued.test OK.
test "parse: self-issued intermediate does not consume path length" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [8192]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{
            pathlenSelfIssuedLeafDer(),
            pathlenSelfIssuedInterDer(),
            pathlenZeroInterDer(),
        }),
        testPolicy(.{
            .bundle = &bundle,
            .now_sec = pathlen_now_sec,
            .host_name = "selfissued.test",
        }),
    );
    try testing.expect(pub_key.len > 0);
}

// RFC 5280 §6.1.4(l) — the self-issued exemption exempts only the self-issued
// certificate itself: a non-self-issued intermediate beneath it still
// consumes budget and violates the pathlen:0 CA above.
// OpenSSL: error 25 at depth 3 (the pathlen:0 CA).
test "parse: intermediate below a self-issued certificate still counts" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [16384]u8 = undefined;
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        parse(
            buildCertChainMsg(&buf, &.{
                pathlenBelowSiLeafDer(),
                pathlenBelowSiInterDer(),
                pathlenSelfIssuedInterDer(),
                pathlenZeroInterDer(),
            }),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = pathlen_now_sec,
                .host_name = "below-si.test",
            }),
        ),
    );
}

// RFC 5280 §6.1.1(d)(g)/§6.2 — a trust anchor supplied as a certificate
// contributes its pathLenConstraint as the initial max_path_length input
// (§6.1.2(k)); OpenSSL applies it (error 25 attributes the failure to the
// anchor root itself at depth 3) and tls matches. Two intermediates below a
// pathlen:1 anchor are rejected.
test "parse: trust anchor pathLenConstraint limits intermediates below it" {
    var bundle = try pathlenBundle(pathlen_root_plc1_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [8192]u8 = undefined;
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        parse(
            buildCertChainMsg(&buf, &.{
                pathlenAnchorDeepLeafDer(),
                pathlenAnchorDeepInterDer(),
                pathlenAnchorMidInterDer(),
            }),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = pathlen_now_sec,
                .host_name = "anchor-deep.test",
            }),
        ),
    );
}

// RFC 5280 §6.1.1(g)/§6.1.2(k) — one intermediate below a pathlen:1 anchor
// is within the anchor's initial budget. OpenSSL: anchor.test OK.
test "parse: trust anchor pathLenConstraint satisfied" {
    var bundle = try pathlenBundle(pathlen_root_plc1_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{ pathlenAnchorLeafDer(), pathlenAnchorMidInterDer() }),
        testPolicy(.{
            .bundle = &bundle,
            .now_sec = pathlen_now_sec,
            .host_name = "anchor.test",
        }),
    );
    try testing.expect(pub_key.len > 0);
}

// RFC 5280 §6.1 — the prospective certification path starts at the
// certificate issued by the trust anchor; certificates presented above the
// anchored certificate are outside the path, so the cross-signed root's
// pathlen:0 does not constrain it. OpenSSL (trusted-first): cross.test OK.
test "parse: certificates above the anchored path are outside the path" {
    var bundle = try pathlenBundle(pathlen_crosssign_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [16384]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{
            pathlenCrossLeafDer(),
            pathlenCrossDeepInterDer(),
            pathlenCrossMidInterDer(),
            pathlenCrossRootCrossDer(),
        }),
        testPolicy(.{
            .bundle = &bundle,
            .now_sec = pathlen_now_sec,
            .host_name = "cross.test",
        }),
    );
    try testing.expect(pub_key.len > 0);
}

// RFC 5280 §6.1 — the same presented chain anchored one certificate higher
// puts the cross-signed root inside the path, where its pathlen:0 binds.
// OpenSSL: error 25 at depth 3 (the cross-signed root).
test "parse: cross-signed root constraint binds inside the anchored path" {
    var bundle = try pathlenBundle(pathlen_crosssign_untrusted_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [16384]u8 = undefined;
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        parse(
            buildCertChainMsg(&buf, &.{
                pathlenCrossLeafDer(),
                pathlenCrossDeepInterDer(),
                pathlenCrossMidInterDer(),
                pathlenCrossRootCrossDer(),
            }),
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = pathlen_now_sec,
                .host_name = "cross.test",
            }),
        ),
    );
}

// RFC 5280 §4.2.1.9, RFC 8446 §4.4.2 — the shared chain-verification path
// also enforces pathLenConstraint for client-auth chains (parseClientChain).
test "parseClientChain: rejects client chain exceeding pathLenConstraint zero" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [8192]u8 = undefined;
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        parseClientChain(
            buildCertChainMsg(&buf, &.{
                pathlenClientBelowZeroLeafDer(),
                pathlenBelowZeroInterDer(),
                pathlenZeroInterDer(),
            }),
            &.{},
            testPolicy(.{
                .bundle = &bundle,
                .now_sec = pathlen_now_sec,
                .leaf_usage = .client_auth,
            }),
        ),
    );
}

// RFC 5280 §4.2.1.9, RFC 8446 §4.4.2 — client-auth chains at a satisfied
// constraint are accepted (target excluded from the pathlen:0 budget).
test "parseClientChain: accepts client chain at pathLenConstraint zero" {
    var bundle = try pathlenBundle(pathlen_root_pem);
    defer bundle.deinit(testing.allocator);

    var buf: [4096]u8 = undefined;
    const verified = try parseClientChain(
        buildCertChainMsg(&buf, &.{ pathlenClientZeroLeafDer(), pathlenZeroInterDer() }),
        &.{},
        testPolicy(.{
            .bundle = &bundle,
            .now_sec = pathlen_now_sec,
            .leaf_usage = .client_auth,
        }),
    );
    try testing.expect(verified.pub_key.len > 0);
}

// RFC 5280 §4.2.1.9 — the explicit no-anchor path still enforces the
// pathLenConstraints carried by the presented chain (mirrors the name-
// constraint behavior above): the whole presented chain is the path.
test "parse: insecure no-anchor path still enforces pathLenConstraint" {
    var buf: [8192]u8 = undefined;
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        parse(
            buildCertChainMsg(&buf, &.{
                pathlenBelowZeroLeafDer(),
                pathlenBelowZeroInterDer(),
                pathlenZeroInterDer(),
            }),
            testPolicy(.{
                .insecure_no_chain_anchor = true,
                .now_sec = pathlen_now_sec,
                .host_name = "below-zero.test",
            }),
        ),
    );
}

// RFC 5280 §6.1 — on the no-anchor path a presented self-signed root behaves
// like an anchor: §6.1.4(l) never charges it budget (self-issued) while
// §6.1.4(m) still applies its pathLenConstraint to everything below.
test "parse: insecure no-anchor path accepts constrained chain with self-issued steps" {
    var buf: [8192]u8 = undefined;
    const pub_key = try parse(
        buildCertChainMsg(&buf, &.{
            pathlenSelfIssuedLeafDer(),
            pathlenSelfIssuedInterDer(),
            pathlenZeroInterDer(),
        }),
        testPolicy(.{
            .insecure_no_chain_anchor = true,
            .now_sec = pathlen_now_sec,
            .host_name = "selfissued.test",
        }),
    );
    try testing.expect(pub_key.len > 0);
}

test "parse: malformed DER length is rejected, not crashed" {
    const msg = [_]u8{
        0x0b, 0x00, 0x00, 0x0e, // Certificate, length 14
        0x00, // context length
        0x00, 0x00, 0x0a, // certificate_list length
        0x00, 0x00, 0x05, // cert length
        0x30, 0x82, 0x01, 0xd3, 0x00, // SEQUENCE claims 467 content bytes, has 1
        0x00, 0x00, // extensions length
    };
    try testing.expectError(error.CertificateFieldHasInvalidLength, parse(&msg, .init));
}

// Build a Parsed leaf carrying only the fields certificate_policy.verifyServerAuth reads,
// so policy enforcement can be tested without generating full DER fixtures.
fn policyLeaf(
    der: []const u8,
    key_usage: Certificate.Parsed.Slice,
    ext_key_usage: Certificate.Parsed.Slice,
    signature_algorithm: Certificate.Algorithm,
) Certificate.Parsed {
    return policyLeafWithVersion(
        der,
        key_usage,
        ext_key_usage,
        signature_algorithm,
        .v3,
    );
}

fn policyLeafWithVersion(
    der: []const u8,
    key_usage: Certificate.Parsed.Slice,
    ext_key_usage: Certificate.Parsed.Slice,
    signature_algorithm: Certificate.Algorithm,
    version: Certificate.Version,
) Certificate.Parsed {
    return .{
        .certificate = .{ .buffer = der, .index = 0 },
        .issuer_slice = .empty,
        .subject_slice = .empty,
        .common_name_slice = .empty,
        .signature_slice = .empty,
        .signature_algorithm = signature_algorithm,
        .pub_key_algo = .{ .curveEd25519 = {} },
        .pub_key_slice = .empty,
        .message_slice = .empty,
        .subject_alt_name_slice = .empty,
        .key_usage_slice = key_usage,
        .ext_key_usage_slice = ext_key_usage,
        .name_constraints_slice = .empty,
        .name_constraints_critical = false,
        .is_ca = false,
        .basic_constraints_path_len = null,
        .validity = .{ .not_before = 0, .not_after = 0 },
        .version = version,
    };
}

fn policyChainCert(
    der: []const u8,
    issuer: Certificate.Parsed.Slice,
    subject: Certificate.Parsed.Slice,
    signature_algorithm: Certificate.Algorithm,
) Certificate.Parsed {
    var cert = policyLeaf(der, .empty, .empty, signature_algorithm);
    cert.issuer_slice = issuer;
    cert.subject_slice = subject;
    return cert;
}

// RFC 8446 §4.4.2.2 — unless another certificate type is negotiated, the
// server certificate must be X.509v3.
test "certificate_policy.verifyServerAuth: non-v3 certificates are rejected" {
    const versions = [_]Certificate.Version{ .v1, .v2 };
    for (versions) |version| {
        const leaf = policyLeafWithVersion("", .empty, .empty, .ecdsa_with_SHA256, version);
        try testing.expectError(
            error.UnsupportedCertificateVersion,
            certificate_policy.verifyServerAuth(leaf),
        );
    }
}

// RFC 8446 §4.4.2.2 — a server certificate whose KeyUsage extension is present
// but omits digitalSignature cannot sign CertificateVerify and must be rejected.
test "certificate_policy.verifyServerAuth: KeyUsage without digitalSignature is rejected" {
    // BIT STRING, 6 unused bits, 0x40 sets bit 1 (nonRepudiation) but not bit 0.
    const key_usage = "\x03\x02\x06\x40";
    const leaf = policyLeaf(
        key_usage,
        .{ .start = 0, .end = key_usage.len },
        .empty,
        .ecdsa_with_SHA256,
    );
    try testing.expectError(
        error.CertificateKeyUsageRejected,
        certificate_policy.verifyServerAuth(leaf),
    );
}

// RFC 5280 §4.2.1.12 — when EKU is present it restricts allowed uses; without
// id-kp-serverAuth the certificate must not be accepted for TLS server auth.
test "certificate_policy.verifyServerAuth: EKU without serverAuth is rejected" {
    // SEQUENCE { OID id-kp-clientAuth (1.3.6.1.5.5.7.3.2) }
    const eku = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02";
    const leaf = policyLeaf(eku, .empty, .{ .start = 0, .end = eku.len }, .ecdsa_with_SHA256);
    try testing.expectError(
        error.CertificateExtendedKeyUsageRejected,
        certificate_policy.verifyServerAuth(leaf),
    );
}

// RFC 5280 §4.2.1.12 — a client certificate whose EKU is present but omits
// id-kp-clientAuth must not be accepted for TLS client auth.
test "certificate_policy.verifyClientAuth: EKU without clientAuth is rejected" {
    // SEQUENCE { OID id-kp-serverAuth (1.3.6.1.5.5.7.3.1) }
    const eku = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01";
    const leaf = policyLeaf(eku, .empty, .{ .start = 0, .end = eku.len }, .ecdsa_with_SHA256);
    try testing.expectError(
        error.CertificateExtendedKeyUsageRejected,
        certificate_policy.verifyClientAuth(leaf),
    );
}

// RFC 8446 §4.4.2.2 — a client certificate whose KeyUsage is present but omits
// digitalSignature cannot sign CertificateVerify and must be rejected.
test "certificate_policy.verifyClientAuth: KeyUsage without digitalSignature is rejected" {
    const key_usage = "\x03\x02\x06\x40";
    const leaf = policyLeaf(
        key_usage,
        .{ .start = 0, .end = key_usage.len },
        .empty,
        .ecdsa_with_SHA256,
    );
    try testing.expectError(
        error.CertificateKeyUsageRejected,
        certificate_policy.verifyClientAuth(leaf),
    );
}

// RFC 8446 §4.4.2.2 — a client certificate with clientAuth EKU and no KeyUsage
// restriction is accepted for TLS client auth.
test "certificate_policy.verifyClientAuth: clientAuth EKU is accepted" {
    // SEQUENCE { OID id-kp-clientAuth (1.3.6.1.5.5.7.3.2) }
    const eku = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02";
    const leaf = policyLeaf(eku, .empty, .{ .start = 0, .end = eku.len }, .ecdsa_with_SHA256);
    try certificate_policy.verifyClientAuth(leaf);
}

// RFC 8446 §4.2.3 — legacy certificate signature algorithms are rejected by
// the TLS 1.3 server-auth policy.
test "certificate_policy.verifyServerAuth: legacy certificate signatures are rejected" {
    const legacy_algorithms = [_]Certificate.Algorithm{
        .sha1WithRSAEncryption,
        .sha224WithRSAEncryption,
        .md2WithRSAEncryption,
        .md5WithRSAEncryption,
    };
    for (legacy_algorithms) |algorithm| {
        const leaf = policyLeaf("", .empty, .empty, algorithm);
        try testing.expectError(
            error.CertificateSignatureAlgorithmRejected,
            certificate_policy.verifyServerAuth(leaf),
        );
    }
}

// RFC 8446 §4.2.3 — rsa_pkcs1_sha256 is a certificate-signature-only scheme;
// accepting it for X.509 signatures does not make it a CertificateVerify scheme.
test "certificate_policy.verifyServerAuth: RSA PKCS1 SHA-256 certificate signature is accepted" {
    const leaf = policyLeaf("", .empty, .empty, .sha256WithRSAEncryption);
    try certificate_policy.verifyServerAuth(leaf);
}

// RFC 8446 §4.4.2.2 vs §4.4.3 — the certificate-chain signature algorithm
// (signature_algorithms_cert) is independent of the CertificateVerify scheme.
// Ed25519 chain signatures are verified via std.crypto.sign.Ed25519 in
// certificate_parser.zig, so .ed25519 is advertised in the backend's
// certificate_signature_schemes even though certificate_verify_schemes omits it.
test "certificate_policy: Ed25519 chain signature algorithm accepted when advertised" {
    const schemes = [_]SignatureScheme{.ed25519};
    try certificate_policy.verifyCertificateSignatureAlgorithm(.curveEd25519, &schemes);
}

// RFC 8446 §4.4.2.2 — Ed25519 must be absent from the advertised schemes to be
// rejected; the chain signature algorithm is policy-gated, not hardcoded.
test "certificate_policy: Ed25519 chain signature algorithm rejected when not advertised" {
    const schemes = [_]SignatureScheme{.ecdsa_secp256r1_sha256};
    try testing.expectError(
        error.CertificateSignatureAlgorithmRejected,
        certificate_policy.verifyCertificateSignatureAlgorithm(.curveEd25519, &schemes),
    );
}

// RFC 8446 §4.4.2.2 — a real Ed25519-signed self-signed certificate fixture is
// parsed and its chain signature is verified via std.crypto.sign.Ed25519. The
// leaf passes server-auth policy because .ed25519 is now in the backend's
// certificate_signature_schemes. The insecure_no_chain_anchor escape hatch is
// used because this is a self-signed fixture without a trust bundle.
test "parse: Ed25519 self-signed certificate verified via std.crypto" {
    var buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&buf, ed25519CertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
        .now_sec = 1_790_000_000,
        .host_name = "ed25519.server.test",
    }));
    try testing.expect(pub_key.len > 0);
}

// RFC 8446 §4.2.3 — signature_algorithms_cert constrains certificate
// signatures independently from CertificateVerify signatures.
test "certificate_policy.verifyServerAuth: rejects certificate signature outside policy" {
    const schemes = [_]SignatureScheme{.rsa_pkcs1_sha256};
    const leaf = policyLeaf("", .empty, .empty, .ecdsa_with_SHA256);
    try testing.expectError(
        error.CertificateSignatureAlgorithmRejected,
        certificate_policy.verifyServerAuthWithSignatureSchemes(leaf, &schemes),
    );
}

// RFC 8446 §4.2.3, §4.4.2.2 — non-self-signed certificates sent by the
// server are checked against the advertised certificate signature schemes.
test "certificate signature policy checks non-self-signed chain certificates" {
    const schemes = [_]SignatureScheme{.ecdsa_secp256r1_sha256};
    const chain = [_]Certificate.Parsed{
        policyChainCert(
            "issuerleaf",
            .{ .start = 0, .end = 6 },
            .{ .start = 6, .end = 10 },
            .ecdsa_with_SHA256,
        ),
        policyChainCert(
            "issuerbad",
            .{ .start = 0, .end = 6 },
            .{ .start = 6, .end = 9 },
            .ecdsa_with_SHA384,
        ),
    };
    try testing.expectError(
        error.CertificateSignatureAlgorithmRejected,
        verifyChainCertificateSignatureAlgorithms(&chain, &schemes),
    );
}

// RFC 8446 §4.4.2.2 — self-signed certificates in the chain are not validated
// as part of the chain and may use algorithms outside the advertised list.
test "certificate signature policy skips self-signed chain certificates" {
    const schemes = [_]SignatureScheme{.ecdsa_secp256r1_sha256};
    const chain = [_]Certificate.Parsed{
        policyChainCert(
            "issuerleaf",
            .{ .start = 0, .end = 6 },
            .{ .start = 6, .end = 10 },
            .ecdsa_with_SHA256,
        ),
        policyChainCert(
            "root",
            .{ .start = 0, .end = 4 },
            .{ .start = 0, .end = 4 },
            .ecdsa_with_SHA384,
        ),
    };
    try verifyChainCertificateSignatureAlgorithms(&chain, &schemes);
}

// RFC 8446 §4.4.2.2 — chainMatchesSignatureSchemes enforces the leaf and
// non-self-signed intermediates while skipping a presented self-signed root.
test "chainMatchesSignatureSchemes: leaf, intermediate, and self-signed root" {
    var ecdsa_only: OfferedCertificateSchemes = .empty;
    ecdsa_only.captureSchemes(&.{.ecdsa_secp256r1_sha256});
    var rsa_only: OfferedCertificateSchemes = .empty;
    rsa_only.captureSchemes(&.{.rsa_pkcs1_sha256});

    try testing.expect(chainMatchesSignatureSchemes(
        &.{&fixtures.server_ecdsa_cert_der},
        ecdsa_only,
    ));
    try testing.expect(!chainMatchesSignatureSchemes(
        &.{&fixtures.server_ecdsa_cert_der},
        rsa_only,
    ));
    try testing.expect(chainMatchesSignatureSchemes(&.{&fixtures.rsa_pss_cert_der}, rsa_only));
    try testing.expect(!chainMatchesSignatureSchemes(&.{&fixtures.rsa_pss_cert_der}, ecdsa_only));
    // Non-self-signed intermediate must match; self-signed root at index > 0 is exempt.
    try testing.expect(chainMatchesSignatureSchemes(
        &.{ &fixtures.chain_leaf_der, &fixtures.chain_intermediate_der },
        ecdsa_only,
    ));
    try testing.expect(!chainMatchesSignatureSchemes(
        &.{ &fixtures.chain_leaf_der, &fixtures.chain_intermediate_der },
        rsa_only,
    ));
    try testing.expect(chainMatchesSignatureSchemes(
        &.{ &fixtures.chain_leaf_der, &fixtures.rsa_pss_cert_der },
        ecdsa_only,
    ));
    // Empty and malformed DER chains surface distinct configuration errors.
    try testing.expectError(error.EmptyCertificateChain, chainRequiredSignatureSchemes(&.{}));
    try testing.expectError(error.InvalidCertificate, chainRequiredSignatureSchemes(&.{"not-der"}));
    try testing.expect(!chainMatchesSignatureSchemes(&.{}, ecdsa_only));
    try testing.expect(!chainMatchesSignatureSchemes(&.{"not-der"}, ecdsa_only));

    // RFC 8446 §4.2.3 — an RSASSA-PSS-signed certificate maps to rsa_pss_rsae_sha256
    // and verifies its own signature through Certificate.Parsed.verify.
    var pss_only: OfferedCertificateSchemes = .empty;
    pss_only.captureSchemes(&.{.rsa_pss_rsae_sha256});
    const parsed_pss = try (Certificate{
        .buffer = &fixtures.rsa_pss_signed_cert_der,
        .index = 0,
    }).parse();
    try testing.expectEqual(
        Certificate.Algorithm.rsassaPss_with_SHA256,
        parsed_pss.signature_algorithm,
    );
    try parsed_pss.verify(parsed_pss, 1_800_000_000);
    const pss_required = try chainRequiredSignatureSchemes(&.{&fixtures.rsa_pss_signed_cert_der});
    try testing.expect(pss_only.containsAll(pss_required));
    try testing.expect(!ecdsa_only.containsAll(pss_required));
}

// RFC 4055 §3.1, §4.1 — an RSASSA-PSS SubjectPublicKeyInfo retains its hash,
// MGF1 hash, salt length, and trailer field, then verifies a matching signature.
test "certificate_parser: RSASSA-PSS SubjectPublicKeyInfo parameters verify" {
    const parsed = try Certificate.parse(.{
        .buffer = &fixtures.rsa_pss_spki_cert_der,
        .index = 0,
    });
    switch (parsed.pub_key_algo) {
        .rsassa_pss => |maybe_params| {
            const params = maybe_params orelse return error.TestUnexpectedResult;
            try testing.expectEqual(Certificate.PssHash.sha256, params.hash);
            try testing.expectEqual(Certificate.PssHash.sha256, params.mgf1_hash);
            try testing.expectEqual(@as(u32, 32), params.salt_length);
            try testing.expectEqual(@as(u32, 1), params.trailer_field);
        },
        else => return error.TestUnexpectedResult,
    }
    try parsed.verify(parsed, fixtures.public_chain_now_sec);
}

// RFC 4055 §3.1, RFC 8446 §4.2.3 — a PSS key constrained to salt 20 cannot
// verify a TLS PSS signature with salt 32, even when every other field matches.
test "certificate_parser: RSASSA-PSS SubjectPublicKeyInfo salt constraint is enforced" {
    const parsed = try Certificate.parse(.{
        .buffer = &fixtures.rsa_pss_spki_salt20_cert_der,
        .index = 0,
    });
    switch (parsed.pub_key_algo) {
        .rsassa_pss => |maybe_params| {
            const params = maybe_params orelse return error.TestUnexpectedResult;
            try testing.expectEqual(Certificate.PssHash.sha256, params.hash);
            try testing.expectEqual(Certificate.PssHash.sha256, params.mgf1_hash);
            try testing.expectEqual(@as(u32, 20), params.salt_length);
            try testing.expectEqual(@as(u32, 1), params.trailer_field);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectError(
        error.CertificateSignatureAlgorithmMismatch,
        parsed.verify(parsed, fixtures.public_chain_now_sec),
    );
}

// RFC 4055 §3.1 — absent RSASSA-PSS public-key parameters mean unrestricted.
// The certificate signature still carries the TLS-required PSS parameters.
const rsa_pss_unrestricted_now_sec: i64 = 1_795_363_592;
test "certificate_parser: absent RSASSA-PSS SubjectPublicKeyInfo parameters are unrestricted" {
    const parsed = try Certificate.parse(.{
        .buffer = &fixtures.rsa_pss_unrestricted_cert_der,
        .index = 0,
    });
    switch (parsed.pub_key_algo) {
        .rsassa_pss => |params| try testing.expect(params == null),
        else => return error.TestUnexpectedResult,
    }
    try parsed.verify(parsed, rsa_pss_unrestricted_now_sec);
}

// RFC 8446 §4.4.2.2 — a leaf with no KeyUsage/EKU restrictions and a supported
// signature algorithm satisfies the residual server-auth policy.
test "certificate_policy.verifyServerAuth: unrestricted supported leaf is accepted" {
    const leaf = policyLeaf("", .empty, .empty, .ecdsa_with_SHA256);
    try certificate_policy.verifyServerAuth(leaf);
}

test "encodeCertificateVerify: wraps signature" {
    var buf: [512]u8 = undefined;
    const msg = try encodeCertificateVerify(&buf, .ecdsa_secp256r1_sha256, fixtureCvSig());
    try testing.expectEqual(@as(u8, 0x0f), msg[0]);
    try testing.expectEqual(certificateVerifyEncodedLen(fixtureCvSig()), msg.len);
    try testing.expectEqualSlices(u8, fixtureCvSig(), msg[8..]);
}

test "verifySignature: valid ECDSA P-256 signature" {
    var cert_buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    try verifyServerSignature(buildCvMsg(&cv_buf, fixtureCvSig()), pub_key, &test_transcript_hash);
}

// RFC 8446 §4.2.3 — rsa_pss_rsae_sha256 uses RSASSA-PSS with SHA-256,
// MGF1(SHA-256), and salt length equal to the digest length.
test "verifySignature: valid RSA-PSS SHA-256 signature" {
    var cert_buf: [2048]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureRsaPssCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    const cv = try encodeCertificateVerify(
        &cv_buf,
        .rsa_pss_rsae_sha256,
        fixtureRsaPssCvSig(),
    );
    try verifyServerSignature(cv, pub_key, &test_transcript_hash);
}

// RFC 8446 §4.2.3 — RSA-PSS CertificateVerify salt length is the hash output
// length, not an arbitrary PSS salt length accepted by generic RSA-PSS.
test "verifySignature: rejects RSA-PSS signature with wrong salt length" {
    var cert_buf: [2048]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureRsaPssCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    const cv = try encodeCertificateVerify(
        &cv_buf,
        .rsa_pss_rsae_sha256,
        fixtureRsaPssCvSalt20Sig(),
    );
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifyServerSignature(cv, pub_key, &test_transcript_hash),
    );
}

test "verifySignature: wrong transcript hash" {
    var cert_buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    const bad_hash: [32]u8 = @splat(0);
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifyServerSignature(buildCvMsg(&cv_buf, fixtureCvSig()), pub_key, &bad_hash),
    );
}

// RFC 8446 §4.4.3 — CertificateVerify must use a scheme from the client's
// signature_algorithms extension, not just any scheme tls globally supports.
test "verifySignature: rejects scheme absent from offered list" {
    var cert_buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    const offered = [_]SignatureScheme{.rsa_pss_rsae_sha256};
    try testing.expectError(
        error.UnsupportedSignatureScheme,
        verifyServerSignatureWithSchemes(
            buildCvMsg(&cv_buf, fixtureCvSig()),
            pub_key,
            &test_transcript_hash,
            &offered,
        ),
    );
}

// RFC 8446 §4.4.3 — a client CertificateVerify whose scheme is not in the
// server's CertificateRequest signature_algorithms is rejected with
// UnsupportedSignatureScheme (maps to illegal_parameter). This is the
// defensive guard the server uses against malicious client CVs.
test "verifySignature: client CV rejects scheme absent from offered list" {
    var cert_buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    const offered = [_]SignatureScheme{.rsa_pss_rsae_sha256};
    try testing.expectError(
        error.UnsupportedSignatureScheme,
        verifyClientSignatureWithSchemes(
            buildCvMsg(&cv_buf, fixtureCvSig()),
            pub_key,
            &test_transcript_hash,
            &offered,
        ),
    );
}

// baskingspot/tls#157 / RFC 8446 §4.4.3 — an RSA leaf key with exponent 1
// makes the public operation the identity, so any well-formed PSS encoding
// verifies as a CertificateVerify signature without any private key. The key
// loader must reject the degenerate key before the public operation runs,
// failing closed with InvalidEncoding. The 1024-bit odd modulus satisfies the
// loader's size policy, so the exponent check alone is what rejects this key.
test "verifySignature: rejects RSA leaf key with exponent 1" {
    // RSAPublicKey (PKCS#1, RFC 8017 §A.1.1): n = 2^1023 + 1, e = 1.
    const e1_pub_key = stdx.fmt.comptimeHex(
        "308187" ++ "02818100" ++ "80" ++ compat.repeatString("00", 126) ++ "01" ++ "020101",
    );
    const sig: [128]u8 = @splat(0x42);
    var cv_buf: [512]u8 = undefined;
    const cv = try encodeCertificateVerify(&cv_buf, .rsa_pss_rsae_sha256, &sig);
    try testing.expectError(
        error.InvalidEncoding,
        verifyServerSignature(cv, &e1_pub_key, &test_transcript_hash),
    );
    try testing.expectError(
        error.InvalidEncoding,
        verifyClientSignature(cv, &e1_pub_key, &test_transcript_hash),
    );
}

// RFC 8446 §4.4.3 — RSASSA-PKCS1-v1_5 schemes are certificate-signature-only
// in TLS 1.3 and must not be accepted for CertificateVerify.
test "verifySignature: rejects RSA PKCS1 CertificateVerify scheme" {
    var cert_buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    const cv = try encodeCertificateVerify(&cv_buf, .rsa_pkcs1_sha256, fixtureCvSig());
    try testing.expectError(
        error.UnsupportedSignatureScheme,
        verifyServerSignature(cv, pub_key, &test_transcript_hash),
    );
}

// RFC 8446 §4.2.3, §4.4.3 — the CertificateVerify scheme must be compatible
// with the certificate public key parameters.
test "verifySignature: rejects certificate key and scheme mismatch" {
    var cert_buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    const cv = try encodeCertificateVerify(&cv_buf, .ecdsa_secp384r1_sha384, fixtureCvSig());
    try testing.expectError(
        error.InvalidEncoding,
        verifyServerSignature(cv, pub_key, &test_transcript_hash),
    );
}

// RFC 8446 §4.4.3 — CertificateVerify context string binds the endpoint role.
test "verifySignature: server signature is not valid for client context" {
    var cert_buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifyClientSignature(buildCvMsg(&cv_buf, fixtureCvSig()), pub_key, &test_transcript_hash),
    );
}

test "verifySignature: wrong handshake type" {
    var cert_buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&cert_buf, fixtureCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    var cv_buf: [512]u8 = undefined;
    _ = buildCvMsg(&cv_buf, fixtureCvSig());
    cv_buf[0] = 0x01;
    try testing.expectError(
        error.InvalidHandshakeType,
        verifyServerSignature(&cv_buf, pub_key, &test_transcript_hash),
    );
}

// ---------------------------------------------------------------------------
// Native CertificateVerify verification — key policy and Wycheproof vectors
// ---------------------------------------------------------------------------
//
// These vectors used to run through EVP_DigestVerify* in the libcrypto
// backend. #183 moved verification in-tree, so they now pin the shipped
// verifier at the level it runs: `verifySignedContent` takes the raw signed
// content (context string followed by the transcript hash).

// Wycheproof v1 RSA-PSS 2048 public modulus
// (rsa_pss_2048_sha256_mgf1_32_test.json), shared by the verify vectors and
// the #157 key-parameter policy tests.
const wycheproof_rsa_n_2048_hex =
    "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717" ++
    "094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429" ++
    "e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3" ++
    "d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f49" ++
    "0ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a1" ++
    "2be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f11" ++
    "26422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc" ++
    "22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf" ++
    "7820283f742b9d5";

fn comptimeHexByte(comptime v: u8) *const [2]u8 {
    const digits = "0123456789abcdef";
    return &.{ digits[v >> 4], digits[v & 0xf] };
}

fn comptimeDerLenHex(comptime len: u16) []const u8 {
    if (len < 0x80) return comptimeHexByte(@intCast(len));
    if (len < 0x100) return "81" ++ comptimeHexByte(@intCast(len));
    return "82" ++ comptimeHexByte(@intCast(len >> 8)) ++ comptimeHexByte(@truncate(len));
}

// RFC 8017 §A.1.1 — RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent
// INTEGER }. Builds minimal PKCS#1 DER hex around a caller-chosen modulus and
// exponent TLV so a test can vary one parameter at a time.
fn rsaPubKeyDerHex(comptime n_hex: []const u8, comptime e_tlv_hex: []const u8) []const u8 {
    const first = std.ascii.toLower(n_hex[0]);
    const needs_sign = (first >= '8' and first <= '9') or
        (first >= 'a' and first <= 'f');
    const sign = if (needs_sign) "00" else "";
    const n_tlv = "02" ++ comptimeDerLenHex(n_hex.len / 2 + sign.len / 2) ++ sign ++ n_hex;
    return "30" ++ comptimeDerLenHex(n_tlv.len / 2 + e_tlv_hex.len / 2) ++ n_tlv ++ e_tlv_hex;
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — RSA-PSS 2048 SHA-256/MGF1-SHA256
// sLen=32, tcId 3, valid. Source: rsa_pss_2048_sha256_mgf1_32_test.json.
// RFC 8446 §4.2.3 requires salt length equal to the digest length, which is
// the sLen=32 this vector uses.
test "verifySignedContent: Wycheproof RSA-PSS tcId 3" {
    const pub_der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(wycheproof_rsa_n_2048_hex, "0203010001"));
    const msg = stdx.fmt.comptimeHex("54657374"); // "Test"
    const sig = stdx.fmt.comptimeHex(
        "401eb03cdb47ca88033e3030f6bdecbac8f5c8fc1dd6a13d23d379ed9a2b3098" ++
            "91d13d74fea9d21d159b9e6d8f37efa2489962e24555f56dd434ff1d31ce4f9f" ++
            "5abd3f22cbea8b691d6a11e44efb83e2bca155e6a164325e0fde2a8865afd5c9" ++
            "f51161a9d615f62af7ec2e31b3e5ab649c164490d31d88cfae35b84aea792569" ++
            "0f929a144b6d2f48e8fb894a52deecd1b9a6496990c4ecf1588699a42cacd10c" ++
            "53af350514e4291ea9a058e77f101e32c1c0cefa61d945f7bc931f8bd19e7ba3" ++
            "169358a60e5a8b0123bc3199b9fdcafe8e519c41ba675491a27b85e44ef2d772" ++
            "77c10fe107293c8290186913bc9a99b640d8da041b64f31eab1d35920985f4a5",
    );

    try verifySignedContent(.rsa_pss_rsae_sha256, &pub_der, &msg, &sig);
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — RSA-PSS 2048 SHA-256/MGF1-SHA256
// sLen=32, tcId 62, invalid (first byte of m_hash modified).
// Source: rsa_pss_2048_sha256_mgf1_32_test.json. The signature is valid for a
// different message hash, so verification must fail for this message.
test "verifySignedContent: Wycheproof RSA-PSS tcId 62 invalid signature" {
    const pub_der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(wycheproof_rsa_n_2048_hex, "0203010001"));
    const msg = stdx.fmt.comptimeHex("313233343030"); // "123400"
    const sig = stdx.fmt.comptimeHex(
        "67d1d1c0a398148625317c3f5e44b738bdf461c27a59594b39ebb2aebef233c7" ++
            "809379e54411411b82d2e7ac88f989b58373d532c758baea121878ce97594417" ++
            "38d121881c1fa2d04421f02dd565b12770d844611ed1873a0b64d822709a6b78" ++
            "d6d3892b294404bce6711001d6c3a54546c76a1d17819674b0be904497a233b4" ++
            "66fe4becc832dee740f9ab79e5b9f5db0b0f9aac0084ba05cebf42303b5ca2ad" ++
            "95e3d61b29ed6475545c02e93e7b0e118af92f5cddb1faeb2cbc23c9e69c120e" ++
            "29df7fe31991e887b3b29e77688c60e80be65cccf3d7861a7a14c39e6a6e5645" ++
            "568e2cc5e4a17b75db1dd415aadb45e112a9b582b2ff6e82a43d7a7347b7b56d",
    );

    try testing.expectError(
        error.SignatureVerificationFailed,
        verifySignedContent(.rsa_pss_rsae_sha256, &pub_der, &msg, &sig),
    );
}

// RFC 8446 §4.4.3 / §C.3 — e = 1 makes the RSA public operation the identity,
// so any well-formed PSS encoding would verify without a private key. The key
// must be rejected before the signature is considered.
test "verifySignedContent: RSA leaf key with exponent 1 is rejected" {
    const der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(wycheproof_rsa_n_2048_hex, "020101"));
    const sig: [256]u8 = @splat(0x42);
    try testing.expectError(
        error.InvalidEncoding,
        verifySignedContent(.rsa_pss_rsae_sha256, &der, "msg", &sig),
    );
}

test "verifySignedContent: RSA key with even exponent is rejected" {
    // e = 65536: parses, but even.
    const der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(wycheproof_rsa_n_2048_hex, "0203010000"));
    const sig: [256]u8 = @splat(0x42);
    try testing.expectError(
        error.InvalidEncoding,
        verifySignedContent(.rsa_pss_rsae_sha256, &der, "msg", &sig),
    );
}

test "verifySignedContent: RSA key with exponent wider than 32 bits is rejected" {
    // e = 2^32 + 1: odd, but 33 bits. The 32-bit cap bounds the cost of the
    // public operation for attacker-chosen keys (Windows CryptoAPI limit).
    const der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(wycheproof_rsa_n_2048_hex, "02050100000001"));
    const sig: [256]u8 = @splat(0x42);
    try testing.expectError(
        error.InvalidEncoding,
        verifySignedContent(.rsa_pss_rsae_sha256, &der, "msg", &sig),
    );
}

test "verifySignedContent: RSA key with even modulus is rejected" {
    const der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(
        wycheproof_rsa_n_2048_hex[0..510] ++ "ce",
        "0203010001",
    ));
    const sig: [256]u8 = @splat(0x42);
    try testing.expectError(
        error.InvalidEncoding,
        verifySignedContent(.rsa_pss_rsae_sha256, &der, "msg", &sig),
    );
}

test "verifySignedContent: RSA key with a 1023-bit modulus is rejected" {
    // A 128-octet modulus whose leading octet is 0x7f has 1023 bits. It clears
    // `rsa.PublicKey.fromBytes` (odd, >= 512 bits) and the modulus-length
    // switch, so the 1024-bit leaf-key floor is the only check that can reject
    // it. Every repo fixture and interop key is >= 2048 bits; the chain
    // verifier keeps its lower 512-bit floor for legacy issuers.
    const der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(
        "7f" ++ compat.repeatString("00", 126) ++ "01",
        "0203010001",
    ));
    const sig: [128]u8 = @splat(0x42);
    try testing.expectError(
        error.InvalidEncoding,
        verifySignedContent(.rsa_pss_rsae_sha256, &der, "msg", &sig),
    );
}

test "verifySignedContent: RSA key with trailing bytes is rejected" {
    // The whole SubjectPublicKey must be exactly one RSAPublicKey.
    const der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(wycheproof_rsa_n_2048_hex, "0203010001"));
    var buf: [der.len + 1]u8 = undefined;
    @memcpy(buf[0..der.len], &der);
    buf[der.len] = 0;
    const sig: [256]u8 = @splat(0x42);
    try testing.expectError(
        error.InvalidEncoding,
        verifySignedContent(.rsa_pss_rsae_sha256, &buf, "msg", &sig),
    );
}

// RFC 8017 §A.1.2 — a positive INTEGER whose high bit is set carries a
// leading 0x00 sign octet, so a 32-bit exponent such as 0x80000001 arrives as
// five octets. The exponent cap is numeric, not an encoding length, and this
// key must reach the signature check rather than being rejected.
test "verifySignedContent: 32-bit exponent with a DER sign octet is accepted" {
    const der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(wycheproof_rsa_n_2048_hex, "02050080000001"));
    const sig: [256]u8 = @splat(0x42);
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifySignedContent(.rsa_pss_rsae_sha256, &der, "msg", &sig),
    );
}

// RFC 8446 §4.4.3 — a key that does not decode is reported as an invalid
// encoding even when the signature is also malformed, so the peer is told
// decode_error rather than decrypt_error.
test "verifySignedContent: undecodable ECDSA key wins over undecodable signature" {
    const bad_key: [3]u8 = @splat(0xff);
    const bad_sig: [8]u8 = @splat(0xff);
    try testing.expectError(
        error.InvalidEncoding,
        verifySignedContent(.ecdsa_secp256r1_sha256, &bad_key, "msg", &bad_sig),
    );
}

// RFC 8017 §3.1 — e = 3 is a legal public exponent, so a key that carries it
// must reach the signature check. Exponent 65537 acceptance is covered by
// Wycheproof tcId 3, which verifies against a 65537 key.
test "verifySignedContent: exponent-3 RSA key is accepted and fails on the signature" {
    const der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(wycheproof_rsa_n_2048_hex, "020103"));
    const sig: [256]u8 = @splat(0x42);
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifySignedContent(.rsa_pss_rsae_sha256, &der, "msg", &sig),
    );
}

// RFC 8017 §8.1.2 step 2c — when modBits ≡ 1 (mod 8), which for a full-width
// modulus means a leading octet of 0x01, emLen is one less than the modulus
// length and I2OSP must drop a zero octet. The modulus is the peer's choice, so
// without that a 2041-bit leaf key panics a Debug or ReleaseSafe build from the
// network.
test "verifySignedContent: RSA-PSS rejects a short-leading-octet modulus without panicking" {
    // 256-byte odd modulus with a 0x01 leading octet: 2041 bits, which clears
    // the 1024-bit floor. The signature leads with 0x00 so the public
    // operation yields an integer below the modulus and reaches EMSA-PSS.
    const der = stdx.fmt.comptimeHex(rsaPubKeyDerHex(
        "01" ++ compat.repeatString("00", 254) ++ "01",
        "0203010001",
    ));
    var sig: [256]u8 = @splat(0x42);
    sig[0] = 0x00;
    try testing.expectError(
        error.SignatureVerificationFailed,
        verifySignedContent(.rsa_pss_rsae_sha256, &der, "msg", &sig),
    );
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — ECDSA P-256 SHA-256 tcId 1,
// valid (pseudorandom signature) over the empty message.
// Source: ecdsa_secp256r1_sha256_test.json.
test "verifySignedContent: Wycheproof ECDSA P-256 tcId 1" {
    const pub_sec1: [65]u8 = stdx.fmt.comptimeHex(
        "0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5" ++
            "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    const sig = stdx.fmt.comptimeHex(
        "3045022100b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d" ++
            "8770b34a02200177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2a" ++
            "bebdf89a62e2",
    );

    try verifySignedContent(.ecdsa_secp256r1_sha256, &pub_sec1, "", &sig);
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — ECDSA P-256 SHA-256 tcId 6,
// invalid (ASN.1 encoding of s misses the required leading zero).
// Source: ecdsa_secp256r1_sha256_test.json.
test "verifySignedContent: Wycheproof ECDSA P-256 tcId 6 invalid signature" {
    const pub_sec1: [65]u8 = stdx.fmt.comptimeHex(
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c73283" ++
            "8c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    const msg = stdx.fmt.comptimeHex("313233343030"); // "123400"
    const sig = stdx.fmt.comptimeHex(
        "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9" ++
            "bd5c2e180220b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c13" ++
            "4b49156847db",
    );

    try testing.expectError(
        error.SignatureVerificationFailed,
        verifySignedContent(.ecdsa_secp256r1_sha256, &pub_sec1, &msg, &sig),
    );
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — ECDSA P-384 SHA-384 tcId 1,
// valid (pseudorandom signature) over the empty message.
// Source: ecdsa_secp384r1_sha384_test.json.
test "verifySignedContent: Wycheproof ECDSA P-384 tcId 1" {
    const pub_sec1: [97]u8 = stdx.fmt.comptimeHex(
        "0429bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61" ++
            "ef182e155a54345a5e8e5e88f064e5bc9a525ab7f764dad3dae1468c2b419f3b6" ++
            "2b9ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3",
    );
    const sig = stdx.fmt.comptimeHex(
        "3064023032401249714e9091f05a5e109d5c1216fdc05e98614261aa0dbd9e9c" ++
            "d4415dee29238afbd3b103c1e40ee5c9144aee0f02304326756fb2c4fd726360" ++
            "dd6479b5849478c7a9d054a833a58c1631c33b63c3441336ddf2c7fe0ed129aa" ++
            "e6d4ddfeb753",
    );

    try verifySignedContent(.ecdsa_secp384r1_sha384, &pub_sec1, "", &sig);
}

// Wycheproof v1 (google-wycheproof 0.9rc5) — ECDSA P-384 SHA-384 tcId 6,
// invalid (ASN.1 encoding of s misses the required leading zero).
// Source: ecdsa_secp384r1_sha384_test.json.
test "verifySignedContent: Wycheproof ECDSA P-384 tcId 6 invalid signature" {
    const pub_sec1: [97]u8 = stdx.fmt.comptimeHex(
        "042da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f2" ++
            "0f47ff888274389772d98cc5752138aa4b6d054d69dcf3e25ec49df870715e34" ++
            "883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f",
    );
    const msg = stdx.fmt.comptimeHex("313233343030"); // "123400"
    const sig = stdx.fmt.comptimeHex(
        "3064023012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28" ++
            "e3113083ba8e4ae4cc45a0320abd3394f1c548d70230e7bf25603e2d07076ff" ++
            "30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04f" ++
            "ecc47bff426f82",
    );

    try testing.expectError(
        error.SignatureVerificationFailed,
        verifySignedContent(.ecdsa_secp384r1_sha384, &pub_sec1, &msg, &sig),
    );
}

// RFC 5280 §4.2.1.10 — Name Constraints extension is parsed from a real
// certificate and its value slice is available, even though path-level
// enforcement is not yet implemented.
test "parse: extracts critical name constraints" {
    var buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&buf, nameConstraintsDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    try testing.expect(pub_key.len > 0);

    // Verify the extension was extracted by parsing the leaf directly.
    const cert: Certificate = .{ .buffer = nameConstraintsDer(), .index = 0 };
    const parsed = try cert.parse();
    const nc = parsed.nameConstraints();
    try testing.expect(nc.len > 0);
    // First byte should be SEQUENCE (0x30) for NameConstraints.
    try testing.expectEqual(@as(u8, 0x30), nc[0]);
}

// RFC 5280 §4.2.1.10 — non-critical Name Constraints are also parsed.
test "parse: extracts non-critical name constraints" {
    var buf: [1024]u8 = undefined;
    const pub_key = try parse(buildCertMsg(&buf, nameConstraintsNoncriticalDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    try testing.expect(pub_key.len > 0);

    const cert: Certificate = .{ .buffer = nameConstraintsNoncriticalDer(), .index = 0 };
    const parsed = try cert.parse();
    const nc = parsed.nameConstraints();
    try testing.expect(nc.len > 0);
    try testing.expectEqual(@as(u8, 0x30), nc[0]);
}

// Fuzz target: parse must reject arbitrary Certificate bytes with an error,
// never crash. Exercises our framing plus certificate_parser's X.509 parser.
// Run with `just fuzz 100K`.
fn fuzzParse(_: void, input: []const u8) anyerror!void {
    _ = parse(input, .init) catch return;
}

test "fuzz: parse handles arbitrary input" {
    var buf: [1024]u8 = undefined;
    try fuzz_compat.fuzzBytes(fuzzParse, {}, .{
        .corpus = &.{buildCertMsg(&buf, fixtureCertDer())},
    });
}

// Fuzz target: CertificateVerify signature verification only. Every input is
// wrapped in a well-formed CertificateVerify message with a scheme from the
// fixed list below. Arbitrary CertificateVerify message parsing is outside
// this target. Certificate message parsing has the separate `fuzz: parse
// handles arbitrary input` target above.
//
// Every full handshake takes a peer-chosen key, scheme, signature, and
// transcript hash through `verifyServerSignature` or `verifyClientSignature`,
// so all four are fuzz
// dimensions and a mutation in one leaves the framing of the others intact:
//
//   byte 0     scheme tag, indexing `fuzz_verify_schemes`
//   bytes 1-2  public-key length, big-endian u16
//   bytes 3-4  signature length, big-endian u16
//   the rest   public key, signature, transcript hash
//
// The verifier holds no secrets, so success or an error is the only legal
// answer to any input and a panic is the bug. The target stops at the
// SubjectPublicKey bits, which is what the verifier takes, so discovery needs
// no valid certificate chain in front of it. Run with `just fuzz 100K`.
const fuzz_verify_schemes = [_]SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .ed25519,
};

/// Largest signature the target frames into a CertificateVerify message. The
/// widest signature any accepted scheme produces is a 512-octet RSA-4096 PSS
/// signature; anything longer is past every key the verifier takes.
const fuzz_verify_sig_max = 1024;
const fuzz_verify_header_len = 5;
/// The CertificateVerify frame `certificateVerifyEncodedLen` reports for a
/// signature of `fuzz_verify_sig_max` octets.
const fuzz_verify_frame_max = certificateVerifyEncodedLen("") + fuzz_verify_sig_max;

const FuzzVerifyInput = struct {
    scheme: SignatureScheme,
    pub_key: []const u8,
    sig: []const u8,
    transcript_hash: []const u8,
};

fn decodeFuzzVerifyInput(input: []const u8) ?FuzzVerifyInput {
    if (input.len < fuzz_verify_header_len) return null;
    const pub_len = mem.readInt(u16, input[1..3], .big);
    const sig_len = mem.readInt(u16, input[3..5], .big);
    var rest = input[fuzz_verify_header_len..];
    // A length past the end clamps to what arrived, so a mutated length byte
    // still reaches the verifier instead of discarding the input.
    const pub_key = rest[0..@min(rest.len, pub_len)];
    rest = rest[pub_key.len..];
    const sig = rest[0..@min(rest.len, sig_len)];
    rest = rest[sig.len..];
    if (sig.len > fuzz_verify_sig_max) return null;
    return .{
        .scheme = fuzz_verify_schemes[input[0] % fuzz_verify_schemes.len],
        .pub_key = pub_key,
        .sig = sig,
        .transcript_hash = rest,
    };
}

fn encodeFuzzVerifyInput(
    buf: []u8,
    scheme: SignatureScheme,
    pub_key: []const u8,
    sig: []const u8,
    transcript_hash: []const u8,
) []const u8 {
    const total = fuzz_verify_header_len + pub_key.len + sig.len + transcript_hash.len;
    assert(buf.len >= total);
    assert(total <= std.math.maxInt(u16));
    buf[0] = @intCast(mem.findScalar(SignatureScheme, &fuzz_verify_schemes, scheme) orelse
        unreachable);
    mem.writeInt(u16, buf[1..3], @intCast(pub_key.len), .big);
    mem.writeInt(u16, buf[3..5], @intCast(sig.len), .big);
    var w: usize = fuzz_verify_header_len;
    for ([_][]const u8{ pub_key, sig, transcript_hash }) |part| {
        @memcpy(buf[w..][0..part.len], part);
        w += part.len;
    }
    return buf[0..total];
}

fn fuzzVerifyCertificateVerify(_: void, input: []const u8) anyerror!void {
    const fields = decodeFuzzVerifyInput(input) orelse return;
    var cv_buf: [fuzz_verify_frame_max]u8 = undefined;
    const cv = encodeCertificateVerify(&cv_buf, fields.scheme, fields.sig) catch return;
    // Every verdict is legal for attacker-shaped input: the contract is that
    // neither role panics on any of the four fuzzed fields. One invariant does
    // hold — RFC 8446 §4.4.3 puts a different context string in front of each
    // role's signed content, so one signature cannot satisfy both.
    const as_server = verifyServerSignature(cv, fields.pub_key, fields.transcript_hash);
    const as_client = verifyClientSignature(cv, fields.pub_key, fields.transcript_hash);
    const server_ok = if (as_server) |_| true else |_| false;
    const client_ok = if (as_client) |_| true else |_| false;
    assert(!(server_ok and client_ok));
}

// The verifier's verdict for one encoded target input, for pinning what a
// seed reaches. Seeds that all fail in the first octet are decoration.
fn verifyFuzzSeed(input: []const u8) VerifyError!void {
    const fields = decodeFuzzVerifyInput(input) orelse return error.UnexpectedEof;
    var cv_buf: [fuzz_verify_frame_max]u8 = undefined;
    const cv = encodeCertificateVerify(&cv_buf, fields.scheme, fields.sig) catch unreachable;
    return verifyServerSignature(cv, fields.pub_key, fields.transcript_hash);
}

// RFC 8446 §4.4.3 — the CertificateVerify verifier must reject arbitrary
// keys, schemes, signatures, and transcript hashes with an error, never a
// panic. The seeds are the shapes that reach deepest: two valid chains from
// the fixtures (P-256 and RSA-PSS-2048), the same signature with one bit
// flipped, the same signature truncated, the P-256 key under a P-384 scheme,
// and the three key encodings the policy rejects (e = 1, a 2041-bit modulus,
// an off-curve point).
test "fuzz: CertificateVerify verification only with well-formed messages" {
    var cert_buf: [2048]u8 = undefined;
    var rsa_cert_buf: [2048]u8 = undefined;
    const p256_pub = try parse(buildCertMsg(&cert_buf, fixtureCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));
    const rsa_pub = try parse(buildCertMsg(&rsa_cert_buf, fixtureRsaPssCertDer()), testPolicy(.{
        .insecure_no_chain_anchor = true,
    }));

    const cv_sig = fixtureCvSig();
    const rsa_sig = fixtureRsaPssCvSig();
    var bad_sig_storage: [128]u8 = undefined;
    const bad_sig = bad_sig_storage[0..cv_sig.len];
    @memcpy(bad_sig, cv_sig);
    bad_sig[cv_sig.len - 1] ^= 0xff;
    // RFC 8017 §3.3.1 — e = 1 makes the public operation the identity, so any
    // well-formed PSS encoding verifies without a private key (#157).
    const exponent_one_key = stdx.fmt.comptimeHex(
        rsaPubKeyDerHex(wycheproof_rsa_n_2048_hex, "020101"),
    );
    // A full-width modulus whose leading octet is 0x01 has 2041 bits, so
    // EMSA-PSS-VERIFY's emLen is one octet shorter than the modulus (#183).
    // The signature below the modulus is what keeps the RSA operation running
    // far enough to reach that slice: the fixture signature starts above n.
    const mod_2041_hex = comptime "01" ++ compat.repeatString("ff", 255);
    const short_emlen_key = stdx.fmt.comptimeHex(rsaPubKeyDerHex(mod_2041_hex, "0203010001"));
    var short_emlen_sig: [256]u8 = @splat(0);
    @memcpy(short_emlen_sig[1..], rsa_sig[1..]);
    var off_curve_key: [65]u8 = @splat(0);
    off_curve_key[0] = 0x04;

    var seed_buf: [8][1200]u8 = undefined;
    var corpus: [8][]const u8 = undefined;
    const Seed = struct {
        scheme: SignatureScheme,
        pub_key: []const u8,
        sig: []const u8,
    };
    const seeds = [_]Seed{
        .{ .scheme = .ecdsa_secp256r1_sha256, .pub_key = p256_pub, .sig = cv_sig },
        .{ .scheme = .rsa_pss_rsae_sha256, .pub_key = rsa_pub, .sig = rsa_sig },
        .{ .scheme = .ecdsa_secp256r1_sha256, .pub_key = p256_pub, .sig = bad_sig },
        .{
            .scheme = .ecdsa_secp256r1_sha256,
            .pub_key = p256_pub,
            .sig = cv_sig[0 .. cv_sig.len / 2],
        },
        .{ .scheme = .ecdsa_secp384r1_sha384, .pub_key = p256_pub, .sig = cv_sig },
        .{ .scheme = .rsa_pss_rsae_sha256, .pub_key = &exponent_one_key, .sig = rsa_sig },
        .{ .scheme = .rsa_pss_rsae_sha256, .pub_key = &short_emlen_key, .sig = &short_emlen_sig },
        .{ .scheme = .ecdsa_secp256r1_sha256, .pub_key = &off_curve_key, .sig = cv_sig },
    };
    for (seeds, &seed_buf, &corpus) |seed, *buf, *corpus_entry| {
        corpus_entry.* = encodeFuzzVerifyInput(
            buf,
            seed.scheme,
            seed.pub_key,
            seed.sig,
            &test_transcript_hash,
        );
    }

    // Each seed must fail at the arm it was built for, not earlier, and the
    // two fixture seeds must verify outright.
    try verifyFuzzSeed(corpus[0]);
    try verifyFuzzSeed(corpus[1]);
    try testing.expectError(error.SignatureVerificationFailed, verifyFuzzSeed(corpus[2]));
    try testing.expectError(error.SignatureVerificationFailed, verifyFuzzSeed(corpus[3]));
    try testing.expectError(error.InvalidEncoding, verifyFuzzSeed(corpus[4]));
    try testing.expectError(error.InvalidEncoding, verifyFuzzSeed(corpus[5]));
    try testing.expectError(error.SignatureVerificationFailed, verifyFuzzSeed(corpus[6]));
    try testing.expectError(error.InvalidEncoding, verifyFuzzSeed(corpus[7]));

    try fuzz_compat.fuzzBytes(fuzzVerifyCertificateVerify, {}, .{ .corpus = &corpus });
}
