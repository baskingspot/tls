//! Wycheproof RSA signature verification vectors (#215).
//!
//! The JSON is committed under tests/fixtures/wycheproof. Tests decode the
//! upstream cases at run time, but never fetch them. Each vector uses the same
//! slice-based entry point as certificate or CertificateVerify verification.
const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const print = std.debug.print;

const Certificate = @import("certificate_parser.zig");
const fixtures = @import("fixtures");

const VectorFile = struct {
    numberOfTests: u32,
    testGroups: []const TestGroup,
};

const TestGroup = struct {
    publicKeyAsn: []const u8,
    tests: []const TestCase,
};

const TestCase = struct {
    tcId: u32,
    comment: []const u8 = "",
    msg: []const u8,
    sig: []const u8,
    result: []const u8,
};

const Algorithm = enum { pkcs1, pss };
const VerifyError = Certificate.rsa.PKCS1v1_5Signature.VerifyDerError ||
    Certificate.rsa.PSSSignature.VerifyDerError;

fn verifyWithScheme(
    comptime Hash: type,
    comptime algorithm: Algorithm,
    msg: []const u8,
    sig: []const u8,
    key: []const u8,
) VerifyError!void {
    return switch (algorithm) {
        .pkcs1 => Certificate.rsa.PKCS1v1_5Signature.verifyDer(Hash, msg, sig, key),
        .pss => Certificate.rsa.PSSSignature.verifyDer(Hash, msg, sig, key, 1024, .forTls(Hash)),
    };
}

fn checkExactSignatureLength(
    comptime Hash: type,
    comptime algorithm: Algorithm,
    msg: []const u8,
    sig: []const u8,
    key: []const u8,
) !void {
    try testing.expectError(
        error.CertificateSignatureInvalidLength,
        verifyWithScheme(Hash, algorithm, msg, sig[0 .. sig.len - 1], key),
    );
    try testing.expectError(
        error.CertificateSignatureInvalidLength,
        verifyWithScheme(Hash, algorithm, msg, sig[0..0], key),
    );
    var long_buf: [1025]u8 = undefined;
    @memcpy(long_buf[0..sig.len], sig);
    long_buf[sig.len] = 0;
    try testing.expectError(
        error.CertificateSignatureInvalidLength,
        verifyWithScheme(Hash, algorithm, msg, long_buf[0 .. sig.len + 1], key),
    );
}

fn runVectors(
    comptime Hash: type,
    comptime algorithm: Algorithm,
    comptime scheme_name: []const u8,
    json: []const u8,
    expected_cases: u32,
    expected_acceptable: u32,
) !void {
    const parsed = try std.json.parseFromSlice(VectorFile, testing.allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    var case_count: u32 = 0;
    var valid_count: u32 = 0;
    var invalid_count: u32 = 0;
    var acceptable_count: u32 = 0;
    var checked_length = false;
    for (parsed.value.testGroups) |group| {
        var key_buf: [1024]u8 = undefined;
        const key = try std.fmt.hexToBytes(&key_buf, group.publicKeyAsn);
        for (group.tests) |case| {
            case_count += 1;
            var msg_buf: [64]u8 = undefined;
            const msg = try std.fmt.hexToBytes(&msg_buf, case.msg);
            var sig_buf: [1024]u8 = undefined;
            const sig = try std.fmt.hexToBytes(&sig_buf, case.sig);

            var failure: ?anyerror = null;
            verifyWithScheme(Hash, algorithm, msg, sig, key) catch |err| {
                failure = err;
            };
            const expect_accept = mem.eql(u8, case.result, "valid");
            const expect_reject = mem.eql(u8, case.result, "invalid") or
                // Wycheproof permits either result here. tls chooses strict
                // DigestInfo DER, so the missing-NULL case must reject.
                mem.eql(u8, case.result, "acceptable");
            if (!expect_accept and !expect_reject) return error.TestUnexpectedResult;
            if (expect_accept) valid_count += 1;
            if (mem.eql(u8, case.result, "invalid")) invalid_count += 1;
            if (mem.eql(u8, case.result, "acceptable")) acceptable_count += 1;
            if ((failure == null) != expect_accept) {
                print(
                    "Wycheproof {s} tcId {d} ({s}) expected {s}, got {t}\n",
                    .{
                        scheme_name,
                        case.tcId,
                        case.comment,
                        case.result,
                        failure orelse error.Accepted,
                    },
                );
                return error.TestUnexpectedResult;
            }

            if (!checked_length and expect_accept) {
                checked_length = true;
                try checkExactSignatureLength(Hash, algorithm, msg, sig, key);
            }
        }
    }
    try testing.expect(checked_length);
    try testing.expectEqual(parsed.value.numberOfTests, case_count);
    try testing.expectEqual(expected_cases, case_count);
    try testing.expect(valid_count > 0);
    try testing.expect(invalid_count > 0);
    try testing.expectEqual(expected_acceptable, acceptable_count);
}

// RFC 8017 §8.2, §9.2 — full Wycheproof v1 rsa_signature_2048_sha256 set.
test "Wycheproof RSA PKCS1 SHA-256: 259 vectors and exact signature length" {
    try runVectors(
        std.crypto.hash.sha2.Sha256,
        .pkcs1,
        "rsa_pkcs1_sha256",
        fixtures.wycheproof_rsa_pkcs1_2048_sha256,
        259,
        1,
    );
}

// RFC 8017 §8.2, §9.2 — full Wycheproof v1 rsa_signature_3072_sha384 set.
test "Wycheproof RSA PKCS1 SHA-384: 259 vectors and exact signature length" {
    try runVectors(
        std.crypto.hash.sha2.Sha384,
        .pkcs1,
        "rsa_pkcs1_sha384",
        fixtures.wycheproof_rsa_pkcs1_3072_sha384,
        259,
        1,
    );
}

// RFC 8017 §8.2, §9.2 — full Wycheproof v1 rsa_signature_4096_sha512 set.
test "Wycheproof RSA PKCS1 SHA-512: 259 vectors and exact signature length" {
    try runVectors(
        std.crypto.hash.sha2.Sha512,
        .pkcs1,
        "rsa_pkcs1_sha512",
        fixtures.wycheproof_rsa_pkcs1_4096_sha512,
        259,
        1,
    );
}

// RFC 8017 §8.1, §9.1 — full Wycheproof v1 RSA-PSS SHA-256/MGF1-SHA-256 set.
test "Wycheproof RSA-PSS SHA-256: 108 vectors and exact signature length" {
    try runVectors(
        std.crypto.hash.sha2.Sha256,
        .pss,
        "rsa_pss_rsae_sha256",
        fixtures.wycheproof_rsa_pss_2048_sha256,
        108,
        0,
    );
}

// RFC 8017 §8.1, §9.1 — full Wycheproof v1 RSA-PSS SHA-384/MGF1-SHA-384 set.
test "Wycheproof RSA-PSS SHA-384: 141 vectors and exact signature length" {
    try runVectors(
        std.crypto.hash.sha2.Sha384,
        .pss,
        "rsa_pss_rsae_sha384",
        fixtures.wycheproof_rsa_pss_2048_sha384,
        141,
        0,
    );
}

// RFC 8017 §8.1, §9.1 — full Wycheproof v1 RSA-PSS SHA-512/MGF1-SHA-512 set.
test "Wycheproof RSA-PSS SHA-512: 179 vectors and exact signature length" {
    try runVectors(
        std.crypto.hash.sha2.Sha512,
        .pss,
        "rsa_pss_rsae_sha512",
        fixtures.wycheproof_rsa_pss_4096_sha512,
        179,
        0,
    );
}
