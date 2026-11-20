//! Public compile-time capability discovery for the selected crypto backend.
const std = @import("std");
const compat = @import("compat.zig");
const testing = std.testing;

const backend = @import("crypto/backend.zig");
const CipherSuite = @import("cipher_suite.zig").CipherSuite;
const kex = @import("kex.zig");
const NamedGroup = kex.NamedGroup;

pub const Backend = backend.Backend;

pub const Role = enum { client, server };

/// Backend identity inferred from the selected libcrypto headers and FIPS policy.
pub const active_backend: Backend = backend.active;

/// True for a compile-time approved-algorithm capability identity.
pub const approved_only: bool = backend.approved_only;

/// TLS 1.3 cipher suites this build advertises. An approved-only build
/// advertises AES-GCM only.
pub const cipher_suites = backend.capabilities.cipher_suites;

/// RFC 10024 groups that tls implements. Backend support remains selectable.
pub const hybrid_groups = [_]NamedGroup{
    .x25519_mlkem768,
    .secp256r1_mlkem768,
    .secp384r1_mlkem1024,
};

pub const HybridPolicyError = error{
    /// The group list or initial-share relation is malformed.
    InvalidHybridPolicy,
    /// The selected backend identity prohibits a known hybrid group.
    HybridGroupUnavailable,
};

/// Report whether this build advertises `suite`.
pub fn supportsCipherSuite(suite: CipherSuite) bool {
    for (cipher_suites) |advertised| {
        if (advertised == suite) return true;
    }
    return false;
}

/// Report whether one role can use a classical group with the active backend.
/// An approved-only build answers false for X25519.
pub fn supportsGroup(role: Role, group: NamedGroup) bool {
    return switch (group) {
        .x25519 => switch (role) {
            .client => backend.capabilities.client_x25519,
            .server => backend.capabilities.server_x25519,
        },
        .secp256r1 => switch (role) {
            .client => backend.capabilities.client_p256,
            .server => backend.capabilities.server_p256,
        },
        .secp384r1 => switch (role) {
            .client => backend.capabilities.client_p384,
            .server => backend.capabilities.server_p384,
        },
        else => supportsHybridGroup(role, group),
    };
}

/// Report whether one role can use an RFC 10024 group with the active backend.
pub fn supportsHybridGroup(role: Role, group: NamedGroup) bool {
    return switch (role) {
        .client => backend.supportsClientHybridGroup(group),
        .server => backend.supportsServerHybridGroup(group),
    };
}

/// Validate a borrowed RFC 10024 group list before key generation or wire I/O.
pub fn validateHybridGroups(
    role: Role,
    groups: []const NamedGroup,
) HybridPolicyError!void {
    if (groups.len > hybrid_groups.len) return error.InvalidHybridPolicy;
    for (groups, 0..) |group, i| {
        if (group.hybridSpec() == null) return error.InvalidHybridPolicy;
        for (groups[0..i]) |earlier| {
            if (earlier == group) return error.InvalidHybridPolicy;
        }
    }
    for (groups) |group| {
        if (!supportsHybridGroup(role, group)) return error.HybridGroupUnavailable;
    }
}

/// RFC 10024 hybrid negotiation policy for one handshake role.
pub const HybridPolicy = struct {
    /// Hybrid groups advertised in supported_groups. Caller-owned; the slice
    /// must outlive the handshake because HRR reuses it verbatim.
    supported_groups: []const NamedGroup,
    /// Optional hybrid key_share sent in ClientHello1. It must also appear in
    /// supported_groups. null advertises support without an initial share,
    /// allowing a server to select the group through HelloRetryRequest.
    initial_key_share: ?NamedGroup,

    /// Hybrid negotiation disabled: no advertised groups and no initial share.
    pub const empty: HybridPolicy = .{ .supported_groups = &.{}, .initial_key_share = null };

    /// Validate the compiled support, group list, and initial-share relation.
    pub fn validate(self: HybridPolicy) HybridPolicyError!void {
        if (self.initial_key_share) |group| {
            if (std.mem.findScalar(NamedGroup, self.supported_groups, group) == null)
                return error.InvalidHybridPolicy;
        }
        try validateHybridGroups(.client, self.supported_groups);
    }

    /// Report whether this policy requires a P-384 keypair.
    pub fn requiresP384(self: HybridPolicy) bool {
        for (self.supported_groups) |group| {
            const spec = group.hybridSpec() orelse continue;
            if (spec.classical_group == .secp384r1) return true;
        }
        return false;
    }
};

/// Report whether a group list requires a P-384 keypair.
pub fn requiresP384(groups: []const NamedGroup) bool {
    const policy: HybridPolicy = .{ .supported_groups = groups, .initial_key_share = null };
    return policy.requiresP384();
}

test "active backend identity matches the private provider facade" {
    try testing.expectEqualStrings(@tagName(backend.active), @tagName(active_backend));
    try testing.expectEqual(backend.approved_only, approved_only);
}

// RFC 10024 §7 — public capability queries cover exactly the implemented groups.
test "hybrid capability queries match the active backend" {
    for (hybrid_groups) |group| {
        try testing.expectEqual(
            backend.supportsClientHybridGroup(group),
            supportsHybridGroup(.client, group),
        );
        try testing.expectEqual(
            backend.supportsServerHybridGroup(group),
            supportsHybridGroup(.server, group),
        );
    }
    try testing.expect(!supportsHybridGroup(.client, .x25519));
    try testing.expect(!supportsHybridGroup(.server, .secp256r1));
    const unknown: NamedGroup = compat.enumFromInt(NamedGroup, 0xdead);
    try testing.expect(!supportsHybridGroup(.client, unknown));
    try testing.expect(!supportsHybridGroup(.server, unknown));

    for (hybrid_groups) |group| {
        if (approved_only or
            (backend.native_selected and group == .secp384r1_mlkem1024))
        {
            try testing.expect(!supportsHybridGroup(.client, group));
            try testing.expect(!supportsHybridGroup(.server, group));
        } else {
            try testing.expect(supportsHybridGroup(.client, group));
            try testing.expect(supportsHybridGroup(.server, group));
        }
    }
}

// RFC 10024 §7 — policy validation rejects non-hybrid, duplicate, and oversized lists.
test "validateHybridGroups reports local policy faults" {
    try testing.expectError(
        error.InvalidHybridPolicy,
        validateHybridGroups(.client, &.{
            .x25519_mlkem768,
            .secp256r1_mlkem768,
            .secp384r1_mlkem1024,
            .x25519_mlkem768,
        }),
    );
    try testing.expectError(
        error.InvalidHybridPolicy,
        validateHybridGroups(.client, &.{.x25519}),
    );
    try testing.expectError(
        error.InvalidHybridPolicy,
        validateHybridGroups(.client, &.{
            .x25519_mlkem768,
            .x25519_mlkem768,
        }),
    );
    if (!supportsHybridGroup(.client, .x25519_mlkem768)) {
        try testing.expectError(
            error.HybridGroupUnavailable,
            validateHybridGroups(.client, &.{.x25519_mlkem768}),
        );
    }
}

test "requiresP384 identifies only P-384 hybrid policy" {
    try testing.expect(!requiresP384(&.{}));
    try testing.expect(!requiresP384(&.{.x25519_mlkem768}));
    try testing.expect(!requiresP384(&.{.secp256r1_mlkem768}));
    try testing.expect(requiresP384(&.{.secp384r1_mlkem1024}));
}
