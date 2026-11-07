const std = @import("std");
const compat = @import("compat.zig");
const builtin = @import("builtin");
const testing = std.testing;
const assert = std.debug.assert;
const tls = @import("root.zig");

pub fn hex(comptime len: usize, comptime encoded: []const u8) [len]u8 {
    // Catch length mismatches at compile time: hexToBytes would otherwise
    // silently zero-fill `out` when `encoded` is shorter than `2*len`,
    // corrupting vectors with trailing zeros (this bit a Wycheproof P-384
    // ECDSA signature during #60-A). Require an exact match.
    comptime assert(encoded.len == 2 * len);
    var out: [len]u8 = @splat(0);
    _ = std.fmt.hexToBytes(&out, encoded) catch unreachable;
    return out;
}

/// Force analysis of every declaration so an unused one still has to
/// compile. Zig 0.17 hides private declarations from reflection, so on 0.17
/// this reaches the public ones only.
fn refAllDeclsRecursive(comptime T: type) void {
    if (!builtin.is_test) return;
    const decl_count = comptime compat.declCount(T);
    inline for (0..decl_count) |i| {
        const name = comptime compat.declName(T, i);
        if (@TypeOf(@field(T, name)) == type) {
            switch (@typeInfo(@field(T, name))) {
                .@"struct",
                .@"enum",
                .@"union",
                .@"opaque",
                => refAllDeclsRecursive(@field(T, name)),
                else => {},
            }
        }
        _ = &@field(T, name);
    }
}

test {
    refAllDeclsRecursive(tls);
    _ = @import("wycheproof.zig");
    _ = @import("interop.zig");
    _ = @import("crypto/backend_primitive_tests.zig");
    _ = @import("certificate_name_constraints_differential_test.zig");
    _ = @import("capi.zig");
}
