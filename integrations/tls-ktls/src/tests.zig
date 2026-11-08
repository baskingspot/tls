const std = @import("std");
const compat = @import("compat.zig");
const testing = std.testing;
const tls = @import("tls");
const ktls = @import("root.zig");

// RFC 8446 §4.6.3 — both roles expose the same KeyUpdate request vocabulary.
test "client and server connection types share the core KeyUpdate enum" {
    try testing.expectEqual(
        compat.enumToInt(tls.ClientHandshake.KeyUpdateRequest.update_requested),
        compat.enumToInt(ktls.KeyUpdateRequest.update_requested),
    );
    try testing.expect(@sizeOf(ktls.Client) > 0);
    try testing.expect(@sizeOf(ktls.Server) > 0);
}
