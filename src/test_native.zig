//! Native backend test roots supported in #199. No handshake claim is made.
test {
    _ = @import("aead.zig");
    _ = @import("certificate.zig");
    _ = @import("crypto/backend.zig");
    _ = @import("crypto/backend_native.zig");
    _ = @import("crypto/backend_primitive_tests.zig");
    _ = @import("hkdf.zig");
    _ = @import("hmac.zig");
    _ = @import("p256.zig");
    _ = @import("p384.zig");
    _ = @import("x25519.zig");
}
