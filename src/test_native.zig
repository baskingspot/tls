//! Native primitive tests. Examples and conformance own the handshake evidence.
test {
    _ = @import("aead.zig");
    _ = @import("certificate.zig");
    _ = @import("capabilities.zig");
    _ = @import("crypto/backend.zig");
    _ = @import("crypto/backend_native.zig");
    _ = @import("crypto/backend_primitive_tests.zig");
    _ = @import("hkdf.zig");
    _ = @import("hmac.zig");
    _ = @import("hybrid_kex.zig");
    _ = @import("mlkem.zig");
    _ = @import("p256.zig");
    _ = @import("p384.zig");
    _ = @import("rsa_wycheproof.zig");
    _ = @import("x25519.zig");
}
