//! Primitive identifiers accepted by the provider seam.

pub const AeadAlgorithm = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    pub fn keyLen(self: AeadAlgorithm) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }

    pub fn nonceLen(self: AeadAlgorithm) usize {
        _ = self;
        return 12;
    }

    pub fn tagLen(self: AeadAlgorithm) usize {
        _ = self;
        return 16;
    }
};

pub const aead_algorithms = [_]AeadAlgorithm{
    .aes_128_gcm,
    .aes_256_gcm,
    .chacha20_poly1305,
};

pub const CurveId = enum {
    x25519,
    p256,
    p384,
};

pub const SignatureAlgorithm = enum {
    ecdsa_p256_sha256,
    ecdsa_p384_sha384,
    ecdsa_p521_sha512,
    rsa_pss_sha256,
    rsa_pss_sha384,
    rsa_pss_sha512,
    ed25519,
};

comptime {
    const assert = @import("std").debug.assert;
    assert(AeadAlgorithm.aes_128_gcm.keyLen() == 16);
    assert(AeadAlgorithm.aes_256_gcm.keyLen() == 32);
    assert(AeadAlgorithm.chacha20_poly1305.keyLen() == 32);
    assert(AeadAlgorithm.aes_128_gcm.nonceLen() == 12);
    assert(AeadAlgorithm.aes_256_gcm.tagLen() == 16);
}
