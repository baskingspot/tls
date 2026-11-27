//! Product HMAC and HKDF differentials against the provider's SHA-2.
const std = @import("std");
const testing = std.testing;
const backend = @import("crypto");
const backend_native = struct {
    const sha2 = std.crypto.hash.sha2;
};
const hmac = @import("../hmac.zig");
const Hkdf = @import("../hkdf.zig").Hkdf;

fn sha2Input(buf: []u8, seed: u64) []u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    prng.random().bytes(buf);
    return buf;
}

// FIPS 180-4 §6.2/§6.5, RFC 2104 §2, RFC 5869 §2, and RFC 8446 §7.1 —
// product HMAC and the TLS key schedule agree across native and libcrypto
// hashes. This compares the product types in hmac.zig and hkdf.zig, not a
// libcrypto HMAC or HKDF entry point.
test "backend.native differential: product HMAC and HKDF match across backends" {
    if (comptime backend.active != .native) return error.SkipZigTest;
    var buf: [300]u8 = undefined;
    const input = sha2Input(&buf, 0x199138);
    inline for (.{
        .{ std.crypto.hash.sha2.Sha256, backend.sha2.Sha256 },
        .{ std.crypto.hash.sha2.Sha384, backend.sha2.Sha384 },
    }) |pair| {
        const NativeHash, const LinkedHash = pair;
        const NativeHmac = hmac.Hmac(NativeHash);
        const LinkedHmac = hmac.Hmac(LinkedHash);
        for ([_]usize{ 0, 1, NativeHash.block_length, 300 }) |key_len| {
            const key = input[0..key_len];
            const msg = input[key_len / 2 ..];
            var native_digest: [NativeHash.digest_length]u8 = undefined;
            var linked_digest: [LinkedHash.digest_length]u8 = undefined;
            NativeHash.hash(msg, &native_digest, .{});
            LinkedHash.hash(msg, &linked_digest, .{});
            try testing.expectEqualSlices(u8, &linked_digest, &native_digest);

            var native_mac: [NativeHmac.mac_length]u8 = undefined;
            var linked_mac: [LinkedHmac.mac_length]u8 = undefined;
            NativeHmac.create(&native_mac, msg, key);
            LinkedHmac.create(&linked_mac, msg, key);
            try testing.expectEqualSlices(u8, &linked_mac, &native_mac);

            const NativeHkdf = Hkdf(NativeHash, NativeHash);
            const LinkedHkdf = Hkdf(LinkedHash, NativeHash);
            const native_prk = NativeHkdf.extract(key, msg);
            const linked_prk = LinkedHkdf.extract(key, msg);
            try testing.expectEqualSlices(u8, &linked_prk.data, &native_prk.data);
            var native_okm: [2 * NativeHash.digest_length + 7]u8 = undefined;
            var linked_okm: [2 * LinkedHash.digest_length + 7]u8 = undefined;
            NativeHkdf.expandLabel(&native_okm, "native differential", "", native_prk);
            LinkedHkdf.expandLabel(&linked_okm, "native differential", "", linked_prk);
            try testing.expectEqualSlices(u8, &linked_okm, &native_okm);
        }
    }
}
