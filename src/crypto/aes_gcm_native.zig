//! AES-GCM over Zig's std primitives, with the software-AES batch padded.
//!
//! std.crypto's protected software AES reads a full bitsliced batch even when
//! its AEAD caller requests one block (aes/soft.zig bitslicedOperation). The
//! unused input blocks are undefined. Encrypting a zero-filled full batch here
//! preserves the requested block's output without reading undefined memory.
//! The GCM composition follows std.crypto's aes_gcm.zig.
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const assert = std.debug.assert;

pub const Aes128Gcm = AesGcm(PaddedAes(crypto.core.aes.Aes128));
pub const Aes256Gcm = AesGcm(PaddedAes(crypto.core.aes.Aes256));

fn PaddedAes(comptime Aes: type) type {
    const Base = crypto.core.aes;

    return struct {
        const Self = @This();

        pub const key_bits = Aes.key_bits;
        pub const block = Aes.block;
        pub const block_length = Aes.block.block_length;

        inner: Base.AesEncryptCtx(Aes),

        fn initEnc(key: [key_bits / 8]u8) Self {
            return .{ .inner = Aes.initEnc(key) };
        }

        pub fn encrypt(
            self: Self,
            out: *[block_length]u8,
            input: *const [block_length]u8,
        ) void {
            if (Base.has_hardware_support) return self.inner.encrypt(out, input);

            const count = block.parallel.optimal_parallel_blocks;
            var source: [count * block_length]u8 = @splat(0);
            source[0..block_length].* = input.*;
            var encrypted: [count * block_length]u8 = undefined;
            self.inner.encryptWide(count, &encrypted, &source);
            out.* = encrypted[0..block_length].*;
        }

        pub fn encryptWide(
            self: Self,
            comptime count: usize,
            out: *[count * block_length]u8,
            input: *const [count * block_length]u8,
        ) void {
            self.inner.encryptWide(count, out, input);
        }

        pub fn xorWide(
            self: Self,
            comptime count: usize,
            out: *[count * block_length]u8,
            input: *const [count * block_length]u8,
            counters: [count * block_length]u8,
        ) void {
            self.inner.xorWide(count, out, input, counters);
        }
    };
}

fn AesGcm(comptime Aes: anytype) type {
    assert(Aes.block.block_length == 16);

    return struct {
        pub const tag_length = 16;
        pub const nonce_length = 12;
        pub const key_length = Aes.key_bits / 8;

        const AuthenticationError = crypto.errors.AuthenticationError;

        pub fn encrypt(
            ciphertext: []u8,
            tag: *[tag_length]u8,
            plaintext: []const u8,
            ad: []const u8,
            npub: [nonce_length]u8,
            key: [key_length]u8,
        ) void {
            assert(ciphertext.len == plaintext.len);
            assert(plaintext.len <= 16 * ((1 << 32) - 2));

            const aes = Aes.initEnc(key);
            var h: [16]u8 = undefined;
            aes.encrypt(&h, &@splat(0));

            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            j[0..nonce_length].* = npub;
            mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
            aes.encrypt(&t, &j);

            const block_count = @divCeil(ad.len, Ghash.block_length) +
                @divCeil(ciphertext.len, Ghash.block_length) + 1;
            var mac = Ghash.initForBlockCount(&h, block_count);
            mac.update(ad);
            mac.pad();

            mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
            modes.ctr(@TypeOf(aes), aes, ciphertext, plaintext, j, .big);
            mac.update(ciphertext);
            mac.pad();

            var final_block = h;
            mem.writeInt(u64, final_block[0..8], @as(u64, ad.len) * 8, .big);
            mem.writeInt(u64, final_block[8..16], @as(u64, plaintext.len) * 8, .big);
            mac.update(&final_block);
            mac.final(tag);
            for (t, 0..) |x, i| tag[i] ^= x;
        }

        pub fn decrypt(
            plaintext: []u8,
            ciphertext: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            npub: [nonce_length]u8,
            key: [key_length]u8,
        ) AuthenticationError!void {
            assert(plaintext.len == ciphertext.len);

            const aes = Aes.initEnc(key);
            var h: [16]u8 = undefined;
            aes.encrypt(&h, &@splat(0));

            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            j[0..nonce_length].* = npub;
            mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
            aes.encrypt(&t, &j);

            const block_count = @divCeil(ad.len, Ghash.block_length) +
                @divCeil(ciphertext.len, Ghash.block_length) + 1;
            var mac = Ghash.initForBlockCount(&h, block_count);
            mac.update(ad);
            mac.pad();
            mac.update(ciphertext);
            mac.pad();

            var final_block = h;
            mem.writeInt(u64, final_block[0..8], @as(u64, ad.len) * 8, .big);
            mem.writeInt(u64, final_block[8..16], @as(u64, ciphertext.len) * 8, .big);
            mac.update(&final_block);
            var computed_tag: [Ghash.mac_length]u8 = undefined;
            mac.final(&computed_tag);
            for (t, 0..) |x, i| computed_tag[i] ^= x;

            const valid = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
            if (!valid) {
                crypto.secureZero(u8, &computed_tag);
                crypto.secureZero(u8, plaintext);
                return error.AuthenticationFailed;
            }

            mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
            modes.ctr(@TypeOf(aes), aes, plaintext, ciphertext, j, .big);
        }
    };
}

const Ghash = crypto.onetimeauth.Ghash;
const modes = crypto.core.modes;
