//! ECDSA signing over Zig's curve arithmetic, with RFC 6979 nonces.
//!
//! The supported TLS schemes have qlen == hlen: P-256/SHA-256 and
//! P-384/SHA-384. `random` adds fresh OS entropy as RFC 6979 §3.6 additional
//! data. `deterministic` omits it and produces the RFC's published answers.
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const entropy = @import("../entropy.zig");

pub const NonceMode = enum {
    random,
    deterministic,
};

pub const Error = error{ BufferTooShort, InvalidPrivateKey };

pub fn Ecdsa(comptime Curve: type, comptime Hash: type) type {
    comptime assert(Hash.digest_length == Curve.scalar.encoded_length);

    return struct {
        const Scheme = std.crypto.sign.ecdsa.Ecdsa(Curve, Hash);
        const Scalar = Curve.scalar.Scalar;
        const Prf = std.crypto.auth.hmac.Hmac(Hash);
        const scalar_length = Curve.scalar.encoded_length;
        const der_length_max = Scheme.Signature.der_encoded_length_max;

        fn wipe(value: anytype) void {
            std.crypto.secureZero(u8, std.mem.asBytes(value));
        }

        fn mac(out: *[Hash.digest_length]u8, key: []const u8, parts: anytype) void {
            var h: Prf = .init(key);
            defer wipe(&h);
            inline for (parts) |part| h.update(part);
            h.final(out);
        }

        /// RFC 6979 §3.2 HMAC_DRBG state. The seed carries the optional §3.6
        /// additional data after bits2octets(H(m)); no added data is the exact
        /// deterministic construction. K, V, and candidates are secret.
        const NonceGenerator = struct {
            k: [Hash.digest_length]u8,
            v: [Hash.digest_length]u8,

            fn init(
                secret_key: *const [scalar_length]u8,
                reduced_hash: *const [scalar_length]u8,
                noise: ?*const [scalar_length]u8,
            ) NonceGenerator {
                var self: NonceGenerator = .{
                    .k = @splat(0),
                    .v = @splat(1),
                };
                self.rekey(0, secret_key, reduced_hash, noise);
                self.rekey(1, secret_key, reduced_hash, noise);
                return self;
            }

            fn rekey(
                self: *NonceGenerator,
                separator: u8,
                secret_key: *const [scalar_length]u8,
                reduced_hash: *const [scalar_length]u8,
                noise: ?*const [scalar_length]u8,
            ) void {
                const additional: []const u8 = if (noise) |n| n else "";
                mac(&self.k, &self.k, .{
                    &self.v,
                    &[_]u8{separator},
                    secret_key,
                    reduced_hash,
                    additional,
                });
                mac(&self.v, &self.k, .{&self.v});
            }

            fn reject(self: *NonceGenerator) void {
                mac(&self.k, &self.k, .{ &self.v, &[_]u8{0} });
                mac(&self.v, &self.k, .{&self.v});
            }

            /// Reject zero and non-canonical candidates instead of reducing
            /// them, per RFC 6979 §3.2 step h.3.
            fn next(self: *NonceGenerator) Scalar {
                while (true) {
                    mac(&self.v, &self.k, .{&self.v});
                    const candidate = Scalar.fromBytes(self.v, .big) catch {
                        self.reject();
                        continue;
                    };
                    if (candidate.isZero()) {
                        self.reject();
                        continue;
                    }
                    return candidate;
                }
            }
        };

        /// RFC 6979 §2.3.2/§2.3.4 — for these schemes the hash and scalar
        /// widths match, so reduction is the only bits2int/bits2octets step.
        fn reduce(bytes: [scalar_length]u8) Scalar {
            if (scalar_length >= 48) {
                var wide: [64]u8 = @splat(0);
                @memcpy(wide[wide.len - bytes.len ..], &bytes);
                return Scalar.fromBytes64(wide, .big);
            }
            var wide: [48]u8 = @splat(0);
            @memcpy(wide[wide.len - bytes.len ..], &bytes);
            return Scalar.fromBytes48(wide, .big);
        }

        /// Sign with a private scalar in [1, q-1]. DER goes directly into
        /// the caller's buffer when it can hold the largest encoding. A short
        /// buffer needs a bounded temporary because `Signature.toDer` takes a
        /// fixed-size array and the actual DER length depends on INTEGER pads.
        pub fn sign(
            secret_key: *const [scalar_length]u8,
            msg: []const u8,
            out: []u8,
            nonce_mode: NonceMode,
        ) Error![]const u8 {
            // RFC 6979 §2.2 — x is non-zero and below the group order.
            var x = Scalar.fromBytes(secret_key.*, .big) catch
                return error.InvalidPrivateKey;
            defer wipe(&x);
            if (x.isZero()) return error.InvalidPrivateKey;

            var digest: [Hash.digest_length]u8 = undefined;
            Hash.hash(msg, &digest, .{});
            const h = reduce(digest);
            const reduced_hash = h.toBytes(.big);

            var noise: [scalar_length]u8 = @splat(0);
            defer wipe(&noise);
            const noise_arg: ?*const [scalar_length]u8 = switch (nonce_mode) {
                .deterministic => null,
                .random => blk: {
                    entropy.fill(&noise);
                    break :blk &noise;
                },
            };

            var generator: NonceGenerator = .init(secret_key, &reduced_hash, noise_arg);
            defer wipe(&generator);
            while (true) {
                var k = generator.next();
                defer wipe(&k);
                const p = Curve.basePoint.mul(k.toBytes(.big), .big) catch unreachable;
                const xs = p.affineCoordinates().x.toBytes(.big);
                const r = reduce(xs);
                if (r.isZero()) {
                    generator.reject();
                    continue;
                }
                var k_inv = k.invert();
                defer wipe(&k_inv);
                var zrs = h.add(r.mul(x));
                defer wipe(&zrs);
                const s = k_inv.mul(zrs);
                if (s.isZero()) {
                    generator.reject();
                    continue;
                }
                const signature: Scheme.Signature = .{
                    .r = r.toBytes(.big),
                    .s = s.toBytes(.big),
                };
                return writeDer(signature, out);
            }
        }

        fn writeDer(signature: Scheme.Signature, out: []u8) Error![]const u8 {
            if (out.len >= der_length_max) {
                const buffer: *[der_length_max]u8 = @ptrCast(out.ptr);
                return signature.toDer(buffer);
            }
            var buffer: [der_length_max]u8 = undefined;
            const der = signature.toDer(&buffer);
            if (out.len < der.len) return error.BufferTooShort;
            @memcpy(out[0..der.len], der);
            return out[0..der.len];
        }
    };
}

// RFC 6979 §2.2 — the private scalar must be in [1, q-1].
test "ECDSA rejects zero and non-canonical private scalars" {
    const P256 = Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha256);
    var out: [72]u8 = undefined;
    const zero: [32]u8 = @splat(0);
    try testing.expectError(
        error.InvalidPrivateKey,
        P256.sign(&zero, "sample", &out, .deterministic),
    );
    const too_large: [32]u8 = @splat(0xff);
    try testing.expectError(
        error.InvalidPrivateKey,
        P256.sign(&too_large, "sample", &out, .deterministic),
    );
}
