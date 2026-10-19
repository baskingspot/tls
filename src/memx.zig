//! TLS wire-format integer helpers.
//!
//! TLS is entirely big-endian, so these drop the endian argument that
//! `std.mem.readInt` and `std.mem.writeInt` require. Generic containers and
//! memory scans live in `stdx`, not here.

const std = @import("std");
const testing = std.testing;

pub inline fn readInt(comptime T: type, buf: *const [@divExact(@bitSizeOf(T), 8)]u8) T {
    return std.mem.readInt(T, buf, .big);
}

pub inline fn writeInt(comptime T: type, buf: *[@divExact(@bitSizeOf(T), 8)]u8, value: T) void {
    std.mem.writeInt(T, buf, value, .big);
}

pub inline fn toBytes(comptime T: type, value: T) [@sizeOf(T)]u8 {
    return std.mem.toBytes(std.mem.nativeTo(T, value, .big));
}

// RFC 8446 Appendix B — every multi-byte integer on the wire is big-endian.
test "readInt and writeInt round-trip big-endian" {
    var buf: [4]u8 = undefined;
    writeInt(u32, &buf, 0x01020304);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, &buf);
    try testing.expectEqual(@as(u32, 0x01020304), readInt(u32, &buf));

    var wide: [8]u8 = undefined;
    writeInt(u64, &wide, 0x0102030405060708);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &wide);
    try testing.expectEqual(@as(u64, 0x0102030405060708), readInt(u64, &wide));
}

test "toBytes writes big-endian" {
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, &toBytes(u16, 0x0102));
}
