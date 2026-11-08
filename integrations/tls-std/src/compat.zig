//! Shims for the Zig 0.16 and 0.17 APIs. Private to the module.

/// Zig 0.17's `zig fmt` rewrites `@intFromEnum` to `@backingInt`, which Zig
/// 0.16 cannot compile. Keep it out of the formatter's reach.
// zig fmt: off
pub fn enumToInt(e: anytype) @typeInfo(@TypeOf(e)).@"enum".tag_type {
    return @intFromEnum(e);
}
// zig fmt: on
