//! Shims for the Zig 0.16 and 0.17 APIs. Private to the module.

/// Zig 0.17's `zig fmt` rewrites these to their `@backingInt` forms, which
/// Zig 0.16 cannot compile. Keep them out of the formatter's reach.
// zig fmt: off
pub fn enumToInt(e: anytype) @typeInfo(@TypeOf(e)).@"enum".tag_type {
    return @intFromEnum(e);
}
pub fn enumFromInt(comptime E: type, raw: anytype) E {
    return @enumFromInt(raw);
}
// zig fmt: on
