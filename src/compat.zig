//! Adapters for the Zig 0.17 API shapes. Private to the module.

const std = @import("std");

/// Zig 0.17 spells these `@backingInt` and `@fromBackingInt`.
pub fn enumToInt(e: anytype) @typeInfo(@TypeOf(e)).@"enum".tag_type {
    return @backingInt(e);
}

pub fn enumFromInt(comptime E: type, raw: anytype) E {
    const tag = @typeInfo(E).@"enum".tag_type;
    return @fromBackingInt(@as(tag, @intCast(raw)));
}

/// `Enum.fields` is split into parallel `field_names` and `field_values`.
pub fn enumFieldCount(comptime E: type) usize {
    return @typeInfo(E).@"enum".field_names.len;
}

pub fn enumFieldName(comptime E: type, comptime i: usize) [:0]const u8 {
    return @typeInfo(E).@"enum".field_names[i];
}

pub fn enumField(comptime E: type, comptime i: usize) E {
    return @fromBackingInt(@typeInfo(E).@"enum".field_values[i]);
}

/// An inferred error set has no names.
pub fn ErrorNames(comptime E: type) type {
    const names = @typeInfo(E).error_set.error_names orelse return [0][:0]const u8;
    return [names.len][:0]const u8;
}

pub fn errorNames(comptime E: type) ErrorNames(E) {
    const names = @typeInfo(E).error_set.error_names orelse return undefined;
    var out: ErrorNames(E) = undefined;
    for (names, 0..) |name, i| out[i] = name;
    return out;
}

/// Zig 0.17's `@hasDecl` sees only public declarations. This looks at the
/// container's declaration names, so a private helper still probes true.
pub fn hasDecl(comptime T: type, comptime name: []const u8) bool {
    if (@hasDecl(T, name)) return true;
    const info = @typeInfo(T).@"struct";
    for (info.decl_names) |decl| if (std.mem.eql(u8, decl, name)) return true;
    return false;
}

/// Zig 0.17 renames `Fn.params` to `param_types`.
pub fn fnParamCount(comptime F: type) usize {
    return @typeInfo(F).@"fn".param_types.len;
}

pub fn fnParamType(comptime F: type, comptime i: usize) ?type {
    return @typeInfo(F).@"fn".param_types[i];
}

/// `std.meta.declarations` returns names in Zig 0.17.
pub fn declCount(comptime T: type) usize {
    return std.meta.declarations(T).len;
}

pub fn declName(comptime T: type, comptime i: usize) [:0]const u8 {
    return std.meta.declarations(T)[i];
}

/// A pointer's constness lives in `attrs` in Zig 0.17.
pub fn pointerIsConst(comptime ptr: anytype) bool {
    return ptr.attrs.@"const";
}

/// `s ** n` is gone. This repeats a string literal.
pub fn repeatString(comptime s: []const u8, comptime n: usize) [s.len * n:0]u8 {
    var out: [s.len * n:0]u8 = undefined;
    for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
    out[s.len * n] = 0;
    return out;
}
