//! Shims for the Zig 0.16 and 0.17 APIs. Private to the module.
//!
//! The tree builds on both compilers from one source. Every entry here exists
//! because a shape cannot be written once for both, and each one probes the
//! API rather than the version number.

const std = @import("std");

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

/// Zig 0.17 split `Enum.fields` into parallel `field_names` and `field_values`.
pub fn enumFieldCount(comptime E: type) usize {
    const info = @typeInfo(E).@"enum";
    if (comptime @hasField(@TypeOf(info), "field_values")) return info.field_names.len;
    return info.fields.len;
}

pub fn enumFieldName(comptime E: type, comptime i: usize) [:0]const u8 {
    const info = @typeInfo(E).@"enum";
    if (comptime @hasField(@TypeOf(info), "field_names")) return info.field_names[i];
    return info.fields[i].name;
}

pub fn enumField(comptime E: type, comptime i: usize) E {
    const info = @typeInfo(E).@"enum";
    if (comptime @hasField(@TypeOf(info), "field_values"))
        return enumFromInt(E, info.field_values[i]);
    return enumFromInt(E, info.fields[i].value);
}

/// Zig 0.17 changed `@typeInfo(E).error_set` from a list of `Error` structs
/// to a struct carrying the names. Returns the names of a closed set, with the
/// empty slice for an inferred one.
pub fn ErrorNames(comptime E: type) type {
    const set = @typeInfo(E).error_set;
    if (comptime @typeInfo(@TypeOf(set)) == .optional) {
        const list = set orelse return [0][:0]const u8;
        return [list.len][:0]const u8;
    } else {
        const names = set.error_names orelse return [0][:0]const u8;
        return [names.len][:0]const u8;
    }
}

pub fn errorNames(comptime E: type) ErrorNames(E) {
    const set = @typeInfo(E).error_set;
    var names: ErrorNames(E) = undefined;
    if (comptime @typeInfo(@TypeOf(set)) == .optional) {
        const list = set orelse return undefined;
        for (list, 0..) |member, i| names[i] = member.name;
    } else {
        for (set.error_names orelse return undefined, 0..) |name, i| names[i] = name;
    }
    return names;
}

/// Zig 0.17 makes `@hasDecl` see only public declarations. This looks at the
/// container's declaration names, so a private helper still probes true.
pub fn hasDecl(comptime T: type, comptime name: []const u8) bool {
    if (@hasDecl(T, name)) return true;
    const info = @typeInfo(T).@"struct";
    if (comptime @hasField(@TypeOf(info), "decl_names")) {
        for (info.decl_names) |decl| if (std.mem.eql(u8, decl, name)) return true;
    }
    return false;
}

/// Zig 0.17 renamed `Fn.params` to `param_types`.
pub fn fnParamCount(comptime F: type) usize {
    const info = @typeInfo(F).@"fn";
    if (comptime @hasField(@TypeOf(info), "param_types")) return info.param_types.len;
    return info.params.len;
}

pub fn fnParamType(comptime F: type, comptime i: usize) ?type {
    const info = @typeInfo(F).@"fn";
    if (comptime @hasField(@TypeOf(info), "param_types")) return info.param_types[i];
    return info.params[i].type;
}

/// Zig 0.17 changed `std.meta.declarations` from a list of name/type structs
/// to a list of names. These two normalize it.
pub fn declCount(comptime T: type) usize {
    return std.meta.declarations(T).len;
}

pub fn declName(comptime T: type, comptime i: usize) [:0]const u8 {
    const decls = std.meta.declarations(T);
    const Elem = @typeInfo(@TypeOf(decls)).pointer.child;
    if (comptime Elem == [:0]const u8) return decls[i];
    return decls[i].name;
}

/// Zig 0.17 moved a pointer's `is_const` into `attrs`. Probe the shape.
pub fn pointerIsConst(comptime ptr: anytype) bool {
    if (comptime @hasField(@TypeOf(ptr), "attrs")) return ptr.attrs.@"const";
    return ptr.is_const;
}

/// Zig 0.17 removed the `**` array-repeat operator. This replaces
/// `s ** n` for string literals; an element repeat writes
/// `@as([n]u8, @splat(v))`, which both compilers accept.
pub fn repeatString(comptime s: []const u8, comptime n: usize) [s.len * n:0]u8 {
    var out: [s.len * n:0]u8 = undefined;
    for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
    out[s.len * n] = 0;
    return out;
}
