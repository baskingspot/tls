const testingx = @import("testingx");

pub const micro_bench = @import("bench/micro_bench.zig");
pub const record_protection = @import("bench/record_protection.zig");

/// Suite root for `zig build bench`. `addMod` registers every top-level
/// `pub fn benchmark*(b: *B) !void` in the module it is given.
pub fn benchmarkMain(b: *testingx.B) !void {
    try b.addMod(micro_bench);
    try b.addMod(record_protection);
}
