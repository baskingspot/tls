//! The passthrough-argument hook Zig 0.17's build runner provides.

const std = @import("std");

pub fn passthruArgs(run: *std.Build.Step.Run) void {
    run.addPassthruArgs();
}
