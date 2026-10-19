//! Smoke executable: proves the tls-std + tls wiring builds and runs under
//! Zig 0.16.
const std = @import("std");
const Io = std.Io;

const tls_std = @import("tls_std");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout_writer = &stdout_file_writer.interface;

    try stdout_writer.print("tls-std OK (tls core wired, API implemented)\n", .{});
    try stdout_writer.flush();
    _ = tls_std;
}

test "smoke: tls_std import resolves" {
    _ = tls_std;
}
