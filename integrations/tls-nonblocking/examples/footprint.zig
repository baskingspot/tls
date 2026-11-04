//! Connection-slot storage, excluding shared credentials and backend allocations.
const std = @import("std");
const transport = @import("tls_nonblocking");
const tls = transport.core;

const Slot = struct {
    server: transport.Server,
    record: [tls.RecordBuffer.min_storage]u8,
    out: [tls.frame.max_wire_record_len]u8,
    reassembly: [tls.ServerHandshake.ch_reassembly_buffer_size]u8,
};

pub fn main() void {
    std.debug.print(
        \\Server: {d} bytes
        \\RX record storage: {d} bytes
        \\TX record storage: {d} bytes
        \\ClientHello reassembly: {d} bytes
        \\Slot including alignment: {d} bytes
        \\Excludes credentials, optional client-certificate storage, and backend allocations.
        \\
    , .{
        @sizeOf(transport.Server),
        tls.RecordBuffer.min_storage,
        tls.frame.max_wire_record_len,
        tls.ServerHandshake.ch_reassembly_buffer_size,
        @sizeOf(Slot),
    });
}
