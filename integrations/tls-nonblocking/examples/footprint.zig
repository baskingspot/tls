//! Connection-slot storage, excluding shared credentials and backend allocations.
const std = @import("std");
const transport = @import("tls_nonblocking");
const tls = transport.core;

const ServerSlot = struct {
    server: transport.Server,
    record: [tls.RecordBuffer.min_storage]u8,
    out: [tls.frame.max_wire_record_len]u8,
    reassembly: [tls.ServerHandshake.ch_reassembly_buffer_size]u8,
};

const ClientSlot = struct {
    client: transport.Client,
    record: [tls.RecordBuffer.min_storage]u8,
    out: [tls.frame.max_wire_record_len]u8,
    reassembly: [tls.ClientHandshake.recommended_handshake_storage]u8,
};

pub fn main() void {
    std.debug.print(
        \\Server: {d} bytes
        \\Server RX record storage: {d} bytes
        \\Server TX record storage: {d} bytes
        \\ClientHello reassembly: {d} bytes
        \\Server slot including alignment: {d} bytes
        \\Client: {d} bytes
        \\Client RX record storage: {d} bytes
        \\Client TX record storage: {d} bytes
        \\Client handshake reassembly: {d} bytes
        \\Client slot including alignment: {d} bytes
        \\SocketClient including its buffers and reassembly: {d} bytes
        \\Excludes credentials, anchors, client-cert storage, and backend allocations.
        \\
    , .{
        @sizeOf(transport.Server),
        tls.RecordBuffer.min_storage,
        tls.frame.max_wire_record_len,
        tls.ServerHandshake.ch_reassembly_buffer_size,
        @sizeOf(ServerSlot),
        @sizeOf(transport.Client),
        tls.RecordBuffer.min_storage,
        tls.frame.max_wire_record_len,
        tls.ClientHandshake.recommended_handshake_storage,
        @sizeOf(ClientSlot),
        @sizeOf(transport.SocketClient),
    });
}
