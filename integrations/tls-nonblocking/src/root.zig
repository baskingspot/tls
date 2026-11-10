//! Caller-driven TLS 1.3 transports over caller-owned byte buffers.
//! The caller owns sockets, readiness, deadlines, and connection lifetime.
pub const core = @import("tls");
pub const anchors = @import("anchors.zig");
pub const Client = @import("Client.zig");
pub const Server = @import("Server.zig");
pub const SocketClient = @import("SocketClient.zig");

test {
    _ = SocketClient;
}
