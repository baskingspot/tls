//! Independent TLS peer over real sockets. Only this test adapter owns I/O.
const std = @import("std");
const Io = std.Io;
const c = std.c;
const testing = std.testing;
const tls = @import("tls");
const Server = @import("tls_nonblocking").Server;
const fixtures = @import("fixtures");

const Context = struct {
    listener: Io.net.Server,
    failure: ?anyerror,

    fn run(self: *Context) void {
        self.exchange() catch |err| {
            self.failure = err;
        };
    }

    fn exchange(self: *Context) !void {
        const io = testing.io;
        try wait(self.listener.socket.handle, c.POLL.IN);
        const socket = try self.listener.accept(io);
        defer socket.close(io);
        var key: tls.signature.PrivateKey = try .fromP256Scalar(&fixtures.server_ecdsa_scalar);
        defer key.deinit();
        var record: [tls.RecordBuffer.min_storage]u8 = undefined;
        defer std.crypto.secureZero(u8, &record);
        var out: [tls.frame.max_wire_record_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &out);
        var reassembly: [tls.ServerHandshake.ch_reassembly_buffer_size]u8 = undefined;
        defer std.crypto.secureZero(u8, &reassembly);
        var server: Server = undefined;
        try server.init(&.{
            .handshake = .{ .alpn_protocols = &.{"h2"} },
            .cert_chain = &.{&fixtures.server_ecdsa_cert_der},
            .signer = key.signer(),
        }, .{
            .keypairs = try .init(.generate()),
            .random = .init(@splat(0x87)),
            .reassembly = &reassembly,
        }, .{ .record = &record, .out = &out });
        defer server.deinit();
        try echo(&server, socket.socket.handle);
    }
};

fn wait(fd: c.fd_t, events: i16) !void {
    var fds: [1]c.pollfd = .{.{ .fd = fd, .events = events, .revents = 0 }};
    while (true) {
        const rc = c.poll(&fds, 1, 5000);
        if (rc > 0) return;
        if (rc == 0) return error.PeerTimeout;
        if (c.errno(rc) != .INTR) return error.PollFailed;
    }
}

/// Per-call DONTWAIT works on Linux and macOS without a platform-specific loop.
fn echo(server: *Server, fd: c.fd_t) !void {
    const Phase = enum { request, response, closing };
    var phase: Phase = .request;
    const request = "ping";
    var request_pos: usize = 0;
    const started = Io.Timestamp.now(testing.io, .awake);
    for (0..10_000) |_| {
        if (started.durationTo(.now(testing.io, .awake)).toMilliseconds() > 5000)
            return error.PeerTimeout;
        switch (try server.next()) {
            .handshake_complete => try testing.expectEqualStrings("h2", server.selectedAlpn().?),
            .application_data => |bytes| {
                try testing.expect(bytes.len <= request.len - request_pos);
                try testing.expectEqualStrings(request[request_pos..][0..bytes.len], bytes);
                const n = server.write(bytes) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return err,
                };
                server.consumeApplication(n);
                request_pos += n;
                if (request_pos == request.len) phase = .response;
            },
            .progress, .key_update, .need_input, .need_output => {},
            else => return error.UnexpectedEvent,
        }
        if (server.sendBuffer().len == 0) {
            switch (phase) {
                .request => {},
                .response => {
                    try server.closeWrite();
                    phase = .closing;
                },
                .closing => return,
            }
        }
        const sent = try send(server, fd);
        const received = if (phase == .request) try receive(server, fd) else 0;
        if (sent != 0 or received != 0) continue;
        var interest: i16 = 0;
        if (server.receiveBuffer().len != 0 and phase == .request) interest |= c.POLL.IN;
        if (server.sendBuffer().len != 0) interest |= c.POLL.OUT;
        try wait(fd, interest);
    }
    return error.NoProgress;
}

fn send(server: *Server, fd: c.fd_t) !u16 {
    const wire = server.sendBuffer();
    if (wire.len == 0) return 0;
    // Force short writes even when the socket accepts the whole record.
    const rc = c.send(fd, wire.ptr, @min(wire.len, 3), c.MSG.DONTWAIT | c.MSG.NOSIGNAL);
    if (rc > 0) {
        server.sent(@intCast(rc));
        return @intCast(rc);
    }
    return switch (c.errno(rc)) {
        .AGAIN, .INTR => 0,
        else => error.SendFailed,
    };
}

fn receive(server: *Server, fd: c.fd_t) !u16 {
    const dest = server.receiveBuffer();
    if (dest.len == 0) return 0;
    const rc = c.recv(fd, dest.ptr, @min(dest.len, 7), c.MSG.DONTWAIT);
    if (rc > 0) {
        server.received(@intCast(rc));
        return @intCast(rc);
    }
    if (rc == 0) {
        server.endInput();
        return 0;
    }
    return switch (c.errno(rc)) {
        .AGAIN, .INTR => 0,
        else => error.ReceiveFailed,
    };
}

// RFC 8446 §4.4.4, §5, §6.1 and RFC 7301 §3.2. No in-tree client engine.
test "OpenSSL: poll adapter, short nonblocking I/O, h2 ALPN, echo, and close_notify" {
    const io = testing.io;
    const address: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    var context: Context = .{
        .listener = try address.listen(io, .{ .mode = .stream, .reuse_address = true }),
        .failure = null,
    };
    defer context.listener.deinit(io);
    var target_buf: [64]u8 = undefined;
    const target = try std.fmt.bufPrint(
        &target_buf,
        "127.0.0.1:{d}",
        .{context.listener.socket.address.getPort()},
    );
    {
        const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
        defer thread.join();
        try openSsl(target);
    }
    if (context.failure) |err| return err;
}

fn openSsl(target: []const u8) !void {
    const io = testing.io;
    var child = try std.process.spawn(io, .{
        .argv = &.{
            "timeout", "10",    "openssl", "s_client", "-tls1_3", "-connect",
            target,    "-alpn", "h2",      "-quiet",
        },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    defer child.kill(io);
    try child.stdin.?.writeStreamingAll(io, "ping");
    child.stdin.?.close(io);
    child.stdin = null;
    var response: [16]u8 = undefined;
    var reader = child.stdout.?.reader(io, &.{});
    const n = try reader.interface.readSliceShort(&response);
    try testing.expectEqualStrings("ping", response[0..n]);
    const term = try child.wait(io);
    try testing.expect(term == .exited);
    try testing.expectEqual(@as(u8, 0), term.exited);
}
