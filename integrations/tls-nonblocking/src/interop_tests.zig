//! Independent TLS peer over real sockets. Only this test adapter owns I/O.
const std = @import("std");
const Io = std.Io;
const c = std.c;
const testing = std.testing;
const tls = @import("tls");
const transport = @import("tls_nonblocking");
const Server = transport.Server;
const SocketClient = transport.SocketClient;
const fixtures = @import("fixtures");

const Context = struct {
    listener: Io.net.Server,
    failure: ?anyerror,
    early: ?[]const u8 = null,
    stop_after_handshake: bool = false,

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
        try echo(&server, socket.socket.handle, self.early, self.stop_after_handshake);
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
fn echo(
    server: *Server,
    fd: c.fd_t,
    initial: ?[]const u8,
    stop_after_handshake: bool,
) !void {
    const Phase = enum { request, response, closing };
    var phase: Phase = .request;
    var early = initial;
    const request = "ping";
    var request_pos: usize = 0;
    const started = Io.Timestamp.now(testing.io, .awake);
    for (0..10_000) |_| {
        if (started.durationTo(.now(testing.io, .awake)).toMilliseconds() > 5000)
            return error.PeerTimeout;
        switch (try server.next()) {
            .handshake_complete => {
                try testing.expectEqualStrings("h2", server.selectedAlpn().?);
                if (stop_after_handshake) return;
                if (early) |bytes| {
                    try testing.expectEqual(bytes.len, try server.write(bytes));
                    early = null;
                }
            },
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

fn connectTo(listener: *Io.net.Server) !Io.net.Stream {
    const address: Io.net.IpAddress = try .parse(
        "127.0.0.1",
        listener.socket.address.getPort(),
    );
    return address.connect(testing.io, .{ .mode = .stream });
}

fn listen() !Io.net.Server {
    const address: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    return address.listen(testing.io, .{ .mode = .stream, .reuse_address = true });
}

fn initLoopbackClient(client: *SocketClient, socket: Io.net.Stream) !void {
    try client.init(testing.allocator, testing.io, socket, .{
        .insecure_no_chain_anchor = true,
        .host_name = "ztls.server.test",
        .now_sec = 1_790_000_000,
        .alpn = &.{"h2"},
    });
}

// RFC 8446 §4.4.4, §5.1, §6.1. The socket adapter keeps coalesced early
// plaintext, hands over partial plaintext tails, and drains partial ciphertext.
test "SocketClient: loopback, early plaintext, partial consume, echo, close_notify" {
    var context: Context = .{
        .listener = try listen(),
        .failure = null,
        .early = "abcdefgh",
    };
    defer context.listener.deinit(testing.io);
    const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    defer thread.join();

    const socket = try connectTo(&context.listener);
    defer socket.close(testing.io);
    var client: SocketClient = undefined;
    try initLoopbackClient(&client, socket);
    defer client.deinit();
    try testing.expectEqualStrings("h2", client.selectedAlpn().?);

    var first: [3]u8 = undefined;
    var second: [2]u8 = undefined;
    var vectors: [2][]u8 = .{ &first, &second };
    try testing.expectEqual(@as(usize, 5), try client.reader().readVec(&vectors));
    try testing.expectEqualStrings("abc", &first);
    try testing.expectEqualStrings("de", &second);
    try client.writer().writeAll("ping");
    var tail: [4]u8 = undefined;
    var tail_vector: [1][]u8 = .{&tail};
    try testing.expectEqual(@as(usize, 3), try client.reader().readVec(&tail_vector));
    try testing.expectEqualStrings("fgh", tail[0..3]);

    var response: [4]u8 = undefined;
    var fixed: Io.Writer = .fixed(&response);
    try testing.expectEqual(
        @as(usize, 4),
        try client.reader().stream(&fixed, .limited(response.len)),
    );
    try testing.expectEqualStrings("ping", &response);
    var response_vector: [1][]u8 = .{&response};
    try testing.expectError(error.EndOfStream, client.reader().readVec(&response_vector));
    try testing.expectEqual(@as(usize, 0), try client.reader().readSliceShort(&response));
    try testing.expectError(error.EndOfStream, client.reader().readSliceAll(&response));
    try testing.expect(client.readError() == null);
    try testing.expect(!client.expired());
    if (context.failure) |err| return err;
}

test "SocketClient: a read timeout keeps its cause across deadline cleanup" {
    const BatchWaits = struct {
        threadlocal var count: usize = 0;

        fn awaitBatch(
            data: ?*anyopaque,
            batch: *Io.Batch,
            timeout: Io.Timeout,
        ) Io.Batch.AwaitConcurrentError!void {
            count += 1;
            return testing.io.vtable.batchAwaitConcurrent(data, batch, timeout);
        }
    };
    var context: Context = .{
        .listener = try listen(),
        .failure = null,
    };
    defer context.listener.deinit(testing.io);
    const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    defer thread.join();
    const socket = try connectTo(&context.listener);
    defer socket.close(testing.io);
    var client: SocketClient = undefined;
    try initLoopbackClient(&client, socket);
    defer client.deinit();

    var vtable = testing.io.vtable.*;
    vtable.batchAwaitConcurrent = BatchWaits.awaitBatch;
    client.io = .{ .userdata = testing.io.userdata, .vtable = &vtable };
    BatchWaits.count = 0;
    const future = @hasField(Io.Operation, "net_read");
    const now = Io.Clock.awake.now(testing.io).nanoseconds;
    client.setDeadline(if (future) now + 200 * std.time.ns_per_ms else now - 1);
    var response: [4]u8 = undefined;
    var vectors: [1][]u8 = .{&response};
    try testing.expectError(error.ReadFailed, client.reader().readVec(&vectors));
    try testing.expect(client.expired());
    try testing.expect(client.readError().? == error.TimedOut);
    if (future) try testing.expect(BatchWaits.count != 0);

    client.setDeadline(null);
    try testing.expect(!client.expired());
    try testing.expect(client.readError().? == error.TimedOut);
    try client.writer().writeAll("ping");
    try client.reader().readSliceAll(&response);
    try testing.expectEqualStrings("ping", &response);
    try testing.expect(client.readError() == null);
    if (context.failure) |err| return err;
}

// RFC 8446 §6.1. Bare EOF after authentication is truncation, not close_notify.
test "SocketClient: bare EOF is a read error, not a timeout or clean close" {
    var context: Context = .{
        .listener = try listen(),
        .failure = null,
        .stop_after_handshake = true,
    };
    defer context.listener.deinit(testing.io);
    const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    defer thread.join();

    const socket = try connectTo(&context.listener);
    defer socket.close(testing.io);
    var client: SocketClient = undefined;
    try initLoopbackClient(&client, socket);
    defer client.deinit();
    var destination: [1]u8 = undefined;
    var vectors: [1][]u8 = .{&destination};
    try testing.expectError(error.ReadFailed, client.reader().readVec(&vectors));
    try testing.expect(client.readError().? == error.UnexpectedEof);
    try testing.expect(!client.expired());
    try testing.expect(client.peerAlert() == null);
    if (context.failure) |err| return err;
}

const RawContext = struct {
    const Mode = enum { silent, alert };

    listener: Io.net.Server,
    failure: ?anyerror,
    mode: Mode,
    release: std.atomic.Value(bool) = .init(false),

    fn run(self: *RawContext) void {
        self.exchange() catch |err| {
            self.failure = err;
        };
    }

    fn exchange(self: *RawContext) !void {
        const io = testing.io;
        const socket = try self.listener.accept(io);
        defer socket.close(io);
        if (self.mode == .alert) {
            const message: [2]u8 = .{ 2, 49 };
            var wire: [tls.frame.header_len + 2]u8 = undefined;
            const bytes = try tls.alert.plaintextRecord(&message, &wire);
            var writer = socket.writer(io, &.{});
            try writer.interface.writeAll(bytes);
        }
        // No accidental input or EOF decides a deadline or alert assertion.
        while (!self.release.load(.acquire)) try io.sleep(.fromMilliseconds(1), .awake);
    }
};

fn rawClientOptions(deadline_ns: ?i96) SocketClient.Options {
    return .{
        .insecure_no_chain_anchor = true,
        .host_name = "ztls.server.test",
        .now_sec = 1_790_000_000,
        .alpn = &.{"h2"},
        .deadline_ns = deadline_ns,
    };
}

// RFC 8446 §6.2. The peer's exact alert survives failed-init cleanup and is
// never reclassified as expiry. The caller's socket remains open.
test "SocketClient: a fatal peer alert survives init cleanup" {
    var context: RawContext = .{
        .listener = try listen(),
        .failure = null,
        .mode = .alert,
    };
    defer context.listener.deinit(testing.io);
    const thread = try std.Thread.spawn(.{}, RawContext.run, .{&context});
    defer thread.join();
    defer context.release.store(true, .release);
    const socket = try connectTo(&context.listener);
    defer socket.close(testing.io);
    var client: SocketClient = undefined;
    try testing.expectError(
        error.PeerAlert,
        client.init(testing.allocator, testing.io, socket, rawClientOptions(null)),
    );
    const received_alert: ?tls.alert.Description = if (client.peerAlert()) |peer_alert|
        peer_alert.description
    else
        null;
    try testing.expectEqual(@as(?tls.alert.Description, .access_denied), received_alert);
    try testing.expect(!client.expired());
    client.deinit();
    if (context.failure) |err| return err;
}

// The eager handshake uses Options.deadline_ns before its first socket wait.
// Zig 0.16 rejects only future deadlines; both versions handle an expired one.
test "SocketClient: deadline bounds eager handshake and init releases resources" {
    const future = @hasField(Io.Operation, "net_read");
    var context: RawContext = .{
        .listener = try listen(),
        .failure = null,
        .mode = .silent,
    };
    defer context.listener.deinit(testing.io);
    const thread = try std.Thread.spawn(.{}, RawContext.run, .{&context});
    defer thread.join();
    defer context.release.store(true, .release);
    const socket = try connectTo(&context.listener);
    defer socket.close(testing.io);
    var client: SocketClient = undefined;
    const now = Io.Clock.awake.now(testing.io).nanoseconds;
    const deadline = if (future) now + 20 * 1_000_000 else now + 1_000_000;
    const result = client.init(
        testing.allocator,
        testing.io,
        socket,
        rawClientOptions(deadline),
    );
    if (future) {
        try testing.expectError(error.TimedOut, result);
        try testing.expect(client.expired());
    } else {
        try testing.expectError(error.DeadlineUnsupported, result);
        try testing.expect(!client.expired());
    }
    client.deinit();
    if (context.failure) |err| return err;
}

test "SocketClient: an already expired deadline works on both Zig versions" {
    var context: RawContext = .{
        .listener = try listen(),
        .failure = null,
        .mode = .silent,
    };
    defer context.listener.deinit(testing.io);
    const thread = try std.Thread.spawn(.{}, RawContext.run, .{&context});
    defer thread.join();
    defer context.release.store(true, .release);
    const socket = try connectTo(&context.listener);
    defer socket.close(testing.io);
    var client: SocketClient = undefined;
    const now = Io.Clock.awake.now(testing.io).nanoseconds;
    try testing.expectError(
        error.TimedOut,
        client.init(testing.allocator, testing.io, socket, rawClientOptions(now - 1)),
    );
    try testing.expect(client.expired());
    client.setDeadline(null);
    try testing.expect(!client.expired());
    client.deinit();
    if (context.failure) |err| return err;
}

// PEM setup is atomic, including allocation cleanup. Socket ownership stays
// with the caller when trust loading fails before ClientHello exists.
test "SocketClient: invalid trust anchors clean up without closing the socket" {
    var context: RawContext = .{
        .listener = try listen(),
        .failure = null,
        .mode = .silent,
    };
    defer context.listener.deinit(testing.io);
    const thread = try std.Thread.spawn(.{}, RawContext.run, .{&context});
    defer thread.join();
    defer context.release.store(true, .release);
    const socket = try connectTo(&context.listener);
    defer socket.close(testing.io);
    var client: SocketClient = undefined;
    var options = rawClientOptions(null);
    options.ca_pem = "not a certificate";
    try testing.expectError(
        error.NoTrustAnchors,
        client.init(testing.allocator, testing.io, socket, options),
    );
    client.deinit();
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
