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
const Bundle = std.crypto.Certificate.Bundle;

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
    const target = try std.mem.print(
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
    const now = Io.Clock.awake.now(testing.io).nanoseconds;
    client.setDeadline(now + 200 * std.time.ns_per_ms);
    var response: [4]u8 = undefined;
    var vectors: [1][]u8 = .{&response};
    try testing.expectError(error.ReadFailed, client.reader().readVec(&vectors));
    try testing.expect(client.expired());
    try testing.expect(client.readError().? == error.TimedOut);
    try testing.expect(BatchWaits.count != 0);

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
test "SocketClient: deadline bounds eager handshake and init releases resources" {
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
    const result = client.init(
        testing.allocator,
        testing.io,
        socket,
        rawClientOptions(now + 20 * 1_000_000),
    );
    try testing.expectError(error.TimedOut, result);
    try testing.expect(client.expired());
    client.deinit();
    if (context.failure) |err| return err;
}

test "SocketClient: an already expired deadline is detected" {
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
    options.trust = .{ .pem = "not a certificate" };
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

const ApplicationCancel = struct {
    start: i96 = 0,
    /// Cancels once this much time has passed; moving it out of reach turns
    /// the hook back into a keeper.
    after_ns: i96,
    calls: usize = 0,

    fn shouldCancel(context: *anyopaque) bool {
        const self: *ApplicationCancel = @ptrCast(@alignCast(context));
        self.calls += 1;
        const now = Io.Timestamp.now(testing.io, .awake).nanoseconds;
        return now - self.start >= self.after_ns;
    }
};

// A watcher has to be able to stop a read that is already waiting, and the
// connection has to survive the cancel. The peer answers only after "ping", so
// the first read has nothing to deliver and no deadline to end it.
test "SocketClient: a cancel ends a blocked application read and the stream resumes" {
    var context: Context = .{ .listener = try listen(), .failure = null };
    defer context.listener.deinit(testing.io);
    const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    defer thread.join();

    const socket = try connectTo(&context.listener);
    defer socket.close(testing.io);

    var state: ApplicationCancel = .{ .after_ns = 150 * std.time.ns_per_ms };
    state.start = Io.Timestamp.now(testing.io, .awake).nanoseconds;
    var client: SocketClient = undefined;
    try client.init(testing.allocator, testing.io, socket, .{
        .insecure_no_chain_anchor = true,
        .host_name = "ztls.server.test",
        .now_sec = 1_790_000_000,
        .alpn = &.{"h2"},
        .cancel = .{ .context = &state, .shouldCancel = ApplicationCancel.shouldCancel },
    });
    defer client.deinit();
    try testing.expectEqualStrings("h2", client.selectedAlpn().?);

    const started = Io.Timestamp.now(testing.io, .awake).nanoseconds;
    var byte: [1]u8 = undefined;
    try testing.expectError(error.ReadFailed, client.reader().readSliceAll(&byte));
    const elapsed = Io.Timestamp.now(testing.io, .awake).nanoseconds - started;
    try testing.expectEqual(
        @as(?SocketClient.ReadError, error.Canceled),
        client.readError(),
    );
    try testing.expect(!client.expired());
    try testing.expect(elapsed < std.time.ns_per_s);

    // The cancel abandoned one read, not the connection: the exchange runs.
    state.after_ns = std.math.maxInt(i96);
    try client.writer().writeAll("ping");
    var reply: [4]u8 = undefined;
    try client.reader().readSliceAll(&reply);
    try testing.expectEqualStrings("ping", &reply);
    try testing.expect(state.calls >= 2);
    if (context.failure) |err| return err;
}

// The seam `http`'s platform-store default depends on: a bundle the caller
// loaded, rather than PEM the adapter parses. The fixture certificate is
// CA:FALSE, so a store holding it reaches the policy and is refused there;
// without a store the handshake fails earlier for a different reason. The
// error names prove the borrowed store was the one consulted.
test "SocketClient: a caller-supplied trust store is the one consulted" {
    var bundle: Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    try bundle.bytes.appendSlice(testing.allocator, &fixtures.server_ecdsa_cert_der);
    try bundle.parseCert(testing.allocator, 0, 1_790_000_000);

    {
        var context: Context = .{ .listener = try listen(), .failure = null };
        defer context.listener.deinit(testing.io);
        const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
        defer thread.join();

        const socket = try connectTo(&context.listener);
        defer socket.close(testing.io);

        var client: SocketClient = undefined;
        try testing.expectError(error.CertificateIssuerNotCa, client.init(
            testing.allocator,
            testing.io,
            socket,
            .{
                .trust = .{ .bundle = &bundle },
                .host_name = "ztls.server.test",
                .now_sec = 1_790_000_000,
                .alpn = &.{"h2"},
            },
        ));
        // Ownership stays with the caller.
        client.deinit();
    }

    // Without a store the same peer fails differently: no anchor at all.
    {
        var context: Context = .{ .listener = try listen(), .failure = null };
        defer context.listener.deinit(testing.io);
        const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
        defer thread.join();

        const socket = try connectTo(&context.listener);
        defer socket.close(testing.io);

        var client: SocketClient = undefined;
        try testing.expectError(error.MissingTrustAnchor, client.init(
            testing.allocator,
            testing.io,
            socket,
            .{
                .host_name = "ztls.server.test",
                .now_sec = 1_790_000_000,
                .alpn = &.{"h2"},
            },
        ));
        client.deinit();
    }
}

const ShortSocketIo = struct {
    threadlocal var read_limit: usize = 0;
    threadlocal var write_limit: usize = 0;
    threadlocal var capped_reads: usize = 0;
    threadlocal var capped_writes: usize = 0;

    fn reset(read: usize, write: usize) void {
        read_limit = read;
        write_limit = write;
        capped_reads = 0;
        capped_writes = 0;
    }

    fn operate(
        userdata: ?*anyopaque,
        operation: Io.Operation,
    ) Io.Cancelable!Io.Operation.Result {
        // Keep testing.io's userdata: every other vtable entry still belongs
        // to that implementation. Only the two socket operations are capped.
        const base: Io = .{ .userdata = userdata, .vtable = testing.io.vtable };
        switch (operation) {
            .net_read => |read| {
                std.debug.assert(read.data.len == 1);
                var bounded = read;
                var data: [1][]u8 = read.data[0..1].*;
                if (read_limit < data[0].len) {
                    data[0] = data[0][0..read_limit];
                    capped_reads += 1;
                }
                bounded.data = &data;
                return base.operate(.{ .net_read = bounded });
            },
            .net_write => |write| {
                std.debug.assert(write.data.len == 1);
                std.debug.assert(write.splat == 1);
                var bounded = write;
                var data: [1][]const u8 = write.data[0..1].*;
                if (write_limit < data[0].len) {
                    data[0] = data[0][0..write_limit];
                    capped_writes += 1;
                }
                bounded.data = &data;
                return base.operate(.{ .net_write = bounded });
            },
            else => return base.operate(operation),
        }
    }
};

const OpenSslCredentials = struct {
    cert_path: []const u8,
    key_path: []const u8,
    pem: []const u8,
    now_sec: i64,

    fn init(allocator: std.mem.Allocator, tmp: anytype) !OpenSslCredentials {
        var path_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
        const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
        const dir = try allocator.dupe(u8, path_buffer[0..path_len]);
        const cert_path: []const u8 = try Io.Dir.path.join(
            allocator,
            &.{ dir, "cert.pem" },
        );
        const key_path: []const u8 = try Io.Dir.path.join(
            allocator,
            &.{ dir, "key.pem" },
        );
        var child = try std.process.spawn(testing.io, .{
            .argv = &.{
                "timeout",                 "10",
                "openssl",                 "req",
                "-x509",                   "-newkey",
                "ec",                      "-pkeyopt",
                "ec_paramgen_curve:P-256", "-keyout",
                key_path,                  "-out",
                cert_path,                 "-days",
                "2",                       "-nodes",
                "-subj",                   "/CN=ztls.server.test",
                "-addext",                 "subjectAltName=DNS:ztls.server.test",
            },
            .stdout = .ignore,
            .stderr = .ignore,
        });
        const term = try child.wait(testing.io);
        if (term != .exited or term.exited != 0)
            return error.CertificateGenerationFailed;
        const pem = try Io.Dir.cwd().readFileAlloc(
            testing.io,
            cert_path,
            allocator,
            .limited(16 * 1024),
        );
        const now = Io.Timestamp.now(testing.io, .real).nanoseconds;
        return .{
            .cert_path = cert_path,
            .key_path = key_path,
            .pem = pem,
            .now_sec = @intCast(@divFloor(now, std.time.ns_per_s)),
        };
    }
};

fn startOpenSslServer(
    allocator: std.mem.Allocator,
    credentials: *const OpenSslCredentials,
    trace_path: []const u8,
    port: u16,
    alpn_protocol: []const u8,
) !std.process.Child {
    const accept = try allocator.print("127.0.0.1:{d}", .{port});
    return std.process.spawn(testing.io, .{
        .argv = &.{
            "timeout",      "15",
            "openssl",      "s_server",
            "-accept",      accept,
            "-cert",        credentials.cert_path,
            "-key",         credentials.key_path,
            "-tls1_3",      "-alpn",
            alpn_protocol,  "-trace",
            "-msgfile",     trace_path,
            "-num_tickets", "0",
            "-naccept",     "1",
        },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
}

fn openSslFreePort() !u16 {
    var listener = try listen();
    defer listener.deinit(testing.io);
    return listener.socket.address.getPort();
}

fn connectToOpenSsl(port: u16) !Io.net.Stream {
    const address: Io.net.IpAddress = try .parse("127.0.0.1", port);
    for (0..250) |_| {
        return address.connect(testing.io, .{ .mode = .stream }) catch |err| switch (err) {
            error.ConnectionRefused => {
                testing.io.sleep(.fromMilliseconds(20), .awake) catch return err;
                continue;
            },
            else => return err,
        };
    }
    return error.OpenSslServerNeverCameUp;
}

const OpenSslOutput = struct {
    bytes: [32 * 1024]u8 = undefined,
    len: usize = 0,

    fn expect(self: *OpenSslOutput, child: *const std.process.Child, needle: []const u8) !void {
        while (std.mem.find(u8, self.bytes[0..self.len], needle) == null) {
            if (self.len == self.bytes.len) return error.OpenSslOutputTooLong;
            try wait(child.stdout.?.handle, c.POLL.IN);
            const count = try std.posix.read(child.stdout.?.handle, self.bytes[self.len..]);
            if (count == 0) return error.OpenSslOutputClosed;
            self.len += count;
        }
    }
};

fn sendOpenSslInput(child: *std.process.Child, bytes: []const u8) !void {
    try child.stdin.?.writeStreamingAll(testing.io, bytes);
}

fn expectKeyUpdateTrace(trace: []const u8) !void {
    const requested = std.mem.find(
        u8,
        trace,
        "KeyUpdate, Length=1\n      update_requested (1)",
    ) orelse return error.OpenSslDidNotRequestKeyUpdate;
    _ = std.mem.find(
        u8,
        trace[requested + 1 ..],
        "KeyUpdate, Length=1\n      update_not_requested (0)",
    ) orelse return error.OpenSslDidNotReceiveKeyUpdateResponse;
}

fn exerciseOpenSslExchange(
    client: *SocketClient,
    socket: Io.net.Stream,
    server: *std.process.Child,
) !void {
    const old_plaintext = "old-epoch-server-data\n";
    try sendOpenSslInput(server, old_plaintext);
    var prefix: [3]u8 = undefined;
    try client.reader().readSliceAll(&prefix);
    try testing.expectEqualStrings("old", &prefix);
    try client.writer().writeAll("client-before-key-update\n");
    var output: OpenSslOutput = .{};
    try output.expect(server, "client-before-key-update\n");

    // The old plaintext tail stays pinned while OpenSSL sends KeyUpdate and
    // new-epoch application data. The next read must answer the update first.
    try sendOpenSslInput(server, "K\n");
    // Do not let one stdin read combine the command and new application data.
    try wait(socket.socket.handle, c.POLL.IN);
    const new_plaintext = "new-epoch-server-data\n";
    try sendOpenSslInput(server, new_plaintext);
    var old_tail: [old_plaintext.len - prefix.len]u8 = undefined;
    try client.reader().readSliceAll(&old_tail);
    try testing.expectEqualStrings(old_plaintext[prefix.len..], &old_tail);
    var received_new: [new_plaintext.len]u8 = undefined;
    try client.reader().readSliceAll(&received_new);
    try testing.expectEqualStrings(new_plaintext, &received_new);
    try client.writer().writeAll("client-after-key-update\n");
    try output.expect(server, "client-after-key-update\n");

    try client.closeWrite();
    var end: [1]u8 = undefined;
    try testing.expectError(error.EndOfStream, client.reader().readSliceAll(&end));
    try testing.expect(client.readError() == null);
    try testing.expect(client.peerAlert() == null);
    try output.expect(server, "DONE\n");
}

// RFC 8446 §4.1, §4.4.4, §4.6.3, §6.1, §7.2 and RFC 7301 §3.2.
// The independent peer checks ClientHello ALPN, Finished, application
// keys, a requested KeyUpdate response, and the client's close_notify. The
// client checks the peer's certificate, both application epochs, and the
// authenticated peer close. Seven-byte reads and three-byte writes fragment
// every flight rather than just application data.
test "SocketClient: OpenSSL fragmented exchange, KeyUpdate, and close_notify" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const credentials: OpenSslCredentials = try .init(allocator, &tmp);
    const dir_end = std.mem.findScalarLast(u8, credentials.cert_path, '/').?;
    const trace_path = try Io.Dir.path.join(
        allocator,
        &.{ credentials.cert_path[0..dir_end], "trace.txt" },
    );
    const port = try openSslFreePort();
    var server = try startOpenSslServer(allocator, &credentials, trace_path, port, "h2");
    defer server.kill(testing.io);

    const socket = try connectToOpenSsl(port);
    defer socket.close(testing.io);
    ShortSocketIo.reset(7, 3);
    var vtable = testing.io.vtable.*;
    vtable.operate = ShortSocketIo.operate;
    const short_io: Io = .{ .userdata = testing.io.userdata, .vtable = &vtable };
    var client: SocketClient = undefined;
    try client.init(testing.allocator, short_io, socket, .{
        .trust = .{ .pem = credentials.pem },
        .host_name = "ztls.server.test",
        .now_sec = credentials.now_sec,
        .alpn = &.{"h2"},
    });
    defer client.deinit();
    try testing.expectEqualStrings("h2", client.selectedAlpn().?);
    try testing.expect(ShortSocketIo.capped_reads != 0);
    try testing.expect(ShortSocketIo.capped_writes != 0);

    try exerciseOpenSslExchange(&client, socket, &server);
    const term = try server.wait(testing.io);
    try testing.expect(term == .exited);
    try testing.expectEqual(@as(u8, 0), term.exited);

    const trace = try Io.Dir.cwd().readFileAlloc(
        testing.io,
        trace_path,
        allocator,
        .limited(256 * 1024),
    );
    try expectKeyUpdateTrace(trace);
}

// RFC 8446 §6.2 and RFC 7301 §3.2. OpenSSL generates this alert, and its exact
// description survives failed-init cleanup in SocketClient.
test "SocketClient: OpenSSL no_application_protocol is a fatal peer alert" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const credentials: OpenSslCredentials = try .init(allocator, &tmp);
    const dir_end = std.mem.findScalarLast(u8, credentials.cert_path, '/').?;
    const trace_path = try Io.Dir.path.join(
        allocator,
        &.{ credentials.cert_path[0..dir_end], "trace.txt" },
    );
    const port = try openSslFreePort();
    var server = try startOpenSslServer(allocator, &credentials, trace_path, port, "h2");
    defer server.kill(testing.io);

    const socket = try connectToOpenSsl(port);
    defer socket.close(testing.io);
    var client: SocketClient = undefined;
    try testing.expectError(error.PeerAlert, client.init(
        testing.allocator,
        testing.io,
        socket,
        .{
            .trust = .{ .pem = credentials.pem },
            .host_name = "ztls.server.test",
            .now_sec = credentials.now_sec,
            .alpn = &.{"http/1.1"},
        },
    ));
    const peer_alert = client.peerAlert().?;
    try testing.expectEqual(tls.alert.Description.no_application_protocol, peer_alert.description);
    try testing.expect(!client.expired());
    client.deinit();

    const term = try server.wait(testing.io);
    try testing.expect(term == .exited);
}
