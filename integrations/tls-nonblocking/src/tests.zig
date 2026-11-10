//! Public API tests over a byte stream with deterministic fragmentation.
const std = @import("std");
const testing = std.testing;
const tls = @import("tls");
const transport = @import("tls_nonblocking");
const Server = transport.Server;
const SocketClient = transport.SocketClient;
const PrivateKey = tls.signature.PrivateKey;
const fixtures = @import("fixtures");
const interop_tests = @import("interop_tests.zig");

comptime {
    _ = interop_tests;
    _ = SocketClient;
}
const frame = tls.frame;
const cert = &fixtures.server_ecdsa_cert_der;
const scalar = &fixtures.server_ecdsa_scalar;

const Pair = struct {
    server: Server,
    client: tls.ClientHandshake,
    key: ?PrivateKey,
    record: [tls.RecordBuffer.min_storage]u8,
    out: [frame.max_wire_record_len]u8,
    reassembly: [tls.ServerHandshake.ch_reassembly_buffer_size]u8,
    client_record: [tls.RecordBuffer.min_storage]u8,
    client_out: [frame.max_wire_record_len]u8,
    client_reassembly: [tls.ClientHandshake.recommended_handshake_storage]u8,
    client_rb: tls.RecordBuffer,
    client_pending: []const u8,

    fn init(self: *Pair, supported_suites: []const tls.CipherSuite) !void {
        self.key = try .fromP256Scalar(scalar);
        errdefer if (self.key) |*key| key.deinit();
        try self.initClient();
        errdefer self.client.deinit();
        try self.initServer(.{
            .supported_suites = supported_suites,
            .alpn_protocols = &.{"h2"},
        }, .{
            .keypairs = try .init(.generate()),
            .random = .init(@splat(0x72)),
            .reassembly = &self.reassembly,
        });
    }

    fn initWithOptions(
        self: *Pair,
        options: *const Server.Options,
        config: tls.ServerHandshake.Config,
    ) !void {
        self.key = null;
        try self.initClient();
        errdefer self.client.deinit();
        try self.server.init(
            options,
            config,
            .{ .record = &self.record, .out = &self.out },
        );
    }

    fn initClient(self: *Pair) !void {
        self.client = .init(.{
            .keypairs = try .init(.generate()),
            .host_name = "ztls.server.test",
            .now_sec = 1_790_000_000,
            .random = .init(@splat(0x31)),
            .insecure_no_chain_anchor = true,
            .alpn_protocols = &.{ "http/1.1", "h2" },
            .reassembly = &self.client_reassembly,
        });
        self.client_rb = .init(&self.client_record);
        self.client_pending = &.{};
    }

    fn initServer(
        self: *Pair,
        server_config: tls.ServerHandshake.ServerConfig,
        config: tls.ServerHandshake.Config,
    ) !void {
        try self.server.init(&.{
            .handshake = server_config,
            .cert_chain = &.{cert},
            .signer = self.key.?.signer(),
        }, config, .{ .record = &self.record, .out = &self.out });
    }

    fn deinit(self: *Pair) void {
        self.server.deinit();
        self.client.deinit();
        if (self.key) |*key| key.deinit();
        std.crypto.secureZero(u8, &self.record);
        std.crypto.secureZero(u8, &self.out);
        std.crypto.secureZero(u8, &self.reassembly);
        std.crypto.secureZero(u8, &self.client_record);
        std.crypto.secureZero(u8, &self.client_out);
        std.crypto.secureZero(u8, &self.client_reassembly);
        self.* = undefined;
    }

    fn input(self: *Pair, bytes: []const u8) !void {
        const dest = self.server.receiveBuffer();
        try testing.expect(dest.len >= bytes.len);
        @memcpy(dest[0..bytes.len], bytes);
        self.server.received(bytes.len);
    }

    fn clientRecord(self: *Pair, bytes: []const u8) !void {
        try self.input(bytes);
        self.client.completeWrite();
    }

    fn handshake(self: *Pair, fragment: u16, first_app: ?[]const u8) !void {
        self.client_pending = try self.client.start(&self.client_out);
        try self.finishHandshake(fragment, first_app);
    }

    fn finishHandshake(self: *Pair, fragment: u16, first_app: ?[]const u8) !void {
        for (0..100_000) |_| {
            if (self.client_pending.len != 0) {
                const n = @min(fragment, self.client_pending.len);
                try self.input(self.client_pending[0..n]);
                self.client_pending = self.client_pending[n..];
                if (self.client_pending.len == 0) {
                    self.client.completeWrite();
                    if (self.client.isConnected()) {
                        if (first_app) |app| {
                            const record = try self.client.sendApplicationData(
                                app,
                                &self.client_out,
                            );
                            try self.clientRecord(record);
                        }
                    }
                }
            }
            const wire = self.server.sendBuffer();
            if (wire.len != 0) {
                const n = @min(fragment, wire.len);
                const dest = self.client_rb.writable();
                try testing.expect(dest.len >= n);
                @memcpy(dest[0..n], wire[0..n]);
                self.client_rb.advance(n);
                self.server.sent(n);
                while (try self.client_rb.next()) |record| {
                    switch (try self.client.handleRecord(record, &self.client_out)) {
                        .write => |bytes| self.client_pending = bytes,
                        .none => {},
                        else => return error.UnexpectedEvent,
                    }
                }
            }
            switch (try self.server.next()) {
                .handshake_complete => return,
                .need_input, .need_output, .progress => {},
                else => return error.UnexpectedEvent,
            }
        }
        return error.NoProgress;
    }

    fn output(self: *Pair, fragment: u16) !void {
        for (0..frame.max_wire_record_len) |_| {
            const wire = self.server.sendBuffer();
            if (wire.len == 0) return;
            const n = @min(fragment, wire.len);
            const dest = self.client_rb.writable();
            try testing.expect(dest.len >= n);
            @memcpy(dest[0..n], wire[0..n]);
            self.client_rb.advance(n);
            self.server.sent(n);
        }
        return error.NoProgress;
    }

    fn applicationOutput(self: *Pair, expected: []const u8) !void {
        try self.output(1);
        const record = (try self.client_rb.next()).?;
        const event = try self.client.receiveRecord(record);
        try testing.expectEqualStrings(expected, event.application_data);
    }
};

const suites = [_]tls.CipherSuite{
    .aes_128_gcm_sha256,
    .aes_256_gcm_sha384,
    .chacha20_poly1305_sha256,
};

// RFC 8446 §4.1, §4.4.4, §5.1. ALPN follows RFC 7301 §3.2.
test "handshake: one-byte reads and writes, each cipher suite, and coalesced application data" {
    for (suites) |suite| {
        for ([_]u16{ 1, 7, frame.max_wire_record_len }) |fragment| {
            var pair: Pair = undefined;
            try pair.init(&.{suite});
            defer pair.deinit();
            try testing.expect(!pair.server.isConnected());
            try testing.expectEqual(@as(usize, 0), pair.server.sendBuffer().len);
            try testing.expectEqual(.need_input, try pair.server.next());
            try testing.expectEqual(@as(?[]const u8, null), pair.server.selectedAlpn());
            try testing.expectError(error.HandshakeIncomplete, pair.server.write("too soon"));
            try pair.handshake(fragment, "preface");
            try testing.expect(pair.server.isConnected());
            try testing.expectEqualStrings("h2", pair.server.selectedAlpn().?);
            try testing.expectEqualStrings("preface", (try pair.server.next()).application_data);
            pair.server.consumeApplication(7);
            try testing.expectEqual(.need_input, try pair.server.next());
        }
    }
}

// RFC 8446 §4.1, §4.4.4. Static listener policy never carries connection state.
test "fixed slots: one listener config and disjoint connection state" {
    var key: PrivateKey = try .fromP256Scalar(scalar);
    defer key.deinit();
    const options: Server.Options = .{
        .handshake = .{
            .supported_suites = &suites,
            .alpn_protocols = &.{"h2"},
        },
        .cert_chain = &.{cert},
        .signer = key.signer(),
    };
    var slow: Pair = undefined;
    try slow.initWithOptions(&options, .{
        .keypairs = try .init(.generate()),
        .random = .init(@splat(0x72)),
        .reassembly = &slow.reassembly,
    });
    defer slow.deinit();
    slow.client_pending = try slow.client.start(&slow.client_out);
    try slow.input(slow.client_pending[0..1]);
    slow.client_pending = slow.client_pending[1..];
    try testing.expectEqual(.need_input, try slow.server.next());

    var ready: Pair = undefined;
    try ready.initWithOptions(&options, .{
        .keypairs = try .init(.generate()),
        .random = .init(@splat(0x73)),
        .reassembly = &ready.reassembly,
    });
    defer ready.deinit();
    try ready.handshake(7, null);
    try testing.expect(ready.server.isConnected());
    try testing.expect(!slow.server.isConnected());
    try slow.finishHandshake(1, null);
    try testing.expect(slow.server.isConnected());
}

// RFC 8446 §4.2.10, §4.5. Early data remains distinct from authenticated data.
test "0-RTT: separate borrowed event and input backpressure before client Finished" {
    const Lookup = struct {
        fn lookup(_: *anyopaque, id: []const u8) ?tls.ServerHandshake.PskEntry {
            if (!std.mem.eql(u8, id, "early-ticket")) return null;
            return .{
                .psk = &(@as([32]u8, @splat(0x42))),
                .cipher_suite = .aes_128_gcm_sha256,
                .max_early_data_size = 1024,
                .alpn = "h2",
            };
        }
    };
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    pair.server.deinit();
    var context: u8 = 0;
    try pair.initServer(.{
        .alpn_protocols = &.{"h2"},
        .psk_lookup = .{ .context = &context, .lookup = Lookup.lookup },
    }, .{
        .keypairs = try .init(.generate()),
        .random = .zero,
        .reassembly = &pair.reassembly,
    });
    var ticket: tls.ClientHandshake.SessionTicket = .init(0, 0, .aes_128_gcm_sha256, 1024);
    ticket.identity.appendSliceAssumeCapacity("early-ticket");
    ticket.psk.appendSliceAssumeCapacity(&(@as([32]u8, @splat(0x42))));
    ticket.alpn_protocol.appendSliceAssumeCapacity("h2");
    try pair.clientRecord(try pair.client.startWithPsk(&ticket, &pair.client_out, true));
    try pair.clientRecord(try pair.client.sendEarlyData("early", &pair.client_out));
    try testing.expectEqual(.need_output, try pair.server.next());
    try pair.output(1);
    const hello = (try pair.client_rb.next()).?;
    _ = try pair.client.handleRecord(hello, &pair.client_out);
    try testing.expectEqual(.need_output, try pair.server.next());
    try pair.output(1);
    while (try pair.client_rb.next()) |record| {
        switch (try pair.client.handleRecord(record, &pair.client_out)) {
            .write => |bytes| pair.client_pending = bytes,
            .none => {},
            else => return error.UnexpectedEvent,
        }
    }
    try testing.expectEqualStrings("early", (try pair.server.next()).early_data);
    try testing.expect(!pair.server.isConnected());
    try testing.expectEqual(@as(usize, 0), pair.server.receiveBuffer().len);
    pair.server.consumeApplication(2);
    try testing.expectEqualStrings("rly", (try pair.server.next()).early_data);
    pair.server.consumeApplication(3);
    try pair.finishHandshake(1, null);
    try testing.expect(pair.server.isConnected());
}

// RFC 8446 §5.1. ClientHello can span records, including its handshake header.
test "handshake: ClientHello header and body reassemble across records" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    const hello = try pair.client.start(&pair.client_out);
    const header = try frame.parseHeader(hello);
    const body = hello[frame.header_len..][0..header.length()];
    var fragment: [frame.max_wire_record_len]u8 = undefined;
    const split: u16 = 2;
    const first: frame.Header = .init(.handshake, split);
    first.write(fragment[0..frame.header_len]);
    @memcpy(fragment[frame.header_len..][0..split], body[0..split]);
    try pair.input(fragment[0 .. frame.header_len + split]);
    try testing.expectEqual(.progress, try pair.server.next());
    try testing.expectEqual(.need_input, try pair.server.next());
    const remaining = body[split..];
    const second: frame.Header = .init(.handshake, @intCast(remaining.len));
    second.write(fragment[0..frame.header_len]);
    @memcpy(fragment[frame.header_len..][0..remaining.len], remaining);
    try pair.input(fragment[0 .. frame.header_len + remaining.len]);
    pair.client.completeWrite();
    try testing.expectEqual(.need_output, try pair.server.next());
    try pair.finishHandshake(1, null);
    try testing.expect(pair.server.isConnected());
}

// RFC 7301 §3.2. ALPN rejection and absence are distinct negotiation results.
test "ALPN: reject disjoint lists, expose absence for the caller to reject" {
    var rejected: Pair = undefined;
    try rejected.init(&suites);
    defer rejected.deinit();
    rejected.client.offerAlpn(&.{"other"});
    try testing.expectError(error.NoApplicationProtocol, rejected.handshake(7, null));
    const wire = rejected.server.sendBuffer();
    const failure = try tls.alert.parse(wire[frame.header_len..]);
    try testing.expectEqual(.no_application_protocol, failure.description);
    try testing.expectEqual(@as(?[]const u8, null), rejected.server.selectedAlpn());

    var absent: Pair = undefined;
    try absent.init(&suites);
    defer absent.deinit();
    absent.client.offerAlpn(&.{});
    try absent.handshake(7, null);
    try testing.expect(absent.server.isConnected());
    try testing.expectEqual(@as(?[]const u8, null), absent.server.selectedAlpn());
}

// RFC 8446 §5.1, §5.2. A pending TX record must not block independent RX.
test "application data: partial consumption pins plaintext and partial sends pin ciphertext" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.handshake(7, null);
    try testing.expectEqual(@as(usize, 8), try pair.server.write("outgoing"));
    const original = pair.server.sendBuffer();
    pair.server.sent(0);
    try testing.expectEqualSlices(u8, original, pair.server.sendBuffer());
    try testing.expectError(error.WouldBlock, pair.server.write("blocked"));
    try testing.expectError(error.WouldBlock, pair.server.closeWrite());
    try pair.clientRecord(try pair.client.sendApplicationData("incoming", &pair.client_out));
    try testing.expectEqualStrings("incoming", (try pair.server.next()).application_data);
    try testing.expectEqual(@as(usize, 0), pair.server.receiveBuffer().len);
    pair.server.consumeApplication(2);
    try testing.expectEqualStrings("coming", (try pair.server.next()).application_data);
    try testing.expectEqualSlices(u8, original, pair.server.sendBuffer());
    try pair.applicationOutput("outgoing");
    try testing.expectEqualStrings("coming", (try pair.server.next()).application_data);
    pair.server.consumeApplication(6);
    try testing.expect(pair.server.receiveBuffer().len != 0);
    try testing.expectEqual(.need_input, try pair.server.next());
}

// RFC 8446 §5.1. One input fill can carry several records, including empty ones.
test "application data: coalesced records and zero-length fragments" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.handshake(frame.max_wire_record_len, null);
    for ([_][]const u8{ "", "one", "two" }) |plain| {
        try pair.clientRecord(try pair.client.sendApplicationData(plain, &pair.client_out));
    }
    try testing.expectEqual(.progress, try pair.server.next());
    try testing.expectEqualStrings("one", (try pair.server.next()).application_data);
    pair.server.consumeApplication(3);
    try testing.expectEqualStrings("two", (try pair.server.next()).application_data);
    pair.server.consumeApplication(3);
    try testing.expectEqual(.need_input, try pair.server.next());
}

// RFC 8446 §5.1. A plaintext fragment cannot exceed 2^14 bytes.
test "write: one record is the output budget" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.handshake(frame.max_wire_record_len, null);
    const large: [frame.max_plaintext_len + 1]u8 = @splat(0x42);
    try testing.expectEqual(@as(usize, frame.max_plaintext_len), try pair.server.write(&large));
    try testing.expectError(
        error.WouldBlock,
        pair.server.write(large[frame.max_plaintext_len..]),
    );
    try pair.applicationOutput(large[0..frame.max_plaintext_len]);
    try testing.expectEqual(@as(usize, 1), try pair.server.write(large[frame.max_plaintext_len..]));
    try pair.applicationOutput(large[frame.max_plaintext_len..]);
}

// RFC 8446 §4.6.3, §7.2. A required response precedes the next application record.
test "KeyUpdate: RX overlaps old TX, response precedes new application data" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.handshake(7, null);
    _ = try pair.server.write("old epoch");
    const old_wire = pair.server.sendBuffer();
    const request = try pair.client.sendKeyUpdate(&pair.client_out, .update_requested);
    try pair.clientRecord(request);
    try testing.expectEqual(.update_requested, (try pair.server.next()).key_update);
    try testing.expectEqualSlices(u8, old_wire, pair.server.sendBuffer());
    try testing.expectError(error.WouldBlock, pair.server.write("new epoch"));
    try pair.applicationOutput("old epoch");
    // Even after the unrelated output drains, the response obligation remains.
    try testing.expectError(error.WouldBlock, pair.server.write("new epoch"));
    try testing.expectEqual(.need_output, try pair.server.next());
    try pair.output(1);
    const update = (try pair.client_rb.next()).?;
    const response = try pair.client.receiveRecord(update);
    try testing.expectEqual(.update_not_requested, response.key_update);
    _ = try pair.server.write("new epoch");
    try pair.applicationOutput("new epoch");
    try pair.clientRecord(try pair.client.sendApplicationData("new RX epoch", &pair.client_out));
    try testing.expectEqualStrings("new RX epoch", (try pair.server.next()).application_data);
}

// RFC 8446 §4.6.3. Borrowed input cannot block the TX response that releases a write.
test "KeyUpdate: response progresses while application plaintext stays borrowed" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.handshake(7, null);
    _ = try pair.server.write("old epoch");
    const request = try pair.client.sendKeyUpdate(&pair.client_out, .update_requested);
    try pair.clientRecord(request);
    try testing.expectEqual(.update_requested, (try pair.server.next()).key_update);
    try pair.clientRecord(try pair.client.sendApplicationData("echo", &pair.client_out));
    try testing.expectEqualStrings("echo", (try pair.server.next()).application_data);
    try testing.expectError(error.WouldBlock, pair.server.write("echo"));
    try pair.applicationOutput("old epoch");
    try testing.expectEqual(.need_output, try pair.server.next());
    try testing.expectEqual(@as(usize, 0), pair.server.receiveBuffer().len);
    try pair.output(1);
    const update = (try pair.client_rb.next()).?;
    const response = try pair.client.receiveRecord(update);
    try testing.expectEqual(.update_not_requested, response.key_update);
    const borrowed = (try pair.server.next()).application_data;
    try testing.expectEqualStrings("echo", borrowed);
    const n = try pair.server.write(borrowed);
    pair.server.consumeApplication(n);
    try pair.applicationOutput("echo");
}

// RFC 8446 §6.1. close_notify closes one direction, not both.
test "close_notify: peer half-close, final response, and local close under backpressure" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.handshake(7, null);
    try pair.clientRecord(try pair.client.sendAlert(.close_notify, &pair.client_out));
    try testing.expectEqual(.close_notify, try pair.server.next());
    try testing.expectEqual(.closed, try pair.server.next());
    try testing.expectEqual(@as(usize, 0), pair.server.receiveBuffer().len);
    _ = try pair.server.write("final response");
    try testing.expectError(error.WouldBlock, pair.server.closeWrite());
    try pair.applicationOutput("final response");
    try pair.server.closeWrite();
    try pair.server.closeWrite();
    try testing.expectError(error.Closed, pair.server.write("too late"));
    try pair.output(1);
    try testing.expectEqual(.closed, try pair.client.receiveRecord((try pair.client_rb.next()).?));
    pair.server.endInput();
    try testing.expectEqual(.closed, try pair.server.next());
}

// RFC 8446 §6.1. EOF cannot authenticate a stream or discard buffered plaintext.
test "EOF: drain plaintext before reporting truncation, including partial records" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.handshake(7, null);
    try pair.clientRecord(try pair.client.sendApplicationData("last data", &pair.client_out));
    try pair.input(&.{ 23, 3, 3, 0, 20, 0xaa });
    pair.server.endInput();
    try testing.expectEqualStrings("last data", (try pair.server.next()).application_data);
    pair.server.consumeApplication(9);
    try testing.expectError(error.UnexpectedEof, pair.server.next());
    try testing.expectError(error.UnexpectedEof, pair.server.next());
    try testing.expectError(error.UnexpectedEof, pair.server.write("no retry"));
    try testing.expectEqual(@as(usize, 0), pair.server.receiveBuffer().len);
}

// RFC 8446 §4.4.4, §6.1. A partial handshake plus FIN is not a connection.
test "EOF: handshake truncation is terminal" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.input(&.{22});
    pair.server.endInput();
    try testing.expectError(error.UnexpectedEof, pair.server.next());
    try testing.expect(!pair.server.isConnected());
    try testing.expectEqual(@as(usize, 0), pair.server.sendBuffer().len);
}

// RFC 8446 §6.2. A peer error alert aborts without a response alert.
test "peer alert: preserve exact alert and do not answer" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.handshake(7, null);
    _ = try pair.server.write("must not reach an aborted peer");
    try pair.clientRecord(try pair.client.sendAlert(.access_denied, &pair.client_out));
    try testing.expectError(error.PeerAlert, pair.server.next());
    try testing.expectEqual(.access_denied, pair.server.lastPeerAlert().?.description);
    try testing.expectEqual(@as(usize, 0), pair.server.sendBuffer().len);
    try testing.expectError(error.PeerAlert, pair.server.next());
}

// RFC 8446 §5.2, §6.2. Authentication failure terminates the epoch permanently.
test "fatal alert: retain pending wire bytes, then send bad_record_mac and never retry RX" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.handshake(7, null);
    _ = try pair.server.write("already queued");
    const record = try pair.client.sendApplicationData("tamper", &pair.client_out);
    pair.client_out[record.len - 1] ^= 1;
    try pair.clientRecord(record);
    try testing.expectError(error.AuthenticationFailed, pair.server.next());
    try pair.applicationOutput("already queued");
    try testing.expectError(error.AuthenticationFailed, pair.server.next());
    try pair.output(1);
    const fatal_record = (try pair.client_rb.next()).?;
    try testing.expectError(error.PeerAlert, pair.client.receiveRecord(fatal_record));
    try testing.expectEqual(.bad_record_mac, pair.client.lastPeerAlert().?.description);
    try testing.expectError(error.AuthenticationFailed, pair.server.next());
    try testing.expectEqual(@as(usize, 0), pair.server.sendBuffer().len);
}

// RFC 8446 §5.1, §6.2. Reject oversized records from the header alone.
test "oversized header: queue record_overflow without waiting for the body" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    try pair.input(&.{ 22, 3, 3, 0xff, 0xff });
    try testing.expectError(error.RecordTooLarge, pair.server.next());
    const wire = pair.server.sendBuffer();
    try testing.expectEqual(@as(usize, frame.header_len + 2), wire.len);
    const overflow_alert = try tls.alert.parse(wire[frame.header_len..]);
    try testing.expectEqual(.record_overflow, overflow_alert.description);
    try testing.expectError(error.RecordTooLarge, pair.server.next());
}

// Buffer admission is a local contract, independent of peer input.
test "init: reject short buffers and absent credentials without resources" {
    var pair: Pair = undefined;
    try pair.init(&suites);
    defer pair.deinit();
    var server: Server = undefined;
    var keys: tls.ServerHandshake.KeyPairs = try .init(.generate());
    defer keys.secureZero();
    var options: Server.Options = .{
        .cert_chain = &.{cert},
        .signer = pair.key.?.signer(),
    };
    const config: tls.ServerHandshake.Config = .{
        .keypairs = keys,
        .random = .init(@splat(0x19)),
    };
    try testing.expectError(error.BufferTooSmall, server.init(
        &options,
        config,
        .{ .record = &.{}, .out = &pair.out },
    ));
    try testing.expectError(error.BufferTooSmall, server.init(
        &options,
        config,
        .{ .record = &pair.record, .out = &.{} },
    ));
    options.cert_chain = &.{};
    try testing.expectError(error.MissingCredentials, server.init(
        &options,
        config,
        .{ .record = &pair.record, .out = &pair.out },
    ));
}

// Teardown releases the engine exactly once and never treats borrowed storage as owned.
test "deinit: idempotent before and after handshake, borrowed storage stays caller-owned" {
    for ([_]Server.State{ .handshaking, .connected }) |state| {
        var pair: Pair = undefined;
        try pair.init(&suites);
        defer pair.deinit();
        @memset(&pair.record, 0x9b);
        if (state == .connected) try pair.handshake(7, null);
        const record_copy = pair.record;
        pair.server.deinit();
        pair.server.deinit();
        try testing.expectEqualSlices(u8, &record_copy, &pair.record);
        try testing.expectError(error.Closed, pair.server.next());
        try testing.expectEqual(@as(usize, 0), pair.server.receiveBuffer().len);
    }
}

// --- Trust anchors from PEM bytes -------------------------------------------

const anchors = @import("tls_nonblocking").anchors;
const Certificate = std.crypto.Certificate;
const anchor_time = fixtures.key_capacity_time;

/// Base64 one DER certificate into `out` as a wrapped PEM block.
fn encodePem(out: []u8, der: []const u8) ![]const u8 {
    const head = "-----BEGIN CERTIFICATE-----\n";
    const tail = "-----END CERTIFICATE-----\n";
    var b64: [16384]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&b64, der);
    const rows = encoded.len / 64 + 1;
    if (out.len < head.len + encoded.len + rows + tail.len) return error.NoSpaceLeft;

    @memcpy(out[0..head.len], head);
    var n: usize = head.len;
    // Wrap at 64 columns so the decoder's ignored whitespace is exercised.
    var i: usize = 0;
    while (i < encoded.len) : (i += 64) {
        const end = @min(i + 64, encoded.len);
        @memcpy(out[n..][0 .. end - i], encoded[i..end]);
        n += end - i;
        out[n] = '\n';
        n += 1;
    }
    @memcpy(out[n..][0..tail.len], tail);
    n += tail.len;
    return out[0..n];
}

fn anchoredBundle(pem: []const u8, now_sec: i64) !Certificate.Bundle {
    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(testing.allocator);
    try testing.expectEqual(1, try anchors.addCertsFromPemBytes(
        &bundle,
        testing.allocator,
        pem,
        now_sec,
    ));
    return bundle;
}

fn derSequence(out: []u8, parts: []const []const u8) ![]const u8 {
    std.debug.assert(parts.len <= 3);
    var length: usize = 0;
    for (parts) |part| length += part.len;
    std.debug.assert(length <= std.math.maxInt(u16));
    var writer: std.Io.Writer = .fixed(out);
    try writer.writeByte(0x30);
    if (length < 0x80) {
        try writer.writeByte(@intCast(length));
    } else if (length <= std.math.maxInt(u8)) {
        try writer.writeByte(0x81);
        try writer.writeByte(@intCast(length));
    } else {
        try writer.writeByte(0x82);
        try writer.writeByte(@intCast(length >> 8));
        try writer.writeByte(@truncate(length));
    }
    for (parts) |part| try writer.writeAll(part);
    return writer.buffered();
}

test "anchors: an empty signature BIT STRING returns InvalidCertificateDer" {
    const source = &fixtures.key_capacity_root_der;
    const outer = try Certificate.der.Element.parse(source, 0);
    const tbs = try Certificate.der.Element.parse(source, outer.slice.start);
    const algorithm = try Certificate.der.Element.parse(source, tbs.slice.end);
    var der_buf: [8192]u8 = undefined;
    const malformed = try derSequence(&der_buf, &.{
        source[outer.slice.start..algorithm.slice.end],
        "\x03\x00",
    });
    var pem_buf: [16384]u8 = undefined;
    const pem = try encodePem(&pem_buf, malformed);
    try testing.expectError(error.InvalidCertificateDer, anchors.build(
        testing.allocator,
        pem,
        anchor_time,
    ));
}

test "anchors: empty mandatory nested fields return InvalidCertificateDer" {
    const source = &fixtures.key_capacity_root_der;
    const outer = try Certificate.der.Element.parse(source, 0);
    const tbs = try Certificate.der.Element.parse(source, outer.slice.start);
    const algorithm = try Certificate.der.Element.parse(source, tbs.slice.end);
    var der_buf: [8192]u8 = undefined;
    var tbs_buf: [8192]u8 = undefined;
    var pem_buf: [16384]u8 = undefined;
    const empty_algorithm = try derSequence(&der_buf, &.{
        source[outer.slice.start..tbs.slice.end],
        "\x30\x00",
        source[algorithm.slice.end..outer.slice.end],
    });
    try testing.expectError(error.InvalidCertificateDer, anchors.build(
        testing.allocator,
        try encodePem(&pem_buf, empty_algorithm),
        anchor_time,
    ));
    try testing.expectEqual(@as(u8, 0xa0), source[tbs.slice.start]);
    for ([_]usize{ 4, 6 }) |field_index| {
        var offset = tbs.slice.start;
        for (0..field_index) |_| {
            const child = try Certificate.der.Element.parse(source, offset);
            offset = child.slice.end;
        }
        const field = try Certificate.der.Element.parse(source, offset);
        const changed_tbs = try derSequence(&tbs_buf, &.{
            source[tbs.slice.start..offset],
            "\x30\x00",
            source[field.slice.end..tbs.slice.end],
        });
        const malformed = try derSequence(&der_buf, &.{
            changed_tbs,
            source[tbs.slice.end..outer.slice.end],
        });
        try testing.expectError(error.InvalidCertificateDer, anchors.build(
            testing.allocator,
            try encodePem(&pem_buf, malformed),
            anchor_time,
        ));
    }
}

// RFC 5280 §4.1.2 — an explicit version precedes six mandatory TBS fields.
test "anchors: an explicit version requires seven TBS fields" {
    const der = [_]u8{
        0x30, 0x17, 0x30, 0x0f, 0xa0, 0x03, 0x02, 0x01, 0x02,
        0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
        0x00, 0x30, 0x00, 0x03, 0x02, 0x00, 0x00,
    };
    var pem_buf: [128]u8 = undefined;
    const pem = try encodePem(&pem_buf, &der);
    try testing.expectError(
        error.InvalidCertificateDer,
        anchors.build(testing.allocator, pem, anchor_time),
    );
}

test "anchors: 256 outer certificate fields return InvalidCertificateDer" {
    var der: [528]u8 = undefined;
    @memcpy(der[0..4], &[_]u8{ 0x30, 0x82, 0x02, 0x0c });
    @memcpy(der[4..6], &[_]u8{ 0x30, 0x0c });
    for (0..261) |i| {
        der[6 + 2 * i] = 0x05;
        der[7 + 2 * i] = 0;
    }
    var pem_buf: [800]u8 = undefined;
    const pem = try encodePem(&pem_buf, &der);
    try testing.expectError(
        error.InvalidCertificateDer,
        anchors.build(testing.allocator, pem, anchor_time),
    );
}

test "anchors.build is owned, nonempty, and atomic" {
    var pem_buf: [24576]u8 = undefined;
    const pem = try encodePem(&pem_buf, &fixtures.key_capacity_root_der);
    var bundle = try anchors.build(testing.allocator, pem, anchor_time);
    defer bundle.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), bundle.map.count());
    try testing.expectError(
        error.NoTrustAnchors,
        anchors.build(testing.allocator, "not a certificate", anchor_time),
    );

    var bad_buf: [128]u8 = undefined;
    const bad = try encodePem(&bad_buf, &.{ 0xde, 0xad, 0xbe, 0xef });
    var combined: [32768]u8 = undefined;
    @memcpy(combined[0..pem.len], pem);
    @memcpy(combined[pem.len..][0..bad.len], bad);
    try testing.expectError(
        error.InvalidCertificateDer,
        anchors.build(testing.allocator, combined[0 .. pem.len + bad.len], anchor_time),
    );
}

// RFC 7468 §2, RFC 5280 §6.1 — an anchor supplied as PEM bytes authenticates a
// chain the same way a path-loaded one does, with no filesystem access.
test "anchors: PEM bytes anchor a chain" {
    var pem_buf: [24576]u8 = undefined;
    const pem = try encodePem(&pem_buf, &fixtures.key_capacity_root_der);
    var bundle = try anchoredBundle(pem, anchor_time);
    defer bundle.deinit(testing.allocator);

    var msg_buf: [4096]u8 = undefined;
    const msg = try tls.certificate.encode(&msg_buf, &.{
        &fixtures.key_capacity_leaf_der,
        &fixtures.key_capacity_root_der,
    });
    var policy: tls.certificate.Policy = .init;
    policy.bundle = &bundle;
    policy.host_name = "capacity.test";
    policy.now_sec = anchor_time;
    const public_key = try tls.certificate.parse(msg, policy);
    try testing.expect(public_key.len > 0);
}

// RFC 5280 §6.1 — an anchor that did not issue the chain cannot authenticate it.
test "anchors: a different anchor rejects the same chain" {
    var pem_buf: [24576]u8 = undefined;
    const pem = try encodePem(&pem_buf, &fixtures.key_capacity_leaf_der);
    var bundle = try anchoredBundle(pem, anchor_time);
    defer bundle.deinit(testing.allocator);

    var msg_buf: [4096]u8 = undefined;
    const msg = try tls.certificate.encode(&msg_buf, &.{
        &fixtures.key_capacity_leaf_der,
        &fixtures.key_capacity_root_der,
    });
    var policy: tls.certificate.Policy = .init;
    policy.bundle = &bundle;
    policy.host_name = "capacity.test";
    policy.now_sec = anchor_time;
    try testing.expectError(error.CertificateIssuerNotFound, tls.certificate.parse(msg, policy));
}

// parseCert skips an expired anchor silently, so the count is the only signal
// that the trust store came up empty.
test "anchors: an expired anchor adds nothing" {
    var pem_buf: [24576]u8 = undefined;
    const pem = try encodePem(&pem_buf, &fixtures.key_capacity_root_der);
    var bundle: Certificate.Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    try testing.expectEqual(0, try anchors.addCertsFromPemBytes(
        &bundle,
        testing.allocator,
        pem,
        4_000_000_000,
    ));
    try testing.expectEqual(@as(usize, 0), bundle.bytes.items.len);
}

test "anchors: no markers, a truncated block, and bad base64" {
    var bundle: Certificate.Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    try testing.expectEqual(0, try anchors.addCertsFromPemBytes(
        &bundle,
        testing.allocator,
        "not a certificate",
        anchor_time,
    ));
    try testing.expectError(error.MissingEndCertificateMarker, anchors.addCertsFromPemBytes(
        &bundle,
        testing.allocator,
        "-----BEGIN CERTIFICATE-----\nMIIB\n",
        anchor_time,
    ));
    try testing.expectError(error.InvalidPemBase64, anchors.addCertsFromPemBytes(
        &bundle,
        testing.allocator,
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        anchor_time,
    ));
}

// A failure on a later block must not invalidate the anchors added before it.
// The error path truncates only the block that failed, and that block never got
// a map entry. Rolling the whole buffer back instead would leave the map
// pointing past the end of `bytes`, which the next lookup slices.
test "anchors: a failed block leaves earlier anchors usable" {
    var pem_buf: [24576]u8 = undefined;
    var bad: [128]u8 = undefined;
    const good = try encodePem(&pem_buf, &fixtures.key_capacity_root_der);
    // Base64 decodes cleanly; the DER is not a certificate, so the failure lands
    // in parseCert rather than in the decoder.
    const garbage_der = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const garbage = try encodePem(&bad, &garbage_der);

    var combined: [32768]u8 = undefined;
    @memcpy(combined[0..good.len], good);
    @memcpy(combined[good.len..][0..garbage.len], garbage);
    const pem = combined[0 .. good.len + garbage.len];

    var bundle: Certificate.Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    if (anchors.addCertsFromPemBytes(&bundle, testing.allocator, pem, anchor_time)) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}
    try testing.expectEqual(fixtures.key_capacity_root_der.len, bundle.bytes.items.len);

    var msg_buf: [4096]u8 = undefined;
    const msg = try tls.certificate.encode(&msg_buf, &.{
        &fixtures.key_capacity_leaf_der,
        &fixtures.key_capacity_root_der,
    });
    var policy: tls.certificate.Policy = .init;
    policy.bundle = &bundle;
    policy.host_name = "capacity.test";
    policy.now_sec = anchor_time;
    const public_key = try tls.certificate.parse(msg, policy);
    try testing.expect(public_key.len > 0);
}

// --- Client transport ------------------------------------------------------

const TransportClient = @import("tls_nonblocking").Client;

/// One client transport against one server transport, no socket in between.
const Wire = struct {
    client: TransportClient,
    server: Server,
    key: PrivateKey,
    record: [tls.RecordBuffer.min_storage]u8,
    out: [frame.max_wire_record_len]u8,
    reassembly: [tls.ServerHandshake.ch_reassembly_buffer_size]u8,
    client_record: [tls.RecordBuffer.min_storage]u8,
    client_out: [frame.max_wire_record_len]u8,
    client_reassembly: [tls.ClientHandshake.recommended_handshake_storage]u8,

    fn init(self: *Wire) !void {
        self.key = try .fromP256Scalar(scalar);
        errdefer self.key.deinit();
        try self.client.init(&.{
            .insecure_no_chain_anchor = true,
            .host_name = "ztls.server.test",
            .now_sec = 1_790_000_000,
            .alpn = &.{"h2"},
        }, .{
            .keypairs = try .init(.generate()),
            .host_name = "ztls.server.test",
            .now_sec = 1_790_000_000,
            .random = .init(@splat(0x31)),
            .alpn_protocols = &.{"h2"},
            .reassembly = &self.client_reassembly,
        }, .{ .record = &self.client_record, .out = &self.client_out });
        errdefer self.client.deinit();
        try self.server.init(&.{
            .handshake = .{
                .supported_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"h2"},
            },
            .cert_chain = &.{cert},
            .signer = self.key.signer(),
        }, .{
            .keypairs = try .init(.generate()),
            .random = .init(@splat(0x72)),
            .reassembly = &self.reassembly,
        }, .{ .record = &self.record, .out = &self.out });
    }

    fn deinit(self: *Wire) void {
        self.server.deinit();
        self.client.deinit();
        self.key.deinit();
        self.* = undefined;
    }

    /// Move every byte each transport is willing to hand over, one record at a time.
    fn move(self: *Wire) void {
        const cw = self.client.sendBuffer();
        if (cw.len != 0) {
            const dest = self.server.receiveBuffer();
            const n = @min(cw.len, dest.len);
            @memcpy(dest[0..n], cw[0..n]);
            self.server.received(n);
            self.client.sent(n);
        }
        const sw = self.server.sendBuffer();
        if (sw.len != 0) {
            const dest = self.client.receiveBuffer();
            const n = @min(sw.len, dest.len);
            @memcpy(dest[0..n], sw[0..n]);
            self.client.received(n);
            self.server.sent(n);
        }
    }

    fn handshake(self: *Wire) !void {
        var client_done = false;
        var server_done = false;
        for (0..10_000) |_| {
            self.move();
            if (!client_done) switch (try self.client.next()) {
                .handshake_complete => client_done = true,
                .need_input, .need_output, .progress => {},
                else => return error.UnexpectedClientEvent,
            };
            if (!server_done) switch (try self.server.next()) {
                .handshake_complete => server_done = true,
                .need_input, .need_output, .progress => {},
                else => return error.UnexpectedServerEvent,
            };
            if (client_done and server_done) return;
        }
        return error.HandshakeStuck;
    }

    fn clientEvent(self: *Wire) !TransportClient.Event {
        for (0..10_000) |_| {
            self.move();
            switch (try self.client.next()) {
                .need_input, .need_output, .progress => continue,
                else => |event| return event,
            }
        }
        return error.ClientStuck;
    }

    fn serverEvent(self: *Wire) !Server.Event {
        for (0..10_000) |_| {
            self.move();
            switch (try self.server.next()) {
                .need_input, .need_output, .progress => continue,
                else => |event| return event,
            }
        }
        return error.ServerStuck;
    }
};

// RFC 8446 §4.4.4, §3.1 — a caller-driven client completes the handshake with
// the caller-driven server and both report the ALPN protocol.
test "client transport: handshake completes and reports ALPN" {
    var w: Wire = undefined;
    try w.init();
    defer w.deinit();
    try w.handshake();
    try testing.expect(w.client.isConnected());
    try testing.expect(w.server.isConnected());
    try testing.expectEqualStrings("h2", w.client.selectedAlpn().?);
    try testing.expectEqualStrings("h2", w.server.selectedAlpn().?);
}

// RFC 8446 §5.1 — application records cross in both directions once connected.
test "client transport: one message each way" {
    var w: Wire = undefined;
    try w.init();
    defer w.deinit();
    try w.handshake();

    try testing.expectEqual(@as(usize, 4), try w.client.write("ping"));
    switch (try w.serverEvent()) {
        .application_data => |bytes| {
            try testing.expectEqualStrings("ping", bytes);
            w.server.consumeApplication(bytes.len);
        },
        else => return error.UnexpectedServerEvent,
    }

    try testing.expectEqual(@as(usize, 4), try w.server.write("pong"));
    switch (try w.clientEvent()) {
        .application_data => |bytes| {
            try testing.expectEqualStrings("pong", bytes);
            w.client.consumeApplication(bytes.len);
        },
        else => return error.UnexpectedClientEvent,
    }
}

// A partial write is normal: the caller acks bytes the socket accepted.
test "client transport: accepts a one-byte-at-a-time drain" {
    var w: Wire = undefined;
    try w.init();
    defer w.deinit();
    try w.handshake();

    try testing.expectEqual(@as(usize, 4), try w.client.write("ping"));
    while (w.client.sendBuffer().len != 0) {
        const before = w.client.sendBuffer().len;
        const dest = w.server.receiveBuffer();
        @memcpy(dest[0..1], w.client.sendBuffer()[0..1]);
        w.server.received(1);
        w.client.sent(1);
        try testing.expectEqual(before - 1, w.client.sendBuffer().len);
    }
    switch (try w.serverEvent()) {
        .application_data => |bytes| try testing.expectEqualStrings("ping", bytes),
        else => return error.UnexpectedServerEvent,
    }
}

// RFC 8446 §6.1 — close_notify ends RX only; the peer can still send, and the
// two events stay distinguishable at the client transport.
test "client transport: close_notify is not closed" {
    var w: Wire = undefined;
    try w.init();
    defer w.deinit();
    try w.handshake();

    try w.server.closeWrite();
    try testing.expectEqual(TransportClient.Event.close_notify, try w.clientEvent());
    try testing.expectEqual(TransportClient.Event.closed, try w.clientEvent());
    // The client's TX is still open after its RX ended.
    try testing.expectEqual(@as(usize, 4), try w.client.write("ping"));
    switch (try w.serverEvent()) {
        .application_data => |bytes| try testing.expectEqualStrings("ping", bytes),
        else => return error.UnexpectedServerEvent,
    }
}

// RFC 8446 §6.1 — the same distinction in the other direction: the client's
// close_notify ends the server's RX, and the server can still answer.
test "server transport: close_notify is not closed" {
    var w: Wire = undefined;
    try w.init();
    defer w.deinit();
    try w.handshake();

    try w.client.closeWrite();
    try testing.expectEqual(Server.Event.close_notify, try w.serverEvent());
    try testing.expectEqual(Server.Event.closed, try w.serverEvent());
    try testing.expectEqual(@as(usize, 4), try w.server.write("pong"));
}

// std's Bundle.parseCert walks a certificate with unchecked reads, so a short
// or truncated DER panics in Debug and reads out of bounds in ReleaseFast.
// Caller-supplied PEM reaches it, so the outer TLV is rejected first. Each case
// below panicked through the loader before the guard existed.
test "anchors: structurally invalid DER is an error, not a crash" {
    const short_sequence = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    const one_byte = [_]u8{0x30};
    const no_body: [0]u8 = .{};
    const length_past_end = [_]u8{ 0x30, 0x84, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 };
    const not_a_sequence = [_]u8{ 0x02, 0x01, 0x00 };
    const cases = [_][]const u8{
        &short_sequence,
        &one_byte,
        &no_body,
        &length_past_end,
        &not_a_sequence,
    };
    for (cases) |der| {
        var pem_buf: [128]u8 = undefined;
        const pem = try encodePem(&pem_buf, der);
        var bundle: Certificate.Bundle = .empty;
        defer bundle.deinit(testing.allocator);
        try testing.expectError(error.InvalidCertificateDer, anchors.addCertsFromPemBytes(
            &bundle,
            testing.allocator,
            pem,
            anchor_time,
        ));
        try testing.expectEqual(@as(usize, 0), bundle.bytes.items.len);
    }
}

test "anchors: trailing bytes after the certificate are rejected" {
    var pem_buf: [32768]u8 = undefined;
    var der_buf: [8192]u8 = undefined;
    const der_len = fixtures.key_capacity_root_der.len;
    @memcpy(der_buf[0..der_len], &fixtures.key_capacity_root_der);
    der_buf[der_len] = 0x00;
    const pem = try encodePem(&pem_buf, der_buf[0 .. der_len + 1]);

    var bundle: Certificate.Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    try testing.expectError(error.InvalidCertificateDer, anchors.addCertsFromPemBytes(
        &bundle,
        testing.allocator,
        pem,
        anchor_time,
    ));
}

// The guard is the only thing between caller bytes and std's unchecked parser,
// so pin it with random input rather than three crafted cases. Before the guard
// this panicked on the first short block; with it removed, it panics here.
test "anchors: random DER never panics" {
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const random = prng.random();
    var der_buf: [96]u8 = undefined;
    var pem_buf: [256]u8 = undefined;

    for (0..4_000) |_| {
        const len = random.uintLessThan(usize, der_buf.len + 1);
        random.bytes(der_buf[0..len]);
        // Bias toward the shape that reaches std's parser: a SEQUENCE prefix.
        if (len >= 2 and random.boolean()) {
            der_buf[0] = 0x30;
            der_buf[1] = @intCast(len - 2);
        }
        const pem = try encodePem(&pem_buf, der_buf[0..len]);

        var bundle: Certificate.Bundle = .empty;
        defer bundle.deinit(testing.allocator);
        _ = anchors.addCertsFromPemBytes(
            &bundle,
            testing.allocator,
            pem,
            anchor_time,
        ) catch |err| {
            try testing.expect(err == error.InvalidCertificateDer);
            try testing.expectEqual(@as(usize, 0), bundle.bytes.items.len);
            continue;
        };
        // A structurally valid certificate would have to parse, not panic.
        try testing.expectEqual(@as(usize, 0), bundle.bytes.items.len);
    }
}

// A blocking reader has a finite destination, so it takes a prefix and comes
// back: a partial consume must keep the tail deliverable, with no copy on the
// caller's side.
test "server transport: partial consume keeps the tail" {
    var w: Wire = undefined;
    try w.init();
    defer w.deinit();
    try w.handshake();

    try testing.expectEqual(@as(usize, 8), try w.client.write("abcdefgh"));
    switch (try w.serverEvent()) {
        .application_data => |bytes| {
            try testing.expectEqualStrings("abcdefgh", bytes);
            w.server.consumeApplication(3);
        },
        else => return error.UnexpectedServerEvent,
    }
    switch (try w.server.next()) {
        .application_data => |bytes| {
            try testing.expectEqualStrings("defgh", bytes);
            w.server.consumeApplication(bytes.len);
        },
        else => return error.UnexpectedServerEvent,
    }
}
