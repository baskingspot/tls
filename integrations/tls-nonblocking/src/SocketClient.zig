//! A blocking TLS 1.3 client over a caller-owned `std.Io.net.Stream`.
//!
//! The adapter owns TLS buffers and an optional PEM trust bundle. The caller
//! owns the socket, its lifetime, and ALPN policy. All calls on one connection
//! must be serial. Initialize the value in its final location and do not move
//! or copy it while initialized.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const secureZero = std.crypto.secureZero;
const testing = std.testing;
const net = Io.net;

const tls = @import("tls");
const anchors = @import("anchors.zig");
const Client = @import("Client.zig");
const Handshake = tls.ClientHandshake;
const Bundle = std.crypto.Certificate.Bundle;
const SocketClient = @This();

pub const Options = struct {
    /// PEM trust anchors. The adapter parses and owns the resulting bundle.
    /// Null trusts nothing unless `insecure_no_chain_anchor` is set.
    ca_pem: ?[]const u8 = null,
    /// Test-only chain-anchor opt-out. Hostname verification still runs.
    /// Ignored when `ca_pem` is present.
    insecure_no_chain_anchor: bool = false,
    /// Name for SNI and hostname verification: a DNS name or an address
    /// literal (RFC 9525 §6.2.1). Borrowed until `deinit`.
    host_name: []const u8,
    /// Caller clock for certificate validity checks.
    now_sec: i64,
    /// ALPN protocols to offer. The slice, entries, and bytes are borrowed
    /// until `deinit`. The adapter reports the selection without enforcing it.
    alpn: []const []const u8 = &.{},
    /// Absolute monotonic deadline for read waits, including the handshake.
    /// Null waits indefinitely. This does not bound socket writes.
    deadline_ns: ?i96 = null,
};

pub const TransportReadError = net.Stream.Reader.Error;
pub const TransportWriteError = net.Stream.Writer.Error;
pub const DeadlineError = error{
    /// The absolute monotonic deadline expired before input arrived.
    TimedOut,
    /// Future read deadlines require `Io.Operation.net_read`, added in 0.17.
    /// An already-expired deadline still reports `TimedOut` on Zig 0.16.
    DeadlineUnsupported,
};
pub const ReadError = Client.Error || TransportReadError || TransportWriteError ||
    DeadlineError || error{ TransportClosed, NoReadCompletion };
pub const WriteError = Client.Error || TransportWriteError || error{TransportClosed};
pub const InitError = Client.InitError || ReadError || anchors.BuildError ||
    tls.p256.Error || Io.RandomSecureError;

const Life = enum { empty, initialized };
const ReceiveResult = enum { received, eof, retry };

io: Io,
allocator: Allocator,
socket: net.Stream,
client: Client = undefined,
record: [tls.RecordBuffer.min_storage]u8 = undefined,
out: [tls.frame.max_wire_record_len]u8 = undefined,
reassembly: [Handshake.recommended_handshake_storage]u8 = undefined,
bundle: Bundle = .empty,
owns_bundle: bool = false,
life: Life = .empty,
input: Io.Reader = undefined,
output: Io.Writer = undefined,
deadline_ns: ?i96 = null,
expired_flag: bool = false,
read_error: ?ReadError = null,
write_error: ?WriteError = null,
latched_peer_alert: ?tls.alert.Alert = null,
pinned: *SocketClient = undefined,

/// Complete a TLS handshake over `socket`. The socket remains caller-owned on
/// success and failure. A failed init releases every acquired TLS resource;
/// `deinit` is safe afterward, and the caller can still close or reuse `socket`.
pub fn init(
    self: *SocketClient,
    allocator: Allocator,
    io: Io,
    socket: net.Stream,
    options: Options,
) InitError!void {
    self.* = .{
        .io = io,
        .allocator = allocator,
        .socket = socket,
        .deadline_ns = options.deadline_ns,
        .pinned = self,
    };
    errdefer self.deinit();

    if (options.ca_pem) |pem| {
        self.bundle = try anchors.build(allocator, pem, options.now_sec);
        self.owns_bundle = true;
    }

    var keypairs: Handshake.KeyPairs = try .init(.generate());
    defer keypairs.secureZero();
    var random: tls.Random = .empty;
    try io.randomSecure(&random.data);
    defer random.secureZero();

    const ca: ?*const Bundle = if (self.owns_bundle) &self.bundle else null;
    try self.client.init(&.{
        .ca = ca,
        .insecure_no_chain_anchor = options.insecure_no_chain_anchor,
        .host_name = options.host_name,
        .now_sec = options.now_sec,
        .alpn = options.alpn,
    }, .{
        .keypairs = keypairs,
        .host_name = options.host_name,
        .now_sec = options.now_sec,
        .random = random,
        .alpn_protocols = options.alpn,
        .reassembly = &self.reassembly,
    }, .{ .record = &self.record, .out = &self.out });
    self.life = .initialized;

    self.input = .{
        .vtable = &.{ .stream = stream, .readVec = readVec },
        .buffer = &.{},
        .seek = 0,
        .end = 0,
    };
    self.output = .{
        .vtable = &.{ .drain = drain, .flush = flush, .rebase = rebase },
        .buffer = &.{},
        .end = 0,
    };
    try self.handshake();
}

/// Release TLS state and owned trust anchors. This never closes the socket.
/// It is idempotent, including after a failed `init`.
// ziglint-ignore: Z030 -- failed-init diagnostics remain inspectable; the socket is borrowed.
pub fn deinit(self: *SocketClient) void {
    if (self.life == .empty) {
        if (self.owns_bundle) self.bundle.deinit(self.allocator);
        self.owns_bundle = false;
        return;
    }
    assert(self.pinned == self);
    self.client.deinit();
    self.life = .empty;
    if (self.owns_bundle) self.bundle.deinit(self.allocator);
    self.owns_bundle = false;
    secureZero(u8, &self.record);
    secureZero(u8, &self.out);
    secureZero(u8, &self.reassembly);
}

pub fn reader(self: *SocketClient) *Io.Reader {
    assert(self.life == .initialized);
    assert(self.pinned == self);
    return &self.input;
}

pub fn writer(self: *SocketClient) *Io.Writer {
    assert(self.life == .initialized);
    assert(self.pinned == self);
    return &self.output;
}

/// The authenticated ALPN selection, borrowed until `deinit`. Requiring a
/// particular protocol is caller policy.
pub fn selectedAlpn(self: *const SocketClient) ?[]const u8 {
    return self.client.selectedAlpn();
}

/// The exact peer alert after `error.PeerAlert`, including a failed handshake.
pub fn peerAlert(self: *const SocketClient) ?tls.alert.Alert {
    return self.latched_peer_alert;
}

/// Why the most recent `reader` call failed with `ReadFailed`.
/// A new reader call clears this value before it advances TLS.
pub fn readError(self: *const SocketClient) ?ReadError {
    return self.read_error;
}

/// Why the most recent `writer` or `closeWrite` call failed with `WriteFailed`
/// or an explicit error. The value is stale after a successful call.
pub fn writeError(self: *const SocketClient) ?WriteError {
    return self.write_error;
}

/// Set the absolute monotonic deadline for subsequent read waits and clear the
/// previous expiry indication. Socket writes are not deadline-bounded.
pub fn setDeadline(self: *SocketClient, absolute_ns: ?i96) void {
    self.deadline_ns = absolute_ns;
    self.expired_flag = false;
}

/// True only when the last deadline failure was `TimedOut`. Cancellation and
/// `DeadlineUnsupported` do not set this flag.
pub fn expired(self: *const SocketClient) bool {
    return self.expired_flag;
}

/// Queue and send `close_notify` after accepted application data. RX remains
/// open and the caller still owns the socket. No write deadline is applied.
pub fn closeWrite(self: *SocketClient) WriteError!void {
    return self.closeWriteFallible() catch |err| self.rememberWriteError(err);
}

fn closeWriteFallible(self: *SocketClient) WriteError!void {
    while (true) {
        try self.flushSend();
        self.client.closeWrite() catch |err| switch (err) {
            error.WouldBlock => {
                try self.makeWriteProgress();
                continue;
            },
            else => {
                self.capturePeerAlert(err);
                return err;
            },
        };
        try self.flushSend();
        return;
    }
}

fn stream(
    erased: *Io.Reader,
    destination: *Io.Writer,
    limit: Io.Limit,
) Io.Reader.StreamError!usize {
    const self: *SocketClient = @alignCast(@fieldParentPtr("input", erased));
    self.read_error = null;
    const plaintext = (self.nextApplication() catch |err|
        return self.failRead(err)) orelse return error.EndOfStream;
    const accepted = try destination.write(limit.sliceConst(plaintext));
    self.client.consumeApplication(accepted);
    return accepted;
}

fn readVec(erased: *Io.Reader, iovecs: [][]u8) Io.Reader.Error!usize {
    const self: *SocketClient = @alignCast(@fieldParentPtr("input", erased));
    self.read_error = null;
    const plaintext = (self.nextApplication() catch |err|
        return self.failRead(err)) orelse return error.EndOfStream;
    const copied = copyInto(iovecs, plaintext);
    self.client.consumeApplication(copied);
    return copied;
}

fn drain(
    erased: *Io.Writer,
    data: []const []const u8,
    splat: usize,
) Io.Writer.Error!usize {
    const self: *SocketClient = @alignCast(@fieldParentPtr("output", erased));
    return self.push(erased, data, splat) catch |err| self.failWrite(err);
}

fn flush(erased: *Io.Writer) Io.Writer.Error!void {
    const self: *SocketClient = @alignCast(@fieldParentPtr("output", erased));
    self.flushSend() catch |err| return self.failWrite(err);
}

fn rebase(_: *Io.Writer, _: usize, _: usize) Io.Writer.Error!void {
    // The direct writer has no owned plaintext staging buffer to rebase.
}

fn nextApplication(self: *SocketClient) ReadError!?[]const u8 {
    while (true) {
        const event = try self.step();
        switch (event) {
            .application_data => |bytes| return bytes,
            .closed => return null,
            .close_notify,
            .handshake_complete,
            .progress,
            .key_update,
            .new_session_ticket,
            => {},
            .need_output => try self.flushSend(),
            .need_input => switch (try self.readSocket()) {
                .received, .retry => {},
                .eof => self.client.endInput(),
            },
        }
    }
}

fn handshake(self: *SocketClient) ReadError!void {
    while (true) {
        switch (try self.step()) {
            .handshake_complete => return,
            // Handshake completion must precede application data. Reject an
            // out-of-order event rather than spin on its pinned plaintext.
            .application_data => return error.UnexpectedRecord,
            .need_output => try self.flushSend(),
            .need_input => switch (try self.readSocket()) {
                .received, .retry => {},
                .eof => self.client.endInput(),
            },
            .progress, .key_update, .new_session_ticket => {},
            .close_notify, .closed => return error.UnexpectedEof,
        }
    }
}

fn step(self: *SocketClient) Client.Error!Client.Event {
    return self.client.next() catch |err| {
        self.capturePeerAlert(err);
        self.bestEffortFailureOutput(err);
        return err;
    };
}

fn capturePeerAlert(self: *SocketClient, err: Client.Error) void {
    if (err == error.PeerAlert) {
        if (self.client.lastPeerAlert()) |peer_alert|
            self.latched_peer_alert = peer_alert;
    }
}

/// A local failure can leave a record or fatal alert pending. Drain it without
/// replacing the protocol error that the caller needs to see.
fn bestEffortFailureOutput(self: *SocketClient, err: Client.Error) void {
    if (err == error.PeerAlert or err == error.Closed) return;
    self.flushSend() catch |write_err| {
        self.write_error = write_err;
        return;
    };
    if (self.client.sendBuffer().len != 0) return;
    _ = self.client.next() catch |retry_err| assert(retry_err == err);
    self.flushSend() catch |write_err| {
        self.write_error = write_err;
    };
}

fn push(
    self: *SocketClient,
    writer_interface: *Io.Writer,
    data: []const []const u8,
    splat: usize,
) WriteError!usize {
    var total: usize = 0;
    const buffered = writer_interface.buffered();
    if (buffered.len != 0) {
        total += try self.pushSlice(buffered);
    }
    for (data, 0..) |slice, index| {
        const repeat = if (index + 1 == data.len) splat else 1;
        for (0..repeat) |_| total += try self.pushSlice(slice);
    }
    return writer_interface.consume(total);
}

fn pushSlice(self: *SocketClient, plaintext: []const u8) WriteError!usize {
    var rest = plaintext;
    while (rest.len != 0) {
        const accepted = self.client.write(rest) catch |err| switch (err) {
            error.WouldBlock => {
                try self.makeWriteProgress();
                continue;
            },
            else => {
                self.capturePeerAlert(err);
                return err;
            },
        };
        rest = rest[accepted..];
        try self.flushSend();
    }
    return plaintext.len;
}

fn makeWriteProgress(self: *SocketClient) WriteError!void {
    try self.flushSend();
    if (self.client.sendBuffer().len != 0) return;
    const event = self.client.next() catch |err| {
        self.capturePeerAlert(err);
        return err;
    };
    if (event == .need_output) try self.flushSend();
}

fn readSocket(self: *SocketClient) ReadError!ReceiveResult {
    const buffer = self.client.receiveBuffer();
    if (buffer.len == 0) {
        try self.flushSend();
        return .retry;
    }
    if (self.deadline_ns) |deadline| return self.readSocketDeadline(buffer, deadline);

    const read = try transportRead(self.io, self.socket.socket.handle, buffer);
    if (read == 0) return .eof;
    self.client.received(read);
    return .received;
}

fn readSocketDeadline(
    self: *SocketClient,
    buffer: []u8,
    deadline: i96,
) ReadError!ReceiveResult {
    const now = Io.Clock.awake.now(self.io).nanoseconds;
    if (now >= deadline) return self.deadlineExpired();
    const give_up: Io.Clock.Timestamp = Io.Timestamp
        .fromNanoseconds(deadline)
        .withClock(Io.Clock.awake);

    // Zig 0.16 has no portable vectored net_read operation in Io.Batch. Keep
    // the compile-time probe so both supported compilers analyze their own API.
    if (comptime @hasField(Io.Operation, "net_read")) {
        var storage: [1]Io.Operation.Storage = undefined;
        var batch: Io.Batch = .init(&storage);
        var iovecs: [1][]u8 = .{buffer};
        _ = batch.add(.{ .net_read = .{
            .socket_handle = self.socket.socket.handle,
            .data = &iovecs,
        } });
        const wait_error: ?Io.Batch.AwaitConcurrentError = wait: {
            batch.awaitConcurrent(self.io, .{ .deadline = give_up }) catch |err|
                break :wait err;
            break :wait null;
        };
        // Timeout does not reap an evented read. Preserve successful racing
        // completions before this batch's stack storage goes out of scope.
        batch.cancel(self.io);
        while (batch.next()) |completion| {
            switch (completion.result) {
                .net_read => |result| {
                    const ready = try result;
                    if (ready.data_len != 0) self.client.received(ready.data_len);
                    if (wait_error != null and wait_error.? == error.Canceled) {
                        return error.Canceled;
                    }
                    if (ready.data_len == 0) return .eof;
                    return .received;
                },
                else => unreachable,
            }
        }
        if (wait_error) |err| return self.deadlineWaitError(err);
        return error.NoReadCompletion;
    }
    return error.DeadlineUnsupported;
}

fn deadlineWaitError(
    self: *SocketClient,
    err: Io.Batch.AwaitConcurrentError,
) ReadError {
    return switch (err) {
        error.Timeout => self.deadlineExpired(),
        error.Canceled => error.Canceled,
        error.ConcurrencyUnavailable => error.DeadlineUnsupported,
    };
}

fn deadlineExpired(self: *SocketClient) error{TimedOut} {
    self.expired_flag = true;
    return error.TimedOut;
}

fn failRead(self: *SocketClient, cause: ReadError) error{ReadFailed} {
    self.read_error = cause;
    return error.ReadFailed;
}

fn rememberWriteError(self: *SocketClient, cause: WriteError) WriteError {
    self.write_error = cause;
    return cause;
}

fn failWrite(self: *SocketClient, cause: WriteError) error{WriteFailed} {
    self.write_error = cause;
    return error.WriteFailed;
}

const direct_stream_io = @hasField(Io.VTable, "netRead");

fn transportRead(
    io: Io,
    handle: net.Socket.Handle,
    buffer: []u8,
) TransportReadError!usize {
    var data: [1][]u8 = .{buffer};
    if (comptime direct_stream_io) {
        return io.vtable.netRead(io.userdata, handle, &data);
    }
    const result = try io.operate(.{ .net_read = .{
        .socket_handle = handle,
        .data = &data,
    } });
    const read = try result.net_read;
    return read.data_len;
}

/// Acknowledge every accepted ciphertext prefix before another socket write.
/// A later error therefore cannot duplicate an already transmitted prefix.
fn flushSend(self: *SocketClient) WriteError!void {
    while (self.client.sendBuffer().len != 0) {
        const wire = self.client.sendBuffer();
        const written = try transportWrite(self.io, self.socket.socket.handle, wire);
        if (written == 0) return error.TransportClosed;
        self.client.sent(written);
    }
}

fn transportWrite(
    io: Io,
    handle: net.Socket.Handle,
    bytes: []const u8,
) TransportWriteError!usize {
    const data: [1][]const u8 = .{bytes};
    if (comptime direct_stream_io) {
        return io.vtable.netWrite(io.userdata, handle, "", &data, 1);
    }
    const result = try io.operate(.{ .net_write = .{
        .socket_handle = handle,
        .header = "",
        .data = &data,
        .splat = 1,
    } });
    const written = try result.net_write;
    return written;
}

fn copyInto(iovecs: [][]u8, bytes: []const u8) usize {
    var copied: usize = 0;
    for (iovecs) |iovec| {
        if (copied == bytes.len) break;
        const count = @min(iovec.len, bytes.len - copied);
        @memcpy(iovec[0..count], bytes[copied..][0..count]);
        copied += count;
    }
    return copied;
}

// An Io cancellation reports why it stopped. It is not evidence that time ran
// out, and a caller uses the distinction to choose retry versus a new deadline.
test "deadline wait: only timeout sets the expired side channel" {
    var client: SocketClient = undefined;
    client.expired_flag = false;
    try testing.expect(client.deadlineWaitError(error.Canceled) == error.Canceled);
    try testing.expect(!client.expired());
    try testing.expect(
        client.deadlineWaitError(error.ConcurrencyUnavailable) == error.DeadlineUnsupported,
    );
    try testing.expect(!client.expired());
    try testing.expect(client.deadlineWaitError(error.Timeout) == error.TimedOut);
    try testing.expect(client.expired());
    client.setDeadline(null);
    try testing.expect(!client.expired());
}

test "unexpected application data cannot spin the eager handshake" {
    var client: SocketClient = undefined;
    try client.client.init(&.{}, .{
        .keypairs = try .init(.generate()),
        .host_name = null,
        .now_sec = 0,
        .random = .zero,
        .reassembly = &client.reassembly,
    }, .{ .record = &client.record, .out = &client.out });
    defer client.client.deinit();
    client.client.started = true;
    client.client.pending_application = "early";
    try testing.expectError(error.UnexpectedRecord, client.handshake());
}

test "deadline batches reap pending reads and preserve completions that race cancellation" {
    if (comptime @hasField(Io.Operation, "net_read")) {
        const Probe = @import("socket_client_test_io.zig").BatchProbe;
        const Scenario = enum {
            timeout,
            canceled,
            unsupported,
            missing,
            timeout_race,
            canceled_race,
        };
        for (std.enums.values(Scenario)) |scenario| {
            var probe: Probe = .init(
                switch (scenario) {
                    .timeout, .timeout_race => error.Timeout,
                    .canceled, .canceled_race => error.Canceled,
                    .unsupported => error.ConcurrencyUnavailable,
                    .missing => null,
                },
                switch (scenario) {
                    .timeout_race, .canceled_race => 0x16,
                    else => null,
                },
            );
            var vtable = testing.io.vtable.*;
            vtable.batchAwaitConcurrent = Probe.awaitConcurrent;
            vtable.batchCancel = Probe.cancel;
            vtable.now = Probe.now;
            const io: Io = .{ .userdata = &probe, .vtable = &vtable };
            var client: SocketClient = .{
                .io = io,
                .allocator = testing.allocator,
                .socket = .{ .socket = .{ .handle = -1, .address = undefined } },
            };
            try client.client.init(&.{}, .{
                .keypairs = try .init(.generate()),
                .host_name = null,
                .now_sec = 0,
                .random = .zero,
                .reassembly = &client.reassembly,
            }, .{ .record = &client.record, .out = &client.out });
            defer client.client.deinit();
            const before = client.client.receiveBuffer().len;
            const result = client.readSocketDeadline(client.client.receiveBuffer(), 12345);
            switch (scenario) {
                .timeout => try testing.expectError(error.TimedOut, result),
                .canceled, .canceled_race => try testing.expectError(error.Canceled, result),
                .unsupported => try testing.expectError(error.DeadlineUnsupported, result),
                .missing => try testing.expectError(error.NoReadCompletion, result),
                .timeout_race => try testing.expectEqual(ReceiveResult.received, try result),
            }
            try testing.expect(probe.cancel_called);
            try testing.expectEqual(scenario == .timeout, client.expired());
            const accepted: usize = if (probe.complete_on_cancel != null) 1 else 0;
            try testing.expectEqual(before - accepted, client.client.receiveBuffer().len);
        }
    } else return error.SkipZigTest;
}
