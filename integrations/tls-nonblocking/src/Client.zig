//! Caller-driven TLS 1.3 client transport. No socket or runtime dependency.
//! The caller owns the socket, the readiness loop, and every buffer.
const std = @import("std");
const assert = std.debug.assert;
const EnumSet = std.EnumSet;
const tls = @import("tls");
const Handshake = tls.ClientHandshake;
const RecordBuffer = tls.RecordBuffer;
const frame = tls.frame;
const alert = tls.alert;
const Certificate = std.crypto.Certificate;
const Client = @This();

/// Connection-wide policy. Safe to copy and reuse for every connection.
/// Borrowed storage must outlive every `Client` that copies this.
pub const Options = struct {
    /// Trust anchors for the server chain. null rejects the certificate unless
    /// `insecure_no_chain_anchor` is set; this is the same rule the engine
    /// applies, stated once here so a caller cannot omit the decision.
    ca: ?*const Certificate.Bundle = null,
    /// Test/demo opt-out from chain verification. Never set in production.
    insecure_no_chain_anchor: bool = false,
    /// ASCII DNS name for SNI and the DNS-ID SAN check. null disables both.
    host_name: ?[]const u8 = null,
    /// Current time in seconds since the Unix epoch, for validity checks.
    now_sec: i64 = 0,
    /// ALPN protocols to offer, in preference order. Empty offers none.
    alpn: []const []const u8 = &.{},
};

/// All working buffers must be disjoint, including handshake reassembly storage.
pub const Buffers = struct {
    /// At least RecordBuffer.min_storage. Holds decrypted plaintext as well.
    record: []u8,
    /// At least frame.max_wire_record_len. Holds at most one outbound record.
    out: []u8,
};

pub const InitError = Handshake.ConfigError || error{BufferTooSmall};
pub const Error = tls.errors.HandshakeError || RecordBuffer.NextError ||
    Handshake.StartError || Handshake.SendError || Handshake.AlertError ||
    error{ Closed, HandshakeIncomplete, WouldBlock };

pub const State = enum { handshaking, connected, failed, closed };

pub const Event = union(enum) {
    /// No complete input record remains. Output can still need a socket write.
    need_input,
    /// Drain sendBuffer(), then call next() again without a readiness wait.
    need_output,
    /// One control or fragmented record advanced the protocol. Call next().
    progress,
    /// The server Finished verified. Check selectedAlpn() before use.
    handshake_complete,
    /// Borrowed until consumeApplication() releases every byte.
    application_data: []const u8,
    /// RX already changed keys. The driver queues any required TX response.
    key_update: Handshake.KeyUpdateRequest,
    /// A post-handshake ticket. Borrowed until the next next(); a caller that
    /// wants resumption calls deriveSessionTicket() while it is fresh.
    new_session_ticket: Handshake.NewSessionTicket,
    /// The peer sent close_notify. TX can remain open (RFC 8446 §6.1).
    close_notify,
    /// close_notify already ended RX. TX can remain open.
    closed,
};

const Flag = enum { input_ended, rx_closed, tx_closed };

hs: Handshake,
records: RecordBuffer,
out: []u8,
pending_send: []const u8,
pending_application: []const u8,
state: State,
flags: EnumSet(Flag),
failure: ?Error,
fatal_alert: ?alert.Description,
/// ClientHello has been produced and handed to the driver.
started: bool,

/// Initialize in its final slot with one connection's fresh keys and storage.
/// This performs no handshake or transport I/O: the ClientHello is produced by
/// the first `next()`. A failed init acquires no resources.
pub fn init(
    self: *Client,
    options: *const Options,
    config: Handshake.Config,
    buffers: Buffers,
) InitError!void {
    if (buffers.record.len < RecordBuffer.min_storage) return error.BufferTooSmall;
    if (buffers.out.len < frame.max_wire_record_len) return error.BufferTooSmall;
    var resolved = config;
    resolved.bundle = options.ca;
    resolved.insecure_no_chain_anchor = options.insecure_no_chain_anchor;
    resolved.host_name = options.host_name;
    resolved.now_sec = options.now_sec;
    resolved.alpn_protocols = options.alpn;
    try resolved.validate();
    self.* = .{
        .hs = .init(resolved),
        .records = .init(buffers.record),
        .out = buffers.out,
        .pending_send = &.{},
        .pending_application = &.{},
        .state = .handshaking,
        .flags = .empty,
        .failure = null,
        .fatal_alert = null,
        .started = false,
    };
}

/// Release backend state and inline secrets. Does not erase borrowed buffers.
/// Repeated deinit calls are harmless.
// ziglint-ignore: Z030 -- closed is an initialized tombstone for idempotent teardown.
pub fn deinit(self: *Client) void {
    if (self.state == .closed) return;
    self.hs.deinit();
    self.pending_send = &.{};
    self.pending_application = &.{};
    self.fatal_alert = null;
    self.state = .closed;
}

/// Destination for a nonblocking socket read. An empty slice is backpressure,
/// not transport EOF.
pub fn receiveBuffer(self: *Client) []u8 {
    if (self.state == .failed or self.state == .closed) return &.{};
    if (self.flags.contains(.input_ended) or self.flags.contains(.rx_closed)) return &.{};
    if (self.pending_application.len != 0) return &.{};
    return self.records.writable();
}

/// Commit bytes written into the last receiveBuffer(). Zero commits no bytes.
pub fn received(self: *Client, n: usize) void {
    assert(self.state == .handshaking or self.state == .connected);
    assert(!self.flags.contains(.input_ended));
    assert(!self.flags.contains(.rx_closed));
    assert(self.pending_application.len == 0);
    self.records.advance(n);
}

/// Report transport EOF. next() drains buffered records and plaintext first.
pub fn endInput(self: *Client) void {
    self.flags.insert(.input_ended);
}

/// Wire bytes ready for a nonblocking socket write. EAGAIN consumes nothing.
pub fn sendBuffer(self: *const Client) []const u8 {
    return self.pending_send;
}

/// Acknowledge only bytes the transport accepted. Partial writes retain the tail.
pub fn sent(self: *Client, n: usize) void {
    assert(n <= self.pending_send.len);
    if (n == 0) return;
    self.pending_send = self.pending_send[n..];
    if (self.pending_send.len == 0) self.hs.completeWrite();
}

/// Release plaintext from the most recent application_data event.
pub fn consumeApplication(self: *Client, n: usize) void {
    assert(n <= self.pending_application.len);
    self.pending_application = self.pending_application[n..];
}

pub fn isConnected(self: *const Client) bool {
    return self.state == .connected;
}

/// Null before the authenticated handshake_complete event, or without ALPN.
/// Requiring a protocol is caller policy: this reports, it does not enforce.
pub fn selectedAlpn(self: *const Client) ?[]const u8 {
    return if (self.isConnected()) self.hs.selectedAlpnProtocol() else null;
}

/// Exact peer alert behind PeerAlert. Read it the moment next() returns that
/// error; it is null once the transport reaches .closed.
pub fn lastPeerAlert(self: *const Client) ?alert.Alert {
    return if (self.state == .closed) null else self.hs.lastPeerAlert();
}

/// Derive a storable ticket from a new_session_ticket event while it is fresh.
pub fn deriveSessionTicket(
    self: *const Client,
    nst: Handshake.NewSessionTicket,
) error{ NoResumptionSecret, TicketIdentityTooLong }!Handshake.SessionTicket {
    return self.hs.deriveSessionTicket(nst);
}

/// Advance the protocol. No internal loop can monopolize a slot.
pub fn next(self: *Client) Error!Event {
    if (self.state == .closed) return error.Closed;
    if (self.failure) |err| {
        self.prepareFatalAlert();
        return err;
    }
    if (self.pending_send.len != 0) return .need_output;

    if (!self.started) {
        self.pending_send = self.hs.start(self.out) catch |err| return self.fail(err);
        self.started = true;
        return .need_output;
    }

    // The client Finished authenticated the server and is on the wire.
    if (self.state == .handshaking and self.hs.isConnected()) {
        self.state = .connected;
        return .handshake_complete;
    }
    if (self.state == .connected and !self.flags.contains(.tx_closed) and
        self.hs.hasPendingKeyUpdateResponse())
    {
        self.pending_send = self.hs.sendKeyUpdate(self.out, .update_not_requested) catch |err|
            return self.fail(err);
        return .need_output;
    }
    if (self.pending_application.len != 0) return .{ .application_data = self.pending_application };
    if (self.flags.contains(.rx_closed)) return .closed;

    const record = (self.records.next() catch |err| return self.fail(err)) orelse {
        if (self.flags.contains(.input_ended)) {
            // EOF is a transport truncation, not a peer protocol error to answer.
            self.failure = error.UnexpectedEof;
            self.state = .failed;
            return error.UnexpectedEof;
        }
        return .need_input;
    };
    return if (self.state == .handshaking)
        self.handshakeRecord(record)
    else
        self.connectedRecord(record);
}

/// Encrypt one fragment, up to max_plaintext_len. Returns the accepted byte count.
pub fn write(self: *Client, plaintext: []const u8) Error!usize {
    try self.checkWrite();
    if (plaintext.len == 0) return 0;
    const n = @min(plaintext.len, frame.max_plaintext_len);
    self.pending_send = self.hs.sendApplicationData(plaintext[0..n], self.out) catch |err|
        return self.fail(err);
    return n;
}

/// Queue close_notify after all accepted application bytes. Does not close a
/// file descriptor. RX stays open (RFC 8446 §6.1).
pub fn closeWrite(self: *Client) Error!void {
    if (self.flags.contains(.tx_closed)) return;
    try self.checkWrite();
    self.pending_send = self.hs.sendAlert(.close_notify, self.out) catch |err|
        return self.fail(err);
    self.flags.insert(.tx_closed);
}

fn checkWrite(self: *const Client) Error!void {
    if (self.failure) |err| return err;
    switch (self.state) {
        .closed, .failed => return error.Closed,
        .handshaking => return error.HandshakeIncomplete,
        .connected => {},
    }
    if (self.flags.contains(.tx_closed)) return error.Closed;
    if (self.pending_send.len != 0) return error.WouldBlock;
    if (self.hs.hasPendingKeyUpdateResponse()) return error.WouldBlock;
}

fn handshakeRecord(self: *Client, record: []u8) Error!Event {
    const event = self.hs.handleRecord(record, self.out) catch |err| return self.fail(err);
    return switch (event) {
        .write => |bytes| blk: {
            self.pending_send = bytes;
            break :blk .need_output;
        },
        .none => .progress,
        // A server never sends application data before its Finished; the
        // engine routes this arm anyway, so surface the bytes rather than drop them.
        .application_data => |bytes| self.application(bytes),
        // close_notify cannot authenticate an incomplete handshake.
        .closed => self.fail(error.UnexpectedEof),
        .key_update, .new_session_ticket => self.fail(error.UnexpectedRecord),
    };
}

fn connectedRecord(self: *Client, record: []u8) Error!Event {
    const event = self.hs.receiveRecord(record) catch |err| return self.fail(err);
    return switch (event) {
        .none => .progress,
        .application_data => |bytes| self.application(bytes),
        .key_update => |request| .{ .key_update = request },
        .new_session_ticket => |ticket| .{ .new_session_ticket = ticket },
        .closed => blk: {
            self.flags.insert(.rx_closed);
            break :blk .close_notify;
        },
    };
}

fn application(self: *Client, bytes: []const u8) Event {
    if (bytes.len == 0) return .progress;
    self.pending_application = bytes;
    return .{ .application_data = self.pending_application };
}

fn fail(self: *Client, err: Error) Error {
    self.failure = err;
    self.state = .failed;
    if (err == error.PeerAlert) {
        // RFC 8446 §6.2: abort without any further output, even a pending tail.
        self.pending_send = &.{};
    } else {
        self.fatal_alert = alert.alertForError(err);
        self.prepareFatalAlert();
    }
    return err;
}

fn prepareFatalAlert(self: *Client) void {
    if (self.pending_send.len != 0 or self.flags.contains(.tx_closed)) return;
    const description = self.fatal_alert orelse return;
    self.fatal_alert = null;
    // The original error remains available if the backend cannot encode an alert.
    self.pending_send = self.hs.sendAlert(description, self.out) catch return;
}
