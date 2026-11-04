//! Caller-driven TLS 1.3 server transport. No socket or runtime dependency.
//! Input records decrypt in place. One output record bounds TX backpressure.
const std = @import("std");
const assert = std.debug.assert;
const EnumSet = std.EnumSet;
const tls = @import("tls");
const Handshake = tls.ServerHandshake;
const RecordBuffer = tls.RecordBuffer;
const frame = tls.frame;
const alert = tls.alert;
const Server = @This();

/// Listener-wide configuration. It is safe to copy and reuse for every accept.
/// Referenced policy storage and credentials must outlive every connection.
pub const Options = struct {
    handshake: Handshake.ServerConfig = .{},
    cert_chain: []const []const u8,
    signer: tls.signature.Signer,
};

/// All working buffers must be disjoint, including handshake reassembly storage.
pub const Buffers = struct {
    /// At least RecordBuffer.min_storage. Holds decrypted plaintext as well.
    record: []u8,
    /// At least frame.max_wire_record_len. Holds at most one outbound record.
    out: []u8,
};

pub const InitError = Handshake.ConfigError || error{ MissingCredentials, BufferTooSmall };
pub const Error = tls.errors.HandshakeError || RecordBuffer.NextError ||
    Handshake.SendError || Handshake.AlertError || error{ Closed, HandshakeIncomplete, WouldBlock };

pub const State = enum { handshaking, connected, failed, closed };

pub const Event = union(enum) {
    /// No complete input record remains. Output can still need a socket write.
    need_input,
    /// Drain sendBuffer(), then call next() again without a readiness wait.
    need_output,
    /// One control or fragmented record advanced the protocol. Call next().
    progress,
    /// The client Finished authenticated. Check selectedAlpn() before use.
    handshake_complete,
    /// Borrowed until consumeApplication() releases every byte.
    application_data: []const u8,
    /// PSK-authorized 0-RTT bytes, NOT authenticated by the client Finished.
    /// Only a caller that supplies replay policy can enable this via psk_lookup.
    early_data: []const u8,
    /// RX already changed keys. The driver queues any required TX response.
    key_update: Handshake.KeyUpdateRequest,
    close_notify,
    /// close_notify already ended RX. TX can remain open (RFC 8446 §6.1).
    closed,
};

const Flag = enum { input_ended, rx_closed, tx_closed };
const ApplicationKind = enum { regular, early };

hs: Handshake,
records: RecordBuffer,
out: []u8,
pending_send: []const u8,
pending_application: []const u8,
application_kind: ApplicationKind,
state: State,
flags: EnumSet(Flag),
failure: ?Error,
fatal_alert: ?alert.Description,

/// Initialize in its final slot with one connection's fresh keys and storage.
/// This performs no handshake or transport I/O. A failed init acquires no resources.
/// Call deinit only after successful init. The caller owns buffer erasure,
/// including Config.reassembly and Config.client_cert_buffer.
pub fn init(
    self: *Server,
    options: *const Options,
    config: Handshake.Config,
    buffers: Buffers,
) InitError!void {
    try options.handshake.validate(&config.keypairs);
    if (options.cert_chain.len == 0) return error.MissingCredentials;
    if (buffers.record.len < RecordBuffer.min_storage) return error.BufferTooSmall;
    if (buffers.out.len < frame.max_wire_record_len) return error.BufferTooSmall;
    self.* = .{
        .hs = .init(options.handshake, config),
        .records = .init(buffers.record),
        .out = buffers.out,
        .pending_send = &.{},
        .pending_application = &.{},
        .application_kind = .regular,
        .state = .handshaking,
        .flags = .empty,
        .failure = null,
        .fatal_alert = null,
    };
    self.hs.setCredentials(options.cert_chain, options.signer);
}

/// Release backend state and inline secrets. Does not erase borrowed buffers.
/// No operation can overlap this call. Repeated deinit calls are harmless.
// ziglint-ignore: Z030 -- closed is an initialized tombstone for idempotent teardown.
pub fn deinit(self: *Server) void {
    if (self.state == .closed) return;
    self.hs.deinit();
    self.pending_send = &.{};
    self.pending_application = &.{};
    self.fatal_alert = null;
    self.state = .closed;
}

/// Destination for a nonblocking socket read. An empty slice is backpressure,
/// not transport EOF. Plaintext must be consumed before input storage can move.
pub fn receiveBuffer(self: *Server) []u8 {
    if (self.state == .failed or self.state == .closed) return &.{};
    if (self.flags.contains(.input_ended) or self.flags.contains(.rx_closed)) return &.{};
    if (self.pending_application.len != 0) return &.{};
    return self.records.writable();
}

/// Commit bytes written into the last receiveBuffer(). Zero commits no bytes.
pub fn received(self: *Server, n: usize) void {
    assert(self.state == .handshaking or self.state == .connected);
    assert(!self.flags.contains(.input_ended));
    assert(!self.flags.contains(.rx_closed));
    assert(self.pending_application.len == 0);
    self.records.advance(n);
}

/// Report transport EOF. next() drains buffered records and plaintext first.
/// Without close_notify it then fails with UnexpectedEof, including mid-handshake.
pub fn endInput(self: *Server) void {
    self.flags.insert(.input_ended);
}

/// Wire bytes ready for a nonblocking socket write. EAGAIN consumes nothing.
/// The slice remains valid until sent(), deinit(), or a fatal peer alert.
pub fn sendBuffer(self: *const Server) []const u8 {
    return self.pending_send;
}

/// Acknowledge only bytes the transport accepted. Partial writes retain the tail.
/// The core TX latch clears only after the final byte. Call next() after a drain.
pub fn sent(self: *Server, n: usize) void {
    assert(n <= self.pending_send.len);
    if (n == 0) return;
    self.pending_send = self.pending_send[n..];
    if (self.pending_send.len == 0) self.hs.completeWrite();
}

/// Release plaintext from the most recent application_data or early_data event.
/// Partial consumption pins the remainder for a later application event.
pub fn consumeApplication(self: *Server, n: usize) void {
    assert(n <= self.pending_application.len);
    self.pending_application = self.pending_application[n..];
}

pub fn isConnected(self: *const Server) bool {
    return self.state == .connected;
}

/// Null before the authenticated handshake_complete event, or without ALPN.
pub fn selectedAlpn(self: *const Server) ?[]const u8 {
    return if (self.isConnected()) self.hs.selectedAlpnProtocol() else null;
}

/// Exact peer alert behind PeerAlert. No response alert is sent to that peer.
pub fn lastPeerAlert(self: *const Server) ?alert.Alert {
    return if (self.state == .closed) null else self.hs.lastPeerAlert();
}

/// Process at most one input record. No internal loop can monopolize a slot.
/// Call again after progress, handshake_complete, key_update, or a buffer drain.
/// At need_input, watch readability and also writability if sendBuffer is nonempty.
/// Fatal errors latch permanently. PeerAlert discards output: close the socket.
/// For local errors, drain output and call next() again for a best-effort alert.
/// Abandon the socket if the caller's write deadline expires.
pub fn next(self: *Server) Error!Event {
    if (self.state == .closed) return error.Closed;
    if (self.failure) |err| {
        self.prepareFatalAlert();
        return err;
    }
    // An echo caller can retain RX until write() succeeds. Service owed TX first.
    if (self.state == .handshaking) {
        if (self.pending_send.len != 0) return .need_output;
        if (self.hs.sendPreparedServerFlight(self.out) catch |err| return self.fail(err)) |bytes| {
            self.pending_send = bytes;
            return .need_output;
        }
    } else if (self.pending_send.len == 0 and !self.flags.contains(.tx_closed)) {
        if (self.hs.hasPendingKeyUpdateResponse()) {
            self.pending_send = self.hs.sendKeyUpdate(self.out, .update_not_requested) catch |err|
                return self.fail(err);
            return .need_output;
        }
    }
    if (self.pending_application.len != 0) return self.applicationEvent();
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
/// WouldBlock accepts nothing: drain output and call next() for any owed KeyUpdate.
/// Input is copied once into the record payload for encryption, never retained.
pub fn write(self: *Server, plaintext: []const u8) Error!usize {
    try self.checkWrite();
    if (plaintext.len == 0) return 0;
    const n = @min(plaintext.len, frame.max_plaintext_len);
    self.pending_send = self.hs.sendApplicationData(plaintext[0..n], self.out) catch |err|
        return self.fail(err);
    return n;
}

/// Queue close_notify after all accepted application bytes. Does not close a fd.
/// WouldBlock requires an output drain and next(), then a retry. RX stays open.
pub fn closeWrite(self: *Server) Error!void {
    if (self.flags.contains(.tx_closed)) return;
    try self.checkWrite();
    self.pending_send = self.hs.sendAlert(.close_notify, self.out) catch |err|
        return self.fail(err);
    self.flags.insert(.tx_closed);
}

fn checkWrite(self: *const Server) Error!void {
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

fn handshakeRecord(self: *Server, record: []u8) Error!Event {
    const event = self.hs.handleRecord(record, self.out) catch |err| return self.fail(err);
    return switch (event) {
        .write => |bytes| blk: {
            self.pending_send = bytes;
            break :blk .need_output;
        },
        .none => blk: {
            if (self.hs.isConnected()) {
                self.state = .connected;
                break :blk .handshake_complete;
            }
            break :blk .progress;
        },
        .application_data => |bytes| self.application(bytes, .early),
        // close_notify cannot authenticate an incomplete handshake.
        .closed => self.fail(error.UnexpectedEof),
        .key_update => self.fail(error.UnexpectedRecord),
    };
}

fn connectedRecord(self: *Server, record: []u8) Error!Event {
    const event = self.hs.receiveRecord(record) catch |err| return self.fail(err);
    return switch (event) {
        .none => .progress,
        .application_data => |bytes| self.application(bytes, .regular),
        .key_update => |request| .{ .key_update = request },
        .closed => blk: {
            self.flags.insert(.rx_closed);
            break :blk .close_notify;
        },
    };
}

fn application(self: *Server, bytes: []const u8, kind: ApplicationKind) Event {
    if (bytes.len == 0) return .progress;
    self.pending_application = bytes;
    self.application_kind = kind;
    return self.applicationEvent();
}

fn applicationEvent(self: *const Server) Event {
    return switch (self.application_kind) {
        .regular => .{ .application_data = self.pending_application },
        .early => .{ .early_data = self.pending_application },
    };
}

fn fail(self: *Server, err: Error) Error {
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

fn prepareFatalAlert(self: *Server) void {
    if (self.pending_send.len != 0 or self.flags.contains(.tx_closed)) return;
    const description = self.fatal_alert orelse return;
    self.fatal_alert = null;
    // The original error remains available if the backend cannot encode an alert.
    self.pending_send = self.hs.sendAlert(description, self.out) catch return;
}
