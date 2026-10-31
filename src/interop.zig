const std = @import("std");
const heap = std.heap;
const mem = std.mem;
const Io = std.Io;
const testing = std.testing;
const assert = std.debug.assert;
const Child = std.process.Child;
const Allocator = mem.Allocator;
const IpAddress = Io.net.IpAddress;
const Stream = Io.net.Stream;
const Server = Io.net.Server;
const path = Io.Dir.path;

const fixtures = @import("fixtures");

const backend = @import("crypto/backend.zig");
const entropy = @import("entropy.zig");
const tls = @import("root.zig");

const host = "127.0.0.1";
const alpn_protocol = "http/1.1";
const response = "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello";

const server_cert_der: []const u8 = &fixtures.server_ecdsa_cert_der;
const server_scalar: []const u8 = &fixtures.server_ecdsa_scalar;

const client_suites = [_][]const u8{
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
};

const ServerSuite = struct {
    openssl_name: []const u8,
    tls_suite: tls.CipherSuite,
};

const server_suites = [_]ServerSuite{
    .{ .openssl_name = "TLS_AES_128_GCM_SHA256", .tls_suite = .aes_128_gcm_sha256 },
    .{ .openssl_name = "TLS_CHACHA20_POLY1305_SHA256", .tls_suite = .chacha20_poly1305_sha256 },
    .{ .openssl_name = "TLS_AES_256_GCM_SHA384", .tls_suite = .aes_256_gcm_sha384 },
};

const InteropGroup = struct {
    openssl_name: []const u8,
    tls_group: tls.kex.NamedGroup,
};

const p384_group: InteropGroup = .{
    .openssl_name = "P-384",
    .tls_group = .secp384r1,
};

const hybrid_groups = [_]InteropGroup{
    .{ .openssl_name = "X25519MLKEM768", .tls_group = .x25519_mlkem768 },
    .{ .openssl_name = "SecP256r1MLKEM768", .tls_group = .secp256r1_mlkem768 },
    .{ .openssl_name = "SecP384r1MLKEM1024", .tls_group = .secp384r1_mlkem1024 },
};

/// A listening socket the test owns, not the server thread.
///
/// The thread exists to run `accept` and `serve`; the caller owns the
/// listener so it can wake a thread stuck in `accept` after the peer failed.
/// Without that, a failed `openssl s_client` leaves the thread blocked in
/// `accept` on its only socket, `join` never returns, and the test hangs with
/// no CPU use (#141).
///
/// The wake-up is a loopback connection to the listener, which is the one
/// mechanism that works on every target: closing the fd from another thread
/// does not interrupt `accept` on Linux, and `shutdown` on a listening socket
/// is not portable.
const Listener = struct {
    server: Server,
    /// The kernel-assigned port, so parallel test runs cannot collide.
    port: u16,

    fn init() !Listener {
        const addr: IpAddress = try .parse(host, 0);
        const server = try addr.listen(testing.io, .{ .reuse_address = true });
        return .{ .server = server, .port = server.socket.address.getPort() };
    }

    /// Releases a thread blocked in `accept`. The connection is accepted and
    /// closed at once, so the server sees `error.ClientClosed` from `serve`
    /// and returns. Idempotent, and a no-op once the peer connected and the
    /// thread returned.
    fn cancel(listener: *const Listener) void {
        const addr: IpAddress = .{ .ip4 = .loopback(listener.port) };
        const stream = addr.connect(testing.io, .{ .mode = .stream }) catch return;
        stream.close(testing.io);
    }

    fn deinit(listener: *Listener) void {
        listener.server.deinit(testing.io);
        listener.* = undefined;
    }
};

test "OpenSSL s_server interoperates with tls client" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirPath(arena, &tmp);
    const cert_path = try path.join(arena, &.{ dir, "cert.pem" });
    const key_path = try path.join(arena, &.{ dir, "key.pem" });

    try genCert(cert_path, key_path);

    for (client_suites) |suite| try runClientSuite(arena, cert_path, key_path, suite);
}

// RFC 8446 §4.2.8.2, §7.4 — OpenSSL independently validates the tls
// secp384r1 ClientHello share and derives matching handshake/traffic keys.
test "OpenSSL s_server interoperates with tls P-384 client" {
    if (!backend.supportsClientP384()) return error.SkipZigTest;

    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirPath(arena, &tmp);
    const cert_path = try path.join(arena, &.{ dir, "cert.pem" });
    const key_path = try path.join(arena, &.{ dir, "key.pem" });
    try genCert(cert_path, key_path);

    try runClientGroup(arena, cert_path, key_path, p384_group);
}

// RFC 10024 §4 — OpenSSL independently validates every tls client hybrid
// share layout and derives matching ECDHE + ML-KEM traffic keys.
test "OpenSSL s_server interoperates with tls RFC 10024 client groups" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirPath(arena, &tmp);
    const cert_path = try path.join(arena, &.{ dir, "cert.pem" });
    const key_path = try path.join(arena, &.{ dir, "key.pem" });
    try genCert(cert_path, key_path);

    var tested = false;
    for (hybrid_groups) |group| {
        if (!backend.supportsClientHybridGroup(group.tls_group)) continue;
        tested = true;
        try runClientGroup(arena, cert_path, key_path, group);
    }
    if (!tested) return error.SkipZigTest;
}

// RFC 8446 §4.6.1, §4.2.11 — tls client resumes with openssl s_server:
// connection 1 completes a full handshake and captures the NewSessionTicket
// the server issues; connection 2 offers that ticket (startWithPsk) and the
// server resumes with the PSK.
test "tls client resumes with OpenSSL s_server (PSK resumption)" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirPath(arena, &tmp);
    const cert_path = try path.join(arena, &.{ dir, "cert.pem" });
    const key_path = try path.join(arena, &.{ dir, "key.pem" });
    try genCert(cert_path, key_path);

    try runResumptionInterop(arena, cert_path, key_path);
}

// RFC 8446 §4.2.10, §4.5, §7.1 — tls client sends 0-RTT early data to
// openssl s_server. Connection 1 captures an NST with early_data; connection
// 2 offers the ticket with early_data, sends 0-RTT data, then completes the
// handshake (EndOfEarlyData + Finished). The server accepts the 0-RTT data
// and responds to the GET request. See PRODUCTION_READINESS.md for status.
test "tls client sends 0-RTT early data to OpenSSL s_server" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirPath(arena, &tmp);
    const cert_path = try path.join(arena, &.{ dir, "cert.pem" });
    const key_path = try path.join(arena, &.{ dir, "key.pem" });
    try genCert(cert_path, key_path);

    try runEarlyDataInterop(arena, cert_path, key_path);
}

test "OpenSSL s_client interoperates with tls server" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    for (server_suites) |suite| try runServerSuite(arena, suite);
}

// RFC 8446 §4.6.1, §4.2.11 — OpenSSL stores a tls-issued ticket on the first
// connection and offers it on the second; the tls server selects the PSK.
test "OpenSSL s_client resumes with tls server-issued ticket" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirPath(arena, &tmp);
    const session_path = try path.join(arena, &.{ dir, "session.pem" });
    try runServerResumptionSuite(arena, session_path);
}

// RFC 8446 §4.2.8.2, §7.4 — OpenSSL independently validates the tls
// secp384r1 ServerHello share and derives matching handshake/traffic keys.
test "OpenSSL s_client interoperates with tls P-384 server" {
    if (!backend.supportsServerP384()) return error.SkipZigTest;

    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    try runServerGroup(arena, p384_group);
}

// RFC 10024 §4 — OpenSSL independently validates every tls server hybrid
// share layout and derives matching ECDHE + ML-KEM traffic keys.
test "OpenSSL s_client interoperates with tls RFC 10024 server groups" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var tested = false;
    for (hybrid_groups) |group| {
        if (!backend.supportsServerHybridGroup(group.tls_group)) continue;
        tested = true;
        try runServerGroup(arena, group);
    }
    if (!tested) return error.SkipZigTest;
}

// RFC 8446 §4.7.2, §4.4.2, §4.4.3 — tls server requiring client authentication
// accepts a client certificate presented by `openssl s_client -cert -key`.
test "OpenSSL s_client with -cert interoperates with tls server (required client auth)" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirPath(arena, &tmp);
    const client_cert_path = try path.join(arena, &.{ dir, "client.pem" });
    const client_key_path = try path.join(arena, &.{ dir, "client.key" });
    try genCert(client_cert_path, client_key_path);

    try runServerClientAuthSuite(arena, client_cert_path, client_key_path);
}

// #141 — a peer that reads its request and exits without ever dialing the
// server used to leave the server thread blocked in `accept` on its only
// socket. `join` then never returned, the test hung with no CPU use, and the
// error that explains it was never reached. The suite must return the client
// failure instead.
test "a peer that exits without connecting fails the server suite" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    // Reads the request off stdin, so the write side cannot race an early
    // exit, then fails. `sh` is the one interpreter every target has.
    const absent_peer = &.{ "sh", "-c", "cat >/dev/null; exit 1" };
    try testing.expectError(
        error.OpenSslClientFailed,
        runServerSuiteAgainst(arena, server_suites[0], absent_peer),
    );
}

// #141 — the suites used to bind fixed ports (16433+i, 16533, 21343, 21433+i),
// so a second checkout on the same host, or anything else holding the port,
// made the bind fail on one side and `accept` block on the other. Ports are
// kernel-assigned now, so two suites run at once on one host.
test "two server suites run at once on one host" {
    const Runner = struct {
        fn run(suite: ServerSuite, failure: *?anyerror) void {
            // A per-thread arena: the suite allocates and never frees.
            var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
            defer arena_allocator.deinit();
            runServerSuite(arena_allocator.allocator(), suite) catch |err| {
                failure.* = err;
            };
        }
    };

    var first_failure: ?anyerror = null;
    var second_failure: ?anyerror = null;
    const first = try std.Thread.spawn(
        .{},
        Runner.run,
        .{ server_suites[0], &first_failure },
    );
    const second = try std.Thread.spawn(
        .{},
        Runner.run,
        .{ server_suites[1], &second_failure },
    );
    first.join();
    second.join();

    try testing.expectEqual(@as(?anyerror, null), first_failure);
    try testing.expectEqual(@as(?anyerror, null), second_failure);
}

// RFC 8446 §4.7.2, §4.4.2, §4.4.3 — tls client presenting a certificate to
// `openssl s_server -Verify` completes the handshake and exchanges data.
test "tls client with credentials interoperates with OpenSSL s_server -Verify" {
    var arena_allocator: heap.ArenaAllocator = .init(testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirPath(arena, &tmp);
    // s_server needs a server cert/key (self-signed) and a CAfile that trusts
    // the tls client's self-signed fixture certificate. The fixture cert is
    // self-signed, so its own PEM is the CAfile.
    const server_cert_path = try path.join(arena, &.{ dir, "server.pem" });
    const server_key_path = try path.join(arena, &.{ dir, "server.key" });
    try genCert(server_cert_path, server_key_path);
    const client_ca_path = try path.join(arena, &.{ dir, "client_ca.pem" });
    try writeFixtureCertPem(arena, client_ca_path);

    try runClientAuthClientSuite(arena, server_cert_path, server_key_path, client_ca_path);
}

// RFC 8446 §4.6.3, §7.2 — tls-to-tls TCP loopback KeyUpdate round trip.
// The server initiates KeyUpdate(update_requested) over a real TCP connection;
// the client responds; both sides ratchet keys; application data flows under
// the new keys. Tested with ChaCha20-Poly1305 to reproduce the TLS-Anvil
// #71 scenario (BoringSSL + ChaCha20 + X25519 + CCS). Unlike the in-memory
// test, this exercises the real socket drive loop including record
// reassembly and partial reads.
test "tls-to-tls TCP KeyUpdate round trip with ChaCha20-Poly1305" {
    const KuCtx = struct {
        server_keypair: tls.x25519.KeyPair,
    };
    const server_keypair: tls.x25519.KeyPair = .generate();
    var ctx: KuCtx = .{ .server_keypair = server_keypair };

    const ServerThread = struct {
        fn serveKeyUpdate(c: *KuCtx, listener: *Listener) !void {
            const stream = try listener.server.accept(testing.io);
            defer stream.close(testing.io);

            var random: tls.Random = .empty;
            entropy.fill(&random.data);
            var hs: tls.ServerHandshake = .init(.{
                .keypairs = try .init(c.server_keypair),
                .random = random,
            });
            defer hs.deinit();
            const suites = [_]tls.CipherSuite{.chacha20_poly1305_sha256};
            hs.supportSuites(&suites);
            var signer = try tls.signature.PrivateKey.fromP256Scalar(server_scalar[0..32]);
            defer signer.deinit();
            hs.setCredentials(&.{server_cert_der}, signer.signer());

            var storage: tls.RecordBuffer.Storage = .empty;
            var rb: tls.RecordBuffer = .init(&storage.buffer);
            var out: tls.ServerHandshake.OutBuffer = .empty;
            var flight: tls.ServerHandshake.FlightBuffer = .empty;

            // Drive handshake.
            while (!hs.isConnected()) {
                const n = try tls.io.fill(testing.io, stream, &rb);
                if (n == 0) return error.ClientClosed;
                while (try rb.next()) |record| {
                    const ev = try hs.handleRecord(record, &out.buffer);
                    switch (ev) {
                        .write => |w| {
                            try tls.io.writeAll(testing.io, stream, w);
                            hs.completeWrite();
                            if (try hs.sendServerFlightBuffered(&flight)) |fb| {
                                try tls.io.writeAll(testing.io, stream, fb);
                                hs.completeWrite();
                            }
                        },
                        .none => {},
                        else => return error.UnexpectedDuringHandshake,
                    }
                }
            }

            // Server sends KeyUpdate(update_requested).
            const ku = try hs.sendKeyUpdate(&out.buffer, .update_requested);
            try tls.io.writeAll(testing.io, stream, ku);
            hs.completeWrite();

            // Echo loop: expect client's KeyUpdate response, then app data.
            while (true) {
                const n = try tls.io.fill(testing.io, stream, &rb);
                if (n == 0) return error.ClientClosed;
                while (try rb.next()) |record| {
                    const ev = try hs.handleRecord(record, &out.buffer);
                    switch (ev) {
                        .key_update => |ku_ev| {
                            if (ku_ev.response) |w| {
                                try tls.io.writeAll(testing.io, stream, w);
                                hs.completeWrite();
                            }
                        },
                        .application_data => |data| {
                            if (!mem.eql(u8, data, "after-ku")) return error.UnexpectedAppData;
                            const resp = try hs.sendApplicationData("pong-ku", &out.buffer);
                            try tls.io.writeAll(testing.io, stream, resp);
                            hs.completeWrite();
                            const close = try hs.sendAlert(.close_notify, &out.buffer);
                            try tls.io.writeAll(testing.io, stream, close);
                            hs.completeWrite();
                            return;
                        },
                        .write => |w| {
                            try tls.io.writeAll(testing.io, stream, w);
                            hs.completeWrite();
                        },
                        .closed => return,
                        .none => {},
                    }
                }
            }
        }

        fn start(c: *KuCtx, listener: *Listener, failure: *?anyerror) void {
            serveKeyUpdate(c, listener) catch |err| {
                failure.* = err;
            };
        }
    };

    // The listener is bound before the thread starts, so its port is known
    // without a spin-wait, and an early client failure cancels `accept`
    // instead of leaving the join blocked (#141).
    var listener: Listener = try .init();
    defer listener.deinit();

    var server_failure: ?anyerror = null;
    const server_thread = try std.Thread.spawn(
        .{},
        ServerThread.start,
        .{ &ctx, &listener, &server_failure },
    );
    // LIFO: the join runs before this check. `serveKeyUpdate` ends with
    // `error.ClientClosed` once the client hangs up; anything else is a bug.
    defer if (server_failure) |err| {
        assert(err == error.ClientClosed);
    };
    defer {
        listener.cancel();
        server_thread.join();
    }

    // Client side.
    const client_keypair: tls.x25519.KeyPair = .generate();
    const addr: IpAddress = try .parse(host, listener.port);
    const stream = try addr.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var random: tls.Random = .empty;
    entropy.fill(&random.data);
    var hs: tls.ClientHandshake = .init(.{
        .keypairs = try .init(client_keypair),
        .host_name = "ztls.server.test",
        .now_sec = 0,
        .random = random,
        .insecure_no_chain_anchor = true,
    });
    defer hs.deinit();

    var out: tls.ClientHandshake.OutBuffer = .empty;
    var storage: tls.RecordBuffer.Storage = .empty;
    var rb: tls.RecordBuffer = .init(&storage.buffer);

    try tls.io.writeAll(testing.io, stream, try hs.start(&out.buffer));
    hs.completeWrite();

    while (!hs.isConnected()) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ServerClosed;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out.buffer)) {
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .application_data,
            .closed,
            .key_update,
            .new_session_ticket,
            => return error.UnexpectedDuringHandshake,
            .none => {},
        };
    }

    // Drive: expect server's KeyUpdate, then send app data under new keys.
    var saw_key_update = false;
    var got_pong = false;
    while (!got_pong) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) break;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out.buffer)) {
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
                // Send app data under the new keys after the KeyUpdate.
                if (!saw_key_update) {
                    saw_key_update = true;
                    const app = try hs.sendApplicationData("after-ku", &out.buffer);
                    try tls.io.writeAll(testing.io, stream, app);
                    hs.completeWrite();
                }
            },
            .application_data => |data| {
                if (!mem.eql(u8, data, "pong-ku")) return error.UnexpectedPong;
                got_pong = true;
            },
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .closed => return,
            .new_session_ticket => {},
            .none => {},
        };
    }
    try testing.expect(saw_key_update);
    try testing.expect(got_pong);
}

fn runClientSuite(
    arena: Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    suite: []const u8,
) !void {
    const port = try freePort();
    var server = try startServer(arena, cert_path, key_path, suite, port);
    defer killChild(&server);
    const stream = try connectWithRetry(port);
    defer stream.close(testing.io);
    try clientInterop(stream, null);
}

fn runClientGroup(
    arena: Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    group: InteropGroup,
) !void {
    const port = try freePort();
    var server = try startServerWithGroup(arena, cert_path, key_path, group, port);
    defer killChild(&server);
    const stream = try connectWithRetry(port);
    defer stream.close(testing.io);
    try clientInterop(stream, group.tls_group);
}

fn runResumptionInterop(
    arena: Allocator,
    cert_path: []const u8,
    key_path: []const u8,
) !void {
    const port = try freePort();
    var server = try startServer(arena, cert_path, key_path, "TLS_AES_128_GCM_SHA256", port);
    defer killChild(&server);

    // Connection 1: full handshake, capture the NewSessionTicket.
    const stream1 = try connectWithRetry(port);
    var ticket: tls.ClientHandshake.SessionTicket = try clientInteropCaptureTicket(stream1);
    defer ticket.secureZero();
    stream1.close(testing.io);

    // Connection 2: offer the ticket and resume.
    const stream2 = try connectWithRetry(port);
    defer stream2.close(testing.io);
    try clientInteropResume(stream2, &ticket);
}

fn runEarlyDataInterop(
    arena: Allocator,
    cert_path: []const u8,
    key_path: []const u8,
) !void {
    const port = try freePort();
    // Start s_server with -early_data to accept 0-RTT.
    const port_str = try std.fmt.allocPrint(arena, "{d}", .{port});
    const argv = &.{
        "openssl",                "s_server",
        "-tls1_3",                "-ciphersuites",
        "TLS_AES_128_GCM_SHA256", "-key",
        key_path,                 "-cert",
        cert_path,                "-port",
        port_str,                 "-www",
        "-alpn",                  alpn_protocol,
        "-early_data",            "-max_early_data",
        "16384",                  "-no_anti_replay",
    };
    var server = try std.process.spawn(testing.io, .{
        .argv = argv,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer killChild(&server);

    // Connection 1: full handshake, capture the NST (with early_data).
    const stream1 = try connectWithRetry(port);
    var ticket: tls.ClientHandshake.SessionTicket = try clientInteropCaptureTicket(stream1);
    defer ticket.secureZero();
    stream1.close(testing.io);

    if (ticket.max_early_data_size == null) return error.NoEarlyDataInTicket;

    // Connection 2: offer early_data + send 0-RTT data, then resume.
    const stream2 = try connectWithRetry(port);
    defer stream2.close(testing.io);
    try clientEarlyDataInterop(stream2, &ticket);
}

fn genCert(cert_path: []const u8, key_path: []const u8) !void {
    const argv = &.{
        "openssl",                 "req",     "-x509",
        "-newkey",                 "ec",      "-pkeyopt",
        "ec_paramgen_curve:P-256", "-keyout", key_path,
        "-out",                    cert_path, "-days",
        "1",                       "-nodes",  "-subj",
        "/CN=localhost",           "-addext", "subjectAltName=DNS:localhost",
    };
    var child = try std.process.spawn(testing.io, .{
        .argv = argv,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try waitChild(&child);
    if (!exitedZero(term)) return error.CertGenFailed;
}

fn startServer(
    arena: Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    suite: []const u8,
    port: u16,
) !Child {
    const port_str = try std.fmt.allocPrint(arena, "{d}", .{port});
    const argv = &.{
        "openssl", "s_server",
        "-tls1_3", "-ciphersuites",
        suite,     "-key",
        key_path,  "-cert",
        cert_path, "-port",
        port_str,  "-www",
        "-alpn",   alpn_protocol,
        "-quiet",
    };
    return std.process.spawn(testing.io, .{
        .argv = argv,
        .stdout = .ignore,
        .stderr = .ignore,
    });
}

fn startServerWithGroup(
    arena: Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    group: InteropGroup,
    port: u16,
) !Child {
    const port_str = try std.fmt.allocPrint(arena, "{d}", .{port});
    const argv = &.{
        "openssl",                "s_server",
        "-tls1_3",                "-ciphersuites",
        "TLS_AES_128_GCM_SHA256", "-groups",
        group.openssl_name,       "-key",
        key_path,                 "-cert",
        cert_path,                "-port",
        port_str,                 "-www",
        "-alpn",                  alpn_protocol,
        "-quiet",
    };
    return std.process.spawn(testing.io, .{
        .argv = argv,
        .stdout = .ignore,
        .stderr = .ignore,
    });
}

fn clientInterop(stream: Stream, group: ?tls.kex.NamedGroup) !void {
    const kp: tls.x25519.KeyPair = .generate();
    var random: tls.Random = .empty;
    entropy.fill(&random.data);

    var keypairs: tls.ClientHandshake.KeyPairs = try .init(kp);
    if (group == .secp384r1 or group == .secp384r1_mlkem1024)
        keypairs.p384 = try .generate();
    const hybrid_group = if (group) |selected|
        if (selected.hybridSpec() != null) selected else null
    else
        null;
    const groups = [_]tls.kex.NamedGroup{hybrid_group orelse .x25519_mlkem768};
    var hs_config: tls.ClientHandshake.Config = .{
        .keypairs = keypairs,
        .host_name = "localhost",
        .now_sec = 0,
        .random = random,
        .insecure_no_chain_anchor = true,
        .alpn_protocols = &.{alpn_protocol},
    };
    hs_config.hybrid = if (hybrid_group) |selected| .{
        .supported_groups = &groups,
        .initial_key_share = selected,
    } else .empty;
    var hs: tls.ClientHandshake = .init(hs_config);
    defer hs.deinit();

    var out: [4096]u8 = undefined;
    var storage: tls.RecordBuffer.Storage = .empty;
    var rb: tls.RecordBuffer = .init(&storage.buffer);

    try tls.io.writeAll(testing.io, stream, try hs.start(&out));
    hs.completeWrite();

    while (!hs.isConnected()) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ServerClosed;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .application_data,
            .closed,
            .new_session_ticket,
            => return error.UnexpectedDuringHandshake,
            .none => {},
        };
    }
    try testing.expectEqualStrings(alpn_protocol, hs.selectedAlpnProtocol().?);

    const request = try hs.sendApplicationData("GET / HTTP/1.0\r\n\r\n", &out);
    try tls.io.writeAll(testing.io, stream, request);
    hs.completeWrite();

    while (true) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) break;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .application_data => |data| if (mem.startsWith(u8, data, "HTTP/1.0 200")) return,
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .new_session_ticket => {},
            .none => {},
            .closed => return error.ServerClosedBeforeResponse,
        };
    }
    return error.NoHttpResponse;
}

/// Connection 1 of PSK resumption: complete a full handshake, capture the
/// NewSessionTicket the server issues post-handshake, derive a SessionTicket,
/// and exchange a request/response so the connection closes cleanly.
fn clientInteropCaptureTicket(stream: Stream) !tls.ClientHandshake.SessionTicket {
    const kp: tls.x25519.KeyPair = .generate();
    var random: tls.Random = .empty;
    entropy.fill(&random.data);

    var hs: tls.ClientHandshake = .init(.{
        .keypairs = try .init(kp),
        .host_name = "localhost",
        .now_sec = 0,
        .random = random,
        .insecure_no_chain_anchor = true,
        .alpn_protocols = &.{alpn_protocol},
    });
    defer hs.deinit();

    var out: [4096]u8 = undefined;
    var storage: tls.RecordBuffer.Storage = .empty;
    var rb: tls.RecordBuffer = .init(&storage.buffer);

    try tls.io.writeAll(testing.io, stream, try hs.start(&out));
    hs.completeWrite();

    while (!hs.isConnected()) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ServerClosed;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .application_data,
            .closed,
            .new_session_ticket,
            => return error.UnexpectedDuringHandshake,
            .none => {},
        };
    }

    // Read post-handshake records until a NewSessionTicket arrives. The server
    // may send the NST immediately or after the request; send the GET and read
    // until both the NST and the response are seen.
    const request = try hs.sendApplicationData("GET / HTTP/1.0\r\n\r\n", &out);
    try tls.io.writeAll(testing.io, stream, request);
    hs.completeWrite();

    var ticket: ?tls.ClientHandshake.SessionTicket = null;
    var got_response = false;
    while (true) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) break;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .new_session_ticket => |nst| {
                ticket = try hs.deriveSessionTicket(nst);
            },
            .application_data => |data| if (mem.startsWith(u8, data, "HTTP/1.0 200")) {
                got_response = true;
            },
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .closed => break,
            .none => {},
        };
        if (ticket != null and got_response) break;
    }
    if (ticket == null) return error.NoSessionTicket;
    return ticket.?;
}

/// Connection 2 of PSK resumption: offer the captured ticket and complete the
/// resumed handshake, then exchange application data.
fn clientInteropResume(stream: Stream, ticket: *const tls.ClientHandshake.SessionTicket) !void {
    const kp: tls.x25519.KeyPair = .generate();
    var random: tls.Random = .empty;
    entropy.fill(&random.data);

    var hs: tls.ClientHandshake = .init(.{
        .keypairs = try .init(kp),
        .host_name = "localhost",
        .now_sec = 0,
        .random = random,
        .insecure_no_chain_anchor = true,
        .alpn_protocols = &.{alpn_protocol},
    });
    defer hs.deinit();

    var out: [4096]u8 = undefined;
    var storage: tls.RecordBuffer.Storage = .empty;
    var rb: tls.RecordBuffer = .init(&storage.buffer);

    try tls.io.writeAll(testing.io, stream, try hs.startWithPsk(ticket, &out, false));
    hs.completeWrite();

    while (!hs.isConnected()) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ServerClosed;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .application_data,
            .closed,
            .new_session_ticket,
            => return error.UnexpectedDuringHandshake,
            .none => {},
        };
    }

    const request = try hs.sendApplicationData("GET / HTTP/1.0\r\n\r\n", &out);
    try tls.io.writeAll(testing.io, stream, request);
    hs.completeWrite();

    while (true) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) break;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .application_data => |data| if (mem.startsWith(u8, data, "HTTP/1.0 200")) return,
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .new_session_ticket => {},
            .none => {},
            .closed => return error.ServerClosedBeforeResponse,
        };
    }
    return error.NoHttpResponse;
}

/// Connection 2 of 0-RTT: offer early_data + send 0-RTT data, then complete
/// the resumed handshake and exchange application data.
fn clientEarlyDataInterop(
    stream: Stream,
    ticket: *const tls.ClientHandshake.SessionTicket,
) !void {
    const kp: tls.x25519.KeyPair = .generate();
    var random: tls.Random = .empty;
    entropy.fill(&random.data);

    var hs: tls.ClientHandshake = .init(.{
        .keypairs = try .init(kp),
        .host_name = "localhost",
        .now_sec = 0,
        .random = random,
        .insecure_no_chain_anchor = true,
        .alpn_protocols = &.{alpn_protocol},
    });
    defer hs.deinit();

    var out: [4096]u8 = undefined;
    var storage: tls.RecordBuffer.Storage = .empty;
    var rb: tls.RecordBuffer = .init(&storage.buffer);

    // Send the PSK ClientHello with early_data.
    try tls.io.writeAll(testing.io, stream, try hs.startWithPsk(ticket, &out, true));
    hs.completeWrite();

    // Send 0-RTT data immediately (before the server responds).
    const early = try hs.sendEarlyData("GET / HTTP/1.0\r\n\r\n", &out);
    try tls.io.writeAll(testing.io, stream, early);
    hs.completeWrite();

    // Process the server's response (ServerHello + flight).
    while (!hs.isConnected()) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ServerClosed;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .application_data,
            .closed,
            .new_session_ticket,
            => return error.UnexpectedDuringHandshake,
            .none => {},
        };
    }

    // Read the server's response (the 0-RTT data was the GET request).
    while (true) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) break;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .application_data => |data| if (mem.startsWith(u8, data, "HTTP/1.0 200")) return,
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .new_session_ticket => {},
            .none => {},
            .closed => return error.ServerClosedBeforeResponse,
        };
    }
    return error.NoHttpResponse;
}

const ServerArgs = struct {
    suite: tls.CipherSuite,
    group: ?tls.kex.NamedGroup = null,
    /// The server thread records its outcome here so a failure surfaces as
    /// itself rather than as a generic missing response. `error.ClientClosed`
    /// is how `serve` ends when the peer hangs up, so callers ignore it.
    failure: ?anyerror = null,
};

const server_ticket_identity = "tls-openssl-resumption";

const ServerTicketState = struct {
    psk: [48]u8 = @splat(0),
    psk_len: u8 = 0,
    cipher_suite: tls.CipherSuite = .aes_128_gcm_sha256,
    did_resume: bool = false,

    fn lookup(context: *anyopaque, identity: []const u8) ?tls.ServerHandshake.PskEntry {
        const self: *ServerTicketState = @ptrCast(@alignCast(context));
        if (!mem.eql(u8, identity, server_ticket_identity)) return null;
        return .init(self.psk[0..self.psk_len], self.cipher_suite);
    }
};

const ServerTicketPhase = enum {
    none,
    issue,
    reuse,
};

const ServerResumptionArgs = struct {
    ticket: ServerTicketState = .{},
    failure: ?anyerror = null,
};

fn runServerSuite(arena: Allocator, suite: ServerSuite) !void {
    return runServerSuiteAgainst(arena, suite, &.{"openssl"});
}

/// `program` is the peer executable. The suite runs `openssl s_client`; the
/// cancellation test runs a program that exits without dialing the server,
/// which must fail the test instead of hanging it (#141).
fn runServerSuiteAgainst(arena: Allocator, suite: ServerSuite, program: []const []const u8) !void {
    var listener: Listener = try .init();
    defer listener.deinit();

    var args: ServerArgs = .{ .suite = suite.tls_suite };
    const thread = try std.Thread.spawn(.{}, serverThread, .{ &listener, &args });

    const peer = driveSinglePeer(arena, program, suite.openssl_name, listener.port);
    listener.cancel();
    thread.join();
    const outcome = try peer;

    if (!outcome.exited_ok) return error.OpenSslClientFailed;
    if (args.failure) |err| if (err != error.ClientClosed) return err;
    if (!outcome.saw_response) return error.NoServerResponse;
}

fn runServerResumptionSuite(arena: Allocator, session_path: []const u8) !void {
    var listener: Listener = try .init();
    defer listener.deinit();

    var args: ServerResumptionArgs = .{};
    defer std.crypto.secureZero(u8, &args.ticket.psk);
    const thread = try std.Thread.spawn(.{}, resumptionServerThread, .{ &listener, &args });

    const peers = driveResumptionPeers(arena, session_path, listener.port);
    listener.cancel();
    thread.join();
    const outcome = try peers;

    if (!outcome.first.exited_ok) return error.OpenSslClientFailed;
    if (!outcome.first.saw_response) return error.NoServerResponse;
    if (!outcome.second.exited_ok) return error.OpenSslClientFailed;
    if (args.failure) |err| if (err != error.ClientClosed) return err;
    if (!outcome.second.saw_response) return error.NoServerResponse;
    if (!args.ticket.did_resume) return error.OpenSslClientDidNotResume;
}

fn runServerGroup(arena: Allocator, group: InteropGroup) !void {
    var listener: Listener = try .init();
    defer listener.deinit();

    var args: ServerArgs = .{
        .suite = .aes_128_gcm_sha256,
        .group = group.tls_group,
    };
    const thread = try std.Thread.spawn(.{}, serverThread, .{ &listener, &args });

    const peer = driveGroupPeer(arena, group, listener.port);
    listener.cancel();
    thread.join();
    const outcome = try peer;

    if (!outcome.exited_ok) return error.OpenSslClientFailed;
    if (args.failure) |err| if (err != error.ClientClosed) return err;
    if (!outcome.saw_response) return error.NoServerResponse;
}

/// What one peer left behind. Which half is a failure belongs to the caller,
/// because the peer that exits at once is the expected result in the
/// cancellation test.
const PeerOutcome = struct {
    exited_ok: bool,
    saw_response: bool,
};

/// Feeds the peer one request and records what it said. The caller cancels
/// the listener, so this returns the error rather than deciding its meaning.
fn drivePeer(child: *Child) !PeerOutcome {
    defer killChild(child);
    try writeFileAll(child.stdin.?, "GET / HTTP/1.0\r\n\r\n");
    closeFile(child.stdin.?);
    child.stdin = null;

    var stdout_buf: [4096]u8 = undefined;
    const n = try readFileAll(child.stdout.?, &stdout_buf);
    const term = try waitChild(child);
    return .{
        .exited_ok = exitedZero(term),
        .saw_response = mem.containsAtLeast(u8, stdout_buf[0..n], 1, "hello"),
    };
}

fn driveSinglePeer(
    arena: Allocator,
    program: []const []const u8,
    suite: []const u8,
    port: u16,
) !PeerOutcome {
    var child = try startClient(arena, program, suite, port);
    return drivePeer(&child);
}

fn driveGroupPeer(arena: Allocator, group: InteropGroup, port: u16) !PeerOutcome {
    var child = try startClientWithGroup(arena, group, port);
    return drivePeer(&child);
}

const ResumptionPeers = struct {
    first: PeerOutcome,
    second: PeerOutcome,
};

fn driveResumptionPeers(
    arena: Allocator,
    session_path: []const u8,
    port: u16,
) !ResumptionPeers {
    const first = blk: {
        var child = try startClientSaveSession(arena, session_path, port);
        break :blk try drivePeer(&child);
    };
    const second = blk: {
        var child = try startClientReuseSession(arena, session_path, port);
        break :blk try drivePeer(&child);
    };
    return .{ .first = first, .second = second };
}

fn startClient(
    arena: Allocator,
    program: []const []const u8,
    suite: []const u8,
    port: u16,
) !Child {
    const port_str = try std.fmt.allocPrint(arena, "{d}", .{port});
    const connect_to = try std.fmt.allocPrint(arena, "{s}:{s}", .{ host, port_str });
    const tail = [_][]const u8{
        "s_client",      "-tls1_3",
        "-connect",      connect_to,
        "-ciphersuites", suite,
        "-alpn",         alpn_protocol,
        "-quiet",
    };
    const argv = try arena.alloc([]const u8, program.len + tail.len);
    @memcpy(argv[0..program.len], program);
    @memcpy(argv[program.len..], &tail);
    return std.process.spawn(testing.io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
}

fn startClientSaveSession(
    arena: Allocator,
    session_path: []const u8,
    port: u16,
) !Child {
    const port_str = try std.fmt.allocPrint(arena, "{d}", .{port});
    const connect_to = try std.fmt.allocPrint(arena, "{s}:{s}", .{ host, port_str });
    const argv = &.{
        "openssl",                "s_client",
        "-tls1_3",                "-connect",
        connect_to,               "-ciphersuites",
        "TLS_AES_128_GCM_SHA256", "-alpn",
        alpn_protocol,            "-sess_out",
        session_path,             "-quiet",
    };
    return spawnClient(argv);
}

fn startClientReuseSession(
    arena: Allocator,
    session_path: []const u8,
    port: u16,
) !Child {
    const port_str = try std.fmt.allocPrint(arena, "{d}", .{port});
    const connect_to = try std.fmt.allocPrint(arena, "{s}:{s}", .{ host, port_str });
    const argv = &.{
        "openssl",                "s_client",
        "-tls1_3",                "-connect",
        connect_to,               "-ciphersuites",
        "TLS_AES_128_GCM_SHA256", "-alpn",
        alpn_protocol,            "-sess_in",
        session_path,             "-quiet",
    };
    return spawnClient(argv);
}

fn spawnClient(argv: []const []const u8) !Child {
    return std.process.spawn(testing.io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
}

fn startClientWithGroup(arena: Allocator, group: InteropGroup, port: u16) !Child {
    const port_str = try std.fmt.allocPrint(arena, "{d}", .{port});
    const connect_to = try std.fmt.allocPrint(arena, "{s}:{s}", .{ host, port_str });
    const argv = &.{
        "openssl",                "s_client",
        "-tls1_3",                "-connect",
        connect_to,               "-ciphersuites",
        "TLS_AES_128_GCM_SHA256", "-groups",
        group.openssl_name,       "-alpn",
        alpn_protocol,            "-quiet",
    };
    return std.process.spawn(testing.io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
}

/// Runs on the server thread and records its outcome in `args`, so a failure
/// in `serve` surfaces as itself instead of as a missing response. Returning
/// `void` keeps the thread entry unwrapped: the caller reads the reason after
/// `join`.
fn serverThread(listener: *Listener, args: *ServerArgs) void {
    serveSuite(listener, args) catch |err| {
        args.failure = err;
    };
}

fn serveSuite(listener: *Listener, args: *const ServerArgs) !void {
    const stream = try listener.server.accept(testing.io);
    defer stream.close(testing.io);
    try serve(stream, args.suite, args.group, null, .none);
}

fn resumptionServerThread(listener: *Listener, args: *ServerResumptionArgs) void {
    serveResumption(listener, args) catch |err| {
        args.failure = err;
    };
}

fn serveResumption(listener: *Listener, args: *ServerResumptionArgs) !void {
    {
        const stream = try listener.server.accept(testing.io);
        defer stream.close(testing.io);
        try serve(stream, .aes_128_gcm_sha256, null, &args.ticket, .issue);
    }
    {
        const stream = try listener.server.accept(testing.io);
        defer stream.close(testing.io);
        try serve(stream, .aes_128_gcm_sha256, null, &args.ticket, .reuse);
    }
}

fn serve(
    stream: Stream,
    suite: tls.CipherSuite,
    group: ?tls.kex.NamedGroup,
    ticket_state: ?*ServerTicketState,
    ticket_phase: ServerTicketPhase,
) !void {
    const server_keypair: tls.x25519.KeyPair = .generate();
    var server_random: tls.Random = .empty;
    entropy.fill(&server_random.data);

    var keypairs: tls.ServerHandshake.KeyPairs = try .init(server_keypair);
    if (group == .secp384r1 or group == .secp384r1_mlkem1024)
        keypairs.p384 = try .generate();
    const hybrid_group = if (group) |selected|
        if (selected.hybridSpec() != null) selected else null
    else
        null;
    const groups = [_]tls.kex.NamedGroup{hybrid_group orelse .x25519_mlkem768};
    var hs_config: tls.ServerHandshake.Config = .{ .keypairs = keypairs, .random = server_random };
    hs_config.psk_lookup = if (ticket_phase == .reuse) .{
        .context = ticket_state.?,
        .lookup = ServerTicketState.lookup,
    } else null;
    hs_config.hybrid_groups = if (hybrid_group != null) &groups else &.{};
    var hs: tls.ServerHandshake = .init(hs_config);
    defer hs.deinit();
    hs.supportAlpn(&.{alpn_protocol});
    const supported = [_]tls.CipherSuite{suite};
    hs.supportSuites(&supported);

    var signer = try tls.signature.PrivateKey.fromP256Scalar(server_scalar[0..32]);
    defer signer.deinit();
    hs.setCredentials(&.{server_cert_der}, signer.signer());

    var storage: tls.RecordBuffer.Storage = .empty;
    var rb: tls.RecordBuffer = .init(&storage.buffer);
    var out: [4096]u8 = undefined;
    errdefer |err| sendBestEffortAlert(&hs, stream, err, &out);

    while (!hs.isConnected()) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ClientClosed;
        while (try rb.next()) |record| {
            const ev = try hs.handleRecord(record, &out);
            switch (ev) {
                .write => |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                    if (try hs.sendPreparedServerFlight(&out)) |flight| {
                        try tls.io.writeAll(testing.io, stream, flight);
                        hs.completeWrite();
                    }
                },
                .key_update => |ku| {
                    if (ku.response) |w| {
                        try tls.io.writeAll(testing.io, stream, w);
                        hs.completeWrite();
                    }
                },
                .none => {},
                .application_data => return error.UnexpectedDuringHandshake,
                .closed => return error.UnexpectedDuringHandshake,
            }
            if (hs.isConnected()) break;
        }
    }

    if (ticket_state) |state| switch (ticket_phase) {
        .none => {},
        .issue => {
            var ticket_psk = try hs.deriveTicketPsk();
            defer ticket_psk.secureZero();
            @memcpy(state.psk[0..ticket_psk.psk.len], ticket_psk.psk.constSlice());
            state.psk_len = ticket_psk.psk.len;
            state.cipher_suite = ticket_psk.cipher_suite;
            var age_add_bytes: [4]u8 = undefined;
            entropy.fill(&age_add_bytes);
            const ticket_record = try hs.sendNewSessionTicket(
                &ticket_psk,
                .{
                    .ticket_lifetime = 3600,
                    .ticket_age_add = mem.readInt(u32, &age_add_bytes, .big),
                    .ticket = server_ticket_identity,
                },
                &out,
            );
            try tls.io.writeAll(testing.io, stream, ticket_record);
            hs.completeWrite();
        },
        .reuse => state.did_resume = hs.isResumed(),
    };
    while (true) {
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .application_data => |data| return sendResponse(stream, &hs, data, &out),
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .closed => return,
            .none => {},
        };
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ClientClosed;
    }
}

fn sendResponse(
    stream: Stream,
    hs: *tls.ServerHandshake,
    request: []const u8,
    out: []u8,
) !void {
    if (!mem.startsWith(u8, request, "GET ")) return error.UnexpectedRequest;
    const rec = try hs.sendApplicationData(response, out);
    try tls.io.writeAll(testing.io, stream, rec);
    hs.completeWrite();
    const close = try hs.sendAlert(.close_notify, out);
    try tls.io.writeAll(testing.io, stream, close);
    hs.completeWrite();
}

// RFC 8446 §4.7.2 — tls server requiring client auth, exercised against an
// `openssl s_client -cert -key` peer. The server uses
// insecure_no_client_chain_anchor so the self-signed openssl client cert is
// accepted without a trust bundle; the CertificateVerify still proves key
// possession. Reuses one cipher suite (AES-128-GCM) for the smoke.
fn runServerClientAuthSuite(
    arena: Allocator,
    client_cert_path: []const u8,
    client_key_path: []const u8,
) !void {
    var listener: Listener = try .init();
    defer listener.deinit();

    var args: ServerAuthArgs = .{};
    const thread = try std.Thread.spawn(.{}, serverClientAuthThread, .{ &listener, &args });

    const peer = driveCertPeer(arena, client_cert_path, client_key_path, listener.port);
    listener.cancel();
    thread.join();
    const outcome = try peer;

    if (!outcome.exited_ok) return error.OpenSslClientFailed;
    if (args.failure) |err| if (err != error.ClientClosed) return err;
    if (!outcome.saw_response) return error.NoServerResponse;
}

const ServerAuthArgs = struct {
    failure: ?anyerror = null,
};

fn serverClientAuthThread(listener: *Listener, args: *ServerAuthArgs) void {
    serveClientAuthOn(listener) catch |err| {
        args.failure = err;
    };
}

fn serveClientAuthOn(listener: *Listener) !void {
    const stream = try listener.server.accept(testing.io);
    defer stream.close(testing.io);
    try serveClientAuth(stream);
}

fn driveCertPeer(
    arena: Allocator,
    client_cert_path: []const u8,
    client_key_path: []const u8,
    port: u16,
) !PeerOutcome {
    var child = try startClientWithCert(arena, client_cert_path, client_key_path, port);
    return drivePeer(&child);
}

fn serveClientAuth(stream: Stream) !void {
    const server_keypair: tls.x25519.KeyPair = .generate();
    var server_random: tls.Random = .empty;
    entropy.fill(&server_random.data);

    var hs: tls.ServerHandshake = .init(.{
        .keypairs = try .init(server_keypair),
        .random = server_random,
        .client_auth = .required,
        .insecure_no_client_chain_anchor = true,
    });
    defer hs.deinit();
    hs.supportAlpn(&.{alpn_protocol});
    const supported = [_]tls.CipherSuite{.aes_128_gcm_sha256};
    hs.supportSuites(&supported);

    var signer = try tls.signature.PrivateKey.fromP256Scalar(server_scalar[0..32]);
    defer signer.deinit();
    hs.setCredentials(&.{server_cert_der}, signer.signer());

    var storage: tls.RecordBuffer.Storage = .empty;
    var rb: tls.RecordBuffer = .init(&storage.buffer);
    var out: [4096]u8 = undefined;
    errdefer |err| sendBestEffortAlert(&hs, stream, err, &out);

    while (!hs.isConnected()) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ClientClosed;
        while (try rb.next()) |record| {
            const ev = try hs.handleRecord(record, &out);
            switch (ev) {
                .write => |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                    if (try hs.sendPreparedServerFlight(&out)) |flight| {
                        try tls.io.writeAll(testing.io, stream, flight);
                        hs.completeWrite();
                    }
                },
                .key_update => |ku| {
                    if (ku.response) |w| {
                        try tls.io.writeAll(testing.io, stream, w);
                        hs.completeWrite();
                    }
                },
                .none => {},
                .application_data => |data| {
                    if (!hs.isConnected()) return error.UnexpectedDuringHandshake;
                    return sendResponse(stream, &hs, data, &out);
                },
                .closed => return error.UnexpectedDuringHandshake,
            }
        }
    }

    while (true) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ClientClosed;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .application_data => |data| return sendResponse(stream, &hs, data, &out),
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .closed => return,
            .none => {},
        };
    }
}

fn startClientWithCert(
    arena: Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    port: u16,
) !Child {
    const port_str = try std.fmt.allocPrint(arena, "{d}", .{port});
    const connect_to = try std.fmt.allocPrint(arena, "{s}:{s}", .{ host, port_str });
    const argv = &.{
        "openssl",                "s_client",
        "-tls1_3",                "-connect",
        connect_to,               "-ciphersuites",
        "TLS_AES_128_GCM_SHA256", "-alpn",
        alpn_protocol,            "-cert",
        cert_path,                "-key",
        key_path,                 "-quiet",
    };
    return std.process.spawn(testing.io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
}

// RFC 8446 §4.7.2 — tls client presenting credentials to `openssl s_server
// -Verify -CAfile`. The client reuses the self-signed ECDSA fixture as its
// client certificate; the CAfile is the fixture cert PEM (self-signed = its
// own CA). The client skips server chain validation (insecure_no_chain_anchor)
// since the openssl s_server uses a generated self-signed cert.
fn runClientAuthClientSuite(
    arena: Allocator,
    server_cert_path: []const u8,
    server_key_path: []const u8,
    client_ca_path: []const u8,
) !void {
    const port = try freePort();
    var child = try startServerVerify(
        arena,
        server_cert_path,
        server_key_path,
        client_ca_path,
        port,
    );
    defer killChild(&child);
    // Give s_server a moment to bind.
    const stream = try connectWithRetry(port);
    defer stream.close(testing.io);
    try clientInteropWithCreds(stream);
}

fn startServerVerify(
    arena: Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    ca_path: []const u8,
    port: u16,
) !Child {
    const port_str = try std.fmt.allocPrint(arena, "{d}", .{port});
    const argv = &.{
        "openssl",                "s_server",
        "-tls1_3",                "-ciphersuites",
        "TLS_AES_128_GCM_SHA256", "-key",
        key_path,                 "-cert",
        cert_path,                "-port",
        port_str,                 "-www",
        "-alpn",                  alpn_protocol,
        "-Verify",                "1",
        "-CAfile",                ca_path,
        "-quiet",
    };
    return std.process.spawn(testing.io, .{
        .argv = argv,
        .stdout = .ignore,
        .stderr = .ignore,
    });
}

fn clientInteropWithCreds(stream: Stream) !void {
    const kp: tls.x25519.KeyPair = .generate();
    var random: tls.Random = .empty;
    entropy.fill(&random.data);

    var hs: tls.ClientHandshake = .init(.{
        .keypairs = try .init(kp),
        .host_name = "localhost",
        .now_sec = 0,
        .random = random,
        .insecure_no_chain_anchor = true,
        .alpn_protocols = &.{alpn_protocol},
    });
    defer hs.deinit();
    // Present the self-signed ECDSA fixture as the client certificate.
    var client_signer = try tls.signature.PrivateKey.fromP256Scalar(server_scalar[0..32]);
    defer client_signer.deinit();
    hs.setCredentials(&.{server_cert_der}, client_signer.signer());

    var out: [4096]u8 = undefined;
    var storage: tls.RecordBuffer.Storage = .empty;
    var rb: tls.RecordBuffer = .init(&storage.buffer);

    try tls.io.writeAll(testing.io, stream, try hs.start(&out));
    hs.completeWrite();

    while (!hs.isConnected()) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) return error.ServerClosed;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .application_data,
            .closed,
            .new_session_ticket,
            => return error.UnexpectedDuringHandshake,
            .none => {},
        };
    }
    try testing.expectEqualStrings(alpn_protocol, hs.selectedAlpnProtocol().?);

    const request = try hs.sendApplicationData("GET / HTTP/1.0\r\n\r\n", &out);
    try tls.io.writeAll(testing.io, stream, request);
    hs.completeWrite();

    while (true) {
        const n = try tls.io.fill(testing.io, stream, &rb);
        if (n == 0) break;
        while (try rb.next()) |record| switch (try hs.handleRecord(record, &out)) {
            .application_data => |data| if (mem.startsWith(u8, data, "HTTP/1.0 200")) return,
            .write => |w| {
                try tls.io.writeAll(testing.io, stream, w);
                hs.completeWrite();
            },
            .key_update => |ku| {
                if (ku.response) |w| {
                    try tls.io.writeAll(testing.io, stream, w);
                    hs.completeWrite();
                }
            },
            .new_session_ticket => {},
            .none => {},
            .closed => return error.ServerClosedBeforeResponse,
        };
    }
    return error.NoHttpResponse;
}

/// Write the self-signed ECDSA fixture certificate (&fixtures.server_ecdsa_cert_der)
/// as a PEM file so `openssl s_server -Verify -CAfile` trusts the tls client's
/// client certificate (the fixture is self-signed, so it is its own CA).
fn writeFixtureCertPem(arena: Allocator, pem_path: []const u8) !void {
    // PEM is base64 of the DER wrapped in BEGIN/END CERTIFICATE lines.
    const der = server_cert_der;
    const enc = std.base64.standard.Encoder;
    const b64_len = enc.calcSize(der.len);
    var b64_buf: [4096]u8 = undefined;
    if (b64_len > b64_buf.len) return error.BufferTooShort;
    const encoded = enc.encode(b64_buf[0..b64_len], der);

    const pem = try std.fmt.allocPrint(
        arena,
        "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n",
        .{encoded},
    );
    try Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = pem_path, .data = pem });
}

fn sendBestEffortAlert(
    hs: *tls.ServerHandshake,
    stream: Stream,
    err: anyerror,
    out: []u8,
) void {
    const description = tls.alert.alertForError(err);
    const alert_record = hs.sendAlert(description, out) catch return;
    tls.io.writeAll(testing.io, stream, alert_record) catch return;
}

/// A port no process holds, for a peer that binds it a moment later. The
/// kernel assigns it, so concurrent test runs get different ports. The peer
/// may lose the tiny race to another process between release and bind;
/// `connectWithRetry` then fails fast instead of blocking.
fn freePort() !u16 {
    const addr: IpAddress = try .parse(host, 0);
    var server = try addr.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);
    return server.socket.address.getPort();
}

fn connectWithRetry(port: u16) !Stream {
    const addr: IpAddress = try .parse("127.0.0.1", port);
    for (0..100) |_| {
        return addr.connect(testing.io, .{ .mode = .stream }) catch {
            sleep20ms();
            continue;
        };
    }
    return error.ServerNeverCameUp;
}

fn tmpDirPath(arena: Allocator, tmp: anytype) ![]const u8 {
    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &path_buf);
    return arena.dupe(u8, path_buf[0..len]);
}

fn killChild(child: *Child) void {
    child.kill(testing.io);
}

fn waitChild(child: *Child) !Child.Term {
    return child.wait(testing.io);
}

fn exitedZero(term: Child.Term) bool {
    return term == .exited and term.exited == 0;
}

fn writeFileAll(file: anytype, bytes: []const u8) !void {
    var writer_buf: [1024]u8 = undefined;
    var writer = file.writer(testing.io, &writer_buf);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn readFileAll(file: anytype, buf: []u8) !usize {
    var reader_buf: [1024]u8 = undefined;
    var reader = file.readerStreaming(testing.io, &reader_buf);
    var total: usize = 0;
    while (total < buf.len) {
        const n = try reader.interface.readSliceShort(buf[total..]);
        if (n == 0) break;
        total += n;
    }
    return total;
}

fn closeFile(file: anytype) void {
    file.close(testing.io);
}

fn sleep20ms() void {
    testing.io.sleep(.fromNanoseconds(20 * std.time.ns_per_ms), .awake) catch return;
}
