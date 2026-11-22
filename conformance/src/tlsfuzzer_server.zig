const std = @import("std");
const Io = std.Io;
const print = std.debug.print;
const IpAddress = Io.net.IpAddress;

const tls = @import("tls");

const harness = @import("harness.zig");

const hybrid_groups = blk: {
    var groups: [tls.capabilities.hybrid_groups.len]tls.kex.NamedGroup = undefined;
    var count = 0;
    for (tls.capabilities.hybrid_groups) |group| {
        if (!tls.capabilities.supportsHybridGroup(.server, group)) continue;
        groups[count] = group;
        count += 1;
    }
    break :blk groups[0..count].*;
};

const Credential = enum { ecdsa, rsa };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 2 and std.mem.eql(u8, args[1], "--capabilities")) {
        printCapabilities();
        return;
    }
    if (args.len != 1) return error.InvalidArguments;

    const io = init.io;
    const credential = try readCredential(init.environ_map);
    var enabled_hybrid_groups = hybrid_groups;
    var hybrid_group_count = enabled_hybrid_groups.len;
    if (init.environ_map.get("TLS_HYBRID_GROUP")) |selected| {
        hybrid_group_count = 0;
        for (enabled_hybrid_groups) |group| {
            if (std.mem.eql(u8, selected, @tagName(group))) {
                enabled_hybrid_groups[0] = group;
                hybrid_group_count = 1;
                break;
            }
        }
        if (hybrid_group_count == 0) return error.UnknownHybridGroup;
    }
    const port = try readPort(init.environ_map);
    const address: IpAddress = try .parse("127.0.0.1", port);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    print("tls tlsfuzzer server listening on 127.0.0.1:{d}\n", .{port});

    while (true) {
        const stream = server.accept(io) catch |err| switch (err) {
            error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => return err,
            else => continue,
        };
        handleConnection(
            io,
            stream,
            credential,
            enabled_hybrid_groups[0..hybrid_group_count],
        ) catch continue;
    }
}

fn printCapabilities() void {
    print("backend={s}\n", .{@tagName(tls.capabilities.active_backend)});
    for (tls.SignatureScheme.supported_handshake) |scheme| {
        printCapability(
            "certificate_verify",
            @tagName(scheme),
            tls.capabilities.supportsCertificateVerifyScheme(scheme),
        );
    }
    // supported_handshake is the default advertisement list, not the full
    // verifier surface. Native also verifies explicit SHA-512 offers.
    printCapability(
        "certificate_verify",
        "rsa_pss_rsae_sha512",
        tls.capabilities.supportsCertificateVerifyScheme(.rsa_pss_rsae_sha512),
    );
    for (tls.SignatureScheme.supported_certificate) |scheme| {
        printCapability(
            "certificate_signature",
            @tagName(scheme),
            tls.capabilities.supportsCertificateSignatureScheme(scheme),
        );
    }
    // RSA-PSS verification does not imply RSA private-key loading or signing.
    printCapability(
        "private_key",
        "rsa_pss_rsae_sha256",
        tls.capabilities.active_backend != .native,
    );
    const classical_groups = [_]tls.kex.NamedGroup{ .x25519, .secp256r1, .secp384r1 };
    for (classical_groups) |group| {
        printGroupCapability("client", group, tls.capabilities.supportsGroup(.client, group));
        printGroupCapability("server", group, tls.capabilities.supportsGroup(.server, group));
    }
    for (tls.capabilities.hybrid_groups) |group| {
        printGroupCapability("client", group, tls.capabilities.supportsGroup(.client, group));
        printGroupCapability("server", group, tls.capabilities.supportsGroup(.server, group));
    }
}

fn printCapability(comptime family: []const u8, name: []const u8, supported: bool) void {
    print("capability.{s}.{s}={s}\n", .{ family, name, if (supported) "true" else "false" });
}

fn printGroupCapability(
    comptime role: []const u8,
    group: tls.kex.NamedGroup,
    supported: bool,
) void {
    printCapability(role ++ "_group", @tagName(group), supported);
}

fn readCredential(env: *std.process.Environ.Map) !Credential {
    const value = env.get("TLS_CREDENTIAL") orelse return .ecdsa;
    if (std.mem.eql(u8, value, "ecdsa")) return .ecdsa;
    if (std.mem.eql(u8, value, "rsa")) return .rsa;
    return error.UnknownCredential;
}

fn readPort(env: *std.process.Environ.Map) !u16 {
    if (env.get("PORT")) |value| {
        return std.fmt.parseInt(u16, value, 10);
    }
    return 4433;
}

fn handleConnection(
    io: Io,
    stream: harness.Stream,
    credential: Credential,
    groups: []const tls.kex.NamedGroup,
) !void {
    defer stream.close(io);

    var signer = switch (credential) {
        .ecdsa => try harness.testSigner(),
        .rsa => try harness.testRsaSigner(),
    };
    defer signer.deinit();

    const random = harness.randomBytes(io);
    // RFC 8446 §5.1 — provide storage for fragmented ClientHello reassembly.
    var reassembly_buf: [tls.ServerHandshake.ch_reassembly_buffer_size]u8 = undefined;
    var hs: tls.ServerHandshake = .init(
        .{
            .alpn_protocols = &.{ "http/1.1", "h2" },
            .hybrid_groups = groups,
        },
        .{
            .keypairs = .initWithP256P384(
                .generate(),
                try .generate(),
                try .generate(),
            ),
            .random = random,
            .reassembly = &reassembly_buf,
        },
    );
    defer hs.deinit();
    const cert_der = switch (credential) {
        .ecdsa => harness.testCertDer(),
        .rsa => harness.testRsaCertDer(),
    };
    try hs.setCredentials(&.{cert_der}, signer.signer());

    var in_buf: [tls.frame.header_len + tls.frame.max_ciphertext_len]u8 = undefined;
    var out_buf: [harness.max_wire_record_len]u8 = undefined;

    while (true) {
        const record = harness.readRecord(io, stream, &in_buf) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return,
        };

        const ev = hs.handleRecord(record, &out_buf) catch |err| {
            harness.sendBestEffortAlert(io, &hs, stream, err, &out_buf);
            return;
        };

        switch (ev) {
            .write => |bytes| {
                try tls.io.writeAll(io, stream, bytes);
                hs.completeWrite();
                if (hs.sendPreparedServerFlight(&out_buf) catch |err| {
                    harness.sendBestEffortAlert(io, &hs, stream, err, &out_buf);
                    return;
                }) |flight| {
                    try tls.io.writeAll(io, stream, flight);
                    hs.completeWrite();
                }
            },
            .application_data => |data| {
                const response = hs.sendApplicationData(data, &out_buf) catch |err| {
                    harness.sendBestEffortAlert(io, &hs, stream, err, &out_buf);
                    return;
                };
                try tls.io.writeAll(io, stream, response);
                hs.completeWrite();
            },
            .key_update => |ku| {
                // RFC 8446 §4.6.3 — peer KeyUpdate ratchets traffic keys.
                // Write the response (if any) and acknowledge it; keep serving.
                if (ku.response) |bytes| {
                    try tls.io.writeAll(io, stream, bytes);
                    hs.completeWrite();
                }
            },
            .closed => {
                harness.sendBestEffortCloseNotify(io, &hs, stream, &out_buf);
                return;
            },
            .none => {},
        }
    }
}
