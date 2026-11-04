const std = @import("std");
const tls = @import("tls");
const integration = @import("integration");
const options = @import("consumer_options");

comptime {
    _ = tls.RecordBuffer;
    if (std.mem.eql(u8, options.mode, "core")) {
        _ = integration.ClientHandshake;
    } else if (std.mem.eql(u8, options.mode, "nonblocking")) {
        _ = integration.Server;
        _ = integration.Server.init;
        _ = integration.Server.next;
        _ = integration.Server.write;
    } else {
        _ = integration.Client;
    }
}

pub fn main() void {}
