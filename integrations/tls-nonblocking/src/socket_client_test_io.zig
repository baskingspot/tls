//! An evented batch fixture. Await leaves one read pending until cancel.
const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

pub const BatchProbe = struct {
    wait_error: ?Io.Batch.AwaitConcurrentError,
    complete_on_cancel: ?u8,
    cancel_called: bool,
    destination: []u8,

    pub fn init(wait_error: ?Io.Batch.AwaitConcurrentError, complete_on_cancel: ?u8) BatchProbe {
        return .{
            .wait_error = wait_error,
            .complete_on_cancel = complete_on_cancel,
            .cancel_called = false,
            .destination = &.{},
        };
    }

    pub fn now(_: ?*anyopaque, _: Io.Clock) Io.Timestamp {
        return .fromNanoseconds(1000);
    }

    pub fn awaitConcurrent(
        context: ?*anyopaque,
        batch: *Io.Batch,
        _: Io.Timeout,
    ) Io.Batch.AwaitConcurrentError!void {
        const self: *BatchProbe = @ptrCast(@alignCast(context.?));
        assert(batch.storage.len == 1);
        assert(batch.submitted.head.toIndex() == 0);
        self.destination = batch.storage[0].submission.operation.net_read.data[0];
        batch.submitted = .empty;
        batch.storage[0] = .{ .pending = .{
            .node = .{ .prev = .none, .next = .none },
            .tag = .net_read,
            .userdata = undefined,
        } };
        batch.pending = .{ .head = .fromIndex(0), .tail = .fromIndex(0) };
        batch.userdata = self;
        if (self.wait_error) |err| return err;
    }

    pub fn cancel(context: ?*anyopaque, batch: *Io.Batch) void {
        const self: *BatchProbe = @ptrCast(@alignCast(context.?));
        assert(batch.pending.head.toIndex() == 0);
        self.cancel_called = true;
        batch.pending = .empty;
        batch.userdata = null;
        if (self.complete_on_cancel) |byte| {
            self.destination[0] = byte;
            batch.storage[0] = .{ .completion = .{
                .node = .{ .next = .none },
                .result = .{ .net_read = .{ .data_len = 1 } },
            } };
            batch.completed = .{ .head = .fromIndex(0), .tail = .fromIndex(0) };
        } else {
            batch.storage[0] = .{ .unused = .{ .prev = .none, .next = .none } };
            batch.unused = .{ .head = .fromIndex(0), .tail = .fromIndex(0) };
        }
    }
};
