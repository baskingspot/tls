//! Adapter from std.testing.fuzz's Smith-driven input to byte-slice targets.
const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const mem = std.mem;

const max_input_len = 64 * 1024;

/// Run a byte-slice target over raw corpus entries and Smith-generated input.
/// `options.corpus` contains target bytes, not Smith's serialized slice framing.
pub fn fuzzBytes(
    comptime testOne: anytype,
    context: anytype,
    options: testing.FuzzInputOptions,
) anyerror!void {
    const Wrapper = struct {
        fn run(ctx: @TypeOf(context), smith: *testing.Smith) anyerror!void {
            var buf: [max_input_len]u8 = undefined;
            const len = smith.slice(&buf);
            return testOne(ctx, buf[0..len]);
        }
    };

    // Smith.slice consumes a little-endian u32 length before each input. Frame
    // raw corpus entries once during setup so direct replay and fuzzing see
    // the same target bytes. The fuzzer copies each entry before this returns.
    const corpus = try testing.allocator.alloc([]const u8, options.corpus.len);
    defer testing.allocator.free(corpus);
    var framed_count: usize = 0;
    defer for (corpus[0..framed_count]) |entry| testing.allocator.free(entry);
    for (options.corpus, corpus) |input, *framed| {
        const bytes = try testing.allocator.alloc(u8, 4 + input.len);
        framed.* = bytes;
        framed_count += 1;
        mem.writeInt(u32, bytes[0..4], @intCast(input.len), .little);
        @memcpy(bytes[4..], input);
    }
    var framed_options = options;
    framed_options.corpus = corpus;
    return testing.fuzz(context, Wrapper.run, framed_options);
}

const CorpusReplay = struct {
    corpus: []const []const u8,
    index: usize = 0,
};

fn expectCorpusReplay(replay: *CorpusReplay, input: []const u8) anyerror!void {
    const expected = if (replay.index < replay.corpus.len) replay.corpus[replay.index] else "";
    try testing.expectEqualSlices(u8, expected, input);
    replay.index += 1;
}

test "fuzzBytes replays unframed corpus entries verbatim" {
    if (builtin.fuzz) return error.SkipZigTest;
    const corpus = [_][]const u8{ "hello", "", "\x00\xff\x04\x00\x00\x00tail" };
    var replay: CorpusReplay = .{ .corpus = &corpus };
    try fuzzBytes(expectCorpusReplay, &replay, .{ .corpus = &corpus });
    try testing.expectEqual(corpus.len + 1, replay.index);
}
