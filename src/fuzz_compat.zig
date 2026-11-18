//! Adapter from std.testing.fuzz's Smith-driven input to byte-slice targets.
const std = @import("std");
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
        framed.* = try frameCorpusEntry(input);
        framed_count += 1;
    }
    var framed_options = options;
    framed_options.corpus = corpus;
    return testing.fuzz(context, Wrapper.run, framed_options);
}

fn frameCorpusEntry(input: []const u8) ![]u8 {
    const bytes = try testing.allocator.alloc(u8, 4 + input.len);
    mem.writeInt(u32, bytes[0..4], @intCast(input.len), .little);
    @memcpy(bytes[4..], input);
    return bytes;
}

test "fuzzBytes frames corpus entries with the Smith.slice length prefix" {
    const corpus = [_][]const u8{ "hello", "", "\x00\xff\x04\x00\x00\x00tail" };
    for (corpus) |input| {
        const framed = try frameCorpusEntry(input);
        defer testing.allocator.free(framed);
        const len = mem.readInt(u32, framed[0..4], .little);
        try testing.expectEqual(@as(u32, @intCast(input.len)), len);
        try testing.expectEqualSlices(u8, input, framed[4..]);
    }
}
