const std = @import("std");

const Mode = enum {
    core,
    nonblocking,
    std,
    ktls,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mode = b.option(Mode, "mode", "tls module to compile") orelse .core;

    const tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
    });
    const integration_name = switch (mode) {
        .core => "tls",
        .nonblocking => "tls_nonblocking",
        .std => "tls_std",
        .ktls => "tls_ktls",
    };

    const options = b.addOptions();
    options.addOption([]const u8, "mode", @tagName(mode));

    const exe = b.addExecutable(.{
        .name = "tls-distribution-consumer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls", .module = tls_dep.module("tls") },
                .{ .name = "integration", .module = tls_dep.module(integration_name) },
                .{ .name = "consumer_options", .module = options.createModule() },
            },
        }),
    });
    b.installArtifact(exe);
}
