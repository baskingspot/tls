const std = @import("std");

const Mode = enum {
    core,
    std,
    xev,
    xev_without_option,
    ktls,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mode = b.option(Mode, "mode", "tls module to compile") orelse .core;

    const tls_dep = if (mode == .xev)
        b.dependency("tls", .{
            .target = target,
            .optimize = optimize,
            .xev = true,
        })
    else
        b.dependency("tls", .{
            .target = target,
            .optimize = optimize,
        });
    const integration_name = switch (mode) {
        .core => "tls",
        .std => "tls_std",
        .xev, .xev_without_option => "tls_xev",
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
