const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("objcopy.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "objcopy",
        .root_module = mod,
    });

    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Run the application").dependOn(&run.step);

    const test_exe = b.addTest(.{
        .root_module = mod,
    });

    b.step("test", "Run unit tests").dependOn(
        &b.addRunArtifact(test_exe).step,
    );
}
