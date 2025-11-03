const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const priv_lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root_priv.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    priv_lib_mod.addImport("util", priv_lib_mod);

    const exe_check = b.addExecutable(.{
        .name = "net_check",
        .root_module = priv_lib_mod,
    });

    const check = b.step("check", "check if app compiles");
    check.dependOn(&exe_check.step);

    const lib_unit_tests = b.addTest(.{
        .root_module = priv_lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const lib_mod = b.addModule("znetw", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });

    priv_lib_mod.addImport("znetw", lib_mod);
    lib_mod.addImport("util", priv_lib_mod);

    const lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "znetw",
        .root_module = lib_mod,
    });

    b.installArtifact(lib);
}
