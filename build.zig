const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The core module: a single translation unit exposing a C ABI surface.
    const mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        // We use std.heap.c_allocator for FFI-owned allocations (the trie),
        // so the shared library links libc.
        .link_libc = true,
    });

    // Shared library consumed by the Python (cffi) wrapper over the C ABI.
    const lib = b.addLibrary(.{
        .name = "znetaddress",
        .root_module = mod,
        .linkage = .dynamic,
    });
    b.installArtifact(lib);

    // Also install the public C header alongside the artifact.
    b.installFile("include/znetaddress.h", "include/znetaddress.h");

    // `zig build test` runs the Zig unit tests.
    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run Zig unit tests");
    test_step.dependOn(&run_tests.step);
}
