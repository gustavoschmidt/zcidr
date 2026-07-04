//! znetaddress core — a fast IP / CIDR toolkit exposed over a C ABI.
//!
//! This file is the single translation unit for the shared library. It
//! re-exports the C ABI surface implemented across the submodules and keeps
//! the FFI boundary simple: bytes / ints / bools in, simple values out.

const std = @import("std");
const builtin = @import("builtin");

/// Semantic version of the library, packed as (major << 16) | (minor << 8) | patch.
pub const version = struct {
    pub const major: u32 = 0;
    pub const minor: u32 = 1;
    pub const patch: u32 = 0;
};

/// Return the packed library version. Stable C ABI entry point; also serves as
/// the minimal "is the library loaded and callable" smoke check for the wrapper.
export fn znet_version() u32 {
    return (version.major << 16) | (version.minor << 8) | version.patch;
}

test "znet_version packs semver" {
    try std.testing.expectEqual(@as(u32, 0x000100), znet_version());
}

// Pull the submodules into the test build so `zig build test` covers them all.
test {
    std.testing.refAllDecls(@This());
}
