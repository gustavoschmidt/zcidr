//! zcidr core — a fast IP / CIDR toolkit exposed over a C ABI.
//!
//! This file is the single translation unit for the shared library. It
//! re-exports the C ABI surface implemented across the submodules and keeps
//! the FFI boundary simple: bytes / ints / bools in, simple values out.

const std = @import("std");
const builtin = @import("builtin");

/// Submodules. Importing them here compiles their `export fn`s into the shared
/// library and pulls their tests into `zig build test`.
pub const lines = @import("lines.zig");
pub const ipv4 = @import("ipv4.zig");
pub const ipv6 = @import("ipv6.zig");
pub const cidr = @import("cidr.zig");
pub const trie = @import("trie.zig");

/// Semantic version of the library, packed as (major << 16) | (minor << 8) | patch.
pub const version = struct {
    pub const major: u32 = 0;
    pub const minor: u32 = 1;
    pub const patch: u32 = 0;
};

/// Return the packed library version. Stable C ABI entry point; also serves as
/// the minimal "is the library loaded and callable" smoke check for the wrapper.
export fn zcidr_version() u32 {
    return (version.major << 16) | (version.minor << 8) | version.patch;
}

// Force the submodules to be analyzed so their `export fn`s are emitted into
// the shared library (importing a file alone does not pull in its exports).
comptime {
    _ = ipv4;
    _ = ipv6;
    _ = cidr;
    _ = trie;
}

test "zcidr_version packs semver" {
    try std.testing.expectEqual(@as(u32, 0x000100), zcidr_version());
}

// Pull the submodules into the test build so `zig build test` covers them all.
test {
    std.testing.refAllDecls(@This());
    _ = lines;
    _ = ipv4;
    _ = ipv6;
    _ = cidr;
    _ = trie;
}
