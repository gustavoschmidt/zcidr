//! CIDR network parsing: "1.2.3.0/24", "2001:db8::/32", or a bare host address
//! (which is treated as a /32 or /128).

const std = @import("std");
const abi = @import("abi.zig");
const ipv4 = @import("ipv4.zig");
const ipv6 = @import("ipv6.zig");

pub const ParseError = error{Invalid};

pub const Cidr = struct {
    is_v6: bool,
    /// Network-order address bytes; for IPv4 only the first 4 are meaningful.
    bytes: [16]u8,
    /// Prefix length in bits (0..32 for IPv4, 0..128 for IPv6).
    prefix_len: u8,

    pub fn maxBits(self: Cidr) u8 {
        return if (self.is_v6) 128 else 32;
    }
};

/// Parse the decimal prefix after '/': 1..3 digits, no leading zeros, <= max.
fn parsePrefix(s: []const u8, max: u8) ParseError!u8 {
    if (s.len == 0 or s.len > 3) return error.Invalid;
    if (s.len > 1 and s[0] == '0') return error.Invalid; // leading zero
    var v: u16 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.Invalid;
        v = v * 10 + (c - '0');
    }
    if (v > max) return error.Invalid;
    return @intCast(v);
}

/// Parse a CIDR string. The family is inferred from the address part (an
/// address containing ':' is IPv6). A missing "/prefix" defaults to a host
/// route (full-length prefix).
pub fn parse(s: []const u8) ParseError!Cidr {
    const slash = std.mem.indexOfScalar(u8, s, '/');
    const addr_part = if (slash) |i| s[0..i] else s;
    const is_v6 = std.mem.indexOfScalar(u8, addr_part, ':') != null;

    var cidr: Cidr = .{ .is_v6 = is_v6, .bytes = undefined, .prefix_len = 0 };

    if (is_v6) {
        cidr.bytes = try ipv6.parse(addr_part);
        cidr.prefix_len = if (slash) |i| try parsePrefix(s[i + 1 ..], 128) else 128;
    } else {
        const v4 = ipv4.parse(addr_part) catch return error.Invalid;
        cidr.bytes = undefined;
        cidr.bytes[0] = @truncate(v4 >> 24);
        cidr.bytes[1] = @truncate(v4 >> 16);
        cidr.bytes[2] = @truncate(v4 >> 8);
        cidr.bytes[3] = @truncate(v4);
        cidr.prefix_len = if (slash) |i| try parsePrefix(s[i + 1 ..], 32) else 32;
    }
    return cidr;
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

/// Parse a CIDR string. On success sets `*is_v6` (0/1), writes up to 16
/// network-order bytes to `out_bytes`, and `*out_prefix`.
export fn zcidr_cidr_parse(
    s: [*]const u8,
    len: usize,
    is_v6: *c_int,
    out_bytes: *[16]u8,
    out_prefix: *u8,
) c_int {
    const c = parse(s[0..len]) catch return abi.ERR_INVALID;
    is_v6.* = if (c.is_v6) 1 else 0;
    out_bytes.* = c.bytes;
    out_prefix.* = c.prefix_len;
    return abi.OK;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parse ipv4 cidr" {
    const c = try parse("192.168.1.0/24");
    try std.testing.expect(!c.is_v6);
    try std.testing.expectEqual(@as(u8, 24), c.prefix_len);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 0 }, c.bytes[0..4]);
}

test "parse ipv4 host defaults to /32" {
    const c = try parse("10.0.0.1");
    try std.testing.expectEqual(@as(u8, 32), c.prefix_len);
}

test "parse ipv6 cidr" {
    const c = try parse("2001:db8::/32");
    try std.testing.expect(c.is_v6);
    try std.testing.expectEqual(@as(u8, 32), c.prefix_len);
    try std.testing.expectEqual(@as(u8, 0x20), c.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x01), c.bytes[1]);
}

test "parse ipv6 host defaults to /128" {
    const c = try parse("::1");
    try std.testing.expectEqual(@as(u8, 128), c.prefix_len);
}

test "parse default routes" {
    try std.testing.expectEqual(@as(u8, 0), (try parse("0.0.0.0/0")).prefix_len);
    try std.testing.expectEqual(@as(u8, 0), (try parse("::/0")).prefix_len);
}

test "parse rejects bad prefix" {
    const bad = [_][]const u8{
        "192.168.1.0/33",
        "192.168.1.0/",
        "192.168.1.0/024",
        "192.168.1.0/abc",
        "2001:db8::/129",
        "1.2.3.4/-1",
        "999.1.1.1/24",
        "192.168.1.0/1000",
    };
    for (bad) |s| try std.testing.expectError(error.Invalid, parse(s));
}
