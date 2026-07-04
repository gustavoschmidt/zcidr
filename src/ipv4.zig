//! IPv4 address parsing and normalization.
//!
//! Addresses are represented as a host-order `u32` whose most significant byte
//! is the first octet, so "1.2.3.4" == 0x01020304 (matching the integer value
//! of Python's `ipaddress.IPv4Address`).

const std = @import("std");
const abi = @import("abi.zig");

pub const ParseError = error{Invalid};

/// Maximum length of a formatted IPv4 address: "255.255.255.255".
pub const max_str_len = 15;

/// Parse a strict dotted-decimal IPv4 address into a host-order `u32`.
///
/// Strict rules (matching Python's `ipaddress`):
///   * exactly four octets separated by '.'
///   * each octet is 1..3 ASCII digits with no leading zeros ("0" is fine,
///     "00"/"01" are rejected)
///   * each octet is in 0..255
pub fn parse(s: []const u8) ParseError!u32 {
    var result: u32 = 0;
    var field: usize = 0;
    var i: usize = 0;

    while (field < 4) : (field += 1) {
        if (field != 0) {
            if (i >= s.len or s[i] != '.') return error.Invalid;
            i += 1;
        }

        // Read 1..3 digits.
        const start = i;
        var octet: u32 = 0;
        while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
            octet = octet * 10 + (s[i] - '0');
            if (i - start >= 3) return error.Invalid; // > 3 digits
        }
        const digits = i - start;
        if (digits == 0) return error.Invalid; // empty octet
        if (digits > 1 and s[start] == '0') return error.Invalid; // leading zero
        if (octet > 255) return error.Invalid;

        result = (result << 8) | octet;
    }

    if (i != s.len) return error.Invalid; // trailing garbage / extra octets
    return result;
}

/// Format a host-order `u32` as dotted-decimal into `buf`.
/// Returns the written slice, or `error.Invalid` if `buf` is too small.
pub fn format(addr: u32, buf: []u8) ParseError![]u8 {
    var n: usize = 0;
    var octet: usize = 0;
    while (octet < 4) : (octet += 1) {
        if (octet != 0) {
            if (n >= buf.len) return error.Invalid;
            buf[n] = '.';
            n += 1;
        }
        const byte: u8 = @truncate(addr >> @intCast((3 - octet) * 8));
        n += writeByte(byte, buf[n..]) catch return error.Invalid;
    }
    return buf[0..n];
}

/// Write the decimal representation of `byte` (0..255) to the front of `buf`.
/// Returns the number of digits written.
fn writeByte(byte: u8, buf: []u8) error{Invalid}!usize {
    if (byte >= 100) {
        if (buf.len < 3) return error.Invalid;
        buf[0] = '0' + byte / 100;
        buf[1] = '0' + (byte / 10) % 10;
        buf[2] = '0' + byte % 10;
        return 3;
    } else if (byte >= 10) {
        if (buf.len < 2) return error.Invalid;
        buf[0] = '0' + byte / 10;
        buf[1] = '0' + byte % 10;
        return 2;
    } else {
        if (buf.len < 1) return error.Invalid;
        buf[0] = '0' + byte;
        return 1;
    }
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

/// Parse dotted-decimal IPv4. On success writes the host-order value to `out`
/// and returns `OK`; otherwise returns a negative status.
export fn znet_ipv4_parse(s: [*]const u8, len: usize, out: *u32) c_int {
    const value = parse(s[0..len]) catch return abi.ERR_INVALID;
    out.* = value;
    return abi.OK;
}

/// Format a host-order IPv4 value into `buf` (no NUL terminator). Returns the
/// number of bytes written, or a negative status if `buf` is too small.
export fn znet_ipv4_format(addr: u32, buf: [*]u8, buflen: usize) isize {
    const written = format(addr, buf[0..buflen]) catch return abi.ERR_BUFFER;
    return @intCast(written.len);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parse basic" {
    try std.testing.expectEqual(@as(u32, 0x01020304), try parse("1.2.3.4"));
    try std.testing.expectEqual(@as(u32, 0), try parse("0.0.0.0"));
    try std.testing.expectEqual(@as(u32, 0xffffffff), try parse("255.255.255.255"));
    try std.testing.expectEqual(@as(u32, 0xc0a80001), try parse("192.168.0.1"));
    try std.testing.expectEqual(@as(u32, 0x7f000001), try parse("127.0.0.1"));
}

test "parse rejects malformed" {
    const bad = [_][]const u8{
        "",
        "1.2.3",
        "1.2.3.4.5",
        "1.2.3.",
        ".1.2.3",
        "1..2.3",
        "256.0.0.1",
        "1.2.3.256",
        "01.2.3.4", // leading zero
        "1.2.3.04",
        "1.2.3.4 ",
        " 1.2.3.4",
        "1.2.3.a",
        "1.2.3.4444",
        "1.2.3.-1",
        "::1",
    };
    for (bad) |s| {
        try std.testing.expectError(error.Invalid, parse(s));
    }
}

test "parse accepts single zero octet" {
    try std.testing.expectEqual(@as(u32, 0x0a000000), try parse("10.0.0.0"));
}

test "format round-trips" {
    var buf: [max_str_len]u8 = undefined;
    const cases = [_][]const u8{
        "0.0.0.0",
        "255.255.255.255",
        "192.168.0.1",
        "8.8.8.8",
        "1.2.3.4",
    };
    for (cases) |s| {
        const v = try parse(s);
        const out = try format(v, &buf);
        try std.testing.expectEqualStrings(s, out);
    }
}

test "format buffer too small" {
    var buf: [3]u8 = undefined;
    try std.testing.expectError(error.Invalid, format(0xffffffff, &buf));
}

test "abi round-trip" {
    var value: u32 = undefined;
    try std.testing.expectEqual(abi.OK, znet_ipv4_parse("1.2.3.4", 7, &value));
    try std.testing.expectEqual(@as(u32, 0x01020304), value);

    var buf: [max_str_len]u8 = undefined;
    const n = znet_ipv4_format(value, &buf, buf.len);
    try std.testing.expect(n > 0);
    try std.testing.expectEqualStrings("1.2.3.4", buf[0..@intCast(n)]);

    try std.testing.expectEqual(abi.ERR_INVALID, znet_ipv4_parse("bad", 3, &value));
}
