//! IPv6 address parsing and RFC 5952 canonical formatting.
//!
//! Addresses are represented as a 16-byte array in network (big-endian) order,
//! matching `bytes(ipaddress.IPv6Address(...))`.

const std = @import("std");
const abi = @import("abi.zig");
const ipv4 = @import("ipv4.zig");
const lines = @import("lines.zig");

pub const ParseError = error{Invalid};

/// Longest canonical output ("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"),
/// though we never emit embedded IPv4 — 45 leaves comfortable headroom.
pub const max_str_len = 45;

fn hexDigit(c: u8) ?u16 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn parseHextet(tok: []const u8) ParseError!u16 {
    if (tok.len == 0 or tok.len > 4) return error.Invalid;
    var v: u16 = 0;
    for (tok) |c| {
        const d = hexDigit(c) orelse return error.Invalid;
        v = (v << 4) | d;
    }
    return v;
}

fn containsDot(tok: []const u8) bool {
    return std.mem.indexOfScalar(u8, tok, '.') != null;
}

/// Parse one colon-separated half of the address into `groups` starting at
/// `idx`. When `is_tail` is true, the final token may be an embedded IPv4
/// dotted-quad, contributing two hextets.
fn parseHalf(s: []const u8, groups: *[8]u16, idx: *usize, is_tail: bool) ParseError!void {
    if (s.len == 0) return;
    var i: usize = 0;
    while (true) {
        var j = i;
        while (j < s.len and s[j] != ':') : (j += 1) {}
        const tok = s[i..j];
        if (tok.len == 0) return error.Invalid; // empty token (stray ':')

        const is_last = (j == s.len);
        if (is_tail and is_last and containsDot(tok)) {
            if (idx.* + 2 > 8) return error.Invalid;
            const v4 = ipv4.parse(tok) catch return error.Invalid;
            groups[idx.*] = @truncate(v4 >> 16);
            groups[idx.* + 1] = @truncate(v4 & 0xffff);
            idx.* += 2;
        } else {
            if (idx.* >= 8) return error.Invalid;
            groups[idx.*] = try parseHextet(tok);
            idx.* += 1;
        }

        if (is_last) break;
        i = j + 1;
        if (i == s.len) return error.Invalid; // trailing ':'
    }
}

/// Parse a textual IPv6 address into 16 network-order bytes.
pub fn parse(s: []const u8) ParseError![16]u8 {
    if (s.len == 0) return error.Invalid;

    // Locate the "::" zero-run marker. At most one is allowed; ":::" or two
    // separate "::" are rejected.
    var dc: ?usize = null;
    {
        var k: usize = 0;
        while (k + 1 < s.len) : (k += 1) {
            if (s[k] == ':' and s[k + 1] == ':') {
                if (dc != null) return error.Invalid;
                dc = k;
            }
        }
    }

    var groups = [_]u16{0} ** 8;

    if (dc) |pos| {
        var head = [_]u16{0} ** 8;
        var head_n: usize = 0;
        try parseHalf(s[0..pos], &head, &head_n, false);

        var tail = [_]u16{0} ** 8;
        var tail_n: usize = 0;
        try parseHalf(s[pos + 2 ..], &tail, &tail_n, true);

        // "::" must compress at least one group, so the explicit groups can
        // never fill all 8.
        if (head_n + tail_n >= 8) return error.Invalid;

        var i: usize = 0;
        while (i < head_n) : (i += 1) groups[i] = head[i];
        i = 0;
        while (i < tail_n) : (i += 1) groups[8 - tail_n + i] = tail[i];
    } else {
        var n: usize = 0;
        try parseHalf(s, &groups, &n, true);
        if (n != 8) return error.Invalid; // must be exactly 8 groups
    }

    var out: [16]u8 = undefined;
    var g: usize = 0;
    while (g < 8) : (g += 1) {
        out[g * 2] = @truncate(groups[g] >> 8);
        out[g * 2 + 1] = @truncate(groups[g] & 0xff);
    }
    return out;
}

fn writeHextet(v: u16, buf: []u8) ParseError!usize {
    const digits = "0123456789abcdef";
    var tmp: [4]u8 = undefined;
    var n: usize = 0;
    var value = v;
    // Build least-significant-first, then reverse.
    while (true) {
        tmp[n] = digits[value & 0xf];
        n += 1;
        value >>= 4;
        if (value == 0) break;
    }
    if (n > buf.len) return error.Invalid;
    var i: usize = 0;
    while (i < n) : (i += 1) buf[i] = tmp[n - 1 - i];
    return n;
}

/// Format 16 network-order bytes as an RFC 5952 canonical string into `buf`.
/// Lowercase hex, no leading zeros, longest run of >= 2 zero groups compressed
/// to "::" (leftmost wins on a tie).
pub fn format(addr: [16]u8, buf: []u8) ParseError![]u8 {
    var g: [8]u16 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        g[i] = (@as(u16, addr[i * 2]) << 8) | addr[i * 2 + 1];
    }

    // Find the longest run of consecutive zero groups (length >= 2).
    var best_base: usize = 0;
    var best_len: usize = 0;
    i = 0;
    while (i < 8) {
        if (g[i] == 0) {
            var j = i;
            while (j < 8 and g[j] == 0) : (j += 1) {}
            const run = j - i;
            if (run > best_len) {
                best_len = run;
                best_base = i;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    const has_run = best_len >= 2;

    // Canonical BSD inet_ntop emission.
    var n: usize = 0;
    i = 0;
    while (i < 8) : (i += 1) {
        if (has_run and i >= best_base and i < best_base + best_len) {
            if (i == best_base) {
                if (n >= buf.len) return error.Invalid;
                buf[n] = ':';
                n += 1;
            }
            continue;
        }
        if (i != 0) {
            if (n >= buf.len) return error.Invalid;
            buf[n] = ':';
            n += 1;
        }
        n += try writeHextet(g[i], buf[n..]);
    }
    if (has_run and best_base + best_len == 8) {
        if (n >= buf.len) return error.Invalid;
        buf[n] = ':';
        n += 1;
    }
    return buf[0..n];
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

/// Parse a textual IPv6 address, writing 16 network-order bytes to `out`.
export fn zcidr_ipv6_parse(s: [*]const u8, len: usize, out: *[16]u8) c_int {
    out.* = parse(s[0..len]) catch return abi.ERR_INVALID;
    return abi.OK;
}

/// Format 16 network-order bytes into `buf` (no NUL). Returns bytes written or
/// a negative status.
export fn zcidr_ipv6_format(in: *const [16]u8, buf: [*]u8, buflen: usize) isize {
    const written = format(in.*, buf[0..buflen]) catch return abi.ERR_BUFFER;
    return @intCast(written.len);
}

/// Batch-parse newline-delimited IPv6 addresses. For each record writes 16
/// network-order bytes to `out_bytes` (16 * record index) and a validity byte
/// to `out_valid`. `cap` is the record capacity. Returns the record count, or
/// `ERR_BUFFER` if it exceeds `cap`.
export fn zcidr_ipv6_parse_lines(
    data: [*]const u8,
    len: usize,
    out_bytes: [*]u8,
    out_valid: [*]u8,
    cap: usize,
) isize {
    var it = lines.LineIter.init(data[0..len]);
    var count: usize = 0;
    while (it.next()) |seg| {
        if (count >= cap) return abi.ERR_BUFFER;
        const base = count * 16;
        if (parse(seg)) |addr| {
            var k: usize = 0;
            while (k < 16) : (k += 1) out_bytes[base + k] = addr[k];
            out_valid[count] = 1;
        } else |_| {
            var k: usize = 0;
            while (k < 16) : (k += 1) out_bytes[base + k] = 0;
            out_valid[count] = 0;
        }
        count += 1;
    }
    return @intCast(count);
}

/// Batch-format `n` addresses (16 network-order bytes each) into `out` as
/// newline-separated RFC 5952 strings (no trailing newline). Returns bytes
/// written, or `ERR_BUFFER`.
export fn zcidr_ipv6_format_lines(bytes_in: [*]const u8, n: usize, out: [*]u8, cap: usize) isize {
    var pos: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (i != 0) {
            if (pos >= cap) return abi.ERR_BUFFER;
            out[pos] = '\n';
            pos += 1;
        }
        var addr: [16]u8 = undefined;
        var k: usize = 0;
        while (k < 16) : (k += 1) addr[k] = bytes_in[i * 16 + k];
        const written = format(addr, out[pos..cap]) catch return abi.ERR_BUFFER;
        pos += written.len;
    }
    return @intCast(pos);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "batch parse and format lines" {
    var bytes: [3 * 16]u8 = undefined;
    var valid: [3]u8 = undefined;
    const input = "::1\nbad\n2001:db8::1";
    const n = zcidr_ipv6_parse_lines(input, input.len, &bytes, &valid, 3);
    try std.testing.expectEqual(@as(isize, 3), n);
    try std.testing.expectEqual(@as(u8, 1), valid[0]);
    try std.testing.expectEqual(@as(u8, 0), valid[1]);
    try std.testing.expectEqual(@as(u8, 1), valid[2]);

    // Round-trip the two valid records (record 1 is zeroed/invalid).
    var out: [64]u8 = undefined;
    var pair: [2 * 16]u8 = undefined;
    var k: usize = 0;
    while (k < 16) : (k += 1) {
        pair[k] = bytes[k];
        pair[16 + k] = bytes[2 * 16 + k];
    }
    const m = zcidr_ipv6_format_lines(&pair, 2, &out, out.len);
    try std.testing.expectEqualStrings("::1\n2001:db8::1", out[0..@intCast(m)]);
}

fn expectParse(s: []const u8, expected: [16]u8) !void {
    try std.testing.expectEqualSlices(u8, &expected, &(try parse(s)));
}

test "parse full form" {
    try expectParse(
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    );
}

test "parse compressed" {
    try expectParse("::", [_]u8{0} ** 16);
    try expectParse("::1", .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    try expectParse("1::", .{ 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    try expectParse("2001:db8::1", .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    try expectParse("fe80::200:5aee:feaa:20a2", .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5a, 0xee, 0xfe, 0xaa, 0x20, 0xa2 });
}

test "parse embedded ipv4" {
    try expectParse("::ffff:1.2.3.4", .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4 });
    try expectParse("::1.2.3.4", .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4 });
    try expectParse("64:ff9b::192.0.2.33", .{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 33 });
}

test "parse rejects malformed" {
    const bad = [_][]const u8{
        "",
        ":",
        ":::",
        "1:::2",
        "1::2::3", // two "::"
        "12345::", // hextet too long
        "1:2:3:4:5:6:7", // too few, no "::"
        "1:2:3:4:5:6:7:8:9", // too many
        "1:2:3:4:5:6:7:8:", // trailing colon
        ":1:2:3:4:5:6:7:8", // leading colon
        "1:2:3:4:5:6:7:8::", // "::" with 8 explicit groups
        "gggg::",
        "1.2.3.4", // bare IPv4
        "::1.2.3", // bad embedded IPv4
        "::1.2.3.4.5",
        "1.2.3.4::", // IPv4 not at tail
        "::12345",
    };
    for (bad) |s| {
        try std.testing.expectError(error.Invalid, parse(s));
    }
}

test "format canonical (RFC 5952)" {
    const cases = [_]struct { in: []const u8, out: []const u8 }{
        .{ .in = "::", .out = "::" },
        .{ .in = "::1", .out = "::1" },
        .{ .in = "1::", .out = "1::" },
        .{ .in = "2001:0db8:0000:0000:0000:0000:0000:0001", .out = "2001:db8::1" },
        .{ .in = "2001:db8:0:0:1:0:0:1", .out = "2001:db8::1:0:0:1" }, // leftmost longest run
        .{ .in = "0:0:0:0:0:0:0:0", .out = "::" },
        .{ .in = "FE80::0202:B3FF:FE1E:8329", .out = "fe80::202:b3ff:fe1e:8329" },
        .{ .in = "0:0:0:0:0:ffff:1.2.3.4", .out = "::ffff:102:304" },
        .{ .in = "2001:db8:0:1:1:1:1:1", .out = "2001:db8:0:1:1:1:1:1" }, // single zero not compressed
        .{ .in = "1:0:0:0:0:0:0:1", .out = "1::1" },
    };
    var buf: [max_str_len]u8 = undefined;
    for (cases) |c| {
        const addr = try parse(c.in);
        const out = try format(addr, &buf);
        try std.testing.expectEqualStrings(c.out, out);
    }
}

test "abi round-trip" {
    var out: [16]u8 = undefined;
    try std.testing.expectEqual(abi.OK, zcidr_ipv6_parse("2001:db8::1", 11, &out));

    var buf: [max_str_len]u8 = undefined;
    const n = zcidr_ipv6_format(&out, &buf, buf.len);
    try std.testing.expect(n > 0);
    try std.testing.expectEqualStrings("2001:db8::1", buf[0..@intCast(n)]);

    try std.testing.expectEqual(abi.ERR_INVALID, zcidr_ipv6_parse("nope", 4, &out));
}
