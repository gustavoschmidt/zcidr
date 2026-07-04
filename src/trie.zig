//! Longest-prefix-match over CIDR rule sets, backed by a binary radix trie.
//!
//! One `Trie` holds two independent bit tries — one keyed on 32-bit IPv4 keys,
//! one on 128-bit IPv6 keys. Each inserted prefix stores an opaque `u64` value;
//! a lookup returns the value of the most specific (longest) matching prefix.

const std = @import("std");
const abi = @import("abi.zig");
const cidr = @import("cidr.zig");

const Node = struct {
    children: [2]?*Node = .{ null, null },
    value: u64 = 0,
    has_value: bool = false,
};

/// Extract bit `i` (0 = most significant of byte 0) from a network-order key.
fn getBit(bytes: []const u8, i: usize) u1 {
    const byte = bytes[i >> 3];
    return @intCast((byte >> @intCast(7 - (i & 7))) & 1);
}

pub const Trie = struct {
    allocator: std.mem.Allocator,
    v4_root: ?*Node = null,
    v6_root: ?*Node = null,

    pub fn init(allocator: std.mem.Allocator) Trie {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Trie) void {
        if (self.v4_root) |r| self.freeNode(r);
        if (self.v6_root) |r| self.freeNode(r);
        self.v4_root = null;
        self.v6_root = null;
    }

    fn freeNode(self: *Trie, node: *Node) void {
        if (node.children[0]) |c| self.freeNode(c);
        if (node.children[1]) |c| self.freeNode(c);
        self.allocator.destroy(node);
    }

    fn newNode(self: *Trie) !*Node {
        const n = try self.allocator.create(Node);
        n.* = .{};
        return n;
    }

    fn rootPtr(self: *Trie, is_v6: bool) *?*Node {
        return if (is_v6) &self.v6_root else &self.v4_root;
    }

    /// Insert a prefix. `bytes` holds the network-order key (>= ceil(prefix/8)
    /// bytes readable). A later insert of the same prefix overwrites its value.
    pub fn insert(self: *Trie, is_v6: bool, bytes: []const u8, prefix_len: u8, value: u64) !void {
        const root = self.rootPtr(is_v6);
        if (root.* == null) root.* = try self.newNode();
        var node = root.*.?;
        var i: usize = 0;
        while (i < prefix_len) : (i += 1) {
            const bit = getBit(bytes, i);
            if (node.children[bit] == null) node.children[bit] = try self.newNode();
            node = node.children[bit].?;
        }
        node.value = value;
        node.has_value = true;
    }

    /// Insert a CIDR string (e.g. "10.0.0.0/8").
    pub fn insertCidr(self: *Trie, s: []const u8, value: u64) !void {
        const c = cidr.parse(s) catch return error.Invalid;
        try self.insert(c.is_v6, &c.bytes, c.prefix_len, value);
    }

    /// Longest-prefix-match lookup. Returns the matching value or null.
    pub fn lookup(self: *Trie, is_v6: bool, bytes: []const u8) ?u64 {
        const max_bits: usize = if (is_v6) 128 else 32;
        var node = (if (is_v6) self.v6_root else self.v4_root) orelse return null;
        var best: ?u64 = if (node.has_value) node.value else null;
        var i: usize = 0;
        while (i < max_bits) : (i += 1) {
            const bit = getBit(bytes, i);
            node = node.children[bit] orelse break;
            if (node.has_value) best = node.value;
        }
        return best;
    }
};

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

/// Allocate a trie (libc allocator). Returns null on failure. Free with
/// znet_trie_destroy.
export fn znet_trie_create() ?*Trie {
    const t = std.heap.c_allocator.create(Trie) catch return null;
    t.* = Trie.init(std.heap.c_allocator);
    return t;
}

export fn znet_trie_destroy(t: ?*Trie) void {
    const trie = t orelse return;
    trie.deinit();
    std.heap.c_allocator.destroy(trie);
}

/// Insert a prefix from raw bytes (4 bytes for IPv4, 16 for IPv6).
export fn znet_trie_insert(t: ?*Trie, is_v6: c_int, addr: [*]const u8, prefix_len: u8, value: u64) c_int {
    const trie = t orelse return abi.ERR_INVALID;
    const v6 = is_v6 != 0;
    const nbytes: usize = if (v6) 16 else 4;
    if (prefix_len > (if (v6) @as(u8, 128) else 32)) return abi.ERR_INVALID;
    trie.insert(v6, addr[0..nbytes], prefix_len, value) catch return abi.ERR_NOMEM;
    return abi.OK;
}

/// Insert a prefix from a CIDR string.
export fn znet_trie_insert_cidr(t: ?*Trie, s: [*]const u8, len: usize, value: u64) c_int {
    const trie = t orelse return abi.ERR_INVALID;
    trie.insertCidr(s[0..len], value) catch |e| return switch (e) {
        error.Invalid => abi.ERR_INVALID,
        else => abi.ERR_NOMEM,
    };
    return abi.OK;
}

/// Longest-prefix-match lookup by raw bytes. On a hit writes the value to
/// `out_value` and returns OK; on a miss returns ERR_NOTFOUND.
export fn znet_trie_lookup(t: ?*Trie, is_v6: c_int, addr: [*]const u8, out_value: *u64) c_int {
    const trie = t orelse return abi.ERR_INVALID;
    const v6 = is_v6 != 0;
    const nbytes: usize = if (v6) 16 else 4;
    if (trie.lookup(v6, addr[0..nbytes])) |value| {
        out_value.* = value;
        return abi.OK;
    }
    return abi.ERR_NOTFOUND;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn v4(a: u8, b: u8, c: u8, d: u8) [4]u8 {
    return .{ a, b, c, d };
}

test "longest prefix match ipv4" {
    var t = Trie.init(testing.allocator);
    defer t.deinit();

    try t.insertCidr("10.0.0.0/8", 1);
    try t.insertCidr("10.1.0.0/16", 2);
    try t.insertCidr("10.1.2.0/24", 3);

    // Most specific wins.
    try testing.expectEqual(@as(?u64, 3), t.lookup(false, &v4(10, 1, 2, 5)));
    try testing.expectEqual(@as(?u64, 2), t.lookup(false, &v4(10, 1, 9, 9)));
    try testing.expectEqual(@as(?u64, 1), t.lookup(false, &v4(10, 9, 9, 9)));
    // No match.
    try testing.expectEqual(@as(?u64, null), t.lookup(false, &v4(11, 0, 0, 1)));
}

test "default route matches everything" {
    var t = Trie.init(testing.allocator);
    defer t.deinit();
    try t.insertCidr("0.0.0.0/0", 42);
    try t.insertCidr("192.168.0.0/16", 7);

    try testing.expectEqual(@as(?u64, 7), t.lookup(false, &v4(192, 168, 5, 5)));
    try testing.expectEqual(@as(?u64, 42), t.lookup(false, &v4(8, 8, 8, 8)));
}

test "overwrite value" {
    var t = Trie.init(testing.allocator);
    defer t.deinit();
    try t.insertCidr("10.0.0.0/8", 1);
    try t.insertCidr("10.0.0.0/8", 99);
    try testing.expectEqual(@as(?u64, 99), t.lookup(false, &v4(10, 1, 1, 1)));
}

test "host route /32" {
    var t = Trie.init(testing.allocator);
    defer t.deinit();
    try t.insertCidr("1.2.3.4/32", 5);
    try testing.expectEqual(@as(?u64, 5), t.lookup(false, &v4(1, 2, 3, 4)));
    try testing.expectEqual(@as(?u64, null), t.lookup(false, &v4(1, 2, 3, 5)));
}

test "ipv6 lookup and family isolation" {
    var t = Trie.init(testing.allocator);
    defer t.deinit();
    try t.insertCidr("2001:db8::/32", 10);
    try t.insertCidr("2001:db8:abcd::/48", 20);
    try t.insertCidr("10.0.0.0/8", 1);

    const q1 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const q2 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expectEqual(@as(?u64, 20), t.lookup(true, &q1));
    try testing.expectEqual(@as(?u64, 10), t.lookup(true, &q2));
    // IPv4 tree is independent.
    try testing.expectEqual(@as(?u64, 1), t.lookup(false, &v4(10, 1, 1, 1)));
    // An unrelated v6 address misses.
    const miss = [_]u8{ 0xfe, 0x80 } ++ [_]u8{0} ** 14;
    try testing.expectEqual(@as(?u64, null), t.lookup(true, &miss));
}

test "abi surface" {
    const t = znet_trie_create() orelse unreachable;
    defer znet_trie_destroy(t);

    try testing.expectEqual(abi.OK, znet_trie_insert_cidr(t, "10.0.0.0/8", 10, 7));

    var out: u64 = 0;
    const addr = v4(10, 20, 30, 40);
    try testing.expectEqual(abi.OK, znet_trie_lookup(t, 0, &addr, &out));
    try testing.expectEqual(@as(u64, 7), out);

    const miss = v4(11, 0, 0, 0);
    try testing.expectEqual(abi.ERR_NOTFOUND, znet_trie_lookup(t, 0, &miss, &out));

    // Raw-bytes insert + prefix bound check.
    const p = v4(192, 168, 0, 0);
    try testing.expectEqual(abi.OK, znet_trie_insert(t, 0, &p, 16, 3));
    try testing.expectEqual(abi.ERR_INVALID, znet_trie_insert(t, 0, &p, 33, 3));
    const q = v4(192, 168, 99, 1);
    try testing.expectEqual(abi.OK, znet_trie_lookup(t, 0, &q, &out));
    try testing.expectEqual(@as(u64, 3), out);
}
