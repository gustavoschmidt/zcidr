//! Newline-delimited record splitting shared by the batch parsers.
//!
//! Records are the segments between '\n' bytes, with a trailing '\r' trimmed
//! (so CRLF input works). A single trailing empty segment produced by a
//! terminating newline is dropped; interior empty lines are kept (they parse as
//! invalid records).

const std = @import("std");

pub const LineIter = struct {
    data: []const u8,
    i: usize = 0,
    done: bool,

    pub fn init(data: []const u8) LineIter {
        return .{ .data = data, .done = data.len == 0 };
    }

    pub fn next(self: *LineIter) ?[]const u8 {
        if (self.done) return null;
        const s = self.data;
        var j = self.i;
        while (j < s.len and s[j] != '\n') : (j += 1) {}
        var seg = s[self.i..j];
        if (seg.len > 0 and seg[seg.len - 1] == '\r') seg = seg[0 .. seg.len - 1];
        if (j >= s.len) {
            self.done = true; // final segment, no terminating newline
        } else {
            self.i = j + 1;
            if (self.i >= s.len) self.done = true; // terminating newline: drop trailing empty
        }
        return seg;
    }
};

fn collect(data: []const u8, buf: [][]const u8) usize {
    var it = LineIter.init(data);
    var n: usize = 0;
    while (it.next()) |seg| : (n += 1) buf[n] = seg;
    return n;
}

test "line splitting semantics" {
    var buf: [8][]const u8 = undefined;

    try std.testing.expectEqual(@as(usize, 0), collect("", &buf));

    try std.testing.expectEqual(@as(usize, 1), collect("a", &buf));
    try std.testing.expectEqualStrings("a", buf[0]);

    try std.testing.expectEqual(@as(usize, 1), collect("a\n", &buf)); // trailing newline dropped
    try std.testing.expectEqual(@as(usize, 2), collect("a\nb", &buf));
    try std.testing.expectEqual(@as(usize, 2), collect("a\nb\n", &buf));

    try std.testing.expectEqual(@as(usize, 3), collect("a\n\nb", &buf)); // interior empty kept
    try std.testing.expectEqualStrings("", buf[1]);

    try std.testing.expectEqual(@as(usize, 2), collect("a\r\nb\r\n", &buf)); // CRLF trimmed
    try std.testing.expectEqualStrings("a", buf[0]);
    try std.testing.expectEqualStrings("b", buf[1]);
}
