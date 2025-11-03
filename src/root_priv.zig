const std = @import("std");
const builtin = @import("builtin");

pub const fnctl = if (builtin.os.tag == .linux) @cImport(@cInclude("fcntl.h")) else void;
pub const socket = @import("socket.zig");

pub const net = @import("znetw");

test {
    std.testing.refAllDecls(@This());
}
