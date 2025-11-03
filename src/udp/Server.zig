const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const mem = std.mem;
const posix = std.posix;
const addr_in = posix.sockaddr.in;
const socket_t = posix.socket_t;
const Ip4Address = net.Ip4Address;
const Thread = std.Thread;
const windows = std.os.windows;
const util = @import("util");
const socket_util = util.socket;
const udp = @import("udp.zig");

const UdpServer = @This();

const AtomicBool = std.atomic.Value(bool);

pub const ServerOpenError = udp.OpenError || posix.BindError;
pub const ServerListenError = udp.ListenError || error{NotBound};
pub const ServerSendToError = udp.SendError || posix.SendToError || error{NotBound};

socket: socket_t,
ip4: net.Ip4Address,
blocking: bool = false,
bound: AtomicBool,
dispatch_fn: ?*const fn (server: *const UdpServer, sender_addr: Ip4Address, data: []const u8) anyerror!void = null,
listening: AtomicBool = .init(false),
serve_th: ?Thread = null,
buffer_size: usize,
allocator: std.mem.Allocator,

/// Creates a UDP server and binds to the specified IP and port. Uses a blocking or non-blocking socket.
///
/// If `buffer_size` is null, the default buffer size defined in `udp.buffer_size` is used.
pub fn open(ip: []const u8, port: u16, blocking: bool, buffer_size: ?usize, allocator: std.mem.Allocator) ServerOpenError!UdpServer {
    const socket: socket_t = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    errdefer posix.close(socket);

    if (!blocking)
        try socket_util.setNonBlocking(socket);

    const ip4 = try Ip4Address.parse(ip, port);

    try posix.bind(socket, @ptrCast(&ip4.sa), @sizeOf(addr_in));

    return UdpServer{
        .socket = socket,
        .ip4 = ip4,
        .buffer_size = buffer_size orelse udp.buffer_size,
        .blocking = blocking,
        .bound = .init(true),
        .allocator = allocator,
    };
}

/// Closes the UDP server socket and stops the serving thread if running.
///
/// It is safe to call this function more than once.
pub fn close(self: *UdpServer) void {
    if (self.serve_th) |th| {
        self.listening.store(false, .release);

        if (self.blocking) {
            self.bound.store(false, .release);
            posix.shutdown(self.socket, .both) catch |err| {
                std.log.err("udp server socket shutdown error: {s}", .{@errorName(err)});
                std.log.info("udp server closing socket", .{});
                posix.close(self.socket);
            };
        }

        th.join();
        self.serve_th = null;
    }

    if (self.bound.load(.acquire)) {
        self.bound.store(false, .release);
        posix.close(self.socket);
    }

    std.log.info("udp server shut down", .{});
}

/// Starts listening for incoming data on a dedicated thread. Triggers callback `dispatch_fn` on receive.
///
/// Returns:
/// - `NotBound` if the server socket is not bound.
/// - `AlreadyListening` if the listen thread is already running.
pub fn listen(self: *UdpServer) ServerListenError!void {
    if (!self.bound.load(.acquire))
        return ServerListenError.NotBound;

    if (self.serve_th != null)
        return ServerListenError.AlreadyListening;

    self.listening.store(true, .release);
    errdefer self.listening.store(false, .release);

    self.serve_th = try Thread.spawn(.{}, listenLoop, .{self});

    std.log.info("udp server listening on {f}...", .{self.ip4});
}

fn listenLoop(self: *UdpServer) std.mem.Allocator.Error!void {
    if (self.dispatch_fn == null)
        std.log.warn("udp server dispatch function is not set, incoming data will not be processed", .{});

    const buffer = try self.allocator.alloc(u8, self.buffer_size);
    defer self.allocator.free(buffer);

    while (self.listening.load(.acquire)) {
        var sender_ip4: Ip4Address = undefined;
        var addr_len: posix.socklen_t = @sizeOf(addr_in);

        const data_len = posix.recvfrom(self.socket, buffer, 0, @ptrCast(&sender_ip4.sa), &addr_len) catch |err| switch (err) {
            posix.RecvFromError.MessageTooBig => self.buffer_size,
            else => continue,
        };
        if (data_len == 0) continue;

        if (self.dispatch_fn) |dspch| {
            dspch(self, sender_ip4, buffer[0..data_len]) catch continue;
        }
    }
}

/// Sends data through the bound socket to the specified address.
///
/// Even though `sendTo` could utilize a different socket, the function will call `sendTo` on the server bound socket, hence returning `NotBound` if the socket is not bound.
/// It might immediately return `WouldBlock` for a blocking operation in non-blocking mode.
pub fn sendTo(self: UdpServer, ip4: Ip4Address, data: []const u8) ServerSendToError!void {
    if (!self.bound.load(.acquire))
        return ServerSendToError.NotBound;

    const bytes_sent = try posix.sendto(self.socket, data, 0, @ptrCast(&ip4.sa), @sizeOf(addr_in));

    if (bytes_sent != data.len)
        std.log.warn("udp server sendTo() inconsistency - number of bytes sent: {d} of {d}", .{ bytes_sent, data.len });
}

/// Attempts to enable broadcast on the server socket.
pub inline fn enableBroadcast(self: UdpServer) posix.SetSockOptError!void {
    const enable: c_int = 1;
    try posix.setsockopt(self.socket, posix.SOL.SOCKET, posix.SO.BROADCAST, std.mem.asBytes(&enable));
}
